use omni_core::{DataPayload, ExecutionContext, OmniError, OmniResult};
use omni_pipeline::{
    PipelineDefinition, PipelineExecutionOptions, PipelineExecutionReport, PipelineExecutor,
};
use omni_registry::OperationRegistry;
use omni_security::sanitize_error_message;
use omni_storage::DatabaseManager;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, mpsc, Semaphore};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
    TimedOut,
}

impl JobStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::TimedOut => "timed_out",
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Cancelled | Self::TimedOut
        )
    }

    /// Enforces valid job lifecycle transitions.
    pub fn can_transition_to(&self, next: JobStatus) -> bool {
        match self {
            Self::Queued => matches!(
                next,
                Self::Running | Self::Cancelled | Self::TimedOut | Self::Failed
            ),
            Self::Running => matches!(
                next,
                Self::Completed | Self::Failed | Self::Cancelled | Self::TimedOut
            ),
            Self::Completed | Self::Failed | Self::Cancelled | Self::TimedOut => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum JobEvent {
    Queued {
        job_id: String,
        operation: String,
    },
    Started {
        job_id: String,
        operation: String,
    },
    Progress {
        job_id: String,
        percent: f32,
        stage: String,
        message: String,
    },
    Completed {
        job_id: String,
        duration_ms: u64,
        output_preview: String,
    },
    Failed {
        job_id: String,
        duration_ms: u64,
        error: String,
    },
    TimedOut {
        job_id: String,
        duration_ms: u64,
        timeout_ms: u64,
    },
    Cancelled {
        job_id: String,
    },
}

impl JobEvent {
    pub fn job_id(&self) -> &str {
        match self {
            Self::Queued { job_id, .. }
            | Self::Started { job_id, .. }
            | Self::Progress { job_id, .. }
            | Self::Completed { job_id, .. }
            | Self::Failed { job_id, .. }
            | Self::TimedOut { job_id, .. }
            | Self::Cancelled { job_id } => job_id.as_str(),
        }
    }
}

struct ActiveJobEntry {
    ctx: ExecutionContext,
    status: JobStatus,
    job_tx: broadcast::Sender<JobEvent>,
}

/// RAII cleanup guard ensuring active job state is always removed even if a future is dropped or panics.
struct ActiveJobCleanupGuard {
    job_id: String,
    active_jobs: Arc<RwLock<HashMap<String, ActiveJobEntry>>>,
}

impl Drop for ActiveJobCleanupGuard {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.active_jobs.write() {
            if let Some(entry) = guard.remove(&self.job_id) {
                if !entry.status.is_terminal() {
                    entry.ctx.cancel();
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct JobManager {
    registry: Arc<RwLock<OperationRegistry>>,
    db: Arc<DatabaseManager>,
    event_tx: broadcast::Sender<JobEvent>,
    active_jobs: Arc<RwLock<HashMap<String, ActiveJobEntry>>>,
    concurrency_limit: Arc<Semaphore>,
}

impl JobManager {
    pub fn new(registry: Arc<RwLock<OperationRegistry>>, db: Arc<DatabaseManager>) -> Self {
        Self::with_max_concurrency(registry, db, 16)
    }

    pub fn with_max_concurrency(
        registry: Arc<RwLock<OperationRegistry>>,
        db: Arc<DatabaseManager>,
        max_concurrent_jobs: usize,
    ) -> Self {
        let (event_tx, _) = broadcast::channel(512);
        let _ = db.recover_interrupted_jobs();
        Self {
            registry,
            db,
            event_tx,
            active_jobs: Arc::new(RwLock::new(HashMap::new())),
            concurrency_limit: Arc::new(Semaphore::new(max_concurrent_jobs.max(1))),
        }
    }

    /// Subscribes to the global event stream (intended for authorized internal/admin consumers).
    pub fn subscribe(&self) -> broadcast::Receiver<JobEvent> {
        self.event_tx.subscribe()
    }

    /// Subscribes exclusively to events for a single active job ID (strict isolation).
    pub fn subscribe_job(&self, job_id: &str) -> Option<broadcast::Receiver<JobEvent>> {
        let guard = self.active_jobs.read().ok()?;
        guard.get(job_id).map(|entry| entry.job_tx.subscribe())
    }

    /// Returns the number of currently active (queued or running) jobs.
    pub fn active_job_count(&self) -> usize {
        self.active_jobs
            .read()
            .map(|g| g.len())
            .unwrap_or(0)
    }

    fn emit_event(&self, job_id: &str, event: JobEvent) {
        if let Ok(guard) = self.active_jobs.read() {
            if let Some(entry) = guard.get(job_id) {
                let _ = entry.job_tx.send(event.clone());
            }
        }
        let _ = self.event_tx.send(event);
    }

    fn transition_status(&self, job_id: &str, next: JobStatus) -> OmniResult<()> {
        let mut guard = self
            .active_jobs
            .write()
            .map_err(|e| OmniError::Internal(format!("Active jobs lock poisoned: {e}")))?;
        if let Some(entry) = guard.get_mut(job_id) {
            if !entry.status.can_transition_to(next) {
                return Err(OmniError::Internal(format!(
                    "Invalid job state transition for '{}': {:?} -> {:?}",
                    job_id, entry.status, next
                )));
            }
            entry.status = next;
        }
        Ok(())
    }

    /// Cancels an active job immediately and notifies waiting workers.
    pub fn cancel_job(&self, job_id: &str) -> bool {
        let entry_ctx = {
            let Ok(mut guard) = self.active_jobs.write() else {
                return false;
            };
            if let Some(entry) = guard.get_mut(job_id) {
                if entry.status.is_terminal() {
                    return false;
                }
                entry.status = JobStatus::Cancelled;
                entry.ctx.cancel();
                Some(entry.job_tx.clone())
            } else {
                None
            }
        };

        if let Some(job_tx) = entry_ctx {
            let evt = JobEvent::Cancelled {
                job_id: job_id.to_string(),
            };
            let _ = job_tx.send(evt.clone());
            let _ = self.event_tx.send(evt);
            true
        } else {
            false
        }
    }

    /// Cancels all active jobs during graceful server shutdown.
    pub fn shutdown(&self) -> usize {
        let job_ids: Vec<String> = self
            .active_jobs
            .read()
            .map(|g| g.keys().cloned().collect())
            .unwrap_or_default();

        let mut cancelled = 0;
        for id in job_ids {
            if self.cancel_job(&id) {
                cancelled += 1;
            }
        }
        cancelled
    }

    pub async fn run_operation(
        &self,
        operation_id: &str,
        input: DataPayload,
        config: serde_json::Value,
        timeout: Duration,
    ) -> OmniResult<DataPayload> {
        let (_, output) = self
            .run_operation_with_id(operation_id, input, config, timeout)
            .await?;
        Ok(output)
    }

    pub async fn run_operation_with_id(
        &self,
        operation_id: &str,
        input: DataPayload,
        config: serde_json::Value,
        timeout: Duration,
    ) -> OmniResult<(String, DataPayload)> {
        let job_id = uuid::Uuid::new_v4().to_string();
        let (prog_tx, mut prog_rx) = mpsc::channel(32);
        let (job_tx, _) = broadcast::channel(64);

        let ctx = ExecutionContext::new(job_id.clone()).with_progress(prog_tx);
        {
            let mut active = self
                .active_jobs
                .write()
                .map_err(|e| OmniError::Internal(format!("Active jobs lock poisoned: {e}")))?;
            active.insert(
                job_id.clone(),
                ActiveJobEntry {
                    ctx: ctx.clone(),
                    status: JobStatus::Queued,
                    job_tx: job_tx.clone(),
                },
            );
        }

        let _cleanup = ActiveJobCleanupGuard {
            job_id: job_id.clone(),
            active_jobs: self.active_jobs.clone(),
        };

        self.db
            .insert_job_with_status(&job_id, operation_id, JobStatus::Queued.as_str())?;
        self.emit_event(
            &job_id,
            JobEvent::Queued {
                job_id: job_id.clone(),
                operation: operation_id.to_string(),
            },
        );

        let op = {
            let reg = self
                .registry
                .read()
                .map_err(|e| OmniError::Internal(format!("Registry lock poisoned: {e}")))?;
            reg.get(operation_id).ok_or_else(|| {
                OmniError::NotFound(format!("Operation '{}' not found in registry", operation_id))
            })?
        };

        // Acquire bounded worker concurrency permit while respecting cancellation & timeout
        let start = Instant::now();
        let permit = tokio::select! {
            biased;
            _ = ctx.cancelled() => {
                let dur = start.elapsed().as_millis() as u64;
                let _ = self.db.finish_job(&job_id, JobStatus::Cancelled.as_str(), dur as i64, Some("Cancelled while queued"));
                return Err(OmniError::Cancelled);
            }
            _ = tokio::time::sleep(timeout) => {
                ctx.cancel();
                let dur = start.elapsed().as_millis() as u64;
                let _ = self.transition_status(&job_id, JobStatus::TimedOut);
                let _ = self.db.finish_job(&job_id, JobStatus::TimedOut.as_str(), dur as i64, Some("Timed out while waiting for worker permit"));
                self.emit_event(&job_id, JobEvent::TimedOut { job_id: job_id.clone(), duration_ms: dur, timeout_ms: timeout.as_millis() as u64 });
                return Err(OmniError::Timeout(timeout.as_millis() as u64));
            }
            p = self.concurrency_limit.clone().acquire_owned() => {
                p.map_err(|_| OmniError::Cancelled)?
            }
        };

        let _ = self.transition_status(&job_id, JobStatus::Running);
        let _ = self
            .db
            .update_job_status(&job_id, JobStatus::Running.as_str());
        self.emit_event(
            &job_id,
            JobEvent::Started {
                job_id: job_id.clone(),
                operation: operation_id.to_string(),
            },
        );

        let evt_tx = self.event_tx.clone();
        let per_job_tx = job_tx.clone();
        let jid = job_id.clone();
        let progress_handle = tokio::spawn(async move {
            while let Some(prog) = prog_rx.recv().await {
                let evt = JobEvent::Progress {
                    job_id: jid.clone(),
                    percent: prog.percent,
                    stage: prog.stage,
                    message: sanitize_error_message(&prog.message),
                };
                let _ = per_job_tx.send(evt.clone());
                let _ = evt_tx.send(evt);
            }
        });

        let worker_ctx = ctx.clone();
        let mut worker_handle = tokio::spawn(async move {
            op.execute(input, config, &worker_ctx).await
        });

        let remaining = timeout.saturating_sub(start.elapsed());
        let result = tokio::select! {
            biased;
            _ = ctx.cancelled() => {
                worker_handle.abort();
                Err(OmniError::Cancelled)
            }
            join_res = &mut worker_handle => {
                match join_res {
                    Ok(op_res) => op_res,
                    Err(join_err) => Err(OmniError::Internal(format!("Worker panicked or aborted: {join_err}"))),
                }
            }
            _ = tokio::time::sleep(remaining) => {
                ctx.cancel();
                worker_handle.abort();
                Err(OmniError::Timeout(timeout.as_millis() as u64))
            }
        };

        drop(permit);
        drop(ctx); // drops progress_tx clone so progress_handle terminates cleanly
        let _ = tokio::time::timeout(Duration::from_millis(50), progress_handle).await;

        let duration_ms = start.elapsed().as_millis() as u64;

        match &result {
            Ok(output) => {
                let _ = self.transition_status(&job_id, JobStatus::Completed);
                self.db.finish_job(
                    &job_id,
                    JobStatus::Completed.as_str(),
                    duration_ms as i64,
                    None,
                )?;
                let raw_preview = match output {
                    DataPayload::Text(s) => s.chars().take(80).collect(),
                    DataPayload::Bytes(b) => format!("<{} bytes>", b.len()),
                    DataPayload::Json(v) => v.to_string().chars().take(80).collect(),
                    DataPayload::FileRef(p) => format!("<File: {}>", p.display()),
                    DataPayload::Multi(m) => format!("<Multi: {} items>", m.len()),
                };
                let safe_preview = sanitize_error_message(&raw_preview);
                self.emit_event(
                    &job_id,
                    JobEvent::Completed {
                        job_id: job_id.clone(),
                        duration_ms,
                        output_preview: safe_preview,
                    },
                );
            }
            Err(OmniError::Cancelled) => {
                let _ = self.transition_status(&job_id, JobStatus::Cancelled);
                let _ = self.db.finish_job(
                    &job_id,
                    JobStatus::Cancelled.as_str(),
                    duration_ms as i64,
                    Some("Operation cancelled"),
                );
            }
            Err(OmniError::Timeout(ms)) => {
                let _ = self.transition_status(&job_id, JobStatus::TimedOut);
                let err_msg = format!("Operation timed out after {} ms", ms);
                let _ = self.db.finish_job(
                    &job_id,
                    JobStatus::TimedOut.as_str(),
                    duration_ms as i64,
                    Some(&err_msg),
                );
                self.emit_event(
                    &job_id,
                    JobEvent::TimedOut {
                        job_id: job_id.clone(),
                        duration_ms,
                        timeout_ms: *ms,
                    },
                );
            }
            Err(e) => {
                let _ = self.transition_status(&job_id, JobStatus::Failed);
                let safe_err = sanitize_error_message(&e.to_string());
                let _ = self.db.finish_job(
                    &job_id,
                    JobStatus::Failed.as_str(),
                    duration_ms as i64,
                    Some(&safe_err),
                );
                self.emit_event(
                    &job_id,
                    JobEvent::Failed {
                        job_id: job_id.clone(),
                        duration_ms,
                        error: safe_err,
                    },
                );
            }
        }

        result.map(|out| (job_id, out))
    }

    pub async fn run_pipeline(
        &self,
        pipeline: &PipelineDefinition,
        input: DataPayload,
        timeout: Duration,
    ) -> OmniResult<HashMap<String, DataPayload>> {
        let report = self.run_pipeline_with_report(pipeline, input, timeout).await?;
        Ok(report.outputs)
    }

    pub async fn run_pipeline_with_report(
        &self,
        pipeline: &PipelineDefinition,
        input: DataPayload,
        timeout: Duration,
    ) -> OmniResult<PipelineExecutionReport> {
        let job_id = uuid::Uuid::new_v4().to_string();
        let (prog_tx, mut prog_rx) = mpsc::channel(32);
        let (job_tx, _) = broadcast::channel(64);

        let ctx = ExecutionContext::new(job_id.clone()).with_progress(prog_tx);
        {
            let mut active = self
                .active_jobs
                .write()
                .map_err(|e| OmniError::Internal(format!("Active jobs lock poisoned: {e}")))?;
            active.insert(
                job_id.clone(),
                ActiveJobEntry {
                    ctx: ctx.clone(),
                    status: JobStatus::Queued,
                    job_tx: job_tx.clone(),
                },
            );
        }

        let _cleanup = ActiveJobCleanupGuard {
            job_id: job_id.clone(),
            active_jobs: self.active_jobs.clone(),
        };

        let op_name = format!("pipeline:{}", pipeline.id);
        self.db
            .insert_job_with_status(&job_id, &op_name, JobStatus::Queued.as_str())?;
        self.emit_event(
            &job_id,
            JobEvent::Queued {
                job_id: job_id.clone(),
                operation: op_name.clone(),
            },
        );

        let start = Instant::now();
        let permit = tokio::select! {
            biased;
            _ = ctx.cancelled() => {
                let dur = start.elapsed().as_millis() as u64;
                let _ = self.db.finish_job(&job_id, JobStatus::Cancelled.as_str(), dur as i64, Some("Cancelled while queued"));
                return Err(OmniError::Cancelled);
            }
            _ = tokio::time::sleep(timeout) => {
                ctx.cancel();
                let dur = start.elapsed().as_millis() as u64;
                let _ = self.transition_status(&job_id, JobStatus::TimedOut);
                let _ = self.db.finish_job(&job_id, JobStatus::TimedOut.as_str(), dur as i64, Some("Timed out while queued"));
                return Err(OmniError::Timeout(timeout.as_millis() as u64));
            }
            p = self.concurrency_limit.clone().acquire_owned() => {
                p.map_err(|_| OmniError::Cancelled)?
            }
        };

        let _ = self.transition_status(&job_id, JobStatus::Running);
        let _ = self
            .db
            .update_job_status(&job_id, JobStatus::Running.as_str());
        self.emit_event(
            &job_id,
            JobEvent::Started {
                job_id: job_id.clone(),
                operation: op_name,
            },
        );

        let evt_tx = self.event_tx.clone();
        let per_job_tx = job_tx.clone();
        let jid = job_id.clone();
        let progress_handle = tokio::spawn(async move {
            while let Some(prog) = prog_rx.recv().await {
                let evt = JobEvent::Progress {
                    job_id: jid.clone(),
                    percent: prog.percent,
                    stage: prog.stage,
                    message: sanitize_error_message(&prog.message),
                };
                let _ = per_job_tx.send(evt.clone());
                let _ = evt_tx.send(evt);
            }
        });

        let pipeline_owned = pipeline.clone();
        let registry_owned = self.registry.clone();
        let worker_ctx = ctx.clone();
        let mut worker_handle = tokio::spawn(async move {
            let options = PipelineExecutionOptions {
                max_concurrency: pipeline_owned.max_concurrency.unwrap_or(4).max(1),
                ..Default::default()
            };
            PipelineExecutor::execute_with_report(
                &pipeline_owned,
                input,
                &registry_owned,
                &worker_ctx,
                options,
            )
            .await
        });

        let remaining = timeout.saturating_sub(start.elapsed());
        let result = tokio::select! {
            biased;
            _ = ctx.cancelled() => {
                worker_handle.abort();
                Err(OmniError::Cancelled)
            }
            join_res = &mut worker_handle => {
                match join_res {
                    Ok(res) => res,
                    Err(join_err) => Err(OmniError::Internal(format!("Pipeline worker panicked or aborted: {join_err}"))),
                }
            }
            _ = tokio::time::sleep(remaining) => {
                ctx.cancel();
                worker_handle.abort();
                Err(OmniError::Timeout(timeout.as_millis() as u64))
            }
        };

        drop(permit);
        drop(ctx);
        let _ = tokio::time::timeout(Duration::from_millis(50), progress_handle).await;

        let duration_ms = start.elapsed().as_millis() as u64;

        match &result {
            Ok(report) => {
                let _ = self.transition_status(&job_id, JobStatus::Completed);
                self.db.finish_job(
                    &job_id,
                    JobStatus::Completed.as_str(),
                    duration_ms as i64,
                    None,
                )?;
                self.emit_event(
                    &job_id,
                    JobEvent::Completed {
                        job_id: job_id.clone(),
                        duration_ms,
                        output_preview: format!("{} nodes executed", report.nodes.len()),
                    },
                );
            }
            Err(OmniError::Cancelled) => {
                let _ = self.transition_status(&job_id, JobStatus::Cancelled);
                let _ = self.db.finish_job(
                    &job_id,
                    JobStatus::Cancelled.as_str(),
                    duration_ms as i64,
                    Some("Pipeline cancelled"),
                );
            }
            Err(OmniError::Timeout(ms)) => {
                let _ = self.transition_status(&job_id, JobStatus::TimedOut);
                let msg = format!("Pipeline timed out after {} ms", ms);
                let _ = self.db.finish_job(
                    &job_id,
                    JobStatus::TimedOut.as_str(),
                    duration_ms as i64,
                    Some(&msg),
                );
                self.emit_event(
                    &job_id,
                    JobEvent::TimedOut {
                        job_id: job_id.clone(),
                        duration_ms,
                        timeout_ms: *ms,
                    },
                );
            }
            Err(e) => {
                let _ = self.transition_status(&job_id, JobStatus::Failed);
                let safe_err = sanitize_error_message(&e.to_string());
                let _ = self.db.finish_job(
                    &job_id,
                    JobStatus::Failed.as_str(),
                    duration_ms as i64,
                    Some(&safe_err),
                );
                self.emit_event(
                    &job_id,
                    JobEvent::Failed {
                        job_id: job_id.clone(),
                        duration_ms,
                        error: safe_err,
                    },
                );
            }
        }

        result
    }
}
