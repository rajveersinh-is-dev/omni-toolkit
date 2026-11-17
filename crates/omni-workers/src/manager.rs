use omni_core::{DataPayload, ExecutionContext, OmniError, OmniResult};
use omni_pipeline::{PipelineDefinition, PipelineExecutor};
use omni_registry::OperationRegistry;
use omni_storage::DatabaseManager;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, mpsc};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum JobEvent {
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
    Cancelled {
        job_id: String,
    },
}

#[derive(Clone)]
pub struct JobManager {
    registry: Arc<RwLock<OperationRegistry>>,
    db: Arc<DatabaseManager>,
    event_tx: broadcast::Sender<JobEvent>,
    contexts: Arc<RwLock<HashMap<String, ExecutionContext>>>,
}

impl JobManager {
    pub fn new(registry: Arc<RwLock<OperationRegistry>>, db: Arc<DatabaseManager>) -> Self {
        let (event_tx, _) = broadcast::channel(1024);
        Self {
            registry,
            db,
            event_tx,
            contexts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<JobEvent> {
        self.event_tx.subscribe()
    }

    pub fn cancel_job(&self, job_id: &str) -> bool {
        let contexts = self.contexts.read().unwrap();
        if let Some(ctx) = contexts.get(job_id) {
            ctx.cancel();
            let _ = self.event_tx.send(JobEvent::Cancelled {
                job_id: job_id.to_string(),
            });
            true
        } else {
            false
        }
    }

    pub async fn run_operation(
        &self,
        operation_id: &str,
        input: DataPayload,
        config: serde_json::Value,
        timeout: Duration,
    ) -> OmniResult<DataPayload> {
        let job_id = uuid::Uuid::new_v4().to_string();
        let (prog_tx, mut prog_rx) = mpsc::channel(32);

        let ctx = ExecutionContext::new(job_id.clone()).with_progress(prog_tx);
        {
            let mut contexts = self.contexts.write().unwrap();
            contexts.insert(job_id.clone(), ctx.clone());
        }

        self.db.insert_job(&job_id, operation_id)?;
        let _ = self.event_tx.send(JobEvent::Started {
            job_id: job_id.clone(),
            operation: operation_id.to_string(),
        });

        let evt_tx = self.event_tx.clone();
        let jid = job_id.clone();
        tokio::spawn(async move {
            while let Some(prog) = prog_rx.recv().await {
                let _ = evt_tx.send(JobEvent::Progress {
                    job_id: jid.clone(),
                    percent: prog.percent,
                    stage: prog.stage,
                    message: prog.message,
                });
            }
        });

        let op = {
            let reg = self.registry.read().map_err(|e| OmniError::Internal(e.to_string()))?;
            reg.get(operation_id).ok_or_else(|| {
                OmniError::NotFound(format!("Operation '{}' not found in registry", operation_id))
            })?
        };

        let start = Instant::now();
        let exec_fut = op.execute(input, config, &ctx);

        let result = tokio::select! {
            res = exec_fut => res,
            _ = tokio::time::sleep(timeout) => Err(OmniError::Timeout(timeout.as_millis() as u64)),
        };

        let duration_ms = start.elapsed().as_millis() as u64;

        {
            let mut contexts = self.contexts.write().unwrap();
            contexts.remove(&job_id);
        }

        match &result {
            Ok(output) => {
                self.db
                    .finish_job(&job_id, "completed", duration_ms as i64, None)?;
                let preview = match output {
                    DataPayload::Text(s) => s.chars().take(80).collect(),
                    DataPayload::Bytes(b) => format!("<{} bytes>", b.len()),
                    DataPayload::Json(v) => v.to_string().chars().take(80).collect(),
                    DataPayload::FileRef(p) => format!("<File: {}>", p.display()),
                };
                let _ = self.event_tx.send(JobEvent::Completed {
                    job_id,
                    duration_ms,
                    output_preview: preview,
                });
            }
            Err(e) => {
                let err_msg = e.to_string();
                self.db
                    .finish_job(&job_id, "failed", duration_ms as i64, Some(&err_msg))?;
                let _ = self.event_tx.send(JobEvent::Failed {
                    job_id,
                    duration_ms,
                    error: err_msg,
                });
            }
        }

        result
    }

    pub async fn run_pipeline(
        &self,
        pipeline: &PipelineDefinition,
        input: DataPayload,
        timeout: Duration,
    ) -> OmniResult<HashMap<String, DataPayload>> {
        let job_id = uuid::Uuid::new_v4().to_string();
        let (prog_tx, mut prog_rx) = mpsc::channel(32);

        let ctx = ExecutionContext::new(job_id.clone()).with_progress(prog_tx);
        {
            let mut contexts = self.contexts.write().unwrap();
            contexts.insert(job_id.clone(), ctx.clone());
        }

        self.db.insert_job(&job_id, &format!("pipeline:{}", pipeline.id))?;
        let _ = self.event_tx.send(JobEvent::Started {
            job_id: job_id.clone(),
            operation: format!("pipeline:{}", pipeline.id),
        });

        let evt_tx = self.event_tx.clone();
        let jid = job_id.clone();
        tokio::spawn(async move {
            while let Some(prog) = prog_rx.recv().await {
                let _ = evt_tx.send(JobEvent::Progress {
                    job_id: jid.clone(),
                    percent: prog.percent,
                    stage: prog.stage,
                    message: prog.message,
                });
            }
        });

        let start = Instant::now();
        let exec_fut = PipelineExecutor::execute(pipeline, input, &self.registry, &ctx);

        let result = tokio::select! {
            res = exec_fut => res,
            _ = tokio::time::sleep(timeout) => Err(OmniError::Timeout(timeout.as_millis() as u64)),
        };

        let duration_ms = start.elapsed().as_millis() as u64;

        {
            let mut contexts = self.contexts.write().unwrap();
            contexts.remove(&job_id);
        }

        match &result {
            Ok(output_map) => {
                self.db.finish_job(&job_id, "completed", duration_ms as i64, None)?;
                let _ = self.event_tx.send(JobEvent::Completed {
                    job_id,
                    duration_ms,
                    output_preview: format!("{} nodes executed", output_map.len()),
                });
            }
            Err(e) => {
                let err_msg = e.to_string();
                self.db.finish_job(&job_id, "failed", duration_ms as i64, Some(&err_msg))?;
                let _ = self.event_tx.send(JobEvent::Failed {
                    job_id,
                    duration_ms,
                    error: err_msg,
                });
            }
        }

        result
    }
}
