pub mod manager;

pub use manager::{JobEvent, JobManager, JobStatus};

#[cfg(test)]
mod tests {
    use super::*;
    use omni_core::{
        async_trait, DataPayload, ExecutionContext, OmniError, OmniResult, Operation,
        OperationCategory, OperationManifest,
    };
    use omni_registry::OperationRegistry;
    use omni_storage::DatabaseManager;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, RwLock};
    use std::time::Duration;

    struct SlowOp {
        delay_ms: u64,
        saw_cancel: Arc<AtomicBool>,
    }

    #[async_trait]
    impl Operation for SlowOp {
        fn manifest(&self) -> OperationManifest {
            OperationManifest::new(
                "test.slow",
                "Slow Op",
                "Waits for delay or cancellation",
                OperationCategory::SystemDiagnostics,
            )
        }
        async fn execute(
            &self,
            input: DataPayload,
            _config: serde_json::Value,
            ctx: &ExecutionContext,
        ) -> OmniResult<DataPayload> {
            ctx.report_progress(50.0, "Working", "Halfway").await;
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(self.delay_ms)) => Ok(input),
                _ = ctx.cancelled() => {
                    self.saw_cancel.store(true, Ordering::SeqCst);
                    Err(OmniError::Cancelled)
                }
            }
        }
    }

    struct PanicOp;
    #[async_trait]
    impl Operation for PanicOp {
        fn manifest(&self) -> OperationManifest {
            OperationManifest::new(
                "test.panic",
                "Panic Op",
                "Panics to verify worker isolation",
                OperationCategory::SystemDiagnostics,
            )
        }
        async fn execute(
            &self,
            _input: DataPayload,
            _config: serde_json::Value,
            _ctx: &ExecutionContext,
        ) -> OmniResult<DataPayload> {
            panic!("intentional test worker panic");
        }
    }

    #[tokio::test]
    async fn test_job_manager_run_and_events() {
        let mut reg = OperationRegistry::new();
        reg.register(Arc::new(SlowOp {
            delay_ms: 20,
            saw_cancel: Arc::new(AtomicBool::new(false)),
        }))
        .unwrap();
        let reg = Arc::new(RwLock::new(reg));
        let db = Arc::new(DatabaseManager::open_in_memory().unwrap());
        let mgr = JobManager::new(reg, db.clone());

        let mut rx = mgr.subscribe();
        let (job_id, res) = mgr
            .run_operation_with_id(
                "test.slow",
                DataPayload::text("ping"),
                serde_json::json!({}),
                Duration::from_secs(2),
            )
            .await
            .unwrap();

        assert_eq!(res.as_str().unwrap(), "ping");
        assert_eq!(mgr.active_job_count(), 0);
        let rec = db.get_job(&job_id).unwrap().unwrap();
        assert_eq!(rec.status, "completed");

        let mut saw_started = false;
        let mut saw_completed = false;
        while let Ok(evt) = rx.try_recv() {
            match evt {
                JobEvent::Started { .. } => saw_started = true,
                JobEvent::Completed { .. } => saw_completed = true,
                _ => {}
            }
        }
        assert!(saw_started);
        assert!(saw_completed);
    }

    #[tokio::test]
    async fn test_job_manager_timeout_cancels_worker_and_cleans_up() {
        let saw_cancel = Arc::new(AtomicBool::new(false));
        let mut reg = OperationRegistry::new();
        reg.register(Arc::new(SlowOp {
            delay_ms: 5000,
            saw_cancel: saw_cancel.clone(),
        }))
        .unwrap();
        let reg = Arc::new(RwLock::new(reg));
        let db = Arc::new(DatabaseManager::open_in_memory().unwrap());
        let mgr = JobManager::new(reg, db.clone());

        let res = mgr
            .run_operation(
                "test.slow",
                DataPayload::text("ping"),
                serde_json::json!({}),
                Duration::from_millis(40),
            )
            .await;

        assert!(matches!(res, Err(OmniError::Timeout(_))));
        assert_eq!(mgr.active_job_count(), 0);
        let jobs = db.list_jobs(10).unwrap();
        assert_eq!(jobs[0].status, "timed_out");
    }

    #[tokio::test]
    async fn test_job_manager_panic_isolation_and_cleanup() {
        let mut reg = OperationRegistry::new();
        reg.register(Arc::new(PanicOp)).unwrap();
        let reg = Arc::new(RwLock::new(reg));
        let db = Arc::new(DatabaseManager::open_in_memory().unwrap());
        let mgr = JobManager::new(reg, db.clone());

        let res = mgr
            .run_operation(
                "test.panic",
                DataPayload::text("boom"),
                serde_json::json!({}),
                Duration::from_secs(2),
            )
            .await;

        assert!(matches!(res, Err(OmniError::Internal(_))));
        assert_eq!(mgr.active_job_count(), 0);
        let jobs = db.list_jobs(10).unwrap();
        assert_eq!(jobs[0].status, "failed");
    }

    #[tokio::test]
    async fn test_job_manager_shutdown_cancels_inflight() {
        let saw_cancel = Arc::new(AtomicBool::new(false));
        let mut reg = OperationRegistry::new();
        reg.register(Arc::new(SlowOp {
            delay_ms: 5000,
            saw_cancel: saw_cancel.clone(),
        }))
        .unwrap();
        let reg = Arc::new(RwLock::new(reg));
        let db = Arc::new(DatabaseManager::open_in_memory().unwrap());
        let mgr = JobManager::new(reg, db);

        let mgr_bg = mgr.clone();
        let handle = tokio::spawn(async move {
            mgr_bg
                .run_operation(
                    "test.slow",
                    DataPayload::text("wait"),
                    serde_json::json!({}),
                    Duration::from_secs(10),
                )
                .await
        });

        // Wait until job registers as active
        for _ in 0..50 {
            if mgr.active_job_count() > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(mgr.shutdown(), 1);
        let res = handle.await.unwrap();
        assert!(matches!(res, Err(OmniError::Cancelled)));
        assert_eq!(mgr.active_job_count(), 0);
    }

    #[test]
    fn test_job_status_state_transitions() {
        assert!(JobStatus::Queued.can_transition_to(JobStatus::Running));
        assert!(JobStatus::Running.can_transition_to(JobStatus::Completed));
        assert!(JobStatus::Running.can_transition_to(JobStatus::TimedOut));
        assert!(!JobStatus::Completed.can_transition_to(JobStatus::Running));
        assert!(!JobStatus::Cancelled.can_transition_to(JobStatus::Completed));
    }
}
