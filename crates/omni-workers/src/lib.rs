pub mod manager;

pub use manager::{JobEvent, JobManager};

#[cfg(test)]
mod tests {
    use super::*;
    use omni_core::{async_trait, DataPayload, ExecutionContext, OmniResult, Operation, OperationCategory, OperationManifest};
    use omni_registry::OperationRegistry;
    use omni_storage::DatabaseManager;
    use std::sync::{Arc, RwLock};
    use std::time::Duration;

    struct SleepOp;
    #[async_trait]
    impl Operation for SleepOp {
        fn manifest(&self) -> OperationManifest {
            OperationManifest::new("test.sleep", "Sleep", "Sleeps for test", OperationCategory::SystemDiagnostics)
        }
        async fn execute(&self, input: DataPayload, _config: serde_json::Value, ctx: &ExecutionContext) -> OmniResult<DataPayload> {
            for _ in 0..10 {
                if ctx.is_cancelled() {
                    return Err(omni_core::OmniError::Cancelled);
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Ok(input)
        }
    }

    #[tokio::test]
    async fn test_job_manager_run_and_events() {
        let mut reg = OperationRegistry::new();
        reg.register(Arc::new(SleepOp)).unwrap();
        let reg = Arc::new(RwLock::new(reg));
        let db = Arc::new(DatabaseManager::open_in_memory().unwrap());

        let mgr = JobManager::new(reg, db);
        let mut sub = mgr.subscribe();

        let input = DataPayload::text("test message");
        let res = mgr
            .run_operation("test.sleep", input, serde_json::json!({}), Duration::from_secs(5))
            .await;

        assert!(res.is_ok());
        assert_eq!(res.unwrap().as_str().unwrap(), "test message");

        // Verify broadcast events
        let mut event_count = 0;
        while let Ok(_evt) = sub.try_recv() {
            event_count += 1;
        }
        assert!(event_count >= 2); // Started & Completed
    }

    #[tokio::test]
    async fn test_job_manager_timeout() {
        let mut reg = OperationRegistry::new();
        reg.register(Arc::new(SleepOp)).unwrap();
        let reg = Arc::new(RwLock::new(reg));
        let db = Arc::new(DatabaseManager::open_in_memory().unwrap());

        let mgr = JobManager::new(reg, db);
        let input = DataPayload::text("timeout test");
        let res = mgr
            .run_operation("test.sleep", input, serde_json::json!({}), Duration::from_millis(50))
            .await;

        assert!(res.is_err());
        assert!(matches!(res.unwrap_err(), omni_core::OmniError::Timeout(_)));
    }
}
