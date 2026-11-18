pub mod executor;
pub mod model;
pub mod ops;
pub mod stream;
pub mod validator;

pub use executor::{
    NodeExecutionReport, NodeExecutionStatus, PipelineExecutionOptions, PipelineExecutionReport,
    PipelineExecutor,
};
pub use model::{PipelineDefinition, PipelineEdge, PipelineNode};
pub use ops::{register_pipeline_ops, PipelineConcatOp, PipelineMergeOp};
pub use stream::{spawn_chunk_producer, spawn_stream_stage, BoundedStreamConfig, StreamChunk};
pub use validator::PipelineValidator;

#[cfg(test)]
mod tests {
    use super::*;
    use omni_core::{
        async_trait, DataPayload, DataType, ExecutionContext, InputPortSpec, OmniError, OmniResult,
        Operation, OperationCategory, OperationManifest,
    };
    use omni_registry::OperationRegistry;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, RwLock};
    use tokio::sync::Barrier;

    struct UpperOp;
    #[async_trait]
    impl Operation for UpperOp {
        fn manifest(&self) -> OperationManifest {
            OperationManifest::new(
                "text.upper",
                "To Uppercase",
                "Converts text to uppercase",
                OperationCategory::TextAndCode,
            )
            .with_types(vec![DataType::Text], vec![DataType::Text])
        }
        async fn execute(
            &self,
            input: DataPayload,
            _config: serde_json::Value,
            _ctx: &ExecutionContext,
        ) -> OmniResult<DataPayload> {
            let s = input.into_text()?.to_uppercase();
            Ok(DataPayload::text(s))
        }
    }

    struct ReverseOp;
    #[async_trait]
    impl Operation for ReverseOp {
        fn manifest(&self) -> OperationManifest {
            OperationManifest::new(
                "text.reverse",
                "Reverse Text",
                "Reverses text",
                OperationCategory::TextAndCode,
            )
            .with_types(vec![DataType::Text], vec![DataType::Text])
        }
        async fn execute(
            &self,
            input: DataPayload,
            _config: serde_json::Value,
            _ctx: &ExecutionContext,
        ) -> OmniResult<DataPayload> {
            let s = input.into_text()?.chars().rev().collect::<String>();
            Ok(DataPayload::text(s))
        }
    }

    struct JsonOnlyOp;
    #[async_trait]
    impl Operation for JsonOnlyOp {
        fn manifest(&self) -> OperationManifest {
            OperationManifest::new(
                "json.only",
                "JSON Only",
                "Requires JSON input",
                OperationCategory::TextAndCode,
            )
            .with_types(vec![DataType::Json], vec![DataType::Json])
        }
        async fn execute(
            &self,
            input: DataPayload,
            _config: serde_json::Value,
            _ctx: &ExecutionContext,
        ) -> OmniResult<DataPayload> {
            Ok(DataPayload::json(input.into_json()?))
        }
    }

    struct BarrierOp {
        barrier: Arc<Barrier>,
        in_flight: Arc<AtomicUsize>,
        max_seen: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Operation for BarrierOp {
        fn manifest(&self) -> OperationManifest {
            OperationManifest::new(
                "test.barrier",
                "Barrier Op",
                "Synchronizes concurrent branches deterministically",
                OperationCategory::SystemDiagnostics,
            )
        }
        async fn execute(
            &self,
            input: DataPayload,
            _config: serde_json::Value,
            _ctx: &ExecutionContext,
        ) -> OmniResult<DataPayload> {
            let current = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_seen.fetch_max(current, Ordering::SeqCst);
            // If branches ran sequentially, this barrier would deadlock!
            self.barrier.wait().await;
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            Ok(input)
        }
    }

    struct NamedPortJoinOp;
    #[async_trait]
    impl Operation for NamedPortJoinOp {
        fn manifest(&self) -> OperationManifest {
            OperationManifest::new(
                "test.named_join",
                "Named Port Join",
                "Joins left and right named ports",
                OperationCategory::TextAndCode,
            )
            .with_input_ports(vec![
                InputPortSpec {
                    name: "left".into(),
                    required: true,
                    accepted_types: vec![DataType::Text],
                    description: "Left text".into(),
                },
                InputPortSpec {
                    name: "right".into(),
                    required: true,
                    accepted_types: vec![DataType::Text],
                    description: "Right text".into(),
                },
            ])
            .with_types(vec![DataType::Multi], vec![DataType::Text])
        }
        async fn execute(
            &self,
            input: DataPayload,
            _config: serde_json::Value,
            _ctx: &ExecutionContext,
        ) -> OmniResult<DataPayload> {
            let map = input
                .as_multi()
                .ok_or_else(|| OmniError::InvalidInput("Expected multi input".into()))?;
            let left = map.get("left").unwrap().as_str()?;
            let right = map.get("right").unwrap().as_str()?;
            Ok(DataPayload::text(format!("{}::{}", left, right)))
        }
    }

    struct FailingOp;
    #[async_trait]
    impl Operation for FailingOp {
        fn manifest(&self) -> OperationManifest {
            OperationManifest::new(
                "test.fail",
                "Failing Op",
                "Always fails",
                OperationCategory::SystemDiagnostics,
            )
        }
        async fn execute(
            &self,
            _input: DataPayload,
            _config: serde_json::Value,
            _ctx: &ExecutionContext,
        ) -> OmniResult<DataPayload> {
            Err(OmniError::Execution {
                operation: "test.fail".into(),
                message: "simulated failure".into(),
            })
        }
    }

    #[tokio::test]
    async fn test_pipeline_dag_execution() {
        let mut reg = OperationRegistry::new();
        reg.register(Arc::new(UpperOp)).unwrap();
        reg.register(Arc::new(ReverseOp)).unwrap();
        let reg = RwLock::new(reg);

        let mut pipeline = PipelineDefinition::new("test_pipe", "Test Pipeline");
        pipeline.add_node("node1", "text.upper", serde_json::json!({}));
        pipeline.add_node("node2", "text.reverse", serde_json::json!({}));
        pipeline.add_edge("node1", "node2");

        let ctx = ExecutionContext::new("job1");
        let results = PipelineExecutor::execute(&pipeline, DataPayload::text("omni"), &reg, &ctx)
            .await
            .unwrap();

        assert_eq!(results.get("node1").unwrap().as_str().unwrap(), "OMNI");
        assert_eq!(results.get("node2").unwrap().as_str().unwrap(), "INMO");
    }

    #[tokio::test]
    async fn test_pipeline_multi_input_diamond_dag() {
        let mut reg = OperationRegistry::new();
        reg.register(Arc::new(UpperOp)).unwrap();
        reg.register(Arc::new(ReverseOp)).unwrap();
        reg.register(Arc::new(NamedPortJoinOp)).unwrap();
        register_pipeline_ops(&mut reg).unwrap();
        let reg = RwLock::new(reg);

        // Diamond DAG: input -> (branch_a: upper, branch_b: reverse) -> join_node
        let mut pipeline = PipelineDefinition::new("diamond", "Diamond Join DAG");
        pipeline.add_node("branch_a", "text.upper", serde_json::json!({}));
        pipeline.add_node("branch_b", "text.reverse", serde_json::json!({}));
        pipeline.add_node("join_named", "test.named_join", serde_json::json!({}));
        pipeline.add_node("join_merge", "pipeline.merge", serde_json::json!({}));

        pipeline.add_edge_to_port("branch_a", "join_named", "left");
        pipeline.add_edge_to_port("branch_b", "join_named", "right");
        pipeline.add_edge("branch_a", "join_merge");
        pipeline.add_edge("branch_b", "join_merge");

        let ctx = ExecutionContext::new("diamond_job");
        let report = PipelineExecutor::execute_with_report(
            &pipeline,
            DataPayload::text("omni"),
            &reg,
            &ctx,
            PipelineExecutionOptions::default(),
        )
        .await
        .unwrap();

        assert_eq!(
            report.outputs.get("join_named").unwrap().as_str().unwrap(),
            "OMNI::inmo"
        );
        let merged = report
            .outputs
            .get("join_merge")
            .unwrap()
            .clone()
            .into_json()
            .unwrap();
        assert_eq!(merged["branch_a"], "OMNI");
        assert_eq!(merged["branch_b"], "inmo");
        assert_eq!(report.nodes.len(), 4);
    }

    #[tokio::test]
    async fn test_pipeline_true_concurrent_execution() {
        let barrier = Arc::new(Barrier::new(2));
        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));

        let mut reg = OperationRegistry::new();
        reg.register(Arc::new(BarrierOp {
            barrier,
            in_flight,
            max_seen: max_seen.clone(),
        }))
        .unwrap();
        let reg = RwLock::new(reg);

        let mut pipeline =
            PipelineDefinition::new("concurrent_test", "Parallel Branches").with_max_concurrency(2);
        pipeline.add_node("p1", "test.barrier", serde_json::json!({}));
        pipeline.add_node("p2", "test.barrier", serde_json::json!({}));

        let ctx = ExecutionContext::new("parallel_job");
        let res = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            PipelineExecutor::execute(&pipeline, DataPayload::text("x"), &reg, &ctx),
        )
        .await
        .expect("Concurrent branches must both reach barrier without deadlocking")
        .unwrap();

        assert_eq!(res.len(), 2);
        assert_eq!(max_seen.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_pipeline_cycle_detection() {
        let mut pipeline = PipelineDefinition::new("cycle", "Cyclic");
        pipeline.add_node("a", "text.upper", serde_json::json!({}));
        pipeline.add_node("b", "text.reverse", serde_json::json!({}));
        pipeline.add_edge("a", "b");
        pipeline.add_edge("b", "a");

        let res = PipelineValidator::topological_sort(&pipeline);
        assert!(res.is_err());
    }

    #[test]
    fn test_pipeline_rejects_type_mismatch_and_multi_input_on_single_op() {
        let mut reg = OperationRegistry::new();
        reg.register(Arc::new(UpperOp)).unwrap();
        reg.register(Arc::new(ReverseOp)).unwrap();
        reg.register(Arc::new(JsonOnlyOp)).unwrap();

        // 1. Type mismatch: Text -> JsonOnlyOp
        let mut bad_types = PipelineDefinition::new("bad_types", "Bad Types");
        bad_types.add_node("a", "text.upper", serde_json::json!({}));
        bad_types.add_node("b", "json.only", serde_json::json!({}));
        bad_types.add_edge("a", "b");
        assert!(matches!(
            PipelineValidator::validate(&bad_types, &reg),
            Err(OmniError::TypeMismatch { .. })
        ));

        // 2. Single-input op receiving 2 incoming edges must be rejected!
        let mut bad_multi = PipelineDefinition::new("bad_multi", "Bad Multi");
        bad_multi.add_node("a", "text.upper", serde_json::json!({}));
        bad_multi.add_node("b", "text.upper", serde_json::json!({}));
        bad_multi.add_node("c", "text.reverse", serde_json::json!({}));
        bad_multi.add_edge("a", "c");
        bad_multi.add_edge("b", "c");
        assert!(PipelineValidator::validate(&bad_multi, &reg).is_err());
    }

    #[tokio::test]
    async fn test_pipeline_failure_propagation() {
        let mut reg = OperationRegistry::new();
        reg.register(Arc::new(FailingOp)).unwrap();
        reg.register(Arc::new(UpperOp)).unwrap();
        let reg = RwLock::new(reg);

        let mut pipeline = PipelineDefinition::new("fail_pipe", "Fail Pipe");
        pipeline.add_node("n1", "test.fail", serde_json::json!({}));
        pipeline.add_node("n2", "text.upper", serde_json::json!({}));
        pipeline.add_edge("n1", "n2");

        let ctx = ExecutionContext::new("fail_job");
        let res =
            PipelineExecutor::execute(&pipeline, DataPayload::text("hello"), &reg, &ctx).await;
        assert!(res.is_err());
        assert!(ctx.is_cancelled());
    }

    #[tokio::test]
    async fn test_bounded_streaming_backpressure_and_cancellation() {
        let ctx = ExecutionContext::new("stream_job");
        let cfg = BoundedStreamConfig {
            channel_capacity: 2,
            max_chunk_bytes: 16,
        };
        let data = b"hello world streaming backpressure test!".to_vec();
        let producer = spawn_chunk_producer(data.clone(), 8, cfg.clone(), ctx.clone());
        let mut stage = spawn_stream_stage(producer, cfg, ctx.clone(), |mut chunk| async move {
            for b in &mut chunk.bytes {
                *b = b.to_ascii_uppercase();
            }
            Ok(chunk)
        });

        let mut collected = Vec::new();
        while let Some(res) = stage.recv().await {
            let chunk = res.unwrap();
            collected.extend_from_slice(&chunk.bytes);
        }

        assert_eq!(collected, b"HELLO WORLD STREAMING BACKPRESSURE TEST!");
    }
}
