pub mod executor;
pub mod model;
pub mod validator;

pub use executor::PipelineExecutor;
pub use model::{PipelineDefinition, PipelineEdge, PipelineNode};
pub use validator::PipelineValidator;

#[cfg(test)]
mod tests {
    use super::*;
    use omni_core::{async_trait, DataPayload, ExecutionContext, OmniResult, Operation, OperationCategory, OperationManifest};
    use omni_registry::OperationRegistry;
    use std::sync::{Arc, RwLock};

    struct UpperOp;
    #[async_trait]
    impl Operation for UpperOp {
        fn manifest(&self) -> OperationManifest {
            OperationManifest::new("text.upper", "To Uppercase", "Converts text to uppercase", OperationCategory::TextAndCode)
        }
        async fn execute(&self, input: DataPayload, _config: serde_json::Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
            let s = input.into_text()?.to_uppercase();
            Ok(DataPayload::text(s))
        }
    }

    struct ReverseOp;
    #[async_trait]
    impl Operation for ReverseOp {
        fn manifest(&self) -> OperationManifest {
            OperationManifest::new("text.reverse", "Reverse Text", "Reverses text", OperationCategory::TextAndCode)
        }
        async fn execute(&self, input: DataPayload, _config: serde_json::Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
            let s = input.into_text()?.chars().rev().collect::<String>();
            Ok(DataPayload::text(s))
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

        let ctx = ExecutionContext::new("job_1");
        let initial_input = DataPayload::text("hello");

        let results = PipelineExecutor::execute(&pipeline, initial_input, &reg, &ctx).await.unwrap();

        // node1: "HELLO", node2: "OLLEH"
        assert_eq!(results.get("node1").unwrap().as_str().unwrap(), "HELLO");
        assert_eq!(results.get("node2").unwrap().as_str().unwrap(), "OLLEH");
    }

    #[test]
    fn test_pipeline_cycle_detection() {
        let mut pipeline = PipelineDefinition::new("cycle_pipe", "Cycle Pipeline");
        pipeline.add_node("a", "op1", serde_json::json!({}));
        pipeline.add_node("b", "op2", serde_json::json!({}));
        pipeline.add_edge("a", "b");
        pipeline.add_edge("b", "a"); // Cycle!

        let sort_res = PipelineValidator::topological_sort(&pipeline);
        assert!(sort_res.is_err());
    }
}
