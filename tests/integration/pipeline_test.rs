use omni_core::{DataPayload, ExecutionContext};
use omni_crypto::register_crypto;
use omni_encoders::register_encoders;
use omni_pipeline::{PipelineDefinition, PipelineExecutor};
use omni_registry::OperationRegistry;
use std::sync::RwLock;

#[tokio::test]
async fn test_end_to_end_hash_and_encode_pipeline() {
    let mut registry = OperationRegistry::new();
    register_encoders(&mut registry).unwrap();
    register_crypto(&mut registry).unwrap();
    let registry = RwLock::new(registry);

    let mut pipeline = PipelineDefinition::new("e2e_pipeline", "End to End Pipeline");
    pipeline.add_node("hash_step", "crypto.hash.sha256", serde_json::json!({}));
    pipeline.add_node("encode_step", "encode.base16", serde_json::json!({}));
    pipeline.add_edge("hash_step", "encode_step");

    let input = DataPayload::text("Hello OMNI Integration Test");
    let ctx = ExecutionContext::new("integration_test_job");

    let results = PipelineExecutor::execute(&pipeline, input, &registry, &ctx)
        .await
        .expect("Pipeline execution must succeed");

    assert!(results.contains_key("hash_step"));
    assert!(results.contains_key("encode_step"));

    let hash_output = results.get("hash_step").unwrap().as_str().unwrap();
    let encode_output = results.get("encode_step").unwrap().as_str().unwrap();

    // Verify SHA-256 output is 64 hex characters
    assert_eq!(hash_output.len(), 64);
    // Base16 encoding of 64 hex chars is 128 characters
    assert_eq!(encode_output.len(), 128);
}

#[tokio::test]
async fn test_branching_dag_execution() {
    let mut registry = OperationRegistry::new();
    register_encoders(&mut registry).unwrap();
    register_crypto(&mut registry).unwrap();
    let registry = RwLock::new(registry);

    let mut pipeline = PipelineDefinition::new("branching_pipe", "Branching Pipeline");
    pipeline.add_node("branch_base64", "encode.base64", serde_json::json!({}));
    pipeline.add_node("branch_crc32", "checksum.crc32", serde_json::json!({}));

    let input = DataPayload::text("Branching test payload");
    let ctx = ExecutionContext::new("branching_test_job");

    let results = PipelineExecutor::execute(&pipeline, input, &registry, &ctx)
        .await
        .expect("Branching pipeline must succeed");

    assert!(results.contains_key("branch_base64"));
    assert!(results.contains_key("branch_crc32"));

    let b64 = results.get("branch_base64").unwrap().as_str().unwrap();
    assert!(!b64.is_empty());
}
