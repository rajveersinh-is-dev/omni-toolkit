//! Example: Constructing and executing a multi-stage DAG pipeline programmatically.

use omni_core::{DataPayload, ExecutionContext};
use omni_crypto::register_crypto;
use omni_encoders::register_encoders;
use omni_pipeline::{PipelineDefinition, PipelineExecutor};
use omni_registry::OperationRegistry;
use std::sync::RwLock;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== OMNI Example: Programmatic Pipeline Composition ===\n");

    // 1. Initialize central registry and register desired crates
    let mut registry = OperationRegistry::new();
    register_encoders(&mut registry)?;
    register_crypto(&mut registry)?;
    let registry = RwLock::new(registry);

    // 2. Build a DAG pipeline: Input -> SHA-256 Digest -> Base16 Hex String
    let mut pipeline = PipelineDefinition::new("demo_pipeline", "Demonstration Pipeline");
    pipeline.add_node("hash_node", "crypto.hash.sha256", serde_json::json!({}));
    pipeline.add_node("encode_node", "encode.base16", serde_json::json!({}));
    pipeline.add_edge("hash_node", "encode_node");

    // 3. Provide input payload and execute DAG
    let input = DataPayload::text("Hello, OMNI Unified Processing Engine!");
    let ctx = ExecutionContext::new("example_job");

    let results = PipelineExecutor::execute(&pipeline, input, &registry, &ctx).await?;

    for (node_id, payload) in results {
        println!("Node [{}]:", node_id);
        println!("  Output Type : {:?}", payload.data_type());
        println!("  Value       : {}\n", payload.as_str()?);
    }

    Ok(())
}
