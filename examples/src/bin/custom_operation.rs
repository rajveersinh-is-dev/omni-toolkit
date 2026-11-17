//! Example: Implementing a custom OMNI Operation and registering it at runtime.

use omni_core::{
    async_trait, DataPayload, ExecutionContext, OmniResult,
    Operation, OperationCategory, OperationManifest,
};
use omni_registry::OperationRegistry;
use std::sync::Arc;

/// A custom operation that reverses every word in a text string.
struct WordReverseOp;

#[async_trait]
impl Operation for WordReverseOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "custom.word_reverse",
            "Word Reverser",
            "Reverses each whitespace-delimited word in a string",
            OperationCategory::TextAndCode,
        )
    }

    async fn execute(
        &self,
        input: DataPayload,
        _config: serde_json::Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let text = input.into_text()?;
        let reversed: String = text
            .split_whitespace()
            .map(|word| word.chars().rev().collect::<String>())
            .collect::<Vec<_>>()
            .join(" ");

        Ok(DataPayload::text(reversed))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== OMNI Example: Custom Operation Implementation ===\n");

    let mut registry = OperationRegistry::new();
    registry.register(Arc::new(WordReverseOp))?;

    let op = registry.get("custom.word_reverse").unwrap();
    let ctx = ExecutionContext::new("custom_op_job");

    let input = DataPayload::text("The quick brown fox jumps over the lazy dog");
    let output = op.execute(input, serde_json::json!({}), &ctx).await?;

    println!("Input : The quick brown fox jumps over the lazy dog");
    println!("Output: {}", output.as_str()?);

    Ok(())
}
