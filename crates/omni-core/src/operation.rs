use crate::context::ExecutionContext;
use crate::error::OmniResult;
use crate::manifest::OperationManifest;
use crate::payload::DataPayload;
use async_trait::async_trait;

#[async_trait]
pub trait Operation: Send + Sync {
    fn manifest(&self) -> OperationManifest;

    async fn execute(
        &self,
        input: DataPayload,
        config: serde_json::Value,
        ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload>;
}
