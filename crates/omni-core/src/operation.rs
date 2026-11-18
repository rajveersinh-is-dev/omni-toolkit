use crate::context::ExecutionContext;
use crate::error::{OmniError, OmniResult};
use crate::manifest::OperationManifest;
use crate::payload::DataPayload;
use async_trait::async_trait;
use std::collections::BTreeMap;

#[async_trait]
pub trait Operation: Send + Sync {
    fn manifest(&self) -> OperationManifest;

    async fn execute(
        &self,
        input: DataPayload,
        config: serde_json::Value,
        ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload>;

    /// Executes an operation receiving multiple named parent inputs in a DAG.
    /// Single-input operations automatically receive their single input when `inputs.len() == 1`.
    /// Operations that declare `accepts_multi_input = true` receive `DataPayload::Multi(inputs)`.
    async fn execute_multi(
        &self,
        mut inputs: BTreeMap<String, DataPayload>,
        config: serde_json::Value,
        ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let manifest = self.manifest();
        if inputs.is_empty() {
            return Err(OmniError::Pipeline(format!(
                "Operation '{}' received zero inputs",
                manifest.id
            )));
        }

        if inputs.len() == 1 && !manifest.accepts_multi_input {
            if let Some((_, single)) = inputs.pop_first() {
                return self.execute(single, config, ctx).await;
            }
        }

        if !manifest.accepts_multi_input {
            let keys: Vec<String> = inputs.keys().cloned().collect();
            return Err(OmniError::Pipeline(format!(
                "Operation '{}' does not accept multiple parent inputs (received {} inputs: {:?}). Insert a merge/join operation or use a multi-input operation.",
                manifest.id,
                keys.len(),
                keys
            )));
        }

        // Validate required named ports if declared
        for port in &manifest.input_ports {
            if port.required && !inputs.contains_key(&port.name) {
                return Err(OmniError::Pipeline(format!(
                    "Operation '{}' is missing required input port '{}'",
                    manifest.id, port.name
                )));
            }
        }

        self.execute(DataPayload::Multi(inputs), config, ctx).await
    }
}
