use crate::model::PipelineDefinition;
use crate::validator::PipelineValidator;
use omni_core::{DataPayload, ExecutionContext, OmniError, OmniResult};
use omni_registry::OperationRegistry;
use std::collections::HashMap;
use std::sync::RwLock;

pub struct PipelineExecutor;

impl PipelineExecutor {
    pub async fn execute(
        pipeline: &PipelineDefinition,
        initial_input: DataPayload,
        registry: &RwLock<OperationRegistry>,
        ctx: &ExecutionContext,
    ) -> OmniResult<HashMap<String, DataPayload>> {
        let execution_order = {
            let reg = registry.read().map_err(|e| OmniError::Internal(e.to_string()))?;
            PipelineValidator::validate(pipeline, &reg)?
        };

        let mut node_outputs: HashMap<String, DataPayload> = HashMap::new();
        let nodes_by_id: HashMap<_, _> = pipeline.nodes.iter().map(|n| (&n.id, n)).collect();

        // Build inverted incoming edges map
        let mut incoming_edges: HashMap<&str, Vec<&str>> = HashMap::new();
        for edge in &pipeline.edges {
            incoming_edges
                .entry(&edge.to_node)
                .or_default()
                .push(&edge.from_node);
        }

        let total_nodes = execution_order.len();

        for (idx, node_id) in execution_order.iter().enumerate() {
            if ctx.is_cancelled() {
                return Err(OmniError::Cancelled);
            }

            let node = nodes_by_id.get(node_id).ok_or_else(|| {
                OmniError::Pipeline(format!("Node {} not found in pipeline definition", node_id))
            })?;

            let op = {
                let reg = registry.read().map_err(|e| OmniError::Internal(e.to_string()))?;
                reg.get(&node.operation_id).ok_or_else(|| {
                    OmniError::NotFound(format!("Operation {} not found in registry", node.operation_id))
                })?
            };

            // Determine input for this node
            let node_input = if let Some(parents) = incoming_edges.get(node_id.as_str()) {
                if parents.is_empty() {
                    initial_input.clone()
                } else {
                    let parent_id = parents[0];
                    node_outputs.get(parent_id).cloned().ok_or_else(|| {
                        OmniError::Pipeline(format!(
                            "Parent node '{}' output missing for node '{}'",
                            parent_id, node_id
                        ))
                    })?
                }
            } else {
                initial_input.clone()
            };

            ctx.report_progress(
                (idx as f32 / total_nodes as f32) * 100.0,
                format!("Running node {}", node_id),
                format!("Executing operation {}", node.operation_id),
            )
            .await;

            let output = op.execute(node_input, node.config.clone(), ctx).await?;
            node_outputs.insert(node_id.clone(), output);
        }

        ctx.report_progress(100.0, "Complete", "Pipeline execution finished successfully").await;

        Ok(node_outputs)
    }
}
