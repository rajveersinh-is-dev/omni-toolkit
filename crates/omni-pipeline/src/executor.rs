use crate::model::{PipelineDefinition, PipelineEdge};
use crate::validator::PipelineValidator;
use chrono::Utc;
use omni_core::{DataPayload, ExecutionContext, OmniError, OmniResult, Operation};
use omni_registry::OperationRegistry;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeExecutionStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeExecutionReport {
    pub node_id: String,
    pub operation_id: String,
    pub status: NodeExecutionStatus,
    pub dependencies: Vec<String>,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub duration_ms: Option<u64>,
    pub output_bytes: Option<usize>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineExecutionReport {
    pub execution_id: String,
    pub pipeline_id: String,
    pub status: NodeExecutionStatus,
    pub started_at: String,
    pub finished_at: String,
    pub total_duration_ms: u64,
    pub nodes: Vec<NodeExecutionReport>,
    pub outputs: HashMap<String, DataPayload>,
}

#[derive(Debug, Clone)]
pub struct PipelineExecutionOptions {
    pub max_concurrency: usize,
    pub max_total_output_bytes: usize,
}

impl Default for PipelineExecutionOptions {
    fn default() -> Self {
        Self {
            max_concurrency: 4,
            max_total_output_bytes: 256 * 1024 * 1024, // 256 MB bounded aggregate outputs
        }
    }
}

struct NodeTaskOutput {
    node_id: String,
    started_at: String,
    finished_at: String,
    duration_ms: u64,
    result: OmniResult<DataPayload>,
}

pub struct PipelineExecutor;

impl PipelineExecutor {
    /// Executes a validated DAG pipeline concurrently up to configured concurrency limits,
    /// returning node outputs keyed by node ID.
    pub async fn execute(
        pipeline: &PipelineDefinition,
        initial_input: DataPayload,
        registry: &RwLock<OperationRegistry>,
        ctx: &ExecutionContext,
    ) -> OmniResult<HashMap<String, DataPayload>> {
        let options = PipelineExecutionOptions {
            max_concurrency: pipeline.max_concurrency.unwrap_or(4).max(1),
            ..Default::default()
        };
        let report =
            Self::execute_with_report(pipeline, initial_input, registry, ctx, options).await?;
        Ok(report.outputs)
    }

    /// Executes a DAG pipeline with full per-node observability, bounded concurrency,
    /// multi-parent input assembly, and immediate cancellation/error propagation.
    pub async fn execute_with_report(
        pipeline: &PipelineDefinition,
        initial_input: DataPayload,
        registry: &RwLock<OperationRegistry>,
        ctx: &ExecutionContext,
        options: PipelineExecutionOptions,
    ) -> OmniResult<PipelineExecutionReport> {
        let execution_id = uuid::Uuid::new_v4().to_string();
        let pipeline_started_at = Utc::now().to_rfc3339();
        let pipeline_start_instant = Instant::now();

        // 1. Validate DAG topology, operations, multi-input contracts, and edge types
        let (execution_order, ops_by_node) = {
            let reg = registry
                .read()
                .map_err(|e| OmniError::Internal(format!("Registry lock poisoned: {e}")))?;
            let order = PipelineValidator::validate(pipeline, &reg)?;
            let mut ops: HashMap<String, Arc<dyn Operation>> =
                HashMap::with_capacity(pipeline.nodes.len());
            for node in &pipeline.nodes {
                let op = reg.get(&node.operation_id).ok_or_else(|| {
                    OmniError::NotFound(format!(
                        "Operation '{}' not found in registry",
                        node.operation_id
                    ))
                })?;
                ops.insert(node.id.clone(), op);
            }
            (order, ops)
        };

        if pipeline.nodes.is_empty() {
            return Ok(PipelineExecutionReport {
                execution_id,
                pipeline_id: pipeline.id.clone(),
                status: NodeExecutionStatus::Completed,
                started_at: pipeline_started_at.clone(),
                finished_at: pipeline_started_at,
                total_duration_ms: 0,
                nodes: Vec::new(),
                outputs: HashMap::new(),
            });
        }

        // 2. Build dependency graph structures
        let nodes_by_id: HashMap<&str, &crate::model::PipelineNode> = pipeline
            .nodes
            .iter()
            .map(|n| (n.id.as_str(), n))
            .collect();

        let mut incoming_edges: HashMap<String, Vec<PipelineEdge>> = HashMap::new();
        let mut dependents: HashMap<String, Vec<String>> = HashMap::new();
        let mut remaining_deps: HashMap<String, usize> = HashMap::new();

        for node in &pipeline.nodes {
            incoming_edges.insert(node.id.clone(), Vec::new());
            dependents.insert(node.id.clone(), Vec::new());
            remaining_deps.insert(node.id.clone(), 0);
        }

        for edge in &pipeline.edges {
            if let Some(inc) = incoming_edges.get_mut(&edge.to_node) {
                inc.push(edge.clone());
            }
            if let Some(deps) = dependents.get_mut(&edge.from_node) {
                deps.push(edge.to_node.clone());
            }
            if let Some(cnt) = remaining_deps.get_mut(&edge.to_node) {
                *cnt += 1;
            }
        }

        // Deterministic ordering of incoming edges for every node
        for inc in incoming_edges.values_mut() {
            inc.sort_by(|a, b| {
                a.effective_port()
                    .cmp(b.effective_port())
                    .then_with(|| a.from_node.cmp(&b.from_node))
            });
        }

        let mut node_reports: HashMap<String, NodeExecutionReport> = pipeline
            .nodes
            .iter()
            .map(|n| {
                let deps = incoming_edges
                    .get(&n.id)
                    .map(|v| v.iter().map(|e| e.from_node.clone()).collect())
                    .unwrap_or_default();
                (
                    n.id.clone(),
                    NodeExecutionReport {
                        node_id: n.id.clone(),
                        operation_id: n.operation_id.clone(),
                        status: NodeExecutionStatus::Pending,
                        dependencies: deps,
                        started_at: None,
                        finished_at: None,
                        duration_ms: None,
                        output_bytes: None,
                        error: None,
                    },
                )
            })
            .collect();

        let total_nodes = execution_order.len();
        let mut completed_count = 0usize;
        let mut node_outputs: HashMap<String, DataPayload> = HashMap::with_capacity(total_nodes);
        let mut total_output_bytes = 0usize;

        let max_conc = pipeline
            .max_concurrency
            .unwrap_or(options.max_concurrency)
            .max(1);
        let semaphore = Arc::new(Semaphore::new(max_conc));
        let mut join_set: JoinSet<NodeTaskOutput> = JoinSet::new();

        // Helper closure-style spawning for ready nodes
        let spawn_node = |join_set: &mut JoinSet<NodeTaskOutput>,
                          node_id: String,
                          node_inputs: BTreeMap<String, DataPayload>,
                          op: Arc<dyn Operation>,
                          config: serde_json::Value,
                          ctx: ExecutionContext,
                          sem: Arc<Semaphore>| {
            join_set.spawn(async move {
                let permit = match sem.acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => {
                        let now = Utc::now().to_rfc3339();
                        return NodeTaskOutput {
                            node_id,
                            started_at: now.clone(),
                            finished_at: now,
                            duration_ms: 0,
                            result: Err(OmniError::Cancelled),
                        };
                    }
                };

                let started_at = Utc::now().to_rfc3339();
                let start = Instant::now();

                let result = if ctx.is_cancelled() {
                    Err(OmniError::Cancelled)
                } else {
                    tokio::select! {
                        res = op.execute_multi(node_inputs, config, &ctx) => res,
                        _ = ctx.cancelled() => Err(OmniError::Cancelled),
                    }
                };

                drop(permit);
                let duration_ms = start.elapsed().as_millis() as u64;
                let finished_at = Utc::now().to_rfc3339();

                NodeTaskOutput {
                    node_id,
                    started_at,
                    finished_at,
                    duration_ms,
                    result,
                }
            });
        };

        // 3. Seed initially ready root nodes (in_degree == 0) in deterministic topological order
        for node_id in &execution_order {
            if ctx.is_cancelled() {
                return Err(OmniError::Cancelled);
            }
            if remaining_deps.get(node_id).copied().unwrap_or(0) == 0 {
                let node = nodes_by_id.get(node_id.as_str()).ok_or_else(|| {
                    OmniError::Pipeline(format!("Node '{}' missing from pipeline", node_id))
                })?;
                let op = ops_by_node.get(node_id).cloned().ok_or_else(|| {
                    OmniError::NotFound(format!("Operation '{}' missing", node.operation_id))
                })?;
                let mut inputs = BTreeMap::new();
                inputs.insert("input".to_string(), initial_input.clone());

                if let Some(rep) = node_reports.get_mut(node_id) {
                    rep.status = NodeExecutionStatus::Running;
                }

                spawn_node(
                    &mut join_set,
                    node_id.clone(),
                    inputs,
                    op,
                    node.config.clone(),
                    ctx.clone(),
                    semaphore.clone(),
                );
            }
        }

        // 4. Event-driven concurrent DAG scheduling loop
        let mut first_error: Option<OmniError> = None;

        while !join_set.is_empty() {
            let next_res = tokio::select! {
                res = join_set.join_next() => res,
                _ = ctx.cancelled() => {
                    join_set.abort_all();
                    first_error = Some(OmniError::Cancelled);
                    break;
                }
            };

            let Some(join_result) = next_res else {
                break;
            };

            match join_result {
                Ok(task_out) => {
                    let node_id = task_out.node_id;
                    match task_out.result {
                        Ok(output_payload) => {
                            let size = output_payload.size_bytes();
                            total_output_bytes = total_output_bytes.saturating_add(size);
                            if total_output_bytes > options.max_total_output_bytes {
                                ctx.cancel();
                                join_set.abort_all();
                                first_error = Some(OmniError::Security(format!(
                                    "Aggregate pipeline output size ({} bytes) exceeded limit ({} bytes)",
                                    total_output_bytes, options.max_total_output_bytes
                                )));
                                break;
                            }

                            completed_count += 1;
                            if let Some(rep) = node_reports.get_mut(&node_id) {
                                rep.status = NodeExecutionStatus::Completed;
                                rep.started_at = Some(task_out.started_at);
                                rep.finished_at = Some(task_out.finished_at);
                                rep.duration_ms = Some(task_out.duration_ms);
                                rep.output_bytes = Some(size);
                            }

                            ctx.report_progress(
                                (completed_count as f32 / total_nodes as f32) * 100.0,
                                format!("Completed node {}", node_id),
                                format!("{}/{} nodes finished", completed_count, total_nodes),
                            )
                            .await;

                            node_outputs.insert(node_id.clone(), output_payload);

                            // Unlock dependent nodes whose dependencies are now all satisfied
                            if let Some(next_nodes) = dependents.get(&node_id) {
                                for child_id in next_nodes {
                                    if let Some(rem) = remaining_deps.get_mut(child_id) {
                                        *rem = rem.saturating_sub(1);
                                        if *rem == 0 {
                                            // Assemble ALL incoming parent inputs deterministically
                                            let mut child_inputs = BTreeMap::new();
                                            if let Some(edges) = incoming_edges.get(child_id) {
                                                for edge in edges {
                                                    let parent_out = node_outputs
                                                        .get(&edge.from_node)
                                                        .cloned()
                                                        .ok_or_else(|| {
                                                            OmniError::Pipeline(format!(
                                                                "Parent node '{}' output missing for node '{}'",
                                                                edge.from_node, child_id
                                                            ))
                                                        })?;
                                                    child_inputs.insert(
                                                        edge.effective_port().to_string(),
                                                        parent_out,
                                                    );
                                                }
                                            }

                                            let child_node = nodes_by_id
                                                .get(child_id.as_str())
                                                .ok_or_else(|| {
                                                    OmniError::Pipeline(format!(
                                                        "Child node '{}' missing",
                                                        child_id
                                                    ))
                                                })?;
                                            let child_op = ops_by_node
                                                .get(child_id)
                                                .cloned()
                                                .ok_or_else(|| {
                                                    OmniError::NotFound(format!(
                                                        "Operation '{}' missing",
                                                        child_node.operation_id
                                                    ))
                                                })?;

                                            if let Some(rep) = node_reports.get_mut(child_id) {
                                                rep.status = NodeExecutionStatus::Running;
                                            }

                                            spawn_node(
                                                &mut join_set,
                                                child_id.clone(),
                                                child_inputs,
                                                child_op,
                                                child_node.config.clone(),
                                                ctx.clone(),
                                                semaphore.clone(),
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            let is_cancel = matches!(err, OmniError::Cancelled);
                            if let Some(rep) = node_reports.get_mut(&node_id) {
                                rep.status = if is_cancel {
                                    NodeExecutionStatus::Cancelled
                                } else {
                                    NodeExecutionStatus::Failed
                                };
                                rep.started_at = Some(task_out.started_at);
                                rep.finished_at = Some(task_out.finished_at);
                                rep.duration_ms = Some(task_out.duration_ms);
                                rep.error = Some(err.to_string());
                            }
                            ctx.cancel();
                            join_set.abort_all();
                            first_error = Some(err);
                            break;
                        }
                    }
                }
                Err(join_err) => {
                    ctx.cancel();
                    join_set.abort_all();
                    first_error = Some(OmniError::Internal(format!(
                        "Pipeline worker task aborted/panicked: {}",
                        join_err
                    )));
                    break;
                }
            }
        }

        // Drain any remaining aborted tasks cleanly
        while join_set.join_next().await.is_some() {}

        if let Some(err) = first_error {
            return Err(err);
        }

        ctx.report_progress(
            100.0,
            "Complete",
            "Pipeline execution finished successfully",
        )
        .await;

        let ordered_reports: Vec<NodeExecutionReport> = execution_order
            .iter()
            .filter_map(|id| node_reports.remove(id))
            .collect();

        Ok(PipelineExecutionReport {
            execution_id,
            pipeline_id: pipeline.id.clone(),
            status: NodeExecutionStatus::Completed,
            started_at: pipeline_started_at,
            finished_at: Utc::now().to_rfc3339(),
            total_duration_ms: pipeline_start_instant.elapsed().as_millis() as u64,
            nodes: ordered_reports,
            outputs: node_outputs,
        })
    }
}
