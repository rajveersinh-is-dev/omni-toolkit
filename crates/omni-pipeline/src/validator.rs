use crate::model::{PipelineDefinition, PipelineEdge};
use omni_core::{DataType, OmniError, OmniResult};
use omni_registry::OperationRegistry;
use std::collections::{BTreeSet, HashMap, HashSet};

pub struct PipelineValidator;

impl PipelineValidator {
    /// Performs deterministic Kahn topological sorting, rejecting duplicate nodes,
    /// self-loops, missing nodes, duplicate/conflicting edges, and cycles.
    pub fn topological_sort(pipeline: &PipelineDefinition) -> OmniResult<Vec<String>> {
        let mut node_ids: HashSet<&str> = HashSet::with_capacity(pipeline.nodes.len());

        for node in &pipeline.nodes {
            if node.id.trim().is_empty() {
                return Err(OmniError::Validation(
                    "Pipeline node ID must not be empty".into(),
                ));
            }
            if !node_ids.insert(node.id.as_str()) {
                return Err(OmniError::Validation(format!(
                    "Duplicate node ID '{}' found in pipeline",
                    node.id
                )));
            }
        }

        let mut in_degrees: HashMap<&str, usize> = HashMap::new();
        let mut adj_list: HashMap<&str, Vec<&str>> = HashMap::new();
        let mut seen_edges: HashSet<(&str, &str)> = HashSet::new();
        let mut seen_target_ports: HashSet<(&str, &str)> = HashSet::new();

        for node in &pipeline.nodes {
            in_degrees.insert(node.id.as_str(), 0);
            adj_list.insert(node.id.as_str(), Vec::new());
        }

        for edge in &pipeline.edges {
            if !node_ids.contains(edge.from_node.as_str()) {
                return Err(OmniError::Validation(format!(
                    "Edge refers to nonexistent source node '{}'",
                    edge.from_node
                )));
            }
            if !node_ids.contains(edge.to_node.as_str()) {
                return Err(OmniError::Validation(format!(
                    "Edge refers to nonexistent target node '{}'",
                    edge.to_node
                )));
            }
            if edge.from_node == edge.to_node {
                return Err(OmniError::Validation(format!(
                    "Self-loop detected on node '{}'",
                    edge.from_node
                )));
            }
            if !seen_edges.insert((edge.from_node.as_str(), edge.to_node.as_str())) {
                return Err(OmniError::Validation(format!(
                    "Duplicate edge from '{}' to '{}' detected",
                    edge.from_node, edge.to_node
                )));
            }
            let port = edge.effective_port();
            if !seen_target_ports.insert((edge.to_node.as_str(), port)) {
                return Err(OmniError::Validation(format!(
                    "Conflicting duplicate input port '{}' on node '{}'",
                    port, edge.to_node
                )));
            }

            if let Some(deg) = in_degrees.get_mut(edge.to_node.as_str()) {
                *deg += 1;
            }
            if let Some(adj) = adj_list.get_mut(edge.from_node.as_str()) {
                adj.push(edge.to_node.as_str());
            }
        }

        // BTreeSet guarantees deterministic alphabetical ordering of ready nodes
        let mut ready: BTreeSet<&str> = in_degrees
            .iter()
            .filter(|(_, &deg)| deg == 0)
            .map(|(&node, _)| node)
            .collect();

        let mut sorted = Vec::with_capacity(pipeline.nodes.len());

        while let Some(u) = ready.pop_first() {
            sorted.push(u.to_string());
            if let Some(neighbors) = adj_list.get(u) {
                for &v in neighbors {
                    if let Some(deg) = in_degrees.get_mut(v) {
                        *deg -= 1;
                        if *deg == 0 {
                            ready.insert(v);
                        }
                    }
                }
            }
        }

        if sorted.len() != pipeline.nodes.len() {
            return Err(OmniError::Validation(
                "Cycle detected in pipeline graph. Pipelines must be Directed Acyclic Graphs (DAGs)."
                    .into(),
            ));
        }

        Ok(sorted)
    }

    /// Validates graph topology, operation existence, multi-input port requirements,
    /// and static type compatibility across all edges.
    pub fn validate(
        pipeline: &PipelineDefinition,
        registry: &OperationRegistry,
    ) -> OmniResult<Vec<String>> {
        let mut manifests = HashMap::with_capacity(pipeline.nodes.len());

        for node in &pipeline.nodes {
            let op = registry.get(&node.operation_id).ok_or_else(|| {
                OmniError::NotFound(format!(
                    "Node '{}' references unknown operation '{}'",
                    node.id, node.operation_id
                ))
            })?;
            manifests.insert(node.id.as_str(), op.manifest());
        }

        let order = Self::topological_sort(pipeline)?;

        // Group incoming edges by target node for multi-input & type validation
        let mut incoming_by_target: HashMap<&str, Vec<&PipelineEdge>> = HashMap::new();
        for edge in &pipeline.edges {
            incoming_by_target
                .entry(edge.to_node.as_str())
                .or_default()
                .push(edge);
        }

        for (target_id, edges) in &incoming_by_target {
            let target_manifest = manifests.get(target_id).ok_or_else(|| {
                OmniError::Pipeline(format!("Target node '{}' missing manifest", target_id))
            })?;

            // Multi-input validation
            if edges.len() > 1 && !target_manifest.accepts_multi_input {
                return Err(OmniError::Validation(format!(
                    "Node '{}' (operation '{}') has {} incoming edges but does not support multiple parent inputs",
                    target_id,
                    target_manifest.id,
                    edges.len()
                )));
            }

            // Required named ports validation (only when ports are explicitly declared)
            if !target_manifest.input_ports.is_empty() && edges.len() > 1 {
                let wired_ports: HashSet<&str> = edges.iter().map(|e| e.effective_port()).collect();
                for port in &target_manifest.input_ports {
                    if port.required && !wired_ports.contains(port.name.as_str()) {
                        return Err(OmniError::Validation(format!(
                            "Node '{}' (operation '{}') is missing required incoming port '{}'",
                            target_id, target_manifest.id, port.name
                        )));
                    }
                }
            }

            // Edge-level static type compatibility check
            for edge in edges {
                let src_manifest = manifests.get(edge.from_node.as_str()).ok_or_else(|| {
                    OmniError::Pipeline(format!(
                        "Source node '{}' missing manifest",
                        edge.from_node
                    ))
                })?;

                let port_name = edge.effective_port();
                let port_spec = target_manifest
                    .input_ports
                    .iter()
                    .find(|p| p.name == port_name);

                let compatible = if let Some(spec) = port_spec {
                    spec.accepted_types.contains(&DataType::Any)
                        || src_manifest.output_types.contains(&DataType::Any)
                        || src_manifest.output_types.iter().any(|out| {
                            spec.accepted_types.contains(out)
                                || (*out == DataType::Text
                                    && spec.accepted_types.contains(&DataType::Bytes))
                        })
                } else {
                    target_manifest.accepts_output_from(&src_manifest.output_types)
                };

                if !compatible {
                    return Err(OmniError::TypeMismatch {
                        expected: format!(
                            "one of {:?} for node '{}' ({})",
                            target_manifest.input_types, target_id, target_manifest.id
                        ),
                        found: format!(
                            "outputs {:?} from node '{}' ({})",
                            src_manifest.output_types, edge.from_node, src_manifest.id
                        ),
                    });
                }
            }
        }

        Ok(order)
    }
}
