use crate::model::PipelineDefinition;
use omni_core::{OmniError, OmniResult};
use omni_registry::OperationRegistry;
use std::collections::{HashMap, HashSet, VecDeque};

pub struct PipelineValidator;

impl PipelineValidator {
    pub fn topological_sort(pipeline: &PipelineDefinition) -> OmniResult<Vec<String>> {
        let node_ids: HashSet<_> = pipeline.nodes.iter().map(|n| n.id.as_str()).collect();

        // Check for duplicate node IDs
        if node_ids.len() != pipeline.nodes.len() {
            return Err(OmniError::Validation("Duplicate node IDs found in pipeline".into()));
        }

        let mut in_degrees: HashMap<&str, usize> = HashMap::new();
        let mut adj_list: HashMap<&str, Vec<&str>> = HashMap::new();

        for node in &pipeline.nodes {
            in_degrees.insert(&node.id, 0);
            adj_list.insert(&node.id, Vec::new());
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

            *in_degrees.entry(&edge.to_node).or_insert(0) += 1;
            adj_list.entry(&edge.from_node).or_default().push(&edge.to_node);
        }

        let mut queue: VecDeque<&str> = in_degrees
            .iter()
            .filter(|(_, &deg)| deg == 0)
            .map(|(&node, _)| node)
            .collect();

        let mut sorted = Vec::new();

        while let Some(u) = queue.pop_front() {
            sorted.push(u.to_string());
            if let Some(neighbors) = adj_list.get(u) {
                for &v in neighbors {
                    let deg = in_degrees.get_mut(v).unwrap();
                    *deg -= 1;
                    if *deg == 0 {
                        queue.push_back(v);
                    }
                }
            }
        }

        if sorted.len() != pipeline.nodes.len() {
            return Err(OmniError::Validation(
                "Cycle detected in pipeline graph. Pipelines must be Directed Acyclic Graphs (DAGs).".into(),
            ));
        }

        Ok(sorted)
    }

    pub fn validate(pipeline: &PipelineDefinition, registry: &OperationRegistry) -> OmniResult<Vec<String>> {
        for node in &pipeline.nodes {
            if registry.get(&node.operation_id).is_none() {
                return Err(OmniError::NotFound(format!(
                    "Node '{}' references unknown operation '{}'",
                    node.id, node.operation_id
                )));
            }
        }

        Self::topological_sort(pipeline)
    }
}
