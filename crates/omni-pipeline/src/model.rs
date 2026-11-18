use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PipelineEdge {
    pub from_node: String,
    pub to_node: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_port: Option<String>,
}

impl PipelineEdge {
    /// Returns the effective deterministic input key for this edge on the target node.
    pub fn effective_port(&self) -> &str {
        self.input_port.as_deref().unwrap_or(self.from_node.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PipelineNode {
    pub id: String,
    pub operation_id: String,
    #[serde(default)]
    pub config: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PipelineDefinition {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub nodes: Vec<PipelineNode>,
    pub edges: Vec<PipelineEdge>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrency: Option<usize>,
}

impl PipelineDefinition {
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: None,
            nodes: Vec::new(),
            edges: Vec::new(),
            max_concurrency: None,
        }
    }

    pub fn with_max_concurrency(mut self, max_concurrency: usize) -> Self {
        self.max_concurrency = Some(max_concurrency.max(1));
        self
    }

    pub fn add_node(
        &mut self,
        id: impl Into<String>,
        operation_id: impl Into<String>,
        config: serde_json::Value,
    ) {
        self.nodes.push(PipelineNode {
            id: id.into(),
            operation_id: operation_id.into(),
            config,
        });
    }

    pub fn add_edge(&mut self, from_node: impl Into<String>, to_node: impl Into<String>) {
        self.edges.push(PipelineEdge {
            from_node: from_node.into(),
            to_node: to_node.into(),
            input_port: None,
        });
    }

    pub fn add_edge_to_port(
        &mut self,
        from_node: impl Into<String>,
        to_node: impl Into<String>,
        input_port: impl Into<String>,
    ) {
        self.edges.push(PipelineEdge {
            from_node: from_node.into(),
            to_node: to_node.into(),
            input_port: Some(input_port.into()),
        });
    }
}
