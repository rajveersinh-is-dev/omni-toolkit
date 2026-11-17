use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PipelineEdge {
    pub from_node: String,
    pub to_node: String,
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
}

impl PipelineDefinition {
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: None,
            nodes: Vec::new(),
            edges: Vec::new(),
        }
    }

    pub fn add_node(&mut self, id: impl Into<String>, operation_id: impl Into<String>, config: serde_json::Value) {
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
        });
    }
}
