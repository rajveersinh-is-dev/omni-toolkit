use omni_core::{OperationManifest, ResourceRequirements, SecurityClassification};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PluginKind {
    Wasm,
    NativeDynamic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub author: String,
    pub license: String,
    pub description: String,
    pub kind: PluginKind,
    pub entrypoint: String,
    pub operations: Vec<OperationManifest>,
    pub security: SecurityClassification,
    pub resource_limits: ResourceRequirements,
}

impl PluginManifest {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        version: impl Into<String>,
        kind: PluginKind,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            version: version.into(),
            author: String::new(),
            license: "MIT".into(),
            description: String::new(),
            kind,
            entrypoint: String::new(),
            operations: Vec::new(),
            security: SecurityClassification::Safe,
            resource_limits: ResourceRequirements::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_manifest_serialization() {
        let manifest = PluginManifest::new("custom.rot13", "Custom ROT13 Plugin", "1.0.0", PluginKind::Wasm);
        let json = serde_json::to_string(&manifest).unwrap();
        assert!(json.contains("custom.rot13"));
        let de: PluginManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(de.id, "custom.rot13");
        assert_eq!(de.kind, PluginKind::Wasm);
    }
}
