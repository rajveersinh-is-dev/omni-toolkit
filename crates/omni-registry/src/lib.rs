use omni_core::{
    DataType, FeatureStatus, OmniError, OmniResult, Operation, OperationCategory, OperationManifest,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};

#[derive(Debug, Default, Clone)]
pub struct RegistryFilter<'a> {
    pub category: Option<OperationCategory>,
    pub query: Option<&'a str>,
    pub tag: Option<&'a str>,
    pub input_type: Option<DataType>,
    pub output_type: Option<DataType>,
    pub status: Option<FeatureStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureInventoryEntry {
    pub id: String,
    pub name: String,
    pub category: OperationCategory,
    pub status: FeatureStatus,
    pub input_types: Vec<DataType>,
    pub output_types: Vec<DataType>,
    pub accepts_multi_input: bool,
    pub streaming_supported: bool,
    pub security_level: omni_core::SecurityClassification,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureInventoryReport {
    pub total_operations: usize,
    pub status_counts: BTreeMap<String, usize>,
    pub category_counts: BTreeMap<String, usize>,
    pub operations: Vec<FeatureInventoryEntry>,
}

#[derive(Default)]
pub struct OperationRegistry {
    operations: HashMap<String, Arc<dyn Operation>>,
}

impl OperationRegistry {
    pub fn new() -> Self {
        Self {
            operations: HashMap::new(),
        }
    }

    pub fn register(&mut self, op: Arc<dyn Operation>) -> OmniResult<()> {
        let manifest = op.manifest();
        if self.operations.contains_key(&manifest.id) {
            return Err(OmniError::Validation(format!(
                "Operation with ID '{}' is already registered",
                manifest.id
            )));
        }
        self.operations.insert(manifest.id, op);
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<Arc<dyn Operation>> {
        self.operations.get(id).cloned()
    }

    pub fn list_manifests(&self) -> Vec<OperationManifest> {
        let mut manifests: Vec<_> = self.operations.values().map(|op| op.manifest()).collect();
        manifests.sort_by(|a, b| a.id.cmp(&b.id));
        manifests
    }

    pub fn search(&self, query: &str) -> Vec<OperationManifest> {
        self.filter(&RegistryFilter {
            query: Some(query),
            ..Default::default()
        })
    }

    pub fn filter_by_category(&self, category: OperationCategory) -> Vec<OperationManifest> {
        self.filter(&RegistryFilter {
            category: Some(category),
            ..Default::default()
        })
    }

    pub fn filter_by_types(&self, input: DataType, output: DataType) -> Vec<OperationManifest> {
        self.filter(&RegistryFilter {
            input_type: Some(input),
            output_type: Some(output),
            ..Default::default()
        })
    }

    pub fn filter(&self, filter: &RegistryFilter<'_>) -> Vec<OperationManifest> {
        let q = filter.query.map(|s| s.to_lowercase());
        let tag = filter.tag.map(|s| s.to_lowercase());

        self.list_manifests()
            .into_iter()
            .filter(|m| {
                if let Some(cat) = filter.category {
                    if m.category != cat {
                        return false;
                    }
                }
                if let Some(status) = filter.status {
                    if m.status != status {
                        return false;
                    }
                }
                if let Some(ref in_ty) = filter.input_type {
                    if !m.input_types.contains(in_ty) && !m.input_types.contains(&DataType::Any) {
                        return false;
                    }
                }
                if let Some(ref out_ty) = filter.output_type {
                    if !m.output_types.contains(out_ty) && !m.output_types.contains(&DataType::Any) {
                        return false;
                    }
                }
                if let Some(ref req_tag) = tag {
                    if !m.tags.iter().any(|t| t.to_lowercase() == *req_tag) {
                        return false;
                    }
                }
                if let Some(ref q_str) = q {
                    if !q_str.is_empty() {
                        let matched = m.id.to_lowercase().contains(q_str)
                            || m.name.to_lowercase().contains(q_str)
                            || m.description.to_lowercase().contains(q_str)
                            || format!("{:?}", m.category).to_lowercase().contains(q_str)
                            || m.category.to_string().to_lowercase().contains(q_str)
                            || m.tags.iter().any(|t| t.to_lowercase().contains(q_str));
                        if !matched {
                            return false;
                        }
                    }
                }
                true
            })
            .collect()
    }

    pub fn export_inventory(&self) -> FeatureInventoryReport {
        let manifests = self.list_manifests();
        let mut status_counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut category_counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut operations = Vec::with_capacity(manifests.len());

        for m in manifests {
            *status_counts.entry(m.status.to_string()).or_insert(0) += 1;
            *category_counts.entry(m.category.to_string()).or_insert(0) += 1;
            operations.push(FeatureInventoryEntry {
                id: m.id,
                name: m.name,
                category: m.category,
                status: m.status,
                input_types: m.input_types,
                output_types: m.output_types,
                accepts_multi_input: m.accepts_multi_input,
                streaming_supported: m.streaming_supported,
                security_level: m.security_level,
                limitations: m.limitations,
            });
        }

        FeatureInventoryReport {
            total_operations: operations.len(),
            status_counts,
            category_counts,
            operations,
        }
    }

    pub fn len(&self) -> usize {
        self.operations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }
}

static GLOBAL_REGISTRY: std::sync::LazyLock<RwLock<OperationRegistry>> =
    std::sync::LazyLock::new(|| RwLock::new(OperationRegistry::new()));

pub fn global_registry() -> &'static RwLock<OperationRegistry> {
    &GLOBAL_REGISTRY
}

#[cfg(test)]
mod tests {
    use super::*;
    use omni_core::{async_trait, DataPayload, ExecutionContext};

    struct DummyOp;
    #[async_trait]
    impl Operation for DummyOp {
        fn manifest(&self) -> OperationManifest {
            OperationManifest::new(
                "dummy.echo",
                "Dummy Echo",
                "Echoes input text",
                OperationCategory::TextAndCode,
            )
            .with_status(FeatureStatus::Verified)
            .with_tags(vec!["echo".into(), "utility".into()])
        }
        async fn execute(
            &self,
            input: DataPayload,
            _config: serde_json::Value,
            _ctx: &ExecutionContext,
        ) -> OmniResult<DataPayload> {
            Ok(input)
        }
    }

    #[test]
    fn test_registry_registration_and_filtering() {
        let mut reg = OperationRegistry::new();
        assert_eq!(reg.len(), 0);

        reg.register(Arc::new(DummyOp)).unwrap();
        assert_eq!(reg.len(), 1);

        assert!(reg.get("dummy.echo").is_some());
        assert!(reg.get("nonexistent").is_none());

        let results = reg.search("echo");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "dummy.echo");

        // Filter by category
        assert_eq!(reg.filter_by_category(OperationCategory::TextAndCode).len(), 1);
        assert_eq!(reg.filter_by_category(OperationCategory::Cryptography).len(), 0);

        // Filter by status and tag
        let filtered = reg.filter(&RegistryFilter {
            status: Some(FeatureStatus::Verified),
            tag: Some("utility"),
            ..Default::default()
        });
        assert_eq!(filtered.len(), 1);

        // Inventory export
        let inv = reg.export_inventory();
        assert_eq!(inv.total_operations, 1);
        assert_eq!(inv.status_counts.get("verified"), Some(&1));

        // Duplicate registration must fail
        assert!(reg.register(Arc::new(DummyOp)).is_err());
    }
}
