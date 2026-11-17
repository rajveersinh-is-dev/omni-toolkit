use omni_core::{DataType, OmniError, OmniResult, Operation, OperationCategory, OperationManifest};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

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
        let q = query.to_lowercase();
        self.list_manifests()
            .into_iter()
            .filter(|m| {
                m.id.to_lowercase().contains(&q)
                    || m.name.to_lowercase().contains(&q)
                    || m.description.to_lowercase().contains(&q)
                    || format!("{:?}", m.category).to_lowercase().contains(&q)
            })
            .collect()
    }

    pub fn filter_by_category(&self, category: OperationCategory) -> Vec<OperationManifest> {
        self.list_manifests()
            .into_iter()
            .filter(|m| m.category == category)
            .collect()
    }

    pub fn filter_by_types(&self, input: DataType, output: DataType) -> Vec<OperationManifest> {
        self.list_manifests()
            .into_iter()
            .filter(|m| {
                (m.input_types.contains(&input) || m.input_types.contains(&DataType::Any))
                    && (m.output_types.contains(&output) || m.output_types.contains(&DataType::Any))
            })
            .collect()
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
            OperationManifest::new("dummy.echo", "Dummy Echo", "Echoes input text", OperationCategory::TextAndCode)
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
    fn test_registry_registration_and_search() {
        let mut reg = OperationRegistry::new();
        assert_eq!(reg.len(), 0);

        reg.register(Arc::new(DummyOp)).unwrap();
        assert_eq!(reg.len(), 1);

        assert!(reg.get("dummy.echo").is_some());
        assert!(reg.get("nonexistent").is_none());

        let results = reg.search("echo");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "dummy.echo");

        // Duplicate registration must fail
        assert!(reg.register(Arc::new(DummyOp)).is_err());
    }
}
