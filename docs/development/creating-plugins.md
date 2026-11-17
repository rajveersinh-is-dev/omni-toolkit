# Creating Custom Plugins for OMNI

The OMNI architecture is fully extensible. Through `omni-plugin-sdk` and `omni-core`, developers can write new operations in Rust or WebAssembly and integrate them seamlessly into the global registry.

---

## 1. The Operation Trait

Every tool in OMNI implements the asynchronous `Operation` trait:

```rust
use omni_core::{
    async_trait, DataPayload, ExecutionContext, OmniResult,
    Operation, OperationCategory, OperationManifest,
    ResourceRequirements, SecurityClassification
};
use serde_json::Value;

pub struct Rot13Op;

#[async_trait]
impl Operation for Rot13Op {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "custom.rot13",
            "ROT-13 Cipher",
            "Rotates ASCII letters by 13 positions",
            OperationCategory::Cryptography,
        )
    }

    async fn execute(
        &self,
        input: DataPayload,
        _config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let text = input.into_text()?;
        let transformed: String = text
            .chars()
            .map(|c| match c {
                'a'..='m' | 'A'..='M' => ((c as u8) + 13) as char,
                'n'..='z' | 'N'..='Z' => ((c as u8) - 13) as char,
                other => other,
            })
            .collect();
        Ok(DataPayload::text(transformed))
    }
}
```

---

## 2. Security and Resource Envelopes

Plugins must declare their security profile and resource constraints:
- `SecurityClassification`: `Safe`, `NetworkAccess`, `FileSystemAccess`, `ElevatedPrivilege`.
- `ResourceRequirements`: Maximum memory allocation, timeout duration, CPU core allowance.

```rust
let mut manifest = OperationManifest::new(
    "custom.analyzer",
    "Deep Analyzer",
    "Parses complex binary formats",
    OperationCategory::BinaryAnalysis,
);
manifest.security = SecurityClassification::Safe;
manifest.resources.max_memory_bytes = 256 * 1024 * 1024; // 256 MB
manifest.resources.timeout_seconds = 30;
```

---

## 3. Registering Plugins

Custom operations can be registered at runtime in the `OperationRegistry`:

```rust
use omni_registry::OperationRegistry;
use std::sync::Arc;

let mut registry = OperationRegistry::new();
registry.register(Arc::new(Rot13Op))?;
```

Once registered, the tool is immediately available across the CLI (`omni run custom.rot13`), the TUI, the REST API, and the visual pipeline builder.
