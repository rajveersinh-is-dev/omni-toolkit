pub mod context;
pub mod error;
pub mod manifest;
pub mod operation;
pub mod payload;

pub use async_trait::async_trait;
pub use context::{ExecutionContext, ProgressUpdate};
pub use error::{OmniError, OmniResult};
pub use manifest::{
    FeatureStatus, InputPortSpec, OperationCategory, OperationManifest, ResourceRequirements,
    SecurityClassification,
};
pub use operation::Operation;
pub use payload::{DataPayload, DataType};

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn test_payload_text_roundtrip() {
        let payload = DataPayload::text("hello world");
        assert_eq!(payload.data_type(), DataType::Text);
        assert_eq!(payload.as_str().unwrap(), "hello world");
        assert_eq!(payload.into_bytes(), b"hello world");
    }

    #[test]
    fn test_payload_bytes_roundtrip() {
        let b = vec![0x00, 0xff, 0x42];
        let payload = DataPayload::bytes(b.clone());
        assert_eq!(payload.data_type(), DataType::Bytes);
        assert_eq!(payload.into_bytes(), b);
    }

    #[test]
    fn test_payload_multi_deterministic() {
        let mut map = BTreeMap::new();
        map.insert("b".to_string(), DataPayload::text("second"));
        map.insert("a".to_string(), DataPayload::text("first"));
        let payload = DataPayload::multi(map);
        assert_eq!(payload.data_type(), DataType::Multi);
        let keys: Vec<_> = payload.as_multi().unwrap().keys().cloned().collect();
        assert_eq!(keys, vec!["a", "b"]);
    }

    #[tokio::test]
    async fn test_execution_context_cancel_notification() {
        let ctx = ExecutionContext::new("cancel_test");
        let ctx_clone = ctx.clone();
        let handle = tokio::spawn(async move {
            ctx_clone.cancelled().await;
            true
        });
        tokio::task::yield_now().await;
        assert!(!ctx.is_cancelled());
        ctx.cancel();
        assert!(ctx.is_cancelled());
        assert!(handle.await.unwrap());
    }
}
