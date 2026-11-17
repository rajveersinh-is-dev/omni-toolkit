pub mod context;
pub mod error;
pub mod manifest;
pub mod operation;
pub mod payload;

pub use async_trait::async_trait;
pub use context::{ExecutionContext, ProgressUpdate};
pub use error::{OmniError, OmniResult};
pub use manifest::{
    OperationCategory, OperationManifest, ResourceRequirements, SecurityClassification,
};
pub use operation::Operation;
pub use payload::{DataPayload, DataType};

#[cfg(test)]
mod tests {
    use super::*;

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
}
