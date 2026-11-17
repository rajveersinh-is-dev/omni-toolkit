use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniError, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use serde_json::Value;

pub struct EncodingsOp;

#[async_trait]
impl Operation for EncodingsOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "text.encodings",
            "Character Encoding Converter",
            "Converts byte streams between UTF-8, UTF-16LE/BE, Windows-1252, ISO-8859, Shift-JIS, GBK, and Big5",
            OperationCategory::TextAndCode,
        )
        .with_types(vec![DataType::Bytes, DataType::Text], vec![DataType::Bytes, DataType::Text])
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let from_enc_name = config.get("from").and_then(|v| v.as_str()).unwrap_or("windows-1252");
        let to_enc_name = config.get("to").and_then(|v| v.as_str()).unwrap_or("utf-8");

        let from_enc = encoding_rs::Encoding::for_label(from_enc_name.as_bytes())
            .ok_or_else(|| OmniError::Validation(format!("Unknown source encoding '{from_enc_name}'")))?;
        let to_enc = encoding_rs::Encoding::for_label(to_enc_name.as_bytes())
            .ok_or_else(|| OmniError::Validation(format!("Unknown destination encoding '{to_enc_name}'")))?;

        let bytes = input.into_bytes();
        let (decoded_cow, _, had_errors) = from_enc.decode(&bytes);
        if had_errors {
            tracing::warn!("Encoding decode encountered invalid byte sequences");
        }

        let (encoded_cow, _, _) = to_enc.encode(&decoded_cow);
        Ok(DataPayload::bytes(encoded_cow.into_owned()))
    }
}
