use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniError, OmniResult,
    Operation, OperationCategory, OperationManifest,
};
use serde_json::{json, Value};
use tiktoken_rs::{cl100k_base, o200k_base, p50k_base, r50k_base};

pub struct TokenizerPlaygroundOp;

#[derive(Debug, Clone, serde::Serialize)]
struct VisualToken {
    id: u32,
    text: String,
    byte_len: usize,
    hex: String,
    is_special: bool,
    color_hint: String,
}

#[async_trait]
impl Operation for TokenizerPlaygroundOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "ai.tokenizer",
            "BPE Tokenizer Playground (tiktoken)",
            "Encodes and decodes text using real OpenAI BPE vocabularies (cl100k_base, o200k_base, p50k_base, r50k_base) with authentic token IDs and byte boundaries",
            OperationCategory::AiAndTensors,
        )
        .with_types(vec![DataType::Text], vec![DataType::Json])
        .with_status(FeatureStatus::Verified)
        .with_limitations(vec![
            "Supports tiktoken BPE encodings (cl100k_base, o200k_base, p50k_base, r50k_base); SentencePiece/WordPiece/LLaMA model files require external vocabulary loading not bundled here".into(),
        ])
        .with_tags(vec!["ai".into(), "tokenizer".into(), "bpe".into(), "tiktoken".into()])
    }

    async fn execute(
        &self,
        input: DataPayload,
        config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let encoding_name = config
            .get("encoding")
            .and_then(|v| v.as_str())
            .unwrap_or("cl100k_base");

        let bpe = match encoding_name {
            "cl100k_base" => cl100k_base(),
            "o200k_base" => o200k_base(),
            "p50k_base" => p50k_base(),
            "r50k_base" => r50k_base(),
            other => {
                return Err(OmniError::InvalidInput(format!(
                    "Unsupported tokenizer encoding '{}'. Supported: cl100k_base, o200k_base, p50k_base, r50k_base",
                    other
                )));
            }
        }
        .map_err(|e| OmniError::Execution {
            operation: "ai.tokenizer".into(),
            message: format!("Failed to initialize tokenizer '{}': {e}", encoding_name),
        })?;

        let text = input.into_text()?;
        let colors = ["#58a6ff", "#bc8cff", "#7ee787", "#ffa657", "#ff7b72"];
        let special_set = bpe.special_tokens();

        // Encode with real special-token recognition and authentic vocabulary IDs
        let token_ids = bpe.encode_with_special_tokens(&text);
        let mut tokens = Vec::with_capacity(token_ids.len());

        for (idx, &rank) in token_ids.iter().enumerate() {
            let decoded_bytes = bpe.decode_bytes(&[rank]).unwrap_or_default();
            let decoded_str = String::from_utf8_lossy(&decoded_bytes).into_owned();
            let is_special = special_set.contains(decoded_str.as_str());
            let hex_str = hex::encode(&decoded_bytes);

            tokens.push(VisualToken {
                id: rank,
                text: decoded_str,
                byte_len: decoded_bytes.len(),
                hex: hex_str,
                is_special,
                color_hint: if is_special {
                    "#ff7b72".to_string()
                } else {
                    colors[idx % colors.len()].to_string()
                },
            });
        }

        let total_tokens = tokens.len();
        let total_chars = text.chars().count();
        let total_bytes = text.len();
        let denom = total_tokens.max(1) as f64;

        let chars_per_token = (total_chars as f64 / denom * 100.0).round() / 100.0;
        let bytes_per_token = (total_bytes as f64 / denom * 100.0).round() / 100.0;

        Ok(DataPayload::json(json!({
            "encoding": encoding_name,
            "total_tokens": total_tokens,
            "total_characters": total_chars,
            "total_bytes": total_bytes,
            "compression_ratio_chars_per_token": chars_per_token,
            "compression_ratio_bytes_per_token": bytes_per_token,
            "token_ids": token_ids,
            "tokens": tokens,
        })))
    }
}
