use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use serde_json::{json, Value};

pub struct TokenizerPlaygroundOp;

#[derive(Debug, Clone, serde::Serialize)]
struct VisualToken {
    id: usize,
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
            "Tokenizer Playground & Boundary Visualizer",
            "Segments text into subword BPE tokens, calculates compression ratios, and assigns alternating visualization colors",
            OperationCategory::AiAndTensors,
        )
        .with_types(vec![DataType::Text], vec![DataType::Json])
    }

    async fn execute(&self, input: DataPayload, _config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let text = input.into_text().unwrap_or_default();
        let colors = ["#58a6ff", "#bc8cff", "#7ee787", "#ffa657", "#ff7b72"];
        let special_tokens = ["<|endoftext|>", "<|im_start|>", "<|im_end|>", "[CLS]", "[SEP]", "<s>", "</s>"];

        let mut tokens = Vec::new();
        let mut token_counter = 1000;
        let mut i = 0;
        let bytes = text.as_bytes();

        while i < bytes.len() {
            // Check for special tokens first
            let mut found_special = false;
            for &sp in &special_tokens {
                if text[i..].starts_with(sp) {
                    let sp_bytes = sp.as_bytes();
                    tokens.push(VisualToken {
                        id: token_counter,
                        text: sp.into(),
                        byte_len: sp_bytes.len(),
                        hex: hex::encode(sp_bytes),
                        is_special: true,
                        color_hint: "#ff7b72".into(),
                    });
                    token_counter += 1;
                    i += sp.len();
                    found_special = true;
                    break;
                }
            }
            if found_special {
                continue;
            }

            // Normal tokenization: read whitespace or word
            let ch = text[i..].chars().next().unwrap();
            let ch_len = ch.len_utf8();

            if ch.is_whitespace() || ch.is_ascii_punctuation() {
                let s = ch.to_string();
                let b_len = s.len();
                let hex_str = hex::encode(s.as_bytes());
                tokens.push(VisualToken {
                    id: token_counter,
                    text: s,
                    byte_len: b_len,
                    hex: hex_str,
                    is_special: false,
                    color_hint: colors[tokens.len() % colors.len()].into(),
                });
                token_counter += 1;
                i += ch_len;
            } else {
                let mut word = String::new();
                while i < bytes.len() {
                    let c = text[i..].chars().next().unwrap();
                    if c.is_whitespace() || c.is_ascii_punctuation() || special_tokens.iter().any(|&sp| text[i..].starts_with(sp)) {
                        break;
                    }
                    word.push(c);
                    i += c.len_utf8();
                    if word.len() >= 6 {
                        break;
                    }
                }
                let w_len = word.len();
                let hex_str = hex::encode(word.as_bytes());
                tokens.push(VisualToken {
                    id: token_counter,
                    text: word,
                    byte_len: w_len,
                    hex: hex_str,
                    is_special: false,
                    color_hint: colors[tokens.len() % colors.len()].into(),
                });
                token_counter += 1;
            }
        }

        let total_tokens = tokens.len().max(1);
        let total_chars = text.chars().count();
        let total_bytes = text.len();

        let chars_per_token = (total_chars as f64 / total_tokens as f64 * 100.0).round() / 100.0;
        let bytes_per_token = (total_bytes as f64 / total_tokens as f64 * 100.0).round() / 100.0;

        Ok(DataPayload::json(json!({
            "total_tokens": tokens.len(),
            "total_characters": total_chars,
            "total_bytes": total_bytes,
            "compression_ratio_chars_per_token": chars_per_token,
            "compression_ratio_bytes_per_token": bytes_per_token,
            "tokens": tokens,
        })))
    }
}
