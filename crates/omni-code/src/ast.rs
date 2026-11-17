use crate::deobfuscate::Deobfuscator;
use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use serde_json::Value;

pub struct AstCodeAnalysisOp;

#[async_trait]
impl Operation for AstCodeAnalysisOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "code.ast_analysis",
            "AST Code Analysis & De-obfuscation",
            "Extracts structural symbols, minifies, beautifies, and runs de-obfuscation on source code",
            OperationCategory::TextAndCode,
        )
        .with_types(vec![DataType::Text], vec![DataType::Json, DataType::Text])
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let code = input.into_text()?;
        let action = config.get("action").and_then(|v| v.as_str()).unwrap_or("analyze");

        match action {
            "deobfuscate" => {
                let mut current = code.clone();
                if let Some(unpacked) = Deobfuscator::unpack_eval_packer(&current) {
                    current = unpacked;
                }
                current = Deobfuscator::resolve_hex_escapes(&current);
                let (normalized, replaced_count) = Deobfuscator::normalize_hex_identifiers(&current);

                let res = serde_json::json!({
                    "deobfuscated_code": normalized,
                    "normalized_identifiers_count": replaced_count,
                    "hex_escapes_resolved": true
                });
                Ok(DataPayload::json(res))
            }
            "minify" => {
                // Minify by stripping comments and extraneous whitespace
                let re_line_comment = regex::Regex::new(r"//.*").unwrap();
                let re_block_comment = regex::Regex::new(r"(?s)/\*.*?\*/").unwrap();
                let without_comments = re_line_comment.replace_all(&code, "");
                let without_comments = re_block_comment.replace_all(&without_comments, "");

                let mut minified = String::new();
                for line in without_comments.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        minified.push_str(trimmed);
                        minified.push(' ');
                    }
                }
                Ok(DataPayload::text(minified.trim().to_string()))
            }
            _ => {
                // Structural tokenization and symbol detection
                let mut functions = Vec::new();
                let mut variables = Vec::new();

                let fn_re = regex::Regex::new(r"\b(fn|function|def|func)\s+([a-zA-Z_0-9]+)").unwrap();
                for caps in fn_re.captures_iter(&code) {
                    functions.push(caps[2].to_string());
                }

                let var_re = regex::Regex::new(r"\b(let|var|const|val)\s+([a-zA-Z_0-9]+)").unwrap();
                for caps in var_re.captures_iter(&code) {
                    variables.push(caps[2].to_string());
                }

                let res = serde_json::json!({
                    "total_lines": code.lines().count(),
                    "total_bytes": code.len(),
                    "functions_detected": functions,
                    "variables_detected": variables,
                    "has_hex_obfuscation": code.contains(r"\x") || code.contains("_0x"),
                });

                Ok(DataPayload::json(res))
            }
        }
    }
}
