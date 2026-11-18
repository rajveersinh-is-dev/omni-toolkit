use crate::deobfuscate::Deobfuscator;
use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, FeatureStatus, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use regex::Regex;
use serde_json::Value;
use std::sync::LazyLock;

static RE_FN: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"\b(fn|function|def|func)\s+([a-zA-Z_0-9]+)").ok());
static RE_VAR: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"\b(let|var|const|val)\s+([a-zA-Z_0-9]+)").ok());

/// Strips `//` line comments and `/* ... */` block comments without corrupting
/// string or template literals (e.g. `"https://example.com"` or `'/* keep */'`).
fn strip_comments_preserving_strings(code: &str) -> String {
    let mut out = String::with_capacity(code.len());
    let chars: Vec<char> = code.chars().collect();
    let len = chars.len();
    let mut i = 0;
    let mut quote: Option<char> = None;

    while i < len {
        let c = chars[i];
        if let Some(q) = quote {
            out.push(c);
            if c == '\\' && i + 1 < len {
                out.push(chars[i + 1]);
                i += 2;
                continue;
            }
            if c == q {
                quote = None;
            }
            i += 1;
            continue;
        }

        if c == '"' || c == '\'' || c == '`' {
            quote = Some(c);
            out.push(c);
            i += 1;
        } else if c == '/' && i + 1 < len && chars[i + 1] == '/' {
            i += 2;
            while i < len && chars[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && i + 1 < len && chars[i + 1] == '*' {
            i += 2;
            while i + 1 < len && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            if i + 1 < len {
                i += 2;
            } else {
                i = len;
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

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
        .with_status(FeatureStatus::Verified)
        .with_tags(vec!["code".into(), "ast".into(), "deobfuscate".into(), "minify".into()])
    }

    async fn execute(
        &self,
        input: DataPayload,
        config: Value,
        _ctx: &ExecutionContext,
    ) -> OmniResult<DataPayload> {
        let code = input.into_text()?;
        let action = config
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("analyze");

        match action {
            "deobfuscate" => {
                let mut current = code.clone();
                if let Some(unpacked) = Deobfuscator::unpack_eval_packer(&current) {
                    current = unpacked;
                }
                current = Deobfuscator::resolve_hex_escapes(&current);
                let (normalized, replaced_count) =
                    Deobfuscator::normalize_hex_identifiers(&current);

                let res = serde_json::json!({
                    "deobfuscated_code": normalized,
                    "normalized_identifiers_count": replaced_count,
                    "hex_escapes_resolved": true
                });
                Ok(DataPayload::json(res))
            }
            "minify" => {
                // Minify by stripping comments (preserving string literals) and extraneous whitespace
                let without_comments = strip_comments_preserving_strings(&code);

                let mut minified = String::with_capacity(without_comments.len());
                for line in without_comments.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        if !minified.is_empty() {
                            minified.push(' ');
                        }
                        minified.push_str(trimmed);
                    }
                }
                Ok(DataPayload::text(minified))
            }
            _ => {
                // Structural tokenization and symbol detection
                let mut functions = Vec::new();
                let mut variables = Vec::new();

                if let Some(fn_re) = RE_FN.as_ref() {
                    for caps in fn_re.captures_iter(&code) {
                        if let Some(m) = caps.get(2) {
                            functions.push(m.as_str().to_string());
                        }
                    }
                }

                if let Some(var_re) = RE_VAR.as_ref() {
                    for caps in var_re.captures_iter(&code) {
                        if let Some(m) = caps.get(2) {
                            variables.push(m.as_str().to_string());
                        }
                    }
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
