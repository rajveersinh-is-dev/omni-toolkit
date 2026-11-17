pub mod ast;
pub mod deobfuscate;

pub use ast::AstCodeAnalysisOp;
pub use deobfuscate::Deobfuscator;

use omni_core::OmniResult;
use omni_registry::OperationRegistry;
use std::sync::Arc;

pub fn register_code(registry: &mut OperationRegistry) -> OmniResult<()> {
    registry.register(Arc::new(AstCodeAnalysisOp))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use omni_core::{DataPayload, ExecutionContext, Operation};

    #[tokio::test]
    async fn test_deobfuscator_hex_and_identifiers() {
        let op = AstCodeAnalysisOp;
        let ctx = ExecutionContext::new("t_code");

        let obfuscated = r#"
            var _0x4a12 = "\x68\x65\x6c\x6c\x6f";
            var _0x5b3c = "\x77\x6f\x72\x6c\x64";
            console.log(_0x4a12, _0x5b3c);
        "#;

        let res = op
            .execute(
                DataPayload::text(obfuscated),
                serde_json::json!({ "action": "deobfuscate" }),
                &ctx,
            )
            .await
            .unwrap();

        let json = res.into_json().unwrap();
        let deob = json["deobfuscated_code"].as_str().unwrap();

        // Check that \x68\x65\x6c\x6c\x6f was resolved to hello
        assert!(deob.contains("\"hello\""));
        assert!(deob.contains("\"world\""));
        // Check that _0x4a12 was normalized to v_1
        assert!(deob.contains("v_1"));
        assert_eq!(json["normalized_identifiers_count"], 2);
    }

    #[tokio::test]
    async fn test_code_analysis_symbols() {
        let op = AstCodeAnalysisOp;
        let ctx = ExecutionContext::new("t_sym");

        let src = r#"
            function calculateHash(data) {
                const secret = "key";
                let count = 42;
                return true;
            }
        "#;

        let res = op
            .execute(
                DataPayload::text(src),
                serde_json::json!({ "action": "analyze" }),
                &ctx,
            )
            .await
            .unwrap();

        let json = res.into_json().unwrap();
        assert_eq!(json["functions_detected"][0], "calculateHash");
        assert!(json["variables_detected"].as_array().unwrap().iter().any(|v| v == "secret"));
        assert!(json["variables_detected"].as_array().unwrap().iter().any(|v| v == "count"));
    }
}
