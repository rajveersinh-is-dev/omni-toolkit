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
        assert!(json["variables_detected"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "secret"));
        assert!(json["variables_detected"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "count"));
    }

    #[tokio::test]
    async fn test_code_minify_and_packer_oom_guard() {
        let op = AstCodeAnalysisOp;
        let ctx = ExecutionContext::new("t_min");

        let min = op
            .execute(
                DataPayload::text("// header\nfn a() {\n /* block */ return 1;\n}"),
                serde_json::json!({ "action": "minify" }),
                &ctx,
            )
            .await
            .unwrap();
        assert_eq!(min.as_str().unwrap(), "fn a() { return 1; }");

        // Adversarial huge c=999999999 must be rejected without allocating OOM HashMap
        let evil_packed = "eval(function(p,a,c,k,e,d){return p}('0',36,999999999,'a'.split('|')))";
        assert!(Deobfuscator::unpack_eval_packer(evil_packed).is_none());

        // Minify MUST preserve URLs and comment-like tokens inside string literals
        let with_url = "const url = \"https://example.com/a/*b*/\"; // trailing comment\nconst s = 'http://x.y'; /* real block */";
        let min_url = op
            .execute(
                DataPayload::text(with_url),
                serde_json::json!({ "action": "minify" }),
                &ctx,
            )
            .await
            .unwrap();
        assert_eq!(
            min_url.as_str().unwrap(),
            "const url = \"https://example.com/a/*b*/\"; const s = 'http://x.y';"
        );

        // Dean Edwards Packer base-62 key encoding (index 36 = 'A')
        let mut words = vec!["w"; 36];
        words.push("SECRET_FN");
        let dict = words.join("|");
        let packed_62 =
            format!("eval(function(p,a,c,k,e,d){{return p}}('A()',62,37,'{dict}'.split('|')))");
        let unpacked = Deobfuscator::unpack_eval_packer(&packed_62).unwrap();
        assert_eq!(unpacked, "SECRET_FN()");
    }
}
