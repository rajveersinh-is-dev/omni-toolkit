pub mod diff;
pub mod encodings;
pub mod query;
pub mod regex_studio;
pub mod strings;
pub mod transpile;

pub use diff::TextDiffOp;
pub use encodings::EncodingsOp;
pub use query::QueryStructuredOp;
pub use regex_studio::RegexStudioOp;
pub use strings::StringTransformersOp;
pub use transpile::TranspilerOp;

use omni_core::OmniResult;
use omni_registry::OperationRegistry;
use std::sync::Arc;

pub fn register_text(registry: &mut OperationRegistry) -> OmniResult<()> {
    registry.register(Arc::new(TranspilerOp))?;
    registry.register(Arc::new(QueryStructuredOp))?;
    registry.register(Arc::new(TextDiffOp))?;
    registry.register(Arc::new(RegexStudioOp))?;
    registry.register(Arc::new(StringTransformersOp))?;
    registry.register(Arc::new(EncodingsOp))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use omni_core::{DataPayload, ExecutionContext, Operation};

    #[tokio::test]
    async fn test_transpiler_json_to_yaml_and_toml() {
        let op = TranspilerOp;
        let ctx = ExecutionContext::new("t_trans");

        let json_input = DataPayload::text(r#"{"service": "omni", "port": 8080, "enabled": true}"#);
        let yaml_out = op
            .execute(
                json_input.clone(),
                serde_json::json!({ "from": "json", "to": "yaml" }),
                &ctx,
            )
            .await
            .unwrap();
        assert!(yaml_out.as_str().unwrap().contains("service: omni"));

        let toml_out = op
            .execute(
                json_input,
                serde_json::json!({ "from": "json", "to": "toml" }),
                &ctx,
            )
            .await
            .unwrap();
        assert!(toml_out.as_str().unwrap().contains(r#"service = "omni""#));
    }

    #[tokio::test]
    async fn test_diff_myers() {
        let op = TextDiffOp;
        let ctx = ExecutionContext::new("t_diff");

        let input = DataPayload::text("line1\nline2_modified\nline3\nline4");
        let cfg = serde_json::json!({
            "original": "line1\nline2\nline3",
            "granularity": "lines"
        });
        let diff = op.execute(input, cfg, &ctx).await.unwrap();
        let diff_str = diff.as_str().unwrap();
        assert!(diff_str.contains("-line2"));
        assert!(diff_str.contains("+line2_modified"));
    }

    #[tokio::test]
    async fn test_regex_studio_matching() {
        let op = RegexStudioOp;
        let ctx = ExecutionContext::new("t_regex");

        let input = DataPayload::text("Error 404 at /api/users, Error 500 at /api/admin");
        let cfg = serde_json::json!({
            "pattern": r"Error (\d+)",
            "replace": "Status [$1]"
        });
        let res = op.execute(input, cfg, &ctx).await.unwrap();
        let json = res.into_json().unwrap();
        assert_eq!(json["total_matches"], 2);
        assert_eq!(
            json["replaced_output"],
            "Status [404] at /api/users, Status [500] at /api/admin"
        );
    }

    #[tokio::test]
    async fn test_string_transformers_case_and_soundex() {
        let op = StringTransformersOp;
        let ctx = ExecutionContext::new("t_str");

        // snake_case
        let inp = DataPayload::text("OmniUniversalMultitool2026");
        let snake = op
            .execute(
                inp.clone(),
                serde_json::json!({ "action": "snake_case" }),
                &ctx,
            )
            .await
            .unwrap();
        assert_eq!(snake.as_str().unwrap(), "omni_universal_multitool2026");

        // camelCase
        let camel = op
            .execute(
                inp.clone(),
                serde_json::json!({ "action": "camel_case" }),
                &ctx,
            )
            .await
            .unwrap();
        assert_eq!(camel.as_str().unwrap(), "omniUniversalMultitool2026");

        // slugify
        let title = DataPayload::text("OMNI: The Universal Digital Engineering Multitool!");
        let slug = op
            .execute(title, serde_json::json!({ "action": "slugify" }), &ctx)
            .await
            .unwrap();
        assert_eq!(
            slug.as_str().unwrap(),
            "omni-the-universal-digital-engineering-multitool"
        );

        // Soundex
        let name = DataPayload::text("Robert");
        let sndx = op
            .execute(name, serde_json::json!({ "action": "soundex" }), &ctx)
            .await
            .unwrap();
        // Robert -> R163
        assert_eq!(sndx.as_str().unwrap(), "R163");
    }

    #[tokio::test]
    async fn test_query_structured_jsonpath() {
        let op = QueryStructuredOp;
        let ctx = ExecutionContext::new("t_query");

        let data = DataPayload::text(
            r#"{
            "store": {
                "books": [
                    { "title": "The Rust Programming Language", "price": 40 },
                    { "title": "Designing Data-Intensive Applications", "price": 50 }
                ]
            }
        }"#,
        );

        let cfg = serde_json::json!({ "query": "store.books[0].title" });
        let res = op.execute(data, cfg, &ctx).await.unwrap();
        assert_eq!(res.into_text().unwrap(), "The Rust Programming Language");
    }

    #[tokio::test]
    async fn test_transpiler_csv_no_double_quoting_and_jsonpath_chained_indices() {
        let ctx = ExecutionContext::new("t_text_edge");

        // CSV -> JSON -> CSV must NOT wrap strings in extra literal quotes
        let trans = TranspilerOp;
        let csv_in = "name,city\nAlice,London\nBob,Tokyo\n";
        let as_json = trans
            .execute(
                DataPayload::text(csv_in),
                serde_json::json!({ "from": "csv", "to": "json" }),
                &ctx,
            )
            .await
            .unwrap();
        let back_csv = trans
            .execute(
                as_json,
                serde_json::json!({ "from": "json", "to": "csv" }),
                &ctx,
            )
            .await
            .unwrap();
        let out_str = back_csv.as_str().unwrap();
        assert!(
            !out_str.contains("\"\"Alice\"\""),
            "CSV corrupted string with double quotes: {out_str}"
        );
        assert!(out_str.contains("Alice") && out_str.contains("London"));

        // JSONPath with `$` prefix and chained 2D array index
        let q = QueryStructuredOp;
        let nested = DataPayload::text(r#"{"matrix": [[10, 20], [30, 40]]}"#);
        let cell = q
            .execute(
                nested.clone(),
                serde_json::json!({ "query": "$.matrix[1][0]" }),
                &ctx,
            )
            .await
            .unwrap();
        assert_eq!(cell.into_json().unwrap(), serde_json::json!(30));
        assert!(q
            .execute(nested, serde_json::json!({ "query": "matrix[0" }), &ctx)
            .await
            .is_err());

        // NARA Soundex H/W adjacency rule
        let str_op = StringTransformersOp;
        let ash = str_op
            .execute(
                DataPayload::text("Ashcraft"),
                serde_json::json!({ "action": "soundex" }),
                &ctx,
            )
            .await
            .unwrap();
        assert_eq!(ash.as_str().unwrap(), "A261");
        let pf = str_op
            .execute(
                DataPayload::text("Pfister"),
                serde_json::json!({ "action": "soundex" }),
                &ctx,
            )
            .await
            .unwrap();
        assert_eq!(pf.as_str().unwrap(), "P236");

        // Regex Studio capture groups + ReDoS heuristic
        let rx = RegexStudioOp;
        let rres = rx
            .execute(
                DataPayload::text("user=alice id=42"),
                serde_json::json!({ "pattern": r"(\w+)=(\w+)" }),
                &ctx,
            )
            .await
            .unwrap()
            .into_json()
            .unwrap();
        assert_eq!(rres["matches"][0]["groups"][0], "user");
        assert_eq!(rres["matches"][0]["groups"][1], "alice");
    }

    #[tokio::test]
    async fn test_encodings_utf16le_utf16be_and_windows1252() {
        let ctx = ExecutionContext::new("t_enc");
        let op = EncodingsOp;

        // UTF-8 -> UTF-16LE MUST emit real 16-bit little-endian code units (NOT UTF-8!)
        let le_bytes = op
            .execute(
                DataPayload::text("Hi"),
                serde_json::json!({ "from": "utf-8", "to": "utf-16le" }),
                &ctx,
            )
            .await
            .unwrap()
            .into_bytes();
        assert_eq!(le_bytes, vec![b'H', 0x00, b'i', 0x00]);

        // Roundtrip UTF-16LE -> UTF-8
        let back = op
            .execute(
                DataPayload::bytes(le_bytes),
                serde_json::json!({ "from": "utf-16le", "to": "utf-8" }),
                &ctx,
            )
            .await
            .unwrap()
            .into_bytes();
        assert_eq!(back, b"Hi");

        // UTF-8 -> UTF-16BE
        let be_bytes = op
            .execute(
                DataPayload::text("Hi"),
                serde_json::json!({ "from": "utf-8", "to": "utf-16be" }),
                &ctx,
            )
            .await
            .unwrap()
            .into_bytes();
        assert_eq!(be_bytes, vec![0x00, b'H', 0x00, b'i']);

        // Windows-1252 0x80 (€) -> UTF-8
        let euro = op
            .execute(
                DataPayload::bytes(vec![0x80]),
                serde_json::json!({ "from": "windows-1252", "to": "utf-8" }),
                &ctx,
            )
            .await
            .unwrap()
            .into_bytes();
        assert_eq!(euro, "€".as_bytes());

        // Unknown encoding rejected
        assert!(op
            .execute(
                DataPayload::text("x"),
                serde_json::json!({ "from": "no-such-charset", "to": "utf-8" }),
                &ctx,
            )
            .await
            .is_err());
    }
}
