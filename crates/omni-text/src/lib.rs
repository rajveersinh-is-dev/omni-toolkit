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
            .execute(inp.clone(), serde_json::json!({ "action": "snake_case" }), &ctx)
            .await
            .unwrap();
        assert_eq!(snake.as_str().unwrap(), "omni_universal_multitool2026");

        // camelCase
        let camel = op
            .execute(inp.clone(), serde_json::json!({ "action": "camel_case" }), &ctx)
            .await
            .unwrap();
        assert_eq!(camel.as_str().unwrap(), "omniUniversalMultitool2026");

        // slugify
        let title = DataPayload::text("OMNI: The Universal Digital Engineering Multitool!");
        let slug = op
            .execute(title, serde_json::json!({ "action": "slugify" }), &ctx)
            .await
            .unwrap();
        assert_eq!(slug.as_str().unwrap(), "omni-the-universal-digital-engineering-multitool");

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

        let data = DataPayload::text(r#"{
            "store": {
                "books": [
                    { "title": "The Rust Programming Language", "price": 40 },
                    { "title": "Designing Data-Intensive Applications", "price": 50 }
                ]
            }
        }"#);

        let cfg = serde_json::json!({ "query": "store.books[0].title" });
        let res = op.execute(data, cfg, &ctx).await.unwrap();
        assert_eq!(res.into_text().unwrap(), "The Rust Programming Language");
    }
}
