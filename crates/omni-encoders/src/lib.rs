pub mod base_all;
pub mod web_encoders;

pub use base_all::*;
pub use web_encoders::*;

use omni_core::OmniResult;
use omni_registry::OperationRegistry;
use std::sync::Arc;

pub fn register_encoders(registry: &mut OperationRegistry) -> OmniResult<()> {
    registry.register(Arc::new(Base16Op))?;
    registry.register(Arc::new(Base32Op { is_hex: false }))?;
    registry.register(Arc::new(Base32Op { is_hex: true }))?;
    registry.register(Arc::new(Base45Op))?;
    registry.register(Arc::new(Base58Op))?;
    registry.register(Arc::new(Base62Op))?;
    registry.register(Arc::new(Base64Op { is_url_safe: false }))?;
    registry.register(Arc::new(Base64Op { is_url_safe: true }))?;
    registry.register(Arc::new(Base85Op))?;
    registry.register(Arc::new(Base91Op))?;
    registry.register(Arc::new(PunycodeOp))?;
    registry.register(Arc::new(QuotedPrintableOp))?;
    registry.register(Arc::new(UrlEncodeOp))?;
    registry.register(Arc::new(HtmlEntitiesOp))?;
    registry.register(Arc::new(UnicodeEscapesOp))?;
    registry.register(Arc::new(OctalEscapesOp))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use omni_core::{DataPayload, ExecutionContext, Operation};

    #[tokio::test]
    async fn test_base16_roundtrip() {
        let op = Base16Op;
        let ctx = ExecutionContext::new("t1");
        let raw = DataPayload::bytes(b"OmniToolkit2026");
        let enc = op.execute(raw, serde_json::json!({ "decode": false }), &ctx).await.unwrap();
        assert_eq!(enc.as_str().unwrap(), "4f6d6e69546f6f6c6b697432303236");

        let dec = op.execute(enc, serde_json::json!({ "decode": true }), &ctx).await.unwrap();
        assert_eq!(dec.into_bytes(), b"OmniToolkit2026");
    }

    #[tokio::test]
    async fn test_base64_roundtrip() {
        let op = Base64Op { is_url_safe: false };
        let ctx = ExecutionContext::new("t2");
        let raw = DataPayload::text("Hello OMNI SwissKnife");
        let enc = op.execute(raw, serde_json::json!({}), &ctx).await.unwrap();
        assert_eq!(enc.as_str().unwrap(), "SGVsbG8gT01OSSBTd2lzc0tuaWZl");

        let dec = op.execute(enc, serde_json::json!({ "decode": true }), &ctx).await.unwrap();
        assert_eq!(dec.into_text().unwrap(), "Hello OMNI SwissKnife");
    }

    #[tokio::test]
    async fn test_base58_roundtrip() {
        let op = Base58Op;
        let ctx = ExecutionContext::new("t3");
        let raw = DataPayload::text("123456789ABCDEF");
        let enc = op.execute(raw, serde_json::json!({}), &ctx).await.unwrap();
        let dec = op.execute(enc, serde_json::json!({ "decode": true }), &ctx).await.unwrap();
        assert_eq!(dec.into_text().unwrap(), "123456789ABCDEF");
    }

    #[tokio::test]
    async fn test_base45_roundtrip() {
        let op = Base45Op;
        let ctx = ExecutionContext::new("t4");
        let raw = DataPayload::text("Hello!!");
        let enc = op.execute(raw, serde_json::json!({}), &ctx).await.unwrap();
        assert_eq!(enc.as_str().unwrap(), "%69 VD92EX0");

        let dec = op.execute(enc, serde_json::json!({ "decode": true }), &ctx).await.unwrap();
        assert_eq!(dec.into_text().unwrap(), "Hello!!");
    }

    #[tokio::test]
    async fn test_url_and_html_encoding() {
        let url_op = UrlEncodeOp;
        let html_op = HtmlEntitiesOp;
        let ctx = ExecutionContext::new("t5");

        // URL
        let raw = DataPayload::text("hello world?query=1&name=omni");
        let enc = url_op.execute(raw, serde_json::json!({}), &ctx).await.unwrap();
        assert_eq!(enc.as_str().unwrap(), "hello%20world%3Fquery%3D1%26name%3Domni");
        let dec = url_op.execute(enc, serde_json::json!({ "decode": true }), &ctx).await.unwrap();
        assert_eq!(dec.as_str().unwrap(), "hello world?query=1&name=omni");

        // HTML
        let raw_html = DataPayload::text("<script>alert('xss & fun')</script>");
        let enc_html = html_op.execute(raw_html, serde_json::json!({}), &ctx).await.unwrap();
        assert!(enc_html.as_str().unwrap().contains("&lt;script&gt;"));
        let dec_html = html_op.execute(enc_html, serde_json::json!({ "decode": true }), &ctx).await.unwrap();
        assert_eq!(dec_html.as_str().unwrap(), "<script>alert('xss & fun')</script>");
    }

    #[tokio::test]
    async fn test_unicode_and_octal_escapes() {
        let u_op = UnicodeEscapesOp;
        let oct_op = OctalEscapesOp;
        let ctx = ExecutionContext::new("t6");

        // Unicode escapes
        let raw = DataPayload::text("Hello 世界 🚀");
        let enc = u_op.execute(raw, serde_json::json!({}), &ctx).await.unwrap();
        assert!(enc.as_str().unwrap().contains("\\u4e16"));
        let dec = u_op.execute(enc, serde_json::json!({ "decode": true }), &ctx).await.unwrap();
        assert_eq!(dec.as_str().unwrap(), "Hello 世界 🚀");

        // Octal escapes
        let raw_bytes = DataPayload::bytes(b"ABC");
        let enc_oct = oct_op.execute(raw_bytes, serde_json::json!({}), &ctx).await.unwrap();
        assert_eq!(enc_oct.as_str().unwrap(), "\\101\\102\\103");
        let dec_oct = oct_op.execute(enc_oct, serde_json::json!({ "decode": true }), &ctx).await.unwrap();
        assert_eq!(dec_oct.into_bytes(), b"ABC");
    }
}
