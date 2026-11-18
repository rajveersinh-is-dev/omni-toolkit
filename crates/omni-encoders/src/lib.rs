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
        let enc = op
            .execute(raw, serde_json::json!({ "decode": false }), &ctx)
            .await
            .unwrap();
        assert_eq!(enc.as_str().unwrap(), "4f6d6e69546f6f6c6b697432303236");

        let dec = op
            .execute(enc, serde_json::json!({ "decode": true }), &ctx)
            .await
            .unwrap();
        assert_eq!(dec.into_bytes(), b"OmniToolkit2026");
    }

    #[tokio::test]
    async fn test_base64_roundtrip() {
        let op = Base64Op { is_url_safe: false };
        let ctx = ExecutionContext::new("t2");
        let raw = DataPayload::text("Hello OMNI SwissKnife");
        let enc = op.execute(raw, serde_json::json!({}), &ctx).await.unwrap();
        assert_eq!(enc.as_str().unwrap(), "SGVsbG8gT01OSSBTd2lzc0tuaWZl");

        let dec = op
            .execute(enc, serde_json::json!({ "decode": true }), &ctx)
            .await
            .unwrap();
        assert_eq!(dec.into_text().unwrap(), "Hello OMNI SwissKnife");
    }

    #[tokio::test]
    async fn test_base58_roundtrip() {
        let op = Base58Op;
        let ctx = ExecutionContext::new("t3");
        let raw = DataPayload::text("123456789ABCDEF");
        let enc = op.execute(raw, serde_json::json!({}), &ctx).await.unwrap();
        let dec = op
            .execute(enc, serde_json::json!({ "decode": true }), &ctx)
            .await
            .unwrap();
        assert_eq!(dec.into_text().unwrap(), "123456789ABCDEF");
    }

    #[tokio::test]
    async fn test_base45_roundtrip() {
        let op = Base45Op;
        let ctx = ExecutionContext::new("t4");
        let raw = DataPayload::text("Hello!!");
        let enc = op.execute(raw, serde_json::json!({}), &ctx).await.unwrap();
        assert_eq!(enc.as_str().unwrap(), "%69 VD92EX0");

        let dec = op
            .execute(enc, serde_json::json!({ "decode": true }), &ctx)
            .await
            .unwrap();
        assert_eq!(dec.into_text().unwrap(), "Hello!!");
    }

    #[tokio::test]
    async fn test_url_and_html_encoding() {
        let url_op = UrlEncodeOp;
        let html_op = HtmlEntitiesOp;
        let ctx = ExecutionContext::new("t5");

        // URL
        let raw = DataPayload::text("hello world?query=1&name=omni");
        let enc = url_op
            .execute(raw, serde_json::json!({}), &ctx)
            .await
            .unwrap();
        assert_eq!(
            enc.as_str().unwrap(),
            "hello%20world%3Fquery%3D1%26name%3Domni"
        );
        let dec = url_op
            .execute(enc, serde_json::json!({ "decode": true }), &ctx)
            .await
            .unwrap();
        assert_eq!(dec.as_str().unwrap(), "hello world?query=1&name=omni");

        // HTML
        let raw_html = DataPayload::text("<script>alert('xss & fun')</script>");
        let enc_html = html_op
            .execute(raw_html, serde_json::json!({}), &ctx)
            .await
            .unwrap();
        assert!(enc_html.as_str().unwrap().contains("&lt;script&gt;"));
        let dec_html = html_op
            .execute(enc_html, serde_json::json!({ "decode": true }), &ctx)
            .await
            .unwrap();
        assert_eq!(
            dec_html.as_str().unwrap(),
            "<script>alert('xss & fun')</script>"
        );
    }

    #[tokio::test]
    async fn test_unicode_and_octal_escapes() {
        let u_op = UnicodeEscapesOp;
        let oct_op = OctalEscapesOp;
        let ctx = ExecutionContext::new("t6");

        // Unicode escapes
        let raw = DataPayload::text("Hello 世界 🚀");
        let enc = u_op
            .execute(raw, serde_json::json!({}), &ctx)
            .await
            .unwrap();
        assert!(enc.as_str().unwrap().contains("\\u4e16"));
        let dec = u_op
            .execute(enc, serde_json::json!({ "decode": true }), &ctx)
            .await
            .unwrap();
        assert_eq!(dec.as_str().unwrap(), "Hello 世界 🚀");

        // Octal escapes
        let raw_bytes = DataPayload::bytes(b"ABC");
        let enc_oct = oct_op
            .execute(raw_bytes, serde_json::json!({}), &ctx)
            .await
            .unwrap();
        assert_eq!(enc_oct.as_str().unwrap(), "\\101\\102\\103");
        let dec_oct = oct_op
            .execute(enc_oct, serde_json::json!({ "decode": true }), &ctx)
            .await
            .unwrap();
        assert_eq!(dec_oct.into_bytes(), b"ABC");

        // Malformed unicode escape preserved instead of silently dropping text, without eating valid escapes, plus UTF-16 surrogate pairs
        let malformed = u_op
            .execute(
                DataPayload::text(r"keep \u{ZZZZ} and \u12\u0041 and \ud83d\ude00"),
                serde_json::json!({ "decode": true }),
                &ctx,
            )
            .await
            .unwrap();
        assert_eq!(
            malformed.as_str().unwrap(),
            "keep \\u{ZZZZ} and \\u12A and 😀"
        );
    }

    #[tokio::test]
    async fn test_remaining_encoders_and_overflow_regressions() {
        let ctx = ExecutionContext::new("t_enc_all");

        // Base32, Base32Hex, Base64URL, Base91, QuotedPrintable, Punycode
        for op in [
            Box::new(Base32Op { is_hex: false }) as Box<dyn Operation>,
            Box::new(Base32Op { is_hex: true }),
            Box::new(Base64Op { is_url_safe: true }),
            Box::new(Base85Op),
            Box::new(Base91Op),
            Box::new(QuotedPrintableOp),
        ] {
            for sample in [
                b"".as_slice(),
                b"\x00",
                b"\x00\x00\x00\x00",
                b"OMNI SwissKnife 2026!\xff\x00",
            ] {
                let enc = op
                    .execute(DataPayload::bytes(sample), serde_json::json!({}), &ctx)
                    .await
                    .unwrap();
                let dec = op
                    .execute(enc, serde_json::json!({ "decode": true }), &ctx)
                    .await
                    .unwrap();
                assert_eq!(
                    dec.into_bytes(),
                    sample,
                    "roundtrip failed for {}",
                    op.manifest().id
                );
            }
        }

        // Base62 leading-zero preservation regression
        let b62 = Base62Op;
        for sample in [b"".as_slice(), b"\x00", b"\x00\x00hello\x00"] {
            let enc = b62
                .execute(DataPayload::bytes(sample), serde_json::json!({}), &ctx)
                .await
                .unwrap();
            let dec = b62
                .execute(enc, serde_json::json!({ "decode": true }), &ctx)
                .await
                .unwrap();
            assert_eq!(
                dec.into_bytes(),
                sample,
                "Base62 leading-zero roundtrip failed"
            );
        }

        // Punycode IDNA roundtrip
        let puny = PunycodeOp;
        let enc_idn = puny
            .execute(DataPayload::text("münchen.de"), serde_json::json!({}), &ctx)
            .await
            .unwrap();
        assert_eq!(enc_idn.as_str().unwrap(), "xn--mnchen-3ya.de");
        let dec_idn = puny
            .execute(enc_idn, serde_json::json!({ "decode": true }), &ctx)
            .await
            .unwrap();
        assert_eq!(dec_idn.as_str().unwrap(), "münchen.de");

        // Base85 overflow regression ("uuuuu" exceeds u32::MAX, must return Err, NEVER panic!)
        let b85 = Base85Op;
        assert!(b85
            .execute(
                DataPayload::text("uuuuu"),
                serde_json::json!({ "decode": true }),
                &ctx
            )
            .await
            .is_err());
        assert!(b85
            .execute(
                DataPayload::text("!"),
                serde_json::json!({ "decode": true }),
                &ctx
            )
            .await
            .is_err());

        // Base45 overflow regression (":::" = 91124 > 65535, must return Err)
        let b45 = Base45Op;
        assert!(b45
            .execute(
                DataPayload::text(":::"),
                serde_json::json!({ "decode": true }),
                &ctx
            )
            .await
            .is_err());
        assert!(b45
            .execute(
                DataPayload::text("::"),
                serde_json::json!({ "decode": true }),
                &ctx
            )
            .await
            .is_err());
    }
}
