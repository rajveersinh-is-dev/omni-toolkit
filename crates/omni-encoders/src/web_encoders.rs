use omni_core::{
    async_trait, DataPayload, ExecutionContext, OmniError, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use serde_json::Value;

// ======================== PUNYCODE / IDNA ========================
pub struct PunycodeOp;
#[async_trait]
impl Operation for PunycodeOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "encode.punycode",
            "Punycode / IDNA",
            "Encodes and decodes Internationalized Domain Names (IDNA / Punycode RFC 3492)",
            OperationCategory::Encoders,
        )
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let decode = config.get("decode").and_then(|v| v.as_bool()).unwrap_or(false);
        let s = input.into_text()?;
        if decode {
            let decoded = idna::domain_to_unicode(&s);
            Ok(DataPayload::text(decoded.0))
        } else {
            let encoded = idna::domain_to_ascii(&s).map_err(|e| OmniError::InvalidInput(format!("IDNA encode error: {e:?}")))?;
            Ok(DataPayload::text(encoded))
        }
    }
}

// ======================== QUOTED-PRINTABLE ========================
pub struct QuotedPrintableOp;
#[async_trait]
impl Operation for QuotedPrintableOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "encode.quoted_printable",
            "Quoted-Printable",
            "Quoted-Printable MIME data encoding according to RFC 2045",
            OperationCategory::Encoders,
        )
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let decode = config.get("decode").and_then(|v| v.as_bool()).unwrap_or(false);
        if decode {
            let bytes = input.into_bytes();
            let decoded = quoted_printable::decode(&bytes, quoted_printable::ParseMode::Robust)
                .map_err(|e| OmniError::InvalidInput(format!("QP decode error: {e:?}")))?;
            Ok(DataPayload::bytes(decoded))
        } else {
            let bytes = input.into_bytes();
            let encoded = quoted_printable::encode_to_str(&bytes);
            Ok(DataPayload::text(encoded))
        }
    }
}

// ======================== URL PERCENT ENCODING ========================
pub struct UrlEncodeOp;
#[async_trait]
impl Operation for UrlEncodeOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "encode.url",
            "URL Percent Encoding",
            "Uniform Resource Identifier (URI) percent-encoding according to RFC 3986",
            OperationCategory::Encoders,
        )
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let decode = config.get("decode").and_then(|v| v.as_bool()).unwrap_or(false);
        let s = input.into_text()?;
        if decode {
            let decoded = urlencoding::decode(&s).map_err(|e| OmniError::InvalidInput(format!("URL decode error: {e}")))?;
            Ok(DataPayload::text(decoded.into_owned()))
        } else {
            let encoded = urlencoding::encode(&s);
            Ok(DataPayload::text(encoded.into_owned()))
        }
    }
}

// ======================== HTML ENTITIES ========================
pub struct HtmlEntitiesOp;
#[async_trait]
impl Operation for HtmlEntitiesOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "encode.html_entities",
            "HTML4 / HTML5 Entities",
            "Converts characters to and from named/numeric HTML entities",
            OperationCategory::Encoders,
        )
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let decode = config.get("decode").and_then(|v| v.as_bool()).unwrap_or(false);
        let s = input.into_text()?;
        if decode {
            let decoded = html_escape::decode_html_entities(&s);
            Ok(DataPayload::text(decoded.into_owned()))
        } else {
            let encoded = html_escape::encode_text(&s);
            Ok(DataPayload::text(encoded.into_owned()))
        }
    }
}

// ======================== UNICODE ESCAPES (\uXXXX) ========================
pub struct UnicodeEscapesOp;
#[async_trait]
impl Operation for UnicodeEscapesOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "encode.unicode_escapes",
            "Unicode Escapes",
            "Encodes non-ASCII characters to \\uXXXX / \\u{X...} and decodes them",
            OperationCategory::Encoders,
        )
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let decode = config.get("decode").and_then(|v| v.as_bool()).unwrap_or(false);
        let s = input.into_text()?;
        if decode {
            let mut out = String::new();
            let mut chars = s.chars().peekable();
            while let Some(c) = chars.next() {
                if c == '\\' && chars.peek() == Some(&'u') {
                    chars.next(); // consume 'u'
                    if chars.peek() == Some(&'{') {
                        chars.next(); // consume '{'
                        let mut hex_buf = String::new();
                        while let Some(&hc) = chars.peek() {
                            if hc == '}' {
                                chars.next();
                                break;
                            }
                            hex_buf.push(chars.next().unwrap());
                        }
                        if let Ok(cp) = u32::from_str_radix(&hex_buf, 16) {
                            if let Some(ch) = char::from_u32(cp) {
                                out.push(ch);
                                continue;
                            }
                        }
                    } else {
                        let mut hex_buf = String::new();
                        for _ in 0..4 {
                            if let Some(hc) = chars.next() {
                                hex_buf.push(hc);
                            }
                        }
                        if let Ok(cp) = u32::from_str_radix(&hex_buf, 16) {
                            if let Some(ch) = char::from_u32(cp) {
                                out.push(ch);
                                continue;
                            }
                        }
                    }
                }
                out.push(c);
            }
            Ok(DataPayload::text(out))
        } else {
            let mut out = String::new();
            for c in s.chars() {
                if c.is_ascii() && !c.is_control() {
                    out.push(c);
                } else {
                    let cp = c as u32;
                    if cp <= 0xFFFF {
                        out.push_str(&format!("\\u{:04x}", cp));
                    } else {
                        out.push_str(&format!("\\u{{{:x}}}", cp));
                    }
                }
            }
            Ok(DataPayload::text(out))
        }
    }
}

// ======================== OCTAL ESCAPES (\000) ========================
pub struct OctalEscapesOp;
#[async_trait]
impl Operation for OctalEscapesOp {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "encode.octal_escapes",
            "Octal Escapes",
            "Encodes and decodes 3-digit octal byte escape sequences (\\000 - \\377)",
            OperationCategory::Encoders,
        )
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let decode = config.get("decode").and_then(|v| v.as_bool()).unwrap_or(false);
        if decode {
            let s = input.into_text()?;
            let mut out = Vec::new();
            let mut chars = s.chars().peekable();
            while let Some(c) = chars.next() {
                if c == '\\' {
                    let mut oct_buf = String::new();
                    while oct_buf.len() < 3 && chars.peek().map(|ch| ('0'..='7').contains(ch)).unwrap_or(false) {
                        oct_buf.push(chars.next().unwrap());
                    }
                    if !oct_buf.is_empty() {
                        if let Ok(b) = u8::from_str_radix(&oct_buf, 8) {
                            out.push(b);
                            continue;
                        }
                    }
                }
                out.extend_from_slice(c.to_string().as_bytes());
            }
            Ok(DataPayload::bytes(out))
        } else {
            let bytes = input.into_bytes();
            let mut out = String::new();
            for &b in &bytes {
                out.push_str(&format!("\\{:03o}", b));
            }
            Ok(DataPayload::text(out))
        }
    }
}
