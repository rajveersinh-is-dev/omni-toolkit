use omni_core::{
    async_trait, DataPayload, DataType, ExecutionContext, OmniError, OmniResult, Operation,
    OperationCategory, OperationManifest,
};
use serde_json::Value;

// ======================== BASE16 (HEX) ========================
pub struct Base16Op;
#[async_trait]
impl Operation for Base16Op {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "encode.base16",
            "Base16 (Hex)",
            "Encodes and decodes hexadecimal strings according to RFC 4648",
            OperationCategory::Encoders,
        )
        .with_types(vec![DataType::Bytes, DataType::Text], vec![DataType::Text, DataType::Bytes])
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let decode = config.get("decode").and_then(|v| v.as_bool()).unwrap_or(false);
        if decode {
            let s = input.into_text()?;
            let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
            let bytes = hex::decode(&cleaned).map_err(|e| OmniError::InvalidInput(format!("Invalid hex string: {e}")))?;
            Ok(DataPayload::bytes(bytes))
        } else {
            let bytes = input.into_bytes();
            let h = hex::encode(&bytes);
            Ok(DataPayload::text(h))
        }
    }
}

// ======================== BASE32 & BASE32HEX ========================
pub struct Base32Op {
    pub is_hex: bool,
}

#[async_trait]
impl Operation for Base32Op {
    fn manifest(&self) -> OperationManifest {
        let (id, name, desc) = if self.is_hex {
            ("encode.base32hex", "Base32Hex", "Base32 with extended hex alphabet (RFC 4648)")
        } else {
            ("encode.base32", "Base32", "Standard Base32 encoding (RFC 4648)")
        };
        OperationManifest::new(id, name, desc, OperationCategory::Encoders)
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let decode = config.get("decode").and_then(|v| v.as_bool()).unwrap_or(false);
        let codec = if self.is_hex {
            &data_encoding::BASE32HEX
        } else {
            &data_encoding::BASE32
        };

        if decode {
            let s = input.into_text()?;
            let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
            let bytes = codec.decode(cleaned.as_bytes()).map_err(|e| OmniError::InvalidInput(format!("Base32 decode error: {e}")))?;
            Ok(DataPayload::bytes(bytes))
        } else {
            let bytes = input.into_bytes();
            let encoded = codec.encode(&bytes);
            Ok(DataPayload::text(encoded))
        }
    }
}

// ======================== BASE45 ========================
pub struct Base45Op;
#[async_trait]
impl Operation for Base45Op {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "encode.base45",
            "Base45",
            "Base45 encoding used in QR codes and Digital COVID Certificates (RFC 9285)",
            OperationCategory::Encoders,
        )
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let decode = config.get("decode").and_then(|v| v.as_bool()).unwrap_or(false);
        const CHARSET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

        if decode {
            let s = input.into_text()?;
            let chars: Vec<u8> = s.bytes().filter(|b| *b != b'\r' && *b != b'\n' && *b != b'\t').collect();
            if chars.len() % 3 == 1 {
                return Err(OmniError::InvalidInput("Base45 input length cannot be 1 mod 3".into()));
            }

            let mut out = Vec::new();
            let mut i = 0;
            while i < chars.len() {
                let remaining = chars.len() - i;
                if remaining >= 3 {
                    let c0 = CHARSET.iter().position(|&x| x == chars[i]).ok_or_else(|| OmniError::InvalidInput(format!("Invalid base45 char: {}", chars[i] as char)))?;
                    let c1 = CHARSET.iter().position(|&x| x == chars[i+1]).ok_or_else(|| OmniError::InvalidInput(format!("Invalid base45 char: {}", chars[i+1] as char)))?;
                    let c2 = CHARSET.iter().position(|&x| x == chars[i+2]).ok_or_else(|| OmniError::InvalidInput(format!("Invalid base45 char: {}", chars[i+2] as char)))?;
                    let val = c0 + c1 * 45 + c2 * 45 * 45;
                    out.push((val / 256) as u8);
                    out.push((val % 256) as u8);
                    i += 3;
                } else if remaining == 2 {
                    let c0 = CHARSET.iter().position(|&x| x == chars[i]).ok_or_else(|| OmniError::InvalidInput(format!("Invalid base45 char: {}", chars[i] as char)))?;
                    let c1 = CHARSET.iter().position(|&x| x == chars[i+1]).ok_or_else(|| OmniError::InvalidInput(format!("Invalid base45 char: {}", chars[i+1] as char)))?;
                    let val = c0 + c1 * 45;
                    out.push(val as u8);
                    i += 2;
                }
            }
            Ok(DataPayload::bytes(out))
        } else {
            let bytes = input.into_bytes();
            let mut out = String::new();
            let mut i = 0;
            while i < bytes.len() {
                if i + 1 < bytes.len() {
                    let val = (bytes[i] as usize) * 256 + (bytes[i + 1] as usize);
                    let c0 = val % 45;
                    let c1 = (val / 45) % 45;
                    let c2 = (val / (45 * 45)) % 45;
                    out.push(CHARSET[c0] as char);
                    out.push(CHARSET[c1] as char);
                    out.push(CHARSET[c2] as char);
                    i += 2;
                } else {
                    let val = bytes[i] as usize;
                    let c0 = val % 45;
                    let c1 = val / 45;
                    out.push(CHARSET[c0] as char);
                    out.push(CHARSET[c1] as char);
                    i += 1;
                }
            }
            Ok(DataPayload::text(out))
        }
    }
}

// ======================== BASE58 ========================
pub struct Base58Op;
#[async_trait]
impl Operation for Base58Op {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "encode.base58",
            "Base58",
            "Base58 encoding as used in Bitcoin and IPFS",
            OperationCategory::Encoders,
        )
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let decode = config.get("decode").and_then(|v| v.as_bool()).unwrap_or(false);
        if decode {
            let s = input.into_text()?;
            let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
            let bytes = bs58::decode(&cleaned).into_vec().map_err(|e| OmniError::InvalidInput(format!("Base58 decode error: {e}")))?;
            Ok(DataPayload::bytes(bytes))
        } else {
            let bytes = input.into_bytes();
            let encoded = bs58::encode(&bytes).into_string();
            Ok(DataPayload::text(encoded))
        }
    }
}

// ======================== BASE62 ========================
pub struct Base62Op;
#[async_trait]
impl Operation for Base62Op {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "encode.base62",
            "Base62",
            "Alphanumeric Base62 encoding [0-9a-zA-Z]",
            OperationCategory::Encoders,
        )
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let decode = config.get("decode").and_then(|v| v.as_bool()).unwrap_or(false);
        const B62_CHARS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

        if decode {
            let s = input.into_text()?;
            let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
            // Arbitrary precision base conversion
            let mut num: Vec<u8> = Vec::new();
            for c in cleaned.bytes() {
                let val = B62_CHARS.iter().position(|&x| x == c).ok_or_else(|| OmniError::InvalidInput(format!("Invalid Base62 char: {}", c as char)))? as u32;
                let mut carry = val;
                for digit in num.iter_mut() {
                    let total = (*digit as u32) * 62 + carry;
                    *digit = (total % 256) as u8;
                    carry = total / 256;
                }
                while carry > 0 {
                    num.push((carry % 256) as u8);
                    carry /= 256;
                }
            }
            num.reverse();
            Ok(DataPayload::bytes(num))
        } else {
            let bytes = input.into_bytes();
            if bytes.is_empty() {
                return Ok(DataPayload::text(""));
            }
            let mut num: Vec<u8> = Vec::new();
            for &b in &bytes {
                let mut carry = b as u32;
                for digit in num.iter_mut() {
                    let total = (*digit as u32) * 256 + carry;
                    *digit = (total % 62) as u8;
                    carry = total / 62;
                }
                while carry > 0 {
                    num.push((carry % 62) as u8);
                    carry /= 62;
                }
            }
            num.reverse();
            let res: String = num.into_iter().map(|d| B62_CHARS[d as usize] as char).collect();
            Ok(DataPayload::text(res))
        }
    }
}

// ======================== BASE64 & BASE64URL ========================
pub struct Base64Op {
    pub is_url_safe: bool,
}

#[async_trait]
impl Operation for Base64Op {
    fn manifest(&self) -> OperationManifest {
        let (id, name, desc) = if self.is_url_safe {
            ("encode.base64url", "Base64URL", "URL-safe Base64 encoding without padding (RFC 4648)")
        } else {
            ("encode.base64", "Base64", "Standard Base64 encoding (RFC 4648)")
        };
        OperationManifest::new(id, name, desc, OperationCategory::Encoders)
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        use base64::prelude::*;
        let decode = config.get("decode").and_then(|v| v.as_bool()).unwrap_or(false);
        let engine = if self.is_url_safe {
            BASE64_URL_SAFE_NO_PAD
        } else {
            BASE64_STANDARD
        };

        if decode {
            let s = input.into_text()?;
            let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
            let bytes = engine.decode(cleaned.as_bytes()).map_err(|e| OmniError::InvalidInput(format!("Base64 decode error: {e}")))?;
            Ok(DataPayload::bytes(bytes))
        } else {
            let bytes = input.into_bytes();
            let encoded = engine.encode(&bytes);
            Ok(DataPayload::text(encoded))
        }
    }
}

// ======================== BASE85 / ASCII85 ========================
pub struct Base85Op;
#[async_trait]
impl Operation for Base85Op {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "encode.base85",
            "Base85 (Ascii85)",
            "Adobe Ascii85 / Base85 encoding",
            OperationCategory::Encoders,
        )
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let decode = config.get("decode").and_then(|v| v.as_bool()).unwrap_or(false);
        if decode {
            let s = input.into_text()?;
            let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
            let bytes = cleaned.as_bytes();
            let mut out = Vec::new();
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] == b'z' {
                    out.extend_from_slice(&[0, 0, 0, 0]);
                    i += 1;
                    continue;
                }
                let mut chunk = [0u8; 5];
                let mut count = 0;
                while count < 5 && i < bytes.len() {
                    chunk[count] = bytes[i];
                    count += 1;
                    i += 1;
                }
                for item in chunk.iter_mut().skip(count) {
                    *item = b'u'; // pad with 'u' (84)
                }
                let mut val: u32 = 0;
                for &b in &chunk {
                    if !(33..=117).contains(&b) {
                        return Err(OmniError::InvalidInput(format!("Invalid Ascii85 character: {}", b as char)));
                    }
                    val = val * 85 + (b - 33) as u32;
                }
                let b4 = val.to_be_bytes();
                if count > 1 {
                    out.extend_from_slice(&b4[..(count - 1)]);
                }
            }
            Ok(DataPayload::bytes(out))
        } else {
            let bytes = input.into_bytes();
            let mut out = String::new();
            let mut i = 0;
            while i < bytes.len() {
                let remaining = bytes.len() - i;
                let mut chunk = [0u8; 4];
                let count = remaining.min(4);
                chunk[..count].copy_from_slice(&bytes[i..i + count]);
                let val = u32::from_be_bytes(chunk);
                if count == 4 && val == 0 {
                    out.push('z');
                } else {
                    let mut b85 = [0u8; 5];
                    let mut temp = val;
                    for k in (0..5).rev() {
                        b85[k] = (temp % 85) as u8 + 33;
                        temp /= 85;
                    }
                    for &c in &b85[..(count + 1)] {
                        out.push(c as char);
                    }
                }
                i += count;
            }
            Ok(DataPayload::text(out))
        }
    }
}

// ======================== BASE91 ========================
pub struct Base91Op;
#[async_trait]
impl Operation for Base91Op {
    fn manifest(&self) -> OperationManifest {
        OperationManifest::new(
            "encode.base91",
            "Base91",
            "BasE91 binary encoding algorithm",
            OperationCategory::Encoders,
        )
    }

    async fn execute(&self, input: DataPayload, config: Value, _ctx: &ExecutionContext) -> OmniResult<DataPayload> {
        let decode = config.get("decode").and_then(|v| v.as_bool()).unwrap_or(false);
        const B91_TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\"";

        if decode {
            let s = input.into_text()?;
            let mut out = Vec::new();
            let mut v: i32 = -1;
            let mut b: u32 = 0;
            let mut n: u32 = 0;

            for &byte in s.as_bytes() {
                if byte.is_ascii_whitespace() {
                    continue;
                }
                let pos = B91_TABLE.iter().position(|&x| x == byte).ok_or_else(|| OmniError::InvalidInput(format!("Invalid Base91 char: {}", byte as char)))? as i32;
                if v < 0 {
                    v = pos;
                } else {
                    v += pos * 91;
                    b |= (v as u32) << n;
                    n += if (v & 8191) > 88 { 13 } else { 14 };
                    while n >= 8 {
                        out.push((b & 255) as u8);
                        b >>= 8;
                        n -= 8;
                    }
                    v = -1;
                }
            }
            if v >= 0 {
                out.push(((b | ((v as u32) << n)) & 255) as u8);
            }
            Ok(DataPayload::bytes(out))
        } else {
            let bytes = input.into_bytes();
            let mut out = String::new();
            let mut b: u32 = 0;
            let mut n: u32 = 0;

            for &byte in &bytes {
                b |= (byte as u32) << n;
                n += 8;
                if n > 13 {
                    let mut v = b & 8191;
                    if v > 88 {
                        b >>= 13;
                        n -= 13;
                    } else {
                        v = b & 16383;
                        b >>= 14;
                        n -= 14;
                    }
                    out.push(B91_TABLE[(v % 91) as usize] as char);
                    out.push(B91_TABLE[(v / 91) as usize] as char);
                }
            }
            if n > 0 {
                out.push(B91_TABLE[(b % 91) as usize] as char);
                if n > 7 || b > 90 {
                    out.push(B91_TABLE[(b / 91) as usize] as char);
                }
            }
            Ok(DataPayload::text(out))
        }
    }
}
