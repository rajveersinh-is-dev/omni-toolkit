use crate::error::{OmniError, OmniResult};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataType {
    Text,
    Bytes,
    Json,
    FileRef,
    Any,
}

impl std::fmt::Display for DataType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DataType::Text => write!(f, "text"),
            DataType::Bytes => write!(f, "bytes"),
            DataType::Json => write!(f, "json"),
            DataType::FileRef => write!(f, "file"),
            DataType::Any => write!(f, "any"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "data")]
pub enum DataPayload {
    Text(String),
    Bytes(Vec<u8>),
    Json(serde_json::Value),
    FileRef(PathBuf),
}

impl DataPayload {
    pub fn text(s: impl Into<String>) -> Self {
        DataPayload::Text(s.into())
    }

    pub fn bytes(b: impl Into<Vec<u8>>) -> Self {
        DataPayload::Bytes(b.into())
    }

    pub fn json(v: serde_json::Value) -> Self {
        DataPayload::Json(v)
    }

    pub fn file_ref(p: impl Into<PathBuf>) -> Self {
        DataPayload::FileRef(p.into())
    }

    pub fn data_type(&self) -> DataType {
        match self {
            DataPayload::Text(_) => DataType::Text,
            DataPayload::Bytes(_) => DataType::Bytes,
            DataPayload::Json(_) => DataType::Json,
            DataPayload::FileRef(_) => DataType::FileRef,
        }
    }

    pub fn as_str(&self) -> OmniResult<&str> {
        match self {
            DataPayload::Text(s) => Ok(s.as_str()),
            DataPayload::Bytes(b) => std::str::from_utf8(b).map_err(|e| {
                OmniError::TypeMismatch {
                    expected: "valid UTF-8 string".into(),
                    found: format!("binary bytes ({e})"),
                }
            }),
            DataPayload::Json(v) => {
                if let serde_json::Value::String(s) = v {
                    Ok(s.as_str())
                } else {
                    Err(OmniError::TypeMismatch {
                        expected: "string".into(),
                        found: format!("json {}", v),
                    })
                }
            }
            DataPayload::FileRef(p) => Err(OmniError::TypeMismatch {
                expected: "inline string".into(),
                found: format!("file reference ({})", p.display()),
            }),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            DataPayload::Bytes(b) => b.as_slice(),
            DataPayload::Text(s) => s.as_bytes(),
            DataPayload::Json(_) => &[],
            DataPayload::FileRef(_) => &[],
        }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            DataPayload::Bytes(b) => b,
            DataPayload::Text(s) => s.into_bytes(),
            DataPayload::Json(v) => serde_json::to_vec(&v).unwrap_or_default(),
            DataPayload::FileRef(p) => std::fs::read(&p).unwrap_or_default(),
        }
    }

    pub fn into_text(self) -> OmniResult<String> {
        match self {
            DataPayload::Text(s) => Ok(s),
            DataPayload::Bytes(b) => String::from_utf8(b).map_err(|e| OmniError::TypeMismatch {
                expected: "valid UTF-8 text".into(),
                found: format!("binary stream ({e})"),
            }),
            DataPayload::Json(v) => {
                if let serde_json::Value::String(s) = v {
                    Ok(s)
                } else {
                    serde_json::to_string_pretty(&v).map_err(|e| OmniError::Execution {
                        operation: "into_text".into(),
                        message: e.to_string(),
                    })
                }
            }
            DataPayload::FileRef(p) => std::fs::read_to_string(&p).map_err(|e| OmniError::Io(e.to_string())),
        }
    }

    pub fn into_json(self) -> OmniResult<serde_json::Value> {
        match self {
            DataPayload::Json(v) => Ok(v),
            DataPayload::Text(s) => serde_json::from_str(&s).map_err(|e| OmniError::InvalidInput(format!("JSON parse error: {e}"))),
            DataPayload::Bytes(b) => serde_json::from_slice(&b).map_err(|e| OmniError::InvalidInput(format!("JSON parse error: {e}"))),
            DataPayload::FileRef(p) => {
                let s = std::fs::read_to_string(&p).map_err(|e| OmniError::Io(e.to_string()))?;
                serde_json::from_str(&s).map_err(|e| OmniError::InvalidInput(format!("JSON parse error: {e}")))
            }
        }
    }

    pub fn size_bytes(&self) -> usize {
        match self {
            DataPayload::Text(s) => s.len(),
            DataPayload::Bytes(b) => b.len(),
            DataPayload::Json(v) => serde_json::to_string(v).map(|s| s.len()).unwrap_or(0),
            DataPayload::FileRef(p) => std::fs::metadata(p).map(|m| m.len() as usize).unwrap_or(0),
        }
    }
}
