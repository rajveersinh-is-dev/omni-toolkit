use crate::payload::DataType;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OperationCategory {
    Cryptography,
    Encoders,
    TextAndCode,
    DocumentsAndMedia,
    Networking,
    BinaryAnalysis,
    StorageAndFormats,
    CloudAndDevOps,
    AiAndTensors,
    SystemDiagnostics,
}

impl std::fmt::Display for OperationCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OperationCategory::Cryptography => write!(f, "Cryptography"),
            OperationCategory::Encoders => write!(f, "Encoders & Ciphers"),
            OperationCategory::TextAndCode => write!(f, "Text & Code"),
            OperationCategory::DocumentsAndMedia => write!(f, "Documents & Media"),
            OperationCategory::Networking => write!(f, "Networking & Protocols"),
            OperationCategory::BinaryAnalysis => write!(f, "Binary Analysis & Hardware"),
            OperationCategory::StorageAndFormats => write!(f, "Storage & Filesystems"),
            OperationCategory::CloudAndDevOps => write!(f, "Cloud & DevOps"),
            OperationCategory::AiAndTensors => write!(f, "AI & Tensors"),
            OperationCategory::SystemDiagnostics => write!(f, "System & Diagnostics"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityClassification {
    Safe,
    RestrictedInput,
    NetworkAccess,
    PrivilegedSystem,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRequirements {
    pub max_memory_mb: u64,
    pub timeout_seconds: u64,
    pub max_file_size_mb: u64,
}

impl Default for ResourceRequirements {
    fn default() -> Self {
        Self {
            max_memory_mb: 512,
            timeout_seconds: 30,
            max_file_size_mb: 250,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationManifest {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: OperationCategory,
    pub version: String,
    pub input_types: Vec<DataType>,
    pub output_types: Vec<DataType>,
    pub streaming_supported: bool,
    pub deterministic: bool,
    pub security_level: SecurityClassification,
    pub required_permissions: Vec<String>,
    pub supported_os: Vec<String>,
    pub resource_requirements: ResourceRequirements,
    pub doc_url: Option<String>,
}

impl OperationManifest {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
        category: OperationCategory,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: description.into(),
            category,
            version: "0.1.0".to_string(),
            input_types: vec![DataType::Text, DataType::Bytes],
            output_types: vec![DataType::Text, DataType::Bytes],
            streaming_supported: false,
            deterministic: true,
            security_level: SecurityClassification::Safe,
            required_permissions: Vec::new(),
            supported_os: vec!["windows".into(), "linux".into(), "macos".into()],
            resource_requirements: ResourceRequirements::default(),
            doc_url: None,
        }
    }

    pub fn with_types(mut self, inputs: Vec<DataType>, outputs: Vec<DataType>) -> Self {
        self.input_types = inputs;
        self.output_types = outputs;
        self
    }

    pub fn with_streaming(mut self, streaming: bool) -> Self {
        self.streaming_supported = streaming;
        self
    }

    pub fn with_security(mut self, sec: SecurityClassification) -> Self {
        self.security_level = sec;
        self
    }
}
