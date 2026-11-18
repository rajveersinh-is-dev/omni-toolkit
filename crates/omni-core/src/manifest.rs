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

impl OperationCategory {
    /// Parses a category string case-insensitively from enum name, display name, or common aliases.
    pub fn from_str_loose(input: &str) -> Option<Self> {
        let normalized = input.trim().to_lowercase();
        match normalized.as_str() {
            "cryptography" | "crypto" | "security" => Some(Self::Cryptography),
            "encoders" | "encode" | "encoders & ciphers" => Some(Self::Encoders),
            "textandcode" | "text_and_code" | "text & code" | "text" | "code" => {
                Some(Self::TextAndCode)
            }
            "documentsandmedia"
            | "documents_and_media"
            | "documents & media"
            | "documents"
            | "media"
            | "pdf" => Some(Self::DocumentsAndMedia),
            "networking" | "network" | "networking & protocols" | "pcap" => Some(Self::Networking),
            "binaryanalysis"
            | "binary_analysis"
            | "binary analysis & hardware"
            | "binary"
            | "firmware" => Some(Self::BinaryAnalysis),
            "storageandformats"
            | "storage_and_formats"
            | "storage & filesystems"
            | "storage"
            | "filesystems" => Some(Self::StorageAndFormats),
            "cloudanddevops"
            | "cloud_and_devops"
            | "cloud & devops"
            | "cloud"
            | "devops"
            | "infrastructure" => Some(Self::CloudAndDevOps),
            "aiandtensors" | "ai_and_tensors" | "ai & tensors" | "ai" | "ml" => {
                Some(Self::AiAndTensors)
            }
            "systemdiagnostics"
            | "system_diagnostics"
            | "system & diagnostics"
            | "system"
            | "diagnostics" => Some(Self::SystemDiagnostics),
            _ => None,
        }
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeatureStatus {
    Planned,
    InProgress,
    Experimental,
    Implemented,
    Verified,
    Unsupported,
}

impl FeatureStatus {
    pub fn from_str_loose(input: &str) -> Option<Self> {
        match input.trim().to_lowercase().as_str() {
            "planned" => Some(Self::Planned),
            "in_progress" | "inprogress" => Some(Self::InProgress),
            "experimental" => Some(Self::Experimental),
            "implemented" => Some(Self::Implemented),
            "verified" => Some(Self::Verified),
            "unsupported" => Some(Self::Unsupported),
            _ => None,
        }
    }
}

impl std::fmt::Display for FeatureStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Planned => write!(f, "planned"),
            Self::InProgress => write!(f, "in_progress"),
            Self::Experimental => write!(f, "experimental"),
            Self::Implemented => write!(f, "implemented"),
            Self::Verified => write!(f, "verified"),
            Self::Unsupported => write!(f, "unsupported"),
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InputPortSpec {
    pub name: String,
    pub required: bool,
    pub accepted_types: Vec<DataType>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationManifest {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: OperationCategory,
    pub version: String,
    pub status: FeatureStatus,
    pub tags: Vec<String>,
    pub limitations: Vec<String>,
    pub input_types: Vec<DataType>,
    pub output_types: Vec<DataType>,
    pub accepts_multi_input: bool,
    pub input_ports: Vec<InputPortSpec>,
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
            status: FeatureStatus::Implemented,
            tags: Vec::new(),
            limitations: Vec::new(),
            input_types: vec![DataType::Text, DataType::Bytes],
            output_types: vec![DataType::Text, DataType::Bytes],
            accepts_multi_input: false,
            input_ports: Vec::new(),
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

    pub fn with_status(mut self, status: FeatureStatus) -> Self {
        self.status = status;
        self
    }

    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    pub fn with_limitations(mut self, limitations: Vec<String>) -> Self {
        self.limitations = limitations;
        self
    }

    pub fn with_multi_input(mut self, accepts: bool) -> Self {
        self.accepts_multi_input = accepts;
        self
    }

    pub fn with_input_ports(mut self, ports: Vec<InputPortSpec>) -> Self {
        self.accepts_multi_input = true;
        self.input_ports = ports;
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

    /// Checks whether any output type from a producer operation is compatible with this operation's inputs.
    pub fn accepts_output_from(&self, producer_outputs: &[DataType]) -> bool {
        if self.input_types.contains(&DataType::Any) || producer_outputs.contains(&DataType::Any) {
            return true;
        }
        producer_outputs.iter().any(|out| {
            self.input_types.contains(out)
                // Text is UTF-8 bytes, so operations accepting Bytes can always consume Text.
                || (*out == DataType::Text && self.input_types.contains(&DataType::Bytes))
        })
    }
}
