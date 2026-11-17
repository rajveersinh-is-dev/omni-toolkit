use thiserror::Error;

#[derive(Error, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum OmniError {
    #[error("Validation failed: {0}")]
    Validation(String),

    #[error("Invalid input data: {0}")]
    InvalidInput(String),

    #[error("Execution error in {operation}: {message}")]
    Execution {
        operation: String,
        message: String,
    },

    #[error("Operation not found: {0}")]
    NotFound(String),

    #[error("Type mismatch: expected {expected}, found {found}")]
    TypeMismatch {
        expected: String,
        found: String,
    },

    #[error("Pipeline error: {0}")]
    Pipeline(String),

    #[error("Security violation: {0}")]
    Security(String),

    #[error("I/O error: {0}")]
    Io(String),

    #[error("Operation timed out after {0} ms")]
    Timeout(u64),

    #[error("Operation cancelled by user")]
    Cancelled,

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type OmniResult<T> = Result<T, OmniError>;
