use thiserror::Error;

/// Bundle Protocol SDK Result type
pub type BpResult<T> = Result<T, BpError>;

/// Bundle Protocol SDK Error types
#[derive(Error, Debug, Clone, PartialEq)]
pub enum BpError {
    #[error("Invalid arguments provided")]
    InvalidArgs,
    
    #[error("SDK not initialized")]
    NotInitialized,
    
    #[error("Memory allocation failed")]
    Memory,
    
    #[error("Operation timed out")]
    Timeout,
    
    #[error("Resource not found")]
    NotFound,
    
    #[error("Duplicate resource")]
    Duplicate,
    
    #[error("Protocol error: {0}")]
    Protocol(String),
    
    #[error("Routing error: {0}")]
    Routing(String),
    
    #[error("Storage error: {0}")]
    Storage(String),
    
    #[error("Security error: {0}")]
    Security(String),
    
    #[error("ION-DTN error: {code}")]
    Ion { code: i32 },
    
    #[error("FFI error: {0}")]
    Ffi(String),
}

/// Convert from C error codes
impl From<i32> for BpError {
    fn from(code: i32) -> Self {
        match code {
            0 => unreachable!("Success code should not be converted to error"),
            -1 => Self::InvalidArgs,
            -2 => Self::NotInitialized,
            -3 => Self::Memory,
            -4 => Self::Timeout,
            -5 => Self::NotFound,
            -6 => Self::Duplicate,
            -7 => Self::Protocol("Protocol error".to_string()),
            -8 => Self::Routing("Routing error".to_string()),
            -9 => Self::Storage("Storage error".to_string()),
            -10 => Self::Security("Security error".to_string()),
            code => Self::Ion { code },
        }
    }
} 