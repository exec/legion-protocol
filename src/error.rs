//! Error types for the Legion Protocol library

use thiserror::Error;

/// The main error type for Legion Protocol operations
#[derive(Error, Debug, Clone, PartialEq)]
pub enum IronError {
    /// Parse error when processing IRC messages or protocol data
    #[error("Parse error: {0}")]
    Parse(String),

    /// Security violation detected
    #[error("Security violation: {0}")]
    SecurityViolation(String),

    /// Authentication failure
    #[error("Authentication failed: {0}")]
    Auth(String),

    /// Connection error
    #[error("Connection error: {0}")]
    Connection(String),

    /// Protocol violation
    #[error("Protocol violation: {0}")]
    Protocol(String),

    /// Rate limiting violation
    #[error("Rate limit exceeded: {0}")]
    RateLimit(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Capability negotiation error
    #[error("Capability error: {0}")]
    Capability(String),

    /// SASL authentication error
    #[error("SASL error: {0}")]
    Sasl(String),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(String),

    /// Timeout error
    #[error("Timeout: {0}")]
    Timeout(String),

    /// Invalid input
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Feature not supported
    #[error("Feature not supported: {0}")]
    NotSupported(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

/// A specialized Result type for Iron Protocol operations
pub type Result<T> = std::result::Result<T, IronError>;

impl From<std::io::Error> for IronError {
    fn from(err: std::io::Error) -> Self {
        IronError::Io(err.to_string())
    }
}

#[cfg(feature = "serde")]
impl From<serde_json::Error> for IronError {
    fn from(err: serde_json::Error) -> Self {
        IronError::Parse(format!("JSON parse error: {}", err))
    }
}

impl IronError {
    /// Returns true if this error indicates a security violation
    pub fn is_security_violation(&self) -> bool {
        matches!(self, IronError::SecurityViolation(_))
    }

    /// Returns true if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            IronError::Parse(_) |
            IronError::Protocol(_) |
            IronError::RateLimit(_) |
            IronError::Timeout(_) |
            IronError::InvalidInput(_) => true,
            
            IronError::SecurityViolation(_) |
            IronError::Auth(_) |
            IronError::Connection(_) |
            IronError::Config(_) |
            IronError::Capability(_) |
            IronError::Sasl(_) |
            IronError::Io(_) |
            IronError::NotSupported(_) |
            IronError::Internal(_) => false,
        }
    }

    /// Returns the error category
    pub fn category(&self) -> &'static str {
        match self {
            IronError::Parse(_) => "parse",
            IronError::SecurityViolation(_) => "security",
            IronError::Auth(_) => "auth",
            IronError::Connection(_) => "connection",
            IronError::Protocol(_) => "protocol",
            IronError::RateLimit(_) => "rate_limit",
            IronError::Config(_) => "config",
            IronError::Capability(_) => "capability",
            IronError::Sasl(_) => "sasl",
            IronError::Io(_) => "io",
            IronError::Timeout(_) => "timeout",
            IronError::InvalidInput(_) => "invalid_input",
            IronError::NotSupported(_) => "not_supported",
            IronError::Internal(_) => "internal",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_categories() {
        assert_eq!(IronError::Parse("test".to_string()).category(), "parse");
        assert_eq!(IronError::SecurityViolation("test".to_string()).category(), "security");
        assert_eq!(IronError::Auth("test".to_string()).category(), "auth");
    }

    #[test]
    fn test_security_violation_detection() {
        assert!(IronError::SecurityViolation("test".to_string()).is_security_violation());
        assert!(!IronError::Parse("test".to_string()).is_security_violation());
    }

    #[test]
    fn test_recoverable_errors() {
        assert!(IronError::Parse("test".to_string()).is_recoverable());
        assert!(IronError::Protocol("test".to_string()).is_recoverable());
        assert!(!IronError::SecurityViolation("test".to_string()).is_recoverable());
        assert!(!IronError::Auth("test".to_string()).is_recoverable());
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "test");
        let iron_err: IronError = io_err.into();
        assert!(matches!(iron_err, IronError::Io(_)));
    }
}