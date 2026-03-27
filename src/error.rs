use std::io;

/// Errors that can occur during archive operations.
#[derive(thiserror::Error, Debug)]
pub enum OpenPackError {
    /// An I/O error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// A Zip format error occurred.
    #[error("Zip format error: {0}")]
    Zip(#[from] zip::result::ZipError),

    /// A string conversion error.
    #[error("UTF-8 decoding error: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),
    
    /// Limits exceeded.
    #[error("Archive exceeds safety limits: {0}")]
    LimitsExceeded(String),

    /// Format unsupported.
    #[error("Format is unsupported: {0}")]
    UnsupportedFormat(String),
}

/// Specialized Result pattern for openpack operations.
pub type Result<T> = std::result::Result<T, OpenPackError>;
