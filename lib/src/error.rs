use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum NfsError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("Invalid path: {0}")]
    InvalidPath(String),

    #[error("Invalid export path: {0}")]
    InvalidExportPath(PathBuf),

    #[error("Path not found: {0}")]
    PathNotFound(PathBuf),

    #[error("Permission denied: {0}")]
    PermissionDenied(PathBuf),

    #[error("Not connected to server")]
    NotConnected,

    #[error("Remote error: {0}")]
    RemoteError(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Encryption not established")]
    EncryptionNotEstablished,

    #[error("Key derivation failed")]
    KeyDerivationFailed,

    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Invalid ciphertext")]
    InvalidCiphertext,

    #[error("Invalid key length")]
    InvalidKeyLength,

    #[error("Invalid public key")]
    InvalidPublicKey,

    #[error("Invalid encryption state")]
    InvalidEncryptionState,

    #[error("Unsupported cipher suite")]
    UnsupportedCipherSuite,

    #[error("Lock error")]
    LockError,

    #[error("Timeout")]
    Timeout,

    #[error("Platform-specific error: {0}")]
    PlatformSpecific(String),

    #[error("Ctrl+C error{0}")]
    CtrlCError(String),
}

impl From<bincode::error::EncodeError> for NfsError {
    fn from(err: bincode::error::EncodeError) -> Self {
        NfsError::SerializationError(err.to_string())
    }
}

impl From<bincode::error::DecodeError> for NfsError {
    fn from(err: bincode::error::DecodeError) -> Self {
        NfsError::DeserializationError(err.to_string())
    }
}

impl From<ctrlc::Error> for NfsError {
    fn from(err: ctrlc::Error) -> Self {
        NfsError::CtrlCError(err.to_string())
    }
}
