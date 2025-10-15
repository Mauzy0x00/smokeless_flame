use bincode::{Decode, Encode};
use std::path::PathBuf;

#[derive(Debug, Clone, Encode, Decode)]
pub struct FileStat {
    pub size: u64,
    pub mode: u32,
    pub modified_time: u64,
    pub access_time: u64,
    pub is_dir: bool,
}

#[derive(Debug, Clone, Encode, Decode)]
pub enum FileType {
    File,
    Directory,
    Symlink,
    Other,
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct DirEntry {
    pub name: String,
    pub file_type: FileType,
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct NfsMessage {
    pub operation: NfsOperation,
}

#[derive(Debug, Clone, Encode, Decode)]
pub enum NfsOperation {
    Read {
        path: PathBuf,
        offset: u64,
        length: u64,
    },
    Write {
        path: PathBuf,
        offset: u64,
        data: Vec<u8>,
    },
    Create {
        path: PathBuf,
        mode: u32,
    },
    Mkdir {
        path: PathBuf,
        mode: u32,
    },
    Remove {
        path: PathBuf,
    },
    Stat {
        path: PathBuf,
    },
    Readdir {
        path: PathBuf,
    },
    Rename {
        from: PathBuf,
        to: PathBuf,
    },
    Symlink {
        target: PathBuf,
        linkpath: PathBuf,
    },
    Fsync {
        path: PathBuf,
    },
    // Add more operations as needed for NFS functionality
}

#[derive(Debug, Clone, Encode, Decode)]
pub enum NfsResponse {
    Success(Vec<u8>),
    Error(String),
}

// Handshake protocol
#[derive(Debug, Clone, Encode, Decode)]
pub struct HandshakeRequest {
    pub protocol_version: u32,
    pub public_key: Vec<u8>,
    pub cipher_suites: Vec<CipherSuite>,
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct HandshakeResponse {
    pub status: HandshakeStatus,
    pub server_public_key: Option<Vec<u8>>,
    pub selected_cipher_suite: Option<CipherSuite>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub enum HandshakeStatus {
    Success,
    UnsupportedVersion,
    NoCipherSuiteMatch,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub enum CipherSuite {
    // Modern cipher suites
    XChaCha20Poly1305,
    AesGcm256,
    // Legacy cipher suites
    Aes256CbcHmacSha256,
}

impl CipherSuite {
    pub fn is_supported(&self) -> bool {
        match self {
            CipherSuite::XChaCha20Poly1305 => true,
            CipherSuite::AesGcm256 => true,
            CipherSuite::Aes256CbcHmacSha256 => true,
        }
    }
}

// Authentication structures
#[derive(Debug, Clone, Encode, Decode)]
pub struct AuthRequest {
    pub username: String,
    pub client_proof: Vec<u8>, // Result of SRP protocol or similar
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct AuthResponse {
    pub status: AuthStatus,
    pub server_proof: Option<Vec<u8>>,
    pub session_id: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub enum AuthStatus {
    Success,
    InvalidCredentials,
    AccessDenied,
    Error,
}
