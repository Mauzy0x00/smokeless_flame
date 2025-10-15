use std::path::PathBuf;

use smol::net::{TcpListener, TcpStream};
use smol::prelude::*;
use smol::spawn;

use crate::async_io::AsyncConnection;
use crate::encryption::{EncryptionManager, KeyPair};
use crate::error::NfsError;
use crate::filesystem::FileSystemManager;
use crate::protocol::{NfsMessage, NfsOperation, NfsResponse};

pub struct NfsServer {
    fs_manager: FileSystemManager,
    encryption_manager: EncryptionManager,
    export_path: PathBuf,
    bind_address: String,
}

impl NfsServer {
    pub fn new(
        export_path: PathBuf,
        bind_address: String,
        keypair: KeyPair,
    ) -> Result<Self, NfsError> {
        // Validate the export path exists
        if !export_path.exists() || !export_path.is_dir() {
            return Err(NfsError::InvalidExportPath(export_path));
        }

        Ok(Self {
            fs_manager: FileSystemManager::new(),
            encryption_manager: EncryptionManager::new(keypair),
            export_path,
            bind_address,
        })
    }

    pub async fn run(&self) -> Result<(), NfsError> {
        let listener = TcpListener::bind(&self.bind_address).await?;
        log::info!("NFS server listening on {}", self.bind_address);

        let mut incoming = listener.incoming();

        while let Some(stream) = incoming.next().await {
            let stream = stream?;
            let server = self.clone();

            // A new task for each client
            spawn(async move {
                if let Err(e) = server.handle_client(stream).await {
                    log::error!("Error handling client: {:?}", e);
                }
            });
        }

        Ok(())
    }

    async fn handle_client(&self, stream: TcpStream) -> Result<(), NfsError> {
        let peer_addr = stream.peer_addr()?;
        log::info!("New connection from {}", peer_addr);

        let mut connection = AsyncConnection::new(stream);

        // Perform handshake and setup encryption
        self.perform_handshake(&mut connection).await?;

        // Process client requests
        loop {
            match connection.receive_message::<NfsMessage>().await {
                Ok(message) => {
                    let response = self.handle_operation(message.operation, &peer_addr).await?;
                    connection
                        .send_message(&NfsResponse::Success(response))
                        .await?;
                }
                Err(e) => {
                    log::error!("Error receiving message from {}: {:?}", peer_addr, e);
                    connection
                        .send_message(&NfsResponse::Error(e.to_string()))
                        .await?;
                    break;
                }
            }
        }

        Ok(())
    }

    async fn perform_handshake(&self, connection: &mut AsyncConnection) -> Result<(), NfsError> {
        // Exchange public keys and establish secure channel
        // ... implementation details ...
        Ok(())
    }

    async fn handle_operation(
        &self,
        operation: NfsOperation,
        client_addr: &std::net::SocketAddr,
    ) -> Result<Vec<u8>, NfsError> {
        match operation {
            NfsOperation::Read {
                path,
                offset,
                length,
            } => {
                let abs_path = self.resolve_path(path)?;
                let data = self.fs_manager.read_file(abs_path, offset, length).await?;
                Ok(data)
            }
            NfsOperation::Write { path, offset, data } => {
                let abs_path = self.resolve_path(path)?;
                self.fs_manager.write_file(abs_path, offset, &data).await?;
                Ok(vec![])
            }
            NfsOperation::Create { path, mode } => {
                let abs_path = self.resolve_path(path)?;
                self.fs_manager.create_file(abs_path, mode).await?;
                Ok(vec![])
            }
            NfsOperation::Mkdir { path, mode } => {
                let abs_path = self.resolve_path(path)?;
                self.fs_manager.create_directory(abs_path, mode).await?;
                Ok(vec![])
            }
            NfsOperation::Remove { path } => {
                let abs_path = self.resolve_path(path)?;
                self.fs_manager.remove(abs_path).await?;
                Ok(vec![])
            }
            NfsOperation::Stat { path } => {
                let abs_path = self.resolve_path(path)?;
                let stat = self.fs_manager.stat(abs_path).await?;
                // Serialize stat info
                Ok(bincode::encode_to_vec(&stat, bincode::config::standard())?)
            }
            NfsOperation::Readdir { path } => {
                let abs_path = self.resolve_path(path)?;
                let entries = self.fs_manager.read_dir(abs_path).await?;
                // Serialize directory entries
                Ok(bincode::encode_to_vec(
                    &entries,
                    bincode::config::standard(),
                )?)
            }
            NfsOperation::Rename { from, to } => {
                let abs_from = self.resolve_path(from)?;
                let abs_to = self.resolve_path(to)?;
                self.fs_manager.rename(abs_from, abs_to).await?;
                Ok(vec![])
            }
            NfsOperation::Symlink { target, linkpath } => {
                let abs_target = self.resolve_path(target)?;
                let abs_linkpath = self.resolve_path(linkpath)?;
                self.fs_manager
                    .create_symlink(abs_target, abs_linkpath)
                    .await?;
                Ok(vec![])
            }
            NfsOperation::Fsync { path } => {
                let abs_path = self.resolve_path(path)?;
                self.fs_manager.fsync(abs_path).await?;
                Ok(vec![])
            }
        }
    }

    fn resolve_path(&self, relative_path: PathBuf) -> Result<PathBuf, NfsError> {
        // Ensure the path doesn't escape the export directory
        let normalized_path = self.normalize_path(relative_path)?;
        let abs_path = self.export_path.join(normalized_path);

        // Extra security check to prevent path traversal attacks
        if !abs_path.starts_with(&self.export_path) {
            return Err(NfsError::InvalidPath(
                "Path traversal attempt detected".into(),
            ));
        }

        Ok(abs_path)
    }

    fn normalize_path(&self, path: PathBuf) -> Result<PathBuf, NfsError> {
        // Remove "." and ".." components to prevent path traversal attacks
        // ... implementation details ...
        Ok(path)
    }
}

impl Clone for NfsServer {
    fn clone(&self) -> Self {
        Self {
            fs_manager: self.fs_manager.clone(),
            encryption_manager: self.encryption_manager.clone(),
            export_path: self.export_path.clone(),
            bind_address: self.bind_address.clone(),
        }
    }
}
