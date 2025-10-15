

use std::path::{Path, PathBuf};
use std::io::Write;

use smol::io::{stdin, BufReader};
use smol::net::{TcpListener, TcpStream};
use futures_lite::io::BufReadExt;
use futures_lite::stream::StreamExt;
use futures_lite::{select, FutureExt};

//use bincode::config::standard;
use bincode::{Decode, Encode};

//use crate::filesystem::FileSystemManager;
use lib::encryption::{EncryptionManager, KeyPair};
use lib::async_io::AsyncConnection;
use lib::protocol::{NfsMessage, NfsOperation, NfsResponse, FileStat, DirEntry};
use lib::error::NfsError;

pub struct NfsClient {
    server_address: String,
    encryption_manager: EncryptionManager,
    connection: Option<AsyncConnection>,
    mount_point: PathBuf,
}

impl NfsClient {
    pub fn new(server_address: String, mount_point: PathBuf, keypair: KeyPair) -> Self {
        Self {
            server_address,
            encryption_manager: EncryptionManager::new(keypair),
            connection: None,
            mount_point,
        }
    }
    
    pub async fn connect(&mut self) -> Result<(), NfsError> {
        log::info!("Connecting to NFS server at {}", self.server_address);
        
        let stream = TcpStream::connect(&self.server_address).await?;
        let mut connection = AsyncConnection::new(stream);
        
        // Perform handshake and setup encryption
        self.perform_handshake(&mut connection).await?;
        
        self.connection = Some(connection);
        log::info!("Connected to NFS server");
        
        Ok(())
    }

    async fn perform_handshake(&self, connection: &mut AsyncConnection) -> Result<(), NfsError> {
        // Exchange public keys and establish secure channel
        // ... implementation details ...
        Ok(())
    }

    pub async fn run(&mut self) -> Result<(), NfsError> {

        let mut lines_from_stdin = BufReader::new(stdin()).lines().fuse();
        
        loop {
            print!("> ");
            std::io::stdout().flush().unwrap();
            
            match lines_from_stdin.next().await {
                Some(line) => {
                    let line = line?;
                    if line.trim() == "exit" || line.trim() == "quit" {
                        break;
                    }
                    
                    self.process_command(line).await?;
                }
                None => break,
            }
        }
        
        Ok(())
    }

    async fn process_command(&mut self, command_line: String) -> Result<(), NfsError> {
        let parts: Vec<&str> = command_line.split_whitespace().collect();
        
        if parts.is_empty() {
            return Ok(());
        }
        
        let command = parts[0];
        match command {
            "help" => {
                println!("Available commands:");
                println!("  ls <path>               - List directory contents");
                println!("  mkdir <path> [mode]     - Create directory (default mode: 0755)");
                println!("  rm <path>               - Remove file or directory");
                println!("  stat <path>             - Display file/directory information");
                println!("  cat <path>              - Display file contents");
                println!("  write <path> <content>  - Write content to a file");
                println!("  touch <path> [mode]     - Create empty file (default mode: 0644)");
                println!("  cp <from> <to>          - Rename/move a file or directory");
                println!("  ln -s <target> <link>   - Create symbolic link");
                println!("  fsync <path>            - Force write of file to storage");
                println!("  exit                    - Exit the client");
            },
            // "ls" => {
            //     if parts.len() < 2 {
            //         println!("Usage: ls <path>");
            //         return Ok(());
            //     }
            //     let path = PathBuf::from(parts[1]);
            //     self.list_directory(path).await?;
            // },
            "mkdir" => {
                if parts.len() < 2 {
                    println!("Usage: mkdir <path> [mode]");
                    return Ok(());
                }
                let path = PathBuf::from(parts[1]);
                let mode = parts.get(2)
                    .map(|m| u32::from_str_radix(m, 8).unwrap_or(0o755))
                    .unwrap_or(0o755);
                
                self.create_directory(path, mode).await?;
                println!("Directory created successfully");
            },
            "rm" => {
                if parts.len() < 2 {
                    println!("Usage: rm <path>");
                    return Ok(());
                }
                let path = PathBuf::from(parts[1]);
                self.remove(path).await?;
                println!("Removed successfully");
            },
            "stat" => {
                if parts.len() < 2 {
                    println!("Usage: stat <path>");
                    return Ok(());
                }
                let path = PathBuf::from(parts[1]);
                let stat = self.stat(path.clone()).await?;
                println!("Stats for {}:", path.display());
                println!("  Size: {} bytes", stat.size);
                println!("  Mode: {:o}", stat.mode);
                println!("  Type: {}", if stat.is_dir { "Directory" } else { "File" });
                println!("  Modified: {}", chrono::DateTime::from_timestamp(stat.modified_time as i64, 0)
                    .map(|dt| dt.to_string()).unwrap_or_else(|| "Unknown".to_string()));
                println!("  Accessed: {}", chrono::DateTime::from_timestamp(stat.access_time as i64, 0)
                    .map(|dt| dt.to_string()).unwrap_or_else(|| "Unknown".to_string()));
            },
            "cat" => {
                if parts.len() < 2 {
                    println!("Usage: cat <path>");
                    return Ok(());
                }
                let path = PathBuf::from(parts[1]);
                let content = self.read_file(path, 0, u64::MAX).await?;
                
                // Print file content (assuming it's UTF-8 text)
                match std::str::from_utf8(&content) {
                    Ok(text) => println!("{}", text),
                    Err(_) => println!("(Binary content, {} bytes)", content.len()),
                }
            },
            "write" => {
                if parts.len() < 3 {
                    println!("Usage: write <path> <content>");
                    return Ok(());
                }
                let path = PathBuf::from(parts[1]);
                let content = parts[2..].join(" ").into_bytes();
                
                self.write_file(path, 0, content).await?;
                println!("Write successful");
            },
            "touch" => {
                if parts.len() < 2 {
                    println!("Usage: touch <path> [mode]");
                    return Ok(());
                }
                let path = PathBuf::from(parts[1]);
                let mode = parts.get(2)
                    .map(|m| u32::from_str_radix(m, 8).unwrap_or(0o644))
                    .unwrap_or(0o644);
                
                self.create_file(path, mode).await?;
                println!("File created successfully");
            },
            // "cp" => {
            //     if parts.len() < 3 {
            //         println!("Usage: cp <from> <to>");
            //         return Ok(());
            //     }
            //     let from = PathBuf::from(parts[1]);
            //     let to = PathBuf::from(parts[2]);
                
            //     self.rename(from, to).await?;
            //     println!("Rename/move successful");
            // },
            // "ln" => {
            //     if parts.len() < 4 || parts[1] != "-s" {
            //         println!("Usage: ln -s <target> <link>");
            //         return Ok(());
            //     }
            //     let target = PathBuf::from(parts[2]);
            //     let link = PathBuf::from(parts[3]);
                
            //     self.symlink(target, link).await?;
            //     println!("Symlink created successfully");
            // },
            // "fsync" => {
            //     if parts.len() < 2 {
            //         println!("Usage: fsync <path>");
            //         return Ok(());
            //     }
            //     let path = PathBuf::from(parts[1]);
                
            //     self.fsync(path).await?;
            //     println!("Fsync successful");
            // },
            _ => {
                println!("Unknown command: {}. Type 'help' for available commands.", command);
            }
        }
        
        Ok(())
    }
    
    pub async fn disconnect(&mut self) -> Result<(), NfsError> {
        self.connection = None;
        Ok(())
    }
    
    async fn send_operation(&mut self, operation: NfsOperation) -> Result<Vec<u8>, NfsError> {
        let connection = self.connection.as_mut()
            .ok_or(NfsError::NotConnected)?;
            
        let message = NfsMessage { operation };
        connection.send_message(&message).await?;
        
        match connection.receive_message::<NfsResponse>().await? {
            NfsResponse::Success(data) => Ok(data),
            NfsResponse::Error(msg) => Err(NfsError::RemoteError(msg)),
        }
    }
    
    async fn read_file(&mut self, path: impl AsRef<Path>, offset: u64, length: u64) -> Result<Vec<u8>, NfsError> {
        let operation = NfsOperation::Read {
            path: path.as_ref().to_path_buf(),
            offset,
            length,
        };
        
        self.send_operation(operation).await
    }
    
    async fn write_file(&mut self, path: impl AsRef<Path>, offset: u64, data: Vec<u8>) -> Result<(), NfsError> {
        let operation = NfsOperation::Write {
            path: path.as_ref().to_path_buf(),
            offset,
            data,
        };
        
        let _ = self.send_operation(operation).await?;
        Ok(())
    }
    
    async fn create_file(&mut self, path: impl AsRef<Path>, mode: u32) -> Result<(), NfsError> {
        let operation = NfsOperation::Create {
            path: path.as_ref().to_path_buf(),
            mode,
        };
        
        let _ = self.send_operation(operation).await?;
        Ok(())
    }
    
    async fn create_directory(&mut self, path: impl AsRef<Path>, mode: u32) -> Result<(), NfsError> {
        let operation = NfsOperation::Mkdir {
            path: path.as_ref().to_path_buf(),
            mode,
        };
        
        let _ = self.send_operation(operation).await?;
        Ok(())
    }
    
    async fn remove(&mut self, path: impl AsRef<Path>) -> Result<(), NfsError> {
        let operation = NfsOperation::Remove {
            path: path.as_ref().to_path_buf(),
        };
        
        let _ = self.send_operation(operation).await?;
        Ok(())
    }
    
    /// An asynchronous function designed to retrieve metadata (stat information) about a file or directory specified by its path. 
    /// It interacts with the network file system to perform this operation. The function returns a `Result` type that, on success, 
    /// contains a `FileStat` structure with the file's metadata, or an `NfsError` if something goes wrong.
    async fn stat(&mut self, path: impl AsRef<Path>) -> Result<FileStat, NfsError> {
        let operation = NfsOperation::Stat {
            path: path.as_ref().to_path_buf(),
        };
        
        let data = self.send_operation(operation).await?;
        // let stat: FileStat = bincode::decode_from_slice(&data, bincode::config::standard())?;
        // Ok(stat)
        match bincode::decode_from_slice(&data, bincode::config::standard()) {
            Ok((stat, _)) => Ok(stat),
            Err(e) => Err(NfsError::DeserializationError(e.to_string()))
        }
    }
    
    async fn read_dir(&mut self, path: impl AsRef<Path>) -> Result<Vec<DirEntry>, NfsError> {
        let operation = NfsOperation::Readdir {
            path: path.as_ref().to_path_buf(),
        };
        
        let data = self.send_operation(operation).await?;
        let (entries, _) = bincode::decode_from_slice(&data, bincode::config::standard())?;
        Ok(entries)
    }
}
