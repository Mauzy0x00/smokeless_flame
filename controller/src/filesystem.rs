use smol::unblock;
use std::fs::{self, File, OpenOptions};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

#[cfg(unix)]
use nix::fcntl::{self, OFlag};
#[cfg(unix)]
use nix::sys::stat::Mode;
#[cfg(unix)]
use nix::unistd;

use crate::error::NfsError;
use crate::protocol::{DirEntry, FileStat, FileType};

pub struct PlatformFileSystem {
    // Linux-specific state
}

impl PlatformFileSystem {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn read_file(
        &self,
        path: PathBuf,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, NfsError> {
        unblock(move || {
            let mut file = File::open(&path).map_err(|e| NfsError::IoError(e))?;

            let metadata = file.metadata().map_err(|e| NfsError::IoError(e))?;

            // Validate offset and length
            if offset >= metadata.len() {
                return Ok(Vec::new());
            }

            let actual_length = std::cmp::min(length, metadata.len() - offset);

            // Seek to the offset
            use std::io::{Read, Seek, SeekFrom};
            file.seek(SeekFrom::Start(offset))
                .map_err(|e| NfsError::IoError(e))?;

            // Read the data
            let mut buffer = vec![0u8; actual_length as usize];
            file.read_exact(&mut buffer)
                .map_err(|e| NfsError::IoError(e))?;

            Ok(buffer)
        })
        .await
    }

    pub async fn write_file(
        &self,
        path: PathBuf,
        offset: u64,
        data: &[u8],
    ) -> Result<(), NfsError> {
        let data_owned = data.to_vec(); // Clone the data to move into the task

        unblock(move || {
            let mut file = OpenOptions::new()
                .write(true)
                .open(&path)
                .map_err(|e| NfsError::IoError(e))?;

            // Seek to the offset
            use std::io::{Seek, SeekFrom, Write};
            file.seek(SeekFrom::Start(offset))
                .map_err(|e| NfsError::IoError(e))?;

            // Write the data
            file.write_all(&data_owned)
                .map_err(|e| NfsError::IoError(e))?;

            Ok(())
        })
        .await
    }

    pub async fn create_file(&self, path: PathBuf, mode: u32) -> Result<(), NfsError> {
        unblock(move || {
            let flags = OFlag::O_CREAT | OFlag::O_WRONLY | OFlag::O_TRUNC;
            let mode = Mode::from_bits_truncate(mode);

            let fd = fcntl::open(&path, flags, mode)
                .map_err(|e| NfsError::IoError(std::io::Error::from_raw_os_error(e as i32)))?;

            unistd::close(fd)
                .map_err(|e| NfsError::IoError(std::io::Error::from_raw_os_error(e as i32)))?;

            Ok(())
        })
        .await
    }

    pub async fn create_directory(&self, path: PathBuf, mode: u32) -> Result<(), NfsError> {
        unblock(move || {
            let mode = Mode::from_bits_truncate(mode);

            unistd::mkdir(&path, mode)
                .map_err(|e| NfsError::IoError(std::io::Error::from_raw_os_error(e as i32)))?;

            Ok(())
        })
        .await
    }

    pub async fn remove(&self, path: PathBuf) -> Result<(), NfsError> {
        unblock(move || {
            let metadata = fs::metadata(&path).map_err(|e| NfsError::IoError(e))?;

            if metadata.is_dir() {
                fs::remove_dir_all(&path).map_err(|e| NfsError::IoError(e))?;
            } else {
                fs::remove_file(&path).map_err(|e| NfsError::IoError(e))?;
            }

            Ok(())
        })
        .await
    }

    pub async fn stat(&self, path: PathBuf) -> Result<FileStat, NfsError> {
        unblock(move || {
            let metadata = fs::metadata(&path).map_err(|e| NfsError::IoError(e))?;

            let file_stat = FileStat {
                size: metadata.len(),
                mode: metadata.permissions().mode(),
                modified_time: metadata
                    .modified()
                    .map(|time| {
                        time.duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs()
                    })
                    .unwrap_or(0),
                access_time: metadata
                    .accessed()
                    .map(|time| {
                        time.duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs()
                    })
                    .unwrap_or(0),
                is_dir: metadata.is_dir(),
            };

            Ok(file_stat)
        })
        .await
    }

    pub async fn read_dir(&self, path: PathBuf) -> Result<Vec<DirEntry>, NfsError> {
        unblock(move || {
            let entries = fs::read_dir(&path)
                .map_err(|e| NfsError::IoError(e))?
                .filter_map(|entry| {
                    let entry = entry.ok()?;
                    let file_type = entry.file_type().ok()?;
                    let name = entry.file_name().to_string_lossy().to_string();

                    let entry_type = if file_type.is_dir() {
                        FileType::Directory
                    } else if file_type.is_file() {
                        FileType::File
                    } else if file_type.is_symlink() {
                        FileType::Symlink
                    } else {
                        FileType::Other
                    };

                    Some(DirEntry {
                        name,
                        file_type: entry_type,
                    })
                })
                .collect::<Vec<_>>();

            Ok(entries)
        })
        .await
    }

    pub async fn rename(&self, from: PathBuf, to: PathBuf) -> Result<(), NfsError> {
        unblock(move || {
            fs::rename(&from, &to).map_err(|e| NfsError::IoError(e))?;

            Ok(())
        })
        .await
    }

    pub async fn create_symlink(&self, target: PathBuf, link: PathBuf) -> Result<(), NfsError> {
        unblock(move || {
            #[cfg(unix)]
            {
                std::os::unix::fs::symlink(&target, &link).map_err(|e| NfsError::IoError(e))?;

                Ok(())
            }
            #[cfg(not(unix))]
            {
                Err(NfsError::PlatformSpecific(
                    "Symlinks not supported on this platform".into(),
                ))
            }
        })
        .await
    }

    pub async fn fsync(&self, path: PathBuf) -> Result<(), NfsError> {
        unblock(move || {
            let file = File::open(&path).map_err(|e| NfsError::IoError(e))?;

            file.sync_all().map_err(|e| NfsError::IoError(e))?;

            Ok(())
        })
        .await
    }
}

#[derive(Clone)]
pub struct FileSystemManager {
    platform_impl: Arc<PlatformFileSystem>,
}

impl FileSystemManager {
    pub fn new() -> Self {
        Self {
            platform_impl: Arc::new(PlatformFileSystem::new()),
        }
    }

    pub async fn read_file(
        &self,
        path: PathBuf,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, NfsError> {
        self.platform_impl.read_file(path, offset, length).await
    }

    pub async fn write_file(
        &self,
        path: PathBuf,
        offset: u64,
        data: &[u8],
    ) -> Result<(), NfsError> {
        self.platform_impl.write_file(path, offset, data).await
    }

    pub async fn create_file(&self, path: PathBuf, mode: u32) -> Result<(), NfsError> {
        self.platform_impl.create_file(path, mode).await
    }

    pub async fn create_directory(&self, path: PathBuf, mode: u32) -> Result<(), NfsError> {
        self.platform_impl.create_directory(path, mode).await
    }

    pub async fn remove(&self, path: PathBuf) -> Result<(), NfsError> {
        self.platform_impl.remove(path).await
    }

    pub async fn stat(&self, path: PathBuf) -> Result<FileStat, NfsError> {
        self.platform_impl.stat(path).await
    }

    pub async fn read_dir(&self, path: PathBuf) -> Result<Vec<DirEntry>, NfsError> {
        self.platform_impl.read_dir(path).await
    }

    pub async fn rename(&self, from: PathBuf, to: PathBuf) -> Result<(), NfsError> {
        self.platform_impl.rename(from, to).await
    }

    pub async fn create_symlink(&self, target: PathBuf, link: PathBuf) -> Result<(), NfsError> {
        self.platform_impl.create_symlink(target, link).await
    }

    pub async fn fsync(&self, path: PathBuf) -> Result<(), NfsError> {
        self.platform_impl.fsync(path).await
    }
}
