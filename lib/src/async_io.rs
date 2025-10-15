use crate::error::NfsError;
use bincode::Decode;
use futures_lite::io::{AsyncReadExt, AsyncWriteExt};
use smol::net::TcpStream;
use std::marker::PhantomData;

pub struct AsyncConnection {
    stream: TcpStream,
}

impl AsyncConnection {
    pub fn new(stream: TcpStream) -> Self {
        Self { stream }
    }

    pub async fn send_message<T: bincode::Encode>(&mut self, message: &T) -> Result<(), NfsError> {
        // Serialize the message
        let data = bincode::encode_to_vec(message, bincode::config::standard())?;

        // Send the length of the message as a u32
        let len = data.len() as u32;
        let len_bytes = len.to_be_bytes();
        self.stream.write_all(&len_bytes).await?;

        // Send the message data
        self.stream.write_all(&data).await?;
        self.stream.flush().await?;

        Ok(())
    }

    pub async fn receive_message<T: Decode<()>>(&mut self) -> Result<T, NfsError> {
        // Read the length of the message
        let mut len_bytes = [0u8; 4];
        self.stream.read_exact(&mut len_bytes).await?;
        let len = u32::from_be_bytes(len_bytes) as usize;

        // Validate message length to prevent memory attacks
        if len > 64 * 1024 * 1024 {
            // 64 MB limit
            return Err(NfsError::ProtocolError("Message too large".into()));
        }

        // Read the message data
        let mut data = vec![0u8; len];
        self.stream.read_exact(&mut data).await?;

        // Deserialize the message
        match bincode::decode_from_slice(&data, bincode::config::standard()) {
            Ok((message, _)) => Ok(message),
            Err(e) => Err(NfsError::DeserializationError(e.to_string())),
        }
    }

    pub async fn send_encrypted_message<T: bincode::Encode>(
        &mut self,
        message: &T,
        encrypt_fn: impl FnOnce(&[u8]) -> Result<Vec<u8>, NfsError>,
    ) -> Result<(), NfsError> {
        // Serialize the message
        let data = bincode::encode_to_vec(message, bincode::config::standard())?;

        // Encrypt the serialized data
        let encrypted_data = encrypt_fn(&data)?;

        // Send the length of the encrypted message
        let len = encrypted_data.len() as u32;
        let len_bytes = len.to_be_bytes();
        self.stream.write_all(&len_bytes).await?;

        // Send the encrypted message
        self.stream.write_all(&encrypted_data).await?;
        self.stream.flush().await?;

        Ok(())
    }

    pub async fn receive_encrypted_message<T: Decode<()>>(
        &mut self,
        decrypt_fn: impl FnOnce(&[u8]) -> Result<Vec<u8>, NfsError>,
    ) -> Result<T, NfsError> {
        // Read the length of the encrypted message
        let mut len_bytes = [0u8; 4];
        self.stream.read_exact(&mut len_bytes).await?;
        let len = u32::from_be_bytes(len_bytes) as usize;

        // Validate message length
        if len > 64 * 1024 * 1024 {
            // 64 MB limit
            return Err(NfsError::ProtocolError("Message too large".into()));
        }

        // Read the encrypted message
        let mut encrypted_data = vec![0u8; len];
        self.stream.read_exact(&mut encrypted_data).await?;

        // Decrypt the message
        let data = decrypt_fn(&encrypted_data)?;

        // Deserialize the decrypted data
        let message = bincode::decode_from_slice(&data, bincode::config::standard())?.0;

        Ok(message)
    }
}
