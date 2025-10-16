use std::sync::Mutex;

use aes_gcm::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use chacha20poly1305::{Key as ChaChaKey, XChaCha20Poly1305};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret, X25519_BASEPOINT_BYTES};

use crate::error::NfsError;
use crate::protocol::CipherSuite;

#[derive(Debug, Clone)]
pub struct KeyPair {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl KeyPair {
    pub fn generate() -> Self {
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);

        Self {
            private_key: private_key.as_bytes().to_vec(),
            public_key: public_key.to_bytes().to_vec(),
        }
    }
}

pub enum EncryptionState {
    Uninitialized,
    KeyExchangeInProgress {
        static_secret: StaticSecret,
    },
    Established {
        cipher_suite: CipherSuite,
        encryption_key: Vec<u8>,
        decryption_key: Vec<u8>,
    },
}

pub struct EncryptionManager {
    state: Mutex<EncryptionState>,
    key_pair: KeyPair,
}

impl EncryptionManager {
    pub fn new(key_pair: KeyPair) -> Self {
        Self {
            state: Mutex::new(EncryptionState::Uninitialized),
            key_pair,
        }
    }

    pub fn start_key_exchange(&self) -> Result<Vec<u8>, NfsError> {
        let static_secret = StaticSecret::random_from_rng(OsRng);
        let static_public = PublicKey::from(&static_secret);

        let mut state = self.state.lock().map_err(|_| NfsError::LockError)?;
        *state = EncryptionState::KeyExchangeInProgress { static_secret };

        Ok(static_public.as_bytes().to_vec())
    }

    pub fn complete_key_exchange(
        &self,
        peer_public_key: [u8; 32],
        cipher_suite: CipherSuite,
    ) -> Result<(), NfsError> {
        let mut state = self.state.lock().map_err(|_| NfsError::LockError)?;

        match &*state {
            EncryptionState::KeyExchangeInProgress { static_secret } => {
                if peer_public_key.len() != X25519_BASEPOINT_BYTES.len() {
                    return Err(NfsError::InvalidPublicKey);
                }

                let peer_public = PublicKey::from(peer_public_key);
                let shared_secret = static_secret.diffie_hellman(&peer_public);

                let (encryption_key, decryption_key) =
                    self.derive_keys(shared_secret.as_bytes(), cipher_suite)?;

                *state = EncryptionState::Established {
                    cipher_suite,
                    encryption_key,
                    decryption_key,
                };

                Ok(())
            }
            _ => Err(NfsError::InvalidEncryptionState),
        }
    }

    fn derive_keys(
        &self,
        shared_secret: &[u8],
        cipher_suite: CipherSuite,
    ) -> Result<(Vec<u8>, Vec<u8>), NfsError> {
        const INFO_ENCRYPTION_KEY: &[u8] = b"nfs_encryption_key";
        const INFO_DECRYPTION_KEY: &[u8] = b"nfs_decryption_key";
        const KEY_LEN: usize = 32; // For AES-256 and XChaCha20Poly1305

        let hkdf = Hkdf::<Sha256>::new(None, shared_secret);

        let mut encryption_key = [0u8; KEY_LEN];
        hkdf.expand(INFO_ENCRYPTION_KEY, &mut encryption_key)
            .map_err(|_| NfsError::KeyDerivationFailed)?;

        let mut decryption_key = [0u8; KEY_LEN];
        hkdf.expand(INFO_DECRYPTION_KEY, &mut decryption_key)
            .map_err(|_| NfsError::KeyDerivationFailed)?;

        Ok((encryption_key.to_vec(), decryption_key.to_vec()))
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, NfsError> {
        let state = self.state.lock().map_err(|_| NfsError::LockError)?;

        match &*state {
            EncryptionState::Established {
                cipher_suite,
                encryption_key,
                ..
            } => {
                match cipher_suite {
                    CipherSuite::XChaCha20Poly1305 => {
                        self.encrypt_xchacha20poly1305(plaintext, encryption_key)
                    }
                    CipherSuite::AesGcm256 => self.encrypt_aes_gcm(plaintext, encryption_key),
                    CipherSuite::Aes256CbcHmacSha256 => Err(NfsError::UnsupportedCipherSuite), // Removed for simplicity and security
                }
            }
            _ => Err(NfsError::EncryptionNotEstablished),
        }
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, NfsError> {
        let state = self.state.lock().map_err(|_| NfsError::LockError)?;

        match &*state {
            EncryptionState::Established {
                cipher_suite,
                decryption_key,
                ..
            } => {
                match cipher_suite {
                    CipherSuite::XChaCha20Poly1305 => {
                        self.decrypt_xchacha20poly1305(ciphertext, decryption_key)
                    }
                    CipherSuite::AesGcm256 => self.decrypt_aes_gcm(ciphertext, decryption_key),
                    CipherSuite::Aes256CbcHmacSha256 => Err(NfsError::UnsupportedCipherSuite), // Removed for simplicity and security
                }
            }
            _ => Err(NfsError::EncryptionNotEstablished),
        }
    }

    fn encrypt_xchacha20poly1305(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, NfsError> {
        if key.len() != 32 {
            return Err(NfsError::InvalidKeyLength);
        }

        let key = ChaChaKey::from_slice(key);
        let cipher = XChaCha20Poly1305::new(key);

        // Generate a random 24-byte nonce
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);

        // Encrypt the plaintext
        let ciphertext = cipher
            .encrypt(&nonce.into(), plaintext)
            .map_err(|_| NfsError::EncryptionFailed)?;

        // Prepend the nonce to the ciphertext
        let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    fn decrypt_xchacha20poly1305(
        &self,
        ciphertext: &[u8],
        key: &[u8],
    ) -> Result<Vec<u8>, NfsError> {
        if key.len() != 32 {
            return Err(NfsError::InvalidKeyLength);
        }

        if ciphertext.len() < 24 {
            return Err(NfsError::InvalidCiphertext);
        }

        let key = ChaChaKey::from_slice(key);
        let cipher = XChaCha20Poly1305::new(key);

        // Extract the nonce from the ciphertext
        let nonce = &ciphertext[..24];
        let actual_ciphertext = &ciphertext[24..];

        // Decrypt the ciphertext
        let plaintext = cipher
            .decrypt(nonce.into(), actual_ciphertext)
            .map_err(|_| NfsError::DecryptionFailed)?;

        Ok(plaintext)
    }

    fn encrypt_aes_gcm(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, NfsError> {
        if key.len() != 32 {
            return Err(NfsError::InvalidKeyLength);
        }

        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| NfsError::InvalidKeyLength)?;

        // Generate a random 12-byte nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt the plaintext
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| NfsError::EncryptionFailed)?;

        // Prepend the nonce to the ciphertext
        let mut result = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    fn decrypt_aes_gcm(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, NfsError> {
        if key.len() != 32 {
            return Err(NfsError::InvalidKeyLength);
        }

        if ciphertext.len() < 12 {
            return Err(NfsError::InvalidCiphertext);
        }

        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| NfsError::InvalidKeyLength)?;

        // Extract the nonce from the ciphertext
        let nonce = Nonce::from_slice(&ciphertext[..12]);
        let actual_ciphertext = &ciphertext[12..];

        // Decrypt the ciphertext
        let plaintext = cipher
            .decrypt(nonce, actual_ciphertext)
            .map_err(|_| NfsError::DecryptionFailed)?;

        Ok(plaintext)
    }
}

impl Clone for EncryptionManager {
    fn clone(&self) -> Self {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());

        let new_state = match &*state {
            EncryptionState::Uninitialized => EncryptionState::Uninitialized,
            EncryptionState::KeyExchangeInProgress { .. } => EncryptionState::Uninitialized, // Reset key exchange on clone
            EncryptionState::Established {
                cipher_suite,
                encryption_key,
                decryption_key,
            } => EncryptionState::Established {
                cipher_suite: *cipher_suite,
                encryption_key: encryption_key.clone(),
                decryption_key: decryption_key.clone(),
            },
        };

        Self {
            state: Mutex::new(new_state),
            key_pair: KeyPair {
                private_key: self.key_pair.private_key.clone(),
                public_key: self.key_pair.public_key.clone(),
            },
        }
    }
}
