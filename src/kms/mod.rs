//! KMS envelope-encryption layer.
//!
//! Provides a [`Kms`] trait that abstracts over external key management
//! services (AWS KMS, Azure Key Vault keys, GCP Cloud KMS, etc.) and a
//! [`SecretsManager`] that performs **envelope encryption**:
//!
//! 1. Generates a random 32-byte data key per plaintext.
//! 2. Encrypts the data key with the external KMS (`kms_key_id`).
//! 3. Encrypts the plaintext with AES-256-GCM using the data key.
//! 4. Stores the result as a versioned CBOR-encoded [`Ciphertext`] envelope.
//!
//! Decryption reverses the process, using an in-memory cache to avoid
//! redundant KMS calls for repeated decryptions of the same envelope.
//!
//! # Example (with `NoopKms` for testing)
//! ```
//! use std::sync::Arc;
//! use secret_store::kms::{Kms, NoopKms, SecretsManager};
//!
//! # #[tokio::main]
//! # async fn main() {
//! let kms = Arc::new(NoopKms);
//! let manager = SecretsManager::new(kms, "my-master-key-id".to_owned());
//!
//! let plaintext = b"my-api-key-value";
//! let aad = b"user-id-12345";
//!
//! let ciphertext = manager.encrypt(plaintext, aad).await.unwrap();
//! let decrypted  = manager.decrypt(&ciphertext, aad).await.unwrap();
//!
//! assert_eq!(decrypted, plaintext);
//! # }
//! ```

pub mod types;

pub use types::{Ciphertext, CiphertextV1};

use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, Payload},
};
use async_trait::async_trait;
use dashmap::DashMap;
use rand::{RngCore, SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha512};
use std::sync::Arc;
use tracing::debug;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::common::error::{Error, Result, StringError};

// ─────────────────────────────────────────────────────────────────────────────
// Kms trait
// ─────────────────────────────────────────────────────────────────────────────

/// Abstraction over an external key management service.
///
/// Implementors wrap the cloud provider's key wrapping API (AWS KMS
/// `GenerateDataKey` / `Decrypt`, Azure Key Vault wrap/unwrap, GCP Cloud KMS
/// `encrypt` / `decrypt`, etc.).
///
/// The `aad` parameter is **Additional Authenticated Data** passed to the KMS
/// to prevent confused-deputy attacks — it must match between encrypt and
/// decrypt calls.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait Kms: Send + Sync {
    /// Encrypts (wraps) a data key with the KMS master key identified by
    /// `kms_key_id`.
    async fn encrypt_data_key(
        &self,
        kms_key_id: &str,
        data_key: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>>;

    /// Decrypts (unwraps) an encrypted data key previously produced by
    /// [`Kms::encrypt_data_key`].
    async fn decrypt_data_key(
        &self,
        kms_key_id: &str,
        encrypted_data_key: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>>;
}

// ─────────────────────────────────────────────────────────────────────────────
// NoopKms — identity implementation for local dev / testing
// ─────────────────────────────────────────────────────────────────────────────

/// A [`Kms`] implementation that **does not actually encrypt data keys**.
///
/// `encrypt_data_key` returns the key unchanged; `decrypt_data_key` returns
/// the "encrypted" bytes unchanged.  **Only use this in tests or local
/// development** — it provides no real security.
#[derive(Debug, Default, Clone)]
pub struct NoopKms;

#[async_trait]
impl Kms for NoopKms {
    async fn encrypt_data_key(
        &self,
        _kms_key_id: &str,
        data_key: &[u8],
        _aad: &[u8],
    ) -> Result<Vec<u8>> {
        Ok(data_key.to_vec())
    }

    async fn decrypt_data_key(
        &self,
        _kms_key_id: &str,
        encrypted_data_key: &[u8],
        _aad: &[u8],
    ) -> Result<Vec<u8>> {
        Ok(encrypted_data_key.to_vec())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SecretsManager — envelope encryption
// ─────────────────────────────────────────────────────────────────────────────

/// Encrypts and decrypts arbitrary bytes using **envelope encryption**.
///
/// The `SecretsManager` never stores data itself; it is an encryption layer
/// that sits in front of whatever persistence mechanism you choose (a
/// database column, a [`crate::SecretStore`], etc.).
///
/// Every [`SecretsManager::encrypt`] call:
/// 1. Generates a unique 256-bit data key and 96-bit nonce.
/// 2. Sends the data key to the KMS for wrapping.
/// 3. Encrypts the plaintext with AES-256-GCM.
/// 4. Returns a versioned CBOR-encoded [`Ciphertext`] envelope.
///
/// Data keys are cached in memory keyed by their `data_key_id` UUID to
/// avoid repeated KMS calls during the lifetime of this struct.
pub struct SecretsManager {
    kms: Arc<dyn Kms>,
    master_key_id: String,
    data_keys_cache: DashMap<Uuid, Zeroizing<[u8; 32]>>,
}

impl std::fmt::Debug for SecretsManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretsManager")
            .field("master_key_id", &self.master_key_id)
            .finish_non_exhaustive()
    }
}

impl SecretsManager {
    /// Creates a new [`SecretsManager`] backed by the given [`Kms`] and using
    /// `master_key_id` as the identifier of the KMS key used to wrap data keys.
    pub fn new(kms: Arc<dyn Kms>, master_key_id: String) -> Self {
        Self {
            kms,
            master_key_id,
            data_keys_cache: DashMap::new(),
        }
    }

    /// Returns the master KMS key ID currently configured.
    pub fn master_key_id(&self) -> &str {
        &self.master_key_id
    }

    /// Encrypts `plaintext` and returns a CBOR-encoded [`Ciphertext`] envelope.
    ///
    /// `aad` is **Additional Authenticated Data** that will be required during
    /// [`SecretsManager::decrypt`].  A good choice is a stable identifier for
    /// the entity that owns the data (e.g., a user or project UUID).
    pub async fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let data_key_id = Uuid::new_v4();
        let mut data_key = Zeroizing::new([0u8; 32]);
        let mut nonce = [0u8; 12];
        {
            let mut r = StdRng::from_os_rng();
            r.fill_bytes(data_key.as_mut());
            r.fill_bytes(&mut nonce);
        }

        let encrypted_data_key = self
            .kms
            .encrypt_data_key(&self.master_key_id, data_key.as_ref(), data_key_id.as_bytes())
            .await
            .map_err(|e| Error::Generic {
                store: "SecretsManager",
                source: Box::new(StringError(format!("KMS encrypt_data_key failed: {e}"))),
            })?;

        let aad_hash = build_aad_hash(aad, &encrypted_data_key, &self.master_key_id, data_key_id);

        let cipher = Aes256Gcm::new(data_key.as_ref().into());
        let encrypted_data = cipher
            .encrypt(
                &nonce.into(),
                Payload { msg: plaintext, aad: &aad_hash },
            )
            .map_err(|e| Error::Generic {
                store: "SecretsManager",
                source: Box::new(StringError(format!("AES-256-GCM encrypt failed: {e}"))),
            })?;

        let estimated = encrypted_data.len() + self.master_key_id.len() + 16 + encrypted_data_key.len() + 12 + 32;
        let ct = Ciphertext::V1(CiphertextV1 {
            kms_key_id: self.master_key_id.clone(),
            data_key_id,
            encrypted_data_key,
            nonce,
            encrypted_data,
        });

        let mut buf = Vec::with_capacity(estimated);
        ciborium::into_writer(&ct, &mut buf).map_err(|e| Error::Generic {
            store: "SecretsManager",
            source: Box::new(StringError(format!("CBOR encode failed: {e}"))),
        })?;

        Ok(buf)
    }

    /// Decrypts a CBOR-encoded [`Ciphertext`] envelope produced by
    /// [`SecretsManager::encrypt`].
    ///
    /// `aad` **must** match the value used during encryption; any mismatch
    /// causes decryption to fail, preventing data from being decrypted in a
    /// wrong context.
    pub async fn decrypt(&self, ciphertext_bytes: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let ct: Ciphertext =
            ciborium::from_reader(ciphertext_bytes).map_err(|e| Error::Generic {
                store: "SecretsManager",
                source: Box::new(StringError(format!("CBOR decode failed: {e}"))),
            })?;

        let Ciphertext::V1(ct) = ct;

        let data_key: Zeroizing<[u8; 32]> =
            if let Some(cached) = self.data_keys_cache.get(&ct.data_key_id) {
                debug!(data_key_id = %ct.data_key_id, "data key cache hit");
                cached.clone()
            } else {
                debug!(data_key_id = %ct.data_key_id, "decrypting data key from KMS");
                let raw = self
                    .kms
                    .decrypt_data_key(&ct.kms_key_id, &ct.encrypted_data_key, ct.data_key_id.as_bytes())
                    .await
                    .map_err(|e| Error::Generic {
                        store: "SecretsManager",
                        source: Box::new(StringError(format!("KMS decrypt_data_key failed: {e}"))),
                    })?;

                let arr: [u8; 32] = raw.try_into().map_err(|_| Error::Generic {
                    store: "SecretsManager",
                    source: Box::new(StringError("decrypted data key is not 32 bytes".to_owned())),
                })?;
                let key = Zeroizing::new(arr);
                self.data_keys_cache.insert(ct.data_key_id, key.clone());
                key
            };

        let aad_hash = build_aad_hash(aad, &ct.encrypted_data_key, &ct.kms_key_id, ct.data_key_id);

        let cipher = Aes256Gcm::new(data_key.as_ref().into());
        let plaintext = cipher
            .decrypt(
                &ct.nonce.into(),
                Payload { msg: &ct.encrypted_data, aad: &aad_hash },
            )
            .map_err(|e| Error::Generic {
                store: "SecretsManager",
                source: Box::new(StringError(format!("AES-256-GCM decrypt failed: {e}"))),
            })?;

        Ok(plaintext)
    }
}

/// Builds the SHA-512 hash used as AAD for AES-256-GCM to bind the ciphertext
/// to its context, preventing confused-deputy attacks.
fn build_aad_hash(
    caller_aad: &[u8],
    encrypted_data_key: &[u8],
    master_key_id: &str,
    data_key_id: Uuid,
) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(caller_aad);
    hasher.update(encrypted_data_key);
    hasher.update(master_key_id.as_bytes());
    hasher.update(data_key_id.as_bytes());
    hasher.finalize().to_vec()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn manager_with_noop() -> SecretsManager {
        SecretsManager::new(Arc::new(NoopKms), "test-master-key".to_owned())
    }

    // ── NoopKms ───────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn noop_kms_encrypt_returns_key_unchanged() {
        let kms = NoopKms;
        let key = b"0123456789abcdef0123456789abcdef";
        let result = kms.encrypt_data_key("key-id", key, b"aad").await.unwrap();
        assert_eq!(result, key);
    }

    #[tokio::test]
    async fn noop_kms_decrypt_returns_ciphertext_unchanged() {
        let kms = NoopKms;
        let enc = vec![1u8, 2, 3];
        let result = kms.decrypt_data_key("key-id", &enc, b"aad").await.unwrap();
        assert_eq!(result, enc);
    }

    // ── SecretsManager — happy path ───────────────────────────────────────────

    #[tokio::test]
    async fn encrypt_decrypt_roundtrip() {
        let mgr = manager_with_noop();
        let plaintext = b"super-sensitive-api-key";
        let aad = b"user-id-42";

        let ct = mgr.encrypt(plaintext, aad).await.unwrap();
        let pt = mgr.decrypt(&ct, aad).await.unwrap();

        assert_eq!(pt, plaintext);
    }

    #[tokio::test]
    async fn encrypt_produces_non_empty_ciphertext() {
        let mgr = manager_with_noop();
        let ct = mgr.encrypt(b"secret", b"aad").await.unwrap();
        assert!(!ct.is_empty());
    }

    #[tokio::test]
    async fn two_encryptions_of_same_plaintext_differ() {
        let mgr = manager_with_noop();
        let aad = b"aad";
        let ct1 = mgr.encrypt(b"same-value", aad).await.unwrap();
        let ct2 = mgr.encrypt(b"same-value", aad).await.unwrap();
        // Different data keys + nonces must yield different ciphertexts.
        assert_ne!(ct1, ct2);
    }

    #[tokio::test]
    async fn encrypt_empty_plaintext_decrypts_correctly() {
        let mgr = manager_with_noop();
        let ct = mgr.encrypt(b"", b"aad").await.unwrap();
        let pt = mgr.decrypt(&ct, b"aad").await.unwrap();
        assert_eq!(pt, b"");
    }

    #[tokio::test]
    async fn data_key_cache_is_populated_after_first_decrypt() {
        let mgr = manager_with_noop();
        let ct = mgr.encrypt(b"value", b"aad").await.unwrap();

        assert!(mgr.data_keys_cache.is_empty());

        mgr.decrypt(&ct, b"aad").await.unwrap();
        assert_eq!(mgr.data_keys_cache.len(), 1);

        // Second decrypt uses the cached key.
        mgr.decrypt(&ct, b"aad").await.unwrap();
        assert_eq!(mgr.data_keys_cache.len(), 1);
    }

    // ── SecretsManager — failing / edge cases ─────────────────────────────────

    #[tokio::test]
    async fn decrypt_with_wrong_aad_fails() {
        let mgr = manager_with_noop();
        let ct = mgr.encrypt(b"secret", b"correct-aad").await.unwrap();
        let result = mgr.decrypt(&ct, b"wrong-aad").await;
        assert!(result.is_err(), "expected decryption to fail with wrong AAD");
    }

    #[tokio::test]
    async fn decrypt_corrupted_ciphertext_fails() {
        let mgr = manager_with_noop();
        let mut ct = mgr.encrypt(b"secret", b"aad").await.unwrap();

        // Corrupt the last byte of the CBOR payload.
        if let Some(last) = ct.last_mut() {
            *last ^= 0xFF;
        }

        let result = mgr.decrypt(&ct, b"aad").await;
        assert!(result.is_err(), "expected failure on corrupted ciphertext");
    }

    #[tokio::test]
    async fn decrypt_empty_bytes_fails() {
        let mgr = manager_with_noop();
        let result = mgr.decrypt(&[], b"aad").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn kms_encrypt_failure_propagates() {
        let mut mock_kms = MockKms::new();
        mock_kms
            .expect_encrypt_data_key()
            .returning(|_, _, _| Err(Error::Generic {
                store: "MockKms",
                source: Box::new(StringError("KMS unavailable".to_owned())),
            }));

        let mgr = SecretsManager::new(Arc::new(mock_kms), "key-id".to_owned());
        let result = mgr.encrypt(b"secret", b"aad").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn kms_decrypt_failure_propagates() {
        let mut mock_kms = MockKms::new();
        mock_kms
            .expect_decrypt_data_key()
            .returning(|_, _, _| Err(Error::Generic {
                store: "MockKms",
                source: Box::new(StringError("KMS unavailable".to_owned())),
            }));
        mock_kms
            .expect_encrypt_data_key()
            .returning(|_, data_key, _| Ok(data_key.to_vec()));

        let mgr = SecretsManager::new(Arc::new(mock_kms), "key-id".to_owned());
        let ct = mgr.encrypt(b"secret", b"aad").await.unwrap();
        let result = mgr.decrypt(&ct, b"aad").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn kms_decrypt_returns_wrong_length_fails() {
        // KMS returns a data key that is not 32 bytes.
        let mut mock_kms = MockKms::new();
        mock_kms
            .expect_encrypt_data_key()
            .returning(|_, data_key, _| Ok(data_key.to_vec()));
        mock_kms
            .expect_decrypt_data_key()
            .returning(|_, _, _| Ok(vec![1u8, 2, 3])); // only 3 bytes — wrong!

        let mgr = SecretsManager::new(Arc::new(mock_kms), "key-id".to_owned());
        let ct = mgr.encrypt(b"secret", b"aad").await.unwrap();
        let result = mgr.decrypt(&ct, b"aad").await;
        assert!(result.is_err());
    }
}
