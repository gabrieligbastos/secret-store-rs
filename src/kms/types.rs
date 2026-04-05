//! Types used by the KMS envelope-encryption layer.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A versioned envelope that wraps an AES-256-GCM ciphertext together with its
/// encrypted data key.
///
/// The outer `version` tag allows future algorithm migrations without breaking
/// existing ciphertexts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "version", content = "ciphertext")]
pub enum Ciphertext {
    /// Version 1: AES-256-GCM data encryption, SHA-512 AAD, CBOR serialization.
    #[serde(rename = "1")]
    V1(CiphertextV1),
}

/// Version-1 ciphertext envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiphertextV1 {
    /// Identifier of the external KMS key used to wrap the data key.
    /// Stored in plaintext so decryption knows which key to request.
    pub kms_key_id: String,

    /// A unique ID for this data key.  Used as the in-memory cache lookup key
    /// so repeated decryptions of the same payload avoid extra KMS round-trips.
    pub data_key_id: Uuid,

    /// The 32-byte data key after being encrypted by the external KMS.
    pub encrypted_data_key: Vec<u8>,

    /// The 12-byte nonce used for AES-256-GCM encryption.
    pub nonce: [u8; 12],

    /// The AES-256-GCM ciphertext (includes the 16-byte GCM authentication tag).
    pub encrypted_data: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ciphertext_v1_serde_roundtrip_cbor() {
        let ct = Ciphertext::V1(CiphertextV1 {
            kms_key_id: "arn:aws:kms:us-east-1:123456789012:key/abc".to_owned(),
            data_key_id: Uuid::new_v4(),
            encrypted_data_key: vec![1, 2, 3, 4],
            nonce: [0u8; 12],
            encrypted_data: vec![9, 8, 7, 6],
        });

        let mut buf = Vec::new();
        ciborium::into_writer(&ct, &mut buf).expect("CBOR encode failed");
        assert!(!buf.is_empty());

        let decoded: Ciphertext = ciborium::from_reader(buf.as_slice()).expect("CBOR decode failed");
        let Ciphertext::V1(inner) = decoded;
        let Ciphertext::V1(orig) = &ct;

        assert_eq!(inner.kms_key_id, orig.kms_key_id);
        assert_eq!(inner.data_key_id, orig.data_key_id);
        assert_eq!(inner.encrypted_data_key, orig.encrypted_data_key);
        assert_eq!(inner.nonce, orig.nonce);
        assert_eq!(inner.encrypted_data, orig.encrypted_data);
    }

    #[test]
    fn ciphertext_v1_serde_roundtrip_json() {
        let ct = Ciphertext::V1(CiphertextV1 {
            kms_key_id: "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key".to_owned(),
            data_key_id: Uuid::new_v4(),
            encrypted_data_key: vec![0xAA, 0xBB],
            nonce: [42u8; 12],
            encrypted_data: vec![0xCC, 0xDD, 0xEE],
        });

        let json = serde_json::to_string(&ct).unwrap();
        let decoded: Ciphertext = serde_json::from_str(&json).unwrap();
        let Ciphertext::V1(inner) = decoded;
        let Ciphertext::V1(orig) = &ct;

        assert_eq!(inner.kms_key_id, orig.kms_key_id);
        assert_eq!(inner.nonce, orig.nonce);
    }
}
