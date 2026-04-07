//! Integration tests — require real cloud credentials.
//!
//! These tests are **skipped by default**.  Set the `TEST_INTEGRATION`
//! environment variable to any non-empty value to opt in:
//!
//! ```sh
//! TEST_INTEGRATION=1 cargo test --test integration --features azure,aws,gcp
//! ```
//!
//! Each provider also requires its own environment variables (see the
//! README's "Quick Start" section for details).

use secret_store::{SecretStore, memory::InMemory};

/// Skip the calling test unless `TEST_INTEGRATION` is set.
macro_rules! maybe_skip_integration {
    () => {
        if std::env::var("TEST_INTEGRATION")
            .unwrap_or_default()
            .is_empty()
        {
            eprintln!("Skipping integration test — set TEST_INTEGRATION=1 to run");
            return;
        }
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// InMemory — always runs (no network required)
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn inmemory_full_lifecycle() {
    let store = InMemory::new();

    store
        .set_secret("integration-key", "integration-value")
        .await
        .unwrap();
    let val = store.get_secret("integration-key").await.unwrap();
    assert_eq!(val.expose_secret(), "integration-value");

    store
        .set_secret("integration-key", "updated-value")
        .await
        .unwrap();
    let updated = store.get_secret("integration-key").await.unwrap();
    assert_eq!(updated.expose_secret(), "updated-value");

    store.delete_secret("integration-key").await.unwrap();
    assert!(
        store
            .get_secret("integration-key")
            .await
            .unwrap_err()
            .is_not_found()
    );
}

#[tokio::test]
async fn inmemory_list_with_prefix() {
    let store = InMemory::new();
    store.set_secret("svc/db-pass", "p1").await.unwrap();
    store.set_secret("svc/api-key", "p2").await.unwrap();
    store.set_secret("infra/cert", "p3").await.unwrap();

    let svc = store.list_secrets(Some("svc/")).await.unwrap();
    assert_eq!(svc.len(), 2);
    assert!(svc.iter().all(|m| m.name.starts_with("svc/")));

    let all = store.list_secrets(None).await.unwrap();
    assert_eq!(all.len(), 3);
}

// ─────────────────────────────────────────────────────────────────────────────
// KMS envelope encryption — always runs
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "kms")]
#[tokio::test]
async fn kms_noop_encrypt_decrypt_roundtrip() {
    use secret_store::kms::{NoopKms, SecretsManager};
    use std::sync::Arc;

    let mgr = SecretsManager::new(Arc::new(NoopKms), "master-key".to_owned());
    let plaintext = b"super-sensitive-value";
    let aad = b"project-uuid-abc123";

    let ct = mgr.encrypt(plaintext, aad).await.unwrap();
    let pt = mgr.decrypt(&ct, aad).await.unwrap();
    assert_eq!(pt, plaintext);
}

#[cfg(feature = "kms")]
#[tokio::test]
async fn kms_wrong_aad_decryption_fails() {
    use secret_store::kms::{NoopKms, SecretsManager};
    use std::sync::Arc;

    let mgr = SecretsManager::new(Arc::new(NoopKms), "master-key".to_owned());
    let ct = mgr.encrypt(b"value", b"correct-aad").await.unwrap();
    assert!(mgr.decrypt(&ct, b"wrong-aad").await.is_err());
}

// ─────────────────────────────────────────────────────────────────────────────
// Azure Key Vault — gated on TEST_INTEGRATION + AZURE_* env vars
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "azure")]
#[tokio::test]
async fn azure_keyvault_full_lifecycle() {
    maybe_skip_integration!();

    use secret_store::azure::KeyVaultBuilder;

    let store = KeyVaultBuilder::from_env()
        .build()
        .await
        .expect("Failed to build Azure Key Vault store — check AZURE_* env vars");

    let name = "secret-store-integration-test";
    let value = "integration-test-value-azure";

    store.set_secret(name, value).await.unwrap();
    let fetched = store.get_secret(name).await.unwrap();
    assert_eq!(fetched.expose_secret(), value);

    store.delete_secret(name).await.unwrap();
    assert!(store.get_secret(name).await.unwrap_err().is_not_found());
}

// ─────────────────────────────────────────────────────────────────────────────
// AWS Secrets Manager — gated on TEST_INTEGRATION + AWS_* env vars
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "aws")]
#[tokio::test]
async fn aws_secrets_manager_full_lifecycle() {
    maybe_skip_integration!();

    use secret_store::aws::AwsSecretsManagerBuilder;

    let store = AwsSecretsManagerBuilder::from_env()
        .build()
        .await
        .expect("Failed to build AWS Secrets Manager store — check AWS_* env vars");

    let name = "secret-store/integration-test";
    let value = "integration-test-value-aws";

    store.set_secret(name, value).await.unwrap();
    let fetched = store.get_secret(name).await.unwrap();
    assert_eq!(fetched.expose_secret(), value);

    store.delete_secret(name).await.unwrap();
    assert!(store.get_secret(name).await.unwrap_err().is_not_found());
}

// ─────────────────────────────────────────────────────────────────────────────
// GCP Secret Manager — gated on TEST_INTEGRATION + GCP_* env vars
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "gcp")]
#[tokio::test]
async fn gcp_secret_manager_full_lifecycle() {
    maybe_skip_integration!();

    use secret_store::gcp::GcpSecretManagerBuilder;

    let store = GcpSecretManagerBuilder::from_env()
        .build()
        .await
        .expect("Failed to build GCP Secret Manager store — check GCP_PROJECT_ID / GOOGLE_APPLICATION_CREDENTIALS");

    let name = "secret-store-integration-test";
    let value = "integration-test-value-gcp";

    store.set_secret(name, value).await.unwrap();
    let fetched = store.get_secret(name).await.unwrap();
    assert_eq!(fetched.expose_secret(), value);

    store.delete_secret(name).await.unwrap();
    assert!(store.get_secret(name).await.unwrap_err().is_not_found());
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP Secret Store — gated on TEST_INTEGRATION + SECRET_STORE_HTTP_* env vars
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "http")]
#[tokio::test]
async fn http_secret_store_full_lifecycle() {
    maybe_skip_integration!();

    use secret_store::http::HttpSecretStoreBuilder;

    let store = HttpSecretStoreBuilder::from_env().build().expect(
        "Failed to build HTTP secret store — check SECRET_STORE_HTTP_URL / SECRET_STORE_HTTP_TOKEN",
    );

    let name = "integration-test-key";
    let value = "integration-test-value-http";

    store.set_secret(name, value).await.unwrap();
    let fetched = store.get_secret(name).await.unwrap();
    assert_eq!(fetched.expose_secret(), value);

    store.delete_secret(name).await.unwrap();
    assert!(store.get_secret(name).await.unwrap_err().is_not_found());
}
