//! # secret_store
//!
//! A unified, async secret-store interface for multiple cloud providers,
//! inspired by [`object_store`](https://docs.rs/object_store).
//!
//! All providers implement the same [`SecretStore`] trait, so you can swap
//! backends without changing application code.
//!
//! ## Providers
//!
//! | Feature   | Provider                                  | Builder                                |
//! |-----------|-------------------------------------------|----------------------------------------|
//! | *(none)*  | [`memory::InMemory`] — for tests          | `InMemory::new()` / `InMemory::with_secrets()` |
//! | `azure`   | Azure Key Vault                           | [`azure::KeyVaultBuilder`]             |
//! | `aws`     | AWS Secrets Manager                       | [`aws::AwsSecretsManagerBuilder`]      |
//! | `gcp`     | GCP Secret Manager                        | [`gcp::GcpSecretManagerBuilder`]       |
//! | `http`    | Generic HTTP / HashiCorp Vault KV         | [`http::HttpSecretStoreBuilder`]       |
//!
//! ## Quick Start — In-Memory (no cloud credentials needed)
//!
//! ```
//! use std::sync::Arc;
//! use secret_store::{SecretStore, memory::InMemory};
//!
//! #[tokio::main]
//! async fn main() -> secret_store::Result<()> {
//!     let store: Arc<dyn SecretStore> = Arc::new(InMemory::new());
//!
//!     store.set_secret("db-password", "hunter2").await?;
//!     let val = store.get_secret("db-password").await?;
//!     println!("{}", val.expose_secret());   // hunter2
//!
//!     // List secrets (optionally filtered by prefix)
//!     let names = store.list_secrets(Some("db-")).await?;
//!     assert_eq!(names[0].name, "db-password");
//!
//!     store.delete_secret("db-password").await?;
//!     Ok(())
//! }
//! ```
//!
//! ## Quick Start — Azure Key Vault (`azure` feature)
//!
//! ```no_run
//! use secret_store::azure::KeyVaultBuilder;
//! use secret_store::SecretStore;
//!
//! #[tokio::main]
//! async fn main() -> secret_store::Result<()> {
//!     // Reads AZURE_KEYVAULT_URL + AZURE_TENANT_ID / AZURE_CLIENT_ID /
//!     // AZURE_CLIENT_SECRET from env, or falls back to the Azure CLI.
//!     let store = KeyVaultBuilder::from_env().build().await?;
//!     println!("{store}");   // AzureKeyVault: https://my-vault.vault.azure.net/
//!     println!("{store:?}"); // vault_url=..., provider=AzureKeyVault
//!     store.set_secret("api-key", "s3cr3t").await?;
//!     Ok(())
//! }
//! ```
//!
//! ## Quick Start — AWS Secrets Manager (`aws` feature)
//!
//! ```no_run
//! use secret_store::aws::AwsSecretsManagerBuilder;
//! use secret_store::SecretStore;
//!
//! #[tokio::main]
//! async fn main() -> secret_store::Result<()> {
//!     // Reads AWS_DEFAULT_REGION / AWS_REGION from env; credentials come
//!     // from the standard AWS credential chain (env, ~/.aws, IMDSv2, …).
//!     let store = AwsSecretsManagerBuilder::from_env().build().await?;
//!     store.set_secret("db-password", "hunter2").await?;
//!     Ok(())
//! }
//! ```
//!
//! ## Quick Start — GCP Secret Manager (`gcp` feature)
//!
//! ```no_run
//! use secret_store::gcp::GcpSecretManagerBuilder;
//! use secret_store::SecretStore;
//!
//! #[tokio::main]
//! async fn main() -> secret_store::Result<()> {
//!     // Reads GCP_PROJECT_ID from env; authenticates via Application Default
//!     // Credentials (GOOGLE_APPLICATION_CREDENTIALS, gcloud CLI, Workload Identity).
//!     let store = GcpSecretManagerBuilder::from_env().build().await?;
//!     store.set_secret("api-key", "s3cr3t").await?;
//!     Ok(())
//! }
//! ```
//!
//! ## Quick Start — Generic HTTP / HashiCorp Vault (`http` feature)
//!
//! ```no_run
//! use secret_store::http::HttpSecretStoreBuilder;
//! use secret_store::SecretStore;
//!
//! #[tokio::main]
//! async fn main() -> secret_store::Result<()> {
//!     // Reads SECRET_STORE_HTTP_URL and SECRET_STORE_HTTP_TOKEN from env.
//!     let store = HttpSecretStoreBuilder::from_env().build()?;
//!     store.set_secret("db-password", "hunter2").await?;
//!     Ok(())
//! }
//! ```
//!
//! ## Display and Debug
//!
//! Every store implements [`fmt::Display`] (minimal, log-friendly) and
//! [`fmt::Debug`] (verbose, useful while debugging):
//!
//! ```
//! use secret_store::memory::InMemory;
//!
//! let store = InMemory::new();
//! println!("{store}");   // InMemory(0 secrets)
//! println!("{store:?}"); // same — InMemory has no extra internal state
//! ```
//!
//! Cloud stores show their identifying info:
//! - **Azure** — `Display`: vault URL; `Debug`: vault URL + provider tag
//! - **AWS**   — `Display`: region; `Debug`: region + provider tag
//! - **GCP**   — `Display`: project ID; `Debug`: project ID + API endpoint + provider tag
//! - **HTTP**  — `Display`: base URL; `Debug`: base URL + namespace + provider tag
//!
//! ## KMS Envelope Encryption
//!
//! Enable the `kms` feature to access [`kms::SecretsManager`], a
//! zero-storage encryption layer that wraps data keys with a cloud KMS and
//! encrypts your data locally with AES-256-GCM before storing ciphertext in
//! any [`SecretStore`] backend.

pub mod common;
pub mod memory;

#[cfg(feature = "kms")]
pub mod kms;

#[cfg(feature = "azure")]
pub mod azure;

#[cfg(feature = "aws")]
pub mod aws;

#[cfg(feature = "gcp")]
pub mod gcp;

#[cfg(feature = "http")]
pub mod http;

pub use common::{Error, Result, SecretMeta, SecretValue, obfuscate_secret};

use async_trait::async_trait;
use std::fmt;
use std::sync::Arc;

// ─────────────────────────────────────────────────────────────────────────────
// Core trait
// ─────────────────────────────────────────────────────────────────────────────

/// A unified, async interface for reading and writing named secrets.
///
/// Implementors must also implement [`fmt::Display`] (used for log output
/// and diagnostics), [`fmt::Debug`], [`Send`], [`Sync`], and have a
/// `'static` lifetime so they can be freely stored in `Arc<dyn SecretStore>`.
///
/// # Implementing a custom backend
///
/// ```
/// use async_trait::async_trait;
/// use secret_store::{SecretStore, SecretValue, SecretMeta, Result};
///
/// #[derive(Debug)]
/// struct MyStore;
///
/// impl std::fmt::Display for MyStore {
///     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
///         write!(f, "MyStore")
///     }
/// }
///
/// #[async_trait]
/// impl SecretStore for MyStore {
///     async fn get_secret(&self, name: &str) -> Result<SecretValue> {
///         Ok(SecretValue::new("placeholder"))
///     }
///     async fn set_secret(&self, _name: &str, _value: &str) -> Result<()> { Ok(()) }
///     async fn delete_secret(&self, _name: &str) -> Result<()> { Ok(()) }
///     async fn list_secrets(&self, _prefix: Option<&str>) -> Result<Vec<SecretMeta>> { Ok(vec![]) }
/// }
/// ```
#[async_trait]
pub trait SecretStore: fmt::Display + fmt::Debug + Send + Sync + 'static {
    /// Retrieves the current value of a named secret.
    ///
    /// # Errors
    /// - [`Error::NotFound`] if the secret does not exist.
    /// - [`Error::Unauthenticated`] / [`Error::PermissionDenied`] on auth failures.
    async fn get_secret(&self, name: &str) -> Result<SecretValue>;

    /// Creates or overwrites a named secret with the given plaintext value.
    ///
    /// # Errors
    /// - [`Error::Unauthenticated`] / [`Error::PermissionDenied`] on auth failures.
    async fn set_secret(&self, name: &str, value: &str) -> Result<()>;

    /// Permanently deletes a named secret.
    ///
    /// # Errors
    /// - [`Error::NotFound`] if the secret does not exist.
    /// - [`Error::NotImplemented`] if the provider does not support deletion.
    async fn delete_secret(&self, name: &str) -> Result<()>;

    /// Lists all secrets whose names start with `prefix`.
    ///
    /// Pass `None` to list all secrets in the store.  The returned
    /// [`SecretMeta`] entries never include the secret value.
    ///
    /// # Errors
    /// - [`Error::NotImplemented`] if the provider does not support listing.
    async fn list_secrets(&self, prefix: Option<&str>) -> Result<Vec<SecretMeta>>;
}

/// Type alias for a dynamically-dispatched [`SecretStore`].
///
/// ```
/// use secret_store::{DynSecretStore, memory::InMemory};
/// use std::sync::Arc;
///
/// let store: Arc<DynSecretStore> = Arc::new(InMemory::new());
/// ```
pub type DynSecretStore = dyn SecretStore;

// ─────────────────────────────────────────────────────────────────────────────
// Blanket Arc / Box delegation
// ─────────────────────────────────────────────────────────────────────────────

/// Implements [`SecretStore`] for `Arc<T>` where `T: SecretStore`.
///
/// This lets you pass an `Arc<dyn SecretStore>` wherever a `&dyn SecretStore`
/// is expected, and compose stores freely.
#[async_trait]
impl<T: SecretStore> SecretStore for Arc<T> {
    async fn get_secret(&self, name: &str) -> Result<SecretValue> {
        self.as_ref().get_secret(name).await
    }
    async fn set_secret(&self, name: &str, value: &str) -> Result<()> {
        self.as_ref().set_secret(name, value).await
    }
    async fn delete_secret(&self, name: &str) -> Result<()> {
        self.as_ref().delete_secret(name).await
    }
    async fn list_secrets(&self, prefix: Option<&str>) -> Result<Vec<SecretMeta>> {
        self.as_ref().list_secrets(prefix).await
    }
}

/// Implements [`SecretStore`] for `Box<T>` where `T: SecretStore`.
#[async_trait]
impl<T: SecretStore> SecretStore for Box<T> {
    async fn get_secret(&self, name: &str) -> Result<SecretValue> {
        self.as_ref().get_secret(name).await
    }
    async fn set_secret(&self, name: &str, value: &str) -> Result<()> {
        self.as_ref().set_secret(name, value).await
    }
    async fn delete_secret(&self, name: &str) -> Result<()> {
        self.as_ref().delete_secret(name).await
    }
    async fn list_secrets(&self, prefix: Option<&str>) -> Result<Vec<SecretMeta>> {
        self.as_ref().list_secrets(prefix).await
    }
}

