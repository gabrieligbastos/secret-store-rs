//! Azure Key Vault secret store provider.
//!
//! # Setup
//! ```no_run
//! use secret_store::azure::KeyVaultBuilder;
//! use secret_store::SecretStore;
//!
//! # #[tokio::main] async fn main() {
//! // Set env vars: AZURE_KEYVAULT_URL, AZURE_TENANT_ID, AZURE_CLIENT_ID,
//! // AZURE_CLIENT_SECRET — then:
//! let store = KeyVaultBuilder::from_env().build().await.unwrap();
//! store.set_secret("my-api-key", "secret-value").await.unwrap();
//! let val = store.get_secret("my-api-key").await.unwrap();
//! println!("{}", val.expose_secret());
//! # }
//! ```

pub mod builder;
pub mod client;
pub mod store;
pub mod types;

pub use builder::KeyVaultBuilder;
pub use store::KeyVaultSecretStore;
pub use types::ConfigKey;
