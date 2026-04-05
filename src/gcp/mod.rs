//! GCP Secret Manager provider — lean implementation using `gcp_auth` + `reqwest`.
//!
//! Calls the [Secret Manager REST API](https://cloud.google.com/secret-manager/docs/reference/rest)
//! directly, avoiding the heavier `google-cloud-secretmanager` SDK.
//!
//! # Setup
//!
//! ```no_run
//! use secret_store::gcp::GcpSecretManagerBuilder;
//! use secret_store::SecretStore;
//!
//! # #[tokio::main] async fn main() {
//! // Authenticates via Application Default Credentials (GOOGLE_APPLICATION_CREDENTIALS,
//! // gcloud CLI, or Workload Identity).  Set GCP_PROJECT_ID or pass it explicitly.
//! let store = GcpSecretManagerBuilder::from_env().build().await.unwrap();
//! store.set_secret("my-api-key", "secret-value").await.unwrap();
//! let val = store.get_secret("my-api-key").await.unwrap();
//! println!("{}", val.expose_secret());
//! # }
//! ```

pub mod builder;
pub mod client;
pub mod store;
pub mod types;

pub use builder::GcpSecretManagerBuilder;
pub use store::GcpSecretManagerStore;
pub use types::ConfigKey;
