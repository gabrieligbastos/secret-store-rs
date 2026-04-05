//! AWS Secrets Manager secret store provider.
//!
//! # Setup
//! ```no_run
//! use secret_store::aws::AwsSecretsManagerBuilder;
//! use secret_store::SecretStore;
//!
//! # #[tokio::main] async fn main() {
//! // Set env vars: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION
//! let store = AwsSecretsManagerBuilder::from_env().build().await.unwrap();
//! store.set_secret("my-api-key", "secret-value").await.unwrap();
//! let val = store.get_secret("my-api-key").await.unwrap();
//! println!("{}", val.expose_secret());
//! # }
//! ```

pub mod builder;
pub mod client;
pub mod store;
pub mod types;

pub use builder::AwsSecretsManagerBuilder;
pub use store::AwsSecretsManagerStore;
pub use types::ConfigKey;
