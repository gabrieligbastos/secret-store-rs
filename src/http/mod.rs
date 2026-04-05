//! Generic HTTP secret store provider.
//!
//! Works with any REST API that follows the pattern:
//! - `GET    {base_url}/{name}` → retrieve a secret
//! - `POST   {base_url}/{name}` → create or update a secret
//! - `DELETE {base_url}/{name}` → delete a secret
//!
//! Suitable for HashiCorp Vault KV v1/v2, custom internal secret APIs, etc.
//!
//! # Setup
//!
//! ```no_run
//! use secret_store::http::HttpSecretStoreBuilder;
//! use secret_store::SecretStore;
//!
//! # fn main() {
//! // Set SECRET_STORE_HTTP_URL and optionally SECRET_STORE_HTTP_TOKEN.
//! let store = HttpSecretStoreBuilder::from_env().build().unwrap();
//! # let _ = store;
//! # }
//! ```
//!
//! Or configure manually:
//!
//! ```no_run
//! use secret_store::http::HttpSecretStoreBuilder;
//! use secret_store::SecretStore;
//!
//! # #[tokio::main] async fn main() {
//! let store = HttpSecretStoreBuilder::new()
//!     .with_base_url("http://vault:8200/v1/secret")
//!     .with_auth_token("s.my-vault-token")
//!     .build()
//!     .unwrap();
//! store.set_secret("db-password", "hunter2").await.unwrap();
//! let val = store.get_secret("db-password").await.unwrap();
//! println!("{}", val.expose_secret());
//! # }
//! ```

pub mod builder;
pub mod client;
pub mod store;
pub mod types;

pub use builder::HttpSecretStoreBuilder;
pub use store::HttpSecretStore;
pub use types::ConfigKey;
