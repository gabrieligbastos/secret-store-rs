//! Builder for [`super::HttpSecretStore`].

use super::client::ReqwestHttpClient;
use super::store::HttpSecretStore;
use super::types::ConfigKey;
use crate::common::Result;

/// Fluent builder for [`HttpSecretStore`].
///
/// Suitable for any REST API that follows the convention:
/// - `GET  {base_url}/{name}` → retrieve a secret value
/// - `POST {base_url}/{name}` → create or update a secret value
/// - `DELETE {base_url}/{name}` → delete a secret
///
/// # Using environment variables
/// ```no_run
/// use secret_store::http::HttpSecretStoreBuilder;
///
/// # #[tokio::main] async fn main() {
/// // Reads SECRET_STORE_HTTP_URL and SECRET_STORE_HTTP_TOKEN automatically.
/// let store = HttpSecretStoreBuilder::from_env().build().unwrap();
/// # }
/// ```
///
/// # Manual configuration
/// ```no_run
/// use secret_store::http::HttpSecretStoreBuilder;
///
/// # #[tokio::main] async fn main() {
/// let store = HttpSecretStoreBuilder::new()
///     .with_base_url("http://vault:8200/v1/secret")
///     .with_auth_token("s.my-vault-token")
///     .build()
///     .unwrap();
/// # }
/// ```
#[derive(Debug, Default)]
pub struct HttpSecretStoreBuilder {
    base_url: Option<String>,
    auth_token: Option<String>,
    namespace: Option<String>,
}

impl HttpSecretStoreBuilder {
    /// Creates a new builder with no pre-set values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Populates all fields from environment variables.
    pub fn from_env() -> Self {
        Self {
            base_url: std::env::var(ConfigKey::BaseUrl.env_var())
                .ok()
                .filter(|v| !v.is_empty()),
            auth_token: std::env::var(ConfigKey::AuthToken.env_var())
                .ok()
                .filter(|v| !v.is_empty()),
            namespace: std::env::var(ConfigKey::Namespace.env_var())
                .ok()
                .filter(|v| !v.is_empty()),
        }
    }

    /// Sets the base URL (e.g. `http://vault:8200/v1/secret`).
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = Some(url.into());
        self
    }

    /// Sets the Bearer token used in `Authorization: Bearer <token>`.
    pub fn with_auth_token(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }

    /// Sets an optional namespace header (e.g. Vault Enterprise namespaces).
    pub fn with_namespace(mut self, ns: impl Into<String>) -> Self {
        self.namespace = Some(ns.into());
        self
    }

    /// Builds an [`HttpSecretStore`].
    ///
    /// # Errors
    /// Returns [`crate::Error::Configuration`] if `base_url` is not set.
    pub fn build(self) -> Result<HttpSecretStore> {
        let base_url = self
            .base_url
            .ok_or_else(|| crate::common::Error::Configuration {
                store: "HttpSecretStore",
                message: format!(
                    "base URL is required — set `{}` or call `.with_base_url()`",
                    ConfigKey::BaseUrl.env_var()
                ),
            })?;

        // Strip trailing slash for consistency.
        let base_url = base_url.trim_end_matches('/').to_owned();

        let http_client = reqwest::Client::builder().build().map_err(|e| {
            crate::common::Error::Configuration {
                store: "HttpSecretStore",
                message: format!("failed to build HTTP client: {e}"),
            }
        })?;

        Ok(HttpSecretStore::from_reqwest_client(ReqwestHttpClient {
            base_url,
            auth_token: self.auth_token,
            namespace: self.namespace,
            http: http_client,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_stores_base_url() {
        let b = HttpSecretStoreBuilder::new().with_base_url("http://localhost:8200/v1/secret");
        assert_eq!(
            b.base_url.as_deref(),
            Some("http://localhost:8200/v1/secret")
        );
    }

    #[test]
    fn builder_stores_auth_token() {
        let b = HttpSecretStoreBuilder::new()
            .with_base_url("http://x")
            .with_auth_token("my-token");
        assert_eq!(b.auth_token.as_deref(), Some("my-token"));
    }

    #[test]
    fn builder_stores_namespace() {
        let b = HttpSecretStoreBuilder::new()
            .with_base_url("http://x")
            .with_namespace("my-ns");
        assert_eq!(b.namespace.as_deref(), Some("my-ns"));
    }

    #[test]
    fn from_env_reads_variables() {
        unsafe { std::env::set_var("SECRET_STORE_HTTP_URL", "http://env-vault:8200") };
        unsafe { std::env::set_var("SECRET_STORE_HTTP_TOKEN", "env-token") };
        let b = HttpSecretStoreBuilder::from_env();
        assert_eq!(b.base_url.as_deref(), Some("http://env-vault:8200"));
        assert_eq!(b.auth_token.as_deref(), Some("env-token"));
        unsafe { std::env::remove_var("SECRET_STORE_HTTP_URL") };
        unsafe { std::env::remove_var("SECRET_STORE_HTTP_TOKEN") };
    }

    #[test]
    fn from_env_ignores_empty_vars() {
        unsafe { std::env::set_var("SECRET_STORE_HTTP_URL", "") };
        let b = HttpSecretStoreBuilder::from_env();
        assert!(b.base_url.is_none());
        unsafe { std::env::remove_var("SECRET_STORE_HTTP_URL") };
    }

    #[test]
    fn build_fails_without_base_url() {
        let result = HttpSecretStoreBuilder::new().build();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            crate::common::Error::Configuration { .. }
        ));
    }

    #[test]
    fn build_strips_trailing_slash_from_url() {
        let store = HttpSecretStoreBuilder::new()
            .with_base_url("http://localhost:8200/v1/secret/")
            .build()
            .unwrap();
        assert!(
            !store.base_url().ends_with('/'),
            "url was: {}",
            store.base_url()
        );
    }

    #[test]
    fn build_succeeds_with_base_url() {
        let result = HttpSecretStoreBuilder::new()
            .with_base_url("http://localhost:8200/v1/secret")
            .build();
        assert!(result.is_ok());
    }
}
