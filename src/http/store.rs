//! [`HttpSecretStore`] — the [`crate::SecretStore`] impl for generic HTTP backends.

use async_trait::async_trait;
use std::fmt;
use std::sync::Arc;

use super::client::{HttpOps, ReqwestHttpClient};
use crate::SecretStore;
use crate::common::{Result, SecretMeta, SecretValue};

/// A generic HTTP-backed [`SecretStore`].
///
/// Constructed via [`super::builder::HttpSecretStoreBuilder`].
pub struct HttpSecretStore {
    pub(super) ops: Arc<dyn HttpOps>,
}

impl fmt::Debug for HttpSecretStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HttpSecretStore {{ {} }}", self.ops.debug_info())
    }
}

impl fmt::Display for HttpSecretStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HttpSecretStore({})", self.ops.display_name())
    }
}

impl HttpSecretStore {
    /// Returns the base URL this store is configured to use.
    pub fn base_url(&self) -> String {
        self.ops.display_name()
    }

    pub(super) fn from_reqwest_client(client: ReqwestHttpClient) -> Self {
        Self {
            ops: Arc::new(client),
        }
    }

    #[cfg(test)]
    pub(crate) fn from_ops(ops: Arc<dyn HttpOps>) -> Self {
        Self { ops }
    }
}

#[async_trait]
impl SecretStore for HttpSecretStore {
    async fn get_secret(&self, name: &str) -> Result<SecretValue> {
        self.ops.get(name).await.map(SecretValue::new)
    }

    async fn set_secret(&self, name: &str, value: &str) -> Result<()> {
        self.ops.set(name, value).await
    }

    async fn delete_secret(&self, name: &str) -> Result<()> {
        self.ops.delete(name).await
    }

    async fn list_secrets(&self, prefix: Option<&str>) -> Result<Vec<SecretMeta>> {
        let names = self.ops.list(prefix.map(str::to_owned)).await?;
        Ok(names.into_iter().map(SecretMeta::new).collect())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::super::client::MockHttpOps;
    use super::*;
    use crate::common::{Error, error::StringError};
    use mockall::predicate::eq;

    const BASE_URL: &str = "http://vault:8200/v1/secret";

    fn store_with_mock(setup: impl FnOnce(&mut MockHttpOps)) -> HttpSecretStore {
        let mut mock = MockHttpOps::new();
        setup(&mut mock);
        mock.expect_display_name()
            .return_const("<mock-url>".to_owned())
            .times(0..);
        mock.expect_debug_info()
            .return_const(
                "base_url=<mock>, auth=none, namespace=none, provider=HttpSecretStore".to_owned(),
            )
            .times(0..);
        HttpSecretStore::from_ops(Arc::new(mock))
    }

    // ── get_secret ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn get_secret_calls_ops_with_correct_name() {
        let store = store_with_mock(|m| {
            m.expect_get()
                .with(eq("my-token"))
                .once()
                .returning(|_| Ok("token-value-123".to_owned()));
        });
        assert_eq!(
            store.get_secret("my-token").await.unwrap().expose_secret(),
            "token-value-123"
        );
    }

    #[tokio::test]
    async fn get_secret_not_found_returns_not_found_error() {
        let store = store_with_mock(|m| {
            m.expect_get().once().returning(|name| {
                Err(Error::NotFound {
                    name: name.to_owned(),
                    source: Box::new(StringError::from("404 Not Found")),
                })
            });
        });
        assert!(
            store
                .get_secret("missing")
                .await
                .unwrap_err()
                .is_not_found()
        );
    }

    #[tokio::test]
    async fn get_secret_unauthenticated_propagates() {
        let store = store_with_mock(|m| {
            m.expect_get().once().returning(|_| {
                Err(Error::Unauthenticated {
                    source: Box::new(StringError::from("401")),
                })
            });
        });
        assert!(store.get_secret("key").await.unwrap_err().is_auth());
    }

    #[tokio::test]
    async fn get_secret_permission_denied_propagates() {
        let store = store_with_mock(|m| {
            m.expect_get().once().returning(|name| {
                Err(Error::PermissionDenied {
                    name: name.to_owned(),
                    source: Box::new(StringError::from("403 Forbidden")),
                })
            });
        });
        assert!(store.get_secret("key").await.unwrap_err().is_auth());
    }

    #[tokio::test]
    async fn get_secret_generic_error_propagates() {
        let store = store_with_mock(|m| {
            m.expect_get().once().returning(|_| {
                Err(Error::Generic {
                    store: "HttpSecretStore",
                    source: Box::new(StringError::from("503 Service Unavailable")),
                })
            });
        });
        assert!(store.get_secret("key").await.is_err());
    }

    // ── set_secret ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn set_secret_calls_ops_with_correct_name_and_value() {
        let store = store_with_mock(|m| {
            m.expect_set()
                .with(eq("config-key"), eq("config-value"))
                .once()
                .returning(|_, _| Ok(()));
        });
        store
            .set_secret("config-key", "config-value")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn set_secret_propagates_auth_error() {
        let store = store_with_mock(|m| {
            m.expect_set().once().returning(|_, _| {
                Err(Error::Unauthenticated {
                    source: Box::new(StringError::from("401")),
                })
            });
        });
        assert!(store.set_secret("k", "v").await.unwrap_err().is_auth());
    }

    #[tokio::test]
    async fn set_secret_propagates_generic_error() {
        let store = store_with_mock(|m| {
            m.expect_set().once().returning(|_, _| {
                Err(Error::Generic {
                    store: "HttpSecretStore",
                    source: Box::new(StringError::from("503")),
                })
            });
        });
        assert!(store.set_secret("k", "v").await.is_err());
    }

    // ── delete_secret ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn delete_secret_calls_ops_with_correct_name() {
        let store = store_with_mock(|m| {
            m.expect_delete()
                .with(eq("stale-secret"))
                .once()
                .returning(|_| Ok(()));
        });
        store.delete_secret("stale-secret").await.unwrap();
    }

    #[tokio::test]
    async fn delete_nonexistent_secret_returns_not_found() {
        let store = store_with_mock(|m| {
            m.expect_delete().once().returning(|name| {
                Err(Error::NotFound {
                    name: name.to_owned(),
                    source: Box::new(StringError::from("404")),
                })
            });
        });
        assert!(
            store
                .delete_secret("ghost")
                .await
                .unwrap_err()
                .is_not_found()
        );
    }

    #[tokio::test]
    async fn delete_propagates_permission_denied() {
        let store = store_with_mock(|m| {
            m.expect_delete().once().returning(|name| {
                Err(Error::PermissionDenied {
                    name: name.to_owned(),
                    source: Box::new(StringError::from("403")),
                })
            });
        });
        assert!(
            store
                .delete_secret("protected")
                .await
                .unwrap_err()
                .is_auth()
        );
    }

    // ── list_secrets ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn list_secrets_returns_meta_for_all_keys() {
        let store = store_with_mock(|m| {
            m.expect_list()
                .once()
                .returning(|_| Ok(vec!["key1".to_owned(), "key2".to_owned()]));
        });
        assert_eq!(store.list_secrets(None).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn list_secrets_with_prefix_passes_prefix_to_ops() {
        let store = store_with_mock(|m| {
            m.expect_list()
                .with(eq(Some("prod/".to_owned())))
                .once()
                .returning(|_| Ok(vec!["prod/db".to_owned()]));
        });
        assert_eq!(
            store.list_secrets(Some("prod/")).await.unwrap()[0].name,
            "prod/db"
        );
    }

    #[tokio::test]
    async fn list_secrets_empty_result() {
        let store = store_with_mock(|m| {
            m.expect_list().once().returning(|_| Ok(vec![]));
        });
        assert!(store.list_secrets(None).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn list_secrets_propagates_error() {
        let store = store_with_mock(|m| {
            m.expect_list().once().returning(|_| {
                Err(Error::Generic {
                    store: "HttpSecretStore",
                    source: Box::new(StringError::from("connection refused")),
                })
            });
        });
        assert!(store.list_secrets(None).await.is_err());
    }

    // ── display ───────────────────────────────────────────────────────────────

    #[test]
    fn display_includes_base_url() {
        let store = store_with_mock(|m| {
            m.expect_display_name()
                .once()
                .return_const(BASE_URL.to_owned());
        });
        assert!(store.to_string().contains(BASE_URL));
    }

    #[test]
    fn base_url_accessor_returns_correct_value() {
        let store = store_with_mock(|m| {
            m.expect_display_name()
                .once()
                .return_const(BASE_URL.to_owned());
        });
        assert_eq!(store.base_url(), BASE_URL);
    }

    #[test]
    fn debug_shows_connection_details() {
        const DETAILS: &str = "base_url=http://vault:8200/v1/secret, auth=Bearer, namespace=none, provider=HttpSecretStore";
        let store = store_with_mock(|m| {
            m.expect_debug_info()
                .once()
                .return_const(DETAILS.to_owned());
        });
        let debug_str = format!("{:?}", store);
        assert!(debug_str.contains("base_url="), "debug was: {debug_str}");
        assert!(
            debug_str.contains("provider=HttpSecretStore"),
            "debug was: {debug_str}"
        );
    }
}
