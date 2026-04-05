//! [`GcpSecretManagerStore`] — the [`crate::SecretStore`] impl for GCP Secret Manager.

use async_trait::async_trait;
use std::fmt;
use std::sync::Arc;

use crate::common::{Result, SecretMeta, SecretValue};
use crate::SecretStore;
use super::client::{GcpSmOps, GcpHttpClient};

/// A GCP Secret Manager-backed [`SecretStore`].
///
/// Constructed via [`super::builder::GcpSecretManagerBuilder`].
pub struct GcpSecretManagerStore {
    pub(super) ops: Arc<dyn GcpSmOps>,
}

impl fmt::Debug for GcpSecretManagerStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GcpSecretManagerStore {{ {} }}", self.ops.debug_info())
    }
}

impl fmt::Display for GcpSecretManagerStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.ops.display_name())
    }
}

impl GcpSecretManagerStore {
    pub(super) fn from_http_client(client: GcpHttpClient) -> Self {
        Self { ops: Arc::new(client) }
    }

    #[cfg(test)]
    pub(crate) fn from_ops(ops: Arc<dyn GcpSmOps>) -> Self {
        Self { ops }
    }
}

#[async_trait]
impl SecretStore for GcpSecretManagerStore {
    async fn get_secret(&self, name: &str) -> Result<SecretValue> {
        self.ops.get(name).await.map(SecretValue::new)
    }

    async fn set_secret(&self, name: &str, value: &str) -> Result<()> {
        match self.ops.update(name, value).await {
            Ok(()) => Ok(()),
            Err(e) if e.is_not_found() => self.ops.create(name, value).await,
            Err(e) => Err(e),
        }
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
    use super::*;
    use super::super::client::MockGcpSmOps;
    use crate::common::{Error, error::StringError};
    use mockall::predicate::eq;

    const PROJECT: &str = "my-gcp-project";

    fn store_with_mock(setup: impl FnOnce(&mut MockGcpSmOps)) -> GcpSecretManagerStore {
        let mut mock = MockGcpSmOps::new();
        setup(&mut mock);
        mock.expect_display_name().return_const("<mock-gcp>".to_owned()).times(0..);
        mock.expect_debug_info().return_const("project_id=<mock>, api=<mock>, provider=GcpSecretManager".to_owned()).times(0..);
        GcpSecretManagerStore::from_ops(Arc::new(mock))
    }

    // ── get_secret ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn get_secret_calls_ops_with_correct_name() {
        let store = store_with_mock(|m| {
            m.expect_get()
                .with(eq("gcp-secret"))
                .once()
                .returning(|_| Ok("gcp-value".to_owned()));
        });
        assert_eq!(store.get_secret("gcp-secret").await.unwrap().expose_secret(), "gcp-value");
    }

    #[tokio::test]
    async fn get_secret_not_found_returns_error() {
        let store = store_with_mock(|m| {
            m.expect_get()
                .once()
                .returning(|name| Err(Error::NotFound {
                    name: name.to_owned(),
                    source: Box::new(StringError::from("404")),
                }));
        });
        assert!(store.get_secret("missing").await.unwrap_err().is_not_found());
    }

    #[tokio::test]
    async fn get_secret_unauthenticated_propagates() {
        let store = store_with_mock(|m| {
            m.expect_get()
                .once()
                .returning(|_| Err(Error::Unauthenticated {
                    source: Box::new(StringError::from("token expired")),
                }));
        });
        assert!(store.get_secret("key").await.unwrap_err().is_auth());
    }

    #[tokio::test]
    async fn get_secret_permission_denied_propagates() {
        let store = store_with_mock(|m| {
            m.expect_get()
                .once()
                .returning(|name| Err(Error::PermissionDenied {
                    name: name.to_owned(),
                    source: Box::new(StringError::from("403")),
                }));
        });
        assert!(store.get_secret("key").await.unwrap_err().is_auth());
    }

    // ── set_secret ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn set_secret_calls_update_first() {
        let store = store_with_mock(|m| {
            m.expect_update()
                .with(eq("sk"), eq("sv"))
                .once()
                .returning(|_, _| Ok(()));
        });
        store.set_secret("sk", "sv").await.unwrap();
    }

    #[tokio::test]
    async fn set_secret_falls_back_to_create_on_not_found() {
        let store = store_with_mock(|m| {
            m.expect_update()
                .once()
                .returning(|name, _| Err(Error::NotFound {
                    name: name.to_owned(),
                    source: Box::new(StringError::from("404")),
                }));
            m.expect_create()
                .with(eq("new-secret"), eq("initial-val"))
                .once()
                .returning(|_, _| Ok(()));
        });
        store.set_secret("new-secret", "initial-val").await.unwrap();
    }

    #[tokio::test]
    async fn set_secret_auth_error_does_not_trigger_create_fallback() {
        let store = store_with_mock(|m| {
            m.expect_update()
                .once()
                .returning(|_, _| Err(Error::Unauthenticated {
                    source: Box::new(StringError::from("401")),
                }));
        });
        assert!(store.set_secret("k", "v").await.unwrap_err().is_auth());
    }

    // ── delete_secret ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn delete_secret_calls_ops_with_correct_name() {
        let store = store_with_mock(|m| {
            m.expect_delete()
                .with(eq("to-remove"))
                .once()
                .returning(|_| Ok(()));
        });
        store.delete_secret("to-remove").await.unwrap();
    }

    #[tokio::test]
    async fn delete_nonexistent_returns_not_found() {
        let store = store_with_mock(|m| {
            m.expect_delete()
                .once()
                .returning(|name| Err(Error::NotFound {
                    name: name.to_owned(),
                    source: Box::new(StringError::from("404")),
                }));
        });
        assert!(store.delete_secret("ghost").await.unwrap_err().is_not_found());
    }

    // ── list_secrets ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn list_secrets_returns_correct_names() {
        let store = store_with_mock(|m| {
            m.expect_list()
                .once()
                .returning(|_| Ok(vec!["s1".to_owned(), "s2".to_owned()]));
        });
        assert_eq!(store.list_secrets(None).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn list_secrets_propagates_error() {
        let store = store_with_mock(|m| {
            m.expect_list()
                .once()
                .returning(|_| Err(Error::Generic {
                    store: "GcpSecretManager",
                    source: Box::new(StringError::from("quota exceeded")),
                }));
        });
        assert!(store.list_secrets(None).await.is_err());
    }

    // ── display / debug ───────────────────────────────────────────────────────

    #[test]
    fn display_includes_project_id() {
        let store = store_with_mock(|m| {
            m.expect_display_name()
                .once()
                .return_const(format!("GcpSecretManager(project={})", PROJECT));
        });
        assert!(store.to_string().contains(PROJECT));
    }

    #[test]
    fn debug_shows_project_and_api() {
        const DETAILS: &str = "project_id=my-gcp-project, api=https://secretmanager.googleapis.com/v1, provider=GcpSecretManager";
        let store = store_with_mock(|m| {
            m.expect_debug_info().once().return_const(DETAILS.to_owned());
        });
        let debug_str = format!("{:?}", store);
        assert!(debug_str.contains("project_id="), "debug was: {debug_str}");
        assert!(debug_str.contains("provider=GcpSecretManager"), "debug was: {debug_str}");
    }
}
