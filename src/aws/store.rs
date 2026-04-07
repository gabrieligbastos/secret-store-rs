//! [`AwsSecretsManagerStore`] — the [`crate::SecretStore`] impl for AWS Secrets Manager.

use async_trait::async_trait;
use std::fmt;
use std::sync::Arc;

use super::client::{AwsSdkClient, AwsSmOps};
use crate::SecretStore;
use crate::common::{Result, SecretMeta, SecretValue};

/// An AWS Secrets Manager-backed [`SecretStore`].
///
/// Constructed via [`super::builder::AwsSecretsManagerBuilder`].
pub struct AwsSecretsManagerStore {
    pub(super) ops: Arc<dyn AwsSmOps>,
}

impl fmt::Debug for AwsSecretsManagerStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AwsSecretsManagerStore {{ {} }}", self.ops.debug_info())
    }
}

impl fmt::Display for AwsSecretsManagerStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.ops.display_name())
    }
}

impl AwsSecretsManagerStore {
    pub(super) fn from_sdk_client(client: AwsSdkClient) -> Self {
        Self {
            ops: Arc::new(client),
        }
    }

    #[cfg(test)]
    pub(crate) fn from_ops(ops: Arc<dyn AwsSmOps>) -> Self {
        Self { ops }
    }
}

#[async_trait]
impl SecretStore for AwsSecretsManagerStore {
    async fn get_secret(&self, name: &str) -> Result<SecretValue> {
        self.ops.get(name).await.map(SecretValue::new)
    }

    /// Creates or updates a secret.
    ///
    /// Attempts `put_secret_value` first (update existing); if that fails with
    /// a not-found error, falls back to `create_secret`.
    async fn set_secret(&self, name: &str, value: &str) -> Result<()> {
        match self.ops.put(name, value).await {
            Ok(()) => Ok(()),
            Err(e) if e.is_not_found() => self.ops.create(name, value).await,
            Err(e) => Err(e),
        }
    }

    async fn delete_secret(&self, name: &str) -> Result<()> {
        self.ops.delete(name).await
    }

    async fn list_secrets(&self, prefix: Option<&str>) -> Result<Vec<SecretMeta>> {
        let all = self.ops.list(prefix.map(str::to_owned)).await?;
        let filtered = all
            .into_iter()
            .filter(|n| prefix.is_none_or(|p| n.starts_with(p)))
            .map(SecretMeta::new)
            .collect();
        Ok(filtered)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::super::client::MockAwsSmOps;
    use super::*;
    use crate::common::{Error, error::StringError};
    use mockall::predicate::eq;

    fn store_with_mock(setup: impl FnOnce(&mut MockAwsSmOps)) -> AwsSecretsManagerStore {
        let mut mock = MockAwsSmOps::new();
        setup(&mut mock);
        mock.expect_display_name()
            .return_const("<mock-aws>".to_owned())
            .times(0..);
        mock.expect_debug_info()
            .return_const("region=<mock>, endpoint=default, provider=AwsSecretsManager".to_owned())
            .times(0..);
        AwsSecretsManagerStore::from_ops(Arc::new(mock))
    }

    // ── display / debug ───────────────────────────────────────────────────────

    #[test]
    fn display_includes_provider_name() {
        let store = store_with_mock(|m| {
            m.expect_display_name()
                .once()
                .return_const("AwsSecretsManager(region=us-east-1)".to_owned());
        });
        assert!(store.to_string().contains("AwsSecretsManager"));
    }

    #[test]
    fn debug_shows_region_and_endpoint() {
        const DETAILS: &str = "region=us-east-1, endpoint=default, provider=AwsSecretsManager";
        let store = store_with_mock(|m| {
            m.expect_debug_info()
                .once()
                .return_const(DETAILS.to_owned());
        });
        let debug_str = format!("{:?}", store);
        assert!(debug_str.contains("region="), "debug was: {debug_str}");
        assert!(
            debug_str.contains("provider=AwsSecretsManager"),
            "debug was: {debug_str}"
        );
    }

    // ── get_secret ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn get_secret_calls_ops_with_correct_name() {
        let store = store_with_mock(|m| {
            m.expect_get()
                .with(eq("my-secret"))
                .once()
                .returning(|_| Ok("secret-val".to_owned()));
        });
        assert_eq!(
            store.get_secret("my-secret").await.unwrap().expose_secret(),
            "secret-val"
        );
    }

    #[tokio::test]
    async fn get_secret_not_found_maps_correctly() {
        let store = store_with_mock(|m| {
            m.expect_get().once().returning(|name| {
                Err(Error::NotFound {
                    name: name.to_owned(),
                    source: Box::new(StringError::from("ResourceNotFoundException")),
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
    async fn get_secret_unauthenticated_maps_correctly() {
        let store = store_with_mock(|m| {
            m.expect_get().once().returning(|_| {
                Err(Error::Unauthenticated {
                    source: Box::new(StringError::from("InvalidClientTokenId")),
                })
            });
        });
        assert!(store.get_secret("key").await.unwrap_err().is_auth());
    }

    #[tokio::test]
    async fn get_secret_permission_denied_maps_correctly() {
        let store = store_with_mock(|m| {
            m.expect_get().once().returning(|name| {
                Err(Error::PermissionDenied {
                    name: name.to_owned(),
                    source: Box::new(StringError::from("AccessDeniedException")),
                })
            });
        });
        assert!(store.get_secret("key").await.unwrap_err().is_auth());
    }

    // ── set_secret — put succeeds ─────────────────────────────────────────────

    #[tokio::test]
    async fn set_secret_calls_put_first() {
        let store = store_with_mock(|m| {
            m.expect_put()
                .with(eq("api-key"), eq("value-123"))
                .once()
                .returning(|_, _| Ok(()));
        });
        store.set_secret("api-key", "value-123").await.unwrap();
    }

    // ── set_secret — put returns not-found → falls back to create ─────────────

    #[tokio::test]
    async fn set_secret_falls_back_to_create_when_not_found() {
        let store = store_with_mock(|m| {
            m.expect_put().once().returning(|name, _| {
                Err(Error::NotFound {
                    name: name.to_owned(),
                    source: Box::new(StringError::from("ResourceNotFoundException")),
                })
            });
            m.expect_create()
                .with(eq("new-key"), eq("new-value"))
                .once()
                .returning(|_, _| Ok(()));
        });
        store.set_secret("new-key", "new-value").await.unwrap();
    }

    #[tokio::test]
    async fn set_secret_propagates_create_error_after_fallback() {
        let store = store_with_mock(|m| {
            m.expect_put().once().returning(|name, _| {
                Err(Error::NotFound {
                    name: name.to_owned(),
                    source: Box::new(StringError::from("not found")),
                })
            });
            m.expect_create().once().returning(|_, _| {
                Err(Error::Generic {
                    store: "AwsSecretsManager",
                    source: Box::new(StringError::from("LimitExceededException")),
                })
            });
        });
        assert!(store.set_secret("k", "v").await.is_err());
    }

    #[tokio::test]
    async fn set_secret_auth_error_does_not_trigger_create_fallback() {
        let store = store_with_mock(|m| {
            m.expect_put().once().returning(|_, _| {
                Err(Error::Unauthenticated {
                    source: Box::new(StringError::from("401")),
                })
            });
        });
        assert!(store.set_secret("k", "v").await.unwrap_err().is_auth());
    }

    // ── delete_secret ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn delete_secret_calls_ops_with_correct_name() {
        let store = store_with_mock(|m| {
            m.expect_delete()
                .with(eq("old-key"))
                .once()
                .returning(|_| Ok(()));
        });
        store.delete_secret("old-key").await.unwrap();
    }

    #[tokio::test]
    async fn delete_nonexistent_secret_returns_not_found() {
        let store = store_with_mock(|m| {
            m.expect_delete().once().returning(|name| {
                Err(Error::NotFound {
                    name: name.to_owned(),
                    source: Box::new(StringError::from("ResourceNotFoundException")),
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

    // ── list_secrets ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn list_secrets_filters_by_prefix() {
        let store = store_with_mock(|m| {
            m.expect_list().once().returning(|_| {
                Ok(vec![
                    "prod-db".to_owned(),
                    "prod-api".to_owned(),
                    "dev-db".to_owned(),
                ])
            });
        });
        let mut metas = store.list_secrets(Some("prod-")).await.unwrap();
        metas.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(metas.len(), 2);
        assert_eq!(metas[0].name, "prod-api");
        assert_eq!(metas[1].name, "prod-db");
    }

    #[tokio::test]
    async fn list_secrets_no_prefix_returns_all() {
        let store = store_with_mock(|m| {
            m.expect_list()
                .once()
                .returning(|_| Ok(vec!["a".to_owned(), "b".to_owned()]));
        });
        assert_eq!(store.list_secrets(None).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn list_secrets_propagates_error() {
        let store = store_with_mock(|m| {
            m.expect_list().once().returning(|_| {
                Err(Error::Generic {
                    store: "AwsSecretsManager",
                    source: Box::new(StringError::from("InternalServiceError")),
                })
            });
        });
        assert!(store.list_secrets(None).await.is_err());
    }
}
