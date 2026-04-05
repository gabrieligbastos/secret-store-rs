//! [`KeyVaultSecretStore`] — the [`crate::SecretStore`] impl for Azure Key Vault.

use async_trait::async_trait;
use std::fmt;
use std::sync::Arc;

use crate::common::{Result, SecretMeta, SecretValue};
use crate::SecretStore;
use super::client::AzureKvOps;

/// An Azure Key Vault-backed [`SecretStore`].
///
/// Constructed via [`super::builder::KeyVaultBuilder`].
pub struct KeyVaultSecretStore {
    pub(super) ops: Arc<dyn AzureKvOps>,
}

impl fmt::Debug for KeyVaultSecretStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyVaultSecretStore {{ {} }}", self.ops.debug_info())
    }
}

impl fmt::Display for KeyVaultSecretStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AzureKeyVault({})", self.ops.display_name())
    }
}

impl KeyVaultSecretStore {
    /// Creates a store wrapping the given [`AzureKvOps`] implementation.
    /// The vault URL (or stub label) lives inside `ops`.
    pub(super) fn new(ops: Arc<dyn AzureKvOps>) -> Self {
        Self { ops }
    }

    /// Injects a mock — used in unit tests only.
    #[cfg(test)]
    pub(crate) fn from_ops(ops: Arc<dyn AzureKvOps>) -> Self {
        Self { ops }
    }
}

#[async_trait]
impl SecretStore for KeyVaultSecretStore {
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
// Unit tests — mock-based, no real network calls
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::client::MockAzureKvOps;
    use crate::common::{Error, error::StringError};
    use mockall::predicate::eq;

    const VAULT_URL: &str = "https://test-vault.vault.azure.net/";

    fn store_with_mock(setup: impl FnOnce(&mut MockAzureKvOps)) -> KeyVaultSecretStore {
        let mut mock = MockAzureKvOps::new();
        setup(&mut mock);
        // Fallbacks: allow display_name / debug_info to be called any number of
        // times (including zero) without requiring an explicit expectation.
        mock.expect_display_name().return_const("<mock-vault>".to_owned()).times(0..);
        mock.expect_debug_info().return_const("vault_url=<mock>, provider=AzureKeyVault".to_owned()).times(0..);
        KeyVaultSecretStore::from_ops(Arc::new(mock))
    }

    // ── get_secret ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn get_secret_calls_ops_with_correct_name() {
        let store = store_with_mock(|m| {
            m.expect_get()
                .with(eq("db-password"))
                .once()
                .returning(|_| Ok("hunter2".to_owned()));
        });
        let val = store.get_secret("db-password").await.unwrap();
        assert_eq!(val.expose_secret(), "hunter2");
    }

    #[tokio::test]
    async fn get_secret_not_found_returns_not_found_error() {
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
                    source: Box::new(StringError::from("401")),
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

    #[tokio::test]
    async fn get_secret_generic_error_propagates() {
        let store = store_with_mock(|m| {
            m.expect_get()
                .once()
                .returning(|_| Err(Error::Generic {
                    store: "AzureKeyVault",
                    source: Box::new(StringError::from("service unavailable")),
                }));
        });
        let err = store.get_secret("key").await.unwrap_err();
        assert!(!err.is_not_found() && !err.is_auth());
    }

    // ── set_secret ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn set_secret_calls_ops_with_correct_name_and_value() {
        let store = store_with_mock(|m| {
            m.expect_set()
                .with(eq("api-key"), eq("my-secret-value"))
                .once()
                .returning(|_, _| Ok(()));
        });
        store.set_secret("api-key", "my-secret-value").await.unwrap();
    }

    #[tokio::test]
    async fn set_secret_propagates_auth_error() {
        let store = store_with_mock(|m| {
            m.expect_set()
                .once()
                .returning(|_, _| Err(Error::Unauthenticated {
                    source: Box::new(StringError::from("401")),
                }));
        });
        assert!(store.set_secret("k", "v").await.unwrap_err().is_auth());
    }

    #[tokio::test]
    async fn set_secret_propagates_generic_error() {
        let store = store_with_mock(|m| {
            m.expect_set()
                .once()
                .returning(|_, _| Err(Error::Generic {
                    store: "AzureKeyVault",
                    source: Box::new(StringError::from("throttled")),
                }));
        });
        assert!(store.set_secret("k", "v").await.is_err());
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
    async fn list_secrets_returns_not_implemented() {
        let store = store_with_mock(|m| {
            m.expect_list()
                .once()
                .returning(|_| Err(Error::NotImplemented {
                    operation: "list_secrets",
                    store: "AzureKeyVault",
                }));
        });
        assert!(matches!(
            store.list_secrets(None).await.unwrap_err(),
            Error::NotImplemented { .. }
        ));
    }

    #[tokio::test]
    async fn list_secrets_returns_meta_for_matching_names() {
        let store = store_with_mock(|m| {
            m.expect_list()
                .with(eq(Some("prod-".to_owned())))
                .once()
                .returning(|_| Ok(vec!["prod-api".to_owned(), "prod-db".to_owned()]));
        });
        let mut metas = store.list_secrets(Some("prod-")).await.unwrap();
        metas.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(metas[0].name, "prod-api");
        assert_eq!(metas[1].name, "prod-db");
    }

    // ── display / debug ───────────────────────────────────────────────────────

    #[test]
    fn display_includes_vault_url() {
        let store = store_with_mock(|m| {
            m.expect_display_name()
                .once()
                .return_const(VAULT_URL.to_owned());
        });
        assert!(store.to_string().contains(VAULT_URL));
    }

    #[test]
    fn debug_shows_vault_details() {
        const DETAILS: &str = "vault_url=https://test-vault.vault.azure.net/, provider=AzureKeyVault";
        let store = store_with_mock(|m| {
            m.expect_debug_info().once().return_const(DETAILS.to_owned());
        });
        let debug_str = format!("{:?}", store);
        assert!(debug_str.contains("vault_url="), "debug was: {debug_str}");
        assert!(debug_str.contains("provider=AzureKeyVault"), "debug was: {debug_str}");
    }
}
