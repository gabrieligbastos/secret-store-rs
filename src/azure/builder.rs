//! Builder for [`super::KeyVaultSecretStore`].

use std::sync::Arc;

use azure_core::credentials::{Secret, TokenCredential};
use azure_identity::{AzureCliCredential, ClientSecretCredential};
use azure_security_keyvault_secrets::SecretClient;

use crate::common::Result;

use super::client::AzureSdkClient;
use super::store::KeyVaultSecretStore;
use super::types::ConfigKey;

/// Fluent builder for [`KeyVaultSecretStore`].
///
/// # Using environment variables
/// ```no_run
/// use secret_store::azure::KeyVaultBuilder;
///
/// # #[tokio::main] async fn main() {
/// // Reads AZURE_KEYVAULT_URL, AZURE_TENANT_ID, AZURE_CLIENT_ID,
/// // AZURE_CLIENT_SECRET automatically.
/// let store = KeyVaultBuilder::from_env().build().await.unwrap();
/// # }
/// ```
///
/// # Manual configuration
/// ```no_run
/// use secret_store::azure::KeyVaultBuilder;
///
/// # #[tokio::main] async fn main() {
/// let store = KeyVaultBuilder::new()
///     .with_vault_url("https://my-vault.vault.azure.net/")
///     .build()
///     .await
///     .unwrap();
/// # }
/// ```
#[derive(Debug, Default)]
pub struct KeyVaultBuilder {
    vault_url: Option<String>,
    tenant_id: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
}

impl KeyVaultBuilder {
    /// Creates a new builder with no pre-set values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Populates all fields from the standard Azure environment variables:
    /// - `AZURE_KEYVAULT_URL`
    /// - `AZURE_TENANT_ID`
    /// - `AZURE_CLIENT_ID`
    /// - `AZURE_CLIENT_SECRET`
    ///
    /// Fields that are already set via `with_*` are **not** overwritten.
    pub fn from_env() -> Self {
        Self {
            vault_url: std::env::var(ConfigKey::VaultUrl.env_var())
                .ok()
                .filter(|v| !v.is_empty()),
            tenant_id: std::env::var(ConfigKey::TenantId.env_var())
                .ok()
                .filter(|v| !v.is_empty()),
            client_id: std::env::var(ConfigKey::ClientId.env_var())
                .ok()
                .filter(|v| !v.is_empty()),
            client_secret: std::env::var(ConfigKey::ClientSecret.env_var())
                .ok()
                .filter(|v| !v.is_empty()),
        }
    }

    /// Sets the Key Vault URL (e.g. `https://my-vault.vault.azure.net/`).
    pub fn with_vault_url(mut self, url: impl Into<String>) -> Self {
        self.vault_url = Some(url.into());
        self
    }

    /// Sets the Azure Active Directory tenant ID.
    pub fn with_tenant_id(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Sets the service-principal client ID.
    pub fn with_client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Sets the service-principal client secret.
    pub fn with_client_secret(mut self, secret: impl Into<String>) -> Self {
        self.client_secret = Some(secret.into());
        self
    }

    /// Builds a [`KeyVaultSecretStore`] using the configured values.
    ///
    /// Falls back to `AZURE_KEYVAULT_URL` for the vault URL if not explicitly
    /// set.  Credentials are resolved via `AzureCliCredential` (default) or
    /// `ClientSecretCredential` when tenant/client/secret env vars are all set.
    ///
    /// # Errors
    /// Returns [`crate::Error::Configuration`] if `vault_url` is missing.
    pub async fn build(self) -> Result<KeyVaultSecretStore> {
        let vault_url = self
            .vault_url
            .or_else(|| {
                std::env::var(ConfigKey::VaultUrl.env_var())
                    .ok()
                    .filter(|v| !v.is_empty())
            })
            .ok_or_else(|| crate::common::Error::Configuration {
                store: "AzureKeyVault",
                message: format!(
                    "vault URL is required — set `{}` or call `.with_vault_url()`",
                    ConfigKey::VaultUrl.env_var()
                ),
            })?;

        let credential: Arc<dyn TokenCredential> = match (
            self.tenant_id.as_deref(),
            self.client_id.as_deref(),
            self.client_secret.as_deref(),
        ) {
            (Some(tenant), Some(client_id), Some(secret)) => ClientSecretCredential::new(
                tenant,
                client_id.to_owned(),
                Secret::new(secret.to_owned()),
                None,
            )
            .map_err(|e| crate::common::Error::Configuration {
                store: "AzureKeyVault",
                message: format!("failed to create ClientSecretCredential: {e}"),
            })?,
            _ => {
                AzureCliCredential::new(None).map_err(|e| crate::common::Error::Configuration {
                    store: "AzureKeyVault",
                    message: format!("failed to create AzureCliCredential: {e}"),
                })?
            }
        };
        let client = SecretClient::new(&vault_url, credential, None).map_err(|e| {
            crate::common::Error::Configuration {
                store: "AzureKeyVault",
                message: format!("failed to create SecretClient: {e}"),
            }
        })?;

        let sdk_client = AzureSdkClient { client, vault_url };
        Ok(KeyVaultSecretStore::new(Arc::new(sdk_client)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_stores_vault_url() {
        let b = KeyVaultBuilder::new().with_vault_url("https://test.vault.azure.net/");
        assert_eq!(
            b.vault_url.as_deref(),
            Some("https://test.vault.azure.net/")
        );
    }

    #[test]
    fn builder_stores_all_fields() {
        let b = KeyVaultBuilder::new()
            .with_vault_url("https://v.vault.azure.net/")
            .with_tenant_id("tenant-123")
            .with_client_id("client-456")
            .with_client_secret("secret-789");
        assert_eq!(b.tenant_id.as_deref(), Some("tenant-123"));
        assert_eq!(b.client_id.as_deref(), Some("client-456"));
        assert_eq!(b.client_secret.as_deref(), Some("secret-789"));
    }

    #[test]
    fn from_env_reads_vault_url_from_env() {
        unsafe { std::env::set_var("AZURE_KEYVAULT_URL", "https://env-vault.vault.azure.net/") };
        let b = KeyVaultBuilder::from_env();
        assert_eq!(
            b.vault_url.as_deref(),
            Some("https://env-vault.vault.azure.net/")
        );
        unsafe { std::env::remove_var("AZURE_KEYVAULT_URL") };
    }

    #[test]
    fn from_env_ignores_empty_vars() {
        unsafe { std::env::set_var("AZURE_KEYVAULT_URL", "") };
        let b = KeyVaultBuilder::from_env();
        assert!(b.vault_url.is_none());
        unsafe { std::env::remove_var("AZURE_KEYVAULT_URL") };
    }

    #[tokio::test]
    async fn build_fails_without_vault_url() {
        unsafe { std::env::remove_var("AZURE_KEYVAULT_URL") };
        let result = KeyVaultBuilder::new().build().await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, crate::common::Error::Configuration { .. }));
    }
}
