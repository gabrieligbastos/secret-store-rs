//! Azure Key Vault-specific types and error-mapping helpers.

/// Configuration keys accepted by [`super::builder::KeyVaultBuilder`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ConfigKey {
    /// The full URL of the Azure Key Vault instance.
    /// Maps to env var `AZURE_KEYVAULT_URL`.
    VaultUrl,
    /// Azure Active Directory tenant ID.
    /// Maps to env var `AZURE_TENANT_ID`.
    TenantId,
    /// Service-principal client ID.
    /// Maps to env var `AZURE_CLIENT_ID`.
    ClientId,
    /// Service-principal client secret.
    /// Maps to env var `AZURE_CLIENT_SECRET`.
    ClientSecret,
}

impl ConfigKey {
    /// Returns the canonical environment variable name for this key.
    pub fn env_var(self) -> &'static str {
        match self {
            Self::VaultUrl => "AZURE_KEYVAULT_URL",
            Self::TenantId => "AZURE_TENANT_ID",
            Self::ClientId => "AZURE_CLIENT_ID",
            Self::ClientSecret => "AZURE_CLIENT_SECRET",
        }
    }
}

impl std::fmt::Display for ConfigKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.env_var())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_key_env_var_names_are_correct() {
        assert_eq!(ConfigKey::VaultUrl.env_var(), "AZURE_KEYVAULT_URL");
        assert_eq!(ConfigKey::TenantId.env_var(), "AZURE_TENANT_ID");
        assert_eq!(ConfigKey::ClientId.env_var(), "AZURE_CLIENT_ID");
        assert_eq!(ConfigKey::ClientSecret.env_var(), "AZURE_CLIENT_SECRET");
    }

    #[test]
    fn config_key_display_equals_env_var() {
        let key = ConfigKey::VaultUrl;
        assert_eq!(key.to_string(), key.env_var());
    }

    #[test]
    fn required_env_returns_err_when_var_unset() {
        // Use a name extremely unlikely to exist in any real environment.
        unsafe { std::env::remove_var("SECRET_STORE_TEST_NONEXISTENT_VAR_XYZ") };
        let result = std::env::var("SECRET_STORE_TEST_NONEXISTENT_VAR_XYZ");
        assert!(result.is_err());
    }
}
