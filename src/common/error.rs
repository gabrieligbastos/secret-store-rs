use std::fmt;

/// Unified error type for all [`crate::SecretStore`] operations.
///
/// Marked `#[non_exhaustive]` so future variants can be added without a
/// breaking change.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The requested secret was not found in the store.
    #[error("Secret '{name}' not found: {source}")]
    NotFound {
        name: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    /// The caller does not have sufficient permissions.
    #[error("Permission denied for secret '{name}': {source}")]
    PermissionDenied {
        name: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    /// Authentication failed (invalid or expired credentials).
    #[error("Unauthenticated: {source}")]
    Unauthenticated {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    /// A configuration error (missing env var, malformed URL, etc.).
    #[error("Configuration error for '{store}': {message}")]
    Configuration { store: &'static str, message: String },

    /// The operation is not implemented by this provider.
    #[error("Operation '{operation}' is not implemented by '{store}'")]
    NotImplemented {
        operation: &'static str,
        store: &'static str,
    },

    /// A generic, provider-specific error that does not map to a known variant.
    #[error("Secret store '{store}' error: {source}")]
    Generic {
        store: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
}

impl Error {
    /// Returns `true` if the error represents a missing secret.
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound { .. })
    }

    /// Returns `true` if the error is authentication-related.
    pub fn is_auth(&self) -> bool {
        matches!(self, Self::Unauthenticated { .. } | Self::PermissionDenied { .. })
    }
}

/// Convenience `Result` alias for this crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// A simple boxed error used in unit tests or simple string error wrapping.
#[derive(Debug)]
pub(crate) struct StringError(pub String);

impl fmt::Display for StringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StringError {}

impl From<String> for StringError {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for StringError {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn not_found_error(name: &str) -> Error {
        Error::NotFound {
            name: name.to_owned(),
            source: Box::new(StringError::from("404")),
        }
    }

    fn auth_error() -> Error {
        Error::Unauthenticated {
            source: Box::new(StringError::from("401 Unauthorized")),
        }
    }

    fn permission_error(name: &str) -> Error {
        Error::PermissionDenied {
            name: name.to_owned(),
            source: Box::new(StringError::from("403 Forbidden")),
        }
    }

    #[test]
    fn not_found_is_correctly_identified() {
        assert!(not_found_error("my-secret").is_not_found());
        assert!(!auth_error().is_not_found());
    }

    #[test]
    fn auth_errors_are_correctly_identified() {
        assert!(auth_error().is_auth());
        assert!(permission_error("my-secret").is_auth());
        assert!(!not_found_error("my-secret").is_auth());
    }

    #[test]
    fn not_found_display_includes_secret_name() {
        let msg = not_found_error("db-password").to_string();
        assert!(msg.contains("db-password"), "message was: {msg}");
    }

    #[test]
    fn configuration_error_display() {
        let e = Error::Configuration {
            store: "AzureKeyVault",
            message: "AZURE_KEYVAULT_URL is not set".to_owned(),
        };
        let msg = e.to_string();
        assert!(msg.contains("AzureKeyVault"), "message was: {msg}");
        assert!(msg.contains("AZURE_KEYVAULT_URL is not set"), "message was: {msg}");
    }

    #[test]
    fn not_implemented_display() {
        let e = Error::NotImplemented {
            operation: "list_secrets",
            store: "HttpSecretStore",
        };
        let msg = e.to_string();
        assert!(msg.contains("list_secrets"), "message was: {msg}");
        assert!(msg.contains("HttpSecretStore"), "message was: {msg}");
    }

    #[test]
    fn generic_error_display() {
        let e = Error::Generic {
            store: "InMemory",
            source: Box::new(StringError::from("internal error")),
        };
        let msg = e.to_string();
        assert!(msg.contains("InMemory"), "message was: {msg}");
    }
}
