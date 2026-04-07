//! HTTP secret store-specific types and error-mapping helpers.

use crate::common::Error;

/// Configuration keys accepted by [`super::builder::HttpSecretStoreBuilder`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ConfigKey {
    /// Base URL of the secret API endpoint (e.g. `http://vault:8200/v1/secret`).
    /// Maps to env var `SECRET_STORE_HTTP_URL`.
    BaseUrl,
    /// Bearer token for `Authorization: Bearer <token>` header.
    /// Maps to env var `SECRET_STORE_HTTP_TOKEN`.
    AuthToken,
    /// Optional namespace header value (e.g. for Vault Enterprise namespaces).
    /// Maps to env var `SECRET_STORE_HTTP_NAMESPACE`.
    Namespace,
}

impl ConfigKey {
    pub fn env_var(self) -> &'static str {
        match self {
            Self::BaseUrl => "SECRET_STORE_HTTP_URL",
            Self::AuthToken => "SECRET_STORE_HTTP_TOKEN",
            Self::Namespace => "SECRET_STORE_HTTP_NAMESPACE",
        }
    }
}

impl std::fmt::Display for ConfigKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.env_var())
    }
}

/// Maps an HTTP status code to our crate's [`Error`] type.
pub(super) fn map_http_error(
    name: &str,
    status: u16,
    e: impl std::error::Error + Send + Sync + 'static,
) -> Error {
    match status {
        404 => Error::NotFound {
            name: name.to_owned(),
            source: Box::new(e),
        },
        401 => Error::Unauthenticated {
            source: Box::new(e),
        },
        403 => Error::PermissionDenied {
            name: name.to_owned(),
            source: Box::new(e),
        },
        _ => Error::Generic {
            store: "HttpSecretStore",
            source: Box::new(e),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::error::StringError;

    #[test]
    fn config_key_env_var_names() {
        assert_eq!(ConfigKey::BaseUrl.env_var(), "SECRET_STORE_HTTP_URL");
        assert_eq!(ConfigKey::AuthToken.env_var(), "SECRET_STORE_HTTP_TOKEN");
        assert_eq!(
            ConfigKey::Namespace.env_var(),
            "SECRET_STORE_HTTP_NAMESPACE"
        );
    }

    #[test]
    fn map_404_to_not_found() {
        let err = map_http_error("secret", 404, StringError::from("not found"));
        assert!(err.is_not_found());
    }

    #[test]
    fn map_401_to_unauthenticated() {
        let err = map_http_error("secret", 401, StringError::from("unauthorized"));
        assert!(matches!(err, Error::Unauthenticated { .. }));
    }

    #[test]
    fn map_403_to_permission_denied() {
        let err = map_http_error("secret", 403, StringError::from("forbidden"));
        assert!(matches!(err, Error::PermissionDenied { .. }));
    }

    #[test]
    fn map_500_to_generic() {
        let err = map_http_error("secret", 500, StringError::from("server error"));
        assert!(matches!(err, Error::Generic { .. }));
    }
}
