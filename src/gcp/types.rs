//! GCP Secret Manager-specific types and error-mapping helpers.

use crate::common::Error;

/// Configuration keys accepted by [`super::builder::GcpSecretManagerBuilder`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ConfigKey {
    /// GCP project ID.
    /// Maps to env var `GCP_PROJECT_ID`.
    ProjectId,
    /// Path to a service-account JSON key file.
    /// Maps to env var `GOOGLE_APPLICATION_CREDENTIALS`.
    CredentialsFile,
}

impl ConfigKey {
    /// Returns the primary environment variable name for this key.
    pub fn env_var(self) -> &'static str {
        match self {
            Self::ProjectId => "GCP_PROJECT_ID",
            Self::CredentialsFile => "GOOGLE_APPLICATION_CREDENTIALS",
        }
    }
}

impl std::fmt::Display for ConfigKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.env_var())
    }
}

/// Maps an HTTP status code (from the GCP REST API) and a message to our
/// crate's [`Error`] type.
pub(super) fn map_gcp_http_error(
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
            store: "GcpSecretManager",
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
        assert_eq!(ConfigKey::ProjectId.env_var(), "GCP_PROJECT_ID");
        assert_eq!(
            ConfigKey::CredentialsFile.env_var(),
            "GOOGLE_APPLICATION_CREDENTIALS"
        );
    }

    #[test]
    fn map_404_to_not_found() {
        let err = map_gcp_http_error("my-secret", 404, StringError::from("not found"));
        assert!(err.is_not_found());
    }

    #[test]
    fn map_401_to_unauthenticated() {
        let err = map_gcp_http_error("my-secret", 401, StringError::from("unauthorized"));
        assert!(matches!(err, Error::Unauthenticated { .. }));
    }

    #[test]
    fn map_403_to_permission_denied() {
        let err = map_gcp_http_error("my-secret", 403, StringError::from("forbidden"));
        assert!(matches!(err, Error::PermissionDenied { .. }));
    }

    #[test]
    fn map_500_to_generic() {
        let err = map_gcp_http_error("my-secret", 500, StringError::from("internal server error"));
        assert!(matches!(err, Error::Generic { .. }));
    }
}
