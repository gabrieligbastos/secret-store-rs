//! AWS Secrets Manager-specific types and error-mapping helpers.

use crate::common::Error;

/// Configuration keys accepted by [`super::builder::AwsSecretsManagerBuilder`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ConfigKey {
    /// AWS region (e.g. `us-east-1`).
    /// Maps to env var `AWS_DEFAULT_REGION` or `AWS_REGION`.
    Region,
    /// AWS access key ID.
    /// Maps to env var `AWS_ACCESS_KEY_ID`.
    AccessKeyId,
    /// AWS secret access key.
    /// Maps to env var `AWS_SECRET_ACCESS_KEY`.
    SecretAccessKey,
    /// AWS session token (for temporary credentials / STS).
    /// Maps to env var `AWS_SESSION_TOKEN`.
    SessionToken,
}

impl ConfigKey {
    /// Returns the primary environment variable name for this key.
    pub fn env_var(self) -> &'static str {
        match self {
            Self::Region => "AWS_DEFAULT_REGION",
            Self::AccessKeyId => "AWS_ACCESS_KEY_ID",
            Self::SecretAccessKey => "AWS_SECRET_ACCESS_KEY",
            Self::SessionToken => "AWS_SESSION_TOKEN",
        }
    }
}

impl std::fmt::Display for ConfigKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.env_var())
    }
}

/// Maps an `aws_sdk_secretsmanager::Error` to our crate's [`Error`] type,
/// inspecting the error code where available.
pub(super) fn map_aws_error(name: &str, e: impl std::error::Error + Send + Sync + 'static) -> Error {
    let msg = e.to_string();
    if msg.contains("ResourceNotFoundException") || msg.contains("SecretNotFound") {
        Error::NotFound {
            name: name.to_owned(),
            source: Box::new(e),
        }
    } else if msg.contains("AccessDeniedException") || msg.contains("AuthorizationError") {
        Error::PermissionDenied {
            name: name.to_owned(),
            source: Box::new(e),
        }
    } else if msg.contains("InvalidClientTokenId") || msg.contains("ExpiredToken") || msg.contains("UnrecognizedClientException") {
        Error::Unauthenticated { source: Box::new(e) }
    } else {
        Error::Generic {
            store: "AwsSecretsManager",
            source: Box::new(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::error::StringError;

    #[test]
    fn config_key_env_var_names_are_correct() {
        assert_eq!(ConfigKey::Region.env_var(), "AWS_DEFAULT_REGION");
        assert_eq!(ConfigKey::AccessKeyId.env_var(), "AWS_ACCESS_KEY_ID");
        assert_eq!(ConfigKey::SecretAccessKey.env_var(), "AWS_SECRET_ACCESS_KEY");
        assert_eq!(ConfigKey::SessionToken.env_var(), "AWS_SESSION_TOKEN");
    }

    #[test]
    fn map_resource_not_found_to_not_found_error() {
        let err = map_aws_error("my-secret", StringError::from("ResourceNotFoundException: Secrets Manager can't find the specified secret."));
        assert!(err.is_not_found());
    }

    #[test]
    fn map_access_denied_to_permission_denied() {
        let err = map_aws_error("my-secret", StringError::from("AccessDeniedException: User not authorized"));
        assert!(matches!(err, Error::PermissionDenied { .. }));
    }

    #[test]
    fn map_invalid_token_to_unauthenticated() {
        let err = map_aws_error("my-secret", StringError::from("InvalidClientTokenId: The security token is not valid"));
        assert!(matches!(err, Error::Unauthenticated { .. }));
    }

    #[test]
    fn map_generic_error_stays_generic() {
        let err = map_aws_error("my-secret", StringError::from("ServiceUnavailableException: Service is unavailable"));
        assert!(matches!(err, Error::Generic { .. }));
    }
}
