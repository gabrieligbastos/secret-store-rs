//! Builder for [`super::GcpSecretManagerStore`].

use crate::common::Result;
use super::client::GcpHttpClient;
use super::store::GcpSecretManagerStore;
use super::types::ConfigKey;

/// Fluent builder for [`GcpSecretManagerStore`].
///
/// Uses `gcp-auth` for Application Default Credentials (ADC) — reads
/// `GOOGLE_APPLICATION_CREDENTIALS` or falls back to the metadata server
/// (when running on GCP infrastructure).
///
/// # Using environment variables
/// ```no_run
/// use secret_store::gcp::GcpSecretManagerBuilder;
///
/// # #[tokio::main] async fn main() {
/// // Reads GCP_PROJECT_ID and GOOGLE_APPLICATION_CREDENTIALS automatically.
/// let store = GcpSecretManagerBuilder::from_env().build().await.unwrap();
/// # }
/// ```
///
/// # Manual configuration
/// ```no_run
/// use secret_store::gcp::GcpSecretManagerBuilder;
///
/// # #[tokio::main] async fn main() {
/// let store = GcpSecretManagerBuilder::new()
///     .with_project_id("my-gcp-project")
///     .build()
///     .await
///     .unwrap();
/// # }
/// ```
#[derive(Debug, Default)]
pub struct GcpSecretManagerBuilder {
    project_id: Option<String>,
}

impl GcpSecretManagerBuilder {
    /// Creates a new builder with no pre-set values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Populates all fields from the standard GCP environment variables.
    pub fn from_env() -> Self {
        Self {
            project_id: std::env::var(ConfigKey::ProjectId.env_var())
                .ok()
                .filter(|v| !v.is_empty()),
        }
    }

    /// Sets the GCP project ID (e.g. `my-gcp-project`).
    pub fn with_project_id(mut self, project_id: impl Into<String>) -> Self {
        self.project_id = Some(project_id.into());
        self
    }

    /// Builds a [`GcpSecretManagerStore`].
    ///
    /// # Errors
    /// Returns [`crate::Error::Configuration`] if `project_id` is not set.
    pub async fn build(self) -> Result<GcpSecretManagerStore> {
        let project_id = self
            .project_id
            .or_else(|| {
                std::env::var(ConfigKey::ProjectId.env_var())
                    .ok()
                    .filter(|v| !v.is_empty())
            })
            .ok_or_else(|| crate::common::Error::Configuration {
                store: "GcpSecretManager",
                message: format!(
                    "project ID is required — set `{}` or call `.with_project_id()`",
                    ConfigKey::ProjectId.env_var()
                ),
            })?;

        let auth_manager = gcp_auth::provider().await.map_err(|e| {
            crate::common::Error::Configuration {
                store: "GcpSecretManager",
                message: format!("failed to initialise GCP authentication: {e}"),
            }
        })?;

        let http_client = reqwest::Client::builder()
            .build()
            .map_err(|e| crate::common::Error::Configuration {
                store: "GcpSecretManager",
                message: format!("failed to build HTTP client: {e}"),
            })?;

        Ok(GcpSecretManagerStore::from_http_client(GcpHttpClient {
            project_id,
            auth: auth_manager,
            http: http_client,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_stores_project_id() {
        let b = GcpSecretManagerBuilder::new().with_project_id("my-project");
        assert_eq!(b.project_id.as_deref(), Some("my-project"));
    }

    #[test]
    fn from_env_reads_gcp_project_id() {
        unsafe { std::env::set_var("GCP_PROJECT_ID", "env-project-123") };
        let b = GcpSecretManagerBuilder::from_env();
        assert_eq!(b.project_id.as_deref(), Some("env-project-123"));
        unsafe { std::env::remove_var("GCP_PROJECT_ID") };
    }

    #[test]
    fn from_env_ignores_empty_project_id() {
        unsafe { std::env::set_var("GCP_PROJECT_ID", "") };
        let b = GcpSecretManagerBuilder::from_env();
        assert!(b.project_id.is_none());
        unsafe { std::env::remove_var("GCP_PROJECT_ID") };
    }

    #[tokio::test]
    async fn build_fails_without_project_id() {
        unsafe { std::env::remove_var("GCP_PROJECT_ID") };
        let result = GcpSecretManagerBuilder::new().build().await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), crate::common::Error::Configuration { .. }));
    }
}
