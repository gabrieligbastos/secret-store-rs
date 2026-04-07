//! Builder for [`super::AwsSecretsManagerStore`].

use aws_config::BehaviorVersion;
use aws_sdk_secretsmanager::Client;

use super::client::AwsSdkClient;
use super::store::AwsSecretsManagerStore;
use super::types::ConfigKey;
use crate::common::Result;

/// Fluent builder for [`AwsSecretsManagerStore`].
///
/// # Using environment variables
/// ```no_run
/// use secret_store::aws::AwsSecretsManagerBuilder;
///
/// # #[tokio::main] async fn main() {
/// // Reads AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION
/// // automatically via the AWS SDK credential chain.
/// let store = AwsSecretsManagerBuilder::from_env().build().await.unwrap();
/// # }
/// ```
///
/// # Manual configuration
/// ```no_run
/// use secret_store::aws::AwsSecretsManagerBuilder;
///
/// # #[tokio::main] async fn main() {
/// let store = AwsSecretsManagerBuilder::new()
///     .with_region("eu-west-1")
///     .build()
///     .await
///     .unwrap();
/// # }
/// ```
#[derive(Debug, Default)]
pub struct AwsSecretsManagerBuilder {
    region: Option<String>,
}

impl AwsSecretsManagerBuilder {
    /// Creates a new builder with no pre-set values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Populates all fields from standard AWS environment variables.
    /// The AWS SDK also honours `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
    /// `AWS_SESSION_TOKEN`, etc. automatically via its credential chain.
    pub fn from_env() -> Self {
        Self {
            region: std::env::var(ConfigKey::Region.env_var())
                .ok()
                .filter(|v| !v.is_empty())
                .or_else(|| std::env::var("AWS_REGION").ok().filter(|v| !v.is_empty())),
        }
    }

    /// Overrides the AWS region (e.g. `us-east-1`).
    pub fn with_region(mut self, region: impl Into<String>) -> Self {
        self.region = Some(region.into());
        self
    }

    /// Builds an [`AwsSecretsManagerStore`] by loading the AWS SDK config
    /// from the environment / credential chain and optionally overriding the
    /// region.
    ///
    /// # Errors
    /// Propagates any SDK configuration error as [`crate::Error::Configuration`].
    pub async fn build(self) -> Result<AwsSecretsManagerStore> {
        let mut loader = aws_config::defaults(BehaviorVersion::latest());
        if let Some(region) = self.region {
            loader = loader.region(aws_config::Region::new(region));
        }
        let config = loader.load().await;
        let client = Client::new(&config);
        Ok(AwsSecretsManagerStore::from_sdk_client(AwsSdkClient {
            client,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn builder_stores_region() {
        let b = AwsSecretsManagerBuilder::new().with_region("ap-southeast-1");
        assert_eq!(b.region.as_deref(), Some("ap-southeast-1"));
    }

    #[test]
    fn from_env_reads_aws_default_region() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::remove_var("AWS_REGION") };
        unsafe { std::env::set_var("AWS_DEFAULT_REGION", "ca-central-1") };
        let b = AwsSecretsManagerBuilder::from_env();
        unsafe { std::env::remove_var("AWS_DEFAULT_REGION") };
        assert_eq!(b.region.as_deref(), Some("ca-central-1"));
    }

    #[test]
    fn from_env_falls_back_to_aws_region() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::remove_var("AWS_DEFAULT_REGION") };
        unsafe { std::env::set_var("AWS_REGION", "eu-north-1") };
        let b = AwsSecretsManagerBuilder::from_env();
        unsafe { std::env::remove_var("AWS_REGION") };
        assert_eq!(b.region.as_deref(), Some("eu-north-1"));
    }

    #[test]
    fn from_env_ignores_empty_region() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("AWS_DEFAULT_REGION", "") };
        unsafe { std::env::set_var("AWS_REGION", "") };
        let b = AwsSecretsManagerBuilder::from_env();
        unsafe { std::env::remove_var("AWS_DEFAULT_REGION") };
        unsafe { std::env::remove_var("AWS_REGION") };
        assert!(b.region.is_none());
    }
}
