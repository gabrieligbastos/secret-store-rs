//! In-memory secret store — always available, no feature flags required.
//!
//! Intended for unit tests and local development.  **Not suitable for
//! production use** as secrets are stored in plaintext in process memory.

pub mod types;

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::RwLock;

use crate::SecretStore;
use crate::common::{Error, Result, SecretMeta, SecretValue};
use types::InMemoryState;

/// An in-memory [`SecretStore`] backed by a `HashMap`.
///
/// Thread-safe via `parking_lot::RwLock`.  All secrets are lost when the
/// struct is dropped.
///
/// # Example
/// ```
/// use secret_store::{SecretStore, memory::InMemory};
///
/// # #[tokio::main]
/// # async fn main() {
/// let store = InMemory::new();
/// store.set_secret("api-key", "my-value").await.unwrap();
/// let val = store.get_secret("api-key").await.unwrap();
/// assert_eq!(val.expose_secret(), "my-value");
/// # }
/// ```
#[derive(Debug, Default, Clone)]
pub struct InMemory {
    state: Arc<RwLock<InMemoryState>>,
}

impl InMemory {
    /// Creates a new empty [`InMemory`] store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an [`InMemory`] store pre-populated with the given key-value
    /// pairs.  Useful for seeding test fixtures.
    pub fn with_secrets(
        secrets: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Self {
        let store = Self::new();
        {
            let mut state = store.state.write();
            for (k, v) in secrets {
                state.secrets.insert(k.into(), v.into());
            }
        }
        store
    }
}

impl fmt::Display for InMemory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InMemory(secrets={})", self.state.read().secrets.len())
    }
}

#[async_trait]
impl SecretStore for InMemory {
    async fn get_secret(&self, name: &str) -> Result<SecretValue> {
        let state = self.state.read();
        state
            .secrets
            .get(name)
            .map(|v| SecretValue::new(v.clone()))
            .ok_or_else(|| Error::NotFound {
                name: name.to_owned(),
                source: Box::new(crate::common::error::StringError(format!(
                    "secret '{name}' does not exist in InMemory store"
                ))),
            })
    }

    async fn set_secret(&self, name: &str, value: &str) -> Result<()> {
        self.state
            .write()
            .secrets
            .insert(name.to_owned(), value.to_owned());
        Ok(())
    }

    async fn delete_secret(&self, name: &str) -> Result<()> {
        let removed = self.state.write().secrets.remove(name);
        removed.map(|_| ()).ok_or_else(|| Error::NotFound {
            name: name.to_owned(),
            source: Box::new(crate::common::error::StringError(format!(
                "secret '{name}' does not exist in InMemory store"
            ))),
        })
    }

    async fn list_secrets(&self, prefix: Option<&str>) -> Result<Vec<SecretMeta>> {
        let state = self.state.read();
        let metas = state
            .secrets
            .keys()
            .filter(|k| prefix.is_none_or(|p| k.starts_with(p)))
            .map(|k| SecretMeta::new(k.clone()))
            .collect();
        Ok(metas)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── get_secret ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn get_existing_secret_returns_value() {
        let store = InMemory::new();
        store.set_secret("key", "value").await.unwrap();
        let result = store.get_secret("key").await.unwrap();
        assert_eq!(result.expose_secret(), "value");
    }

    #[tokio::test]
    async fn get_missing_secret_returns_not_found() {
        let store = InMemory::new();
        let result = store.get_secret("nonexistent").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().is_not_found());
    }

    #[tokio::test]
    async fn get_returns_not_found_on_empty_store() {
        let store = InMemory::new();
        let err = store.get_secret("anything").await.unwrap_err();
        assert!(err.is_not_found());
    }

    // ── set_secret ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn set_then_get_roundtrip() {
        let store = InMemory::new();
        store.set_secret("db-pass", "s3cr3t!").await.unwrap();
        let val = store.get_secret("db-pass").await.unwrap();
        assert_eq!(val.expose_secret(), "s3cr3t!");
    }

    #[tokio::test]
    async fn set_overwrites_existing_secret() {
        let store = InMemory::new();
        store.set_secret("key", "first").await.unwrap();
        store.set_secret("key", "second").await.unwrap();
        let val = store.get_secret("key").await.unwrap();
        assert_eq!(val.expose_secret(), "second");
    }

    #[tokio::test]
    async fn set_empty_value_is_accepted() {
        let store = InMemory::new();
        store.set_secret("empty-key", "").await.unwrap();
        let val = store.get_secret("empty-key").await.unwrap();
        assert_eq!(val.expose_secret(), "");
    }

    // ── delete_secret ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn delete_existing_secret_removes_it() {
        let store = InMemory::new();
        store.set_secret("tmp", "value").await.unwrap();
        store.delete_secret("tmp").await.unwrap();
        let result = store.get_secret("tmp").await;
        assert!(result.unwrap_err().is_not_found());
    }

    #[tokio::test]
    async fn delete_nonexistent_secret_returns_not_found() {
        let store = InMemory::new();
        let result = store.delete_secret("ghost").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().is_not_found());
    }

    #[tokio::test]
    async fn delete_is_idempotent_second_call_returns_not_found() {
        let store = InMemory::new();
        store.set_secret("once", "val").await.unwrap();
        store.delete_secret("once").await.unwrap();
        let second = store.delete_secret("once").await;
        assert!(second.unwrap_err().is_not_found());
    }

    // ── list_secrets ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn list_all_secrets_with_no_prefix() {
        let store = InMemory::with_secrets([("a", "1"), ("b", "2"), ("c", "3")]);
        let mut metas = store.list_secrets(None).await.unwrap();
        metas.sort_by(|x, y| x.name.cmp(&y.name));
        let names: Vec<_> = metas.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, ["a", "b", "c"]);
    }

    #[tokio::test]
    async fn list_secrets_filters_by_prefix() {
        let store = InMemory::with_secrets([
            ("prod-db-pass", "x"),
            ("prod-api-key", "y"),
            ("dev-db-pass", "z"),
        ]);
        let mut metas = store.list_secrets(Some("prod-")).await.unwrap();
        metas.sort_by(|x, y| x.name.cmp(&y.name));
        let names: Vec<_> = metas.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, ["prod-api-key", "prod-db-pass"]);
    }

    #[tokio::test]
    async fn list_secrets_returns_empty_on_no_match() {
        let store = InMemory::with_secrets([("a", "1")]);
        let metas = store.list_secrets(Some("zzz-")).await.unwrap();
        assert!(metas.is_empty());
    }

    #[tokio::test]
    async fn list_secrets_empty_store_returns_empty_vec() {
        let store = InMemory::new();
        let metas = store.list_secrets(None).await.unwrap();
        assert!(metas.is_empty());
    }

    // ── with_secrets helper ───────────────────────────────────────────────────

    #[tokio::test]
    async fn with_secrets_seeds_store_correctly() {
        let store = InMemory::with_secrets([("k1", "v1"), ("k2", "v2")]);
        assert_eq!(store.get_secret("k1").await.unwrap().expose_secret(), "v1");
        assert_eq!(store.get_secret("k2").await.unwrap().expose_secret(), "v2");
    }

    // ── display ───────────────────────────────────────────────────────────────

    #[test]
    fn display_shows_count() {
        let store = InMemory::with_secrets([("a", "1"), ("b", "2")]);
        let s = store.to_string();
        assert!(s.contains("InMemory"), "display was: {s}");
        assert!(s.contains('2'), "display was: {s}");
    }

    // ── Arc delegation ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn arc_wrapped_store_works_via_trait() {
        let store: Arc<dyn SecretStore> = Arc::new(InMemory::new());
        store.set_secret("key", "val").await.unwrap();
        let v = store.get_secret("key").await.unwrap();
        assert_eq!(v.expose_secret(), "val");
    }
}
