use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// A secret value that **never leaks** its content through [`fmt::Debug`] or
/// [`fmt::Display`].
///
/// Use [`SecretValue::expose_secret`] to access the underlying string.
#[derive(Clone, Serialize, Deserialize)]
pub struct SecretValue(String);

impl SecretValue {
    /// Wraps a string as a secret value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns a reference to the underlying secret string.
    ///
    /// This is the **only** way to access the raw value; call it deliberately.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    /// Consumes the wrapper and returns the inner `String`.
    pub fn into_string(self) -> String {
        self.0
    }

    /// Returns the byte length of the secret (useful for validation without
    /// exposing the content).
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the secret value is an empty string.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Intentionally redacted so secrets never appear in log output.
impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue([REDACTED])")
    }
}

/// Intentionally redacted so secrets never appear in formatted output.
impl fmt::Display for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl PartialEq for SecretValue {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for SecretValue {}

// ─────────────────────────────────────────────────────────────────────────────

/// Metadata about a named secret in the store.
///
/// Returned by [`crate::SecretStore::list_secrets`].  The actual secret value
/// is **not** included.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretMeta {
    /// The unique name / identifier of the secret.
    pub name: String,

    /// An optional version string (format depends on the provider).
    pub version: Option<String>,

    /// When the secret was first created, if available.
    pub created_at: Option<DateTime<Utc>>,

    /// When the secret was last updated, if available.
    pub updated_at: Option<DateTime<Utc>>,
}

impl SecretMeta {
    /// Creates a minimal [`SecretMeta`] with only a name set.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: None,
            created_at: None,
            updated_at: None,
        }
    }
}

impl fmt::Display for SecretMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretMeta(name={}", self.name)?;
        if let Some(v) = &self.version {
            write!(f, ", version={v}")?;
        }
        write!(f, ")")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── SecretValue ───────────────────────────────────────────────────────────

    #[test]
    fn secret_value_debug_is_redacted() {
        let s = SecretValue::new("super-secret-password");
        let debug_output = format!("{s:?}");
        assert_eq!(debug_output, "SecretValue([REDACTED])");
        assert!(!debug_output.contains("super-secret-password"));
    }

    #[test]
    fn secret_value_display_is_redacted() {
        let s = SecretValue::new("another-secret");
        let display_output = format!("{s}");
        assert_eq!(display_output, "[REDACTED]");
        assert!(!display_output.contains("another-secret"));
    }

    #[test]
    fn secret_value_expose_returns_raw_value() {
        let raw = "my-secret-value";
        let s = SecretValue::new(raw);
        assert_eq!(s.expose_secret(), raw);
    }

    #[test]
    fn secret_value_into_string_consumes_wrapper() {
        let raw = "consume-me";
        let s = SecretValue::new(raw);
        assert_eq!(s.into_string(), raw);
    }

    #[test]
    fn secret_value_len_and_is_empty() {
        let empty = SecretValue::new("");
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);

        let nonempty = SecretValue::new("abc");
        assert!(!nonempty.is_empty());
        assert_eq!(nonempty.len(), 3);
    }

    #[test]
    fn secret_value_equality_uses_inner_value() {
        let a = SecretValue::new("same");
        let b = SecretValue::new("same");
        let c = SecretValue::new("different");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn secret_value_serde_roundtrip() {
        let original = SecretValue::new("serde-test");
        let json = serde_json::to_string(&original).unwrap();
        let decoded: SecretValue = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
    }

    // ── SecretMeta ────────────────────────────────────────────────────────────

    #[test]
    fn secret_meta_new_has_none_fields() {
        let m = SecretMeta::new("my-key");
        assert_eq!(m.name, "my-key");
        assert!(m.version.is_none());
        assert!(m.created_at.is_none());
        assert!(m.updated_at.is_none());
    }

    #[test]
    fn secret_meta_display_includes_name() {
        let m = SecretMeta {
            name: "db-password".to_owned(),
            version: Some("v3".to_owned()),
            created_at: None,
            updated_at: None,
        };
        let s = m.to_string();
        assert!(s.contains("db-password"), "display was: {s}");
        assert!(s.contains("v3"), "display was: {s}");
    }

    #[test]
    fn secret_meta_serde_roundtrip() {
        let original = SecretMeta {
            name: "api-key".to_owned(),
            version: Some("1".to_owned()),
            created_at: Some(Utc::now()),
            updated_at: None,
        };
        let json = serde_json::to_string(&original).unwrap();
        let decoded: SecretMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(original.name, decoded.name);
        assert_eq!(original.version, decoded.version);
    }
}
