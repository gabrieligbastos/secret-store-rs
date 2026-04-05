//! Internal types for the in-memory secret store backend.

use std::collections::HashMap;

/// The inner state held by the [`super::InMemory`] store.
///
/// Separated into its own type so it can be wrapped in
/// `parking_lot::RwLock` and shared via `Arc`.
#[derive(Debug, Default)]
pub(super) struct InMemoryState {
    pub secrets: HashMap<String, String>,
}

impl InMemoryState {
    pub fn new() -> Self {
        Self::default()
    }
}
