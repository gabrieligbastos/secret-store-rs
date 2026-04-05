//! Shared types, error definitions, and utility functions used across all
//! secret store providers.

pub mod error;
pub mod types;
pub mod utils;

pub use error::{Error, Result};
pub use types::{SecretMeta, SecretValue};
pub use utils::obfuscate_secret;
