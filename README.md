# secret_store

[![Crates.io](https://img.shields.io/crates/v/secret_store.svg)](https://crates.io/crates/secret_store)
[![docs.rs](https://docs.rs/secret_store/badge.svg)](https://docs.rs/secret_store)
[![License: MIT OR Apache-2.0](https://img.shields.io/crates/l/secret_store.svg)](LICENSE-MIT)

A unified, async `SecretStore` trait for multiple cloud secret backends, inspired by the architecture of [`object_store`](https://crates.io/crates/object_store).

## Supported Providers

| Provider | Feature flag | Status |
|---|---|---|
| In-Memory (tests / local dev) | *(none)* | ✅ |
| Azure Key Vault | `azure` | ✅ |
| AWS Secrets Manager | `aws` | ✅ |
| GCP Secret Manager | `gcp` | ✅ |
| Generic HTTP / HashiCorp Vault | `http` | ✅ |

KMS envelope encryption (`kms` feature) is available for all providers.

---

## Quick Start

Add to `Cargo.toml`:

```toml
[dependencies]
secret_store = { version = "0.1", features = ["azure"] }
```

```rust
use secret_store::azure::KeyVaultBuilder;
use secret_store::SecretStore;

#[tokio::main]
async fn main() -> secret_store::Result<()> {
    // Reads AZURE_KEYVAULT_URL, AZURE_TENANT_ID, AZURE_CLIENT_ID,
    // AZURE_CLIENT_SECRET from the environment.
    let store = KeyVaultBuilder::from_env().build().await?;

    store.set_secret("db-password", "hunter2").await?;
    let val = store.get_secret("db-password").await?;
    println!("{}", val.expose_secret());

    Ok(())
}
```

### In-memory (for tests)

```rust
use secret_store::{SecretStore, memory::InMemory};

let store = InMemory::new();
store.set_secret("key", "value").await.unwrap();
let val = store.get_secret("key").await.unwrap();
assert_eq!(val.expose_secret(), "value");
```

### KMS Envelope Encryption

```rust
use std::sync::Arc;
use secret_store::kms::{Kms, NoopKms, SecretsManager};

let kms = Arc::new(NoopKms); // replace with AwsKms / AzureKms in production
let manager = SecretsManager::new(kms, "my-master-key-id".to_owned());

let encrypted = manager.encrypt(b"api-key-value", b"user-uuid").await?;
// Store `encrypted` bytes in your DB.

let decrypted = manager.decrypt(&encrypted, b"user-uuid").await?;
assert_eq!(decrypted, b"api-key-value");
```

---

## Environment Variables

### Azure Key Vault

| Variable | Description |
|---|---|
| `AZURE_KEYVAULT_URL` | Full vault URL, e.g. `https://my-vault.vault.azure.net/` |
| `AZURE_TENANT_ID` | Azure AD tenant ID |
| `AZURE_CLIENT_ID` | Service-principal client ID |
| `AZURE_CLIENT_SECRET` | Service-principal client secret |

### AWS Secrets Manager

| Variable | Description |
|---|---|
| `AWS_DEFAULT_REGION` | AWS region, e.g. `us-east-1` |
| `AWS_ACCESS_KEY_ID` | AWS access key ID |
| `AWS_SECRET_ACCESS_KEY` | AWS secret access key |
| `AWS_SESSION_TOKEN` | Session token (optional, for STS credentials) |

### GCP Secret Manager

| Variable | Description |
|---|---|
| `GCP_PROJECT_ID` | GCP project ID |
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to service-account JSON key file |

### HTTP / HashiCorp Vault

| Variable | Description |
|---|---|
| `SECRET_STORE_HTTP_URL` | Base URL, e.g. `http://vault:8200/v1/secret` |
| `SECRET_STORE_HTTP_TOKEN` | Bearer auth token |
| `SECRET_STORE_HTTP_NAMESPACE` | Optional namespace header |

---

## Feature Parity Matrix

### Secret Operations

| Operation | In-Memory | Azure KV | AWS SM | GCP SM | HTTP |
|---|:---:|:---:|:---:|:---:|:---:|
| `get_secret` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `set_secret` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `delete_secret` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `list_secrets` | ✅ | 🔮 | ✅ | ✅ | ✅ |
| Secret versioning | ➖ | 🔮 | 🔮 | 🔮 | ➖ |
| Secret rotation hooks | ➖ | 🔮 | 🔮 | 🔮 | 🔮 |

### Authentication

| Method | In-Memory | Azure KV | AWS SM | GCP SM | HTTP |
|---|:---:|:---:|:---:|:---:|:---:|
| `from_env()` builder | ✅ | ✅ | ✅ | ✅ | ✅ |
| Service principal / IAM | ➖ | ✅ | ✅ | ✅ | ➖ |
| Workload / managed identity | ➖ | 🔮 | 🔮 | 🔮 | ➖ |
| Token caching / refresh | ➖ | 🔮 | ✅ (SDK) | 🔮 | ➖ |
| Custom credential provider | ➖ | 🔮 | 🔮 | 🔮 | ➖ |

### KMS Envelope Encryption (`kms` feature)

| Feature | Status |
|---|:---:|
| `Kms` trait | ✅ |
| `SecretsManager` (AES-256-GCM + CBOR) | ✅ |
| `NoopKms` (testing) | ✅ |
| SHA-512 AAD / confused-deputy protection | ✅ |
| Data key in-memory cache | ✅ |
| Versioned ciphertext envelope | ✅ |
| AWS KMS adapter | 🔮 |
| Azure Key Vault Keys adapter | 🔮 |
| GCP Cloud KMS adapter | 🔮 |
| HashiCorp Vault Transit adapter | 🔮 |

### Certificate & Key Operations

| Operation | Azure KV | AWS SM | GCP SM | HTTP |
|---|:---:|:---:|:---:|:---:|
| Store / retrieve certificates | 🔮 | 🚫 | 🚫 | ➖ |
| Store / retrieve asymmetric keys | 🔮 | 🚫 | 🚫 | ➖ |
| Key rotation | 🔮 | 🚫 | 🔮 | ➖ |

> **Legend:** ✅ Implemented · 🔮 Planned · 🚧 In progress · 🚫 Not supported by provider · ➖ Not applicable

---

## Migrating from `KeyVaultService`

**Before:**

```rust
pub struct KeyVaultService {
    secret_client: SecretClient,
}

impl KeyVaultService {
    pub async fn get_secret(&self, name: &str) -> Result<String, String> { ... }
    pub async fn set_secret(&self, name: &str, value: &str) -> Result<(), String> { ... }
}
```

**After:**

```rust
use secret_store::azure::KeyVaultBuilder;
use secret_store::SecretStore;

let store = KeyVaultBuilder::from_env().build().await?;

// Same env vars — zero config change:
// AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_KEYVAULT_URL
let val = store.get_secret("my-secret").await?;
store.set_secret("my-secret", "new-value").await?;
```

---

## Running Tests

```sh
# Unit tests (no cloud credentials required)
cargo test

# Unit tests for all providers
cargo test --features azure,aws,gcp,http,kms

# Integration tests (requires real cloud credentials)
TEST_INTEGRATION=1 cargo test --test integration --features azure,aws,gcp,http,kms
```

---

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
