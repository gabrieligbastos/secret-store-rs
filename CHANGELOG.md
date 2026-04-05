# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release with Azure Key Vault, AWS Secrets Manager, GCP Secret Manager, and generic HTTP providers
- `InMemory` store always available (no features needed) — ideal for tests
- `kms` feature: AES-256-GCM envelope encryption backed by any `Kms` implementation
- Fluent builders for all providers, reading configuration from environment variables
- `display_name()` / `debug_info()` on all provider ops traits — minimal `Display`, rich `Debug`
- Prefix filtering on `list_secrets()` for all providers
- Full async trait (`async-trait`) — all operations are non-blocking

[Unreleased]: https://github.com/gabrieligbastos/secret-store-rs/compare/HEAD...HEAD
