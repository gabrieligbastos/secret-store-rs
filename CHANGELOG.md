# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-04-08

### Changed
- Updated `thiserror` to 2.0.18
- Updated `chrono` to 0.4.44
- Updated `futures-util` to 0.3.32
- Updated `gcp_auth` to 0.12.6
- Updated `aws-config` to 1.8.15

## [0.1.0] - 2026-04-08

### Added
- Initial release with Azure Key Vault, AWS Secrets Manager, GCP Secret Manager, and generic HTTP providers
- `InMemory` store always available (no features needed) — ideal for tests
- `kms` feature: AES-256-GCM envelope encryption backed by any `Kms` implementation
- Fluent builders for all providers, reading configuration from environment variables
- `display_name()` / `debug_info()` on all provider ops traits — minimal `Display`, rich `Debug`
- Prefix filtering on `list_secrets()` for all providers
- Full async trait (`async-trait`) — all operations are non-blocking

[Unreleased]: https://github.com/gabrieligbastos/secret-store-rs/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/gabrieligbastos/secret-store-rs/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/gabrieligbastos/secret-store-rs/releases/tag/v0.1.0
