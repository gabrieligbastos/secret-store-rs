# Contributing to secret-store-rs

Thank you for considering a contribution! This document explains how to get started.

## Development Setup

You need a recent stable Rust toolchain. Install via [rustup](https://rustup.rs/):

```shell
rustup update stable
```

Additional tools used in CI (install once):

```shell
cargo install cargo-deny typos-cli
```

## Running Tests

Unit and integration tests (no cloud credentials needed — all use mocks):

```shell
# Default features only (memory + common)
cargo test

# All features
cargo test --all-features
```

To run a specific feature set:

```shell
cargo test --features azure
cargo test --features "aws,gcp,http,kms"
```

## Linting and Checks

```shell
# Format check
cargo fmt --check

# Clippy (warnings treated as errors, same as CI)
cargo clippy --all-features -- -D warnings

# Security advisories, license compliance, duplicate deps
cargo deny check

# Spell check source and docs
typos
```

## Documentation

```shell
# Build docs locally with all features
cargo doc --all-features --no-deps --open
```

## Submitting a Pull Request

1. Fork the repo and create a feature branch from `master`.
2. Add tests for any new behaviour.
3. Make sure `cargo test --all-features`, `cargo clippy --all-features -- -D warnings`, `cargo fmt --check`, `cargo deny check`, and `typos` all pass locally.
4. Open a PR — the template will guide you through describing the change.

## Versioning

This project follows [Semantic Versioning](https://semver.org/).  
Breaking changes to the public API require a major version bump.

## Releasing (maintainer only)

1. Update `version` in `Cargo.toml`.
2. Move `## [Unreleased]` entries in `CHANGELOG.md` to a new `## [x.y.z]` section.
3. Commit: `chore: release vx.y.z`.
4. Push a tag: `git tag vx.y.z && git push origin vx.y.z`.
5. The [`publish` workflow](.github/workflows/publish.yml) handles the rest.
