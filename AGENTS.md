# AGENTS.md

This file provides guidance for coding agents working in `cfms-ctl`.

## Project Overview

`cfms-ctl` is a standalone Rust CLI (Edition 2024) for maintaining CFMS servers across SQLite, MySQL, and PostgreSQL backends.

Key modules under `src/`:
- `src/cli/`: `clap` derive command and subcommand definitions.
- `src/core/`: Error types (`CfmsError`), workspace path discovery, lossless `toml_edit` configuration handling, runtime lock (`server.lock`), and atomic file writes.
- `src/db/`: Multi-backend `sqlx` pools (`SQLite`, `MySQL`, `PostgreSQL`), schema registry, drift inspection, and transfer types.
- `src/storage/`: Pluggable storage backend trait and local filesystem backend.
- `src/ops/`: Domain operation orchestrators and typed reports.
- `src/ui/`: Dual-mode (`Human` / `Json`) console output, tables, and interactive prompts.

## Planning & Research Rules

1. **Conduct thorough online research when formulating plans**
   - When formulating a plan, search the web as extensively as possible for relevant materials—such as official documentation, standards, library/crate behaviors, best practices, and known caveats—to provide a comprehensive analysis.
   - Do not rely solely on prior knowledge or assumptions when online sources can verify current details, surface alternative approaches, or uncover edge cases and compatibility risks.

## Dependency Management Rules

1. **Always use the latest versions when adding dependencies**
   - Never guess or hardcode outdated crate versions from memory.
   - New dependencies must target the latest stable release available on crates.io (unless a known security/compatibility issue explicitly requires a newer unreleased upstream commit/branch).
   - Avoid unmaintained crates; if an existing or candidate dependency is flagged as unmaintained, research and adopt its actively maintained successor or alternative.

2. **Prefer `cargo` commands over manual `Cargo.toml` edits**
   - **Add dependencies:** Use `cargo add <crate>` (with `-F <features>`, `--no-default-features`, `--dev`, etc.) so Cargo resolves and writes the latest version automatically.
     ```powershell
     cargo add <crate>
     cargo add <crate> --no-default-features -F feature1,feature2
     cargo add --dev <crate>
     ```
   - **Inspect before adding/upgrading:** Use `cargo info <crate>` or `cargo search <crate>` to check the latest version, MSRV, and feature flags.
   - **Upgrade existing dependencies:** Use `cargo upgrade` (e.g., `cargo upgrade -p <crate> --incompatible allow`) followed by `cargo update`.
   - **Remove dependencies:** Use `cargo remove <crate>`.
   - Only edit `Cargo.toml` manually for complex settings that `cargo add`/`cargo upgrade` cannot express cleanly.

3. **Security & Audit Hygiene**
   - Run `cargo audit` after any `Cargo.toml` or `Cargo.lock` change to confirm there are no known security advisories or unmaintained transitive dependencies.
   - Note on `sqlx`: `Cargo.toml` currently pins `sqlx` to the upstream `transact-rs/sqlx` `release/0.9.1` branch so `sqlx-sqlite` allows `libsqlite3-sys 0.39.1` (fixing `RUSTSEC-2026-0459` / `CVE-2026-119375`) and `sqlx-mysql` avoids pulling in `rsa 0.9` (`RUSTSEC-2023-0071`). Once `sqlx >= 0.9.1` is published to crates.io, migrate back to the crates.io release via `cargo add` / `cargo upgrade`.

## Verification Commands

After making changes, verify with:
```powershell
cargo test
cargo clippy --all-targets
cargo audit
```

## Changelog & Release Workflow

- `CHANGELOG.md` follows Keep a Changelog and is managed by `git-cliff` via `cliff.toml`.
- Preserve historical manually curated entries (such as `0.1.0`) by prepending new releases below `<!-- git-cliff: end of header -->` instead of overwriting the entire file:
  ```powershell
  git-cliff -u --bump --prepend CHANGELOG.md
  ```
- Releases are built and published by `cargo-dist` (`.github/workflows/release.yml`), which extracts release notes for the tagged version from `CHANGELOG.md`. Verify with `dist generate --check` and `dist plan --output-format=json` when updating release files.
