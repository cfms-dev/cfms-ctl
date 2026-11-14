# Changelog

All notable changes to `cfms-ctl` will be documented in this file.

## [0.1.0] - 2026-11-14

### Added

- Standalone Rust CLI (`cfms-ctl`) supporting SQLite, MySQL, and PostgreSQL CFMS deployments.
- `doctor` diagnostics for server health, configuration, runtime lock, and database schema checks.
- `deployment` lifecycle management (`check`, `upgrade`, `update`, `downgrade`, `resume`, `prune`).
- `database` inspection, validation, schema upgrade, Alembic stamp, SQL/Alembic migration template rendering, and cross-engine migration.
- `backup` Format v2 encrypted logical export, import, inspection, and verification.
- `config` lossless template synchronization, secret management, and schema-validated database option editing.
- `extension` management (`inspect`, `install`, `upgrade`, `enable`, `disable`, `uninstall`, `purge`).
- `user`, `permission`, and `audit` administration commands.
- `self-update` command backed by GitHub Releases and `cargo-dist` artifacts.
