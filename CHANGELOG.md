# Changelog

All notable changes to `cfms-ctl` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- git-cliff: end of header -->

## [0.4.0] - 2026-11-16

### Added

- Implement auto configuration file migration
- Implement core configuration contract handling and validation
- Refactor the storage backend to be asynchronous; add support for S3 storage

### Fixed

- Add named schema candidates resolution and enhance config schema path handling

### Documentation

- Add README.md

**Full Changelog**: https://github.com/cfms-dev/cfms-ctl/compare/v0.3.0..v0.4.0

## [0.3.0] - 2026-11-15

### Added

- Implement transactional extension database purge functionality
- Implement password policy management with Argon2id hashing
- Implement database-backed audit log retention policy with validation and defaults
- *(permission)* Implement retention policy management for permission purging
- Implement `extension purge-data`
- Implement `deployment install / upgrade / update`
- [**breaking**] Refactor server version handling and improve error reporting, remove `--server-version` argument

**Full Changelog**: https://github.com/cfms-dev/cfms-ctl/compare/v0.2.0..v0.3.0

## [0.2.0] - 2026-11-14

### Added

- Implement backup verification functionality in `cfms-ctl`
- Update backup import/export format to version 2
- Implement version parsing and compatibility evaluation for CFMS servers and extensions

### Documentation

- Add planning and research guidelines to AGENTS.md

**Full Changelog**: https://github.com/cfms-dev/cfms-ctl/compare/v0.1.0..v0.2.0

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
