# cfms-ctl

Standalone, high-performance, multi-database operations and maintenance CLI for CFMS (`cfms-on-websocket`) servers.

Built in Rust (Edition 2024), `cfms-ctl` manages the full operational lifecycle of CFMS deployments across **SQLite**, **MySQL** (`utf8mb4`), and **PostgreSQL** without requiring a running server process.

## Features

- **Multi-database backend support**: Native `sqlx` + `sea-query` support for SQLite, MySQL, and PostgreSQL.
- **Packaged deployment lifecycle**: Cold-install, adopt, verify, upgrade, online-update from GitHub Releases, downgrade, resume interrupted transactions, and prune historical snapshots.
- **Hybrid schema engine**: Inspect schema drift, diff schemas, render risk-annotated SQL/Alembic scripts, run hybrid Python + static-AST + native Rust upgrades, and migrate databases across engines.
- **Encrypted logical backups**: Export, inspect, verify, and restore streaming `.confbak` (`CFMSCBK2`) archives compressed with Zstd and encrypted with HKDF-SHA256 + chunked AES-256-GCM.
- **Safe, lock-aware operations**: Respects `src/.maintenance/server.lock` and `src/.maintenance/transaction.json`, performs atomic writes, and provides `--dry-run` previews on mutating workflows.
- **Interactive & CI friendly**: Dual output modes (`--output human` terminal tables and `--output json` structured envelopes) plus `--yes` for non-interactive automation.

## Installation

### Prebuilt Binaries

Download prebuilt binaries and SHA-256 checksums for Linux (`x86_64`, `aarch64`), macOS (`x86_64`, `aarch64`), and Windows (`x86_64`) from [GitHub Releases](https://github.com/cfms-dev/cfms-ctl/releases).

Release artifacts include GitHub Artifact Attestations and can be verified with the GitHub CLI:

```sh
gh attestation verify <downloaded-artifact> --repo cfms-dev/cfms-ctl
```

Once installed, check for or install newer releases anytime with:

```sh
cfms-ctl self-update --check
cfms-ctl self-update
```

### Build from Source

Requires a Rust toolchain supporting Edition 2024:

```sh
git clone https://github.com/cfms-dev/cfms-ctl.git
cd cfms-ctl
cargo install --path .
```

## Quick Start

`cfms-ctl` automatically discovers your CFMS workspace (`<project_root>/src`) from the current directory upward, or you can specify `--root <DIR>` / `--config <FILE>`.

```sh
# 1. Run health, config, runtime lock, and schema drift diagnostics
cfms-ctl doctor

# 2. Cold-install a CFMS release from GitHub into ./cfms
cfms-ctl deployment install --from-github --target ./cfms

# 3. Inspect deployment & database status (or emit JSON for automation)
cfms-ctl deployment status
cfms-ctl -o json database status

# 4. Validate schema contract and preview an upgrade
cfms-ctl database check
cfms-ctl database upgrade --dry-run

# 5. Create and verify an encrypted logical backup
cfms-ctl backup export ./backup.confbak --key-out ./backup.key
cfms-ctl backup verify ./backup.confbak --key-file ./backup.key
```

## Commands

| Command | Subcommands / Flags | Summary |
| --- | --- | --- |
| `doctor` | `[--skip-db]` | Run workspace, `config.toml`, runtime lock, and database schema diagnostics |
| `deployment` | `status`, `verify`, `check`, `install`, `adopt`, `upgrade`, `update`, `downgrade`, `resume`, `prune` | Manage packaged CFMS releases, snapshots, `uv` environment sync, and recovery |
| `database` | `status`, `check`, `upgrade`, `diff`, `export-ir`, `migrate`, `stamp` | Inspect schema drift, diff/render DDL or Alembic scripts, upgrade, and migrate engines |
| `backup` | `export`, `import`, `info`, `verify` | Create, inspect, cryptographically verify, and restore encrypted `.confbak` backups |
| `config` | `sync-template`, `fill-pepper`, `options` (`list`, `get`, `set`, `set-many`, `reset`) | Losslessly sync `config.toml`, initialize `security.pepper`, and edit DB `options` |
| `extension` | `list`, `info`, `install`, `upgrade`, `enable`, `disable`, `uninstall`, `purge-data` | Manage built-in and third-party extensions declaratively via `manifest.toml` |
| `user` | `reset-password`, `rotate-secrets`, `clear-totp` | Reset Argon2id passwords, rotate user signing keys, and clear TOTP credentials |
| `permission` | `purge-expired`, `sync-defaults` | Prune expired permission entries and restore default `user` / `sysop` group rules |
| `audit` | `inspect`, `export`, `purge`, `verify` | Query, export (`jsonl` / `.jsonl.zst`), archive-and-purge, and verify audit logs |
| `self-update` | `[--check] [--version <VERSION>]` | Check for and install updates to `cfms-ctl` from GitHub Releases |

Run `cfms-ctl <command> --help` (or `cfms-ctl <command> <subcommand> --help`) for full flags and arguments.

## Global Options & Environment

| Option | Env Var | Description |
| --- | --- | --- |
| `--root <DIR>` | `CFMS_ROOT` | Path to CFMS project or server root directory (auto-discovered if omitted) |
| `--config <FILE>` | `CFMS_CONFIG` | Override path to `config.toml` |
| `-o, --output <FORMAT>` | — | Output format: `human` (default) or `json` |
| `-y, --yes` | — | Automatically confirm high-risk or mutating prompts |
| `-v, --verbose` | `RUST_LOG` | Enable diagnostic logging on `stderr` |

Additional environment overrides:

- **Tooling discovery**: `CFMS_PYTHON` (Python interpreter for schema probes/Alembic) and `CFMS_UV` (`uv` binary for environment sync).
- **GitHub Releases**: `GITHUB_TOKEN` / `GH_TOKEN` for API authentication; `CFMS_DEPLOY_REPO_OWNER`, `CFMS_DEPLOY_REPO_NAME`, `CFMS_DEPLOY_API_BASE_URL` for CFMS deployment sources; `CFMS_UPDATE_REPO_OWNER`, `CFMS_UPDATE_REPO_NAME`, `CFMS_UPDATE_API_BASE_URL` for `self-update` mirrors.

## Development & Testing

```text
src/
├── cli/       # clap derive command and argument definitions
├── core/      # errors, workspace discovery, lossless toml_edit config, runtime lock, atomic I/O
├── db/        # multi-backend sqlx pools, schema IR/diff/risk/DDL engine, cross-engine transfer
├── storage/   # storage backend trait and local filesystem backend
├── ops/       # domain operation orchestrators and structured reports
└── ui/        # human tables, interactive prompts, and JSON output envelopes
```

Run the test suite, linter, and security audit:

```sh
cargo test
cargo clippy --all-targets
cargo audit
```

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
