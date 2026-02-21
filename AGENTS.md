# AGENTS.md

InferaDB Control Plane: multi-tenant administration APIs. Rust 1.92 (2024 edition), gRPC API.

## Commands

```bash
cargo build --workspace  # build
cargo nextest run  # test
cargo nextest run -p inferadb-control-core  # test crate
cargo +1.92 clippy --workspace --all-targets -- -D warnings  # lint
cargo +nightly fmt --all  # format
just ci  # all checks
```

## Architecture

```
inferadb-control (bin) → api → core → storage → inferadb-common-storage → Ledger
```

| Crate     | Purpose                              |
| --------- | ------------------------------------ |
| `control` | Binary entrypoint                    |
| `api`     | HTTP/gRPC handlers, middleware       |
| `core`    | Auth, crypto, JWT, repos, entities   |
| `config`  | CLI configuration (clap::Parser)     |
| `storage` | Storage factory, backend abstraction |
| `types`   | `Error` enum, `Result` alias         |

## Critical Constraints

**Non-negotiable:**

- No `unsafe` code
- No `.unwrap()` — use snafu `.context()`
- No `panic!`, `todo!()`, `unimplemented!()`
- No placeholder stubs — fully implement or don't write
- No TODO/FIXME/HACK comments
- No backwards compatibility shims or feature flags
- Write tests before implementation, target 90%+ coverage
- Never make git commits
- Never reference implementation steps, tasks, phases, etc. in code comments
- Must review changes using the CodeRabbit MCP; all genuine issues must be addressed

**Errors**: Use `inferadb_control_types::{Error, Result}` with factory methods:

```rust
Error::validation("msg")  // 400
Error::not_found("msg")   // 404
Error::auth("msg")        // 401
Error::authz("msg")       // 403
Error::storage("msg")     // 500
Error::internal("msg")    // 500
```

## Serena MCP

Activate at session start: `mcp__plugin_serena_serena__activate_project`

**Use semantic tools, not file operations:**

| Task            | Use                             | Not                  |
| --------------- | ------------------------------- | -------------------- |
| Understand file | `get_symbols_overview`          | Reading entire file  |
| Find symbol     | `find_symbol` with pattern      | Grep/glob            |
| Find usages     | `find_referencing_symbols`      | Grep for text        |
| Edit function   | `replace_symbol_body`           | Raw text replacement |
| Add code        | `insert_after/before_symbol`    | Line number editing  |
| Search patterns | `search_for_pattern` + rel_path | Global grep          |

**Symbol paths:** `ClassName/method_name`. Patterns: `Foo` (any), `Foo/bar` (nested), `/Foo/bar` (exact root).

**Workflow:**

1. `get_symbols_overview` first
2. `find_symbol` with `depth=1` for methods without bodies
3. `include_body=True` only when needed
4. `find_referencing_symbols` before any refactor

## Task Completion

**A task is not complete until all of these pass — no "pre-existing issue" exceptions:**

- `cargo build --workspace` — no errors or warnings
- `cargo nextest run` — all tests pass
- `cargo +1.92 clippy --workspace --all-targets -- -D warnings` — no warnings
- `cargo +nightly fmt --all -- --check` — no formatting issues

**Review workflow:**

1. Run `just ci` — all checks must pass
2. Review changes with CodeRabbit: `mcp__coderabbit__review_changes`
3. Fix all identified issues — no exceptions
4. Re-review if fixes were substantial

## Code Conventions

**Builders (bon):**

- `#[builder(into)]` for `String` fields to accept `&str`
- Match `#[builder(default)]` with `#[serde(default)]` for config
- Fallible builders via `#[bon]` impl block when validation needed
- Prefer compile-time required fields over runtime checks

**Doc comments:** Use ` ```no_run ` — `cargo test` skips, `cargo doc` validates.

**Writing:** No filler (very, really, basically), no wordiness (in order to → to), active voice, specific language.

**Markdown:** Concise, kebab-case filenames, specify language in code blocks.

## Key Paths

| Path                          | Contents                |
| ----------------------------- | ----------------------- |
| `crates/types/src/error.rs`   | Error enum              |
| `crates/core/src/repository/` | Repository impls        |
| `crates/storage/src/`         | Storage traits/backends |
| `crates/api/src/handlers/`    | API handlers            |

## Dev

```bash
docker-compose up -d
cargo run --bin inferadb-control -- --dev-mode  # in-memory storage
```

REST `:9090` | Health `/healthz` | Metrics `/metrics`

## Config

CLI-first configuration with `INFERADB__CONTROL__` env var prefix. CLI args override env vars override defaults.

```bash
# Development
inferadb-control --dev-mode

# Production
inferadb-control --storage ledger --ledger-endpoint https://ledger:50051 \
  --ledger-client-id ctrl-01 --ledger-namespace-id 1 --log-format json
```

| Variable                                 | Default                 | Notes                        |
| ---------------------------------------- | ----------------------- | ---------------------------- |
| `INFERADB__CONTROL__LISTEN`              | `127.0.0.1:9090`        | HTTP bind address            |
| `INFERADB__CONTROL__LOG_LEVEL`           | `info`                  | tracing filter               |
| `INFERADB__CONTROL__LOG_FORMAT`          | `auto`                  | auto/json/text               |
| `INFERADB__CONTROL__PEM`                 | —                       | Ed25519 PEM (auto-gen)       |
| `INFERADB__CONTROL__KEY_FILE`            | `./data/master.key`     | Master key path              |
| `INFERADB__CONTROL__STORAGE`             | `ledger`                | memory/ledger                |
| `INFERADB__CONTROL__LEDGER_ENDPOINT`     | —                       | Required when storage=ledger |
| `INFERADB__CONTROL__LEDGER_CLIENT_ID`    | —                       | Required when storage=ledger |
| `INFERADB__CONTROL__LEDGER_NAMESPACE_ID` | —                       | Required when storage=ledger |
| `INFERADB__CONTROL__LEDGER_VAULT_ID`     | —                       | Optional                     |
| `INFERADB__CONTROL__EMAIL_HOST`          | `""`                    | Empty = email disabled       |
| `INFERADB__CONTROL__EMAIL_PORT`          | `587`                   |                              |
| `INFERADB__CONTROL__EMAIL_USERNAME`      | —                       |                              |
| `INFERADB__CONTROL__EMAIL_PASSWORD`      | —                       |                              |
| `INFERADB__CONTROL__EMAIL_FROM_ADDRESS`  | `noreply@inferadb.com`  |                              |
| `INFERADB__CONTROL__EMAIL_FROM_NAME`     | `InferaDB`              |                              |
| `INFERADB__CONTROL__EMAIL_INSECURE`      | `false`                 | Skip TLS verification        |
| `INFERADB__CONTROL__FRONTEND_URL`        | `http://localhost:3000` | Base URL for email links     |
