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
| `config`  | Configuration loading                |
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
export INFERADB_CTRL__AUTH__KEY_ENCRYPTION_SECRET=$(openssl rand -base64 32)
cargo run --bin inferadb-control -- --dev-mode  # in-memory storage
```

REST `:9090` | gRPC `:9091` | Health `/healthz` | Metrics `/metrics`

## Config

Prefix: `INFERADB_CTRL__` (double underscore nesting)

| Variable                      | Default  |
| ----------------------------- | -------- |
| `LISTEN__HTTP`                | 9090     |
| `STORAGE`                     | ledger   |
| `LEDGER__ENDPOINT`            | -        |
| `AUTH__KEY_ENCRYPTION_SECRET` | required |
