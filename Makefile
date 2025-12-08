# Makefile for InferaDB Control
# Provides convenient shortcuts for common cargo commands
#
# Quick start:
#   make setup    - One-time setup (installs tools)
#   make test     - Run all tests
#   make check    - Run all quality checks
#   make dev      - Start development server with watch
#
# Use 'make help' to see all available commands

.PHONY: help setup test test-integration test-fdb check format lint audit deny run build release clean reset dev doc coverage bench fix ci

# Use mise exec if available, otherwise use system cargo
CARGO := $(shell command -v mise > /dev/null 2>&1 && echo "mise exec -- cargo" || echo "cargo")
PRETTIER := $(shell command -v mise > /dev/null 2>&1 && echo "mise exec -- prettier" || echo "prettier")
TAPLO := $(shell command -v mise > /dev/null 2>&1 && echo "mise exec -- taplo" || echo "taplo")
MARKDOWNLINT := $(shell command -v mise > /dev/null 2>&1 && echo "mise exec -- markdownlint-cli2" || echo "markdownlint-cli2")

# Default target - show help
.DEFAULT_GOAL := help

help: ## Show this help message
	@echo "InferaDB Control Commands"
	@echo ""
	@echo "Setup & Development:"
	@grep -E '^(setup|run|dev|build|release|clean|reset):.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Testing:"
	@grep -E '^test.*:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Code Quality:"
	@grep -E '^(check|format|lint|audit|deny|fix):.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Documentation & Analysis:"
	@grep -E '^(doc|coverage|bench):.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "CI/CD:"
	@grep -E '^ci:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Use 'cargo <command> --help' for more options"
	@echo ""

setup: ## One-time development environment setup
	@echo "🔧 Setting up Control development environment..."
	@if command -v mise > /dev/null 2>&1; then \
		mise trust && mise install; \
	else \
		echo "⚠️  mise not found - using system cargo"; \
	fi
	@$(CARGO) fetch
	@echo "✅ Setup complete!"

test: ## Run all tests (unit + integration)
	@echo "🧪 Running all tests..."
	@$(CARGO) test --all-targets

test-integration: ## Run integration tests only
	@echo "🧪 Running integration tests..."
	@$(CARGO) test --test '*' --workspace

test-fdb: ## Run FoundationDB integration tests (requires Docker)
	@echo "🧪 Running FDB integration tests..."
	@./docker/fdb-integration-tests/test.sh

check: ## Run code quality checks (format, lint, audit)
	@echo "🔍 Running code quality checks..."
	@$(MAKE) format
	@$(MAKE) lint
	@$(MAKE) audit
	@echo "✅ All checks passed!"

format: ## Format code (Prettier, Taplo, markdownlint, rustfmt)
	@echo "📝 Formatting code..."
	@$(PRETTIER) --write "**/*.{md,yml,yaml,json}" --log-level warn || true
	@$(MARKDOWNLINT) --fix "**/*.md" || true
	@$(TAPLO) fmt || true
	@$(CARGO) +nightly fmt --all
	@echo "✅ Formatting complete!"

lint: ## Run linters (clippy, markdownlint)
	@echo "🔍 Running linters..."
	@$(MARKDOWNLINT) "**/*.md"
	@$(CARGO) clippy --workspace --all-targets --all-features -- -D warnings

audit: ## Run security audit
	@echo "🔒 Running security audit..."
	@$(CARGO) audit || echo "⚠️  cargo-audit not installed, skipping..."

deny: ## Check dependencies with cargo-deny
	@echo "🔍 Checking dependencies..."
	@$(CARGO) deny check || echo "⚠️  cargo-deny not installed, skipping..."

run: ## Run Control server (debug mode)
	@echo "🚀 Starting Control server..."
	@$(CARGO) run --bin inferadb-control

dev: ## Run with auto-reload (requires cargo-watch)
	@echo "🔄 Starting Control server with auto-reload..."
	@$(CARGO) watch -x 'run --bin inferadb-control'

build: ## Build debug binary
	@echo "🔨 Building debug binary..."
	@$(CARGO) build

release: ## Build optimized release binary
	@echo "🚀 Building release binary..."
	@$(CARGO) build --release

clean: ## Clean build artifacts
	@echo "🧹 Cleaning build artifacts..."
	@$(CARGO) clean

reset: ## Full reset (clean + remove target directory)
	@echo "⚠️  Performing full reset..."
	@$(CARGO) clean
	@rm -rf target
	@rm -rf Cargo.lock
	@echo "✅ Reset complete!"

doc: ## Generate and open documentation
	@echo "📚 Generating documentation..."
	@$(CARGO) doc --no-deps --open

coverage: ## Generate code coverage report
	@echo "📊 Generating coverage report..."
	@$(CARGO) tarpaulin --workspace --timeout 300 --out Html --output-dir target/coverage
	@echo "✅ Coverage report generated at target/coverage/index.html"

bench: ## Run benchmarks
	@echo "⚡ Running benchmarks..."
	@$(CARGO) bench

fix: ## Auto-fix clippy warnings
	@echo "🔧 Auto-fixing clippy warnings..."
	@$(CARGO) clippy --fix --allow-dirty --allow-staged

ci: ## Run CI checks (format, lint, test, audit)
	@echo "🤖 Running CI checks..."
	@$(MAKE) format
	@$(MAKE) lint
	@$(MAKE) test
	@$(MAKE) audit
	@echo "✅ CI checks passed!"
