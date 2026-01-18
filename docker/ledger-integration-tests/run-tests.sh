#!/usr/bin/env bash
# Run Control integration tests with a real Ledger cluster.
#
# Usage:
#   ./run-tests.sh          # Run all tests
#   ./run-tests.sh --clean  # Clean up after tests
#   ./run-tests.sh --shell  # Start test runner shell for debugging

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

COMPOSE_FILE="docker-compose.yml"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

CLEAN=0
SHELL_MODE=0
while [[ $# -gt 0 ]]; do
    case $1 in
        --clean) CLEAN=1; shift ;;
        --shell) SHELL_MODE=1; shift ;;
        *) log_error "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ $CLEAN -eq 1 ]]; then
    log_info "Cleaning up Control+Ledger integration test environment..."
    docker-compose -f "$COMPOSE_FILE" down -v --remove-orphans
    log_info "Cleanup complete"
    exit 0
fi

BUILD_ARGS=""
if [[ "${LEDGER_BUILD:-0}" == "1" ]]; then
    BUILD_ARGS="--build"
fi

log_info "Starting Ledger server..."
docker-compose -f "$COMPOSE_FILE" up -d $BUILD_ARGS ledger

log_info "Waiting for Ledger to be ready..."
RETRIES=30
while [[ $RETRIES -gt 0 ]]; do
    if docker-compose -f "$COMPOSE_FILE" exec -T ledger nc -z localhost 50051 2>/dev/null; then
        log_info "Ledger is ready!"
        break
    fi
    ((RETRIES--))
    sleep 2
done

if [[ $RETRIES -eq 0 ]]; then
    log_error "Ledger failed to start within timeout"
    docker-compose -f "$COMPOSE_FILE" logs ledger
    docker-compose -f "$COMPOSE_FILE" down
    exit 1
fi

if [[ $SHELL_MODE -eq 1 ]]; then
    log_info "Starting test runner shell..."
    docker-compose -f "$COMPOSE_FILE" run --rm test-runner /bin/bash
    exit_code=$?
else
    log_info "Running Control+Ledger integration tests..."
    docker-compose -f "$COMPOSE_FILE" run --rm test-runner
    exit_code=$?
fi

if [[ "${KEEP_RUNNING:-0}" != "1" ]]; then
    log_info "Stopping Ledger..."
    docker-compose -f "$COMPOSE_FILE" down
fi

if [[ $exit_code -eq 0 ]]; then
    log_info "All integration tests passed!"
else
    log_error "Integration tests failed with exit code $exit_code"
fi

exit $exit_code
