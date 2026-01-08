#!/bin/bash
# Code Coverage Script for InferaDB Control Plane
# Generates code coverage reports using cargo-llvm-cov
#
# Usage:
#   ./scripts/coverage.sh           # HTML report
#   ./scripts/coverage.sh ci        # CI mode (lcov)
#   ./scripts/coverage.sh clean     # Clean coverage data

set -e

cd "$(dirname "$0")/.."

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0;0m' # No Color

echo -e "${BLUE}=== InferaDB Control Plane Code Coverage ===${NC}"
echo ""

# Check if llvm-cov is installed
if ! command -v cargo-llvm-cov &> /dev/null; then
    echo -e "${YELLOW}cargo-llvm-cov not found. Installing...${NC}"
    cargo install cargo-llvm-cov
    echo ""
fi

# Determine mode
MODE="${1:-html}"

case "$MODE" in
    clean)
        echo -e "${YELLOW}Cleaning coverage data...${NC}"
        cargo llvm-cov clean --workspace
        rm -rf target/llvm-cov
        rm -f lcov.info
        echo -e "${GREEN}✓ Coverage data cleaned${NC}"
        exit 0
        ;;

    ci)
        echo -e "${YELLOW}Running coverage in CI mode...${NC}"
        cargo llvm-cov \
            --workspace \
            --lcov \
            --output-path lcov.info
        ;;

    json)
        echo -e "${YELLOW}Running coverage with JSON output...${NC}"
        cargo llvm-cov \
            --workspace \
            --json \
            --output-path coverage.json
        ;;

    html|*)
        echo -e "${YELLOW}Running coverage with HTML output...${NC}"
        cargo llvm-cov \
            --workspace \
            --html
        ;;
esac

EXIT_CODE=$?

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✓ Coverage generation complete${NC}"

    # Show coverage summary if available
    if [ -d "target/llvm-cov/html" ]; then
        echo ""
        echo -e "${BLUE}HTML Report: file://$(pwd)/target/llvm-cov/html/index.html${NC}"
    fi

    if [ -f "lcov.info" ]; then
        echo -e "${BLUE}LCOV Report: lcov.info${NC}"
    fi

    if [ -f "coverage.json" ]; then
        echo -e "${BLUE}JSON Report: coverage.json${NC}"
    fi

    # Try to open HTML report if in interactive mode
    if [ "$MODE" = "html" ] && [ -d "target/llvm-cov/html" ]; then
        if command -v open &> /dev/null; then
            echo ""
            echo -e "${YELLOW}Opening HTML report...${NC}"
            open "target/llvm-cov/html/index.html"
        elif command -v xdg-open &> /dev/null; then
            echo ""
            echo -e "${YELLOW}Opening HTML report...${NC}"
            xdg-open "target/llvm-cov/html/index.html"
        fi
    fi
else
    echo -e "${RED}✗ Coverage generation failed${NC}"
fi

exit $EXIT_CODE
