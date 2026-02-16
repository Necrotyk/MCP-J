#!/bin/bash
set -eo pipefail

echo "[*] Compiling malicious payload suite (static musl)..."
cargo build --release --target x86_64-unknown-linux-musl --bin malicious_agent --manifest-path tests/e2e/Cargo.toml

TARGET_BIN="tests/e2e/target/x86_64-unknown-linux-musl/release/malicious_agent"

echo "[*] Initializing MCP-J Engine E2E Simulation..."
echo "=================================================="
echo "      PROTOCOL ZERO / OPERATIONAL LOGIC ENV       "
echo "=================================================="

# Execute the supervisor and pipe stderr (telemetry) to jq for hyper-visual demonstration tracking
# Build the CLI first to avoid cargo output pollution
cargo build -p mcp-j-cli

# Path to the CLI binary (adjust based on profile)
CLI_BIN="./target/debug/mcp-j-cli"

# Execute
$CLI_BIN --manifest profiles/python.json $TARGET_BIN 2>&1 | grep "^{" | jq -C '.'

