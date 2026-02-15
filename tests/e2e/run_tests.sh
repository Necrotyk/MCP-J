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
cargo run -p mcp-j-cli -- --manifest profiles/python.json $TARGET_BIN 2>&1 | jq -C '.'
