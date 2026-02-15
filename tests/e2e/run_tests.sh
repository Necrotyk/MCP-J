#!/bin/bash
set -e

# Compile malicious payload
rustc tests/e2e/malicious_agent.rs -o tests/e2e/malicious_agent

# Run against mcp-j-cli
echo ">>> Running Escape Regression Test"
cargo run -p mcp-j-cli -- --manifest profiles/python.json tests/e2e/malicious_agent
