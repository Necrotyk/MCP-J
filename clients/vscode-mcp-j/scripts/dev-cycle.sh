#!/bin/bash
set -e

# Project Root (3 levels up from scripts/)
ROOT_DIR=$(dirname "$0")/../../..
CLIENT_DIR=$(dirname "$0")/..

echo "[MCP-J] Building Rust CLI (Release)..."
cd "$ROOT_DIR"
cargo build --package mcp-j-cli --release

echo "[MCP-J] Copying binary to extension..."
mkdir -p "$CLIENT_DIR/bin"
cp "target/release/mcp-j-cli" "$CLIENT_DIR/bin/"

echo "[MCP-J] compiling extension..."
cd "$CLIENT_DIR"
npm install
npm run compile

echo "[MCP-J] Packaging extension..."
# Use npx to run vsce from local or fetch it
npx vsce package --no-dependencies

VSIX_FILE=$(ls *.vsix | head -n 1)

if [ -z "$VSIX_FILE" ]; then
    echo "Error: VSIX not found!"
    exit 1
fi

echo "[MCP-J] Reinstalling extension..."
# Try to uninstall first
code --uninstall-extension dystopi-research.vscode-mcp-j || true

# Install new version
code --install-extension "$VSIX_FILE" --force

echo "[MCP-J] Done! Reload VS Code window to apply changes."
