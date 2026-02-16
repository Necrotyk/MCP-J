#!/bin/bash

# Reset the local MCP-J configuration to force re-onboarding
ROOT_DIR=$(dirname "$0")/../../..
PROFILE_DIR="$ROOT_DIR/.mcp-j/profiles"

if [ -d "$PROFILE_DIR" ]; then
    echo "[MCP-J] Removing profile directory: $PROFILE_DIR"
    rm -rf "$PROFILE_DIR"
else
    echo "[MCP-J] Profile directory not found, nothing to do."
fi

echo "[MCP-J] Configuration reset complete. Reload VS Code window to trigger auto-configure."
