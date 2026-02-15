# MCP-J VSCode Client

A secure, sandboxed runtime for execute Model Context Protocol (MCP) agents within Visual Studio Code. This extension manages the lifecycle of `mcp-j-cli` and provides a seamless development experience for MCP agents.

## Features

- **Secure Execution**: Runs agents in isolated Linux namespaces (Process, Network, User, Filesystem).
- **Resource Control**: Limits memory and CPU usage per agent.
- **Network Policy**: Strict allowlist-based network access.
- **Integrated Terminal**: View agent logs and output directly in VSCode.

## Requirements

- **Linux**: This extension requires a Linux environment (WSL2 also supported) due to reliance on namespaces/cgroups.
- **`mcp-j-cli`**: The binary must be available in your path or bundled with the extension.
- **VSCode**: 1.85.0 or newer.

## Installation

### From VSIX

1.  Download the latest `.vsix` release from the [GitHub Releases](https://github.com/Necrotyk/MCP-J/releases) page.
2.  In VSCode, run `Extensions: Install from VSIX...`.
3.  Select the downloaded file.

### For Development

1.  Clone the repository:
    ```bash
    git clone https://github.com/Necrotyk/MCP-J.git
    cd MCP-J/clients/vscode-mcp-j
    ```
2.  Install dependencies:
    ```bash
    npm install
    ```
3.  Open the folder in VSCode.
4.  Press `F5` to start debugging. This will launch a new VSCode window with the extension loaded.

## Configuration

You can configure the runtime behavior in your `settings.json`:

```json
{
  "mcp-j.runtime.memoryLimit": 512, // MB (default: 512)
  "mcp-j.runtime.cpuQuota": 100, // Percentage (default: 100)
  "mcp-j.network.allowList": [
    "1.1.1.1", // Cloudflare DNS
    "8.8.8.8"  // Google DNS
  ]
}
```

## Troubleshooting

### "Extension activation failed"

- Ensure you are running on Linux.
- Check the "Output" panel and select "MCP-J Runtime" from the dropdown.
- Verify `mcp-j-cli` binary permissions (execution bit).

### "Permission Denied" in Sandbox

- The sandbox uses unprivileged user namespaces. Ensure your kernel supports `CLONE_NEWUSER`.
- Check if `kernel.unprivileged_userns_clone` sysctl is set to 1.
