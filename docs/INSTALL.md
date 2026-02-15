# Installation Guide

## System Requirements

MCP-J relies on modern Linux kernel features for isolation. Please ensure your system meets the following requirements:

- **Operating System**: Linux (Kernel 5.13+ recommended for full Landlock support).
- **Architecture**: x86_64 or aarch64 (ARM64).
- **Dependencies**:
  - `musl-tools` (for building from source).
  - Unprivileged User Namespaces enabled (`kernel.unprivileged_userns_clone = 1`).
  - Cgroups v2 unified hierarchy enabled (standard on modern systemd distros).

## Installing the CLI

### Option 1: Pre-built Binary (Recommended)

1.  Download the latest release from the [GitHub Releases](https://github.com/Necrotyk/MCP-J/releases) page.
2.  Extract the binary:
    ```bash
    tar -xzf mcp-j-cli-x86_64-unknown-linux-musl.tar.gz
    ```
3.  Move it to your `$PATH`:
    ```bash
    sudo mv mcp-j-cli /usr/local/bin/
    sudo chmod +x /usr/local/bin/mcp-j-cli
    ```
4.  Verify installation:
    ```bash
    mcp-j-cli --version
    ```

### Option 2: Build from Source

1.  Clone the repository:
    ```bash
    git clone https://github.com/Necrotyk/MCP-J.git
    cd MCP-J
    ```
2.  Install Rust toolchain (if not already installed):
    ```bash
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    ```
3.  Build and install:
    ```bash
    cargo install --path mcp-j-cli
    ```

## Installing the VSCode Extension

1.  Download the `.vsix` file from the [Releases](https://github.com/Necrotyk/MCP-J/releases) page.
2.  In VSCode:
    - Press `Ctrl+Shift+P`.
    - Type "Install from VSIX..." and select the command.
    - Choose the downloaded `.vsix` file.
3.  Alternatively, install via CLI:
    ```bash
    code --install-extension vscode-mcp-j.vsix
    ```

## Verify Installation

To check if the sandbox is working correctly, try running a simple command:

```bash
mcp-j-cli -- /bin/echo "Hello from the sandbox!"
```
If successful, you will see the output. Check logs if explicit permission errors occur.
