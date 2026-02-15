# Contributing to MCP-J

We welcome contributions to MCP-J! This document provides guidelines for setting up your development environment and submitting contributions.

## Development Environment Setup

### Prerequisites

- **Rust**: Latest stable version.
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```
- **Node.js**: Version 20+ (for VSCode extension).
  ```bash
  # Example using nvm
  nvm install 20
  ```
- **Musl Tools**: Required for cross-compilation and static linking.
  ```bash
  # Ubuntu/Debian
  sudo apt-get install musl-tools
  ```

### Building the Project

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/Necrotyk/MCP-J.git
    cd MCP-J
    ```

2.  **Build the Rust core:**
    ```bash
    cargo build
    ```

3.  **Run Tests:**
    ```bash
    cargo test
    ```

### VSCode Client Development

The VSCode extension is located in `clients/vscode-mcp-j`.

1.  **Install dependencies:**
    ```bash
    cd clients/vscode-mcp-j
    npm install
    ```

2.  **Build/Watch:**
    Open the project in VSCode. Press `F5` to launch the Extension Development Host.

## Project Structure

- **`mcp-j-engine`**: Core library for sandboxing and isolation logic.
- **`mcp-j-cli`**: Command-line interface and supervisor process.
- **`mcp-j-proxy`**: JSON-RPC message validation and proxying.
- **`clients/vscode-mcp-j`**: Visual Studio Code extension.

## Pull Request Guidelines

1.  **Descriptive Title**: Use a clear and descriptive title for your PR.
2.  **Pass Tests**: Ensure all tests pass (`cargo test`) before submitting.
3.  **Linting**: Run `cargo clippy` and ensure there are no warnings.
4.  **Formatting**: Run `cargo fmt` to verify code formatting.

## Release Process

Releases are automated via GitHub Actions when a tag starting with `v` is pushed (e.g., `v0.1.0`).
