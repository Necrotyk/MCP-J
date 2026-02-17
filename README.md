[Under construction]

# MCP-J: Secure MCP Agent Runtime

MCP-J is a hardened, secure runtime environment for executing untrusted [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) agents. It leverages modern Linux kernel isolation primitives to enforce strict boundaries between the agent and the host system, mitigating risks associated with executing potentially diverse AI-generated code or tools.

## 🚀 Key Features

- **Deep Isolation**: Filesystem Jail (`pivot_root`), Landlock LSM, and Namespace Isolation (PID, Net, IPC, User).
- **Kernel Hardening**: Seccomp Syscall Interception (`connect`, `execve`, `openat`) in user space.
- **Network Control**: Default-deny network policy with strict allowlisting.
- **Resource Limits**: Cgroups v2 for memory and CPU quotas.
- **Secure IPC**: Strict JSON-RPC 2.0 proxy with message framing and validation.
- **Structured Logs**: High-fidelity JSON logs for SIEM integration.

## 📚 Documentation

- [**Installation Guide**](docs/INSTALL.md) - How to install the CLI and VSCode extension.
- [**Configuration Guide**](docs/CONFIGURATION.md) - Manifest schema, environment variables, and logging.
- [**Architecture Overview**](docs/ARCHITECTURE.md) - Deep dive into supervisor, jail, and seccomp internals.
- [**Troubleshooting**](docs/TROUBLESHOOTING.md) - Common errors and solutions.
- [**Contributing**](CONTRIBUTING.md) - Development setup and guidelines.

## ⚡ Quick Start

### Run a Sanboxed Command
```bash
# Run python3 inside the jail with default settings
mcp-j-cli -- /usr/bin/python3 -c "print('Hello from the sandbox!')"
```

### With Configuration
```bash
# Use a manifest for custom net/fs policies
mcp-j-cli --manifest config.json -- /usr/bin/node app.js
```

## 🧩 VSCode Extension

The official VSCode extension provides a seamless integration with the MCP-J runtime.

- **Marketplace**: (Coming Soon)
- **Manual Install**: Download `.vsix` from [Releases](https://github.com/Necrotyk/MCP-J/releases).
- [**Client Documentation**](clients/vscode-mcp-j/README.md)

## 🛠️ Project Structure

- **`mcp-j-engine`**: Core library sandboxing logic (namespaces, landlock, seccomp).
- **`mcp-j-cli`**: Command-line supervisor and IPC proxy manager.
- **`mcp-j-proxy`**: JSON-RPC message validation and framing.
- **`clients/vscode-mcp-j`**: Visual Studio Code extension.

## ⚠️ Requirements

- **Linux Kernel 5.13+**: For Landlock and Seccomp User Notification support.
- **Unprivileged User Namespaces**: `kernel.unprivileged_userns_clone = 1`.
- **Cgroups v2**: Enabled system-wide.

## Security Status

**Current Status**: 🛡️ **Hardened Beta** 🛡️ [Currently may be broken will update when sorted out]

This project has undergone significant security hardening. However, it should be reviewed and tested in your specific environment before deployment in high-assurance contexts.

## License

MIT / Apache-2.0
