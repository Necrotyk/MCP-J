# MCP-J: Secure MCP Agent Runtime

MCP-J is a hardened, secure runtime environment for executing untrusted [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) agents. It leverages modern Linux kernel isolation primitives to enforce strict boundaries between the agent and the host system, mitigating risks associated with executing potentially diverse AI-generated code or tools.

## Key Features

### 🛡️ Deep System Isolation
- **Filesystem Jail**: Uses `pivot_root` to completely detatch the agent from the host filesystem. The agent sees a constructed root with minimal necessary mounts (`/bin`, `/lib`, `/usr`, `/proc`).
- **Landlock LSM**: Adds a second layer of defense by restricting file access within the jail to a default-deny policy.
- **Namespace Isolation**: Runs agents in isolated namespaces (PID, Mount, IPC, UTS, Net, User) to prevent process visibility and unauthorized IPC.

### 🔐 Kernel-Level Hardening
- **Seccomp Syscall Interception**: Uses `SECCOMP_RET_USER_NOTIF` to intercept critical system calls (`openat`, `connect`, `execve`, `bind`) in user space.
- **TOCTOU Mitigation**: Secure file descriptor handling using `pidfd_open` and `pidfd_getfd` to prevent race conditions.
- **Strict Execve Control**: Implementation of `handle_execve` ensures only approved binaries within read-only, root-owned mount points can be executed.
- **Privilege Dropping**: The agent process drops all capabilities (`PR_CAPBSET_DROP`) and permanently switches to the unprivileged `nobody` user (UID 65534).

### 🌐 Network & Resource Control
- **Default-Deny Network Policy**: Outbound network access is strictly blocked by default.
    - **Allowlist**: Only `127.0.0.1` (localhost) is permitted for proxy communication.
    - **Blocklist**: All other IPv4/IPv6 traffic is denied, explicitly blocking cloud metadata services (e.g., AWS `169.254.169.254`).
- **Resource Constraints**: Cgroups v2 integration limits the agent to **512MB** of memory to prevent Denial-of-Service (DoS) via resource exhaustion.

### ⚡ Secure IPC Proxy
- **Memory Safety**: Enforces a strict **5MB** payload limit on JSON-RPC messages to prevent heap exhaustion.
- **Protocol Compliance**: A fully JSON-RPC 2.0 compliant proxy validates and sanitizes all messages between the host and method.
- **Error Handling**: Gracefully handles protocol violations with structured error responses, ensuring IDE stability.

## Project Structure

- **`mcp-j-engine`**: The core library implementing the sandboxing logic, seccomp notification loop, supervisor state machine, and Landlock rules.
- **`mcp-j-cli`**: The command-line entry point. It launches the supervisor, spawns the jailed process, and manages the secure IPC proxy.
- **`mcp-j-proxy`**: A strict JSON-RPC 2.0 proxy library that validates, parses, and sanitizes messages, enforcing security policies on tool calls.

## Architecture

1.  **Supervisor**: The `mcp-j-cli` starts the `Supervisor`, which sets up Cgroups and prepares the environment.
2.  **Jail Setup**:
    -   **Namespaces**: The process unshares User, Mount, PID, IPC, UTS, and Net namespaces.
    -   **Root Pivot**: A temporary root is created in `/tmp`, essential system directories are bind-mounted read-only, and `pivot_root` is executed.
    -   **Proc Mount**: A fresh `/proc` is mounted within the jail.
    -   **Privilege Drop**: Capabilities are dropped, and the process switches to UID `nobody`.
3.  **Seccomp Filter**: A BPF filter is installed to trap sensitive syscalls (`connect`, `execve`, `openat`).
4.  **Execution**: The supervisor intercepts syscalls via the Seccomp Notify user-space API.
    -   **Network**: Connect attempts are validated against the allowlist.
    -   **Filesystem**: Open attempts are checked against Landlock rules and path allowlists.
    -   **Execution**: Execve attempts are verified to ensure only safe binaries are run.

## Usage

To run a command inside the secure jail:

```bash
cargo run -p mcp-j-cli -- /path/to/mcp-server-binary [args]
```

Example:

```bash
cargo run -p mcp-j-cli -- /usr/bin/python3 -m my_mcp_server
```

## Requirements

- **Linux Kernel**: 5.13+ (for Landlock and Seccomp User Notification support).
- **Cgroups v2**: Enabled system-wide (standard on modern systemd distros).
- **Unprivileged User Namespaces**: Must be enabled (`kernel.unprivileged_userns_clone = 1` on some distros).

## Security Status

**Current Status**: 🛡️ **Hardened Beta** 🛡️

This project has undergone significant security hardening, including memory safety bounds, privilege dropping, and network egress filtering. However, as with any security-critical software, it should be reviewed and tested in your specific environment before deployment in high-assurance contexts.

## License

MIT / Apache-2.0
