# MCP-J: Secure MCP Agent Runtime

MCP-J is a secure, sandboxed runtime environment for executing untrusted [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) agents. It leverages modern Linux kernel isolation primitives to enforce strict boundaries between the agent and the host system, mitigating risks associated with executing potentially diverse AI-generated code or tools.

## Key Features

- **Landlock LSM**: Restricts filesystem access to a strictly defined set of directories (e.g., project root only), enforcing a default-deny policy.
- **Seccomp Syscall Interception**: Uses `SECCOMP_RET_USER_NOTIF` to intercept critical system calls (like `openat`, `connect`, `execve`) in user space without the performance overhead of `ptrace`.
- **TOCTOU Mitigation**: Implements atomic filesystem operations using `openat2` with `RESOLVE_BENEATH` and file descriptor injection (`SECCOMP_IOCTL_NOTIF_ADDFD`), ensuring that path checks cannot be bypassed via race conditions or symlink attacks.
- **Namespace Isolation**: Runs agents in isolated namespaces (PID, Mount, IPC, UTS, Net) to prevent process visibility and unauthorized IPC.
- **Supervisor-Child Architecture**: The runtime operates as a privileged supervisor that spawns and manages the unprivileged agent process.

## Project Structure

- **`mcp-j-engine`**: The core library implementing the sandboxing logic, seccomp notification loop, and supervisor state machine.
- **`mcp-j-cli`**: A command-line interface for launching jailed MCP servers.
- **`mcp-j-proxy`**: (Planned) A proxy to sanitize JSON-RPC messages between the host and the jailed agent.

## Architecture

1.  **Supervisor**: The `mcp-j-cli` starts the `Supervisor`, which sets up a Landlock ruleset and prepares the environment.
2.  **Fork & Isolate**: The supervisor forks a child process.
    -   **Child**: Unshares namespaces, installs a Seccomp filter that notifies the parent on specific syscalls, and then `exec`s the target MCP server binary.
    -   **Parent**: Listens for Seccomp notifications on a file descriptor received from the child via a Unix Domain Socket.
3.  **Syscall Handling**: When the agent attempts a sensitive operation (e.g., `open("/etc/passwd")`), the kernel pauses the agent and notifies the supervisor.
    -   The supervisor inspects the request.
    -   If allowed, it performs the action safely (e.g., `openat2` on the host side).
    -   The result (e.g., a file descriptor) is injected directly into the agent's process.

## Usage

To run a command inside the jail:

```bash
cargo run -p mcp-j-cli -- /path/to/mcp-server-binary [args]
```

Example:

```bash
cargo run -p mcp-j-cli -- /usr/bin/python3 -m my_mcp_server
```

## Security Status

**Current Status**: 🚧 Alpha / Work In Progress 🚧

This project is currently under active development. While the core isolation mechanisms (Landlock, Seccomp) are being implemented, it should not yet be relied upon for critical production security boundaries without thorough review.

## License

MIT / Apache-2.0
