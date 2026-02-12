# MCP-J Isolation Specification

## 1. Security Boundary

The isolation boundary between the **Host** (untrusted user environment) and the **Jailed Process** (untrusted AI agent) is strictly enforced by the Linux kernel using Landlock LSM, seccomp-bpf, and User Namespaces.

### 1.1 Host <-> Jailed Process Communication

All communication between the Host (IDE, CLI) and the Jailed Process (MCP server) occurs strictly over standard input/output (stdio) or Unix Domain Sockets, which are managed by the `mcp-j-engine`.

- **Host:** Can invoke `mcp-j-cli` to start a jailed MCP server.
- **mcp-j-engine (Supervisor):** Acts as the parent process. It sets up the sandbox (Landlock ruleset, seccomp filters, namespaces) and then `execve`s the MCP server binary.
- **Jailed Process (MCP Server):** Runs with minimal privileges. Can only perform actions permitted by the Landlock ruleset and seccomp filters.

## 2. Syscall Interception Flow (seccomp_unotify)

To ensure low latency for high-frequency JSON-RPC tool calls, `seccomp_unotify` is used instead of ptrace. This mechanism allows the supervisor (mcp-j-engine) to intercept specific syscalls without stopping the entire process for every syscall.

### 2.1 Intercepted Syscalls

The following syscalls are intercepted and handled by the supervisor:

| Syscall | Action | Rationale |
| :--- | :--- | :--- |
| `connect(2)` | **Intercept** | Validate destination IP/Port against allow-list. Block arbitrary outbound connections. |
| `execve(2)` | **Intercept** | Restrict execution to allowed binaries only. Prevent shell spawning unless authorized. |
| `bind(2)` | **Intercept** | Prevent binding to privileged ports or unauthorized interfaces. |
| `socket(2)` | **Allow (Conditional)** | Allow only specific socket families (e.g., AF_UNIX, AF_INET) required for legitimate operation. |
| `openat(2)` / `open(2)` | **Intercept/Redirect** | See Section 3 (Filesystem Atomic Operations). |

### 2.2 Notification Handling Flow

1.  **Agent attempts syscall:** The jailed process executes a restricted syscall (e.g., `connect`).
2.  **Kernel trap:** The kernel pauses the thread and sends a `SECCOMP_RET_USER_NOTIF` to the supervisor's notification file descriptor.
3.  **Supervisor inspects:** The `mcp-j-engine` reads the notification, inspects the syscall arguments (e.g., destination address), and validates against the policy.
4.  **Verdict:**
    - **Allow:** The supervisor writes `SECCOMP_USER_NOTIF_FLAG_CONTINUE` to the notification FD. The kernel allows the syscall to proceed.
    - **Deny:** The supervisor writes an error code (e.g., `EPERM`, `EACCES`) to the notification FD. The kernel returns this error to the jailed process.
    - **Emulate:** The supervisor performs the action on behalf of the agent (e.g., opening a file) and injects the result (e.g., a file descriptor) using `SECCOMP_ADDFD_FLAG_SEND`.

## 3. Filesystem Atomic Operations (TOCTOU Mitigation)

To eliminate Time-of-Check to Time-of-Use (TOCTOU) vulnerabilities, all filesystem operations must be atomic and race-free.

### 3.1 `openat2` with `RESOLVE_BENEATH`

All file opens performed by the supervisor on behalf of the agent (or allowed by Landlock) must use the `openat2` syscall with the `RESOLVE_BENEATH` flag.

- **Objective:** Prevent symlink attacks where a path component is swapped with a symlink to a sensitive location (e.g., `/etc/passwd`) between check and use.
- **Mechanism:** `RESOLVE_BENEATH` ensures that the path resolution never traverses outside the directory tree rooted at the `dirfd` provided to `openat2`. If a path attempts to escape (e.g., `../`, absolute symlink), the syscall fails with `EXDEV` or `ELOOP`.

### 3.2 File Descriptor Injection

For sensitive file access where the agent should not handle the path directly:

1.  **Agent requests file:** The agent attempts `open("/path/to/file")`.
2.  **Intercept:** `seccomp_unotify` catches the `open` call.
3.  **Supervisor resolves:** The supervisor resolves the path safely using `openat2` relative to the project root.
4.  **Validation:** The supervisor checks if the resolved file is allowed by policy.
5.  **Inject FD:** If allowed, the supervisor opens the file and injects the file descriptor into the agent's process using `ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_ADDFD, ...)`.
6.  **Return:** The supervisor returns the injected FD number to the agent as the result of the `open` call.

This ensures the agent never operates on raw paths that could be manipulated, only on validated file descriptors.

## 4. Landlock Ruleset Specification

The Landlock ruleset defines the filesystem view for the jailed process.

- **Default Policy:** Deny all access.
- **Allowed Paths:**
    - Project Root: Read/Write (configurable).
    - `/lib`, `/usr/lib`, `/bin` (system libraries/binaries): Read-Execute only.
    - `/tmp` (scoped): Read/Write (private temp directory recommended).
- **Explicitly Denied:**
    - `~/.ssh`
    - `~/.aws`
    - `~/.env`
    - `/etc/shadow`, `/etc/passwd` (unless necessary for user mapping, usually avoided by user namespaces).
