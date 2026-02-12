# MCP-J Threat Model

## 1. Remediation of CVE-2025-6514 (RCE via OAuth URLs)

### Threat Description
CVE-2025-6514 is a critical Remote Code Execution (RCE) vulnerability in the `mcp-remote` project. It allows attackers to execute arbitrary commands by injecting malicious authorization URLs (specifically using PowerShell subexpressions `$(...)` or other shell injection techniques) into the OAuth flow.

### Remediation Strategy
MCP-J addresses this vulnerability through a multi-layered defense:

1.  **Strict Input Validation (Proxy Layer):**
    - The `mcp-j-proxy` intercepts all JSON-RPC 2.0 messages.
    - It parses and validates all string arguments, specifically looking for shell metacharacters and suspicious URL schemes.
    - Any payload resembling a command injection attempt is rejected before it reaches the MCP server.

2.  **Network Egress Filtering (Seccomp/Landlock Layer):**
    - Even if an injection bypasses the proxy, the jailed process is restricted from making unauthorized network connections.
    - `seccomp_unotify` intercepts `connect()` syscalls.
    - The supervisor validates the destination IP/Port against a strict allow-list (e.g., `api.anthropic.com`, `github.com`).
    - Connections to arbitrary C2 servers are blocked at the kernel level.

3.  **Process Execution Restrictions:**
    - The `execve` syscall is intercepted and restricted.
    - The jailed process can only execute binaries within the project's virtual environment or a pre-approved toolchain.
    - Execution of system shells (e.g., `/bin/sh`, `powershell.exe`) is denied unless explicitly authorized for a specific tool.

## 2. Ambient Authority Risks (IDE Exploitation)

### Threat Description
AI-Native IDEs (e.g., Cursor, Google Antigravity) often grant "Confused Deputy" agents full system permissions. These agents operate with the user's ambient authority, meaning they can access any file or resource the user can access. A compromised agent (via prompt injection) can exploit this to read sensitive files (`~/.ssh`, `~/.env`) or modify system configurations.

### Remediation Strategy
MCP-J enforces Least-Privilege Enforcement (LPE) by stripping ambient authority:

1.  **Filesystem Isolation (Landlock LSM):**
    - The agent is confined to the project root directory.
    - Access to sensitive directories (`~/.ssh`, `~/.aws`, `~/.env`) is denied by default at the kernel level.
    - `LANDLOCK_ACCESS_FS_READ_FILE` and `LANDLOCK_ACCESS_FS_WRITE_FILE` are restricted to the project scope and essential libraries.

2.  **User Namespaces:**
    - The MCP server is spawned in a new User Namespace (`CLONE_NEWUSER`).
    - Inside the namespace, the agent may appear as root (uid 0), but outside it maps to an unprivileged user (nobody/nogroup) or a specific low-privileged UID.
    - This prevents the agent from escalating privileges or affecting the host system even if it escapes the chroot/sandbox.

3.  **Atomic Path Resolution (TOCTOU Mitigation):**
    - All filesystem operations use `openat2` with `RESOLVE_BENEATH`.
    - This prevents symlink attacks where an attacker swaps a safe path with a symlink to a sensitive file between check and use.
    - File descriptors are opened by the supervisor and injected into the agent process using `SECCOMP_ADDFD_FLAG_SEND`, ensuring the agent never handles the raw path.

## 3. Threat Matrix

| Threat | Impact | Mitigation |
| :--- | :--- | :--- |
| **CVE-2025-6514 (RCE)** | Critical | Input Validation, Network Egress Filtering, Execve Restrictions |
| **Ambient Authority** | High | Landlock Filesystem Isolation, User Namespaces |
| **TOCTOU / Symlink Attacks** | High | `openat2` with `RESOLVE_BENEATH`, FD Injection |
| **Memory Exhaustion** | Medium | Resource Limits (cgroups), Fixed-size Buffers |
| **Prompt Injection** | High | Intent-Aware Auditing, Human-in-the-Loop (Future) |
