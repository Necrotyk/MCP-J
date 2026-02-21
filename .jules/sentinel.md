## 2024-05-23 - Path Traversal in Regex Validation
**Vulnerability:** Path traversal (`..`) was possible despite regex validation `^[\w\-. /]+$`.
**Learning:** The regex character class `[\w\-. /]` includes `.` which allows `..` sequences. Regex validation for paths is tricky and should be supplemented with explicit logic checks (e.g. `contains("..")`). Also, blocking `..` is insufficient if absolute paths are allowed (e.g. `/etc/passwd`).
**Prevention:** Always combine regex allowlisting with negative checks for dangerous patterns (`..`) and absolute paths (`starts_with('/')`) when validating file paths.

## 2024-05-24 - Untrusted Search Path for System Binaries
**Vulnerability:** `Command::new("ip")` relied on `PATH` to locate the `ip` binary. If `PATH` is manipulated by an attacker, they could hijack the command execution, potentially leading to privilege escalation if the calling process has elevated privileges.
**Learning:** System binaries like `ip`, `mount`, `iptables` should always be invoked with absolute paths in security-sensitive contexts to avoid ambiguity and reliance on environment variables.
**Prevention:** Use absolute paths for system commands or sanitize `PATH` to a known safe list before execution. Implement helper functions to locate binaries securely.

## 2024-05-25 - Seccomp Rule Priority & Deadlock Prevention
**Vulnerability:** `sendmsg` was unconditionally allowed to prevent a deadlock during seccomp notification handover, creating a network security bypass. Attempts to fix this with mixed `Allow` (conditional) and `Notify` (unconditional) rules failed because `Notify` has higher priority than `Allow` in BPF/libseccomp.
**Learning:** In seccomp filters, if multiple rules match a syscall, the action with the highest priority wins. `Notify` > `Allow`. Mixing conditional `Allow` with general `Notify` results in `Notify` always winning, re-introducing the deadlock.
**Prevention:** Use a single conditional rule with the higher priority action (e.g., `Notify` if `fd != exempt_fd`) rather than multiple conflicting rules.

## 2024-05-27 - Execveat TOCTOU and Allowlist Bypass
**Vulnerability:** The `execveat` syscall handler allowed execution of any binary residing within a `readonly_mounts` path (e.g., `/bin`, `/usr/bin`). This bypassed the strict `execve` whitelist policy intended to block shells and unauthorized binaries.
**Learning:** Validating execution based solely on file location (e.g., "is in a read-only system mount") is insufficient security. It conflates "safe to read/map" with "safe to execute". An attacker can leverage `execveat` with a file descriptor to a standard shell (`/bin/sh`) located in a trusted mount to gain arbitrary code execution.
**Prevention:** Execution control logic must consistently enforce the same strict allowlist policy across all execution-related syscalls (`execve`, `execveat`). Do not assume that files in trusted/read-only locations are safe to execute unless explicitly whitelisted.
