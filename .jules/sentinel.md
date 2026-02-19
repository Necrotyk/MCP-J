## 2024-05-23 - Path Traversal in Regex Validation
**Vulnerability:** Path traversal (`..`) was possible despite regex validation `^[\w\-. /]+$`.
**Learning:** The regex character class `[\w\-. /]` includes `.` which allows `..` sequences. Regex validation for paths is tricky and should be supplemented with explicit logic checks (e.g. `contains("..")`). Also, blocking `..` is insufficient if absolute paths are allowed (e.g. `/etc/passwd`).
**Prevention:** Always combine regex allowlisting with negative checks for dangerous patterns (`..`) and absolute paths (`starts_with('/')`) when validating file paths.

## 2024-05-24 - Untrusted Search Path for System Binaries
**Vulnerability:** `Command::new("ip")` relied on `PATH` to locate the `ip` binary. If `PATH` is manipulated by an attacker, they could hijack the command execution, potentially leading to privilege escalation if the calling process has elevated privileges.
**Learning:** System binaries like `ip`, `mount`, `iptables` should always be invoked with absolute paths in security-sensitive contexts to avoid ambiguity and reliance on environment variables.
**Prevention:** Use absolute paths for system commands or sanitize `PATH` to a known safe list before execution. Implement helper functions to locate binaries securely.
