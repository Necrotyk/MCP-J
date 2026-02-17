## 2024-05-23 - Path Traversal in Regex Validation
**Vulnerability:** Path traversal (`..`) was possible despite regex validation `^[\w\-. /]+$`.
**Learning:** The regex character class `[\w\-. /]` includes `.` which allows `..` sequences. Regex validation for paths is tricky and should be supplemented with explicit logic checks (e.g. `contains("..")`). Also, blocking `..` is insufficient if absolute paths are allowed (e.g. `/etc/passwd`).
**Prevention:** Always combine regex allowlisting with negative checks for dangerous patterns (`..`) and absolute paths (`starts_with('/')`) when validating file paths.
