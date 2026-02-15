# Troubleshooting Guide

This guide addresses common issues encountered when setting up or running MCP-J.

## Common Errors

### Permission Denied (Sandboxing)

**Symptom:**
```
Failed to create user namespace: Permission denied (os error 13)
```
or
```
Failed to write to /proc/self/gid_map: Permission denied
```

**Cause:**
Your kernel likely restricts unprivileged user namespaces.

**Solution:**
Enable unprivileged user namespaces temporarily:
```bash
sudo sysctl -w kernel.unprivileged_userns_clone=1
```
To persist this change, add `kernel.unprivileged_userns_clone = 1` to `/etc/sysctl.d/99-userns.conf`.

### Seccomp Filter Installation Failed

**Symptom:**
```
Failed to load seccomp filter: Operation not permitted
```

**Cause:**
The process lacks the necessary capabilities (`CAP_SYS_ADMIN` inside the namespace is insufficient if `NO_NEW_PRIVS` is not set or conflicting). Alternatively, your kernel might not support `SECCOMP_RET_USER_NOTIF`.

**Solution:**
Ensure your kernel version is >= 5.0. Check if `CONFIG_SECCOMP_USER_NOTIFICATION` is enabled in your kernel configuration:
```bash
grep CONFIG_SECCOMP_USER_NOTIFICATION /boot/config-$(uname -r)
```

### Landlock ABI Version Warning

**Symptom:**
```
WARN mcp_j_engine::landlock: Landlock ABI version 1 detected. Some features may be unavailable.
```

**Cause:**
You are running on an older kernel (e.g., 5.13-5.18).

**Solution:**
Upgrade your kernel to >= 5.19 for full Landlock ABI v2+ support (e.g., directory reparenting protection).

### VSCode Extension Activation Failed

**Symptom:**
VSCode shows "Extension activation failed" notification.

**Cause:**
The extension failed to spawn the `mcp-j-cli` process or the binary is missing.

**Solution:**
1.  Check VSCode "Output" panel -> "MCP-J Runtime".
2.  Verify `mcp-j-cli` is in your `$PATH` or configured in settings.
3.  Ensure the binary has execution permissions (`chmod +x`).

### Connection Refused (Network)

**Symptom:**
The agent fails to connect to an external service.

**Cause:**
Default deny network policy blocks strictly all outbound traffic not in the allowlist.

**Solution:**
Add the destination IP/Port to the `--allow-net` flag or your `manifest.json`.
```bash
mcp-j-cli --allow-net "api.example.com:443" -- ...
```

## Debugging

To enable verbose logging, set the `RUST_LOG` environment variable:

```bash
RUST_LOG=debug mcp-j-cli -- /bin/bash
```

This will print detailed trace logs to stderr, including every intercepted syscall and policy decision.
