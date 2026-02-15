# Configuration Guide

## JSON Manifest Configuration

You can configure the sandbox environment using a JSON manifest file via the `--manifest` flag.

### Usage
```bash
mcp-j-cli --manifest sandbox_config.json -- /usr/bin/python3 app.py
```

### Schema

```json
{
  "max_memory_mb": 1024,
  "allowed_egress_ips": [
    "127.0.0.1",
    "10.0.0.5"
  ],
  "readonly_mounts": [
    "/bin",
    "/usr/bin",
    "/lib",
    "/lib64",
    "/usr/lib",
    "/opt/my-libs"
  ],
  "env_vars": {
    "RUST_LOG": "info",
    "MY_API_KEY": "secret"
  },
  "max_cpu_quota_pct": 50
}
```

## Logging & Telemetry

The runtime emits high-fidelity, structured JSON logs via `tracing`.

### Log Structure

Each log entry contains:
- `timestamp`: ISO 8601 timestamp.
- `level`: Log level (INFO, WARN, ERROR).
- `message`: Human-readable event description.
- `target`: The Rust module source.
- Contextual fields: `pid`, `path`, `dst_ip`, `error`, etc.

### Example (Blocked Connection)

```json
{
  "timestamp": "2024-02-14T21:00:00.000Z",
  "level": "WARN",
  "message": "Blocked outbound connection to IPv4",
  "target": "mcp_j_engine::seccomp_loop",
  "pid": 1234,
  "dst_ip": "192.168.1.1"
}
```

### Stderr Multiplexing

Standard error from the jailed process is captured and wrapped in structured JSON logs with `source="tracee_stderr"`. This preserves observability without corrupting the parent IDE's JSON parser.
