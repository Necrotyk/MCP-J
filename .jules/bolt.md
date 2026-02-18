# Bolt's Journal

## 2024-05-22 - Initial Setup
**Learning:** The project is a Rust workspace with `mcp-j-engine`, `mcp-j-cli`, and `mcp-j-proxy`. The release profile is currently optimized for size (`z`).
**Action:** Explore the codebase for performance bottlenecks.

## 2024-05-22 - Zero-Copy Deserialization
**Learning:** Deep cloning `serde_json::Value` for large payloads (up to 10MB) in `mcp-j-proxy` was a significant performance bottleneck.
**Action:** Replaced `raw.clone()` with a move into `serde_json::from_value(raw)`, reducing allocation overhead by ~5% on 5MB payloads and eliminating a large memcpy.

## 2024-05-23 - Repeated Regex Compilation in Proxy
**Learning:** `mcp-j-proxy` was recompiling a regex on every `validate_tool_schema` call (e.g., `read_file`), causing ~100x overhead (8.4ms vs 0.05ms per call).
**Action:** Use `std::sync::OnceLock` for all regexes in hot paths to ensure one-time compilation.
