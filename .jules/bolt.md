# Bolt's Journal

## 2024-05-22 - Initial Setup
**Learning:** The project is a Rust workspace with `mcp-j-engine`, `mcp-j-cli`, and `mcp-j-proxy`. The release profile is currently optimized for size (`z`).
**Action:** Explore the codebase for performance bottlenecks.

## 2024-05-22 - Zero-Copy Deserialization
**Learning:** Deep cloning `serde_json::Value` for large payloads (up to 10MB) in `mcp-j-proxy` was a significant performance bottleneck.
**Action:** Replaced `raw.clone()` with a move into `serde_json::from_value(raw)`, reducing allocation overhead by ~5% on 5MB payloads and eliminating a large memcpy.

## 2024-05-23 - Regex Compilation Overhead
**Learning:** Compiling regexes inside frequently called validation functions (like `validate_tool_schema`) creates massive overhead (~7ms per op). Using `std::sync::OnceLock` reduces this to ~36µs, a ~196x speedup.
**Action:** Always hoist regex compilation to static scope using `OnceLock` or `lazy_static` for hot paths.

## 2024-05-24 - Optimization Regression
**Learning:** The Zero-Copy Deserialization optimization (removing `.clone()`) was found reverted in the codebase, despite the comment remaining.
**Action:** Re-applied the optimization. Always verify code matches the comments.

## 2024-05-24 - Double Deserialization Overhead
**Learning:** Parsing JSON into `Value`, then `from_value` into a struct, then `to_value` back to `Value` causes massive allocation overhead (deep copies) and breaks protocol correctness (e.g. notifications gaining `id: null`).
**Action:** Validate and modify `serde_json::Value` directly in place using `get`/`get_mut` and `retain` for strictness. This yielded a ~17% speedup on mixed payloads and fixed a bug.
