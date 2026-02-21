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

## 2024-05-24 - String Processing Overhead in Proxy
**Learning:** `shlex::try_quote` and `regex::Regex::replace_all` return `Cow::Borrowed` when no changes are needed. Leveraging this avoids redundant allocations and `is_match` scans.
**Action:** Use `Cow::Borrowed` variant to skip allocations and redundant checks in hot paths involving string sanitization.

## 2024-05-24 - Large Buffer Initialization
**Learning:** `Vec::resize(len, 0)` forces zero-initialization (memset), which is expensive for large LSP payloads (up to 10MB) in `mcp-j-cli`. Using `reader.take(len).read_to_end(&mut buf)` avoids this overhead by leveraging `read_buf` to read directly into uninitialized capacity. Benchmarks showed a ~1.72x speedup for 10MB payloads.
**Action:** Use `read_to_end` with `take` for reading large chunks into `Vec<u8>` instead of `resize` + `read_exact`.

## 2024-05-25 - Regex Sanitization Allocation
**Learning:** Chained `str::replace` calls inside a `regex::replace_all` closure allocate intermediate `String`s for each replacement step. Using a single-pass character iterator with a pre-allocated buffer avoids these redundant allocations, improving performance by ~13% in heavy sanitization scenarios.
**Action:** Use single-pass string building instead of chained replacements for multi-step string sanitization.
