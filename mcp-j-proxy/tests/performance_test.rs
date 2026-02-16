use mcp_j_proxy::JsonRpcProxy;
use serde_json::{json, Value};
use std::time::Instant;

#[test]
fn benchmark_validate_and_parse() {
    let proxy = JsonRpcProxy::default();

    // Create a large argument value
    let args = json!({
        "large_array": (0..1000).map(|i| format!("string_{}", i)).collect::<Vec<_>>(),
        "nested_object": (0..100).map(|i| (format!("key_{}", i), Value::String(format!("val_{}", i)))).collect::<serde_json::Map<String, Value>>(),
        "another_large_field": "x".repeat(100_000)
    });

    let payload = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "large_tool",
            "arguments": args
        },
        "id": 1
    });

    let payload_str = payload.to_string();
    let iterations = 1000;

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = proxy.validate_and_parse(&payload_str);
    }
    let duration = start.elapsed();

    println!("Performance test: Processed {} iterations in {:.2?}", iterations, duration);
    println!("Average time per iteration: {:.2?}", duration / iterations as u32);
}
