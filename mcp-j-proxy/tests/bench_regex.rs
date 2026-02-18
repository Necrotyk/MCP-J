use mcp_j_proxy::JsonRpcProxy;
use std::time::Instant;

#[test]
fn bench_validate_and_parse_regex() {
    let proxy = JsonRpcProxy::new(Some(vec!["read_file".to_string()]));
    // Pre-create a payload calling 'read_file' which triggers validate_tool_schema
    let payload = r#"{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "/tmp/test.txt"}}, "id": 1}"#;

    let start = Instant::now();
    for _ in 0..10000 {
        let _ = proxy.validate_and_parse(payload);
    }
    let duration = start.elapsed();
    println!("10000 iterations took: {:?}", duration);
}
