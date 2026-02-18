use mcp_j_proxy::JsonRpcProxy;
use serde_json::json;

#[test]
fn test_read_file_path_traversal() {
    let allowed = Some(vec!["read_file".to_string()]);
    let proxy = JsonRpcProxy::new(allowed);

    // Test with path traversal using ..
    // The current regex r"^[\w\-. /]+$" allows dots, including ".."
    // This test expects the proxy to BLOCK this, so we assert it returns an Error.
    let payload = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {
                "path": "../../etc/passwd"
            }
        },
        "id": 1
    });

    let result = proxy.validate_and_parse(&payload.to_string());

    if result.is_ok() {
        panic!("VULNERABILITY: Path traversal should have been blocked but wasn't: '../../etc/passwd'");
    }

    // Test with absolute path
    let payload_abs = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {
                "path": "/etc/passwd"
            }
        },
        "id": 2
    });

    let result_abs = proxy.validate_and_parse(&payload_abs.to_string());
    if result_abs.is_ok() {
        panic!("VULNERABILITY: Absolute path should have been blocked but wasn't: '/etc/passwd'");
    }
}
