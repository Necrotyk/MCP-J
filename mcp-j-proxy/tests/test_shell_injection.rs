use mcp_j_proxy::JsonRpcProxy;
use serde_json::json;

#[test]
fn test_shell_metacharacters_are_blocked() {
    let proxy = JsonRpcProxy::default();

    let dangerous_inputs = vec![
        // New metacharacters added
        "command & background",    // Single ampersand
        "input < file",            // Input redirection
        "$VAR expansion",          // Variable expansion
        "command >> append",       // Append redirection
        // Original metacharacters (should still be blocked)
        "command | pipe",
        "command ; sequence",
        "command ` backtick",
        "$(command substitution)",
        "command && logic",
        "command || logic",
        "command > redirect",
    ];

    for input in dangerous_inputs {
        let payload = json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "execute_command",
                "arguments": {
                    "cmd": input
                }
            },
            "id": 1
        });

        let result = proxy.validate_and_parse(&payload.to_string());

        match result {
            Ok(_) => panic!("VULNERABILITY: Input should have been blocked but wasn't: '{}'", input),
            Err(val) => {
                let err_msg = val["error"]["message"].as_str().unwrap();
                println!("Successfully blocked: '{}' -> {}", input, err_msg);
                assert!(err_msg.contains("MCP-J SECCOMP: Argument contains forbidden shell metacharacter sequence"),
                        "Unexpected error message: {}", err_msg);
            }
        }
    }
}

#[test]
fn test_safe_inputs_allowed() {
    let proxy = JsonRpcProxy::default();
    let safe_inputs = vec![
        "ls -la",
        "echo hello world",
        "cat file.txt",
        "git status",
        "npm install",
        "echo \"Hello world\"",
        "echo 'Hello world'",
        "echo path/to/file",
        "echo param=value",
        "echo \"Hello, world!\"",
        // Should confirm that legitimate JSON is fine, assuming it doesn't contain shell chars
    ];

    for input in safe_inputs {
        let payload = json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "execute_command",
                "arguments": {
                    "cmd": input
                }
            },
            "id": 1
        });

        let result = proxy.validate_and_parse(&payload.to_string());
        assert!(result.is_ok(), "Safe input was blocked: '{}'", input);
    }
}
