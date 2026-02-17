use mcp_j_proxy::JsonRpcProxy;
use serde_json::json;

#[test]
fn test_shell_metacharacters_are_quoted() {
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
            Ok(val) => {
                 let cmd = val["params"]["arguments"]["cmd"].as_str().unwrap();
                 println!("Input: '{}' -> Quoted: '{}'", input, cmd);
                 // Verify it is quoted. shlex usually adds single quotes.
                 if !cmd.starts_with('\'') || !cmd.ends_with('\'') {
                      panic!("Input was not properly quoted: '{}' -> '{}'", input, cmd);
                 }
            },
            Err(val) => {
                let err_msg = val["error"]["message"].as_str().unwrap();
                panic!("Input was blocked unexpectedly: '{}' -> {}", input, err_msg);
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

        // Also verify safe inputs are quoted, as they are "unknown tools" to the proxy
        // unless they are whitelisted. "execute_command" is not "read_file" or "list_directory".
        // So validate_arguments will run and quote them.
        let val = result.unwrap();
        let cmd = val["params"]["arguments"]["cmd"].as_str().unwrap();
        // shlex can use ' or " depending on content
        assert!((cmd.starts_with('\'') && cmd.ends_with('\'')) || (cmd.starts_with('"') && cmd.ends_with('"')),
                "Safe input should also be quoted: '{}' -> '{}'", input, cmd);
    }
}
