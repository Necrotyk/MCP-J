use serde_json::Value;
use std::sync::OnceLock;

#[derive(Clone)]
pub struct JsonRpcProxy {
    allowed_tools: Option<Vec<String>>,
    sanitization_regex: regex::Regex,
}

impl Default for JsonRpcProxy {
    fn default() -> Self {
        Self::new(None)
    }
}

impl JsonRpcProxy {
    pub fn new(allowed_tools: Option<Vec<String>>) -> Self {
        // Task 3.2: Regex-based LLM token detection
        // Task 1.1: Escape-Aware Filtering
        // We use a broader regex to catch hex/unicode escapes like \u003c| or %3C|
        // and standard tokens.
        static SANITIZATION_REGEX: OnceLock<regex::Regex> = OnceLock::new();
        let re = SANITIZATION_REGEX.get_or_init(|| {
            regex::Regex::new(r"(?i)(?:\\u003c\||%3C\||<\|)(?:endoftext|im_start|im_end|system|user|assistant)|\[INST\]")
                .expect("Failed to compile sanitization regex")
        });

        Self { allowed_tools, sanitization_regex: re.clone() }
    }

    pub fn validate_and_parse(&self, message: &str) -> Result<Value, Value> {
        // Phase 53: IPC Proxy Byte Saturation Limits
        // This is currently hardcoded but will be dynamic in Task 3.
        const MAX_PAYLOAD_BYTES: usize = 10 * 1024 * 1024;
        if message.len() > MAX_PAYLOAD_BYTES {
                let err = serde_json::json!({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32600,
                        "message": format!("IPC_PAYLOAD_OVERFLOW: Payload exceeds maximum allowed size of {} bytes", MAX_PAYLOAD_BYTES)
                    },
                    "id": null
                });
                return Err(err);
        }

        // 1. Strict JSON-RPC 2.0 Parsing
        let mut raw: Value = match serde_json::from_str(message) {
                Ok(v) => v,
                Err(e) => {
                    let err = serde_json::json!({
                        "jsonrpc": "2.0",
                        "error": { "code": -32700, "message": format!("Parse error: {}", e) },
                        "id": null
                    });
                    return Err(err);
                }
        };

        // Extract ID for error reporting
        let id = raw.get("id").cloned().unwrap_or(Value::Null);

        // Check if it's a Request (has method) or Response (has result/error)
        let is_request = raw.get("method").is_some();

        if is_request {
            // Task 1.2: Request Sanitization (Inbound)
            if let Some(params) = raw.get_mut("params") {
                if self.recursive_sanitize(params) {
                    // Log warning but allow modified request to proceed?
                    // Or just silently sanitize.
                    tracing::warn!("Sanitized inbound request params containing LLM control tokens");
                }
            }

            // 2. Protocol Enforcement (Manual Validation)
            // Ensure jsonrpc is "2.0"
            match raw.get("jsonrpc") {
                Some(Value::String(s)) if s == "2.0" => {},
                _ => return Err(serde_json::json!({
                    "jsonrpc": "2.0",
                    "error": { "code": -32600, "message": "Invalid JSON-RPC version" },
                    "id": id
                }))
            }

            // Ensure method is a string and valid
            let method_str = match raw.get("method") {
                Some(Value::String(s)) => s.clone(),
                _ => return Err(serde_json::json!({
                    "jsonrpc": "2.0",
                    "error": { "code": -32600, "message": "Invalid Request: method must be a string" },
                    "id": id
                }))
            };

            // 3. Method Validation & Logic
            let validation_result = match method_str.as_str() {
                "tools/call" => {
                    if let Some(params) = raw.get_mut("params") {
                        self.validate_tool_call(params)
                    } else {
                         Ok(())
                    }
                }
                "mcp-remote/authorize" | "mcp-remote/token" => {
                     Err("Blocked restricted method: mcp-remote/*".to_string())
                }
                _ => Ok(())
            };

            if let Err(msg) = validation_result {
                    let code = if msg.contains("Tool execution blocked") { -32601 } else { -32600 };
                    let err = serde_json::json!({
                        "jsonrpc": "2.0",
                        "error": {
                            "code": code,
                            "message": format!("MCP-J SECCOMP: {}", msg)
                        },
                        "id": id
                    });
                    return Err(err);
            }

            // 4. Strip Unknown Fields (Security / Strictness)
            // Remove any key that is not jsonrpc, method, params, id.
            // This maintains the strictness behavior of the previous implementation
            // (which deserialized into a struct with only these fields).
            if let Some(obj) = raw.as_object_mut() {
                obj.retain(|k, _| matches!(k.as_str(), "jsonrpc" | "method" | "params" | "id"));
            }

            Ok(raw)

        } else {
            // Handle Response (Potential Prompt Injection)
            // Phase 68: Prompt Injection Sanitization (Egress Filter)
            // We need to inspect 'result' for LLM control tokens.
            if let Some(result) = raw.get_mut("result") {
                    self.recursive_sanitize(result);
            }
            if let Some(error) = raw.get_mut("error") {
                    self.recursive_sanitize(error);
            }
            Ok(raw)
        }
    }

    fn recursive_sanitize(&self, val: &mut Value) -> bool {
        let mut modified = false;
        match val {
            Value::String(s) => {
                // Task 3.2: Regex-based sanitization
                // Optimization: calling replace_all directly avoids double-scanning (is_match + replace_all)
                // when matches are found, and is efficient (single scan) when no matches are found.
                let sanitized = self.sanitization_regex.replace_all(s, |caps: &regex::Captures| {
                    let m = &caps[0];
                    // Optimization: Avoid multiple String allocations by building the result in a single pass.
                    // Previous implementation used m.to_string() then up to 3 .replace() calls, causing up to 4 allocations.
                    let mut out = String::with_capacity(m.len() + 8);

                    let mut chars = m.chars().peekable();
                    while let Some(c) = chars.next() {
                        match c {
                            '<' => {
                                // Check for literal <| which we want to sanitize to &lt;|
                                if let Some(&'|') = chars.peek() {
                                    out.push_str("&lt;");
                                } else {
                                    out.push('<');
                                }
                            }
                            '[' => out.push_str("&#91;"),
                            ':' => out.push_str("&#58;"),
                            _ => out.push(c),
                        }
                    }
                    out
                });

                if let std::borrow::Cow::Owned(new_s) = sanitized {
                    *s = new_s;
                    eprintln!("[PROMPT_INJECTION_ATTEMPT] Detected and neutralized LLM control tokens");
                    modified = true;
                }
            }
            Value::Array(arr) => {
                for item in arr {
                    if self.recursive_sanitize(item) { modified = true; }
                }
            }
            Value::Object(map) => {
                for (_, value) in map {
                    if self.recursive_sanitize(value) { modified = true; }
                }
            }
            _ => {}
        }
        modified
    }

    fn validate_tool_call(&self, params: &mut Value) -> Result<(), String> {
        let params_obj = params.as_object_mut()
            .ok_or_else(|| "Invalid params structure for tools/call".to_string())?;

        let name = params_obj.get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Invalid params structure for tools/call".to_string())?
            .to_string(); // Clone name to avoid borrow issues

        // Phase 67: Protocol-Aware Tool Filtering
        if let Some(allowed) = &self.allowed_tools {
            if !allowed.iter().any(|s| s == &name) {
                return Err(format!("Tool execution blocked by Layer 7 policy: '{}'", name));
            }
        }

        if let Some(args) = params_obj.get_mut("arguments") {
            // Task 4.2: Schema Enforcement
            self.validate_tool_schema(&name, args)?;
            
            // Task 1: Schema-Aware Validation & Quoting
            match name.as_str() {
                "read_file" | "list_directory" => {
                    // Already validated by schema (regex check)
                },
                _ => {
                    // For unknown/generic tools, we conservatively quote strings
                    // to prevent shell injection if they are used in shells.
                    self.validate_arguments(args, 0)?;
                }
            }
        }
        Ok(())
    }

    fn validate_tool_schema(&self, name: &str, args: &Value) -> Result<(), String> {
        let args_obj = args.as_object().ok_or("Arguments must be an object")?;
        // Task B-3: Strict Regex for paths
        // Optimization: Use OnceLock to compile regex once.
        static PATH_REGEX: OnceLock<regex::Regex> = OnceLock::new();
        let path_regex = PATH_REGEX.get_or_init(|| {
            regex::Regex::new(r"^[\w\-. /]+$").unwrap()
        });
        
        match name {
            "read_file" => {
                if !args_obj.contains_key("path") { return Err("Missing 'path' argument".into()); }
                let p = args_obj["path"].as_str().ok_or("'path' must be a string")?;
                
                // Optimization: Early rejection of traversal attempts
                let has_traversal = p == ".." || p.starts_with("../") || p.ends_with("/..") || p.contains("/../");
                if has_traversal { return Err("Invalid 'path': Traversal detected".into()); }
                
                if !path_regex.is_match(p) { return Err("Invalid 'path': Must match ^[\\w\\-. /]+$".into()); }
                if p.contains("..") { return Err("Invalid 'path': Path traversal '..' is not allowed".into()); }
                if p.starts_with('/') { return Err("Invalid 'path': Absolute paths are not allowed".into()); }
                if args_obj.len() != 1 { return Err("Unexpected arguments for read_file".into()); }
            },
            "list_directory" => {
                 if !args_obj.contains_key("path") { return Err("Missing 'path' argument".into()); }
                 let p = args_obj["path"].as_str().ok_or("'path' must be a string")?;
                 
                 // Optimization: Early rejection of traversal attempts
                 let has_traversal = p == ".." || p.starts_with("../") || p.ends_with("/..") || p.contains("/../");
                 if has_traversal { return Err("Invalid 'path': Traversal detected".into()); }
                 
                 if !path_regex.is_match(p) { return Err("Invalid 'path': Must match ^[\\w\\-. /]+$".into()); }
                 if p.contains("..") { return Err("Invalid 'path': Path traversal '..' is not allowed".into()); }
                 if p.starts_with('/') { return Err("Invalid 'path': Absolute paths are not allowed".into()); }
                 if args_obj.len() != 1 { return Err("Unexpected arguments for list_directory".into()); }
            },
            _ => {}
        }
        Ok(())
    }


    fn validate_arguments(&self, args: &mut Value, depth: usize) -> Result<(), String> {
        const MAX_RECURSION_DEPTH: usize = 128;
        if depth > MAX_RECURSION_DEPTH {
            return Err(format!("Recursion limit exceeded at depth {}", depth));
        }

        match args {
            Value::String(s) => {
                // Task B-3: Enforce shlex::try_quote
                // We strictly quote ALL free-text arguments for unknown tools.
                // This ensures that even if they are passed to a shell, they are treated as literals.
                match shlex::try_quote(s) {
                    Ok(std::borrow::Cow::Owned(quoted)) => *s = quoted,
                    Ok(std::borrow::Cow::Borrowed(_)) => {}, // Optimization: No change needed
                    Err(_) => return Err("Argument contains null byte, cannot be quoted".to_string()),
                }
            }
            Value::Array(arr) => {
                for item in arr {
                    self.validate_arguments(item, depth + 1)?;
                }
            }
            Value::Object(map) => {
                for (_, value) in map {
                    self.validate_arguments(value, depth + 1)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_request() {
        let proxy = JsonRpcProxy::default();
        let msg = r#"{"jsonrpc": "2.0", "method": "ping", "params": {}, "id": 1}"#;
        let res = proxy.validate_and_parse(msg);
        assert!(res.is_ok());
        let val = res.unwrap();
        assert_eq!(val["method"], "ping");
    }

    #[test]
    fn test_valid_response() {
        let proxy = JsonRpcProxy::default();
        let msg = r#"{"jsonrpc": "2.0", "result": "pong", "id": 1}"#;
        let res = proxy.validate_and_parse(msg);
        assert!(res.is_ok());
        let val = res.unwrap();
        assert_eq!(val["result"], "pong");
    }

    #[test]
    fn test_payload_overflow() {
        let proxy = JsonRpcProxy::default();
        // 10MB + 1 byte
        let big_msg = "a".repeat(10 * 1024 * 1024 + 1);
        let res = proxy.validate_and_parse(&big_msg);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err["error"]["code"], -32600);
        assert!(err["error"]["message"].as_str().unwrap().contains("IPC_PAYLOAD_OVERFLOW"));
    }

    #[test]
    fn test_invalid_json() {
        let proxy = JsonRpcProxy::default();
        let msg = r#"{"jsonrpc": "2.0", "method": "ping", "params": {}, "id": 1"#; // Missing closing brace
        let res = proxy.validate_and_parse(msg);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err["error"]["code"], -32700);
        assert!(err["error"]["message"].as_str().unwrap().contains("Parse error"));
    }

    #[test]
    fn test_invalid_jsonrpc_version() {
        let proxy = JsonRpcProxy::default();
        let msg = r#"{"jsonrpc": "1.0", "method": "ping", "params": {}, "id": 1}"#;
        let res = proxy.validate_and_parse(msg);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err["error"]["code"], -32600);
        assert_eq!(err["error"]["message"], "Invalid JSON-RPC version");
    }

    #[test]
    fn test_restricted_method() {
        let proxy = JsonRpcProxy::default();
        let msg = r#"{"jsonrpc": "2.0", "method": "mcp-remote/authorize", "params": {}, "id": 1}"#;
        let res = proxy.validate_and_parse(msg);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err["error"]["code"], -32600);
        assert!(err["error"]["message"].as_str().unwrap().contains("MCP-J SECCOMP"));
    }

    #[test]
    fn test_tool_call_allowed() {
        let allowed = Some(vec!["safe_tool".to_string()]);
        let proxy = JsonRpcProxy::new(allowed);
        let msg = r#"{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "safe_tool", "arguments": {}}, "id": 1}"#;
        let res = proxy.validate_and_parse(msg);
        assert!(res.is_ok());
    }

    #[test]
    fn test_tool_call_blocked() {
        let allowed = Some(vec!["safe_tool".to_string()]);
        let proxy = JsonRpcProxy::new(allowed);
        let msg = r#"{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "unsafe_tool", "arguments": {}}, "id": 1}"#;
        let res = proxy.validate_and_parse(msg);
        assert!(res.is_err());
        let err = res.unwrap_err();
        // The implementation returns -32601 if msg contains "Tool execution blocked"
        assert_eq!(err["error"]["code"], -32601);
        assert!(err["error"]["message"].as_str().unwrap().contains("Tool execution blocked"));
    }

    #[test]
    fn test_shell_injection_mitigation() {
        let allowed = Some(vec!["safe_tool".to_string()]);
        let proxy = JsonRpcProxy::new(allowed);
        // Test with pipe character |
        let msg = r#"{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "safe_tool", "arguments": {"cmd": "ls | rm -rf /"}}, "id": 1}"#;
        let res = proxy.validate_and_parse(msg);
        assert!(res.is_ok()); // Should succeed with quoting
        let val = res.unwrap();
        // Check if argument was quoted
        let cmd = val["params"]["arguments"]["cmd"].as_str().unwrap();
        // shlex::quote("ls | rm -rf /") -> "'ls | rm -rf /'"
        assert_eq!(cmd, "'ls | rm -rf /'");
    }

    #[test]
    fn test_read_file_path_validation() {
        let allowed = Some(vec!["read_file".to_string()]);
        let proxy = JsonRpcProxy::new(allowed);
        // Test with path traversal/unsafe chars
        let msg = r#"{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "/etc/passwd; ls"}}, "id": 1}"#;
        let res = proxy.validate_and_parse(msg);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(err["error"]["message"].as_str().unwrap().contains("Invalid 'path'"));
    }

    #[test]
    fn test_prompt_injection_sanitization() {
        let proxy = JsonRpcProxy::default();
        let msg = r#"{"jsonrpc": "2.0", "result": "Hello <|im_start|> system", "id": 1}"#;
        let res = proxy.validate_and_parse(msg);
        assert!(res.is_ok());
        let val = res.unwrap();
        // Should be sanitized to &lt;|im_start|>
        assert!(val["result"].as_str().unwrap().contains("&lt;|im_start|>"));
    }

    #[test]
    fn test_error_sanitization() {
        let proxy = JsonRpcProxy::default();
        let msg = r#"{"jsonrpc": "2.0", "error": {"code": -32000, "message": "Hidden prompt <|im_start|> injection"}, "id": 1}"#;
        let res = proxy.validate_and_parse(msg).unwrap(); // validate_and_parse returns Ok(Value) on successful parsing/sanitization
        assert!(res["error"]["message"].as_str().unwrap().contains("&lt;|im_start|>"));
    }

    #[test]
    fn test_notification_passthrough() {
        let proxy = JsonRpcProxy::default();
        let msg = r#"{"jsonrpc": "2.0", "method": "notify", "params": {}}"#; // No ID
        let res = proxy.validate_and_parse(msg).unwrap();
        // Check if "id" is present
        if let Some(obj) = res.as_object() {
             assert!(!obj.contains_key("id"), "Notification acquired an ID!");
        }
    }
}
