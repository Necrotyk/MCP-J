use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone)]
pub struct JsonRpcProxy {
    allowed_tools: Option<Vec<String>>,
}

#[derive(Deserialize, Serialize, Debug)]
#[allow(dead_code)]
struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    params: Option<Value>,
    id: Option<Value>,
}

#[derive(Deserialize, Serialize, Debug)]
struct ToolCallParams {
    name: String,
    arguments: Option<Value>,
}

impl Default for JsonRpcProxy {
    fn default() -> Self {
        Self::new(None)
    }
}

impl JsonRpcProxy {
    pub fn new(allowed_tools: Option<Vec<String>>) -> Self {
        Self { allowed_tools }
    }

    pub fn validate_and_parse(&self, message: &str) -> Result<Value, Value> {
        // Phase 53: IPC Proxy Byte Saturation Limits
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
        let raw: Value = match serde_json::from_str(message) {
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
        if raw.get("method").is_some() {
            // Handle Request
            let request: JsonRpcRequest = match serde_json::from_value(raw.clone()) {
                Ok(r) => r,
                Err(e) => {
                    let err = serde_json::json!({
                        "jsonrpc": "2.0",
                        "error": { "code": -32600, "message": format!("Invalid Request: {}", e) },
                        "id": id
                    });
                    return Err(err);
                }
            };

            // Protocol Enforcement
            if request.jsonrpc != "2.0" {
                return Err(serde_json::json!({
                    "jsonrpc": "2.0",
                    "error": { "code": -32600, "message": "Invalid JSON-RPC version" },
                    "id": id
                }));
            }

            // Method Validation
            let validation_result = match request.method.as_str() {
                "tools/call" => {
                    if let Some(params) = &request.params {
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
            
            Ok(serde_json::to_value(request).unwrap())

        } else {
            // Handle Response (Potential Prompt Injection)
            // Phase 68: Prompt Injection Sanitization (Egress Filter)
            // We need to inspect 'result' for LLM control tokens.
            if let Some(result) = raw.get("result") {
                 let mut safe_result = result.clone();
                 if self.recursive_sanitize(&mut safe_result) {
                     // If sanitization occurred, synthesize a new response
                     let mut new_raw = raw.clone();
                     new_raw["result"] = safe_result;
                     return Ok(new_raw);
                 }
            }
            Ok(raw)
        }
    }

    fn recursive_sanitize(&self, val: &mut Value) -> bool {
        let mut modified = false;
        match val {
            Value::String(s) => {
                let targets = ["<|im_start|>", "[INST]", "\nSystem:"];
                for target in targets {
                    if s.contains(target) {
                        // Sanitization: Replace <| with &lt;| to break the token
                        *s = s.replace("<|", "&lt;|")
                              .replace("[INST]", "[SANITIZED_INST]")
                              .replace("\nSystem:", "\n[SANITIZED_SYS]:");
                        
                        eprintln!("[PROMPT_INJECTION_ATTEMPT] Detected and neutralized LLM control token: {}", target);
                        modified = true;
                    }
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

    fn validate_tool_call(&self, params: &Value) -> Result<(), String> {
        let tool_params: ToolCallParams = serde_json::from_value(params.clone())
            .map_err(|_| "Invalid params structure for tools/call".to_string())?;

        // Phase 67: Protocol-Aware Tool Filtering
        if let Some(allowed) = &self.allowed_tools {
            if !allowed.contains(&tool_params.name) {
                return Err(format!("Tool execution blocked by Layer 7 policy: '{}'", tool_params.name));
            }
        }

        if let Some(args) = tool_params.arguments {
            self.validate_arguments(&args, 0)?;
        }
        Ok(())
    }

    fn validate_arguments(&self, args: &Value, depth: usize) -> Result<(), String> {
        const MAX_RECURSION_DEPTH: usize = 128;
        if depth > MAX_RECURSION_DEPTH {
            return Err(format!("Recursion limit exceeded at depth {}", depth));
        }

        // Validation logic for user-space (proxy) has been simplified.
        // We rely on kernel-level enforcement (Landlock, Seccomp) for security.
        // The proxy mainly ensures structural integrity of JSON-RPC 2.0.
        // Deep inspection of string arguments for shell injection is prone to false positives
        // with legitimate code artifacts (e.g. bash scripts, markdown).
        
        match args {
            Value::String(s) => {
                // Phase 4: CVE-2025-6514 Shell Metacharacter Scrubbing
                // Reject sequences: $(, `, |, ;, &&, ||, >
                let forbidden = ["$(", "`", "|", ";", "&&", "||", ">"];
                for pattern in forbidden {
                    if s.contains(pattern) {
                         return Err(format!("Argument contains forbidden shell metacharacter sequence '{}'", pattern));
                    }
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

