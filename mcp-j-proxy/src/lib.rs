use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone)]
pub struct JsonRpcProxy;

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

impl JsonRpcProxy {
    pub fn new() -> Self {
        Self
    }

    pub fn validate_and_parse(&self, message: &str) -> Result<Value, String> {
        // 1. Strict JSON-RPC 2.0 Parsing
        let request: JsonRpcRequest = serde_json::from_str(message).map_err(|e| format!("Invalid JSON-RPC: {}", e))?;

        // 2. Protocol Enforcement
        if request.jsonrpc != "2.0" {
            return Err("Invalid JSON-RPC version".to_string());
        }

        // 3. Method-Specific Validation
        match request.method.as_str() {
            "tools/call" => {
                if let Some(params) = &request.params {
                    // Validate tool call arguments
                    self.validate_tool_call(params)?;
                }
            }
            "mcp-remote/authorize" | "mcp-remote/token" => {
                // CVE-2025-6514 Remediation: Block OAuth manipulation
                return Err("Blocked restricted method: mcp-remote/*".to_string());
            }
            _ => {
                // Allow other methods (notifications, resources/list, etc.)
                // We do not sanitize standard IPC strings to avoid breaking protocol.
            }
        }

        // Return the parsed value (or re-serialize if modification was needed, but here we just validated)
        serde_json::to_value(request).map_err(|e| e.to_string())
    }

    fn validate_tool_call(&self, params: &Value) -> Result<(), String> {
        // Parse params structure specific to tools/call
        // expected: { name: "...", arguments: { ... } }
        let tool_params: ToolCallParams = serde_json::from_value(params.clone())
            .map_err(|_| "Invalid params structure for tools/call".to_string())?;

        if let Some(args) = tool_params.arguments {
            self.validate_arguments(&args)?;
        }
        Ok(())
    }

    fn validate_arguments(&self, args: &Value) -> Result<(), String> {
        // Recursive validation for shell injection patterns in arguments
        match args {
            Value::String(s) => {
                // Heuristic: Check for obvious shell injection markers
                // We keep it simple but stricter than before:
                // `backticks`, $(...)
                if s.contains('`') || s.contains("$(") {
                    return Err(format!("Unsafe shell pattern detected in argument: {}", s));
                }
            }
            Value::Array(arr) => {
                for item in arr {
                    self.validate_arguments(item)?;
                }
            }
            Value::Object(map) => {
                for (_, value) in map {
                    self.validate_arguments(value)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

