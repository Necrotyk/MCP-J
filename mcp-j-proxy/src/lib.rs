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

impl Default for JsonRpcProxy {
    fn default() -> Self {
        Self::new()
    }
}

impl JsonRpcProxy {
    pub fn new() -> Self {
        Self
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
        // We parse into Value first to extract ID even if partial structs fail.
        let raw: Value = match serde_json::from_str(message) {
             Ok(v) => v,
             Err(e) => {
                 // Parse error. Standard JSON-RPC 2.0 error for Parse Error is code -32700.
                 // ID is null if parse failed.
                 let err = serde_json::json!({
                     "jsonrpc": "2.0",
                     "error": {
                         "code": -32700,
                         "message": format!("Parse error: {}", e)
                     },
                     "id": null
                 });
                 return Err(err);
             }
        };
        
        // Extract ID for error reporting
        let id = raw.get("id").cloned().unwrap_or(Value::Null);

        // Map to structured request for validation
        let request: JsonRpcRequest = match serde_json::from_value(raw.clone()) {
            Ok(r) => r,
            Err(e) => {
                let err = serde_json::json!({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32600,
                        "message": format!("Invalid Request: {}", e)
                    },
                    "id": id
                });
                return Err(err);
            }
        };

        // 2. Protocol Enforcement
        if request.jsonrpc != "2.0" {
            let err = serde_json::json!({
                "jsonrpc": "2.0",
                "error": {
                    "code": -32600,
                    "message": "Invalid JSON-RPC version"
                },
                "id": id
            });
            return Err(err);
        }

        // 3. Method-Specific Validation
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
            _ => {
                Ok(())
            }
        };

        if let Err(msg) = validation_result {
             let err = serde_json::json!({
                 "jsonrpc": "2.0",
                 "error": {
                     "code": -32600, // Invalid Request / Policy violation
                     "message": format!("Security policy violation: {}", msg)
                 },
                 "id": id
             });
             return Err(err);
        }

        // Return the parsed value
        // We return the original raw value re-serialized (or just the struct)
        // Returning request struct as Value
        Ok(serde_json::to_value(request).unwrap())
    }

    fn validate_tool_call(&self, params: &Value) -> Result<(), String> {
        let tool_params: ToolCallParams = serde_json::from_value(params.clone())
            .map_err(|_| "Invalid params structure for tools/call".to_string())?;

        if let Some(args) = tool_params.arguments {
            self.validate_arguments(&args)?;
        }
        Ok(())
    }

    fn validate_arguments(&self, args: &Value) -> Result<(), String> {
        // Validation logic for user-space (proxy) has been simplified.
        // We rely on kernel-level enforcement (Landlock, Seccomp) for security.
        // The proxy mainly ensures structural integrity of JSON-RPC 2.0.
        // Deep inspection of string arguments for shell injection is prone to false positives
        // with legitimate code artifacts (e.g. bash scripts, markdown).
        
        match args {
            Value::String(_) => {
                // No-op: Allow all strings.
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

