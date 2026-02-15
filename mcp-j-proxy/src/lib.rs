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

    pub fn validate_and_parse(&self, message: &str) -> Result<Value, Value> {
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
        // Strict Argument Validation
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

