use serde_json::Value;
use regex::Regex;

#[derive(Clone)]
pub struct JsonRpcProxy {
    unsafe_pattern: Regex,
}

impl JsonRpcProxy {
    pub fn new() -> Self {
        // Regex to detect shell metacharacters: $(...), `...`, etc.
        // Also simpler: | ; & 
        // Just blocking $ and ` is a good start for shell command injection prevention 
        // if the agent blindly passes strings to a shell.
        Self {
            unsafe_pattern: Regex::new(r"[`$]").unwrap(),
        }
    }

    pub fn validate_and_parse(&self, message: &str) -> Result<Value, String> {
        // 1. Basic JSON parsing
        let v: Value = serde_json::from_str(message).map_err(|e| e.to_string())?;

        // 2. Recursive validation of all string values
        self.validate_value(&v)?;

        Ok(v)
    }

    fn validate_value(&self, v: &Value) -> Result<(), String> {
        match v {
            Value::String(s) => {
                if self.unsafe_pattern.is_match(s) {
                    return Err(format!("Unsafe characters detected in input: {}", s));
                }
            }
            Value::Array(arr) => {
                for item in arr {
                    self.validate_value(item)?;
                }
            }
            Value::Object(map) => {
                for (_, value) in map {
                    self.validate_value(value)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}
