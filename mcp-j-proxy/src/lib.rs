use serde_json::Value;

pub fn parse_message(message: &str) -> Result<Value, serde_json::Error> {
    serde_json::from_str(message)
}

pub struct JsonRpcProxy {
    // proxy fields
}

impl JsonRpcProxy {
    pub fn new() -> Self {
        Self {}
    }

    pub fn forward(&self, message: &str) {
        println!("Proxying message: {}", message);
    }
}
