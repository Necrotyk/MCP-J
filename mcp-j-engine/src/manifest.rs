use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxManifest {
    #[serde(default = "default_max_memory_mb")]
    pub max_memory_mb: u64,
    
    #[serde(default)]
    pub allowed_egress_ips: Vec<String>,
    
    #[serde(default)]
    pub readonly_mounts: Vec<String>,
    
    #[serde(default)]
    pub env_vars: HashMap<String, String>,
}

fn default_max_memory_mb() -> u64 {
    512
}

impl Default for SandboxManifest {
    fn default() -> Self {
        Self {
            max_memory_mb: 512,
            allowed_egress_ips: vec!["127.0.0.1".to_string()],
            readonly_mounts: vec![
                "/lib".to_string(), 
                "/lib64".to_string(), 
                "/usr/lib".to_string(), 
                "/usr/lib64".to_string(), 
                "/bin".to_string(), 
                "/usr/bin".to_string()
            ],
            env_vars: HashMap::new(),
        }
    }
}
