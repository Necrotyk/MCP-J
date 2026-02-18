use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SecurityMode {
    Enforcing,
    Audit,
}

impl Default for SecurityMode {
    fn default() -> Self {
        SecurityMode::Enforcing
    }
}

fn default_ipc_limit() -> u32 {
    10
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SandboxManifest {
    pub max_memory_mb: u64,
    #[serde(default = "default_ipc_limit")]
    pub max_ipc_payload_mb: u32,
    pub allowed_egress_ips: Vec<String>,
    #[serde(default)]
    pub allowed_egress_ipv6: Vec<String>,
    pub readonly_mounts: Vec<String>,
    pub env_vars: HashMap<String, String>,
    pub allowed_tools: Option<Vec<String>>,
    #[serde(default)]
    pub allowed_dns_resolvers: Vec<String>,
    #[serde(default)]
    pub allowed_egress_ports: Vec<u16>,
    #[serde(default)]
    pub allowed_runtimes: Vec<String>,
    pub max_cpu_quota_pct: u32,
    pub mode: SecurityMode,
}

impl Default for SandboxManifest {
    fn default() -> Self {
        Self {
            max_memory_mb: 512,
            max_ipc_payload_mb: 10,
            allowed_egress_ips: vec!["127.0.0.1".to_string()],
            allowed_egress_ipv6: vec!["::1".to_string()],
            allowed_egress_ports: vec![80, 443], // Task 3: Default ports
            readonly_mounts: vec![
                "/lib".to_string(), 
                "/lib64".to_string(), 
                "/usr/lib".to_string(), 
                "/usr/lib64".to_string(), 
                "/bin".to_string(), 
                "/usr/bin".to_string()
            ],
            env_vars: HashMap::new(),
            allowed_tools: Some(vec![
                "read_file".to_string(),
                "list_directory".to_string(),
            ]),
            allowed_runtimes: vec![
                "/usr/bin/node".to_string(),
                "/usr/local/bin/node".to_string(),
                "/usr/bin/python3".to_string(),
                "/usr/local/bin/python3".to_string(),
                "/usr/bin/git".to_string(),
                "/bin/ls".to_string(),
                "/bin/cat".to_string(),
            ],
            allowed_dns_resolvers: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
            max_cpu_quota_pct: 100,
            mode: SecurityMode::Enforcing,
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_manifest_default_values() {
        let manifest = SandboxManifest::default();
        assert_eq!(manifest.max_memory_mb, 512);
        assert!(manifest.allowed_egress_ips.contains(&"127.0.0.1".to_string()));
        assert!(manifest.readonly_mounts.contains(&"/bin".to_string()));
        assert_eq!(manifest.max_cpu_quota_pct, 100);
        assert_eq!(manifest.mode, SecurityMode::Enforcing);
        assert!(manifest.allowed_tools.is_some());
        let tools = manifest.allowed_tools.as_ref().unwrap();
        assert!(tools.contains(&"read_file".to_string()));
    }

    #[test]
    fn test_manifest_serialization_roundtrip() {
        let manifest = SandboxManifest::default();
        let json = serde_json::to_string(&manifest).expect("Failed to serialize");
        let deserialized: SandboxManifest = serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(deserialized.max_memory_mb, manifest.max_memory_mb);
        assert_eq!(deserialized.allowed_egress_ips, manifest.allowed_egress_ips);
        assert_eq!(deserialized.readonly_mounts, manifest.readonly_mounts);
        assert_eq!(deserialized.max_cpu_quota_pct, manifest.max_cpu_quota_pct);
        assert_eq!(deserialized.mode, manifest.mode);
        assert_eq!(deserialized.allowed_tools, manifest.allowed_tools);
    }

    #[test]
    fn test_manifest_deserialization_defaults() {
        let json = r#"{}"#;
        let manifest: SandboxManifest = serde_json::from_str(json).expect("Failed to deserialize empty object");

        let expected = SandboxManifest::default();

        assert_eq!(manifest.max_memory_mb, expected.max_memory_mb);
        assert_eq!(manifest.max_cpu_quota_pct, expected.max_cpu_quota_pct);
        assert_eq!(manifest.mode, expected.mode);
        assert_eq!(manifest.allowed_egress_ips, expected.allowed_egress_ips);
        assert_eq!(manifest.readonly_mounts, expected.readonly_mounts);
        assert_eq!(manifest.allowed_tools, expected.allowed_tools);
    }

    #[test]
    fn test_manifest_partial_deserialization() {
        let json = r#"{"max_memory_mb": 1024, "mode": "audit"}"#;
        let manifest: SandboxManifest = serde_json::from_str(json).expect("Failed to deserialize partial object");

        assert_eq!(manifest.max_memory_mb, 1024);
        assert_eq!(manifest.mode, SecurityMode::Audit);

        // Other fields should still be at their defaults
        let expected = SandboxManifest::default();
        assert_eq!(manifest.allowed_egress_ips, expected.allowed_egress_ips);
        assert_eq!(manifest.readonly_mounts, expected.readonly_mounts);
    }
}
