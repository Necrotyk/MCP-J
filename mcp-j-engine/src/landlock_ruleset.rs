use landlock::{
    Access, AccessFs, AccessNet, Ruleset, ABI, RulesetStatus, RulesetAttr, RulesetCreatedAttr,
    PathBeneath
};
use std::collections::HashMap;
use anyhow::Result;
use std::path::PathBuf;
use enumflags2::BitFlags;

#[derive(Clone)]
#[derive(Clone)]
pub struct LandlockRuleset {
    allowed_paths: HashMap<PathBuf, BitFlags<AccessFs>>,
    allow_tcp_connect: bool,
    allow_tcp_bind: bool,
}

impl LandlockRuleset {
    pub fn new() -> Result<Self> {
        Ok(Self {
            allowed_paths: HashMap::new(),
            allow_tcp_connect: false,
            allow_tcp_bind: false,
        })
    }

    pub fn allow_all_tcp_connect(&mut self) -> &mut Self {
        self.allow_tcp_connect = true;
        self
    }
    
    pub fn allow_all_tcp_bind(&mut self) -> &mut Self {
        self.allow_tcp_bind = true;
        self
    }

    pub fn allow_read<P: Into<PathBuf>>(&mut self, path: P) -> &mut Self {
        let access = AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::Execute;
        let mut p: PathBuf = path.into();
        self.allowed_paths.insert(p, access);
        self
    }

    pub fn allow_write<P: Into<PathBuf>>(&mut self, path: P) -> &mut Self {
        // Task 2.1: Include Truncate (will be filtered later if not supported)
        let access = AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::Execute | AccessFs::WriteFile | AccessFs::RemoveDir | AccessFs::RemoveFile | AccessFs::MakeChar | AccessFs::MakeDir | AccessFs::MakeReg | AccessFs::MakeSock | AccessFs::MakeFifo | AccessFs::MakeBlock | AccessFs::MakeSym | AccessFs::Truncate;
        let mut p: PathBuf = path.into();
        self.allowed_paths.insert(p, access);
        self
    }


    pub fn apply(&self) -> Result<()> {
        // Task 2.1: Dynamic Landlock ABI Probing
        // Probe for highest supported ABI (checking V4 down to V1)
        let supported_abi = [ABI::V4, ABI::V3, ABI::V2, ABI::V1]
            .into_iter()
            .find(|&abi| {
                // Check if we can create a ruleset with this ABI's FS flags
                Ruleset::new().handle_access(AccessFs::from_all(abi)).create().is_ok()
            })
            .unwrap_or(ABI::V1);

        tracing::info!("Detected Landlock ABI version: {:?}", supported_abi);

        let mut builder = Ruleset::new()
            .handle_access(AccessFs::from_all(supported_abi))?;
            
        // Task 5: Network Rules (V4+)
        let mut handle_net = false;
        if supported_abi >= ABI::V4 {
             // If we have V4, we can restrict network.
             // Policy: If allow_tcp_connect is TRUE, we add rules for common ports.
             // If FALSE, we Enable Net Restriction but add NO rules (Block All).
             // If the user didn't ask us to touch net (e.g. legacy), we might conflict?
             // But here we want hardening.
             
             // Currently, we ALWAYS handle net if V4 is present to enforce "Deny by Default" if not allowed.
             builder = builder.handle_access(AccessNet::from_all(supported_abi))?;
             handle_net = true;
        }

        let mut ruleset = builder.create()?;
        
        if handle_net {
            use landlock::net::NetPortRule;
            if self.allow_tcp_connect {
                // Task 5: Landlock V4 Network Enforcement
                // Allow common ports for agent activity
                let ports = [80, 443, 53, 3000, 8000, 8080, 22]; 
                for port in ports {
                    let rule = NetPortRule::new(port, AccessNet::ConnectTcp);
                    match ruleset.add_rule(rule) {
                        Ok(r) => ruleset = r,
                        Err(e) => {
                             // Log but continue? Landlock failures might be critical.
                             eprintln!("Failed to add network rule for port {}: {}", port, e);
                             return Err(anyhow::anyhow!("Failed to add network rule"));
                        }
                    }
                }
            }
            if self.allow_tcp_bind {
                // If we want to allow binding, expected ports?
                // For now, only Connect is safer.
            }
        }

        for (path, access) in &self.allowed_paths {
             if !path.exists() {
                 continue;
             }
             
             // Open the path to get an FD
             let file = std::fs::File::open(path)
                 .map_err(|e| anyhow::anyhow!("Failed to open path for landlock {:?}: {}", path, e))?;
                 
             // Filter access flags based on supported ABI
             let supported_access = *access & AccessFs::from_all(supported_abi);
             
             if supported_access.is_empty() {
                 continue;
             }

             let rule = PathBeneath::new(&file, supported_access);
             
             ruleset = ruleset.add_rule(rule)
                 .map_err(|e| anyhow::anyhow!("Failed to add Landlock rule for {:?}: {}", path, e))?;
        }
        
        let status = ruleset.restrict_self().map_err(|e| anyhow::anyhow!("Landlock restrict error: {}", e))?;
        
        if status.ruleset == RulesetStatus::NotEnforced {
             eprintln!("Warning: Landlock ruleset was not enforced! Kernel might not support Landlock.");
        }

        Ok(())
    }
}


