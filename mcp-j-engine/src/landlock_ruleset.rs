use landlock::{
    Access, AccessFs, AccessNet, Ruleset, ABI, RulesetStatus, RulesetAttr, RulesetCreatedAttr,
    PathBeneath
};
use std::collections::HashMap;
use anyhow::Result;
use std::path::PathBuf;
use enumflags2::BitFlags;

#[derive(Clone)]
pub struct LandlockRuleset {
    allowed_paths: HashMap<PathBuf, BitFlags<AccessFs>>,
    allow_tcp_connect: bool,
    allow_tcp_bind: bool,
    allowed_tcp_ports: Vec<u16>,
}

impl LandlockRuleset {
    pub fn new() -> Result<Self> {
        Ok(Self {
            allowed_paths: HashMap::new(),
            allow_tcp_connect: false,
            allow_tcp_bind: false,
            allowed_tcp_ports: Vec::new(),
        })
    }

    pub fn allow_all_tcp_connect(&mut self) -> &mut Self {
        self.allow_tcp_connect = true;
        self
    }
    
    pub fn allow_tcp_ports(&mut self, ports: &[u16]) -> &mut Self {
        self.allowed_tcp_ports.extend_from_slice(ports);
        self
    }
    
    pub fn allow_all_tcp_bind(&mut self) -> &mut Self {
        self.allow_tcp_bind = true;
        self
    }
// ... (skip unchanged methods)


    pub fn allow_read<P: Into<PathBuf>>(&mut self, path: P) -> &mut Self {
        let access = AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::Execute;
        let p: PathBuf = path.into();
        self.allowed_paths.insert(p, access);
        self
    }

    pub fn allow_write<P: Into<PathBuf>>(&mut self, path: P) -> &mut Self {
        // Task 2.1: Include Truncate (will be filtered later if not supported)
        let access = AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::Execute | AccessFs::WriteFile | AccessFs::RemoveDir | AccessFs::RemoveFile | AccessFs::MakeChar | AccessFs::MakeDir | AccessFs::MakeReg | AccessFs::MakeSock | AccessFs::MakeFifo | AccessFs::MakeBlock | AccessFs::MakeSym | AccessFs::Truncate;
        let p: PathBuf = path.into();
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
                Ruleset::default()
                    .handle_access(AccessFs::from_all(abi))
                    .and_then(|b| b.create())
                    .is_ok()
            })
            .unwrap_or(ABI::V1);

        tracing::info!("Detected Landlock ABI version: {:?}", supported_abi);

        let mut builder = Ruleset::default()
            .handle_access(AccessFs::from_all(supported_abi))?;
            
        // Task 5: Network Rules (V4+)
        let mut handle_net = false;
        
        // Fix T-01: Landlock Network Blackhole
        // If allow_tcp_connect is true, we skip AccessNet restriction entirely
        // because we cannot add allow-rules with current crate.
        // We rely on Seccomp for filtering in that case.
        // We ONLY restrict AccessNet if we explicitly want to BLOCK connections (allow_tcp_connect = false).
        if !self.allow_tcp_connect && supported_abi >= ABI::V4 {
             builder = builder.handle_access(AccessNet::from_all(supported_abi))?;
             handle_net = true;
        }

        let mut ruleset = builder.create()?;
        
        if handle_net {
            tracing::info!("Landlock V4: Blocking ALL network access (Default Deny)");
        } else if supported_abi >= ABI::V4 {
             tracing::warn!("Landlock V4: Network restriction disabled to allow connectivity (Relying on Seccomp)");
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


