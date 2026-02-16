use landlock::{
    Access, AccessFs, Ruleset, ABI, RulesetStatus, RulesetAttr, RulesetCreatedAttr,
    PathBeneath
};
use std::collections::HashMap;
use anyhow::Result;
use std::path::PathBuf;
use enumflags2::BitFlags;

#[derive(Clone)]
pub struct LandlockRuleset {
    allowed_paths: HashMap<PathBuf, BitFlags<AccessFs>>,
}

impl LandlockRuleset {
    pub fn new() -> Result<Self> {
        Ok(Self {
            allowed_paths: HashMap::new(),
        })
    }

    pub fn allow_read<P: Into<PathBuf>>(&mut self, path: P) -> &mut Self {
        let access = AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::Execute;
        let mut p: PathBuf = path.into();
        self.allowed_paths.insert(p, access);
        self
    }

    pub fn allow_write<P: Into<PathBuf>>(&mut self, path: P) -> &mut Self {
        let access = AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::Execute | AccessFs::WriteFile | AccessFs::RemoveDir | AccessFs::RemoveFile | AccessFs::MakeChar | AccessFs::MakeDir | AccessFs::MakeReg | AccessFs::MakeSock | AccessFs::MakeFifo | AccessFs::MakeBlock | AccessFs::MakeSym;
        let mut p: PathBuf = path.into();
        self.allowed_paths.insert(p, access);
        self
    }


    pub fn apply(&self) -> Result<()> {
        // Phase 31: Dynamic LSM ABI Negotiation
        // Use default() which probes V1
        let abi = ABI::V1; 
        
        // Attempt to upgrade to best supported if possible? 
        // Actually, just using V1 is safest for broad compatibility if we only need V1 features.
        // But if we want max protection, we should check.
        // The landlock crate's ABI enum usually has V1, V2, V3 etc.
        // `AccessFs::from_all(abi)` will return access rights supported by that ABI.
        
        let mut ruleset = Ruleset::default()
            .handle_access(AccessFs::from_all(abi))?
            .create()?;

        for (path, access) in &self.allowed_paths {
             if !path.exists() {
                 continue;
             }
             
             // Open the path to get an FD (AsFd)
             let file = std::fs::File::open(path)
                 .map_err(|e| anyhow::anyhow!("Failed to open path for landlock {:?}: {}", path, e))?;
                 
             let rule = PathBeneath::new(&file, *access);
             
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


