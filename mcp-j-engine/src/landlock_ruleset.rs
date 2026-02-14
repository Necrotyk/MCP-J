use landlock::{
    AccessFs, Ruleset, RulesetError, ABI,
    PathFd,
};
use std::collections::HashMap;
use anyhow::{Result, Context};
use std::path::PathBuf;

#[derive(Clone)]
pub struct LandlockRuleset {
    allowed_paths: HashMap<PathBuf, AccessFs>,
}

impl LandlockRuleset {
    pub fn new() -> Result<Self> {
        Ok(Self {
            allowed_paths: HashMap::new(),
        })
    }

    pub fn allow_read<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.allowed_paths.insert(path.into(), AccessFs::from_read(ABI::V1));
        self
    }

    pub fn allow_write<P: Into<PathBuf>>(mut self, path: P) -> Self {
        // Read + Write usually
        let access = AccessFs::from_read(ABI::V1) | AccessFs::from_write(ABI::V1);
        self.allowed_paths.insert(path.into(), access);
        self
    }

    pub fn apply(&self) -> Result<()> {
        // ABI V4 supports more features (e.g. truncate), use best effort or specific version?
        // Let's rely on the crate's robust handling or defaulting.
        // The landlock crate's `Ruleset::new()` typically picks the highest supported ABI by default 
        // or allows configuration.
        // We'll try to use a recent ABI if available, but fallback handling is good.
        let abi = ABI::V4; 
        
        let mut ruleset = Ruleset::new()
            .handle_access(AccessFs::from_all(abi))?
            .create()?;

        for (path, access) in &self.allowed_paths {
             // We need to resolve path to PathFd or use Path directly if crate supports it.
             // landlock crate 0.4 `add_rule` takes `PathFd` which handles opening the path.
             // We must handle the case where path doesn't exist (skip or error?)
             // For strictness, if a configured allowed path is missing, arguably we should warn but proceed,
             // or fail. Let's warn and continue to allow flexible configs.
             
             let path_fd = match PathFd::new(path) {
                 Ok(fd) => fd,
                 Err(e) => {
                     // Log warning? 
                     eprintln!("Warning: Failed to resolve path for Landlock rule: {:?} - {}", path, e);
                     continue;
                 }
             };
             
             // Apply the rule
             // The Rust landlock crate uses `add_rule(path_fd, access)`.
             ruleset = ruleset.add_rule(path_fd, *access).map_err(|e| anyhow::anyhow!("Failed to add Landlock rule for {:?}: {}", path, e))?;
        }
        
        let status = ruleset.restrict_self().map_err(|e| anyhow::anyhow!("Landlock restrict error: {}", e))?;
        
        if status.ruleset == landlock::RulesetStatus::NotEnforced {
             eprintln!("Warning: Landlock ruleset was not enforced! Kernel might not support Landlock.");
        }

        Ok(())
    }
}

