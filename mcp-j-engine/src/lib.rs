pub mod supervisor;
pub mod seccomp_loop;
pub mod landlock_ruleset;
pub mod fs_utils;
pub mod seccomp_sys;
pub mod manifest;

pub use manifest::SandboxManifest;

// TODO: Integrate seccomp-stream when available or use alternative seccomp handling.
// Dependency: seccomp-stream = { git = "https://github.com/firecracker-microvm/seccomp-stream" }

pub fn check_kernel_compatibility() -> anyhow::Result<()> {
    // We need 5.13+ for Landlock (or 5.14 recommended)
    let uts = nix::sys::utsname::uname()?;
    let release = uts.release();
    let release_str = release.to_str().unwrap_or("0.0.0");
    
    validate_kernel_version(release_str)
}

fn validate_kernel_version(release_str: &str) -> anyhow::Result<()> {
    // Task 4.2: Robust parsing
    // Strip "v" prefix if present
    let clean = release_str.trim_start_matches(|c: char| !c.is_digit(10));
    
    let parts: Vec<&str> = clean.split('.').collect();
    if parts.len() < 2 {
        anyhow::bail!("Unparseable kernel version string: {}", release_str);
    }
    
    // Helper to extract number from segment (e.g. "1-rc1" -> 1)
    let parse_part = |s: &str| -> anyhow::Result<u32> {
        let digits: String = s.chars().take_while(|c| c.is_digit(10)).collect();
        if digits.is_empty() {
             anyhow::bail!("Invalid version segment: {}", s);
        }
        digits.parse::<u32>().map_err(|e| anyhow::anyhow!("Parse error: {}", e))
    };
    
    let major = parse_part(parts[0])?;
    let minor = parse_part(parts[1])?;

    if major < 5 || (major == 5 && minor < 14) {
         anyhow::bail!("Kernel too old: {}. Need 5.14+ for full isolation support.", release_str);
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_kernel() {
        assert!(validate_kernel_version("5.15.0").is_ok());
        assert!(validate_kernel_version("6.0.0").is_ok());
        // Robustness cases
        assert!(validate_kernel_version("v6.1-rc1").is_ok()); 
    }

    #[test]
    fn test_old_kernel() {
        assert!(validate_kernel_version("5.10.0").is_err());
        assert!(validate_kernel_version("4.19.0").is_err());
    }
    
    #[test]
    fn test_weird_version() {
        // Task 4.1: Logic Error Correction
        // "foo.bar" should fail parsing and return Err.
        assert!(validate_kernel_version("foo.bar").is_err());
    }
}
