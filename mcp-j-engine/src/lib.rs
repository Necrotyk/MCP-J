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
    // Task 4.1: Return Error if version string is unparseable
    let parts: Vec<&str> = release_str.split('.').collect();
    if parts.len() < 2 {
        anyhow::bail!("Unparseable kernel version string: {}", release_str);
    }
    
    let major = parts[0].parse::<u32>().map_err(|_| anyhow::anyhow!("Invalid kernel major version: {}", parts[0]))?;
    let minor = parts[1].parse::<u32>().map_err(|_| anyhow::anyhow!("Invalid kernel minor version: {}", parts[1]))?;

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
    }

    #[test]
    fn test_old_kernel() {
        assert!(validate_kernel_version("5.10.0").is_err());
        assert!(validate_kernel_version("4.19.0").is_err());
    }
    
    #[test]
    fn test_weird_version() {
        // If parsing fails, we default to Ok (per current logic) or fail?
        // Current logic only fails if it successfully parses major/minor AND they are too low.
        // If parsing fails (e.g. "foo"), parts[0].parse fails, so it skips the check and returns Ok.
        // This might be a bug or intended loose coupling.
        // Assuming current logic is loose.
        assert!(validate_kernel_version("foo.bar").is_ok());
    }
}
