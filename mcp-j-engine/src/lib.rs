pub mod supervisor;
pub mod seccomp_loop;
pub mod landlock_ruleset;
pub mod fs_utils;
pub mod seccomp_sys;

// TODO: Integrate seccomp-stream when available or use alternative seccomp handling.
// Dependency: seccomp-stream = { git = "https://github.com/firecracker-microvm/seccomp-stream" }

pub fn check_kernel_compatibility() -> anyhow::Result<()> {
    // We need 5.13+ for Landlock (or 5.14 recommended)
    let uts = nix::sys::utsname::uname()?;
    let release = uts.release();
    let release_str = release.to_str().unwrap_or("0.0.0");
    
    // Simple parsing "X.Y.Z"
    let parts: Vec<&str> = release_str.split('.').collect();
    if parts.len() >= 2 {
        if let (Ok(major), Ok(minor)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
            if major < 5 || (major == 5 && minor < 14) {
                 anyhow::bail!("Kernel too old: {}. Need 5.14+ for full isolation support.", release_str);
            }
        }
    }
    
    Ok(())
}
