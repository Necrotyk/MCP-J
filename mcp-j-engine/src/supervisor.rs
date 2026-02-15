use std::path::PathBuf;
use std::process::Command;
use std::os::unix::process::CommandExt;
use nix::sched::{unshare, CloneFlags};
use nix::unistd::{self, ForkResult};
use nix::sys::wait::{waitpid, WaitStatus};
use std::os::unix::io::{AsRawFd, IntoRawFd, FromRawFd, RawFd};
use anyhow::{Result, Context};
use crate::landlock_ruleset::LandlockRuleset;
use crate::seccomp_loop::SeccompLoop;

use crate::SandboxManifest;

pub struct Supervisor {
    command: PathBuf,
    args: Vec<String>,
    landlock_ruleset: LandlockRuleset,
    project_root: PathBuf,
    manifest: SandboxManifest,
}

impl Supervisor {
    pub fn new(
        command: PathBuf, 
        args: Vec<String>, 
        project_root: PathBuf,
        manifest: SandboxManifest
    ) -> Result<Self> {
        Ok(Self {
            command,
            args,
            landlock_ruleset: LandlockRuleset::new()?,
            project_root,
            manifest,
        })
    }

    pub fn with_landlock(mut self, ruleset: LandlockRuleset) -> Self {
        self.landlock_ruleset = ruleset;
        self
    }

    pub fn spawn(mut self) -> Result<JailedChild> {
        // Automatically allow reading the executable we are about to run
        self.landlock_ruleset = self.landlock_ruleset.allow_read(&self.command);
        // Also allow read on manifest mounts
        for mount_path in &self.manifest.readonly_mounts {
            self.landlock_ruleset = self.landlock_ruleset.allow_read(mount_path);
        }

        // Create Seccomp Notify Socketpair (O_CLOEXEC)
        let (parent_sock, child_sock) = nix::sys::socket::socketpair(
            nix::sys::socket::AddressFamily::Unix,
            nix::sys::socket::SockType::Stream,
            None,
            nix::sys::socket::SockFlag::SOCK_CLOEXEC,
        ).context("Failed to create socketpair")?;

        // Create Stdin/Stdout/Stderr pipes (O_CLOEXEC)
        let (stdin_read, stdin_write) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).context("Failed to create stdin pipe")?;
        let (stdout_read, stdout_write) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).context("Failed to create stdout pipe")?;
        let (stderr_read, stderr_write) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).context("Failed to create stderr pipe")?;

        match unsafe { unistd::fork() } {
            Ok(ForkResult::Parent { child, .. }) => {
                // Parent process
                unistd::close(child_sock.as_raw_fd()).ok(); 
                unistd::close(stdin_read.as_raw_fd()).ok();
                unistd::close(stdout_write.as_raw_fd()).ok();
                unistd::close(stderr_write.as_raw_fd()).ok();
                
                tracing::info!(pid = %child, "Supervisor: Started child");

                // Receive the notification FD from child
                let notify_fd = self.receive_notify_fd(parent_sock.as_raw_fd())?;
                unistd::close(parent_sock.as_raw_fd()).ok(); 

                // Start Seccomp Loop in background thread
                let loop_root = self.project_root.clone();
                let allowed_cmd = self.command.clone();
                let manifest_clone = self.manifest.clone();
                let seccomp_loop = SeccompLoop::new(notify_fd, loop_root, allowed_cmd, manifest_clone);
                std::thread::spawn(move || {
                    if let Err(e) = seccomp_loop.run() {
                        tracing::error!(error = %e, "Seccomp loop error");
                    }
                });
                
                // Use unsafe to create File from OwnedFd (by taking raw fd)
                let stdin_file = unsafe { std::fs::File::from_raw_fd(stdin_write.into_raw_fd()) };
                let stdout_file = unsafe { std::fs::File::from_raw_fd(stdout_read.into_raw_fd()) };
                let stderr_file = unsafe { std::fs::File::from_raw_fd(stderr_read.into_raw_fd()) };

                Ok(JailedChild {
                    pid: child,
                    stdin: Some(stdin_file),
                    stdout: Some(stdout_file),
                    stderr: Some(stderr_file),
                    cgroup_guard: Some(CgroupGuard::new(child.as_raw() as u32)),
                })
            }
            Ok(ForkResult::Child) => {
                // Child process
                unistd::close(parent_sock.as_raw_fd()).ok();
                
                // Convert OwnedFds to RawFds to manage manually
                let stdin_r_fd = stdin_read.into_raw_fd();
                let stdin_w_fd = stdin_write.into_raw_fd();
                let stdout_r_fd = stdout_read.into_raw_fd();
                let stdout_w_fd = stdout_write.into_raw_fd();
                let stderr_r_fd = stderr_read.into_raw_fd();
                let stderr_w_fd = stderr_write.into_raw_fd();

                // Close unused ends
                unistd::close(stdin_w_fd).ok(); 
                unistd::close(stdout_r_fd).ok();
                unistd::close(stderr_r_fd).ok();
                
                // Dup2
                let _ = unistd::dup2(stdin_r_fd, 0); // Stdin
                let _ = unistd::dup2(stdout_w_fd, 1); // Stdout
                let _ = unistd::dup2(stderr_w_fd, 2); // Stderr
                
                // Close original FDs
                unistd::close(stdin_r_fd).ok();
                unistd::close(stdout_w_fd).ok();
                unistd::close(stderr_w_fd).ok();

                if let Err(e) = self.setup_child(child_sock.as_raw_fd()) {
                    tracing::error!(error = %e, "Child setup failed");
                    std::process::exit(1);
                }
                
                // Exec
                let err = Command::new(&self.command)
                    .args(&self.args)
                    .env_clear() // Critical: Strip host environment
                    .envs(&self.manifest.env_vars) // Whitelisted env vars
                    .exec();
                    
                tracing::error!(error = %err, "Failed to exec");
                std::process::exit(1);
            }
            Err(e) => {
                anyhow::bail!("Fork failed: {}", e);
            }
        }
    }

    fn receive_notify_fd(&self, sock: RawFd) -> Result<RawFd> {
        use nix::sys::socket::{recvmsg, MsgFlags, ControlMessageOwned};
        use std::io::IoSliceMut;

        let mut buf = [0u8; 1];
        let mut iov = [IoSliceMut::new(&mut buf)];
        let mut cmsg_buffer = nix::cmsg_space!(RawFd);
        
        // Blocking recv
        let msg = recvmsg::<()>(sock, &mut iov, Some(&mut cmsg_buffer), MsgFlags::empty())?;
        
        let fd = msg.cmsgs().map(|mut iter| iter.find_map(|cmsg| {
            match cmsg {
                ControlMessageOwned::ScmRights(fds) => fds.first().cloned(),
                _ => None,
            }
        }))? 
        .ok_or_else(|| anyhow::anyhow!("No FD received from child"))?;

        Ok(fd)
    }

    fn setup_child(&self, sock: RawFd) -> Result<()> {
        // --- PHASE 0: Cgroup v2 Resource Bounding ---
        // --- PHASE 0: Cgroup v2 Resource Bounding ---
        let pid = std::process::id();
        let cgroup_guard = CgroupGuard::new(pid);
        let cgroup_path = cgroup_guard.path().clone();
        
        // Attempt to create cgroup and limit resource
        if let Err(e) = std::fs::create_dir(&cgroup_path) {
             tracing::warn!(path = ?cgroup_path, error = %e, "Failed to create cgroup. Resource limits might not be applied.");
             // If failed to create, maybe return error or proceed without cgroup?
             // Proceed for now, but guard won't remove anything if it wasn't created theoretically (rmdir fails).
        } else {
             // Add self to cgroup
             if let Err(e) = std::fs::write(cgroup_path.join("cgroup.procs"), pid.to_string()) {
                 tracing::warn!(error = %e, "Failed to add pid to cgroup");
             }
             
             // Set memory limit from manifest
             let mem_bytes = self.manifest.max_memory_mb * 1024 * 1024;
             if let Err(e) = std::fs::write(cgroup_path.join("memory.max"), mem_bytes.to_string()) {
                 tracing::warn!(error = %e, "Failed to set memory limit");
             }
             
             // Set CPU quota (Phase 29)
             if self.manifest.max_cpu_quota_pct > 0 {
                  // cpu.max: "quota period" -> "{pct * 1000} 100000" (100000us = 100ms cycle)
                  let quota = self.manifest.max_cpu_quota_pct * 1000;
                  let val = format!("{} 100000", quota);
                  if let Err(e) = std::fs::write(cgroup_path.join("cpu.max"), val) {
                      tracing::warn!(error = %e, "Failed to set cpu limit");
                  }
             }
        }

        // 1. Unshare Namespaces
        unshare(CloneFlags::CLONE_NEWUSER)?;

        // Map UID/GID
        let uid = unistd::getuid();
        let gid = unistd::getgid();
        std::fs::write("/proc/self/uid_map", format!("0 {} 1", uid))?;
        std::fs::write("/proc/self/setgroups", "deny")?;
        std::fs::write("/proc/self/gid_map", format!("0 {} 1", gid))?;
        
        // Now unshare the rest
        unshare(CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWIPC | CloneFlags::CLONE_NEWUTS | CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWPID)?;
        
        // Mount setup
        use nix::mount::{mount, umount2, MsFlags, MntFlags};
        
        mount(
            None::<&str>,
            "/",
            None::<&str>,
            MsFlags::MS_PRIVATE | MsFlags::MS_REC,
            None::<&str>,
        ).context("Failed to make / private")?;

        mount(
            Some("tmpfs"),
            "/tmp",
            Some("tmpfs"),
            MsFlags::empty(),
            Some("mode=1777,size=64m"),
        ).context("Failed to mount tmpfs on /tmp")?;
        
        // --- PHASE 3: Pivot Root ---
        let jail_root = std::path::Path::new("/tmp/jail_root");
        if !jail_root.exists() {
            std::fs::create_dir(jail_root).context("Failed to create jail root")?;
        }
        
        let workspace_path = jail_root.join("workspace");
        if !workspace_path.exists() {
            std::fs::create_dir(&workspace_path).context("Failed to create workspace in jail")?;
        }
        
        mount(
            Some(&self.project_root),
            &workspace_path,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        ).context("Failed to bind mount project root")?;
        
        // Use manifest mounts
        for mount_path_str in &self.manifest.readonly_mounts {
            let src = PathBuf::from(mount_path_str);
            // destination in jail (e.g. /tmp/jail_root/bin)
            // Strip leading '/' from mount_path to join safely
            let rel_path = mount_path_str.trim_start_matches('/');
            let dst = jail_root.join(rel_path);
            
            if src.exists() {
                if !dst.exists() { std::fs::create_dir_all(&dst).ok(); }
                mount(
                    Some(&src),
                    &dst,
                    None::<&str>,
                    MsFlags::MS_BIND | MsFlags::MS_REC | MsFlags::MS_RDONLY,
                    None::<&str>
                ).ok(); 
            }
        }
        
        let old_root = jail_root.join("old_root");
        if !old_root.exists() {
            std::fs::create_dir(&old_root).context("Failed to create old_root")?;
        }
        
        mount(
            Some(jail_root),
            jail_root,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>
        ).context("Failed to bind mount jail root to itself")?;
        
        // Create and mount /proc
        let proc_path = jail_root.join("proc");
        if !proc_path.exists() {
             std::fs::create_dir(&proc_path).context("Failed to create /proc in jail")?;
        }
        
        mount(
            Some("proc"),
            &proc_path,
            Some("proc"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
            None::<&str>,
        ).context("Failed to mount /proc")?;
        
        // --- PHASE 23: POSIX Device Node Injection ---
        let dev_path = jail_root.join("dev");
        if !dev_path.exists() {
             std::fs::create_dir(&dev_path).context("Failed to create /dev in jail")?;
        }

        // Mount essential devices
        for device in &["null", "zero", "urandom"] {
             let host_dev = PathBuf::from("/dev").join(device);
             let jail_dev = dev_path.join(device);
             
             if !jail_dev.exists() {
                 std::fs::File::create(&jail_dev).context(format!("Failed to create /dev/{}", device))?;
             }

             if host_dev.exists() {
                 mount(
                     Some(&host_dev),
                     &jail_dev,
                     None::<&str>,
                     MsFlags::MS_BIND | MsFlags::MS_RDONLY, // Read-only for safety
                     None::<&str>
                 ).context(format!("Failed to bind mount /dev/{}", device))?;
             }
        }

        nix::unistd::pivot_root(jail_root, &old_root).context("Failed to pivot root")?;
        
        unistd::chdir("/").context("Failed to chdir to new root")?;
        
        umount2("/old_root", MntFlags::MNT_DETACH).context("Failed to unmount old_root")?;
        
        std::fs::remove_dir("/old_root").ok();
        
        unistd::chdir("/workspace").context("Failed to chdir to workspace")?;

        // --- PHASE 2: Capability Dropping & UID Downgrade ---
        // Bind lifecycle to parent (supervisor) before dropping privileges
        unsafe {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                 return Err(anyhow::anyhow!("Failed to set PR_SET_PDEATHSIG"));
            }
        }

        for cap in 0..=63 {
             unsafe {
                 libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0);
             }
        }
        

        
        // 2. Install Seccomp Filter and get Notify FD
        let notify_fd = self.install_seccomp_filter()?;
        
        // 3. Send Notify FD to parent
        self.send_notify_fd(sock, notify_fd)?;
        
        // 4. Close Notify FD and Socket in child
        unistd::close(notify_fd).ok();
        unistd::close(sock).ok();
        
        // 5. Apply Landlock 
        self.landlock_ruleset.apply().context("Failed to apply Landlock rules")?;
        
        Ok(())
    }

    fn send_notify_fd(&self, sock: RawFd, fd: RawFd) -> Result<()> {
        use nix::sys::socket::{sendmsg, MsgFlags, ControlMessage};
        use std::io::IoSlice;

        let buf = [0u8; 1];
        let iov = [IoSlice::new(&buf)];
        let fds = [fd];
        let cmsg = ControlMessage::ScmRights(&fds);
        
        sendmsg::<()>(sock, &iov, &[cmsg], MsgFlags::empty(), None)?;
        Ok(())
    }

    fn install_seccomp_filter(&self) -> Result<RawFd> {
        use libseccomp::{ScmpFilterContext, ScmpAction, ScmpSyscall, ScmpArch};
        
        let mut ctx = ScmpFilterContext::new(ScmpAction::Allow)?;
        
        // Phase 33: Multi-Architecture & Static Compilation
        // Explicitly add the native architecture to ensure the filter targets the correct ABI.
        // This is critical when running on mixed-environment hosts or under emulation.
        ctx.add_arch(ScmpArch::Native)?;

        ctx.add_rule(ScmpAction::Notify, ScmpSyscall::from_name("connect")?)?;
        ctx.add_rule(ScmpAction::Notify, ScmpSyscall::from_name("execve")?)?;
        ctx.add_rule(ScmpAction::Notify, ScmpSyscall::from_name("bind")?)?;
        ctx.add_rule(ScmpAction::Notify, ScmpSyscall::from_name("openat")?)?;
        ctx.add_rule(ScmpAction::Notify, ScmpSyscall::from_name("open")?)?; // Legacy open, maps to openat often but good to catch.
        
        ctx.load()?;
        
        let fd = ctx.get_notify_fd()?;
        Ok(fd)
    }
}

// Helper for Cgroup RAII cleanup
pub struct CgroupGuard {
    path: PathBuf,
}

impl CgroupGuard {
    pub fn new(pid: u32) -> Self {
        let path = PathBuf::from(format!("/sys/fs/cgroup/mcp-j-{}", pid));
        Self { path }
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}

impl Drop for CgroupGuard {
    fn drop(&mut self) {
        // Phase 10 & 18: Annihilate all processes in cgroup with retry before removal
        let procs_path = self.path.join("cgroup.procs");
        
        // 1. Initial Kill
        if let Ok(content) = std::fs::read_to_string(&procs_path) {
            for line in content.lines() {
                if let Ok(pid) = line.trim().parse::<i32>() {
                    unsafe { libc::kill(pid, libc::SIGKILL); }
                }
            }
        }
        
        // 2. Retry Loop (Phase 18)
        for _ in 0..10 {
            let mut empty = true;
            if let Ok(content) = std::fs::read_to_string(&procs_path) {
                 if !content.trim().is_empty() {
                     empty = false;
                     // Re-issue kill just in case
                     for line in content.lines() {
                        if let Ok(pid) = line.trim().parse::<i32>() {
                            unsafe { libc::kill(pid, libc::SIGKILL); }
                        }
                     }
                 }
            }
            
            if empty {
                break;
            }
            
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        // Try removing the directory
        let _ = std::fs::remove_dir(&self.path);
    }
}


pub struct JailedChild {
    pub pid: nix::unistd::Pid,
    pub stdin: Option<std::fs::File>,
    pub stdout: Option<std::fs::File>,
    pub stderr: Option<std::fs::File>,
    pub cgroup_guard: Option<CgroupGuard>, // Moved here, or keep in Supervisor context? 
    // Wait, the child is in the cgroup. We can only remove cgroup after all processes in it are gone.
    // So JailedChild should own the guard, and on Drop (after wait), it cleans up.
}

impl JailedChild {
    pub fn wait(&mut self) -> Result<WaitStatus> {
        let res = waitpid(self.pid, None).map_err(|e| anyhow::anyhow!("waitpid failed: {}", e));
        
        // After wait returns, the child is dead (zombie harvested).
        // Cgroup should be empty (unless other processes spawned in it?).
        // It's safe to assume we can try to remove it now?
        // But JailedChild::drop will handle it strictly via CgroupGuard.
        res
    }
}
