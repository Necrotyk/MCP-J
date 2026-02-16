use std::path::PathBuf;
use std::process::Command;
use std::os::unix::process::CommandExt;
use nix::sched::{unshare, CloneFlags};
use nix::unistd::{self, ForkResult, Pid};
use nix::sys::wait::{waitpid, WaitStatus};
use std::os::unix::io::{AsRawFd, RawFd, OwnedFd};
use anyhow::{Result, Context};
use crate::landlock_ruleset::LandlockRuleset;
use crate::seccomp_loop::SeccompLoop;
use crate::SandboxManifest;
use nix::mount::{mount, umount2, MsFlags, MntFlags};

pub struct Supervisor {
    command: PathBuf,
    args: Vec<String>,
    landlock_ruleset: LandlockRuleset,
    project_root: PathBuf,
    manifest: SandboxManifest,
}

struct Pipes {
    stdin_read: OwnedFd,
    stdin_write: OwnedFd,
    stdout_read: OwnedFd,
    stdout_write: OwnedFd,
    stderr_read: OwnedFd,
    stderr_write: OwnedFd,
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
        self.prepare_landlock_rules();

        // Create Seccomp Notify Socketpair (O_CLOEXEC)
        let (parent_sock, child_sock) = nix::sys::socket::socketpair(
            nix::sys::socket::AddressFamily::Unix,
            nix::sys::socket::SockType::Stream,
            None,
            nix::sys::socket::SockFlag::SOCK_CLOEXEC,
        ).context("Failed to create socketpair")?;

        let pipes = self.create_pipes()?;

        match unsafe { unistd::fork() } {
            Ok(ForkResult::Parent { child, .. }) => {
                // Determine raw FDs to keep before dropping `pipes` ownership
                // Note: We need to close ends intended for child, convert ends for parent to File.
                // We pass `pipes` struct to handle_parent which will consume it.
                // child_sock is closed in parent automatically when dropped?
                // Yes, OwnedFd closes on drop.
                // So we just need to drop child_sock. (It happens at end of scope).
                self.handle_parent(child, parent_sock, pipes)
            }
            Ok(ForkResult::Child) => {
                // Parent socket is closed on drop.
                match self.handle_child(child_sock, pipes) {
                    Ok(_) => std::process::exit(0), // Should have exec'd, so this is unreachable?
                    Err(e) => {
                        tracing::error!(error = %e, "Child process initialization failed");
                        std::process::exit(1);
                    }
                }
            }
            Err(e) => anyhow::bail!("Fork failed: {}", e),
        }
    }

    fn prepare_landlock_rules(&mut self) {
        // Automatically allow reading the executable
        self.landlock_ruleset.allow_read(&self.command);
        // Also allow read on manifest mounts
        for mount_path in &self.manifest.readonly_mounts {
            self.landlock_ruleset.allow_read(mount_path);
        }
    }

    fn create_pipes(&self) -> Result<Pipes> {
        let (stdin_read, stdin_write) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC)?;
        let (stdout_read, stdout_write) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC)?;
        let (stderr_read, stderr_write) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC)?;
        
        Ok(Pipes {
            stdin_read, stdin_write,
            stdout_read, stdout_write,
            stderr_read, stderr_write,
        })
    }

    fn handle_parent(self, child: Pid, parent_sock: OwnedFd, pipes: Pipes) -> Result<JailedChild> {
        // Close child ends by dropping them (handled by Pipes struct destruction if we take fields out)
        // We take parent ends.
        
        tracing::info!(pid = %child, "Supervisor: Started child");

        // Receive the notification FD from child
        let notify_fd = self.receive_notify_fd(parent_sock.as_raw_fd())?;
        // parent_sock closed when dropped.

        // Start Seccomp Loop in background thread
        let loop_root = self.project_root.clone();
        let allowed_cmd = self.command.clone();
        let manifest_clone = self.manifest.clone();
        
        // Spawn thread
        std::thread::spawn(move || {
            let seccomp_loop = SeccompLoop::new(notify_fd, loop_root, allowed_cmd, manifest_clone);
            if let Err(e) = seccomp_loop.run() {
                tracing::error!(error = %e, "Seccomp loop error");
            }
        });

        // Convert OwnedFd to File for JailedChild
        // We rely on generic From<OwnedFd> for File if available or use generic FromRawFd logic safely.
        // Rust's std::fs::File implements From<OwnedFd>.
        let stdin_file = std::fs::File::from(pipes.stdin_write);
        let stdout_file = std::fs::File::from(pipes.stdout_read);
        let stderr_file = std::fs::File::from(pipes.stderr_read);

        Ok(JailedChild {
            pid: child,
            stdin: Some(stdin_file),
            stdout: Some(stdout_file),
            stderr: Some(stderr_file),
            cgroup_guard: Some(CgroupGuard::new(child.as_raw() as u32)),
        })
    }

    fn handle_child(self, child_sock: OwnedFd, pipes: Pipes) -> Result<()> {
        // Enforce NoNewPrivs (Phase 1.3)
        unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(anyhow::anyhow!("Failed to set NO_NEW_PRIVS"));
            }
        }

        // Redirect stdio
        let _ = unistd::dup2(pipes.stdin_read.as_raw_fd(), 0);
        let _ = unistd::dup2(pipes.stdout_write.as_raw_fd(), 1);
        let _ = unistd::dup2(pipes.stderr_write.as_raw_fd(), 2);
        
        // Close all pipe FDs (original ones) by dropping `pipes`
        drop(pipes); 
        // Note: dup2 created copies. The originals in `Pipes` will be closed on drop.
        
        // Setup environment (namespaces, cgroups, mounts)
        self.setup_child_env()?;

        // Install Seccomp
        let notify_fd = self.install_seccomp_filter()?;
        self.send_notify_fd(child_sock.as_raw_fd(), notify_fd)?;
        
        // Close Notify FD and Socket
        unistd::close(notify_fd).ok();
        drop(child_sock); // Closes socket

        // Double Fork for PID Namespace
        match unsafe { unistd::fork() } {
            Ok(ForkResult::Parent { child, .. }) => {
                // Monitor immediate child (which becomes reparented to init of new namespace?)
                // Actually, in new PID ns, the child is PID 1.
                // We are the "loader" process (PID 0 inside ns perspective? No, we are outside or at boundary).
                // Wait for PID 1 (tracee) to exit.
                match waitpid(child, None) {
                    Ok(WaitStatus::Exited(_, code)) => std::process::exit(code),
                    Ok(WaitStatus::Signaled(_, sig, _)) => std::process::exit(128 + sig as i32),
                    _ => std::process::exit(1),
                }
            }
            Ok(ForkResult::Child) => {
                self.handle_grandchild()
            }
            Err(e) => Err(anyhow::anyhow!("Double fork failed: {}", e))
        }
    }

    fn setup_child_env(&self) -> Result<()> {
        // Cgroup setup
        self.setup_cgroup()?;
        
        // Namespaces
        unshare(CloneFlags::CLONE_NEWUSER)?;
        self.setup_uid_gid_map()?;
        unshare(CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWIPC | CloneFlags::CLONE_NEWUTS | CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWPID)?;
        
        // Mounts
        self.setup_mounts()?;
        
        Ok(())
    }

    fn setup_cgroup(&self) -> Result<()> {
        let pid = std::process::id();
        let guard = CgroupGuard::new(pid);
        let cgroup_path = guard.path().clone();
        
        if let Err(e) = std::fs::create_dir(&cgroup_path) {
             let msg = format!("Failed to create cgroup {}: {}", cgroup_path.display(), e);
             if self.manifest.mode == crate::manifest::SecurityMode::Enforcing {
                 anyhow::bail!(msg);
             } else {
                 tracing::warn!("{}", msg);
                 return Ok(());
             }
        }
        
        // Add self
        if let Err(e) = std::fs::write(cgroup_path.join("cgroup.procs"), pid.to_string()) {
             let msg = format!("Failed to add pid to cgroup: {}", e);
             if self.manifest.mode == crate::manifest::SecurityMode::Enforcing {
                 anyhow::bail!(msg);
             } else {
                 tracing::warn!("{}", msg);
             }
        }
        
        let mem_bytes = self.manifest.max_memory_mb * 1024 * 1024;
        if let Err(e) = std::fs::write(cgroup_path.join("memory.max"), mem_bytes.to_string()) {
             let msg = format!("Failed to set memory limit: {}", e);
             if self.manifest.mode == crate::manifest::SecurityMode::Enforcing {
                 anyhow::bail!(msg);
             } else {
                 tracing::warn!("{}", msg);
             }
        }
        
        if self.manifest.max_cpu_quota_pct > 0 {
             let quota = self.manifest.max_cpu_quota_pct * 1000;
             let val = format!("{} 100000", quota);
             if let Err(e) = std::fs::write(cgroup_path.join("cpu.max"), val) {
                  let msg = format!("Failed to set cpu limit: {}", e);
                  if self.manifest.mode == crate::manifest::SecurityMode::Enforcing {
                      anyhow::bail!(msg);
                  } else {
                       tracing::warn!("{}", msg);
                  }
             }
        }
        Ok(())
    }

    fn setup_uid_gid_map(&self) -> Result<()> {
        let uid = unistd::getuid();
        let gid = unistd::getgid();
        std::fs::write("/proc/self/uid_map", format!("0 {} 1", uid))?;
        std::fs::write("/proc/self/setgroups", "deny")?;
        std::fs::write("/proc/self/gid_map", format!("0 {} 1", gid))?;
        Ok(())
    }

    fn setup_mounts(&self) -> Result<()> {
        // Root private
        mount(None::<&str>, "/", None::<&str>, MsFlags::MS_PRIVATE | MsFlags::MS_REC, None::<&str>).context("Failed to make / private")?;
        mount(Some("tmpfs"), "/tmp", Some("tmpfs"), MsFlags::empty(), Some("mode=1777,size=64m")).context("Failed to mount tmpfs on /tmp")?;
        
        // Pivot Root Preparation
        let jail_root = std::path::Path::new("/tmp/jail_root");
        if !jail_root.exists() { std::fs::create_dir(jail_root)?; }
        
        let workspace_path = jail_root.join("workspace");
        if !workspace_path.exists() { std::fs::create_dir(&workspace_path)?; }
        
        // Ephemeral OverlayFS (Phase 41)
        // Task 1.1: Use std::env::temp_dir() and UUID
        let temp_dir = std::env::temp_dir();
        let uuid = uuid::Uuid::new_v4().simple().to_string();
        let upper_dir = temp_dir.join(format!("mcp_upper_{}", uuid));
        let work_dir = temp_dir.join(format!("mcp_work_{}", uuid));
        if !upper_dir.exists() { std::fs::create_dir(&upper_dir)?; }
        if !work_dir.exists() { std::fs::create_dir(&work_dir)?; }
        
        let overlay_opts = format!("lowerdir={},upperdir={},workdir={}", self.project_root.display(), upper_dir.display(), work_dir.display());
        mount(Some("overlay"), &workspace_path, Some("overlay"), MsFlags::empty(), Some(overlay_opts.as_str())).context("Failed to mount overlayfs")?;
        
        // Bind mounts per manifest
        for mount_path_str in &self.manifest.readonly_mounts {
            let src = PathBuf::from(mount_path_str);
            let rel_path = mount_path_str.trim_start_matches('/');
            let dst = jail_root.join(rel_path);
            if src.exists() {
                if !dst.exists() { std::fs::create_dir_all(&dst).ok(); }
                mount(Some(&src), &dst, None::<&str>, MsFlags::MS_BIND | MsFlags::MS_REC | MsFlags::MS_RDONLY, None::<&str>).ok();
            }
        }
        
        // Pivot Root
        let old_root = jail_root.join("old_root");
        if !old_root.exists() { std::fs::create_dir(&old_root)?; }
        
        mount(Some(jail_root), jail_root, None::<&str>, MsFlags::MS_BIND, None::<&str>)?; // Bind self for pivot constraint
        
        // Create /proc and /dev
        let proc_path = jail_root.join("proc");
        if !proc_path.exists() { std::fs::create_dir(&proc_path)?; }
        mount(Some("proc"), &proc_path, Some("proc"), MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC, None::<&str>)?;
        
        let dev_path = jail_root.join("dev");
        if !dev_path.exists() { std::fs::create_dir(&dev_path)?; }
        for device in &["null", "zero", "urandom"] {
             let host = PathBuf::from("/dev").join(device);
             let jail = dev_path.join(device);
             if !jail.exists() { std::fs::File::create(&jail)?; }
             if host.exists() {
                 mount(Some(&host), &jail, None::<&str>, MsFlags::MS_BIND | MsFlags::MS_RDONLY, None::<&str>).ok();
             }
        }

        nix::unistd::pivot_root(jail_root, &old_root).context("Failed to pivot root")?;
        unistd::chdir("/").context("Failed to chdir to new root")?;
        umount2("/old_root", MntFlags::MNT_DETACH).context("Failed to unmount old_root")?;
        std::fs::remove_dir("/old_root").ok();
        unistd::chdir("/workspace").context("Failed to chdir to workspace")?;
        
        Ok(())
    }

    fn handle_grandchild(&self) -> Result<()> {
        // Remount /proc for new PID ns
        let _ = mount(Some("proc"), "/proc", Some("proc"), MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC, None::<&str>);
        
        // Drop Capabilities
        unsafe {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {}
            for cap in 0..=63 {
                 libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0);
            }
        }

        // Apply Landlock
        self.landlock_ruleset.apply().context("Failed to apply Landlock rules")?;
        
        // Exec
        let err = Command::new(&self.command)
            .args(&self.args)
            .env_clear()
            .envs(&self.manifest.env_vars)
            .exec();
            
        tracing::error!(error = %err, "Failed to exec");
        std::process::exit(1);
    }

    fn receive_notify_fd(&self, sock: RawFd) -> Result<RawFd> {
        use nix::sys::socket::{recvmsg, MsgFlags, ControlMessageOwned};
        use std::io::IoSliceMut;

        let mut buf = [0u8; 1];
        let mut iov = [IoSliceMut::new(&mut buf)];
        let mut cmsg_buffer = nix::cmsg_space!(RawFd);
        
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
        // ... Same implementation as before ...
        use libseccomp::{ScmpFilterContext, ScmpAction, ScmpSyscall, ScmpArch};
        let mut ctx = ScmpFilterContext::new(ScmpAction::Allow)?;
        ctx.add_arch(ScmpArch::Native)?;
        ctx.add_rule(ScmpAction::Notify, ScmpSyscall::from_name("connect")?)?;
        ctx.add_rule(ScmpAction::Notify, ScmpSyscall::from_name("execve")?)?;
        ctx.add_rule(ScmpAction::Notify, ScmpSyscall::from_name("bind")?)?;
        ctx.add_rule(ScmpAction::Notify, ScmpSyscall::from_name("sendto")?)?;
        ctx.add_rule(ScmpAction::Notify, ScmpSyscall::from_name("sendmsg")?)?; 
        ctx.add_rule(ScmpAction::Notify, ScmpSyscall::from_name("openat")?)?;
        ctx.add_rule(ScmpAction::Notify, ScmpSyscall::from_name("open")?)?;
        ctx.load()?;
        Ok(ctx.get_notify_fd()?)
    }
}

pub struct CgroupGuard {
    path: PathBuf,
}

impl CgroupGuard {
    pub fn new(pid: u32) -> Self {
        let path = PathBuf::from(format!("/sys/fs/cgroup/mcp-j-{}", pid));
        Self { path }
    }
    pub fn path(&self) -> &PathBuf { &self.path }
}

impl Drop for CgroupGuard {
    fn drop(&mut self) {
        let procs_path = self.path.join("cgroup.procs");
        if let Ok(content) = std::fs::read_to_string(&procs_path) {
            for line in content.lines() {
                if let Ok(pid) = line.trim().parse::<i32>() {
                    unsafe { libc::kill(pid, libc::SIGKILL); }
                }
            }
        }
        for _ in 0..10 {
            if let Ok(content) = std::fs::read_to_string(&procs_path) {
                 if content.trim().is_empty() { break; }
                 for line in content.lines() {
                     if let Ok(pid) = line.trim().parse::<i32>() { unsafe { libc::kill(pid, libc::SIGKILL); } }
                 }
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let _ = std::fs::remove_dir(&self.path);
    }
}

pub struct JailedChild {
    pub pid: nix::unistd::Pid,
    pub stdin: Option<std::fs::File>,
    pub stdout: Option<std::fs::File>,
    pub stderr: Option<std::fs::File>,
    pub cgroup_guard: Option<CgroupGuard>, 
}

impl JailedChild {
    pub fn wait(&mut self) -> Result<WaitStatus> {
        let res = waitpid(self.pid, None).map_err(|e| anyhow::anyhow!("waitpid failed: {}", e));
        res
    }
}
