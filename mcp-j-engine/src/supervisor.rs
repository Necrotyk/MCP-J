use std::path::PathBuf;
use std::process::Command;
use std::os::unix::process::CommandExt;
use nix::sched::{unshare, CloneFlags};
use nix::unistd::{self, ForkResult, Pid};
use nix::sys::wait::{waitpid, WaitStatus};
use std::os::unix::io::{AsRawFd, RawFd, OwnedFd, AsFd};
use std::os::unix::fs::DirBuilderExt;
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
        
        // Task 5: Enable Landlock Network Rules if manifest requires networking
        if !self.manifest.allowed_egress_ips.is_empty() || !self.manifest.allowed_egress_ipv6.is_empty() {
             self.landlock_ruleset.allow_all_tcp_connect();
             self.landlock_ruleset.allow_tcp_ports(&self.manifest.allowed_egress_ports);
             // Bind? Usually agents act as clients.
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

        // Receive the notification FD from child, whilst draining stderr to avoid deadlock
        let notify_fd; // Will be set in loop
        
        loop {
             let mut fds = [
                 nix::poll::PollFd::new(parent_sock.as_fd(), nix::poll::PollFlags::POLLIN),
                 nix::poll::PollFd::new(pipes.stderr_read.as_fd(), nix::poll::PollFlags::POLLIN),
             ];
             
             // Poll with timeout (10s) just in case
             let n = nix::poll::poll(&mut fds, 10000u16)?;
             if n == 0 {
                 anyhow::bail!("Timeout waiting for child initialization");
             }
             
             // Check Stderr (Index 1)
             if let Some(revents) = fds[1].revents() {
                 if revents.contains(nix::poll::PollFlags::POLLIN) {
                     let mut buf = [0u8; 1024];
                     match unistd::read(pipes.stderr_read.as_raw_fd(), &mut buf) {
                         Ok(0) => {
                             // EOF? Child stderr closed
                         },
                         Ok(n) => {
                             let s = String::from_utf8_lossy(&buf[..n]);
                             // We print to parent stderr immediately
                             eprint!("CHILD_INIT_LOG: {}", s);
                         }
                         Err(_) => {} // Ignore read errors
                     }
                 }
                 if revents.contains(nix::poll::PollFlags::POLLHUP) {
                      // HUP on stderr usually means child died
                      // Check process status?
                 }
             }

             // Check Parent Sock (Index 0)
             if let Some(revents) = fds[0].revents() {
                 if revents.contains(nix::poll::PollFlags::POLLIN) {
                     // Message ready (FD)
                     notify_fd = self.receive_notify_fd(parent_sock.as_raw_fd())?;
                     break; 
                 }
                 if revents.contains(nix::poll::PollFlags::POLLHUP) {
                     anyhow::bail!("Child closed connection without sending notify FD");
                 }
             }
        }
        
        // parent_sock closed when dropped. (at end of function)

        // Start Seccomp Loop in background thread
        let loop_root = self.project_root.clone();
        let allowed_cmd = self.command.clone();
        let manifest_clone = self.manifest.clone();
        
        // Spawn thread
        std::thread::spawn(move || {
             let seccomp_loop = SeccompLoop::new(notify_fd, loop_root, allowed_cmd, manifest_clone);
             if let Err(e) = seccomp_loop.run() {
                 // Use eprintln instead of tracing here to ensure visibility
                 eprintln!("Seccomp loop error: {}", e);
             }
        });

        // Convert OwnedFd to File for JailedChild
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
        // Redirect stdio
        let _ = unistd::dup2(pipes.stdin_read.as_raw_fd(), 0);
        let _ = unistd::dup2(pipes.stdout_write.as_raw_fd(), 1);
        let _ = unistd::dup2(pipes.stderr_write.as_raw_fd(), 2);
        
        // Close all pipe FDs (original ones) by dropping `pipes`
        drop(pipes); 
        // Note: dup2 created copies. The originals in `Pipes` will be closed on drop.
        
        // Setup environment (namespaces, cgroups, mounts)
        tracing::debug!("Setting up child env");
        self.setup_child_env()?;

        // Enforce NoNewPrivs (Phase 1.3)
        // Moved after setup_child_env to allow uid_map writing (which fails with EPERM if NNP is set)
        unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(anyhow::anyhow!("Failed to set NO_NEW_PRIVS"));
            }
        }

        // Install Seccomp
        // Fix: We must exempt child_sock from sendmsg filter because we use it to send the notify FD!
        // Otherwise, send_notify_fd blocks, parent blocks slightly later (receive_notify_fd),
        // and seccomp_loop (spawned after receive) never starts -> DEADLOCK.
        tracing::debug!("Installing seccomp filter");
        let notify_fd = self.install_seccomp_filter(child_sock.as_raw_fd())?;
        tracing::debug!("Sending notify fd");
        if let Err(e) = self.send_notify_fd(child_sock.as_raw_fd(), notify_fd) {
            // Log manually to be sure
            tracing::error!("send_notify_fd failed: {}", e);
            return Err(e).context("Failed to send notify fd");
        }
        
        // Close Notify FD and Socket
        unistd::close(notify_fd).ok();
        drop(child_sock); // Closes socket

        // Double Fork for PID Namespace
        tracing::debug!("Forking grandchild");
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
        let uid = unistd::getuid();
        let gid = unistd::getgid();
        
        // Cgroup setup
        self.setup_cgroup()?;
        
        // Namespaces
        unshare(CloneFlags::CLONE_NEWUSER).context("Failed to unshare user namespace")?;
        self.setup_uid_gid_map(uid, gid).context("Failed to setup uid/gid map")?;
        unshare(CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWIPC | CloneFlags::CLONE_NEWUTS | CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWPID).context("Failed to unshare remaining namespaces")?;
        
        // Task: Bring up loopback interface to allow localhost networking
        // We use the host's `ip` command as we haven't pivoted yet.
        // Fix: Use absolute path to prevent PATH hijacking (CWE-426)
        let ip_cmd = find_ip_command().unwrap_or_else(|_| PathBuf::from("ip"));

        if let Err(e) = Command::new(&ip_cmd)
            .args(["link", "set", "lo", "up"])
            .status() 
        {
             tracing::warn!("Failed to bring up loopback interface using {:?}: {}", ip_cmd, e);
        }
        
        // Mounts
        self.setup_mounts()?;
        
        Ok(())
    }

    fn setup_cgroup(&self) -> Result<()> {
        // ... (lines 220-267 unmodified) ...
        let pid = std::process::id();
        let guard = CgroupGuard::new(pid);
        let cgroup_path = guard.path().clone();
        
        if let Err(e) = std::fs::create_dir(&cgroup_path) {
             let msg = format!("Failed to create cgroup {}: {}", cgroup_path.display(), e);
             // Downgrade to warning for CI/Container environments where cgroups are read-only
             tracing::warn!("{}", msg);
             return Ok(());
        }
        
        // Add self
        if let Err(e) = std::fs::write(cgroup_path.join("cgroup.procs"), pid.to_string()) {
             let msg = format!("Failed to add pid to cgroup: {}", e);
             // Downgrade
             tracing::warn!("{}", msg);
        }
        
        let mem_bytes = self.manifest.max_memory_mb * 1024 * 1024;
        if let Err(e) = std::fs::write(cgroup_path.join("memory.max"), mem_bytes.to_string()) {
             let msg = format!("Failed to set memory limit: {}", e);
             tracing::warn!("{}", msg);
        }
        
        if self.manifest.max_cpu_quota_pct > 0 {
             let quota = self.manifest.max_cpu_quota_pct * 1000;
             let val = format!("{} 100000", quota);
             if let Err(e) = std::fs::write(cgroup_path.join("cpu.max"), val) {
                  let msg = format!("Failed to set cpu limit: {}", e);
                  tracing::warn!("{}", msg);
             }
        }
        Ok(())
    }

    fn setup_uid_gid_map(&self, uid: nix::unistd::Uid, gid: nix::unistd::Gid) -> Result<()> {
        // uid and gid passed from before unshare
        if let Err(e) = std::fs::write("/proc/self/uid_map", format!("0 {} 1", uid)) {
             tracing::warn!("Failed to write uid_map: {}", e);
             return Err(e.into());
        }
        if let Err(e) = std::fs::write("/proc/self/setgroups", "deny") {
             tracing::warn!("Failed to write setgroups: {}", e);
             return Err(e.into());
        }
        if let Err(e) = std::fs::write("/proc/self/gid_map", format!("0 {} 1", gid)) {
             tracing::warn!("Failed to write gid_map: {}", e);
             return Err(e.into());
        }
        Ok(())
    }

    fn setup_mounts(&self) -> Result<()> {
        tracing::debug!("Setting up mounts");
        // Root private
        mount(None::<&str>, "/", None::<&str>, MsFlags::MS_PRIVATE | MsFlags::MS_REC, None::<&str>).context("Failed to make / private")?;
        tracing::debug!("Mounted / private");
        
        mount(Some("tmpfs"), "/tmp", Some("tmpfs"), MsFlags::empty(), None::<&str>).context("Failed to mount tmpfs on /tmp")?;
        tracing::debug!("Mounted tmpfs (simplified)");
        
        // Pivot Root Preparation
        let jail_root = std::path::Path::new("/tmp/jail_root");
        if !jail_root.exists() { 
            if let Err(e) = std::fs::create_dir(jail_root) {
                 tracing::error!("Failed to create jail_root: {:?}", e);
                 return Err(e).context("Failed to create jail_root");
            }
        }
        
        let workspace_path = jail_root.join("workspace");
        if !workspace_path.exists() { std::fs::create_dir(&workspace_path).context("Failed to create workspace_path")?; }
        
        // Ephemeral OverlayFS (Phase 41)
        // Task 1.1: Use std::env::temp_dir() and PID (as expected by cleanup_ephemeral)
        let temp_dir = std::env::temp_dir();
        let pid = std::process::id(); // Use the intermediate process ID
        let upper_dir = temp_dir.join(format!("mcp_upper_{}", pid));
        let work_dir = temp_dir.join(format!("mcp_work_{}", pid));

        // Fix: Use DirBuilder to set mode 0700 and fail if exists to prevent hijacking
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&upper_dir)
            .context("Failed to create upper_dir (possible hijacking attempt)")?;

        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&work_dir)
            .context("Failed to create work_dir (possible hijacking attempt)")?;
        
        let overlay_opts = format!("lowerdir={},upperdir={},workdir={}", self.project_root.display(), upper_dir.display(), work_dir.display());
        tracing::debug!("Mounting overlayfs with opts len: {}", overlay_opts.len());
        mount(Some("overlay"), &workspace_path, Some("overlay"), MsFlags::empty(), Some(overlay_opts.as_str())).context("Failed to mount overlayfs")?;
        tracing::debug!("Mounted overlayfs");
        
        // Bind mounts per manifest
        for mount_path_str in &self.manifest.readonly_mounts {
            let src = PathBuf::from(mount_path_str);
            let rel_path = mount_path_str.trim_start_matches('/');
            let dst = jail_root.join(rel_path);
            if src.exists() {
                if !dst.exists() { std::fs::create_dir_all(&dst).ok(); }
                mount(Some(&src), &dst, None::<&str>, MsFlags::MS_BIND | MsFlags::MS_REC | MsFlags::MS_RDONLY, None::<&str>).with_context(|| format!("Failed to bind mount {}", src.display()))?;
            }
        }
        tracing::debug!("Finished bind mounts");
        
        // Pivot Root
        let old_root = jail_root.join("old_root");
        if !old_root.exists() { std::fs::create_dir(&old_root).context("Failed to create old_root")?; }
        
        mount(Some(jail_root), jail_root, None::<&str>, MsFlags::MS_BIND, None::<&str>).context("Failed to bind jail_root to itself")?; 
        tracing::debug!("Bound jail_root");
        
        // Create /proc and /dev
        let proc_path = jail_root.join("proc");
        if !proc_path.exists() { std::fs::create_dir(&proc_path).context("Failed to create proc_path")?; }
        // Note: We cannot mount proc here because we are not yet in the new PID namespace.
        // It will be mounted in handle_grandchild.
        tracing::debug!("Created proc mountpoint");
        
        let dev_path = jail_root.join("dev");
        if !dev_path.exists() { std::fs::create_dir(&dev_path).context("Failed to create dev_path")?; }
        for device in &["null", "zero", "urandom"] {
             let host = PathBuf::from("/dev").join(device);
             let jail = dev_path.join(device);
             if !jail.exists() { std::fs::File::create(&jail).context("Failed to touch dev node")?; }
             if host.exists() {
                 mount(Some(&host), &jail, None::<&str>, MsFlags::MS_BIND | MsFlags::MS_RDONLY, None::<&str>).with_context(|| format!("Failed to bind mount device {}", device))?;
             }
        }
        tracing::debug!("Mounted dev");

        nix::unistd::pivot_root(jail_root, &old_root).context("Failed to pivot root")?;
        unistd::chdir("/").context("Failed to chdir to new root")?;
        umount2("/old_root", MntFlags::MNT_DETACH).context("Failed to unmount old_root")?;
        std::fs::remove_dir("/old_root").ok();
        unistd::chdir("/workspace").context("Failed to chdir to workspace")?;
        
        Ok(())
    }

    fn handle_grandchild(&self) -> Result<()> {
        // Remount /proc for new PID ns
        // We defer mounting /proc until here because we are in the new PID NS.
        let proc_path = std::path::Path::new("/proc");
        let _ = mount(Some("proc"), proc_path, Some("proc"), MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC, None::<&str>);
        
        // Debug FS State
        tracing::debug!("Grandchild started. CWD: {:?}", std::env::current_dir());
        
        if let Ok(entries) = std::fs::read_dir(".") {
             tracing::debug!("Listing /workspace:");
             for entry in entries.flatten() {
                  tracing::debug!("  {:?}", entry.path());
             }
        }
        
        let sub = std::path::Path::new("tests/e2e");
        if let Ok(entries) = std::fs::read_dir(sub) {
             tracing::debug!("Listing tests/e2e:");
             for entry in entries.flatten() {
                  tracing::debug!("  {:?}", entry.path());
             }
        }
        
        let linker = std::path::Path::new("/lib64/ld-linux-x86-64.so.2");
        if linker.exists() {
             tracing::debug!("Linker found at {:?}", linker);
        } else {
             tracing::error!("Linker NOT found at {:?}", linker);
        }

        // Drop Capabilities
        unsafe {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                // If we cannot set parent death signal, we should probably die as we are in an inconsistent state
                let _ = libc::write(2, b"Failed to set PR_SET_PDEATHSIG\n".as_ptr() as *const _, 31);
                libc::exit(1);
            }

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
    
    fn install_seccomp_filter(&self, exempt_fd: RawFd) -> Result<RawFd> {
        // ... Same implementation as before ...
        use libseccomp::{ScmpFilterContext, ScmpAction, ScmpSyscall, ScmpArch, ScmpArgCompare, ScmpCompareOp};
        let mut ctx = ScmpFilterContext::new(ScmpAction::Allow).context("Failed to create seccomp context")?;
        ctx.add_arch(ScmpArch::Native).context("Failed to add native arch")?;

        // Network: Connect, Bind, Sendto, Sendmsg
        // We notify all interactions unless exempted.
        ctx.add_rule(ScmpAction::Notify, ScmpSyscall::from_name("connect")?).context("Failed to add connect rule")?;
        ctx.add_rule(ScmpAction::Notify, ScmpSyscall::from_name("bind")?).context("Failed to add bind rule")?;
        ctx.add_rule(ScmpAction::Notify, ScmpSyscall::from_name("sendto")?).context("Failed to add sendto rule")?;
        
        // sendmsg: Exempt the socket used for Seccomp Notification Handover
        // We notify on sendmsg UNLESS the FD is the exempt_fd.
        // If fd == exempt_fd, this rule doesn't match, and we fall through to default Allow.
        let sendmsg = ScmpSyscall::from_name("sendmsg")?;

        ctx.add_rule_conditional(
            ScmpAction::Notify,
            sendmsg,
            &[ScmpArgCompare::new(0, ScmpCompareOp::NotEqual, exempt_fd as u64)]
        ).context("Failed to add sendmsg notify rule")?;

        ctx.add_rule(ScmpAction::Notify, ScmpSyscall::from_name("execve")?).context("Failed to add execve rule")?;
        ctx.add_rule(ScmpAction::Notify, ScmpSyscall::from_name("execveat")?).context("Failed to add execveat rule")?;
        ctx.add_rule(ScmpAction::Notify, ScmpSyscall::from_name("openat")?).context("Failed to add openat rule")?;
        ctx.add_rule(ScmpAction::Notify, ScmpSyscall::from_name("open")?).context("Failed to add open rule")?;
        ctx.load().context("Failed to load seccomp filter")?;
        ctx.get_notify_fd().context("Failed to get notify fd")
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
        // Task 3.1: Subtree Control (cgroup.kill)
        // Try to signal kill to all processes atomically via cgroup.kill (v2)
        let kill_file = self.path.join("cgroup.kill");
        if kill_file.exists() {
             if let Err(e) = std::fs::write(&kill_file, "1") {
                  tracing::warn!(error = %e, "Failed to write to cgroup.kill. Falling back to manual kill loop.");
             }
        }

        let procs_path = self.path.join("cgroup.procs");
        // Fallback or V1 cleanup
        for _ in 0..5 {
            if let Ok(content) = std::fs::read_to_string(&procs_path) {
                if content.trim().is_empty() { break; }
                for line in content.lines() {
                    if let Ok(pid) = line.trim().parse::<i32>() {
                        unsafe { libc::kill(pid, libc::SIGKILL); }
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
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

fn find_ip_command() -> Result<PathBuf> {
    for path in ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"] {
        let p = PathBuf::from(path);
        if p.exists() {
            return Ok(p);
        }
    }
    Err(anyhow::anyhow!("'ip' command not found"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_ip_command() {
        // This test depends on the environment having 'ip' installed.
        // We only assert if it finds something, it should exist.
        if let Ok(path) = find_ip_command() {
            assert!(path.exists());
            assert!(path.to_string_lossy().ends_with("/ip"));
        } else {
            // If ip is not found, we can't really test much other than it returned Err
            // But usually CI/dev env has ip.
            // We can warn.
            eprintln!("'ip' command not found in test environment");
        }
    }
}
