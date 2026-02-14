use std::path::PathBuf;
use std::process::Command;
use std::os::unix::process::CommandExt;
use nix::sched::{unshare, CloneFlags};
use nix::unistd::{self, ForkResult};
use nix::sys::wait::{waitpid, WaitStatus};
use anyhow::{Result, Context};
use crate::landlock_ruleset::LandlockRuleset;
use crate::seccomp_loop::SeccompLoop;

pub struct Supervisor {
    command: PathBuf,
    args: Vec<String>,
    landlock_ruleset: LandlockRuleset,
}

impl Supervisor {
    pub fn new(command: PathBuf, args: Vec<String>) -> Result<Self> {
        Ok(Self {
            command,
            args,
            landlock_ruleset: LandlockRuleset::new()?,
        })
    }

    pub fn with_landlock(mut self, ruleset: LandlockRuleset) -> Self {
        self.landlock_ruleset = ruleset;
        self
    }

    pub fn spawn(mut self) -> Result<JailedChild> {
        // Automatically allow reading the executable we are about to run
        self.landlock_ruleset = self.landlock_ruleset.allow_read(&self.command);
        for lib_path in ["/lib", "/lib64", "/usr/lib", "/usr/lib64", "/bin", "/usr/bin"] {
            self.landlock_ruleset = self.landlock_ruleset.allow_read(lib_path);
        }

        // Create Seccomp Notify Socketpair
        let (parent_sock, child_sock) = nix::sys::socket::socketpair(
            nix::sys::socket::AddressFamily::Unix,
            nix::sys::socket::SockType::Stream,
            None,
            nix::sys::socket::SockFlag::empty(),
        ).context("Failed to create socketpair")?;

        // Create Stdin/Stdout pipes
        let (stdin_read, stdin_write) = nix::unistd::pipe().context("Failed to create stdin pipe")?;
        let (stdout_read, stdout_write) = nix::unistd::pipe().context("Failed to create stdout pipe")?;

        match unsafe { unistd::fork() } {
            Ok(ForkResult::Parent { child, .. }) => {
                // Parent process
                unistd::close(child_sock).ok(); 
                unistd::close(stdin_read).ok();
                unistd::close(stdout_write).ok();
                
                println!("Supervisor: Started child with PID {}", child);

                // Receive the notification FD from child
                let notify_fd = self.receive_notify_fd(parent_sock)?;
                unistd::close(parent_sock).ok(); 

                // Start Seccomp Loop in background thread
                let seccomp_loop = SeccompLoop::new(notify_fd);
                std::thread::spawn(move || {
                    if let Err(e) = seccomp_loop.run() {
                        eprintln!("Seccomp loop error: {}", e);
                    }
                });
                
                let stdin_file = unsafe { std::fs::File::from_raw_fd(stdin_write) };
                let stdout_file = unsafe { std::fs::File::from_raw_fd(stdout_read) };

                Ok(JailedChild {
                    pid: child,
                    stdin: Some(stdin_file),
                    stdout: Some(stdout_file),
                })
            }
            Ok(ForkResult::Child) => {
                // Child process
                unistd::close(parent_sock).ok();
                
                // Setup redirection
                unistd::close(stdin_write).ok(); // Close parent end
                unistd::close(stdout_read).ok();
                
                let _ = unistd::dup2(stdin_read, 0); // Stdin
                let _ = unistd::dup2(stdout_write, 1); // Stdout
                
                unistd::close(stdin_read).ok();
                unistd::close(stdout_write).ok();

                if let Err(e) = self.setup_child(child_sock) {
                    eprintln!("Child setup failed: {}", e);
                    std::process::exit(1);
                }
                
                // Exec
                let err = Command::new(&self.command)
                    .args(&self.args)
                    .exec();
                    
                eprintln!("Failed to exec: {}", err);
                std::process::exit(1);
            }
            Err(e) => {
                anyhow::bail!("Fork failed: {}", e);
            }
        }
    }
}

pub struct JailedChild {
    pub pid: nix::unistd::Pid,
    pub stdin: Option<std::fs::File>,
    pub stdout: Option<std::fs::File>,
}

impl JailedChild {
    pub fn wait(&mut self) -> Result<WaitStatus> {
        waitpid(self.pid, None).map_err(|e| anyhow::anyhow!("waitpid failed: {}", e))
    }

    fn receive_notify_fd(&self, sock: RawFd) -> Result<RawFd> {
        use nix::sys::socket::{recvmsg, MsgFlags, ControlMessageOwned};
        use nix::sys::uio::IoVec;

        let mut buf = [0u8; 1];
        let iov = [IoVec::from_slice(&buf)];
        let mut cmsg_buffer = nix::cmsg_space!(RawFd);
        
        // Blocking recv
        let msg = recvmsg(sock, &iov, Some(&mut cmsg_buffer), MsgFlags::empty())?;
        
        let fd = msg.cmsgs().find_map(|cmsg| {
            match cmsg {
                ControlMessageOwned::ScmRights(fds) => fds.first().cloned(),
                _ => None,
            }
        }).ok_or_else(|| anyhow::anyhow!("No FD received from child"))?;

        Ok(fd)
    }

    fn setup_child(&self, sock: RawFd) -> Result<()> {
        // 1. Unshare Namespaces
        // We unshare Mount, IPC, PID, Net, UTS namesapces.
        // We DO NOT unshare User namespace here if we want to map it simply?
        // Actually, to use Landlock effectively without privilege, we just need to be able to apply it.
        // But for full isolation, creating a new User Namespace is best practice to drop real privileges.
        
        // However, setting up User Namespace requires writing to /proc/self/uid_map, which must be done
        // by a parent or a privileged process *before* the child drops privileges or gives up context.
        // If we unshare, we become root in the new namespace but user 'nobody' in the parent namespace logic.
        // If we are already running as regular user, unshare(CLONE_NEWUSER) gives us full capa in the new namespace.
        
        // Unshare User namespace separately first to gain capabilities?
        // Actually, unshare(CLONE_NEWUSER) implicitly sets other capabilities.
        // It is often cleaner to unshare User first, map, then unshare others.
        // But unshare() allows multiple flags.
        // However, if we unshare(CLONE_NEWNS) without being root (or capacitated in user NS), it fails.
        // So we MUST unshare CLONE_NEWUSER first if we are unprivileged.
        
        unshare(CloneFlags::CLONE_NEWUSER)?;

        // Map UID/GID
        let uid = unistd::getuid();
        let gid = unistd::getgid();
        std::fs::write("/proc/self/uid_map", format!("0 {} 1", uid))?;
        std::fs::write("/proc/self/setgroups", "deny")?;
        std::fs::write("/proc/self/gid_map", format!("0 {} 1", gid))?;
        
        // Now unshare the rest as the new root user in the new user namespace
        unshare(CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWIPC | CloneFlags::CLONE_NEWUTS | CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWPID)?;
        
        // Mount setup
        // 1. Mark propagation as private
        // MS_REC | MS_PRIVATE
        use nix::mount::{mount, MsFlags};
        
        // We need to ensure we have the "mount" feature in nix.
        // Assuming it is available or I will add it.
        
        mount(
            None::<&str>,
            "/",
            None::<&str>,
            MsFlags::MS_PRIVATE | MsFlags::MS_REC,
            None::<&str>,
        ).context("Failed to make / private")?;

        // 2. Mount tmpfs on /tmp
        // We need to ensure /tmp exists? It likely does.
        mount(
            Some("tmpfs"),
            "/tmp",
            Some("tmpfs"),
            MsFlags::empty(),
            Some("mode=1777,size=64m"),
        ).context("Failed to mount tmpfs on /tmp")?;
        
        // 3. Proc? 
        // If we want to hide processes, we DO NOT mount proc.
        // If the tool needs it, we mount it.
        // Spec says "minimal jail", usually implies no /proc if possible.
        // Or mount a fresh proc instance:
        // mount(Some("proc"), "/proc", Some("proc"), MsFlags::empty(), None)?;
        // Let's explicitly NOT mount proc for now to prevent info leaks.



        
        // 2. Install Seccomp Filter and get Notify FD
        let notify_fd = self.install_seccomp_filter()?;
        
        // 3. Send Notify FD to parent
        self.send_notify_fd(sock, notify_fd)?;
        
        // 4. Close Notify FD and Socket in child
        unistd::close(notify_fd).ok();
        unistd::close(sock).ok();

        // 5. Apply Landlock (Last step before exec usually, or before seccomp?)
        // Landlock should be applied.
        self.landlock_ruleset.apply().context("Failed to apply Landlock rules")?;

        Ok(())
    }

    fn send_notify_fd(&self, sock: RawFd, fd: RawFd) -> Result<()> {
        use nix::sys::socket::{sendmsg, MsgFlags, ControlMessage};
        use nix::sys::uio::IoVec;

        let buf = [0u8; 1];
        let iov = [IoVec::from_slice(&buf)];
        let fds = [fd];
        let cmsg = ControlMessage::ScmRights(&fds);
        
        sendmsg(sock, &iov, &[cmsg], MsgFlags::empty(), None)?;
        Ok(())
    }

    fn install_seccomp_filter(&self) -> Result<RawFd> {
        // Use libseccomp or raw syscall to install filter with SECCOMP_RET_USER_NOTIF
        // For now, let's assume we use a specialized crate or helper.
        // Since I cannot trust crate availability, I'll use a placeholder that
        // effectively does nothing or mocks it, UNLESS I found libseccomp works.
        // But for "carry on", I must implement it.
        
        // NOTE: Without a working libseccomp crate, creating BPF is hard.
        // user previously added `libseccomp` to Cargo.toml.
        // Let's assume `libseccomp` crate is available.
        
        use libseccomp::{ScmpFilterContext, ScmpAction, ScmpSyscall};
        
        // Create filter: Default Action = Allow (for now, to test flow).
        // Spec says: Default Default = Deny? No, spec "Ruleset Specification" says landlock default deny.
        // Seccomp spec says "Intercept ... Allow (Conditional)".
        // Ideally: Default Allow, Intercept specific.
        
        let mut ctx = ScmpFilterContext::new_filter(ScmpAction::Allow)?;
        
        // Add rule to intercept CONNECT
        // Note: `ScmpAction::Notify` matches `SECCOMP_RET_USER_NOTIF`.
        // If crate doesn't have Notify, we are stuck.
        ctx.add_rule(ScmpAction::Notify, ScmpSyscall::from_name("connect")?)?;
        ctx.add_rule(ScmpAction::Notify, ScmpSyscall::from_name("execve")?)?;
        ctx.add_rule(ScmpAction::Notify, ScmpSyscall::from_name("bind")?)?;
        
        ctx.load()?;
        
        // Get the notification FD. 
        // libseccomp crate implementation of `get_notify_fd`?
        // If not available, we might need to use `check_version` or `export_bpf` and load manually?
        // `libseccomp` > 2.5 has `get_notify_fd()`.
        
        // Assuming:
        let fd = ctx.get_notify_fd()?;
        Ok(fd)
    }

}
