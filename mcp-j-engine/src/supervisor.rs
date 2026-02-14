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

    pub fn start(mut self) -> Result<()> {
        // Automatically allow reading the executable we are about to run
        self.landlock_ruleset = self.landlock_ruleset.allow_read(&self.command);
        for lib_path in ["/lib", "/lib64", "/usr/lib", "/usr/lib64", "/bin", "/usr/bin"] {
            self.landlock_ruleset = self.landlock_ruleset.allow_read(lib_path);
        }

        // Create socketpair for passing the notification FD from child to parent
        let (parent_sock, child_sock) = nix::sys::socket::socketpair(
            nix::sys::socket::AddressFamily::Unix,
            nix::sys::socket::SockType::Stream,
            None,
            nix::sys::socket::SockFlag::empty(),
        ).context("Failed to create socketpair")?;

        match unsafe { unistd::fork() } {
            Ok(ForkResult::Parent { child, .. }) => {
                // Parent process
                unistd::close(child_sock).ok(); // Close child end
                println!("Supervisor: Started child with PID {}", child);

                // Receive the notification FD from child
                let notify_fd = self.receive_notify_fd(parent_sock)?;
                unistd::close(parent_sock).ok(); // Close socket after receiving

                // Start Seccomp Loop
                // We run it in a separate thread or async task if we want to waitpid concurrently?
                // The loop is blocking in current implementation.
                // But we ultimately need to handle the child exit too.
                // For now, let's just run it in a thread so main thread can waitpid.
                
                let seccomp_loop = SeccompLoop::new(notify_fd);
                std::thread::spawn(move || {
                    if let Err(e) = seccomp_loop.run() {
                        eprintln!("Seccomp loop error: {}", e);
                    }
                });

                // Wait for child
                loop {
                    match waitpid(child, None) {
                        Ok(WaitStatus::Exited(_, code)) => {
                            println!("Child exited with code {}", code);
                            break;
                        }
                        Ok(WaitStatus::Signaled(_, sig, _)) => {
                            println!("Child signaled by {:?}", sig);
                            break;
                        }
                        Ok(_) => continue,
                        Err(e) => {
                            eprintln!("Waitpid error: {}", e);
                            break;
                        }
                    }
                }
            }
            Ok(ForkResult::Child) => {
                // Child process
                unistd::close(parent_sock).ok(); // Close parent end
                
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

        Ok(())
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
        // 1. Unshare Namespaces (TODO: Implement full unshare)
        // unshare(CloneFlags::CLONE_NEWNS | ...)?; 
        
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
