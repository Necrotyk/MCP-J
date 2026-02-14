use anyhow::{Result, Context};
use std::os::unix::io::RawFd;
use libc::{c_int, ioctl, pid_t};
use crate::seccomp_sys::{
    seccomp_notif, seccomp_notif_resp,
    SECCOMP_IOCTL_NOTIF_RECV, SECCOMP_IOCTL_NOTIF_SEND, 
    SECCOMP_USER_NOTIF_FLAG_CONTINUE,
    seccomp_notif_addfd, SECCOMP_IOCTL_NOTIF_ADDFD
};
use nix::sys::uio::{process_vm_readv, RemoteIoVec};
use std::io::IoSliceMut;

pub struct SeccompLoop {
    notify_fd: RawFd,
}

impl SeccompLoop {
    pub fn new(notify_fd: RawFd) -> Self {
        Self { notify_fd }
    }

    // Helper to read memory from the tracee
    fn read_tracee_memory(&self, pid: pid_t, addr: u64, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let local_iov = [IoSliceMut::new(&mut buf)];
        let remote_iov = [RemoteIoVec { base: addr as usize, len }];
        
        let n = process_vm_readv(nix::unistd::Pid::from_raw(pid), &local_iov, &remote_iov)?;
        if n != len {
            // Partial read?
            // anyhow::bail!("Partial read from tracee memory");
        }
        Ok(buf)
    }

    pub fn run(&self) -> Result<()> {
        println!("Seccomp loop running on FD: {}", self.notify_fd);
        
        loop {
            // Receive notification
            // We must zero initialize the struct as per C conventions generally, 
            // although RECV overwrites it.
            let mut req: seccomp_notif = unsafe { std::mem::zeroed() };
            
            // ioctl call
            let ret = unsafe { libc::ioctl(self.notify_fd, SECCOMP_IOCTL_NOTIF_RECV, &mut req) };
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                // Handle ENOENT if the target process died?
                // If checking for closed connection, handle it gracefully.
                return Err(anyhow::anyhow!("ioctl RECV failed: {}", err));
            }

            // Process
            let resp = self.handle_request(&req)?;

            // Send response
            let ret = unsafe { libc::ioctl(self.notify_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) };
            if ret < 0 {
                 let err = std::io::Error::last_os_error();
                 // If process died between RECV and SEND, acceptable.
                 if err.raw_os_error() == Some(libc::ENOENT) {
                     continue;
                 }
                 return Err(anyhow::anyhow!("ioctl SEND failed: {}", err));
            }
        }
    }

    fn handle_request(&self, req: &seccomp_notif) -> Result<seccomp_notif_resp> {
        let syscall = req.data.nr as i64;
        
        // Match syscalls
        // Note: libc::SYS_* are usually c_long (i64 or i32)
        // We cast to i64 for comparison
        
        match syscall {
            libc::SYS_connect => self.handle_connect(req),
            libc::SYS_execve => self.handle_execve(req),
            libc::SYS_bind => self.handle_bind(req),
            libc::SYS_openat => self.handle_openat(req), // If intercepted
            _ => {
               // Allow others by default for now (e.g. read, write)
               Ok(self.resp_continue(req))
            }
        }
    }

    fn resp_continue(&self, req: &seccomp_notif) -> seccomp_notif_resp {
        seccomp_notif_resp {
            id: req.id,
            val: 0,
            error: 0,
            flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
        }
    }
    
    fn resp_error(&self, req: &seccomp_notif, error: i32) -> seccomp_notif_resp {
        seccomp_notif_resp {
            id: req.id,
            val: 0,
            error,
            flags: 0, // Not continue, return error
        }
    }

    fn handle_connect(&self, req: &seccomp_notif) -> Result<seccomp_notif_resp> {
        // Validation logic for connect
        // args[0] = sockfd
        // args[1] = struct sockaddr *addr
        // args[2] = addrlen
        
        let addr_ptr = req.data.args[1];
        let addr_len = req.data.args[2] as usize;
        
        // Read sockaddr from tracee
        // We need the pid from req.pid, not self.pid (which is supervisor)
        // req.pid is u32, pid_t is i32 usually.
        let tracee_pid = req.pid as pid_t;
        
        // Limit addr_len to avoid huge allocation
        if addr_len > 128 { // sockaddr_storage is ~128 bytes
             return Ok(self.resp_error(req, libc::EINVAL));
        }

        let sockaddr_buf = match self.read_tracee_memory(tracee_pid, addr_ptr, addr_len) {
            Ok(buf) => buf,
            Err(_) => return Ok(self.resp_error(req, libc::EFAULT)),
        };
        
        // Parse sockaddr
        // For now, allow everything
        // TODO: Parse IP/Port and validate against allowlist
        
        Ok(self.resp_continue(req))
    }

    fn handle_execve(&self, req: &seccomp_notif) -> Result<seccomp_notif_resp> {
        // Prevent arbitrary execve
        // Only allow if it matches specific patterns?
        // Or if we are in expected state?
        // Supervisor loop handles initial exec, subsequent execs might be dangerous.
        // For now, allow.
        Ok(self.resp_continue(req))
    }

    fn handle_bind(&self, req: &seccomp_notif) -> Result<seccomp_notif_resp> {
        Ok(self.resp_continue(req))
    }

    fn handle_openat(&self, req: &seccomp_notif) -> Result<seccomp_notif_resp> {
        // Handle atomic open with emulation
        // For now, allow (continue) as stub, but we have inject_fd ready.
        Ok(self.resp_continue(req))
    }

    fn inject_fd(&self, req: &seccomp_notif, fd: RawFd) -> Result<RawFd> {
        let mut addfd = seccomp_notif_addfd {
            id: req.id,
            flags: 0,
            srcfd: fd as u32,
            newfd: 0,
            newfd_flags: 0,
        };
        
        let ret = unsafe { libc::ioctl(self.notify_fd, SECCOMP_IOCTL_NOTIF_ADDFD, &mut addfd) };
        if ret < 0 {
             let err = std::io::Error::last_os_error();
             return Err(anyhow::anyhow!("ioctl ADDFD failed: {}", err));
        }
        
        // ret is the new FD in remote process.
        Ok(ret as RawFd)
    }
}


