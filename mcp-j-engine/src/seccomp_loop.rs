use anyhow::{Result, Context};
use std::os::unix::io::{RawFd, AsRawFd};
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
        
        let addr_ptr = req.data.args[1];
        let addr_len = req.data.args[2] as usize;
        let tracee_pid = req.pid as pid_t;
        
        if addr_len > 128 { 
             return Ok(self.resp_error(req, libc::EINVAL));
        }
        
        // Read sockaddr struct from tracee memory
        let buf = match self.read_tracee_memory(tracee_pid, addr_ptr, addr_len) {
            Ok(b) => b,
            Err(_) => return Ok(self.resp_error(req, libc::EFAULT)),
        };

        // Check address family
        // sockaddr structure: first 2 bytes are family (sa_family_t)
        if buf.len() < 2 {
             return Ok(self.resp_error(req, libc::EINVAL));
        }
        
        // We assume little-endian for now, or native endian.
        // sa_family is usually u16.
        let sa_family = u16::from_ne_bytes([buf[0], buf[1]]);
        
        match sa_family as i32 {
            libc::AF_UNIX => {
                 // Allow local unix sockets?
                 // Maybe filter by path if we parse it.
                 // For now, allow AF_UNIX for IPC.
                 Ok(self.resp_continue(req))
            },
            libc::AF_INET => {
                 // IPv4
                 // sockaddr_in: family (2), port (2), addr (4), zero (8)
                 if buf.len() < 6 {
                      return Ok(self.resp_error(req, libc::EINVAL));
                 }
                 
                 let port = u16::from_be_bytes([buf[2], buf[3]]);
                 let ip_bytes = [buf[4], buf[5], buf[6], buf[7]];
                 // let ip = std::net::Ipv4Addr::from(ip_bytes);
                 
                 // TODO: Validate IP/Port against policy
                 // Example: Prevent internal networks/metadata service (169.254.169.254)
                 
                 // CVE-2025-6514 remediation: Block access to metadata service
                 if ip_bytes == [169, 254, 169, 254] {
                      eprintln!("Blocked access to metadata service!");
                      return Ok(self.resp_error(req, libc::EACCES));
                 }
                 
                 Ok(self.resp_continue(req))
            },
            libc::AF_INET6 => {
                 // IPv6
                 // Block for now or stricter checks
                 Ok(self.resp_continue(req))
            },
            _ => {
                 // Deny unknown families
                 Ok(self.resp_error(req, libc::EAFNOSUPPORT))
            }
        }
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
        // Implement atomic open using openat2 + inject_fd
        
        let dirfd = req.data.args[0] as i32;
        let path_ptr = req.data.args[1];
        let _flags = req.data.args[2];
        let _mode = req.data.args[3];
        let tracee_pid = req.pid as pid_t;
        
        // 1. Read path string from tracee with robust handling (page boundaries)
        // We'll read in chunks until null terminator or max.
        let mut path_buf = Vec::new();
        let chunk_size = 256;
        let max_len = 4096;
        let mut current_addr = path_ptr as usize;
        let mut loop_count = 0;
        
        loop {
            if path_buf.len() >= max_len || loop_count > 20 {
                return Ok(self.resp_error(req, libc::ENAMETOOLONG));
            }
            
            // Determine distance to next page boundary to avoid partial read failure if crossing unmapped page?
            // Actually process_vm_readv handles crossing if pages are mapped. 
            // But if we hit an unmapped page at the end of a string, it might fail.
            // Better to read smaller chunks or use byte-by-byte if paranoid?
            // "process_vm_readv" returns success even for partial reads if the first part is good? 
            // No, it returns what it read.
            
            let mut buf = vec![0u8; chunk_size];
            let local_iov = [IoSliceMut::new(&mut buf)];
            let remote_iov = [RemoteIoVec { base: current_addr, len: chunk_size }];
            
            let n = match process_vm_readv(nix::unistd::Pid::from_raw(tracee_pid), &local_iov, &remote_iov) {
                Ok(n) => n,
                Err(_) => {
                    if path_buf.is_empty() {
                         return Ok(self.resp_error(req, libc::EFAULT));
                    }
                    0 // Stop reading if we hit an error but have some data (maybe null terminator is just before?)
                }
            };
            
            if n == 0 && path_buf.is_empty() {
                return Ok(self.resp_error(req, libc::EFAULT));
            }
            
            // Append and check for null
            let read_slice = &buf[..n];
            if let Some(pos) = read_slice.iter().position(|&b| b == 0) {
                path_buf.extend_from_slice(&read_slice[..pos]);
                break;
            } else {
                path_buf.extend_from_slice(read_slice);
                current_addr += n;
                if n < chunk_size {
                    // Short read (EOF?), but no null terminator found yet?
                    // String must be null terminated.
                    return Ok(self.resp_error(req, libc::EFAULT)); // Or EINVAL
                }
            }
            loop_count += 1;
        }

        let path_str = match std::str::from_utf8(&path_buf) {
            Ok(s) => s,
            Err(_) => return Ok(self.resp_error(req, libc::EINVAL)),
        };

        // 2. Resolve Root FD based on dirfd
        // If dirfd == AT_FDCWD (-100), we should use the sandbox root.
        // If dirfd is a valid FD, we should ensure it resolves to something inside the sandbox.
        // But since we control the injections, any FD the process has *should* be safe if we only injected safe FDs.
        // However, standard descriptors (0, 1, 2) are not directories.
        
        // For strict sandbox, we enforce that all resolution happens relative to our designated locked root.
        // We'll open "." of the supervisor as the effective root for now (assuming supervisor is chdir-ed or we configured it).
        // Spec says: "Map it to the enforced sandbox project root."
        
        let root_fd = if dirfd == -100 { // AT_FDCWD
             // Open the sandbox root. Ideally we cache this or pass it in SeccompLoop struct.
             // For now, safely open "."
             std::fs::File::open(".")
        } else {
             // If tracee supplies a dirfd, we must duplicate it to use it in openat2 in the supervisor?
             // No, `openat2` needs a dirfd in the SUPERVISOR's namespace.
             // The `dirfd` value provided in `req` is valid in the TRACEE's namespace.
             // We cannot use it directly!
             // We must fetch the FD from the tracee using `pidfd_getfd` (linux 5.6+) or `/proc/<pid>/fd/<fd>`.
             
             // Opening /proc/<pid>/fd/<fd> gives us a handle to the same file description.
             let proc_path = format!("/proc/{}/fd/{}", tracee_pid, dirfd);
             std::fs::File::open(proc_path)
        }.map_err(|e| anyhow::anyhow!("Failed to resolve dirfd: {}", e));

        let root_handle = match root_fd {
            Ok(f) => f,
            Err(_) => return Ok(self.resp_error(req, libc::EBADF)),
        };
        
        // 3. Perform safe open
        let file = match crate::fs_utils::safe_open_beneath(&root_handle, path_str) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("Blocked open access to {}: {}", path_str, e);
                return Ok(self.resp_error(req, libc::EACCES));
            }
        };
        
        // 4. Inject FD
        let injected_fd = self.inject_fd(req, file.as_raw_fd())?;
        
        Ok(seccomp_notif_resp {
            id: req.id,
            val: injected_fd as i64,
            error: 0,
            flags: 0,
        })
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


