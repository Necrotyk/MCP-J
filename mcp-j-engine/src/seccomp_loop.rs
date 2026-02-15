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

use std::path::PathBuf;

#[derive(Clone)]
pub struct SeccompLoop {
    notify_fd: RawFd,
    project_root: PathBuf,
    allowed_command: PathBuf,
}

impl SeccompLoop {
    pub fn new(notify_fd: RawFd, project_root: PathBuf, allowed_command: PathBuf) -> Self {
        Self { notify_fd, project_root, allowed_command }
    }

    // Helper to read memory from the tracee
    fn read_tracee_memory(&self, pid: pid_t, addr: u64, len: usize) -> Result<Vec<u8>> {
        
        let mut buf = vec![0u8; len];
        let mut local_iov = [IoSliceMut::new(&mut buf)];
        let remote_iov = [RemoteIoVec { base: addr as usize, len }];
        
        let n = process_vm_readv(nix::unistd::Pid::from_raw(pid), &mut local_iov, &remote_iov)?;
        if n != len {
            // Partial read?
            // anyhow::bail!("Partial read from tracee memory");
        }
        Ok(buf)
    }

    // Helper to read a string from tracee memory (page aligned)
    fn read_string_tracee(&self, pid: pid_t, addr: u64) -> Result<String> {
        let mut path_buf = Vec::new();
        let max_len = 4096;
        let page_size = 4096;
        let mut current_addr = addr as usize;
        
        loop {
            if path_buf.len() >= max_len {
                return Err(anyhow::anyhow!("String too long"));
            }
            
            // Calculate distance to next page boundary
            let bytes_to_boundary = page_size - (current_addr % page_size);
            let chunk_size = std::cmp::min(bytes_to_boundary, max_len - path_buf.len());
            
            let mut buf = vec![0u8; chunk_size];
            let mut local_iov = [IoSliceMut::new(&mut buf)];
            let remote_iov = [RemoteIoVec { base: current_addr, len: chunk_size }];
            
            let n = match process_vm_readv(nix::unistd::Pid::from_raw(pid), &mut local_iov, &remote_iov) {
                Ok(n) => n,
                Err(_) => {
                    if path_buf.is_empty() { return Err(anyhow::anyhow!("Failed to read memory")); }
                    0 
                }
            };
            
            if n == 0 && path_buf.is_empty() {
                return Err(anyhow::anyhow!("Failed to read memory, 0 bytes"));
            }
            
            let read_slice = &buf[..n];
            if let Some(pos) = read_slice.iter().position(|&b| b == 0) {
                path_buf.extend_from_slice(&read_slice[..pos]);
                break;
            } else {
                path_buf.extend_from_slice(read_slice);
                current_addr += n;
                if n < chunk_size {
                    // Partial read (EOF/EFAULT on remote?)
                    // If we didn't find nul, and read less than expected, it's likely error unless string ends exactly at end of readable mapping without nul?
                    // C strings must be nul terminated.
                    return Err(anyhow::anyhow!("String not null terminated within readable memory"));
                }
            }
        }

        let s = std::str::from_utf8(&path_buf).map_err(|_| anyhow::anyhow!("Invalid UTF-8"))?;
        Ok(s.to_string())
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
        
        // Strict length checking for known families
        if addr_len < std::mem::size_of::<libc::sa_family_t>() {
             return Ok(self.resp_error(req, libc::EINVAL));
        }
        
        if addr_len > 128 { // Max sockaddr size usually
             return Ok(self.resp_error(req, libc::EINVAL));
        }

        let buf = match self.read_tracee_memory(tracee_pid, addr_ptr, addr_len) {
            Ok(b) => b,
            Err(_) => return Ok(self.resp_error(req, libc::EFAULT)),
        };

        if buf.len() < 2 {
             return Ok(self.resp_error(req, libc::EINVAL));
        }
        
        let sa_family = u16::from_ne_bytes([buf[0], buf[1]]);
        
        match sa_family as i32 {
            libc::AF_UNIX => {
                 // Allow local unix sockets?
                 // User didn't specify, but often needed.
                 // "If local loopback is required... whitelist 127.0.0.1... drop all other routable address spaces".
                 // AF_UNIX is local. I'll allow it for now or stick to strict interpretations.
                 // "drop all other routable address spaces". UNIX isn't routable IP space.
                 Ok(self.resp_continue(req))
            },
            libc::AF_INET => {
                 if addr_len != std::mem::size_of::<libc::sockaddr_in>() {
                      return Ok(self.resp_error(req, libc::EINVAL));
                 }
                 
                 let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
                 if buf.len() < std::mem::size_of::<libc::sockaddr_in>() {
                     return Ok(self.resp_error(req, libc::EINVAL));
                 }
                 
                 unsafe {
                     std::ptr::copy_nonoverlapping(
                         buf.as_ptr(), 
                         &mut sin as *mut _ as *mut u8, 
                         std::mem::size_of::<libc::sockaddr_in>()
                     );
                 }
                 
                 let ip_raw = u32::from_be(sin.sin_addr.s_addr);
                 
                 // Whitelist 127.0.0.1 (0x7F000001)
                 let localhost: u32 = 0x7F000001;
                 
                 if ip_raw == localhost {
                      Ok(self.resp_continue(req))
                 } else {
                      eprintln!("Blocked outbound connection to IPv4: {:X}", ip_raw);
                      Ok(self.resp_error(req, libc::EACCES))
                 }
            },
            libc::AF_INET6 => {
                 // Block all IPv6 as per instruction "Explicitly drop all other"
                 eprintln!("Blocked outbound connection to IPv6");
                 Ok(self.resp_error(req, libc::EACCES))
            },
            _ => {
                 // Deny unknown families
                 Ok(self.resp_error(req, libc::EAFNOSUPPORT))
            }
        }
    }

    fn handle_execve(&self, req: &seccomp_notif) -> Result<seccomp_notif_resp> {
        let ptr = req.data.args[0];
        let tracee_pid = req.pid as pid_t;
        
        // We read the path. Note that tracee could modify it after we read.
        // However, we rely on the fact that only specific paths are mounted executably/accessibly 
        // and we have dropped privileges and namespaces.
        // The user instruction "Shift execution boundary enforcement: Rely on the MS_RDONLY bind mounts" 
        // implies that we should check if the path is indeed in one of those mounts.
        
        let path = match self.read_string_tracee(tracee_pid, ptr) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to read execve path: {}", e);
                return Ok(self.resp_error(req, libc::EFAULT));
            }
        };

        // Allowed prefixes for binaries (from supervisor mounts)
        // /bin, /usr/bin, /lib, /lib64, /usr/lib, /usr/lib64
        // And the original command itself?
        // The user says "Restrict the path check to ensure the binary resides within these read-only, root-owned mount points."
        let allowed_prefixes = ["/bin/", "/usr/bin/", "/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/"];
        
        let is_allowed = allowed_prefixes.iter().any(|prefix| path.starts_with(prefix)) || path == self.allowed_command.to_string_lossy();

        if is_allowed {
             Ok(self.resp_continue(req))
        } else {
             eprintln!("Blocked execve: {} (Not in allowed RO mounts)", path);
             Ok(self.resp_error(req, libc::EACCES))
        }
    }

    fn handle_bind(&self, req: &seccomp_notif) -> Result<seccomp_notif_resp> {
        Ok(self.resp_continue(req))
    }

    fn handle_openat(&self, req: &seccomp_notif) -> Result<seccomp_notif_resp> {
        let dirfd = req.data.args[0] as i32;
        let path_ptr = req.data.args[1];
        let tracee_pid = req.pid as pid_t;
        
        // 1. Read path string from tracee with page-aligned handling
        let mut path_buf = Vec::new();
        let max_len = 4096;
        let page_size = 4096;
        let mut current_addr = path_ptr as usize;
        
        loop {
            if path_buf.len() >= max_len {
                return Ok(self.resp_error(req, libc::ENAMETOOLONG));
            }
            
            // Calculate distance to next page boundary
            let bytes_to_boundary = page_size - (current_addr % page_size);
            let chunk_size = std::cmp::min(bytes_to_boundary, max_len - path_buf.len());
            
            let mut buf = vec![0u8; chunk_size];
            let mut local_iov = [IoSliceMut::new(&mut buf)];
            let remote_iov = [RemoteIoVec { base: current_addr, len: chunk_size }];
            
            let n = match process_vm_readv(nix::unistd::Pid::from_raw(tracee_pid), &mut local_iov, &remote_iov) {
                Ok(n) => n,
                Err(_) => {
                    if path_buf.is_empty() { return Ok(self.resp_error(req, libc::EFAULT)); }
                    0 
                }
            };
            
            if n == 0 && path_buf.is_empty() {
                return Ok(self.resp_error(req, libc::EFAULT));
            }
            
            let read_slice = &buf[..n];
            if let Some(pos) = read_slice.iter().position(|&b| b == 0) {
                path_buf.extend_from_slice(&read_slice[..pos]);
                break;
            } else {
                path_buf.extend_from_slice(read_slice);
                current_addr += n;
                if n < chunk_size {
                    return Ok(self.resp_error(req, libc::EFAULT));
                }
            }
        }

        let path_str = match std::str::from_utf8(&path_buf) {
            Ok(s) => s,
            Err(_) => return Ok(self.resp_error(req, libc::EINVAL)),
        };

        // 2. Resolve Root FD using pidfd_getfd for safety
        use std::os::unix::io::FromRawFd;
        
        let root_handle = if dirfd == -100 { // AT_FDCWD
             // Use our project root handle
             std::fs::File::open(&self.project_root).map_err(|e| anyhow::anyhow!("Failed to open root {:?}: {}", self.project_root, e))?
        } else {
             // Use pidfd_open + pidfd_getfd
             let pidfd = unsafe { libc::syscall(crate::seccomp_sys::SYS_PIDFD_OPEN, tracee_pid, 0) };
             if pidfd < 0 {
                 let err = std::io::Error::last_os_error();
                 eprintln!("pidfd_open failed: {}", err);
                 // If pidfd_open is blocked or fails, we might want to fail the request or continue with fallback?
                 // But for strict security, we fail.
                 return Ok(self.resp_error(req, 0-libc::ESRCH)); 
             }
             
             let dup_fd = unsafe { libc::syscall(crate::seccomp_sys::SYS_PIDFD_GETFD, pidfd, dirfd, 0) };
             unsafe { libc::close(pidfd as i32) };
             
             if dup_fd < 0 {
                  // EBADF probably
                  return Ok(self.resp_error(req, libc::EBADF));
             }
             
             unsafe { std::fs::File::from_raw_fd(dup_fd as i32) }
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


