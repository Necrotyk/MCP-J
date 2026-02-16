use anyhow::{Result};
use std::os::unix::io::{RawFd, AsRawFd};
use libc::{pid_t};
use crate::seccomp_sys::{
    seccomp_notif, seccomp_notif_resp,
    SECCOMP_IOCTL_NOTIF_RECV, SECCOMP_IOCTL_NOTIF_SEND, 
    SECCOMP_USER_NOTIF_FLAG_CONTINUE,
    seccomp_notif_addfd, SECCOMP_IOCTL_NOTIF_ADDFD
};
use nix::sys::uio::{process_vm_readv, RemoteIoVec};
use std::io::IoSliceMut;

use std::path::PathBuf;

use crate::SandboxManifest;

use std::collections::HashSet;

#[derive(Clone)]
pub struct SeccompLoop {
    notify_fd: RawFd,
    project_root: PathBuf,
    allowed_command: PathBuf,
    manifest: SandboxManifest,
    allowed_ips: HashSet<u32>,
}

impl SeccompLoop {
    pub fn new(notify_fd: RawFd, project_root: PathBuf, allowed_command: PathBuf, manifest: SandboxManifest) -> Self {
        // Pre-parse allowed IPs into u32 (network byte order)
        let mut allowed_ips = HashSet::new();
        // Always allow localhost
        allowed_ips.insert(0x7F000001); // 127.0.0.1
        
        // Phase 38: DNS Resolution Entitlement (Cloudflare/Google)
        // Explicitly allow UDP/TCP traffic to 1.1.1.1 and 8.8.8.8 for resolution
        allowed_ips.insert(u32::from(std::net::Ipv4Addr::new(1, 1, 1, 1)));
        allowed_ips.insert(u32::from(std::net::Ipv4Addr::new(8, 8, 8, 8)));
        
        for ip_str in &manifest.allowed_egress_ips {
            if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                 allowed_ips.insert(u32::from(ip));
            } else {
                 tracing::warn!(ip = %ip_str, "Failed to parse allowed egress IP in manifest");
            }
        }
    
        Self { notify_fd, project_root, allowed_command, manifest, allowed_ips }
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

    // Helper to read path bytes from tracee memory (page aligned)
    fn read_path_tracee(&self, pid: pid_t, addr: u64) -> Result<Vec<u8>> {
        let mut path_buf = Vec::new();
        let max_len = 4096;
        let page_size = 4096;
        let mut current_addr = addr as usize;
        
        loop {
            if path_buf.len() >= max_len {
                return Err(anyhow::anyhow!("Path too long"));
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
                    return Err(anyhow::anyhow!("Path not null terminated within readable memory"));
                }
            }
        }
        
        // No UTF-8 validation here (Phase 16)
        Ok(path_buf)
    }

    pub fn run(&self) -> Result<()> {
        println!("Seccomp loop running on FD: {}", self.notify_fd);
        
        loop {
            // Receive notification
            // We must zero initialize the struct as per C conventions generally, 
            // although RECV overwrites it.
            let mut req: seccomp_notif = unsafe { std::mem::zeroed() };
            
            // ioctl call
            let ret = unsafe { libc::ioctl(self.notify_fd, SECCOMP_IOCTL_NOTIF_RECV as i32, &mut req) };
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                // Handle ENOENT if the target process died?
                // If checking for closed connection, handle it gracefully.
                tracing::error!(notify_fd = self.notify_fd, error = %err, "ioctl RECV failed");
                return Err(anyhow::anyhow!("ioctl RECV failed: {}", err));
            }

            // Process
            let resp = self.handle_request(&req)?;

            // Send response
            let ret = unsafe { libc::ioctl(self.notify_fd, SECCOMP_IOCTL_NOTIF_SEND as i32, &resp) };
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
            libc::SYS_sendto => self.handle_sendto(req),
            libc::SYS_sendmsg => self.handle_sendmsg(req),
            libc::SYS_openat => self.handle_openat(req),
            libc::SYS_open => {
                // Legacy open: int open(const char *pathname, int flags, mode_t mode);
                // Mapped to handle_openat(AT_FDCWD, path, flags, mode)
                self.handle_open_legacy(req)
            }
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
        // Phase 58: "Dry-Run" Profiler (Audit Mode)
        use crate::manifest::SecurityMode;
        if self.manifest.mode == SecurityMode::Audit {
            tracing::warn!(id = req.id, "AUDIT MODE: Allowing violation that would have been blocked");
            return self.resp_continue(req);
        }

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
                 // Allow local unix sockets by default per logic
                 // UNIX sockets are usually for IPC within namespaces if private.
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
                 
                 // The hashset stores u32::from(Ipv4Addr). Ipv4Addr "127.0.0.1" -> 0x7F000001 (Host Order).
                 // sin.sin_addr.s_addr is Network Order (Big Endian).
                 // So we need: u32::from_be(sin.sin_addr.s_addr) to match Host Order.
                 
                 let ip_host_order = u32::from_be(sin.sin_addr.s_addr);
                 
                 if self.allowed_ips.contains(&ip_host_order) {
                      Ok(self.resp_continue(req))
                 } else {
                      let ip_addr = std::net::Ipv4Addr::from(ip_host_order);
                      tracing::warn!(pid = tracee_pid, dst_ip = %ip_addr, "Blocked outbound connection to IPv4");
                      Ok(self.resp_error(req, libc::EACCES))
                 }
            },
            libc::AF_INET6 => {
                 // Block all IPv6 unless allowed?
                 // Does manifest allow IPv6 strings?
                 tracing::warn!(pid = tracee_pid, family = "IPv6", "Blocked outbound connection");
                 Ok(self.resp_error(req, libc::EACCES))
            },
            _ => {
                 // Deny unknown families
                 Ok(self.resp_error(req, libc::EAFNOSUPPORT))
            }
        }
    }

    fn handle_execve(&self, req: &seccomp_notif) -> Result<seccomp_notif_resp> {
        use std::os::unix::ffi::OsStrExt;
        let ptr = req.data.args[0];
        let tracee_pid = req.pid as pid_t;
        
        let path_bytes = match self.read_path_tracee(tracee_pid, ptr) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to read execve path: {}", e);
                return Ok(self.resp_error(req, libc::EFAULT));
            }
        };

        // Phase 30: Lexical Path Traversal Eradication
        if path_bytes.windows(2).any(|w| w == b"..") {
            tracing::warn!(pid = tracee_pid, "Blocked execve with directory traversal payload ('..')");
            return Ok(self.resp_error(req, libc::EACCES));
        }

        // Check against readonly mounts prefixes (byte comparison)
        let is_allowed = self.manifest.readonly_mounts.iter().any(|prefix| {
            let prefix_bytes = std::ffi::OsStr::new(prefix).as_bytes();
            path_bytes.starts_with(prefix_bytes)
        }) || path_bytes == self.allowed_command.as_os_str().as_bytes()
           || path_bytes.starts_with(b"/workspace/"); // Phase 24: Enable Workspace Execution

        if is_allowed {
             // Phase 21: TOCTOU Acknowledgment
             // Note: There is a theoretical Time-Of-Check-Time-Of-Use race here where the tracee
             // could swap the path memory after we read it but before the kernel executes it.
             // We rely on Landlock LSM as the authoritative security boundary to prevent unauthorized execution.
             tracing::debug!(pid = tracee_pid, "Authorizing execve (Landlock will enforce final boundary)");
             Ok(self.resp_continue(req))
        } else {
             // Reconstruct lossy string for logging
             let path_lossy = String::from_utf8_lossy(&path_bytes);
             tracing::warn!(pid = tracee_pid, path = %path_lossy, "Blocked execve (Not in allowed RO mounts)");
             Ok(self.resp_error(req, libc::EACCES))
        }
    }

    fn handle_bind(&self, req: &seccomp_notif) -> Result<seccomp_notif_resp> {
        Ok(self.resp_continue(req))
    }

    fn handle_sendto(&self, req: &seccomp_notif) -> Result<seccomp_notif_resp> {
        // sendto(sockfd, buf, len, flags, dest_addr, addrlen)
        let addr_ptr = req.data.args[4];
        let addr_len = req.data.args[5];
        
        if addr_ptr == 0 {
             // If addr is NULL, it's a connected socket. Allow as connect() was already checked.
             return Ok(self.resp_continue(req));
        }
        
        // Re-use handle_connect logic effectively by mocking a connect request or factoring out validation
        // We will call validate_address directly.
        // But handle_connect takes &req. We need a helper that takes (pid, addr_ptr, addr_len).
        
        self.validate_address(req.pid as i32, addr_ptr, addr_len as usize, req)
    }

    fn handle_sendmsg(&self, req: &seccomp_notif) -> Result<seccomp_notif_resp> {
        // sendmsg(sockfd, msg, flags)
        // msg is struct msghdr { void *msg_name; socklen_t msg_namelen; ... }
        // We need to read msghdr from tracee memory to check msg_name (dest address).
        
        let msg_ptr = req.data.args[1];
        let tracee_pid = req.pid as i32;
        
        // struct msghdr (glibc x64):
        // void *msg_name; (0)
        // socklen_t msg_namelen; (8)
        // struct iovec *msg_iov; (16)
        // size_t msg_iovlen; (24)
        // void *msg_control; (32)
        // size_t msg_controllen; (40)
        // int msg_flags; (48)
        
        let header_bytes = match self.read_tracee_memory(tracee_pid, msg_ptr, 16) { // Read first 16 bytes for name and namelen
             Ok(b) => b,
             Err(_) => return Ok(self.resp_error(req, libc::EFAULT)),
        };
        
        if header_bytes.len() < 16 {
             return Ok(self.resp_error(req, libc::EFAULT));
        }
        
        let msg_name_ptr = u64::from_ne_bytes(header_bytes[0..8].try_into().unwrap());
        let msg_namelen = u32::from_ne_bytes(header_bytes[8..12].try_into().unwrap()); // socklen_t is u32 usually
        
        if msg_name_ptr == 0 {
             // Connected socket
             return Ok(self.resp_continue(req));
        }
        
        self.validate_address(tracee_pid, msg_name_ptr, msg_namelen as usize, req)
    }
    
    // Refactored validation logic
    fn validate_address(&self, pid: i32, addr_ptr: u64, addr_len: usize, req: &seccomp_notif) -> Result<seccomp_notif_resp> {
        // Strict length checking for known families
        if addr_len < std::mem::size_of::<libc::sa_family_t>() {
             return Ok(self.resp_error(req, libc::EINVAL));
        }
        
        if addr_len > 128 { 
             return Ok(self.resp_error(req, libc::EINVAL));
        }

        let buf = match self.read_tracee_memory(pid, addr_ptr, addr_len) {
            Ok(b) => b,
            Err(_) => return Ok(self.resp_error(req, libc::EFAULT)),
        };

        if buf.len() < 2 {
             return Ok(self.resp_error(req, libc::EINVAL));
        }
        
        let sa_family = u16::from_ne_bytes([buf[0], buf[1]]);
        
        match sa_family as i32 {
            libc::AF_UNIX => Ok(self.resp_continue(req)),
            libc::AF_INET => {
                 if addr_len < std::mem::size_of::<libc::sockaddr_in>() {
                      return Ok(self.resp_error(req, libc::EINVAL));
                 }
                 
                 let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
                 unsafe {
                     std::ptr::copy_nonoverlapping(
                         buf.as_ptr(), 
                         &mut sin as *mut _ as *mut u8, 
                         std::mem::size_of::<libc::sockaddr_in>()
                     );
                 }
                 
                 let ip_host_order = u32::from_be(sin.sin_addr.s_addr);
                 
                 if self.allowed_ips.contains(&ip_host_order) {
                      Ok(self.resp_continue(req))
                 } else {
                      let ip_addr = std::net::Ipv4Addr::from(ip_host_order);
                      tracing::warn!(pid = pid, dst_ip = %ip_addr, "Blocked outbound UDP/TCP (sendto/msg)");
                      Ok(self.resp_error(req, libc::EACCES))
                 }
            },
            libc::AF_INET6 => {
                 tracing::warn!(pid = pid, family = "IPv6", "Blocked outbound connection");
                 Ok(self.resp_error(req, libc::EACCES))
            },
            _ => Ok(self.resp_error(req, libc::EAFNOSUPPORT))
        }
    }

    fn handle_openat(&self, req: &seccomp_notif) -> Result<seccomp_notif_resp> {
        let dirfd = req.data.args[0] as i32;
        let path_ptr = req.data.args[1];
        let tracee_pid = req.pid as pid_t;
        
        // 1. Read path bytes
        let path_bytes = match self.read_path_tracee(tracee_pid, path_ptr) {
             Ok(p) => p,
             Err(_) => return Ok(self.resp_error(req, libc::EFAULT)),
        };

        // Phase 30: Lexical Path Traversal Eradication
        if path_bytes.windows(2).any(|w| w == b"..") {
            tracing::warn!(pid = tracee_pid, "Blocked openat with directory traversal payload ('..')");
            return Ok(self.resp_error(req, libc::EACCES));
        }

        // Phase 20: Absolute Path Resolution Bypass (Library Loading)
        if path_bytes.starts_with(b"/") {
             use std::os::unix::ffi::OsStrExt;
             let is_allowed_system = self.manifest.readonly_mounts.iter().any(|prefix| {
                  let prefix_bytes = std::ffi::OsStr::new(prefix).as_bytes();
                  path_bytes.starts_with(prefix_bytes)
             });
             
             if is_allowed_system {
                  // Phase 31: Strict Flag Masking for System Mounts
                  // Reject O_WRONLY, O_RDWR, O_CREAT for system mounts
                  let acc_mode = req.data.args[2] as i32 & libc::O_ACCMODE;
                  let flags = req.data.args[2] as i32;
                  
                  if acc_mode == libc::O_WRONLY || acc_mode == libc::O_RDWR || (flags & libc::O_CREAT) != 0 {
                      tracing::warn!(pid = tracee_pid, flags = flags, "Blocked write/create flags on system mount");
                      return Ok(self.resp_error(req, libc::EACCES));
                  }
                  
                  return Ok(self.resp_continue(req));
             }
        }

        // 2. Resolve Root FD
        use std::os::unix::io::FromRawFd;
        
        let root_handle = if dirfd == -100 { // AT_FDCWD
             std::fs::File::open(&self.project_root).map_err(|e| anyhow::anyhow!("Failed to open root {:?}: {}", self.project_root, e))?
        } else {
             let pidfd = unsafe { libc::syscall(crate::seccomp_sys::SYS_PIDFD_OPEN, tracee_pid, 0) };
             if pidfd < 0 {
                 return Ok(self.resp_error(req, 0-libc::ESRCH)); 
             }
             
             let dup_fd = unsafe { libc::syscall(crate::seccomp_sys::SYS_PIDFD_GETFD, pidfd, dirfd, 0) };
             unsafe { libc::close(pidfd as i32) };
             
             if dup_fd < 0 {
                  return Ok(self.resp_error(req, libc::EBADF));
             }
             
             unsafe { std::fs::File::from_raw_fd(dup_fd as i32) }
        };

        // 3. Perform safe open
        let flags = req.data.args[2]; // openat(dirfd, path, flags, mode)
        let mode = req.data.args[3];
        let file = match crate::fs_utils::safe_open_beneath(&root_handle, &path_bytes, flags, mode) {
            Ok(f) => f,
            Err(e) => {
                let path_lossy = String::from_utf8_lossy(&path_bytes);
                tracing::warn!(pid = tracee_pid, path = %path_lossy, error = %e, "Blocked openat access");
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
        
        let ret = unsafe { libc::ioctl(self.notify_fd, SECCOMP_IOCTL_NOTIF_ADDFD as i32, &mut addfd) };
        if ret < 0 {
             let err = std::io::Error::last_os_error();
             return Err(anyhow::anyhow!("ioctl ADDFD failed: {}", err));
        }
        
        // ret is the new FD in remote process.
        Ok(ret as RawFd)
    }

    // Handling legacy open syscall: open(path, flags, mode)
    fn handle_open_legacy(&self, req: &seccomp_notif) -> Result<seccomp_notif_resp> {
         let ptr = req.data.args[0];
         let flags = req.data.args[1];
         let mode = req.data.args[2];
         
         let tracee_pid = req.pid as pid_t;
         let path_bytes = match self.read_path_tracee(tracee_pid, ptr) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(pid = tracee_pid, error = %e, "Failed to read open path");
                return Ok(self.resp_error(req, libc::EFAULT));
            }
         };
         
        // Phase 30: Lexical Path Traversal Eradication
        if path_bytes.windows(2).any(|w| w == b"..") {
            tracing::warn!(pid = tracee_pid, "Blocked open(legacy) with directory traversal payload ('..')");
            return Ok(self.resp_error(req, libc::EACCES));
        }

        // Phase 20: Absolute Path Resolution Bypass (Library Loading)
        if path_bytes.starts_with(b"/") {
             use std::os::unix::ffi::OsStrExt;
             let is_allowed_system = self.manifest.readonly_mounts.iter().any(|prefix| {
                  let prefix_bytes = std::ffi::OsStr::new(prefix).as_bytes();
                  path_bytes.starts_with(prefix_bytes)
             });
             
             if is_allowed_system {
                  // Phase 31: Strict Flag Masking for System Mounts
                  let acc_mode = flags as i32 & libc::O_ACCMODE;
                  let flags_i32 = flags as i32;
                  
                  if acc_mode == libc::O_WRONLY || acc_mode == libc::O_RDWR || (flags_i32 & libc::O_CREAT) != 0 {
                      tracing::warn!(pid = tracee_pid, flags = flags, "Blocked write/create flags on system mount");
                      return Ok(self.resp_error(req, libc::EACCES));
                  }

                  return Ok(self.resp_continue(req));
             }
        }

         let root_handle = match std::fs::File::open(&self.project_root) {
             Ok(f) => f,
             Err(e) => {
                 tracing::error!(project_root = ?self.project_root, error = %e, "Failed to open project root handle");
                 return Ok(self.resp_error(req, libc::ENOTDIR));
             }
         };
         
         match crate::fs_utils::safe_open_beneath(&root_handle, &path_bytes, flags, mode) {
            Ok(file) => {
                let injected = self.inject_fd(req, file.as_raw_fd())?;
                Ok(seccomp_notif_resp {
                    id: req.id,
                    val: injected as i64,
                    error: 0,
                    flags: 0,
                })
            }
            Err(e) => {
                let path_lossy = String::from_utf8_lossy(&path_bytes);
                tracing::warn!(pid = tracee_pid, path = %path_lossy, error = %e, "Blocked open(legacy) access");
                Ok(self.resp_error(req, libc::EACCES))
            }
         }
    }
}


