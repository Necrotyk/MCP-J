use anyhow::{Result};
use std::os::unix::io::{RawFd, AsRawFd, FromRawFd};
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
    // project_root: PathBuf, // Removed unused field
    allowed_command: PathBuf,
    manifest: SandboxManifest,
    allowed_ips: HashSet<u32>,
    allowed_ips_v6: HashSet<u128>,
}

impl SeccompLoop {
    pub fn new(notify_fd: RawFd, _project_root: PathBuf, allowed_command: PathBuf, manifest: SandboxManifest) -> Self {
        eprintln!("DEBUG: SeccompLoop::new starting");
        // Pre-parse allowed IPs into u32 (network byte order)
        let mut allowed_ips = HashSet::new();
        // Always allow localhost
        allowed_ips.insert(0x7F000001); // 127.0.0.1
        
        // Task 2.2: DNS Manifest Integration
        // Explicitly allow UDP/TCP traffic to configured DNS resolvers.
        // This replaces hardcoded DNS servers (e.g. 1.1.1.1, 8.8.8.8) to allow user configuration.
        for resolver in &manifest.allowed_dns_resolvers {
            if let Ok(ip) = resolver.parse::<std::net::Ipv4Addr>() {
                 allowed_ips.insert(u32::from(ip));
            } else {
                 tracing::warn!(resolver = %resolver, "Failed to parse allowed DNS resolver IP");
            }
        }
        
        for ip_str in &manifest.allowed_egress_ips {
            if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                 allowed_ips.insert(u32::from(ip));
            } else {
                 tracing::warn!(ip = %ip_str, "Failed to parse allowed egress IP in manifest");
            }
        }
    
        let mut allowed_ips_v6 = HashSet::new();
        // Always allow localhost IPv6
        allowed_ips_v6.insert(0x0000_0000_0000_0000_0000_0000_0000_0001); // ::1
        
        // Task 2.1: Allowed Egress IPv6
        for ip_str in &manifest.allowed_egress_ipv6 {
            if let Ok(ip) = ip_str.parse::<std::net::Ipv6Addr>() {
                 allowed_ips_v6.insert(u128::from(ip));
            } else {
                 tracing::warn!(ip = %ip_str, "Failed to parse allowed egress IPv6 in manifest");
            }
        }

        eprintln!("DEBUG: SeccompLoop::new finished");
        Self { notify_fd, allowed_command, manifest, allowed_ips, allowed_ips_v6 }
    }

    
    // Helper to read memory from the tracee
    fn read_tracee_memory(&self, pid: pid_t, addr: u64, buf: &mut [u8]) -> Result<()> {
        let len = buf.len();
        let mut local_iov = [IoSliceMut::new(buf)];
        let remote_iov = [RemoteIoVec { base: addr as usize, len }];
        
        let n = process_vm_readv(nix::unistd::Pid::from_raw(pid), &mut local_iov, &remote_iov)?;
        if n != len {
            // Partial read?
            anyhow::bail!("Partial read from tracee memory: requested {}, read {}", buf.len(), n);
        }
        Ok(())
    }

    // Helper to read path bytes from tracee memory (page aligned)
    fn read_path_tracee(&self, pid: pid_t, addr: u64, buf: &mut Vec<u8>) -> Result<()> {
        buf.clear();
        let max_len = 4096;
        let page_size = 4096;
        let mut current_addr = addr as usize;
        
        // Task 2.3: Robust memory reading loop
        loop {
            if buf.len() >= max_len {
                return Err(anyhow::anyhow!("Path too long"));
            }
            
            // Calculate distance to next page boundary
            let bytes_to_boundary = page_size - (current_addr % page_size);
            let chunk_size = std::cmp::min(bytes_to_boundary, max_len - buf.len());
            
            if chunk_size == 0 {
                break;
            }
            
            // Optimization: Read directly into buf to avoid intermediate allocation/copy
            let current_len = buf.len();

            // SAFETY: We use set_len to expose uninitialized memory to avoid the cost of memset (buf.resize).
            // This is safe because:
            // 1. process_vm_readv writes directly to this memory (via IoSliceMut).
            // 2. We truncate the buffer immediately after the read if the read is partial or fails,
            //    ensuring no uninitialized memory is exposed to safe code.
            buf.reserve(chunk_size);
            unsafe { buf.set_len(current_len + chunk_size); }

            let mut local_iov = [IoSliceMut::new(&mut buf[current_len..])];
            let remote_iov = [RemoteIoVec { base: current_addr, len: chunk_size }];
            
            let n = match process_vm_readv(nix::unistd::Pid::from_raw(pid), &mut local_iov, &remote_iov) {
                Ok(n) => n,
                Err(e) => {
                    // Fail hard on EFAULT/errors if we haven't found a null terminator yet
                    return Err(anyhow::anyhow!("EFAULT during path read: {}", e));
                }
            };
            
            if n == 0 {
                return Err(anyhow::anyhow!("Unexpected 0-byte read (EOF)"));
            }
            
            // Check for null terminator in the newly read chunk
            if let Some(pos) = buf[current_len..current_len+n].iter().position(|&b| b == 0) {
                buf.truncate(current_len + pos);
                break;
            } else {
                buf.truncate(current_len + n);
                current_addr += n;
            }
        }
        
        Ok(())
    }

    pub fn run(&self) -> Result<()> {
        println!("Seccomp loop running on FD: {}", self.notify_fd);
        
        // Bolt Optimization: Reuse buffer for path reading to avoid frequent allocations
        let mut path_buffer = Vec::with_capacity(4096);

        loop {
            // Receive notification
            // We must zero initialize the struct as per C conventions generally, 
            // although RECV overwrites it.
            let mut req: seccomp_notif = unsafe { std::mem::zeroed() };
            
            // ioctl call
            let ret = unsafe { libc::ioctl(self.notify_fd, SECCOMP_IOCTL_NOTIF_RECV as _, &mut req) };
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
            let resp = self.handle_request(&req, &mut path_buffer)?;

            // Send response
            let ret = unsafe { libc::ioctl(self.notify_fd, SECCOMP_IOCTL_NOTIF_SEND as _, &resp) };
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

    fn handle_request(&self, req: &seccomp_notif, path_buffer: &mut Vec<u8>) -> Result<seccomp_notif_resp> {
        let syscall = req.data.nr as i64;
        
        // Match syscalls
        // Note: libc::SYS_* are usually c_long (i64 or i32)
        // We cast to i64 for comparison
        
        match syscall {
            libc::SYS_connect => self.handle_connect(req),
            libc::SYS_execve => self.handle_execve(req, path_buffer),
            libc::SYS_execveat => self.handle_execveat(req, path_buffer),
            libc::SYS_bind => self.handle_bind(req),
            libc::SYS_sendto => self.handle_sendto(req),
            libc::SYS_sendmsg => self.handle_sendmsg(req),
            libc::SYS_openat => self.handle_openat(req, path_buffer),
            libc::SYS_open => {
                // Legacy open: int open(const char *pathname, int flags, mode_t mode);
                // Mapped to handle_openat(AT_FDCWD, path, flags, mode)
                self.handle_open_legacy(req, path_buffer)
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
            tracing::warn!(id = req.id, syscall = req.data.nr, "AUDIT MODE: Allowing violation that would have been blocked");
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
        let addr_ptr = req.data.args[1];
        let addr_len = req.data.args[2] as usize;
        let tracee_pid = req.pid as pid_t;
        
        // Delegate to unified address validation
        self.validate_address(tracee_pid as i32, addr_ptr, addr_len, req)
    }

    fn handle_execve(&self, req: &seccomp_notif, path_buffer: &mut Vec<u8>) -> Result<seccomp_notif_resp> {
        // Task 1: Eliminate execve TOCTOU
        // Strategy: Block unauthorized execve(), but ALLOW the initial agent launch.
        
        // Task T-01: Engine Shell Execution Bypass
        // Remove wildcard /bin/ and /usr/bin/ allow-lists.
        // Implement an explicit ExactMatch allow-list for approved binaries only.
        // Add specific deny logic for shells.

        let filename_ptr = req.data.args[0];
        let tracee_pid = req.pid as pid_t;
        
        if let Err(e) = self.read_path_tracee(tracee_pid, filename_ptr, path_buffer) {
             tracing::warn!("Failed to read execve path from tracee: {}", e);
             return Ok(self.resp_error(req, libc::EACCES));
        }
        let path_bytes = &path_buffer[..];
        
        // Use OsStr for path comparison to avoid UTF-8 issues if possible, 
        // but verify against string allowlists.
        let path_str = String::from_utf8_lossy(path_bytes);
        let path = std::path::Path::new(path_str.as_ref());
        
        // 1. Explicit Deny List (Shells)
        let binding = path.file_name().unwrap_or_default().to_string_lossy();
        let name = binding.as_ref();
        match name {
            "sh" | "bash" | "dash" | "zsh" | "csh" | "ksh" | "powershell" | "pwsh" | "cmd.exe" => {
                tracing::warn!(pid = tracee_pid, binary = ?name, "Blocked shell execution attempt");
                return Ok(self.resp_error(req, libc::EACCES));
            },
            _ => {}
        }
        
        // 2. Exact Match Allow List
        // We only allow:
        // - The `allowed_command` explicitly passed to the Supervisor
        // - Specific trusted runtimes if needed (e.g. node, python) - here we stick to bare minimum to be secure.
        // - Read-only mounts are treated as data unless they effectively contain the binary. 
        //   However, we should probably NOT allow executing *anything* from a readonly mount blindly 
        //   unless it's the intended binary.
        
        // Strictly allow ONLY the target binary (self.allowed_command)
        // OR if the path is an absolute path to a known safe utility *if required*.
        // For now, adhere to T-01: "Implement an explicit ExactMatch allow-list for approved binaries only".
        
        let mut allowed = path == self.allowed_command.as_path();
        
        // Allow common trusted interpreters if they are the allowed_command or explicitly whitelisted
        // Example: if allowed_command is "node", then "node" is allowed.
        // If we want to allow "git" as a helper, we add it here.
        // For standard "Agent" use case, we might need basic tools? 
        // User instruction implies: "(e.g., node, python, git)"
        
        // Fix T-03: Dynamic Execve Allowlist
        // Instead of hardcoded whitelist, use the dynamic list from manifest
        if !allowed {
            allowed = self.manifest.allowed_runtimes.iter().any(|p| path == std::path::Path::new(p));
        }


        if allowed {
            tracing::debug!("Permitting execve for whitelisted path: {:?}", path);
            Ok(self.resp_continue(req))
        } else {
             // Block others
             tracing::warn!(pid = tracee_pid, path = ?path, "Blocked execve() - Not in ExactMatch AllowList");
             Ok(self.resp_error(req, libc::EACCES))
        }
    }

    fn handle_execveat(&self, req: &seccomp_notif, path_buffer: &mut Vec<u8>) -> Result<seccomp_notif_resp> {
        // execveat(dirfd, pathname, argv, envp, flags)
        let dirfd = req.data.args[0] as i32;
        let _ptr = req.data.args[1]; 
        let flags = req.data.args[4] as i32;
        let tracee_pid = req.pid as pid_t;

        // Verify AT_EMPTY_PATH to ensure FD is used
        if (flags & libc::AT_EMPTY_PATH) == 0 {
             tracing::warn!(pid = tracee_pid, "Blocked execveat() without AT_EMPTY_PATH (TOCTOU risk)");
             return Ok(self.resp_error(req, libc::EACCES));
        }

        // Verify path is actually empty (Linux kernel should enforce this with AT_EMPTY_PATH, but we double check)
        if req.data.args[1] != 0 {
             if let Ok(()) = self.read_path_tracee(tracee_pid, req.data.args[1], path_buffer) {
                 let path_bytes = &path_buffer[..];
                 // Check if it contains anything other than null.
                 // read_path_tracee stops at null or max length.
                 if !path_bytes.is_empty() && path_bytes != b"\0" {
                     // If using AT_EMPTY_PATH, path should be ""
                     tracing::warn!(pid = tracee_pid, "Blocked execveat() with non-empty path bypass");
                     return Ok(self.resp_error(req, libc::EACCES));
                 }
             }
        }
        
        // Resolve FD from tracee
        // We need to verify if the file pointed to by dirfd is allowed.
        // We use pidfd_getfd to duplicate it to supervisor and check path.
        
        let pidfd = unsafe { libc::syscall(crate::seccomp_sys::SYS_PIDFD_OPEN, tracee_pid, 0) };
        if pidfd < 0 { return Ok(self.resp_error(req, 0-libc::ESRCH)); }
        
        let dup_fd = unsafe { libc::syscall(crate::seccomp_sys::SYS_PIDFD_GETFD, pidfd, dirfd, 0) };
        unsafe { libc::close(pidfd as i32) };
        
        if dup_fd < 0 { return Ok(self.resp_error(req, libc::EBADF)); }
        
        let _file = unsafe { std::fs::File::from_raw_fd(dup_fd as i32) };
        
        // Get path from FD
        // /proc/self/fd/N -> link
        let fd_path = format!("/proc/self/fd/{}", dup_fd);
        let link_path = match std::fs::read_link(&fd_path) {
            Ok(p) => p,
            Err(_) => return Ok(self.resp_error(req, libc::EACCES)),
        };
        
        // Verify path against manifest
        let is_allowed = self.manifest.readonly_mounts.iter().any(|prefix| {
            link_path.starts_with(prefix)
        }) || link_path == self.allowed_command;

        if is_allowed {
             tracing::debug!(pid = tracee_pid, path = ?link_path, "Authorizing execveat(FD)");
             Ok(self.resp_continue(req))
        } else {
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
        
        let mut header_bytes = [0u8; 16];
        if let Err(_) = self.read_tracee_memory(tracee_pid, msg_ptr, &mut header_bytes) {
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

        let mut buf = [0u8; 128];
        // Ensure we don't panic on slice access, although checked above.
        let safe_len = std::cmp::min(addr_len, buf.len());
        if let Err(_) = self.read_tracee_memory(pid, addr_ptr, &mut buf[..safe_len]) {
            return Ok(self.resp_error(req, libc::EFAULT));
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
                 // Task 2: Harmonized IPv6 Validation
                 if addr_len < std::mem::size_of::<libc::sockaddr_in6>() {
                      return Ok(self.resp_error(req, libc::EINVAL));
                 }
                 
                 let mut sin6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
                 unsafe {
                     std::ptr::copy_nonoverlapping(
                         buf.as_ptr(), 
                         &mut sin6 as *mut _ as *mut u8, 
                         std::mem::size_of::<libc::sockaddr_in6>()
                     );
                 }
                 
                 // Handle IPv4-Mapped IPv6 (::ffff:1.2.3.4)
                 let raw_ip = u128::from_be_bytes(sin6.sin6_addr.s6_addr);
                 
                 // Check valid IPv4 mapped prefix: ::ffff:0:0/96
                 if (raw_ip >> 32) == 0x0000_0000_0000_0000_0000_FFFF {
                     // Extract IPv4 part
                     let ipv4_part = (raw_ip & 0xFFFFFFFF) as u32;
                     
                     if self.allowed_ips.contains(&ipv4_part) {
                         Ok(self.resp_continue(req))
                     } else {
                         let ip_addr = std::net::Ipv4Addr::from(ipv4_part);
                         tracing::warn!(pid = pid, dst_ip = %ip_addr, "Blocked outbound UDP/TCP (v4-mapped) (sendto/msg)");
                         Ok(self.resp_error(req, libc::EACCES))
                     }
                 } else if self.allowed_ips_v6.contains(&raw_ip) {
                     Ok(self.resp_continue(req))
                 } else {
                     let ip_addr = std::net::Ipv6Addr::from(raw_ip);
                     tracing::warn!(pid = pid, dst_ip = %ip_addr, "Blocked outbound IPv6 UDP/TCP (sendto/msg)");
                     Ok(self.resp_error(req, libc::EACCES))
                 }

            },
            _ => Ok(self.resp_error(req, libc::EAFNOSUPPORT))
        }
    }

    fn handle_openat(&self, req: &seccomp_notif, path_buffer: &mut Vec<u8>) -> Result<seccomp_notif_resp> {
        let dirfd = req.data.args[0] as i32;
        let path_ptr = req.data.args[1];
        let tracee_pid = req.pid as pid_t;
        
        // 1. Read path bytes
        if let Err(_) = self.read_path_tracee(tracee_pid, path_ptr, path_buffer) {
             return Ok(self.resp_error(req, libc::EFAULT));
        }
        let path_bytes = &path_buffer[..];

        // Shared Security Claims (Traversal + System Mount Protection)
        if let Err(resp) = self.validate_path_security(tracee_pid, path_bytes, req.data.args[2] as i32, req.id) {
             return Ok(resp);
        }

        // 2. Resolve Root FD
        use std::os::unix::io::FromRawFd;
        
        let root_handle = if dirfd == libc::AT_FDCWD {
             let cwd_path = format!("/proc/{}/cwd", tracee_pid);
             std::fs::File::open(&cwd_path).map_err(|e| anyhow::anyhow!("Failed to open tracee cwd: {}", e))?
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

        // Check for write to system mount via dirfd/cwd
        let flags = req.data.args[2] as i32;
        let acc_mode = flags & libc::O_ACCMODE;
        let is_write = acc_mode == libc::O_WRONLY || acc_mode == libc::O_RDWR || (flags & libc::O_CREAT) != 0;

        if is_write {
             let fd = root_handle.as_raw_fd();
             let fd_link = format!("/proc/self/fd/{}", fd);
             if let Ok(root_path) = std::fs::read_link(&fd_link) {
                  let root_path_str = root_path.to_string_lossy();
                  let is_system = self.manifest.readonly_mounts.iter().any(|prefix| {
                       let jail_prefix = format!("/tmp/jail_root{}", prefix);
                       root_path_str.starts_with(&jail_prefix) || root_path_str.starts_with(prefix)
                  });
                  if is_system {
                       tracing::warn!(pid = tracee_pid, root = ?root_path, "Blocked write access to system mount via dirfd");
                       return Ok(self.resp_error(req, libc::EACCES));
                  }
             }
        }

        // 3. Perform safe open
        let flags = req.data.args[2]; // openat(dirfd, path, flags, mode)
        let mode = req.data.args[3];
        let file = match crate::fs_utils::safe_open_beneath(&root_handle, path_bytes, flags, mode) {
            Ok(f) => f,
            Err(e) => {
                let path_lossy = String::from_utf8_lossy(path_bytes);
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
        
        let ret = unsafe { libc::ioctl(self.notify_fd, SECCOMP_IOCTL_NOTIF_ADDFD as _, &mut addfd) };
        if ret < 0 {
             let err = std::io::Error::last_os_error();
             return Err(anyhow::anyhow!("ioctl ADDFD failed: {}", err));
        }
        
        // ret is the new FD in remote process.
        Ok(ret as RawFd)
    }

    // Handling legacy open syscall: open(path, flags, mode)
    fn handle_open_legacy(&self, req: &seccomp_notif, path_buffer: &mut Vec<u8>) -> Result<seccomp_notif_resp> {
         let ptr = req.data.args[0];
         let flags = req.data.args[1];
         let mode = req.data.args[2];
         
         let tracee_pid = req.pid as pid_t;
         if let Err(e) = self.read_path_tracee(tracee_pid, ptr, path_buffer) {
             tracing::error!(pid = tracee_pid, error = %e, "Failed to read open path");
             return Ok(self.resp_error(req, libc::EFAULT));
         }
         let path_bytes = &path_buffer[..];
         
        // Shared Security Claims (Traversal + System Mount Protection)
        if let Err(resp) = self.validate_path_security(tracee_pid, path_bytes, flags as i32, req.id) {
             return Ok(resp);
        }

          let root_handle = {
              let cwd_path = format!("/proc/{}/cwd", tracee_pid);
              match std::fs::File::open(&cwd_path) {
                  Ok(f) => f,
                  Err(e) => {
                      tracing::error!(pid = tracee_pid, error = %e, "Failed to open tracee cwd");
                      return Ok(self.resp_error(req, libc::EACCES));
                  }
              }
          };

          // Check for write to system mount via cwd
          let acc_mode = flags as i32 & libc::O_ACCMODE;
          let flags_i32 = flags as i32;
          let is_write = acc_mode == libc::O_WRONLY || acc_mode == libc::O_RDWR || (flags_i32 & libc::O_CREAT) != 0;

          if is_write {
               let fd = root_handle.as_raw_fd();
               let fd_link = format!("/proc/self/fd/{}", fd);
               if let Ok(root_path) = std::fs::read_link(&fd_link) {
                    let root_path_str = root_path.to_string_lossy();
                    let is_system = self.manifest.readonly_mounts.iter().any(|prefix| {
                        let jail_prefix = format!("/tmp/jail_root{}", prefix);
                        root_path_str.starts_with(&jail_prefix) || root_path_str.starts_with(prefix)
                    });
                    if is_system {
                         tracing::warn!(pid = tracee_pid, root = ?root_path, "Blocked write access to system mount via cwd");
                         return Ok(self.resp_error(req, libc::EACCES));
                    }
               }
          }
         
         match crate::fs_utils::safe_open_beneath(&root_handle, path_bytes, flags, mode) {
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
                let path_lossy = String::from_utf8_lossy(path_bytes);
                tracing::warn!(pid = tracee_pid, path = %path_lossy, error = %e, "Blocked open(legacy) access");
                Ok(self.resp_error(req, libc::EACCES))
            }
         }
    }


    // Helper for Path Security
    fn validate_path_security(&self, pid: pid_t, path_bytes: &[u8], flags: i32, request_id: u64) -> Result<(), seccomp_notif_resp> {
        // 1. Traversal Check
        let has_traversal = path_bytes == b".." || 
                            path_bytes.starts_with(b"../") || 
                            path_bytes.ends_with(b"/..") || 
                            path_bytes.windows(4).any(|w| w == b"/../");

        if has_traversal {
            tracing::warn!(pid = pid, "Blocked open with directory traversal payload ('..')");
            return Err(self.resp_error(&seccomp_notif { id: request_id, pid: pid as u32, ..unsafe { std::mem::zeroed() } }, libc::EACCES));
        }

        // 2. System Mount Write Protection
        if path_bytes.starts_with(b"/") {
             use std::os::unix::ffi::OsStrExt;
             let is_allowed_system = self.manifest.readonly_mounts.iter().any(|prefix| {
                  let prefix_bytes = std::ffi::OsStr::new(prefix).as_bytes();
                  path_bytes.starts_with(prefix_bytes)
             });
             
             if is_allowed_system {
                  let acc_mode = flags & libc::O_ACCMODE;
                  if acc_mode == libc::O_WRONLY || acc_mode == libc::O_RDWR || (flags & libc::O_CREAT) != 0 {
                      tracing::warn!(pid = pid, flags = flags, "Blocked write/create flags on system mount");
                      return Err(self.resp_error(&seccomp_notif { id: request_id, pid: pid as u32, ..unsafe { std::mem::zeroed() } }, libc::EACCES));
                  }
                  
                  // If system mount and RO, we allow host access (Continue)
                  return Err(self.resp_continue(&seccomp_notif { id: request_id, pid: pid as u32, ..unsafe { std::mem::zeroed() } }));
             }
        }
        Ok(())
    }
}


