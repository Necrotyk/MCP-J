use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use anyhow::{Result, Context};
use libc::c_long;

// openat2 constants - normally in linux/openat2.h or fcntl.h
// If libc doesn't define them, we define them.
const SYS_OPENAT2: c_long = 437; // x86_64
const RESOLVE_BENEATH: u64 = 0x08;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;

#[repr(C)]
#[derive(Debug, Default)]
struct open_how {
    flags: u64,
    mode: u64,
    resolve: u64,
}

pub fn safe_open_beneath(root: &File, path_bytes: &[u8], flags: u64, mode: u64) -> Result<File> {
    use std::ffi::CString;
    
    // Byte-safe CString conversion (Phase 16)
    // We expect path_bytes to NOT contain null bytes in the middle, but if they do, CString::new checks.
    let path_cstr = CString::new(path_bytes).context("Failed to create CString from path bytes")?;
    
    // Mask allowed flags.
    let allowed_mask = (libc::O_RDONLY | libc::O_WRONLY | libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_TRUNC | libc::O_APPEND) as u64;
    let safe_flags = (flags & allowed_mask) | (libc::O_CLOEXEC as u64);

    // Apply strict mode masking if O_CREAT is involved (Phase 11)
    let safe_mode = if (safe_flags & (libc::O_CREAT as u64)) != 0 {
         mode & 0o777 // Mask out SUID/SGID/Sticky bits for safety
    } else {
         0
    };

    let how = open_how {
        flags: safe_flags,
        mode: safe_mode, 
        resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS,
    };

    let ret = unsafe {
        libc::syscall(
            SYS_OPENAT2,
            root.as_raw_fd(),
            path_cstr.as_ptr(),
            &how as *const open_how,
            std::mem::size_of::<open_how>()
        )
    };

    if ret < 0 {
        let err = std::io::Error::last_os_error();
        anyhow::bail!("openat2 failed: {}", err);
    }

    Ok(unsafe { File::from_raw_fd(ret as RawFd) })
}
