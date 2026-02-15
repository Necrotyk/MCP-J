use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::Path;
use anyhow::Result;
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

pub fn safe_open_beneath<P: AsRef<Path>>(root: &File, path: P, flags: u64) -> Result<File> {
    let path_cstr = std::ffi::CString::new(path.as_ref().to_str().unwrap_or("")).unwrap();
    
    // Mask allowed flags. We allow read/write, create, etc.
    // Important: O_CLOEXEC is mandatory for injected FDs usually, though injection handles it separately?
    // We enforce O_CLOEXEC here for good measure.
    let allowed_mask = (libc::O_RDONLY | libc::O_WRONLY | libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_TRUNC | libc::O_APPEND) as u64;
    let safe_flags = (flags & allowed_mask) | (libc::O_CLOEXEC as u64);

    let how = open_how {
        flags: safe_flags,
        mode: 0o666, // Default mode if O_CREAT is used. User mask applies? Openat2 might need explicit mode.
        // Actually, seccomp notify usually passes the 'mode' argument from openat syscall too.
        // For now, simpler implementation with default conservative mode (rw-rw-rw-).
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
        // ELOOP or EXDEV usually indicates escape attempt
        anyhow::bail!("openat2 failed: {}", err);
    }

    Ok(unsafe { File::from_raw_fd(ret as RawFd) })
}
