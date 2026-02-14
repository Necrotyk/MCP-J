use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::Path;
use anyhow::{Result, Context};
use libc::{c_int, c_long};

// openat2 constants - normally in linux/openat2.h or fcntl.h
// If libc doesn't define them, we define them.
const SYS_OPENAT2: c_long = 437; // x86_64
const RESOLVE_BENEATH: u64 = 0x08;

#[repr(C)]
#[derive(Debug, Default)]
struct open_how {
    flags: u64,
    mode: u64,
    resolve: u64,
}

pub fn safe_open_beneath<P: AsRef<Path>>(root: &File, path: P) -> Result<File> {
    let path_cstr = std::ffi::CString::new(path.as_ref().to_str().unwrap_or("")).unwrap();
    
    let how = open_how {
        flags: (libc::O_RDWR | libc::O_CLOEXEC) as u64, // Default flags, adjust as needed
        mode: 0,
        resolve: RESOLVE_BENEATH,
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
