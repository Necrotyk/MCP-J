use libc::{c_int, c_long, c_ulong};
use std::mem;

// Seccomp constants
pub const SECCOMP_SET_MODE_FILTER: c_int = 1;
pub const SECCOMP_FILTER_FLAG_TSYNC: c_ulong = 1;
pub const SECCOMP_FILTER_FLAG_LOG: c_ulong = 2;
pub const SECCOMP_FILTER_FLAG_SPEC_ALLOW: c_ulong = 4;
pub const SECCOMP_FILTER_FLAG_NEW_LISTENER: c_ulong = 8;

pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;
pub const SECCOMP_RET_KILL_THREAD: u32 = 0x00000000;
pub const SECCOMP_RET_TRAP: u32 = 0x00030000;
pub const SECCOMP_RET_ERRNO: u32 = 0x00050000;
pub const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc00000;
pub const SECCOMP_RET_TRACE: u32 = 0x7ff00000;
pub const SECCOMP_RET_LOG: u32 = 0x7ffc0000;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;

pub const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 0x00000001;

// IOCTL Magic '!' = 33
const SECCOMP_IOC_MAGIC: u8 = 33; 

// Macros to calculate ioctl numbers (simplified for Linux generic)
// _IOWR(type,nr,size) = ((type) << _IOC_TYPESHIFT) | ((nr) << _IOC_NRSHIFT) | ((size) << _IOC_SIZESHIFT) | _IOC_READ | _IOC_WRITE
// On x86_64:
// _IOC_NRSHIFT = 0, _IOC_TYPESHIFT = 8, _IOC_SIZESHIFT = 16, _IOC_DIRSHIFT = 30
// _IOC_READ = 2, _IOC_WRITE = 1 -> _IOC_READ|_IOC_WRITE = 3 (Direction is 2 bits at bit 30)

// Standard Linux ioctl direction bits
const _IOC_NRSHIFT: u32 = 0;
const _IOC_TYPESHIFT: u32 = 8;
const _IOC_SIZESHIFT: u32 = 16;
const _IOC_DIRSHIFT: u32 = 30;
const _IOC_READ: u32 = 2;
const _IOC_WRITE: u32 = 1;
const _IOC_NONE: u32 = 0;

const fn _ioc(dir: u32, type_: u8, nr: u32, size: usize) -> u64 {
    ((dir as u64) << _IOC_DIRSHIFT) |
    ((type_ as u64) << _IOC_TYPESHIFT) |
    ((nr as u64) << _IOC_NRSHIFT) |
    ((size as u64) << _IOC_SIZESHIFT)
}

const fn _iowr(type_: u8, nr: u32, size: usize) -> u64 {
    _ioc(_IOC_READ | _IOC_WRITE, type_, nr, size)
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct seccomp_data {
    pub nr: c_int,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct seccomp_notif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: seccomp_data,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct seccomp_notif_resp {
    pub id: u64,
    pub val: i64,
    pub error: i32,
    pub flags: u32,
}

pub const SECCOMP_IOCTL_NOTIF_RECV: u64 = _iowr(SECCOMP_IOC_MAGIC, 0, mem::size_of::<seccomp_notif>());
pub const SECCOMP_IOCTL_NOTIF_SEND: u64 = _iowr(SECCOMP_IOC_MAGIC, 1, mem::size_of::<seccomp_notif_resp>());
pub const SECCOMP_IOCTL_NOTIF_ID_VALID: u64 = _iowr(SECCOMP_IOC_MAGIC, 2, mem::size_of::<u64>());
pub const SECCOMP_IOCTL_NOTIF_ADDFD: u64 = _iowr(SECCOMP_IOC_MAGIC, 3, mem::size_of::<seccomp_notif_addfd>());

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct seccomp_notif_addfd {
    pub id: u64,
    pub flags: u32,
    pub srcfd: u32,
    pub newfd: u32,
    pub newfd_flags: u32,
}

pub const SYS_PIDFD_OPEN: c_long = 434;
pub const SYS_PIDFD_GETFD: c_long = 438;


