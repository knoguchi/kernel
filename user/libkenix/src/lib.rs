//! Kenix user-space runtime library
//!
//! Provides syscall wrappers and common functionality for user-space programs.

#![no_std]

use core::panic::PanicInfo;

// ============================================================================
// Memory Intrinsics
// ============================================================================

#[no_mangle]
pub unsafe extern "C" fn memset(dest: *mut u8, c: i32, n: usize) -> *mut u8 {
    let c = c as u8;
    for i in 0..n {
        *dest.add(i) = c;
    }
    dest
}

#[no_mangle]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    for i in 0..n {
        *dest.add(i) = *src.add(i);
    }
    dest
}

#[no_mangle]
pub unsafe extern "C" fn memmove(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if src < dest as *const u8 {
        for i in (0..n).rev() {
            *dest.add(i) = *src.add(i);
        }
    } else {
        for i in 0..n {
            *dest.add(i) = *src.add(i);
        }
    }
    dest
}

#[no_mangle]
pub unsafe extern "C" fn memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    for i in 0..n {
        let a = *s1.add(i);
        let b = *s2.add(i);
        if a != b {
            return a as i32 - b as i32;
        }
    }
    0
}

// ============================================================================
// Panic Handler
// ============================================================================

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // TODO: Print panic message via write() once we have better infrastructure
    syscall::exit(1);
}

// ============================================================================
// Syscall Interface
// ============================================================================

pub mod syscall {
    use core::arch::asm;

    // Syscall numbers
    pub const SYS_YIELD: u64 = 0;
    pub const SYS_SEND: u64 = 1;
    pub const SYS_RECV: u64 = 2;
    pub const SYS_CALL: u64 = 3;
    pub const SYS_REPLY: u64 = 4;
    pub const SYS_SHMCREATE: u64 = 10;
    pub const SYS_SHMMAP: u64 = 11;
    pub const SYS_SHMUNMAP: u64 = 12;
    pub const SYS_SHMGRANT: u64 = 13;
    pub const SYS_CLOSE: u64 = 57;
    pub const SYS_READ: u64 = 63;
    pub const SYS_WRITE: u64 = 64;
    pub const SYS_EXIT: u64 = 93;

    /// Exit the process
    pub fn exit(code: i32) -> ! {
        unsafe {
            asm!(
                "svc #0",
                in("x0") code,
                in("x8") SYS_EXIT,
                options(noreturn)
            );
        }
    }

    /// Write to a file descriptor
    pub fn write(fd: usize, buf: &[u8]) -> isize {
        let ret: isize;
        unsafe {
            asm!(
                "svc #0",
                inout("x0") fd => ret,
                in("x1") buf.as_ptr(),
                in("x2") buf.len(),
                in("x8") SYS_WRITE,
                options(nostack)
            );
        }
        ret
    }

    /// Read from a file descriptor
    pub fn read(fd: usize, buf: &mut [u8]) -> isize {
        let ret: isize;
        unsafe {
            asm!(
                "svc #0",
                inout("x0") fd => ret,
                in("x1") buf.as_mut_ptr(),
                in("x2") buf.len(),
                in("x8") SYS_READ,
                options(nostack)
            );
        }
        ret
    }

    /// Close a file descriptor
    pub fn close(fd: usize) -> isize {
        let ret: isize;
        unsafe {
            asm!(
                "svc #0",
                inout("x0") fd => ret,
                in("x8") SYS_CLOSE,
                options(nostack)
            );
        }
        ret
    }

    /// Yield CPU
    pub fn yield_cpu() {
        unsafe {
            asm!(
                "svc #0",
                in("x8") SYS_YIELD,
                options(nostack)
            );
        }
    }
}

// ============================================================================
// Shared Memory Interface
// ============================================================================

pub mod shm {
    use core::arch::asm;
    use super::syscall::*;

    /// Shared memory region ID
    pub type ShmId = u64;

    /// SHM error codes
    pub const SHM_ERR_INVALID: i64 = -1;
    pub const SHM_ERR_NO_MEMORY: i64 = -2;
    pub const SHM_ERR_PERMISSION: i64 = -3;
    pub const SHM_ERR_ALREADY_MAPPED: i64 = -4;
    pub const SHM_ERR_NOT_MAPPED: i64 = -5;
    pub const SHM_ERR_NO_SLOTS: i64 = -6;

    /// Create a new shared memory region
    /// size: Size in bytes (will be rounded up to 4KB page alignment)
    /// Returns: Shared memory ID on success, negative error code on failure
    pub fn create(size: usize) -> isize {
        let ret: isize;
        unsafe {
            asm!(
                "svc #0",
                inout("x0") size => ret,
                in("x8") SYS_SHMCREATE,
                options(nostack)
            );
        }
        ret
    }

    /// Map a shared memory region into the current task's address space
    /// id: Shared memory region ID
    /// hint: Suggested virtual address (0 for auto-allocation)
    /// Returns: Virtual address on success, negative error code on failure
    pub fn map(id: ShmId, hint: usize) -> isize {
        let ret: isize;
        unsafe {
            asm!(
                "svc #0",
                inout("x0") id => ret,
                in("x1") hint,
                in("x8") SYS_SHMMAP,
                options(nostack)
            );
        }
        ret
    }

    /// Unmap a shared memory region from the current task's address space
    /// id: Shared memory region ID
    /// Returns: 0 on success, negative error code on failure
    pub fn unmap(id: ShmId) -> isize {
        let ret: isize;
        unsafe {
            asm!(
                "svc #0",
                inout("x0") id => ret,
                in("x8") SYS_SHMUNMAP,
                options(nostack)
            );
        }
        ret
    }

    /// Grant another task permission to map the shared memory region
    /// id: Shared memory region ID
    /// task_id: Task ID to grant access to
    /// Returns: 0 on success, negative error code on failure
    pub fn grant(id: ShmId, task_id: usize) -> isize {
        let ret: isize;
        unsafe {
            asm!(
                "svc #0",
                inout("x0") id => ret,
                in("x1") task_id,
                in("x8") SYS_SHMGRANT,
                options(nostack)
            );
        }
        ret
    }
}

// ============================================================================
// IPC Interface
// ============================================================================

pub mod ipc {
    use core::arch::asm;
    use super::syscall::*;

    /// IPC Message
    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    pub struct Message {
        pub tag: u64,
        pub data: [u64; 4],
    }

    impl Message {
        pub const fn new(tag: u64, data: [u64; 4]) -> Self {
            Self { tag, data }
        }

        pub const fn empty() -> Self {
            Self { tag: 0, data: [0; 4] }
        }
    }

    /// Result of receiving a message
    #[derive(Clone, Copy, Debug)]
    pub struct RecvResult {
        pub sender: usize,
        pub msg: Message,
    }

    /// Task ID for receiving from any sender
    pub const TASK_ANY: usize = usize::MAX;

    /// Send a message and wait for reply (RPC call)
    pub fn call(dest: usize, msg: &mut Message) {
        let tag: u64;
        let d0: u64;
        let d1: u64;
        let d2: u64;
        let d3: u64;

        unsafe {
            asm!(
                "svc #0",
                inout("x0") dest => tag,
                inout("x1") msg.tag => d0,
                inout("x2") msg.data[0] => d1,
                inout("x3") msg.data[1] => d2,
                inout("x4") msg.data[2] => d3,
                in("x5") msg.data[3],
                in("x8") SYS_CALL,
                options(nostack)
            );
        }

        msg.tag = tag;
        msg.data[0] = d0;
        msg.data[1] = d1;
        msg.data[2] = d2;
        msg.data[3] = d3;
    }

    /// Receive a message
    pub fn recv(from: usize) -> RecvResult {
        let sender: usize;
        let tag: u64;
        let d0: u64;
        let d1: u64;
        let d2: u64;
        let d3: u64;

        unsafe {
            asm!(
                "svc #0",
                inout("x0") from => sender,
                out("x1") tag,
                out("x2") d0,
                out("x3") d1,
                out("x4") d2,
                out("x5") d3,
                in("x8") SYS_RECV,
                options(nostack)
            );
        }

        RecvResult {
            sender,
            msg: Message {
                tag,
                data: [d0, d1, d2, d3],
            },
        }
    }

    /// Reply to a caller
    pub fn reply(msg: &Message) -> isize {
        let ret: isize;
        unsafe {
            asm!(
                "svc #0",
                inout("x0") msg.tag => ret,
                in("x1") msg.data[0],
                in("x2") msg.data[1],
                in("x3") msg.data[2],
                in("x4") msg.data[3],
                in("x8") SYS_REPLY,
                options(nostack)
            );
        }
        ret
    }
}

// ============================================================================
// Console Output (for debugging)
// ============================================================================

pub mod console {
    use super::syscall;

    /// Print a string to stdout
    pub fn print(s: &str) {
        syscall::write(1, s.as_bytes());
    }

    /// Print a string with newline
    pub fn println(s: &str) {
        print(s);
        print("\n");
    }

    /// Print a number in hex
    pub fn print_hex(prefix: &str, value: u64) {
        print(prefix);
        print("0x");

        let mut buf = [0u8; 16];
        for i in 0..16 {
            let nibble = ((value >> (60 - i * 4)) & 0xf) as u8;
            buf[i] = if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 };
        }
        syscall::write(1, &buf);
        print("\n");
    }
}

// ============================================================================
// Message Types (shared between servers)
// ============================================================================

pub mod msg {
    // Console server messages
    pub const MSG_WRITE: u64 = 1;
    pub const MSG_EXIT: u64 = 2;
    pub const MSG_SHM_WRITE: u64 = 10;

    // IPC result codes
    pub const IPC_OK: i64 = 0;
    pub const IPC_ERR_INVALID: i64 = -1;

    // VFS messages
    pub const VFS_OPEN: u64 = 100;
    pub const VFS_CLOSE: u64 = 101;
    pub const VFS_READ: u64 = 102;
    pub const VFS_WRITE: u64 = 103;
    pub const VFS_STAT: u64 = 104;

    // Error codes
    pub const ERR_OK: i64 = 0;
    pub const ERR_NOENT: i64 = -2;
    pub const ERR_IO: i64 = -5;
    pub const ERR_BADF: i64 = -9;
    pub const ERR_NOMEM: i64 = -12;
    pub const ERR_EXIST: i64 = -17;
    pub const ERR_NOTDIR: i64 = -20;
    pub const ERR_ISDIR: i64 = -21;
    pub const ERR_INVAL: i64 = -22;
    pub const ERR_NFILE: i64 = -23;
    pub const ERR_NOSPC: i64 = -28;
}

// ============================================================================
// Well-known Task IDs
// ============================================================================

pub mod tasks {
    pub const IDLE: usize = 0;
    pub const CONSOLE: usize = 1;
    pub const INIT: usize = 2;
    pub const VFS: usize = 3;
}
