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
    pub const SYS_NOTIFY: u64 = 7;
    pub const SYS_WAIT_NOTIFY: u64 = 8;
    pub const SYS_SHMCREATE: u64 = 10;
    pub const SYS_SHMMAP: u64 = 11;
    pub const SYS_SHMUNMAP: u64 = 12;
    pub const SYS_SHMGRANT: u64 = 13;
    pub const SYS_GETPID: u64 = 20;
    pub const SYS_SPAWN: u64 = 21;
    pub const SYS_FORK: u64 = 22;
    pub const SYS_IRQ_REGISTER: u64 = 30;
    pub const SYS_IRQ_WAIT: u64 = 31;
    pub const SYS_IRQ_ACK: u64 = 32;
    pub const SYS_GETCWD: u64 = 17;
    pub const SYS_DUP: u64 = 23;
    pub const SYS_DUP3: u64 = 24;
    pub const SYS_CHDIR: u64 = 49;
    pub const SYS_OPENAT: u64 = 56;
    pub const SYS_CLOSE: u64 = 57;
    pub const SYS_PIPE: u64 = 59;
    pub const SYS_GETDENTS64: u64 = 61;
    pub const SYS_READ: u64 = 63;
    pub const SYS_WRITE: u64 = 64;
    pub const SYS_FSTAT: u64 = 80;
    pub const SYS_EXIT: u64 = 93;
    pub const SYS_CLOCK_GETTIME: u64 = 113;
    pub const SYS_KILL: u64 = 129;
    pub const SYS_RT_SIGACTION: u64 = 134;
    pub const SYS_RT_SIGPROCMASK: u64 = 135;
    pub const SYS_BRK: u64 = 214;
    pub const SYS_MUNMAP: u64 = 215;
    pub const SYS_EXECVE: u64 = 221;
    pub const SYS_MMAP: u64 = 222;
    pub const SYS_MPROTECT: u64 = 226;
    pub const SYS_WAIT4: u64 = 260;
    pub const SYS_READV: u64 = 65;
    pub const SYS_WRITEV: u64 = 66;
    pub const SYS_PRLIMIT64: u64 = 261;
    pub const SYS_GETRANDOM: u64 = 278;
    pub const SYS_SET_TID_ADDRESS: u64 = 96;
    pub const SYS_IOCTL: u64 = 29;

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

    /// Get current task ID
    pub fn getpid() -> isize {
        let ret: isize;
        unsafe {
            asm!(
                "svc #0",
                out("x0") ret,
                in("x8") SYS_GETPID,
                options(nostack)
            );
        }
        ret
    }

    /// Spawn a new task from an ELF image
    ///
    /// # Arguments
    /// * `elf_data` - Slice containing the ELF binary
    ///
    /// # Returns
    /// * On success: task ID of the new task (>= 0)
    /// * On failure: negative error code
    pub fn spawn(elf_data: &[u8]) -> isize {
        let ret: isize;
        unsafe {
            asm!(
                "svc #0",
                inout("x0") elf_data.as_ptr() => ret,
                in("x1") elf_data.len(),
                in("x8") SYS_SPAWN,
                options(nostack)
            );
        }
        ret
    }

    /// Create child process (fork)
    ///
    /// # Returns
    /// * In parent: child's PID (>= 0)
    /// * In child: 0
    /// * On failure: negative error code
    pub fn fork() -> isize {
        let ret: isize;
        unsafe {
            asm!(
                "svc #0",
                out("x0") ret,
                in("x8") SYS_FORK,
                options(nostack)
            );
        }
        ret
    }

    /// Register current task as handler for an IRQ
    ///
    /// # Arguments
    /// * `irq` - IRQ number (GIC interrupt ID)
    ///
    /// # Returns
    /// * 0 on success
    /// * Negative error code on failure
    pub fn irq_register(irq: u32) -> isize {
        let ret: isize;
        unsafe {
            asm!(
                "svc #0",
                inout("x0") irq as u64 => ret,
                in("x8") SYS_IRQ_REGISTER,
                options(nostack)
            );
        }
        ret
    }

    /// Wait for an IRQ to fire
    ///
    /// If the IRQ is already pending, returns immediately.
    /// Otherwise, blocks until the IRQ fires.
    ///
    /// # Arguments
    /// * `irq` - IRQ number
    ///
    /// # Returns
    /// * 0 when IRQ fires
    /// * Negative error code on failure
    pub fn irq_wait(irq: u32) -> isize {
        let ret: isize;
        unsafe {
            asm!(
                "svc #0",
                inout("x0") irq as u64 => ret,
                in("x8") SYS_IRQ_WAIT,
                options(nostack)
            );
        }
        ret
    }

    /// Acknowledge an IRQ (clear pending flag and send EOI)
    ///
    /// Must be called after handling an IRQ to re-enable it.
    ///
    /// # Arguments
    /// * `irq` - IRQ number
    ///
    /// # Returns
    /// * 0 on success
    /// * Negative error code on failure
    pub fn irq_ack(irq: u32) -> isize {
        let ret: isize;
        unsafe {
            asm!(
                "svc #0",
                inout("x0") irq as u64 => ret,
                in("x8") SYS_IRQ_ACK,
                options(nostack)
            );
        }
        ret
    }

    /// Send asynchronous notification to a task
    ///
    /// Sets notification bits on the target task. If the target is waiting
    /// for any of these bits, it will be woken up.
    ///
    /// # Arguments
    /// * `dest` - Target task ID
    /// * `bits` - Notification bits to set
    ///
    /// # Returns
    /// * 0 on success
    /// * Negative error code on failure
    pub fn notify(dest: usize, bits: u64) -> isize {
        let ret: isize;
        unsafe {
            asm!(
                "svc #0",
                inout("x0") dest => ret,
                in("x1") bits,
                in("x8") SYS_NOTIFY,
                options(nostack)
            );
        }
        ret
    }

    /// Wait for notification bits
    ///
    /// Blocks until any of the expected notification bits are set.
    /// Returns immediately if any expected bits are already pending.
    ///
    /// # Arguments
    /// * `expected_bits` - Bits to wait for (0 = any bit)
    ///
    /// # Returns
    /// * Matched notification bits (which are then cleared)
    pub fn wait_notify(expected_bits: u64) -> u64 {
        let ret: u64;
        unsafe {
            asm!(
                "svc #0",
                inout("x0") expected_bits => ret,
                in("x8") SYS_WAIT_NOTIFY,
                options(nostack)
            );
        }
        ret
    }

    /// Create a pipe
    ///
    /// Creates a unidirectional pipe with a read end and write end.
    ///
    /// # Returns
    /// * (read_fd, write_fd) tuple on success
    /// * (-1, -1) on failure
    pub fn pipe() -> (isize, isize) {
        let read_fd: isize;
        let write_fd: isize;
        unsafe {
            asm!(
                "svc #0",
                out("x0") read_fd,
                out("x1") write_fd,
                in("x8") SYS_PIPE,
                options(nostack)
            );
        }
        (read_fd, write_fd)
    }

    /// Duplicate a file descriptor
    ///
    /// Returns the lowest available fd number that is a copy of oldfd.
    pub fn dup(oldfd: usize) -> isize {
        let ret: isize;
        unsafe {
            asm!(
                "svc #0",
                inout("x0") oldfd => ret,
                in("x8") SYS_DUP,
                options(nostack)
            );
        }
        ret
    }

    /// Duplicate a file descriptor to a specific number
    ///
    /// If newfd is already open, it is closed first.
    pub fn dup2(oldfd: usize, newfd: usize) -> isize {
        let ret: isize;
        unsafe {
            asm!(
                "svc #0",
                inout("x0") oldfd => ret,
                in("x1") newfd,
                in("x2") 0u64,  // flags (O_CLOEXEC not supported yet)
                in("x8") SYS_DUP3,
                options(nostack)
            );
        }
        ret
    }

    /// Open flags
    pub const O_RDONLY: u32 = 0;
    pub const O_WRONLY: u32 = 1;
    pub const O_RDWR: u32 = 2;
    pub const O_CREAT: u32 = 0o100;
    pub const O_TRUNC: u32 = 0o1000;
    pub const O_APPEND: u32 = 0o2000;
    pub const O_DIRECTORY: u32 = 0o200000;

    /// AT_FDCWD constant for openat
    pub const AT_FDCWD: i32 = -100;

    /// Open a file
    ///
    /// # Arguments
    /// * `path` - Path to the file (null-terminated)
    /// * `flags` - Open flags (O_RDONLY, O_WRONLY, etc.)
    ///
    /// # Returns
    /// * File descriptor on success
    /// * Negative error code on failure
    pub fn open(path: &[u8], flags: u32) -> isize {
        let ret: isize;
        unsafe {
            asm!(
                "svc #0",
                inout("x0") AT_FDCWD as i64 => ret,
                in("x1") path.as_ptr(),
                in("x2") flags as u64,
                in("x3") 0u64,  // mode (ignored for now)
                in("x8") SYS_OPENAT,
                options(nostack)
            );
        }
        ret
    }

    /// Get current working directory
    ///
    /// # Arguments
    /// * `buf` - Buffer to store the path
    ///
    /// # Returns
    /// * Buffer address on success
    /// * Negative error code on failure
    pub fn getcwd(buf: &mut [u8]) -> isize {
        let ret: isize;
        unsafe {
            asm!(
                "svc #0",
                inout("x0") buf.as_mut_ptr() => ret,
                in("x1") buf.len(),
                in("x8") SYS_GETCWD,
                options(nostack)
            );
        }
        ret
    }

    /// Change current working directory
    ///
    /// # Arguments
    /// * `path` - Path to the new directory (null-terminated)
    ///
    /// # Returns
    /// * 0 on success
    /// * Negative error code on failure
    pub fn chdir(path: &[u8]) -> isize {
        let ret: isize;
        unsafe {
            asm!(
                "svc #0",
                inout("x0") path.as_ptr() => ret,
                in("x8") SYS_CHDIR,
                options(nostack)
            );
        }
        ret
    }

    /// Stat structure (simplified)
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct Stat {
        pub st_dev: u64,
        pub st_ino: u64,
        pub st_mode: u32,
        pub st_nlink: u32,
        pub st_uid: u32,
        pub st_gid: u32,
        pub st_rdev: u64,
        pub __pad1: u64,
        pub st_size: i64,
        pub st_blksize: i32,
        pub __pad2: i32,
        pub st_blocks: i64,
        pub st_atime: i64,
        pub st_atime_nsec: i64,
        pub st_mtime: i64,
        pub st_mtime_nsec: i64,
        pub st_ctime: i64,
        pub st_ctime_nsec: i64,
        pub __unused: [i32; 2],
    }

    /// File mode bits
    pub const S_IFMT: u32 = 0o170000;
    pub const S_IFDIR: u32 = 0o040000;
    pub const S_IFREG: u32 = 0o100000;

    /// Get file status
    ///
    /// # Arguments
    /// * `fd` - File descriptor
    /// * `stat` - Stat structure to fill
    ///
    /// # Returns
    /// * 0 on success
    /// * Negative error code on failure
    pub fn fstat(fd: usize, stat: &mut Stat) -> isize {
        let ret: isize;
        unsafe {
            asm!(
                "svc #0",
                inout("x0") fd => ret,
                in("x1") stat as *mut Stat,
                in("x8") SYS_FSTAT,
                options(nostack)
            );
        }
        ret
    }

    /// Directory entry structure
    #[repr(C)]
    pub struct Dirent64 {
        pub d_ino: u64,
        pub d_off: i64,
        pub d_reclen: u16,
        pub d_type: u8,
        pub d_name: [u8; 256],
    }

    /// Directory entry types
    pub const DT_UNKNOWN: u8 = 0;
    pub const DT_REG: u8 = 8;
    pub const DT_DIR: u8 = 4;

    /// Get directory entries
    ///
    /// # Arguments
    /// * `fd` - Directory file descriptor
    /// * `buf` - Buffer for dirent64 structures
    ///
    /// # Returns
    /// * Number of bytes read on success
    /// * 0 on end of directory
    /// * Negative error code on failure
    pub fn getdents64(fd: usize, buf: &mut [u8]) -> isize {
        let ret: isize;
        unsafe {
            asm!(
                "svc #0",
                inout("x0") fd => ret,
                in("x1") buf.as_mut_ptr(),
                in("x2") buf.len(),
                in("x8") SYS_GETDENTS64,
                options(nostack)
            );
        }
        ret
    }

    /// Wait options
    pub const WNOHANG: u32 = 1;

    /// Wait for child process
    ///
    /// # Arguments
    /// * `pid` - Child PID to wait for (-1 for any)
    /// * `options` - Wait options (WNOHANG, etc.)
    ///
    /// # Returns
    /// * (pid, status) on success
    /// * (negative error, 0) on failure
    pub fn waitpid(pid: i32, options: u32) -> (isize, i32) {
        let ret: isize;
        let mut status: i32 = 0;
        unsafe {
            asm!(
                "svc #0",
                inout("x0") pid as i64 => ret,
                in("x1") &mut status as *mut i32,
                in("x2") options as u64,
                in("x3") 0u64,  // rusage (ignored)
                in("x8") SYS_WAIT4,
                options(nostack)
            );
        }
        (ret, status)
    }

    /// Change data segment size (heap)
    ///
    /// # Arguments
    /// * `addr` - New brk address (0 to query current)
    ///
    /// # Returns
    /// * New/current brk address
    pub fn brk(addr: usize) -> usize {
        let ret: usize;
        unsafe {
            asm!(
                "svc #0",
                inout("x0") addr => ret,
                in("x8") SYS_BRK,
                options(nostack)
            );
        }
        ret
    }

    /// Execute a program, replacing the current process image
    ///
    /// # Arguments
    /// * `pathname` - Path to the executable (null-terminated)
    /// * `argv` - Argument array (null-terminated array of null-terminated strings)
    /// * `envp` - Environment array (null-terminated array of null-terminated strings)
    ///
    /// # Returns
    /// * On success: does not return (replaced by new program)
    /// * On failure: negative error code
    ///
    /// # Safety
    /// The caller must ensure:
    /// - pathname points to a valid null-terminated string
    /// - argv and envp point to valid null-terminated arrays
    /// - All string pointers in argv and envp are valid
    pub fn execve(pathname: *const u8, argv: *const *const u8, envp: *const *const u8) -> isize {
        let ret: isize;
        unsafe {
            asm!(
                "svc #0",
                inout("x0") pathname => ret,
                in("x1") argv,
                in("x2") envp,
                in("x8") SYS_EXECVE,
                options(nostack)
            );
        }
        ret
    }

    // ========================================================================
    // New BusyBox support syscalls
    // ========================================================================

    /// Timespec structure for clock_gettime
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct Timespec {
        pub tv_sec: i64,
        pub tv_nsec: i64,
    }

    /// Clock IDs
    pub const CLOCK_REALTIME: i32 = 0;
    pub const CLOCK_MONOTONIC: i32 = 1;

    /// Get current time
    pub fn clock_gettime(clock_id: i32, tp: &mut Timespec) -> isize {
        let ret: isize;
        unsafe {
            asm!(
                "svc #0",
                inout("x0") clock_id as i64 => ret,
                in("x1") tp as *mut Timespec,
                in("x8") SYS_CLOCK_GETTIME,
                options(nostack)
            );
        }
        ret
    }

    /// mmap protection flags
    pub const PROT_NONE: u32 = 0x0;
    pub const PROT_READ: u32 = 0x1;
    pub const PROT_WRITE: u32 = 0x2;
    pub const PROT_EXEC: u32 = 0x4;

    /// mmap flags
    pub const MAP_SHARED: u32 = 0x01;
    pub const MAP_PRIVATE: u32 = 0x02;
    pub const MAP_FIXED: u32 = 0x10;
    pub const MAP_ANONYMOUS: u32 = 0x20;

    /// mmap failure value
    pub const MAP_FAILED: usize = usize::MAX;

    /// Map memory region (anonymous only)
    pub fn mmap(addr: usize, len: usize, prot: u32, flags: u32, fd: i32, offset: i64) -> isize {
        let ret: isize;
        unsafe {
            asm!(
                "svc #0",
                inout("x0") addr => ret,
                in("x1") len,
                in("x2") prot as u64,
                in("x3") flags as u64,
                in("x4") fd as i64,
                in("x5") offset,
                in("x8") SYS_MMAP,
                options(nostack)
            );
        }
        ret
    }

    /// Unmap memory region
    pub fn munmap(addr: usize, len: usize) -> isize {
        let ret: isize;
        unsafe {
            asm!(
                "svc #0",
                inout("x0") addr => ret,
                in("x1") len,
                in("x8") SYS_MUNMAP,
                options(nostack)
            );
        }
        ret
    }

    /// Change memory protection
    pub fn mprotect(addr: usize, len: usize, prot: u32) -> isize {
        let ret: isize;
        unsafe {
            asm!(
                "svc #0",
                inout("x0") addr => ret,
                in("x1") len,
                in("x2") prot as u64,
                in("x8") SYS_MPROTECT,
                options(nostack)
            );
        }
        ret
    }

    /// Signal numbers
    pub const SIGCHLD: i32 = 17;

    /// Signal handler values
    pub const SIG_DFL: u64 = 0;
    pub const SIG_IGN: u64 = 1;

    /// Sigaction structure (simplified)
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Sigaction {
        pub sa_handler: u64,
        pub sa_flags: u64,
        pub sa_restorer: u64,
        pub sa_mask: u64,
    }

    impl Default for Sigaction {
        fn default() -> Self {
            Self {
                sa_handler: SIG_DFL,
                sa_flags: 0,
                sa_restorer: 0,
                sa_mask: 0,
            }
        }
    }

    /// Set signal handler
    pub fn sigaction(sig: i32, act: Option<&Sigaction>, oldact: Option<&mut Sigaction>) -> isize {
        let ret: isize;
        let act_ptr = act.map(|a| a as *const Sigaction).unwrap_or(core::ptr::null());
        let oldact_ptr = oldact.map(|a| a as *mut Sigaction).unwrap_or(core::ptr::null_mut());
        unsafe {
            asm!(
                "svc #0",
                inout("x0") sig as i64 => ret,
                in("x1") act_ptr,
                in("x2") oldact_ptr,
                in("x3") 8u64,  // sigsetsize
                in("x8") SYS_RT_SIGACTION,
                options(nostack)
            );
        }
        ret
    }

    /// sigprocmask "how" values
    pub const SIG_BLOCK: i32 = 0;
    pub const SIG_UNBLOCK: i32 = 1;
    pub const SIG_SETMASK: i32 = 2;

    /// Set signal mask
    pub fn sigprocmask(how: i32, set: Option<&u64>, oldset: Option<&mut u64>) -> isize {
        let ret: isize;
        let set_ptr = set.map(|s| s as *const u64).unwrap_or(core::ptr::null());
        let oldset_ptr = oldset.map(|s| s as *mut u64).unwrap_or(core::ptr::null_mut());
        unsafe {
            asm!(
                "svc #0",
                inout("x0") how as i64 => ret,
                in("x1") set_ptr,
                in("x2") oldset_ptr,
                in("x3") 8u64,  // sigsetsize
                in("x8") SYS_RT_SIGPROCMASK,
                options(nostack)
            );
        }
        ret
    }

    /// Send signal to process
    pub fn kill(pid: i32, sig: i32) -> isize {
        let ret: isize;
        unsafe {
            asm!(
                "svc #0",
                inout("x0") pid as i64 => ret,
                in("x1") sig as i64,
                in("x8") SYS_KILL,
                options(nostack)
            );
        }
        ret
    }

    /// Syscall number for sigreturn
    pub const SYS_RT_SIGRETURN: u64 = 139;

    /// Return from signal handler
    ///
    /// This restores the context that was saved before the signal handler was invoked.
    /// Must be called at the end of signal handlers.
    pub fn sigreturn() -> ! {
        unsafe {
            asm!(
                "svc #0",
                in("x8") SYS_RT_SIGRETURN,
                options(noreturn, nostack)
            );
        }
    }

    // ========================================================================
    // musl startup syscalls
    // ========================================================================

    /// Set TID address for thread exit notification
    ///
    /// Returns the current task ID.
    pub fn set_tid_address(tidptr: *mut i32) -> isize {
        let ret: isize;
        unsafe {
            asm!(
                "svc #0",
                inout("x0") tidptr => ret,
                in("x8") SYS_SET_TID_ADDRESS,
                options(nostack)
            );
        }
        ret
    }

    /// Resource limit constants
    pub const RLIMIT_STACK: i32 = 3;
    pub const RLIMIT_NOFILE: i32 = 7;

    /// Rlimit structure
    #[repr(C)]
    pub struct Rlimit {
        pub rlim_cur: u64,
        pub rlim_max: u64,
    }

    /// Get/set resource limits
    ///
    /// If pid is 0, operates on the current process.
    pub fn prlimit64(
        pid: i32,
        resource: i32,
        new_limit: Option<&Rlimit>,
        old_limit: Option<&mut Rlimit>,
    ) -> isize {
        let ret: isize;
        let new_ptr = new_limit.map(|l| l as *const Rlimit).unwrap_or(core::ptr::null());
        let old_ptr = old_limit.map(|l| l as *mut Rlimit).unwrap_or(core::ptr::null_mut());
        unsafe {
            asm!(
                "svc #0",
                inout("x0") pid as i64 => ret,
                in("x1") resource as i64,
                in("x2") new_ptr,
                in("x3") old_ptr,
                in("x8") SYS_PRLIMIT64,
                options(nostack)
            );
        }
        ret
    }

    /// getrandom flags
    pub const GRND_NONBLOCK: u32 = 1;
    pub const GRND_RANDOM: u32 = 2;

    /// Fill buffer with random bytes
    pub fn getrandom(buf: &mut [u8], flags: u32) -> isize {
        let ret: isize;
        unsafe {
            asm!(
                "svc #0",
                inout("x0") buf.as_mut_ptr() => ret,
                in("x1") buf.len(),
                in("x2") flags as u64,
                in("x8") SYS_GETRANDOM,
                options(nostack)
            );
        }
        ret
    }

    // ========================================================================
    // Vector I/O (writev/readv)
    // ========================================================================

    /// I/O vector for scatter/gather I/O
    #[repr(C)]
    pub struct Iovec {
        pub iov_base: *const u8,
        pub iov_len: usize,
    }

    /// Write from multiple buffers (gather write)
    pub fn writev(fd: usize, iov: &[Iovec]) -> isize {
        let ret: isize;
        unsafe {
            asm!(
                "svc #0",
                inout("x0") fd => ret,
                in("x1") iov.as_ptr(),
                in("x2") iov.len(),
                in("x8") SYS_WRITEV,
                options(nostack)
            );
        }
        ret
    }

    /// Read into multiple buffers (scatter read)
    pub fn readv(fd: usize, iov: &mut [Iovec]) -> isize {
        let ret: isize;
        unsafe {
            asm!(
                "svc #0",
                inout("x0") fd => ret,
                in("x1") iov.as_mut_ptr(),
                in("x2") iov.len(),
                in("x8") SYS_READV,
                options(nostack)
            );
        }
        ret
    }

    // ========================================================================
    // IOCTL
    // ========================================================================

    /// Terminal window size
    #[repr(C)]
    pub struct Winsize {
        pub ws_row: u16,
        pub ws_col: u16,
        pub ws_xpixel: u16,
        pub ws_ypixel: u16,
    }

    /// IOCTL request codes
    pub const TIOCGWINSZ: u64 = 0x5413;
    pub const TCGETS: u64 = 0x5401;

    /// Perform ioctl on a file descriptor
    pub fn ioctl(fd: usize, request: u64, arg: usize) -> isize {
        let ret: isize;
        unsafe {
            asm!(
                "svc #0",
                inout("x0") fd => ret,
                in("x1") request,
                in("x2") arg,
                in("x8") SYS_IOCTL,
                options(nostack)
            );
        }
        ret
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
    pub const MSG_READ: u64 = 0;
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
    pub const VFS_READDIR: u64 = 105;   // Read directory entries
    pub const VFS_READ_SHM: u64 = 110;  // Read via shared memory
    pub const VFS_WRITE_SHM: u64 = 111; // Write via shared memory

    // Block device server messages
    pub const BLK_READ: u64 = 200;      // Read sectors
    pub const BLK_WRITE: u64 = 201;     // Write sectors
    pub const BLK_INFO: u64 = 202;      // Get device info (sector count, sector size)

    // Network device server messages
    pub const NET_SEND: u64 = 300;      // Send packet (shm_id, offset, len)
    pub const NET_RECV: u64 = 301;      // Receive packet (shm_id, offset, max_len)
    pub const NET_INFO: u64 = 302;      // Get device info (MAC, link status)

    // Pipe server messages
    pub const PIPE_CREATE: u64 = 500;   // Create new pipe -> returns pipe_id
    pub const PIPE_READ: u64 = 501;     // Read from pipe (pipe_id, shm_id, max_len)
    pub const PIPE_WRITE: u64 = 502;    // Write to pipe (pipe_id, shm_id, len)
    pub const PIPE_CLOSE: u64 = 503;    // Close pipe end (pipe_id, is_read_end)

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

/// VirtIO block device IRQ (SPI 48 + 32 for GIC offset)
pub const VIRTIO_BLK_IRQ: u32 = 48 + 32;

/// VirtIO network device IRQ (SPI 49 + 32 for GIC offset)
/// Each VirtIO MMIO slot gets its own IRQ (48, 49, 50, ...)
pub const VIRTIO_NET_IRQ: u32 = 49 + 32;

// ============================================================================
// Well-known Task IDs
// ============================================================================

pub mod tasks {
    pub const IDLE: usize = 0;
    pub const CONSOLE: usize = 1;
    pub const INIT: usize = 2;
    pub const VFS: usize = 3;
    pub const BLKDEV: usize = 4;
    pub const NETDEV: usize = 5;
    pub const PIPESERV: usize = 6;
}
