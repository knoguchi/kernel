//! System call dispatcher for Kenix
//!
//! IPC syscall numbers (Kenix microkernel):
//! - 1: SYS_SEND  - Send message, block until received
//! - 2: SYS_RECV  - Receive message, block until available
//! - 3: SYS_CALL  - Send + wait for reply (RPC)
//! - 4: SYS_REPLY - Reply to caller
//!
//! Legacy syscall numbers (Linux-compatible, kept for transition):
//! - 64: SYS_WRITE - Write to file descriptor
//! - 93: SYS_EXIT  - Terminate the current task
//!
//! Kenix-specific syscall numbers:
//! - 0: SYS_YIELD - Voluntarily yield the CPU

use crate::exception::ExceptionContext;
use crate::sched::{self, TaskId, Message, TaskState, FileDescriptor, PendingSyscall, KERNEL_STACK_SIZE};
use crate::sched::task::find_free_slot;
use crate::ipc;
use crate::shm;
use crate::irq;
use crate::timer;
use crate::mmap;
use crate::mm::frame::{alloc_frame, free_frame, PAGE_SIZE};
use crate::mm::AddressSpace;
use core::ptr;
use crate::println;

/// Pipe server task ID
const PIPESERV_TID: TaskId = TaskId(6);

/// Pipe server IPC message tags
const PIPE_CREATE: u64 = 500;
const PIPE_READ: u64 = 501;
const PIPE_WRITE: u64 = 502;
const PIPE_CLOSE: u64 = 503;

/// Syscall numbers - IPC (Kenix microkernel)
pub const SYS_SEND: u16 = 1;     // Send message, block until received
pub const SYS_RECV: u16 = 2;     // Receive message, block until available
pub const SYS_CALL: u16 = 3;     // Send + wait for reply (RPC)
pub const SYS_REPLY: u16 = 4;    // Reply to caller
pub const SYS_REPLY_TO: u16 = 5; // Reply to a specific task (for deferred replies)

/// Syscall numbers - Shared Memory
pub const SYS_SHMCREATE: u16 = 10;  // Create shared memory region
pub const SYS_SHMMAP: u16 = 11;     // Map shared memory into current task
pub const SYS_SHMUNMAP: u16 = 12;   // Unmap shared memory from current task
pub const SYS_SHMGRANT: u16 = 13;   // Grant another task access to shared memory

/// Syscall numbers - Kenix-specific
pub const SYS_YIELD: u16 = 0;    // Voluntarily yield CPU
pub const SYS_NOTIFY: u16 = 7;   // Send async notification
pub const SYS_WAIT_NOTIFY: u16 = 8;  // Wait for notification
pub const SYS_GETPID: u16 = 172;  // Get current task ID (Linux number)
pub const SYS_SPAWN: u16 = 21;   // Create new task from ELF
pub const SYS_FORK: u16 = 22;    // Create child process (fork) - Kenix number
pub const SYS_CLONE: u16 = 220;  // Linux clone (treated as fork for now)

/// Syscall numbers - IRQ handling
pub const SYS_IRQ_REGISTER: u16 = 30;  // Register for IRQ handling
pub const SYS_IRQ_WAIT: u16 = 31;      // Wait for IRQ to fire
pub const SYS_IRQ_ACK: u16 = 32;       // Acknowledge IRQ

/// Syscall numbers - POSIX-compatible file I/O
pub const SYS_DUP: u16 = 23;     // Duplicate file descriptor
pub const SYS_DUP3: u16 = 24;    // Duplicate fd to specific number (dup2 equivalent)
pub const SYS_CHDIR: u16 = 49;   // Change working directory
pub const SYS_GETCWD: u16 = 17;  // Get current working directory
pub const SYS_OPENAT: u16 = 56;  // Open file relative to directory fd
pub const SYS_CLOSE: u16 = 57;   // Close file descriptor
pub const SYS_PIPE: u16 = 59;    // Create pipe
pub const SYS_GETDENTS64: u16 = 61;  // Get directory entries
pub const SYS_READ: u16 = 63;    // Read from file descriptor
pub const SYS_WRITE: u16 = 64;   // Write to file descriptor
pub const SYS_READV: u16 = 65;   // Read into multiple buffers (scatter)
pub const SYS_WRITEV: u16 = 66;  // Write from multiple buffers (gather)
pub const SYS_PPOLL: u16 = 73;   // Poll with timeout
pub const SYS_FSTATAT: u16 = 79; // Get file status at directory
pub const SYS_FSTAT: u16 = 80;   // Get file status
pub const SYS_EXIT: u16 = 93;    // Terminate process
pub const SYS_EXIT_GROUP: u16 = 94;  // Terminate all threads (same as exit for single-threaded)
pub const SYS_WAIT4: u16 = 260;  // Wait for child process
pub const SYS_BRK: u16 = 214;    // Change data segment size
pub const SYS_EXECVE: u16 = 221; // Execute program

// Stub syscalls (return success or reasonable defaults)
pub const SYS_FCNTL: u16 = 25;   // File control (stub)
pub const SYS_IOCTL: u16 = 29;   // I/O control (stub)
pub const SYS_FACCESSAT: u16 = 48;  // Check file access (stub)
pub const SYS_CLOCK_GETTIME: u16 = 113;  // Get clock time
pub const SYS_UNAME: u16 = 160;  // Get system name (stub)
pub const SYS_GETUID: u16 = 174; // Get user ID (stub)
pub const SYS_GETEUID: u16 = 175; // Get effective user ID (stub)
pub const SYS_GETGID: u16 = 176; // Get group ID (stub)
pub const SYS_GETEGID: u16 = 177; // Get effective group ID (stub)

// Memory mapping syscalls
pub const SYS_MUNMAP: u16 = 215;    // Unmap memory region
pub const SYS_MMAP: u16 = 222;      // Map memory region
pub const SYS_MPROTECT: u16 = 226;  // Change memory protection

// musl startup syscalls
pub const SYS_SET_TID_ADDRESS: u16 = 96;  // Set pointer for thread ID on exit
pub const SYS_FUTEX: u16 = 98;            // Fast userspace mutex
pub const SYS_SET_ROBUST_LIST: u16 = 99;  // Set robust futex list
pub const SYS_PRLIMIT64: u16 = 261;       // Get/set resource limits
pub const SYS_GETRANDOM: u16 = 278;       // Get random bytes

// Additional syscalls
pub const SYS_READLINKAT: u16 = 78;       // Read symbolic link
pub const SYS_PRCTL: u16 = 167;           // Process control
pub const SYS_GETPPID: u16 = 173;         // Get parent process ID
pub const SYS_GETTID: u16 = 178;          // Get thread ID
pub const SYS_RSEQ: u16 = 293;            // Restartable sequence (stub)

// Signal syscalls
pub const SYS_KILL: u16 = 129;              // Send signal to process
pub const SYS_RT_SIGACTION: u16 = 134;      // Set signal handler
pub const SYS_RT_SIGPROCMASK: u16 = 135;    // Set signal mask
pub const SYS_RT_SIGRETURN: u16 = 139;      // Return from signal handler

// Scheduler syscalls
pub const SYS_SCHED_SETAFFINITY: u16 = 122; // Set CPU affinity mask
pub const SYS_SCHED_GETAFFINITY: u16 = 123; // Get CPU affinity mask

// Process group syscalls
pub const SYS_SETPGID: u16 = 154;           // Set process group ID
pub const SYS_GETPGID: u16 = 155;           // Get process group ID

// File transfer syscalls
pub const SYS_SENDFILE: u16 = 71;           // Transfer data between file descriptors (stub)
pub const SYS_FADVISE64: u16 = 223;         // File access pattern hint (stub)

/// Error codes (Linux-compatible)
pub const ESUCCESS: i64 = 0;   // Success
pub const ENOENT: i64 = -2;    // No such file or directory
pub const ESRCH: i64 = -3;     // No such process
pub const ECHILD: i64 = -10;   // No child processes
pub const EAGAIN: i64 = -11;   // Resource temporarily unavailable
pub const ENOMEM: i64 = -12;   // Out of memory
pub const EBADF: i64 = -9;     // Bad file descriptor
pub const EFAULT: i64 = -14;   // Bad address
pub const ENOTDIR: i64 = -20;  // Not a directory
pub const EINVAL: i64 = -22;   // Invalid argument
pub const EMFILE: i64 = -24;   // Too many open files
pub const ENOSYS: i64 = -38;   // Function not implemented
pub const ENAMETOOLONG: i64 = -36;  // File name too long

/// Handle a system call
///
/// # Arguments
/// * `ctx` - Exception context (registers)
/// * `syscall_num` - Syscall number from x8 register (AArch64 convention)
///
/// # Returns
/// The return value is placed in ctx.gpr[0] (x0)
pub fn handle_syscall(ctx: &mut ExceptionContext, _svc_imm: u16) {
    // AArch64 Linux syscall convention: syscall number in x8
    let syscall_num = ctx.gpr[8] as u16;

    match syscall_num {
        SYS_YIELD => {
            ctx.gpr[0] = sys_yield() as u64;
        }

        // Notification syscalls
        // SYS_NOTIFY: x0=dest_tid, x1=bits → returns result in x0
        SYS_NOTIFY => {
            let dest = TaskId(ctx.gpr[0] as usize);
            let bits = ctx.gpr[1];
            ctx.gpr[0] = sys_notify(dest, bits) as u64;
        }

        // SYS_WAIT_NOTIFY: x0=expected_bits → returns received bits in x0
        SYS_WAIT_NOTIFY => {
            let expected_bits = ctx.gpr[0];
            let result = sys_wait_notify(ctx, expected_bits);
            ctx.gpr[0] = result as u64;
        }

        // IPC syscalls - register convention:
        // SYS_SEND: x0=dest_tid, x1=tag, x2-x5=data → returns result in x0
        // SYS_RECV: x0=from_tid (-1 for any) → returns sender_tid in x0, tag in x1, data in x2-x5
        // SYS_CALL: x0=dest_tid, x1=tag, x2-x5=data → returns reply_tag in x0, reply_data in x1-x4
        // SYS_REPLY: x0=tag, x1-x4=data → returns result in x0

        SYS_SEND => {
            let dest = TaskId(ctx.gpr[0] as usize);
            let msg = Message::new(ctx.gpr[1], [ctx.gpr[2], ctx.gpr[3], ctx.gpr[4], ctx.gpr[5]]);
            let result = ipc::sys_send(ctx, dest, msg);
            ctx.gpr[0] = result as u64;
        }

        SYS_RECV => {
            let from = ctx.gpr[0] as usize;
            let from_filter = if from == usize::MAX {
                None // -1 means any
            } else {
                Some(TaskId(from))
            };
            let (sender_id, msg) = ipc::sys_recv(ctx, from_filter);
            // Return sender_tid in x0, tag in x1, data in x2-x5
            ctx.gpr[0] = sender_id.0 as u64;
            ctx.gpr[1] = msg.tag;
            ctx.gpr[2] = msg.data[0];
            ctx.gpr[3] = msg.data[1];
            ctx.gpr[4] = msg.data[2];
            ctx.gpr[5] = msg.data[3];
        }

        SYS_CALL => {
            let dest = TaskId(ctx.gpr[0] as usize);
            let msg = Message::new(ctx.gpr[1], [ctx.gpr[2], ctx.gpr[3], ctx.gpr[4], ctx.gpr[5]]);
            let reply = ipc::sys_call(ctx, dest, msg);
            // Return reply_tag in x0, reply_data in x1-x4
            ctx.gpr[0] = reply.tag;
            ctx.gpr[1] = reply.data[0];
            ctx.gpr[2] = reply.data[1];
            ctx.gpr[3] = reply.data[2];
            ctx.gpr[4] = reply.data[3];
        }

        SYS_REPLY => {
            let msg = Message::new(ctx.gpr[0], [ctx.gpr[1], ctx.gpr[2], ctx.gpr[3], ctx.gpr[4]]);
            let result = ipc::sys_reply(msg);
            ctx.gpr[0] = result as u64;
        }

        // SYS_REPLY_TO: x0=target_task, x1=tag, x2-x5=data → returns result in x0
        SYS_REPLY_TO => {
            let target = TaskId(ctx.gpr[0] as usize);
            let msg = Message::new(ctx.gpr[1], [ctx.gpr[2], ctx.gpr[3], ctx.gpr[4], ctx.gpr[5]]);
            let result = ipc::sys_reply_to(target, msg);
            ctx.gpr[0] = result as u64;
        }

        // Shared memory syscalls
        // SYS_SHMCREATE: x0=size → returns shm_id in x0
        SYS_SHMCREATE => {
            let size = ctx.gpr[0] as usize;
            ctx.gpr[0] = shm::sys_shmcreate(size) as u64;
        }

        // SYS_SHMMAP: x0=shm_id, x1=vaddr_hint → returns vaddr in x0
        SYS_SHMMAP => {
            let shm_id = ctx.gpr[0] as usize;
            let vaddr_hint = ctx.gpr[1] as usize;
            ctx.gpr[0] = shm::sys_shmmap(shm_id, vaddr_hint) as u64;
        }

        // SYS_SHMUNMAP: x0=shm_id → returns result in x0
        SYS_SHMUNMAP => {
            let shm_id = ctx.gpr[0] as usize;
            ctx.gpr[0] = shm::sys_shmunmap(shm_id) as u64;
        }

        // SYS_SHMGRANT: x0=shm_id, x1=task_id → returns result in x0
        SYS_SHMGRANT => {
            let shm_id = ctx.gpr[0] as usize;
            let task_id = ctx.gpr[1] as usize;
            ctx.gpr[0] = shm::sys_shmgrant(shm_id, task_id) as u64;
        }

        // POSIX-compatible file I/O syscalls
        SYS_READ => {
            let fd = ctx.gpr[0] as usize;
            let buf = ctx.gpr[1] as usize;
            let len = ctx.gpr[2] as usize;
            ctx.gpr[0] = sys_read(ctx, fd, buf, len) as u64;
        }

        SYS_WRITE => {
            let fd = ctx.gpr[0] as usize;
            let buf = ctx.gpr[1] as usize;
            let len = ctx.gpr[2] as usize;
            ctx.gpr[0] = sys_write(ctx, fd, buf, len) as u64;
        }

        SYS_READV => {
            // readv(fd, iov, iovcnt) - scatter read
            let fd = ctx.gpr[0] as usize;
            let iov = ctx.gpr[1] as usize;
            let iovcnt = ctx.gpr[2] as usize;
            ctx.gpr[0] = sys_readv(ctx, fd, iov, iovcnt) as u64;
        }

        SYS_WRITEV => {
            // writev(fd, iov, iovcnt) - gather write
            let fd = ctx.gpr[0] as usize;
            let iov = ctx.gpr[1] as usize;
            let iovcnt = ctx.gpr[2] as usize;
            ctx.gpr[0] = sys_writev(ctx, fd, iov, iovcnt) as u64;
        }

        SYS_CLOSE => {
            let fd = ctx.gpr[0] as usize;
            ctx.gpr[0] = sys_close(ctx, fd) as u64;
        }

        // SYS_DUP: x0=oldfd → returns new_fd in x0
        SYS_DUP => {
            let oldfd = ctx.gpr[0] as usize;
            ctx.gpr[0] = sys_dup(oldfd) as u64;
        }

        // SYS_DUP3: x0=oldfd, x1=newfd, x2=flags → returns new_fd in x0
        SYS_DUP3 => {
            let oldfd = ctx.gpr[0] as usize;
            let newfd = ctx.gpr[1] as usize;
            let _flags = ctx.gpr[2] as u32;  // O_CLOEXEC not implemented yet
            ctx.gpr[0] = sys_dup2(oldfd, newfd) as u64;
        }

        // SYS_OPENAT: x0=dirfd, x1=pathname, x2=flags, x3=mode → returns fd in x0
        // Note: sys_open uses IPC and the actual return value is set by complete_pending_syscall
        SYS_OPENAT => {
            let _dirfd = ctx.gpr[0] as i32;  // AT_FDCWD = -100
            let pathname = ctx.gpr[1] as usize;
            let flags = ctx.gpr[2] as u32;
            let _mode = ctx.gpr[3] as u32;
            sys_open(ctx, pathname, flags);
            // Return value is set by complete_pending_syscall, don't overwrite it
        }

        // SYS_GETCWD: x0=buf, x1=size → returns buf address or error
        SYS_GETCWD => {
            let buf = ctx.gpr[0] as usize;
            let size = ctx.gpr[1] as usize;
            ctx.gpr[0] = sys_getcwd(buf, size) as u64;
        }

        // SYS_CHDIR: x0=path → returns 0 or error
        SYS_CHDIR => {
            let path = ctx.gpr[0] as usize;
            ctx.gpr[0] = sys_chdir(path) as u64;
        }

        // SYS_FSTAT: x0=fd, x1=statbuf → returns 0 or error
        SYS_FSTAT => {
            let fd = ctx.gpr[0] as usize;
            let statbuf = ctx.gpr[1] as usize;
            ctx.gpr[0] = sys_fstat(ctx, fd, statbuf) as u64;
        }
        // SYS_FSTATAT: x0=dirfd, x1=pathname, x2=statbuf, x3=flags → returns 0 or error
        SYS_FSTATAT => {
            let dirfd = ctx.gpr[0] as i32;
            let pathname = ctx.gpr[1] as usize;
            let statbuf = ctx.gpr[2] as usize;
            let _flags = ctx.gpr[3] as u32;
            ctx.gpr[0] = sys_fstatat(ctx, dirfd, pathname, statbuf) as u64;
        }
        // SYS_PPOLL: x0=fds, x1=nfds, x2=tmo_p, x3=sigmask → returns count or 0
        SYS_PPOLL => {
            // ppoll(fds, nfds, tmo_p, sigmask) - poll with timeout
            let fds = ctx.gpr[0] as usize;
            let nfds = ctx.gpr[1] as usize;
            ctx.gpr[0] = sys_ppoll(fds, nfds) as u64;
        }

        // SYS_GETDENTS64: x0=fd, x1=dirent_buf, x2=count → returns bytes read
        SYS_GETDENTS64 => {
            let fd = ctx.gpr[0] as usize;
            let buf = ctx.gpr[1] as usize;
            let count = ctx.gpr[2] as usize;
            ctx.gpr[0] = sys_getdents64(ctx, fd, buf, count) as u64;
        }

        // SYS_WAIT4: x0=pid, x1=wstatus, x2=options, x3=rusage → returns pid or error
        SYS_WAIT4 => {
            let pid = ctx.gpr[0] as i32;
            let wstatus = ctx.gpr[1] as usize;
            let options = ctx.gpr[2] as u32;
            ctx.gpr[0] = sys_wait4(ctx, pid, wstatus, options) as u64;
        }

        // SYS_BRK: x0=addr → returns new brk or current brk
        SYS_BRK => {
            let addr = ctx.gpr[0] as usize;
            ctx.gpr[0] = sys_brk(addr) as u64;
        }

        // SYS_PIPE: returns read_fd in x0, write_fd in x1
        SYS_PIPE => {
            let (read_fd, write_fd) = sys_pipe(ctx);
            ctx.gpr[0] = read_fd as u64;
            ctx.gpr[1] = write_fd as u64;
        }

        SYS_EXIT => {
            let exit_code = ctx.gpr[0] as i32;
            sys_exit_with_switch(ctx, exit_code);
            // Never returns
        }

        SYS_EXIT_GROUP => {
            // For single-threaded processes, exit_group is the same as exit
            let exit_code = ctx.gpr[0] as i32;
            sys_exit_with_switch(ctx, exit_code);
            // Never returns
        }

        SYS_GETPID => {
            ctx.gpr[0] = sys_getpid() as u64;
        }

        SYS_SPAWN => {
            let elf_ptr = ctx.gpr[0] as usize;
            let elf_len = ctx.gpr[1] as usize;
            ctx.gpr[0] = sys_spawn(elf_ptr, elf_len) as u64;
        }

        SYS_FORK => {
            ctx.gpr[0] = sys_fork(ctx) as u64;
        }
        SYS_CLONE => {
            // clone(flags, stack, ptid, tls, ctid) - treat as fork for now
            // musl's fork() calls clone(SIGCHLD, 0, ...) which is equivalent to fork
            ctx.gpr[0] = sys_fork(ctx) as u64;
        }

        // SYS_EXECVE: x0=pathname, x1=argv, x2=envp → returns error (doesn't return on success)
        SYS_EXECVE => {
            let pathname = ctx.gpr[0] as usize;
            let argv = ctx.gpr[1] as usize;
            let envp = ctx.gpr[2] as usize;
            ctx.gpr[0] = sys_execve(ctx, pathname, argv, envp) as u64;
        }

        // IRQ syscalls
        // SYS_IRQ_REGISTER: x0=irq → returns result in x0
        SYS_IRQ_REGISTER => {
            let irq_num = ctx.gpr[0] as u32;
            ctx.gpr[0] = sys_irq_register(irq_num) as u64;
        }

        // SYS_IRQ_WAIT: x0=irq → returns result in x0 (may block)
        SYS_IRQ_WAIT => {
            let irq_num = ctx.gpr[0] as u32;
            let result = sys_irq_wait(ctx, irq_num);
            ctx.gpr[0] = result as u64;
        }

        // SYS_IRQ_ACK: x0=irq → returns result in x0
        SYS_IRQ_ACK => {
            let irq_num = ctx.gpr[0] as u32;
            ctx.gpr[0] = sys_irq_ack(irq_num) as u64;
        }

        // Stub syscalls - return reasonable defaults for compatibility
        SYS_FCNTL => {
            // fcntl(fd, cmd, arg) - return 0 for most commands
            ctx.gpr[0] = 0;
        }
        SYS_IOCTL => {
            // ioctl(fd, request, arg) - handle common terminal ioctls
            let fd = ctx.gpr[0] as usize;
            let request = ctx.gpr[1] as u64;
            let arg = ctx.gpr[2] as usize;
            ctx.gpr[0] = sys_ioctl(fd, request, arg) as u64;
        }
        SYS_FACCESSAT => {
            // faccessat(dirfd, pathname, mode, flags) - return 0 (file accessible)
            ctx.gpr[0] = 0;
        }
        SYS_CLOCK_GETTIME => {
            let clock_id = ctx.gpr[0] as i32;
            let tp = ctx.gpr[1] as usize;
            ctx.gpr[0] = sys_clock_gettime(clock_id, tp) as u64;
        }
        SYS_UNAME => {
            // uname(buf) - fill in basic system info
            ctx.gpr[0] = sys_uname(ctx.gpr[0] as *mut u8) as u64;
        }
        SYS_GETUID | SYS_GETEUID | SYS_GETGID | SYS_GETEGID => {
            // Return 0 (root) for all user/group IDs
            ctx.gpr[0] = 0;
        }
        SYS_MMAP => {
            // mmap(addr, len, prot, flags, fd, offset)
            let addr = ctx.gpr[0] as usize;
            let len = ctx.gpr[1] as usize;
            let prot = ctx.gpr[2] as u32;
            let flags = ctx.gpr[3] as u32;
            let fd = ctx.gpr[4] as i32;
            let offset = ctx.gpr[5] as i64;

            // Check if this is anonymous or file-backed mmap
            if (flags & mmap::MAP_ANONYMOUS) != 0 || fd == -1 {
                // Anonymous mmap - handle synchronously
                let result = mmap::sys_mmap(addr, len, prot, flags, fd, offset);
                ctx.gpr[0] = result as u64;
            } else {
                // File-backed mmap - requires IPC to VFS
                sys_mmap_file(ctx, addr, len, prot, flags, fd, offset);
            }
        }
        SYS_MUNMAP => {
            // munmap(addr, len)
            let addr = ctx.gpr[0] as usize;
            let len = ctx.gpr[1] as usize;
            ctx.gpr[0] = mmap::sys_munmap(addr, len) as u64;
        }
        SYS_MPROTECT => {
            // mprotect(addr, len, prot)
            let addr = ctx.gpr[0] as usize;
            let len = ctx.gpr[1] as usize;
            let prot = ctx.gpr[2] as u32;
            ctx.gpr[0] = mmap::sys_mprotect(addr, len, prot) as u64;
        }
        SYS_RT_SIGACTION => {
            // rt_sigaction(sig, act, oldact, sigsetsize)
            let sig = ctx.gpr[0] as i32;
            let act = ctx.gpr[1] as usize;
            let oldact = ctx.gpr[2] as usize;
            ctx.gpr[0] = sys_rt_sigaction(sig, act, oldact) as u64;
        }
        SYS_RT_SIGPROCMASK => {
            // rt_sigprocmask(how, set, oldset, sigsetsize)
            let how = ctx.gpr[0] as i32;
            let set = ctx.gpr[1] as usize;
            let oldset = ctx.gpr[2] as usize;
            ctx.gpr[0] = sys_rt_sigprocmask(how, set, oldset) as u64;
        }
        SYS_KILL => {
            // kill(pid, sig)
            let pid = ctx.gpr[0] as i32;
            let sig = ctx.gpr[1] as i32;
            ctx.gpr[0] = sys_kill(pid, sig) as u64;
        }
        SYS_RT_SIGRETURN => {
            // rt_sigreturn() - restore context from signal frame
            sys_rt_sigreturn(ctx);
            // Note: sys_rt_sigreturn modifies ctx directly, no return value needed
        }

        // musl startup syscalls
        SYS_SET_TID_ADDRESS => {
            // set_tid_address(tidptr) - store pointer and return current TID
            let _tidptr = ctx.gpr[0] as usize;
            ctx.gpr[0] = sys_set_tid_address(_tidptr) as u64;
        }
        SYS_FUTEX => {
            // futex(uaddr, op, val, ...) - fast userspace mutex
            // For single-threaded programs, we can stub this
            let _uaddr = ctx.gpr[0] as usize;
            let op = ctx.gpr[1] as i32;
            let _val = ctx.gpr[2] as u32;
            // FUTEX_WAIT = 0, FUTEX_WAKE = 1
            // For single-threaded: WAIT returns immediately, WAKE returns 0
            if op & 0x7f == 0 {
                // FUTEX_WAIT - return EAGAIN (no wait needed in single-threaded)
                ctx.gpr[0] = EAGAIN as u64;
            } else {
                // FUTEX_WAKE and others - return 0 (no threads to wake)
                ctx.gpr[0] = 0;
            }
        }
        SYS_SET_ROBUST_LIST => {
            // set_robust_list(head, len) - register robust futex list
            // For single-threaded programs, just return success
            ctx.gpr[0] = 0;
        }
        SYS_RSEQ => {
            // rseq(rseq, rseq_len, flags, sig) - restartable sequence
            // Return ENOSYS - not implemented (programs can work without it)
            ctx.gpr[0] = ENOSYS as u64;
        }
        SYS_READLINKAT => {
            // readlinkat(dirfd, pathname, buf, bufsiz) - read symbolic link
            // For now, return EINVAL (no symlink support)
            ctx.gpr[0] = EINVAL as u64;
        }
        SYS_PRCTL => {
            // prctl(option, arg2, arg3, arg4, arg5) - process control
            // Return 0 for most options (stub)
            ctx.gpr[0] = 0;
        }
        SYS_GETPPID => {
            // getppid() - get parent process ID
            // For now, return 1 (init is parent)
            ctx.gpr[0] = 1;
        }
        SYS_GETTID => {
            // gettid() - get thread ID (same as PID for single-threaded)
            let tid = sched::current().map(|t| t.0).unwrap_or(0);
            ctx.gpr[0] = tid as u64;
        }
        SYS_PRLIMIT64 => {
            // prlimit64(pid, resource, new_limit, old_limit) - get/set resource limits
            let pid = ctx.gpr[0] as i32;
            let resource = ctx.gpr[1] as i32;
            let new_limit = ctx.gpr[2] as usize;
            let old_limit = ctx.gpr[3] as usize;
            ctx.gpr[0] = sys_prlimit64(pid, resource, new_limit, old_limit) as u64;
        }
        SYS_GETRANDOM => {
            // getrandom(buf, buflen, flags) - fill buffer with random bytes
            let buf = ctx.gpr[0] as usize;
            let buflen = ctx.gpr[1] as usize;
            let flags = ctx.gpr[2] as u32;
            ctx.gpr[0] = sys_getrandom(buf, buflen, flags) as u64;
        }
        SYS_GETPGID => {
            // getpgid(pid) - get process group ID
            // pid=0 means current process
            let pid = ctx.gpr[0] as i32;
            if pid == 0 {
                // Return current task's process group (same as task ID for now)
                let tid = sched::current().map(|t| t.0).unwrap_or(1);
                ctx.gpr[0] = tid as u64;
            } else {
                // For other pids, just return the pid as its pgid (each process is its own group)
                ctx.gpr[0] = pid as u64;
            }
        }
        SYS_SETPGID => {
            // setpgid(pid, pgid) - set process group ID (stub - just return success)
            ctx.gpr[0] = 0;
        }
        SYS_SCHED_GETAFFINITY => {
            // sched_getaffinity(pid, cpusetsize, mask) - get CPU affinity mask
            // Return a mask with CPU 0 set (single-CPU system)
            let cpusetsize = ctx.gpr[1] as usize;
            let mask = ctx.gpr[2] as *mut u8;
            if cpusetsize > 0 && !mask.is_null() {
                unsafe {
                    // Set bit 0 (CPU 0) in the mask
                    core::ptr::write_volatile(mask, 0x01);
                    // Zero out the rest
                    for i in 1..cpusetsize.min(128) {
                        core::ptr::write_volatile(mask.add(i), 0);
                    }
                }
                ctx.gpr[0] = cpusetsize.min(128) as u64;
            } else {
                ctx.gpr[0] = EINVAL as u64;
            }
        }
        SYS_SCHED_SETAFFINITY => {
            // sched_setaffinity(pid, cpusetsize, mask) - set CPU affinity (stub - return success)
            ctx.gpr[0] = 0;
        }
        SYS_SENDFILE => {
            // sendfile(out_fd, in_fd, offset, count) - return ENOSYS so cat falls back to read/write
            ctx.gpr[0] = ENOSYS as u64;
        }
        SYS_FADVISE64 => {
            // fadvise64(fd, offset, len, advice) - hint about file access patterns (stub - return success)
            ctx.gpr[0] = 0;
        }

        _ => {
            // Log unknown syscall for debugging
            let task_id = sched::current().map(|t| t.0).unwrap_or(0);
            println!("[syscall] task {} unknown syscall {} (x0={:#x}, x1={:#x}, x2={:#x})",
                task_id, syscall_num, ctx.gpr[0], ctx.gpr[1], ctx.gpr[2]);
            ctx.gpr[0] = ENOSYS as u64;
        }
    }

}

/// SYS_YIELD - Voluntarily yield the CPU to another task
fn sys_yield() -> i64 {
    sched::yield_cpu();
    ESUCCESS
}

/// SYS_EXIT - Terminate the current task with proper context switch
fn sys_exit_with_switch(ctx: &mut ExceptionContext, exit_code: i32) {
    unsafe {
        sched::exit_with_switch(ctx, exit_code);
    }
    // Never returns
}

use sched::task::{TASKS, FdKind};

/// SYS_READ - Read from a file descriptor
///
/// Currently only supports stdin (fd=0) from console.
/// Returns number of bytes read, or negative error code.
fn sys_read(ctx: &mut ExceptionContext, fd: usize, buf: usize, len: usize) -> i64 {
    // Get current task's fd table
    let current_id = match sched::current() {
        Some(id) => id,
        None => return EBADF,
    };

    let fd_entry = unsafe {
        let task = &TASKS[current_id.0];
        if fd >= sched::MAX_FDS {
            return EBADF;
        }
        task.fds[fd]
    };

    // Check if fd is valid and readable
    if fd_entry.kind == FdKind::None {
        return EBADF;
    }
    if !fd_entry.flags.readable {
        return EBADF;
    }

    // Handle based on fd kind
    match fd_entry.kind {
        FdKind::Console => {
            // Read from UART - no echo here, let shell handle it
            const UART_BASE: usize = 0x0900_0000;
            const UART_DR: usize = 0x000;
            const UART_FR: usize = 0x018;
            const UART_FR_RXFE: u32 = 1 << 4; // RX FIFO empty

            if len == 0 {
                return 0;
            }

            let mut count = 0usize;

            // Read characters without echo - let shell handle echo
            unsafe {
                let fr = (UART_BASE + UART_FR) as *const u32;
                let dr = (UART_BASE + UART_DR) as *const u8;

                loop {
                    // Wait for a character
                    while (core::ptr::read_volatile(fr) & UART_FR_RXFE) != 0 {
                        // Yield to other tasks while waiting
                        sched::yield_cpu();
                    }

                    let c = core::ptr::read_volatile(dr);

                    // Convert CR to LF
                    let c = if c == b'\r' { b'\n' } else { c };

                    // Store character in buffer
                    if count < len {
                        core::ptr::write_volatile((buf + count) as *mut u8, c);
                        count += 1;
                    }

                    // Stop on newline or buffer full
                    if c == b'\n' || count >= len {
                        break;
                    }
                }
            }

            count as i64
        }
        FdKind::PipeRead => {
            let pipe_id = fd_entry.handle;
            if len == 0 {
                return 0;
            }

            // Create SHM for data transfer
            let shm_id_i64 = shm::sys_shmcreate(len);
            if shm_id_i64 < 0 {
                return ENOMEM;
            }
            let shm_id = shm_id_i64 as usize;

            // Grant pipeserv access to SHM
            shm::sys_shmgrant(shm_id, PIPESERV_TID.0);

            // Set up pending syscall - IPC reply will complete it
            unsafe {
                let task = &mut TASKS[current_id.0];
                task.pending_syscall = PendingSyscall::PipeRead {
                    user_buf: buf,
                    max_len: len,
                    shm_id,
                };
            }

            // Send PIPE_READ request to pipeserv
            // The IPC will block, and when pipeserv replies, the reply handler
            // will complete the syscall by copying data from SHM to user_buf
            let msg = Message::new(PIPE_READ, [pipe_id, shm_id as u64, len as u64, 0]);
            ipc::sys_call(ctx, PIPESERV_TID, msg);

            // Note: Code after sys_call never runs due to ERET.
            // The return value is set by complete_pending_syscall in ipc.rs
            0 // Placeholder - never actually returned
        }
        FdKind::File => {
            let vnode = fd_entry.handle;
            if len == 0 {
                return 0;
            }

            // Reuse cached SHM for file I/O to avoid per-read allocation overhead
            // We use a larger SHM (128KB) to support bulk transfers
            const IO_SHM_SIZE: usize = 131072;
            let actual_len = len.min(IO_SHM_SIZE);

            let shm_id = unsafe {
                let task = &mut TASKS[current_id.0];

                // Check if we have a cached SHM that's large enough
                if let Some(cached_id) = task.io_shm_id {
                    if task.io_shm_size >= actual_len {
                        cached_id
                    } else {
                        // Existing SHM too small, destroy and create larger one
                        shm::sys_shmdestroy(cached_id);
                        task.io_shm_id = None;
                        task.io_shm_size = 0;

                        // Create new larger SHM
                        let new_id = shm::sys_shmcreate(IO_SHM_SIZE);
                        if new_id < 0 {
                            return ENOMEM;
                        }
                        shm::sys_shmgrant(new_id as usize, VFS_TID.0);
                        task.io_shm_id = Some(new_id as usize);
                        task.io_shm_size = IO_SHM_SIZE;
                        new_id as usize
                    }
                } else {
                    // No cached SHM, create one
                    let new_id = shm::sys_shmcreate(IO_SHM_SIZE);
                    if new_id < 0 {
                        return ENOMEM;
                    }
                    shm::sys_shmgrant(new_id as usize, VFS_TID.0);
                    task.io_shm_id = Some(new_id as usize);
                    task.io_shm_size = IO_SHM_SIZE;
                    new_id as usize
                }
            };

            // Set up pending syscall (don't destroy SHM on completion - keep it cached)
            unsafe {
                let task = &mut TASKS[current_id.0];
                task.pending_syscall = PendingSyscall::VfsRead {
                    user_buf: buf,
                    max_len: actual_len,
                    shm_id,
                };
            }

            // Send VFS_READ_SHM request
            // data[0] = vnode, data[1] = shm_id, data[2] = shm_offset, data[3] = max_len
            let msg = Message::new(VFS_READ_SHM, [vnode, shm_id as u64, 0, actual_len as u64]);
            ipc::sys_call(ctx, VFS_TID, msg);

            0 // Placeholder
        }
        _ => EBADF,
    }
}

/// SYS_WRITE - Write to a file descriptor
///
/// Currently supports stdout (fd=1) and stderr (fd=2) to console.
/// Returns number of bytes written, or negative error code.
fn sys_write(ctx: &mut ExceptionContext, fd: usize, buf: usize, len: usize) -> i64 {
    // Get current task's fd table
    let current_id = match sched::current() {
        Some(id) => id,
        None => return EBADF,
    };

    let fd_entry = unsafe {
        let task = &TASKS[current_id.0];
        if fd >= sched::MAX_FDS {
            return EBADF;
        }
        task.fds[fd]
    };

    // Check if fd is valid and writable
    if fd_entry.kind == FdKind::None {
        return EBADF;
    }
    if !fd_entry.flags.writable {
        return EBADF;
    }

    // Handle based on fd kind
    match fd_entry.kind {
        FdKind::Console => {
            // Write to UART
            const UART_BASE: usize = 0x0900_0000;
            const UART_DR: usize = 0x000;
            const UART_FR: usize = 0x018;
            const UART_FR_TXFF: u32 = 1 << 5;

            // Limit write size to prevent excessive time in kernel
            let len = len.min(4096);

            for i in 0..len {
                let c = unsafe {
                    core::ptr::read_volatile((buf + i) as *const u8)
                };

                unsafe {
                    let fr = (UART_BASE + UART_FR) as *const u32;
                    while (core::ptr::read_volatile(fr) & UART_FR_TXFF) != 0 {
                        core::hint::spin_loop();
                    }
                    let dr = (UART_BASE + UART_DR) as *mut u8;
                    core::ptr::write_volatile(dr, c);
                }
            }

            len as i64
        }
        FdKind::PipeWrite => {
            let pipe_id = fd_entry.handle;
            if len == 0 {
                return 0;
            }

            // Create SHM for data transfer
            let shm_id_i64 = shm::sys_shmcreate(len);
            if shm_id_i64 < 0 {
                return ENOMEM;
            }
            let shm_id = shm_id_i64 as usize;

            // Map SHM and copy data from user buffer
            let shm_addr = shm::sys_shmmap(shm_id, 0);
            if shm_addr < 0 {
                return ENOMEM;
            }
            unsafe {
                core::ptr::copy_nonoverlapping(
                    buf as *const u8,
                    shm_addr as *mut u8,
                    len,
                );
            }

            // Grant pipeserv access to SHM
            shm::sys_shmgrant(shm_id, PIPESERV_TID.0);

            // Set up pending syscall
            unsafe {
                let task = &mut TASKS[current_id.0];
                task.pending_syscall = PendingSyscall::PipeWrite { shm_id };
            }

            // Send PIPE_WRITE request to pipeserv
            let msg = Message::new(PIPE_WRITE, [pipe_id, shm_id as u64, len as u64, 0]);
            ipc::sys_call(ctx, PIPESERV_TID, msg);

            // Return value set by complete_pending_syscall
            0 // Placeholder
        }
        FdKind::File => {
            let vnode = fd_entry.handle;
            if len == 0 {
                return 0;
            }

            // Create SHM for data transfer
            let shm_id_i64 = shm::sys_shmcreate(len);
            if shm_id_i64 < 0 {
                return ENOMEM;
            }
            let shm_id = shm_id_i64 as usize;

            // Map SHM and copy data from user buffer
            let shm_addr = shm::sys_shmmap(shm_id, 0);
            if shm_addr < 0 {
                return ENOMEM;
            }
            unsafe {
                core::ptr::copy_nonoverlapping(
                    buf as *const u8,
                    shm_addr as *mut u8,
                    len,
                );
            }

            // Grant VFS access to SHM
            shm::sys_shmgrant(shm_id, VFS_TID.0);

            // Set up pending syscall
            unsafe {
                let task = &mut TASKS[current_id.0];
                task.pending_syscall = PendingSyscall::VfsWrite { shm_id };
            }

            // Send VFS_WRITE_SHM request to VFS
            // data[0] = vnode, data[1] = shm_id, data[2] = shm_offset, data[3] = len
            let msg = Message::new(VFS_WRITE_SHM, [vnode, shm_id as u64, 0, len as u64]);
            ipc::sys_call(ctx, VFS_TID, msg);

            // Return value set by complete_pending_syscall
            0 // Placeholder
        }
        _ => EBADF,
    }
}

/// SYS_CLOSE - Close a file descriptor
fn sys_close(ctx: &mut ExceptionContext, fd: usize) -> i64 {
    let current_id = match sched::current() {
        Some(id) => id,
        None => return EBADF,
    };

    unsafe {
        let task = &mut TASKS[current_id.0];
        if fd >= sched::MAX_FDS {
            return EBADF;
        }

        let fd_entry = task.fds[fd];
        if fd_entry.kind == FdKind::None {
            return EBADF;
        }

        // Close the local fd first
        task.close_fd(fd);

        // Handle pipe cleanup via IPC to pipeserv
        match fd_entry.kind {
            FdKind::PipeRead | FdKind::PipeWrite => {
                let is_read = fd_entry.kind == FdKind::PipeRead;

                // Set up pending syscall
                task.pending_syscall = PendingSyscall::PipeClose;

                // Send PIPE_CLOSE to pipeserv
                let msg = Message::new(PIPE_CLOSE, [fd_entry.handle, is_read as u64, 0, 0]);
                ipc::sys_call(ctx, PIPESERV_TID, msg);

                // Return value set by complete_pending_syscall
                return 0;
            }
            _ => {}
        }

        ESUCCESS
    }
}

/// SYS_PIPE - Create a pipe
///
/// Creates a pipe via pipeserv and returns two file descriptors.
///
/// # Returns
/// (read_fd, write_fd) on success, or (-1, -1) on failure
fn sys_pipe(ctx: &mut ExceptionContext) -> (i64, i64) {
    let current_id = match sched::current() {
        Some(id) => id,
        None => return (EBADF, EBADF),
    };

    // Set up pending syscall - IPC reply will allocate fds and return them
    unsafe {
        let task = &mut TASKS[current_id.0];
        task.pending_syscall = PendingSyscall::PipeCreate;
    }

    // Send PIPE_CREATE request to pipeserv
    // The reply handler (complete_pending_syscall) will:
    // 1. Get pipe_id from reply
    // 2. Allocate two fds
    // 3. Set x0=read_fd, x1=write_fd
    let msg = Message::new(PIPE_CREATE, [0; 4]);
    ipc::sys_call(ctx, PIPESERV_TID, msg);

    // Return value set by complete_pending_syscall
    (0, 0) // Placeholder - never actually returned
}

/// SYS_GETPID - Get current task ID
fn sys_getpid() -> i64 {
    match sched::current() {
        Some(id) => id.0 as i64,
        None => EINVAL,
    }
}

/// SYS_FORK - Create child process (fork)
fn sys_fork(ctx: &mut ExceptionContext) -> i64 {
    // 1. Find a free task slot for the child
    let child_id = match find_free_slot() {
        Some(id) => id,
        None => return ENOMEM,
    };

    let parent_id = match sched::current() {
        Some(id) => id,
        None => return EINVAL, // Should not happen if a task is running
    };

    // Get mutable references to parent and child tasks
    // Safety: We ensure child_id and parent_id are valid and distinct.
    let (parent_task, child_task) = unsafe {
        let ptr = ptr::addr_of_mut!(sched::task::TASKS);
        let parent_ptr = ptr.cast::<sched::task::Task>().add(parent_id.0);
        let child_ptr = ptr.cast::<sched::task::Task>().add(child_id.0);

        (&mut *parent_ptr, &mut *child_ptr)
    };

    // 2. Allocate kernel stack for the child
    let child_kstack_paddr = match sched::task::alloc_kernel_stack_frames() {
        Some(paddr) => paddr,
        None => return ENOMEM,
    };
    // Kernel uses identity mapping (virtual == physical for RAM)
    let child_kstack_top_virt = child_kstack_paddr.0 + KERNEL_STACK_SIZE;

    // 3. Duplicate parent's page table
    let child_addr_space = unsafe {
        parent_task.addr_space.as_ref().and_then(|parent_as| {
            AddressSpace::clone_for_fork(parent_as)
        })
    };
    let child_addr_space = match child_addr_space {
        Some(aspace) => aspace,
        None => {
            sched::task::free_kernel_stack_frames(child_kstack_paddr);
            return ENOMEM;
        }
    };
    // 4. Initialize child task
    *child_task = sched::task::Task::empty(); // Reset to empty state
    child_task.id = child_id;
    child_task.state = TaskState::Ready;
    child_task.kernel_stack_base = child_kstack_paddr; // Store the physical address
    child_task.kernel_stack_top = child_kstack_top_virt;
    child_task.addr_space = Some(child_addr_space); // Assign the cloned address space
    child_task.set_name(parent_task.name_str()); // Copy name
    child_task.parent = Some(parent_id);
    child_task.cwd = parent_task.cwd;
    child_task.heap_brk = parent_task.heap_brk;
    child_task.time_slice = parent_task.time_slice; // Inherit time slice

    // 5. Set up child's execution context
    // Copy the parent's exception context (registers) onto the child's kernel stack
    let child_exception_ctx = (child_kstack_top_virt - core::mem::size_of::<ExceptionContext>()) as *mut ExceptionContext;

    unsafe {
        ptr::write_volatile(child_exception_ctx, *ctx);
        // Child's return value from fork is 0
        (*child_exception_ctx).gpr[0] = 0;
    }

    // Set kernel_stack_top to point to the ExceptionContext.
    // The scheduler's switch_context_and_restore() will use this to restore
    // the ExceptionContext and ERET back to user space.
    child_task.kernel_stack_top = child_exception_ctx as usize;


    // 6. Duplicate file descriptors
    for i in 0..sched::MAX_FDS {
        if parent_task.fds[i].is_valid() {
            child_task.fds[i] = parent_task.fds[i];
            // TODO: Increment reference counts for underlying file/pipe objects
            // This is crucial for proper resource management. For now, sharing implicitly.
        }
    }

    // 7. Add child to ready queue
    sched::enqueue_task(child_id);

    // 8. Parent returns child's TID
    child_id.0 as i64
}

/// Maximum ELF size we'll accept for spawn (2MB to support BusyBox)
const MAX_ELF_SIZE: usize = 2 * 1024 * 1024;

/// SYS_SPAWN - Create a new task from an ELF image
///
/// # Arguments
/// * `elf_ptr` - Pointer to ELF data in user space
/// * `elf_len` - Length of ELF data in bytes
///
/// # Returns
/// * On success: task ID of the new task (>= 0)
/// * On failure: negative error code
fn sys_spawn(elf_ptr: usize, elf_len: usize) -> i64 {
    // Validate arguments
    if elf_len == 0 || elf_len > MAX_ELF_SIZE {
        return EINVAL;
    }

    // Basic validation that pointer looks like user space (not kernel)
    // User space is mapped at low addresses (< 0x8000_0000 in our setup)
    if elf_ptr >= 0x8000_0000 {
        return EFAULT;
    }

    // Check for overflow
    if elf_ptr.checked_add(elf_len).is_none() {
        return EFAULT;
    }

    // Create a slice from user memory
    // Safety: We've validated the pointer is in user space range.
    // The actual memory access safety depends on the user having this mapped.
    // If it's not mapped, we'll get a page fault (which is handled).
    let elf_data = unsafe {
        core::slice::from_raw_parts(elf_ptr as *const u8, elf_len)
    };

    // Get current task (will be parent)
    let parent_id = sched::current();

    // Create the task using the existing ELF loader
    match sched::create_user_task_from_elf("spawned", elf_data) {
        Some(task_id) => {
            // Set parent for waitpid support
            if let Some(pid) = parent_id {
                unsafe {
                    TASKS[task_id.0].parent = Some(pid);
                }
            }
            task_id.0 as i64
        }
        None => ENOMEM,
    }
}

/// SYS_IRQ_REGISTER - Register the current task as handler for an IRQ
///
/// # Arguments
/// * `irq` - IRQ number (GIC interrupt ID)
///
/// # Returns
/// * 0 on success
/// * Negative error code on failure
fn sys_irq_register(irq: u32) -> i64 {
    let current_id = match sched::current() {
        Some(id) => id,
        None => return EINVAL,
    };

    irq::register_irq_handler(irq, current_id)
}

/// SYS_IRQ_WAIT - Wait for an IRQ to fire
///
/// If the IRQ is already pending, returns immediately.
/// Otherwise, blocks the task until the IRQ fires.
///
/// # Arguments
/// * `ctx` - Exception context (for potential blocking)
/// * `irq` - IRQ number
///
/// # Returns
/// * 0 when IRQ fires
/// * Negative error code on failure
fn sys_irq_wait(ctx: &mut ExceptionContext, irq: u32) -> i64 {
    let current_id = match sched::current() {
        Some(id) => id,
        None => return EINVAL,
    };

    let result = irq::wait_for_irq(irq, current_id);

    if result == 1 {
        // Need to block - set task state and context switch
        unsafe {
            use sched::task::TASKS;
            TASKS[current_id.0].state = TaskState::IrqBlocked;
            sched::context_switch_blocking(ctx);
        }
        // When we wake up, the IRQ has fired
        0
    } else {
        result
    }
}

/// SYS_IRQ_ACK - Acknowledge an IRQ (clear pending flag and send EOI)
///
/// # Arguments
/// * `irq` - IRQ number
///
/// # Returns
/// * 0 on success
/// * Negative error code on failure
fn sys_irq_ack(irq: u32) -> i64 {
    irq::acknowledge_irq(irq)
}

/// SYS_NOTIFY - Send asynchronous notification to a task
///
/// Sets notification bits on the target task. If the target is blocked
/// waiting for any of these bits, it will be woken up.
///
/// # Arguments
/// * `dest` - Target task ID
/// * `bits` - Notification bits to set (OR'd with existing pending bits)
///
/// # Returns
/// * 0 on success
/// * Negative error code on failure
fn sys_notify(dest: TaskId, bits: u64) -> i64 {
    use sched::task::MAX_TASKS;

    // Validate target
    if dest.0 >= MAX_TASKS {
        return EINVAL;
    }

    unsafe {
        let target = &mut TASKS[dest.0];

        // Check target is valid
        if target.state == TaskState::Free || target.state == TaskState::Terminated {
            return EINVAL;
        }

        // Set notification bits
        target.notify_pending |= bits;

        // If target is waiting for notifications and any expected bits are now set, wake it
        if target.state == TaskState::NotifyBlocked {
            let matched = target.notify_pending & target.notify_waiting;
            if matched != 0 {
                target.state = TaskState::Ready;
                sched::enqueue_task(dest);
            }
        }
    }

    ESUCCESS
}

/// SYS_WAIT_NOTIFY - Wait for notification bits
///
/// Blocks until any of the expected notification bits are set.
/// Returns immediately if any expected bits are already pending.
///
/// # Arguments
/// * `ctx` - Exception context (for potential blocking)
/// * `expected_bits` - Bits to wait for (0 = any bit)
///
/// # Returns
/// * Matched notification bits (which are then cleared)
fn sys_wait_notify(ctx: &mut ExceptionContext, expected_bits: u64) -> i64 {
    let current_id = match sched::current() {
        Some(id) => id,
        None => return EINVAL,
    };

    // If expected_bits is 0, wait for any notification
    let mask = if expected_bits == 0 { !0u64 } else { expected_bits };

    unsafe {
        let task = &mut TASKS[current_id.0];

        // Check if any expected bits are already pending
        let matched = task.notify_pending & mask;
        if matched != 0 {
            // Clear matched bits and return them
            task.notify_pending &= !matched;
            return matched as i64;
        }

        // No bits pending - need to block
        task.notify_waiting = mask;
        task.state = TaskState::NotifyBlocked;
        sched::context_switch_blocking(ctx);

        // When we wake up, check which bits matched
        let matched = task.notify_pending & mask;
        task.notify_pending &= !matched;
        task.notify_waiting = 0;
        matched as i64
    }
}

// ============================================================================
// New POSIX-compatible syscalls
// ============================================================================

/// SYS_DUP - Duplicate a file descriptor
///
/// Returns the lowest available fd number that is a copy of oldfd.
fn sys_dup(oldfd: usize) -> i64 {
    let current_id = match sched::current() {
        Some(id) => id,
        None => return EBADF,
    };

    unsafe {
        let task = &mut TASKS[current_id.0];

        // Validate oldfd
        if oldfd >= sched::MAX_FDS || task.fds[oldfd].kind == FdKind::None {
            return EBADF;
        }

        // Find lowest available fd
        let newfd = match task.alloc_fd() {
            Some(fd) => fd,
            None => return EMFILE,
        };

        // Copy the fd entry
        task.fds[newfd] = task.fds[oldfd];

        newfd as i64
    }
}

/// SYS_DUP2/DUP3 - Duplicate a file descriptor to a specific number
///
/// If newfd is already open, it is closed first.
fn sys_dup2(oldfd: usize, newfd: usize) -> i64 {
    let current_id = match sched::current() {
        Some(id) => id,
        None => return EBADF,
    };

    unsafe {
        let task = &mut TASKS[current_id.0];

        // Validate oldfd
        if oldfd >= sched::MAX_FDS || task.fds[oldfd].kind == FdKind::None {
            return EBADF;
        }

        // Validate newfd range
        if newfd >= sched::MAX_FDS {
            return EBADF;
        }

        // If oldfd == newfd, just return newfd
        if oldfd == newfd {
            return newfd as i64;
        }

        // Close newfd if it's open (silently ignore errors)
        if task.fds[newfd].kind != FdKind::None {
            task.fds[newfd] = FileDescriptor::empty();
        }

        // Copy the fd entry
        task.fds[newfd] = task.fds[oldfd];

        newfd as i64
    }
}

/// VFS server task ID
const VFS_TID: TaskId = TaskId(3);

/// VFS IPC message tags
const VFS_OPEN: u64 = 100;
const VFS_CLOSE: u64 = 101;
const VFS_READ_SHM: u64 = 110;
const VFS_WRITE_SHM: u64 = 111;
const VFS_STAT: u64 = 104;
const VFS_READDIR: u64 = 105;

/// Open flags (Linux-compatible)
pub const O_RDONLY: u32 = 0;
pub const O_WRONLY: u32 = 1;
pub const O_RDWR: u32 = 2;
pub const O_CREAT: u32 = 0o100;
pub const O_TRUNC: u32 = 0o1000;
pub const O_APPEND: u32 = 0o2000;
pub const O_DIRECTORY: u32 = 0o200000;

/// Pending syscall variants for VFS operations
#[derive(Debug, Clone, Copy)]
pub enum PendingVfsSyscall {
    None,
    Open { flags: u32 },
    Stat { statbuf: usize },
    Getdents { buf: usize, count: usize },
}

/// SYS_MMAP for file-backed mappings
///
/// Maps a file into memory. Pre-faults all pages and reads file content via VFS IPC.
fn sys_mmap_file(ctx: &mut ExceptionContext, addr: usize, len: usize, prot: u32, flags: u32, fd: i32, offset: i64) {
    use sched::task::FdKind;

    let current_id = match sched::current() {
        Some(id) => id,
        None => {
            ctx.gpr[0] = EINVAL as u64;
            return;
        }
    };

    // Validate length
    if len == 0 {
        ctx.gpr[0] = EINVAL as u64;
        return;
    }

    // Must have either MAP_PRIVATE or MAP_SHARED
    if (flags & (mmap::MAP_PRIVATE | mmap::MAP_SHARED)) == 0 {
        ctx.gpr[0] = EINVAL as u64;
        return;
    }

    // Validate fd and get vnode
    let (vnode, fd_readable) = unsafe {
        let task = &TASKS[current_id.0];
        if fd < 0 || fd as usize >= sched::MAX_FDS {
            ctx.gpr[0] = EBADF as u64;
            return;
        }
        let fd_entry = task.fds[fd as usize];
        if fd_entry.kind != FdKind::File {
            ctx.gpr[0] = EBADF as u64;
            return;
        }
        (fd_entry.handle, fd_entry.flags.readable)
    };

    // Must be readable for mmap
    if !fd_readable {
        ctx.gpr[0] = EBADF as u64;
        return;
    }

    let aligned_len = (len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    // These will be set in the unsafe block and used for IPC
    let final_vaddr: usize;
    let final_shm_id: usize;

    unsafe {
        let task = &mut TASKS[current_id.0];

        // Determine the virtual address
        let vaddr = if (flags & mmap::MAP_FIXED) != 0 {
            let aligned_addr = addr & !(PAGE_SIZE - 1);
            if aligned_addr < mmap::MMAP_BASE || aligned_addr + aligned_len > mmap::MMAP_END {
                ctx.gpr[0] = EINVAL as u64;
                return;
            }
            // Remove any existing mappings in this range
            task.mmap_state.remove_region(aligned_addr, aligned_len);
            aligned_addr
        } else {
            match task.mmap_state.find_free_region(aligned_len) {
                Some(a) => a,
                None => {
                    ctx.gpr[0] = ENOMEM as u64;
                    return;
                }
            }
        };

        // Check for maximum regions
        if task.mmap_state.regions.len() >= mmap::MAX_MMAP_REGIONS {
            ctx.gpr[0] = ENOMEM as u64;
            return;
        }

        // Pre-allocate all physical pages and map them
        let num_pages = aligned_len / PAGE_SIZE;
        let addr_space = match &mut task.addr_space {
            Some(aspace) => aspace,
            None => {
                ctx.gpr[0] = ENOMEM as u64;
                return;
            }
        };

        let page_flags = crate::mm::address_space::PageFlags {
            mattr: 0, // Normal memory
            writable: (prot & mmap::PROT_WRITE) != 0,
            executable: (prot & mmap::PROT_EXEC) != 0,
            user: true,
        };

        // Allocate and map all pages
        for i in 0..num_pages {
            let page_vaddr = vaddr + i * PAGE_SIZE;
            let phys_frame = match alloc_frame() {
                Some(f) => f,
                None => {
                    // Cleanup: unmap already allocated pages
                    for j in 0..i {
                        let prev_vaddr = vaddr + j * PAGE_SIZE;
                        addr_space.unmap_4kb(prev_vaddr);
                        // TODO: free the physical frame
                    }
                    ctx.gpr[0] = ENOMEM as u64;
                    return;
                }
            };

            // Zero the page
            core::ptr::write_bytes(phys_frame.0 as *mut u8, 0, PAGE_SIZE);

            // Map the page
            if !addr_space.map_4kb(page_vaddr, phys_frame, page_flags) {
                free_frame(phys_frame);
                // Cleanup previous pages
                for j in 0..i {
                    let prev_vaddr = vaddr + j * PAGE_SIZE;
                    addr_space.unmap_4kb(prev_vaddr);
                }
                ctx.gpr[0] = ENOMEM as u64;
                return;
            }
        }

        // TLB invalidate
        core::arch::asm!(
            "dsb ishst",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            options(nostack)
        );

        // Create mmap region with file info (all pages marked as allocated)
        let mut region = mmap::MmapRegion::new_with_file(vaddr, aligned_len, prot, flags, vnode, offset);
        for i in 0..num_pages {
            region.mark_allocated(i);
        }
        task.mmap_state.add_region(region);

        // Create SHM for reading file content
        let shm_id = shm::sys_shmcreate(aligned_len);
        if shm_id < 0 {
            // Cleanup: unmap all pages
            for i in 0..num_pages {
                let page_vaddr = vaddr + i * PAGE_SIZE;
                addr_space.unmap_4kb(page_vaddr);
            }
            task.mmap_state.remove_region(vaddr, aligned_len);
            ctx.gpr[0] = ENOMEM as u64;
            return;
        }
        let shm_id = shm_id as usize;

        // Grant VFS access to the SHM
        shm::sys_shmgrant(shm_id, VFS_TID.0);

        // Set up pending syscall
        task.pending_syscall = PendingSyscall::MmapFile {
            vaddr,
            len: aligned_len,
            vnode,
            shm_id,
        };

        // Save for use after unsafe block
        final_vaddr = vaddr;
        final_shm_id = shm_id;
    }

    // Send VFS_READ_SHM request
    // data[0] = vnode, data[1] = shm_id, data[2] = file_offset, data[3] = max_len
    let msg = Message::new(VFS_READ_SHM, [vnode, final_shm_id as u64, offset as u64, aligned_len as u64]);
    ipc::sys_call(ctx, VFS_TID, msg);

    // Note: The actual return value (vaddr) is set by complete_pending_syscall
    let _ = final_vaddr; // Used to suppress unused warning - actual value set by IPC completion
}

/// SYS_OPENAT - Open a file
///
/// Opens a file and returns a file descriptor.
fn sys_open(ctx: &mut ExceptionContext, pathname: usize, flags: u32) -> i64 {
    use sched::task::TASKS;

    let current_id = match sched::current() {
        Some(id) => id,
        None => return EBADF,
    };

    // Read pathname from user memory (max 255 chars)
    let mut user_path = [0u8; 256];
    let mut user_path_len = 0usize;
    unsafe {
        while user_path_len < 255 {
            let c = core::ptr::read_volatile((pathname + user_path_len) as *const u8);
            if c == 0 {
                break;
            }
            user_path[user_path_len] = c;
            user_path_len += 1;
        }
    }

    if user_path_len == 0 {
        return ENOENT;
    }

    // Resolve path: handle ".", "./" prefix, and relative paths
    let mut resolved_path = [0u8; 256];
    let resolved_len: usize;

    // Strip "./" prefix from user path if present
    let (effective_path, effective_len) = if user_path_len >= 2 && user_path[0] == b'.' && user_path[1] == b'/' {
        // Skip "./" prefix
        (&user_path[2..], user_path_len - 2)
    } else {
        (&user_path[..], user_path_len)
    };

    if effective_len > 0 && effective_path[0] == b'/' {
        // Absolute path - use as-is
        resolved_path[..effective_len].copy_from_slice(&effective_path[..effective_len]);
        resolved_len = effective_len;
    } else if effective_len == 0 || (effective_len == 1 && effective_path[0] == b'.') {
        // "." or empty (from "./") means current directory
        let cwd_len = unsafe {
            let task = &TASKS[current_id.0];
            let mut len = 0;
            while len < sched::MAX_PATH_LEN && len < 255 && task.cwd[len] != 0 {
                resolved_path[len] = task.cwd[len];
                len += 1;
            }
            len
        };
        resolved_len = if cwd_len == 0 {
            // Default to root
            resolved_path[0] = b'/';
            1
        } else {
            cwd_len
        };
    } else {
        // Relative path - prepend cwd
        let cwd_len = unsafe {
            let task = &TASKS[current_id.0];
            let mut len = 0;
            while len < sched::MAX_PATH_LEN && len < 200 && task.cwd[len] != 0 {
                resolved_path[len] = task.cwd[len];
                len += 1;
            }
            len
        };

        if cwd_len == 0 || resolved_path[0] != b'/' {
            // No cwd set, use root
            resolved_path[0] = b'/';
            let copy_len = effective_len.min(254);
            resolved_path[1..1 + copy_len].copy_from_slice(&effective_path[..copy_len]);
            resolved_len = 1 + copy_len;
        } else {
            // Append "/" if needed, then path
            let mut pos = cwd_len;
            if pos > 0 && resolved_path[pos - 1] != b'/' && pos < 255 {
                resolved_path[pos] = b'/';
                pos += 1;
            }
            let copy_len = effective_len.min(255 - pos);
            resolved_path[pos..pos + copy_len].copy_from_slice(&effective_path[..copy_len]);
            resolved_len = pos + copy_len;
        }
    }

    // Allocate fd first (before IPC)
    let fd = unsafe {
        let task = &mut TASKS[current_id.0];
        match task.alloc_fd() {
            Some(fd) => fd,
            None => return EMFILE,
        }
    };

    // Create SHM for path transfer
    let shm_id_i64 = shm::sys_shmcreate(256);
    if shm_id_i64 < 0 {
        return ENOMEM;
    }
    let shm_id = shm_id_i64 as usize;

    // Map SHM and copy resolved path
    let shm_addr = shm::sys_shmmap(shm_id, 0);
    if shm_addr < 0 {
        return ENOMEM;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(
            resolved_path.as_ptr(),
            shm_addr as *mut u8,
            resolved_len,
        );
        // Null-terminate
        core::ptr::write_volatile((shm_addr as usize + resolved_len) as *mut u8, 0);
    }

    // Grant VFS access
    shm::sys_shmgrant(shm_id, VFS_TID.0);

    // Set up pending syscall
    unsafe {
        let task = &mut TASKS[current_id.0];
        task.pending_syscall = PendingSyscall::VfsOpen {
            fd,
            flags,
            shm_id,
        };
    }

    // Send VFS_OPEN request
    // data[0] = shm_id, data[1] = path_len, data[2] = flags
    let msg = Message::new(VFS_OPEN, [shm_id as u64, resolved_len as u64, flags as u64, 0]);
    ipc::sys_call(ctx, VFS_TID, msg);

    0 // Placeholder - actual return set by complete_pending_syscall
}

/// SYS_GETCWD - Get current working directory
fn sys_getcwd(buf: usize, size: usize) -> i64 {
    let current_id = match sched::current() {
        Some(id) => id,
        None => return EFAULT,
    };

    if size == 0 {
        return EINVAL;
    }

    unsafe {
        let task = &TASKS[current_id.0];

        // Find cwd length
        let mut cwd_len = 0;
        while cwd_len < sched::MAX_PATH_LEN && task.cwd[cwd_len] != 0 {
            cwd_len += 1;
        }

        // Check buffer size (need space for null terminator)
        if size <= cwd_len {
            return ENAMETOOLONG;
        }

        // Copy to user buffer
        core::ptr::copy_nonoverlapping(
            task.cwd.as_ptr(),
            buf as *mut u8,
            cwd_len + 1, // Include null terminator
        );

        buf as i64
    }
}

/// SYS_CHDIR - Change current working directory
fn sys_chdir(path: usize) -> i64 {
    let current_id = match sched::current() {
        Some(id) => id,
        None => return EFAULT,
    };

    // Read path from user memory
    let mut user_path = [0u8; 256];
    let mut path_len = 0;
    unsafe {
        while path_len < 255 {
            let c = core::ptr::read_volatile((path + path_len) as *const u8);
            if c == 0 {
                break;
            }
            user_path[path_len] = c;
            path_len += 1;
        }
    }

    if path_len == 0 {
        return ENOENT;
    }

    // Build absolute path
    let mut new_cwd = [0u8; 256];
    let new_cwd_len: usize;

    if user_path[0] == b'/' {
        // Absolute path - use as-is
        new_cwd[..path_len].copy_from_slice(&user_path[..path_len]);
        new_cwd_len = path_len;
    } else {
        // Relative path - prepend current cwd
        let cwd_len = unsafe {
            let task = &TASKS[current_id.0];
            let mut len = 0;
            while len < sched::MAX_PATH_LEN && len < 200 && task.cwd[len] != 0 {
                new_cwd[len] = task.cwd[len];
                len += 1;
            }
            len
        };

        if cwd_len == 0 || new_cwd[0] != b'/' {
            // No cwd set, use root
            new_cwd[0] = b'/';
            let copy_len = path_len.min(254);
            new_cwd[1..1 + copy_len].copy_from_slice(&user_path[..copy_len]);
            new_cwd_len = 1 + copy_len;
        } else {
            // Append "/" if needed, then path
            let mut pos = cwd_len;
            if pos > 0 && new_cwd[pos - 1] != b'/' && pos < 255 {
                new_cwd[pos] = b'/';
                pos += 1;
            }
            let copy_len = path_len.min(255 - pos);
            new_cwd[pos..pos + copy_len].copy_from_slice(&user_path[..copy_len]);
            new_cwd_len = pos + copy_len;
        }
    }

    // Store the absolute path as the new cwd
    unsafe {
        let task = &mut TASKS[current_id.0];
        task.cwd[..new_cwd_len].copy_from_slice(&new_cwd[..new_cwd_len]);
        task.cwd[new_cwd_len] = 0; // Null-terminate
    }

    ESUCCESS
}

/// Timespec structure for clock_gettime
#[repr(C)]
pub struct Timespec {
    pub tv_sec: i64,   // Seconds
    pub tv_nsec: i64,  // Nanoseconds
}

/// Clock IDs
pub const CLOCK_REALTIME: i32 = 0;
pub const CLOCK_MONOTONIC: i32 = 1;
pub const CLOCK_BOOTTIME: i32 = 7;

/// SYS_CLOCK_GETTIME - Get clock time
fn sys_clock_gettime(clock_id: i32, tp: usize) -> i64 {
    // We support CLOCK_MONOTONIC and CLOCK_REALTIME (both return time since boot)
    // In a real implementation, CLOCK_REALTIME would need RTC support
    match clock_id {
        CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_BOOTTIME => {
            let ns = timer::get_time_ns();
            unsafe {
                let timespec = tp as *mut Timespec;
                (*timespec).tv_sec = (ns / 1_000_000_000) as i64;
                (*timespec).tv_nsec = (ns % 1_000_000_000) as i64;
            }
            ESUCCESS
        }
        _ => EINVAL,
    }
}

/// Linux stat structure (simplified for AArch64)
#[repr(C)]
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

/// File type bits for st_mode
pub const S_IFMT: u32 = 0o170000;   // File type mask
pub const S_IFDIR: u32 = 0o040000;  // Directory
pub const S_IFREG: u32 = 0o100000;  // Regular file

/// SYS_FSTAT - Get file status
fn sys_fstat(ctx: &mut ExceptionContext, fd: usize, statbuf: usize) -> i64 {
    let current_id = match sched::current() {
        Some(id) => id,
        None => return EBADF,
    };

    // Validate fd
    let fd_entry = unsafe {
        let task = &TASKS[current_id.0];
        if fd >= sched::MAX_FDS || task.fds[fd].kind == FdKind::None {
            return EBADF;
        }
        task.fds[fd]
    };

    // Get boot time for timestamps
    let time_ns = timer::get_time_ns();
    let time_sec = (time_ns / 1_000_000_000) as i64;
    let time_nsec = (time_ns % 1_000_000_000) as i64;

    // For console fds, return a complete stat for character device
    if fd_entry.kind == FdKind::Console {
        unsafe {
            let stat = statbuf as *mut Stat;
            (*stat) = core::mem::zeroed();
            (*stat).st_dev = 0; // Device 0 for special files
            (*stat).st_ino = 1; // Console inode
            (*stat).st_mode = 0o020666; // Character device (S_IFCHR | rw-rw-rw-)
            (*stat).st_nlink = 1;
            (*stat).st_blksize = 4096;
            (*stat).st_atime = time_sec;
            (*stat).st_atime_nsec = time_nsec;
            (*stat).st_mtime = time_sec;
            (*stat).st_mtime_nsec = time_nsec;
            (*stat).st_ctime = time_sec;
            (*stat).st_ctime_nsec = time_nsec;
        }
        return ESUCCESS;
    }

    // For pipes
    if fd_entry.kind == FdKind::PipeRead || fd_entry.kind == FdKind::PipeWrite {
        unsafe {
            let stat = statbuf as *mut Stat;
            (*stat) = core::mem::zeroed();
            (*stat).st_dev = 0; // Device 0 for special files
            (*stat).st_ino = fd_entry.handle; // Pipe ID as inode
            (*stat).st_mode = 0o010666; // FIFO/pipe (S_IFIFO | rw-rw-rw-)
            (*stat).st_nlink = 1;
            (*stat).st_blksize = 4096;
            (*stat).st_atime = time_sec;
            (*stat).st_atime_nsec = time_nsec;
            (*stat).st_mtime = time_sec;
            (*stat).st_mtime_nsec = time_nsec;
            (*stat).st_ctime = time_sec;
            (*stat).st_ctime_nsec = time_nsec;
        }
        return ESUCCESS;
    }

    // For VFS files, send IPC to VFS
    // Set up pending syscall
    unsafe {
        let task = &mut TASKS[current_id.0];
        task.pending_syscall = PendingSyscall::VfsStat { statbuf };
    }

    // Send VFS_STAT request with vnode handle
    let msg = Message::new(VFS_STAT, [fd_entry.handle, 0, 0, 0]);
    ipc::sys_call(ctx, VFS_TID, msg);

    0 // Placeholder
}

/// SYS_FSTATAT - Get file status at directory
///
/// Forwards the request to VFS via IPC.
fn sys_fstatat(ctx: &mut ExceptionContext, dirfd: i32, pathname: usize, statbuf: usize) -> i64 {
    use sched::task::TASKS;

    let current_id = match sched::current() {
        Some(id) => id,
        None => return EINVAL,
    };

    // Read the pathname from user space (up to 31 chars for inline VFS message)
    let mut user_path = [0u8; 32];
    let mut user_path_len = 0usize;
    unsafe {
        for i in 0..31 {
            let c = core::ptr::read_volatile((pathname + i) as *const u8);
            if c == 0 {
                break;
            }
            user_path[i] = c;
            user_path_len += 1;
        }
    }

    // Handle empty path with AT_EMPTY_PATH flag (common for fstat-like usage)
    if user_path_len == 0 {
        return ENOENT;
    }

    // Resolve path: handle ".", "./" prefix, and relative paths
    let mut resolved_path = [0u8; 32];
    let resolved_len: usize;

    // AT_FDCWD = -100, meaning use current working directory
    let _ = dirfd;

    // Strip "./" prefix from user path if present
    let (effective_path, effective_len) = if user_path_len >= 2 && user_path[0] == b'.' && user_path[1] == b'/' {
        // Skip "./" prefix
        let start = 2;
        let len = user_path_len - 2;
        let mut tmp = [0u8; 32];
        tmp[..len].copy_from_slice(&user_path[start..start + len]);
        (tmp, len)
    } else {
        (user_path, user_path_len)
    };

    if effective_len > 0 && effective_path[0] == b'/' {
        // Absolute path - use as-is
        resolved_path[..effective_len].copy_from_slice(&effective_path[..effective_len]);
        resolved_len = effective_len;
    } else if effective_len == 0 || (effective_len == 1 && effective_path[0] == b'.') {
        // "." or empty (from "./") means current directory
        let cwd_len = unsafe {
            let task = &TASKS[current_id.0];
            let mut len = 0;
            while len < sched::MAX_PATH_LEN && len < 31 && task.cwd[len] != 0 {
                resolved_path[len] = task.cwd[len];
                len += 1;
            }
            len
        };
        resolved_len = if cwd_len == 0 {
            // Default to root
            resolved_path[0] = b'/';
            1
        } else {
            cwd_len
        };
    } else {
        // Relative path - prepend cwd
        let cwd_len = unsafe {
            let task = &TASKS[current_id.0];
            let mut len = 0;
            while len < sched::MAX_PATH_LEN && len < 20 && task.cwd[len] != 0 {
                resolved_path[len] = task.cwd[len];
                len += 1;
            }
            len
        };

        if cwd_len == 0 || resolved_path[0] != b'/' {
            // No cwd set, use root
            resolved_path[0] = b'/';
            let copy_len = effective_len.min(30);
            resolved_path[1..1 + copy_len].copy_from_slice(&effective_path[..copy_len]);
            resolved_len = 1 + copy_len;
        } else {
            // Append "/" if needed, then path
            let mut pos = cwd_len;
            if pos > 0 && resolved_path[pos - 1] != b'/' && pos < 31 {
                resolved_path[pos] = b'/';
                pos += 1;
            }
            let copy_len = effective_len.min(31 - pos);
            resolved_path[pos..pos + copy_len].copy_from_slice(&effective_path[..copy_len]);
            resolved_len = pos + copy_len;
        }
    }

    // Pack resolved path into message data for VFS_STAT
    // Format: byte 0 = length, bytes 1-31 = path characters
    let mut msg_data = [0u64; 4];
    unsafe {
        let msg_bytes = core::slice::from_raw_parts_mut(
            msg_data.as_mut_ptr() as *mut u8,
            32
        );
        msg_bytes[0] = resolved_len as u8;
        msg_bytes[1..1 + resolved_len].copy_from_slice(&resolved_path[..resolved_len]);
    }

    // Set up pending syscall to handle the reply
    unsafe {
        let task = &mut TASKS[current_id.0];
        task.pending_syscall = PendingSyscall::VfsStat { statbuf };
    }

    // Send VFS_STAT request
    let msg = Message::new(VFS_STAT, msg_data);
    ipc::sys_call(ctx, VFS_TID, msg);

    0 // Result will be set by IPC reply handler
}

/// Poll event flags
const POLLIN: u16 = 0x0001;   // Data ready to read
const POLLOUT: u16 = 0x0004;  // Writing won't block
const POLLERR: u16 = 0x0008;  // Error condition
const POLLHUP: u16 = 0x0010;  // Hang up

/// struct pollfd layout:
/// fd: i32 (offset 0)
/// events: i16 (offset 4)
/// revents: i16 (offset 6)
const POLLFD_SIZE: usize = 8;

/// SYS_PPOLL - Poll file descriptors with timeout
///
/// Waits for events on file descriptors. For console (stdin), blocks until
/// UART has data available.
fn sys_ppoll(fds: usize, nfds: usize) -> i64 {
    use sched::task::{TASKS, FdKind};

    const UART_BASE: usize = 0x0900_0000;
    const UART_FR: usize = 0x018;
    const UART_FR_RXFE: u32 = 1 << 4; // RX FIFO empty

    let current_id = match sched::current() {
        Some(id) => id,
        None => return EINVAL,
    };

    let mut ready_count = 0i64;
    let mut polling_stdin = false;

    // First pass: check which fds are ready and if we're polling stdin
    for i in 0..nfds {
        let pollfd_addr = fds + i * POLLFD_SIZE;
        let fd = unsafe { core::ptr::read_volatile(pollfd_addr as *const i32) };
        let events = unsafe { core::ptr::read_volatile((pollfd_addr + 4) as *const i16) } as u16;
        let revents_ptr = (pollfd_addr + 6) as *mut u16;

        if fd < 0 {
            unsafe { core::ptr::write_volatile(revents_ptr, 0); }
            continue;
        }

        // Check fd type
        let fd_kind = unsafe {
            let task = &TASKS[current_id.0];
            if (fd as usize) < sched::MAX_FDS {
                task.fds[fd as usize].kind
            } else {
                FdKind::None
            }
        };

        let mut revents: u16 = 0;

        match fd_kind {
            FdKind::Console => {
                // Check if UART has data
                let has_data = unsafe {
                    let fr = (UART_BASE + UART_FR) as *const u32;
                    (core::ptr::read_volatile(fr) & UART_FR_RXFE) == 0
                };

                if has_data && (events & POLLIN) != 0 {
                    revents |= POLLIN;
                    ready_count += 1;
                } else if (events & POLLIN) != 0 {
                    polling_stdin = true;
                }

                // Console is always writable
                if (events & POLLOUT) != 0 {
                    revents |= POLLOUT;
                    if revents == POLLOUT {
                        ready_count += 1;
                    }
                }
            }
            FdKind::PipeRead => {
                // Pipes: check if data available (simplified - just report ready)
                if (events & POLLIN) != 0 {
                    // For now, don't report ready to avoid busy-loop
                    // A real implementation would check pipe buffer
                }
            }
            FdKind::PipeWrite => {
                if (events & POLLOUT) != 0 {
                    revents |= POLLOUT;
                    ready_count += 1;
                }
            }
            FdKind::File => {
                // Regular files are always ready
                if (events & POLLIN) != 0 {
                    revents |= POLLIN;
                    ready_count += 1;
                }
                if (events & POLLOUT) != 0 {
                    revents |= POLLOUT;
                    if (revents & POLLIN) == 0 {
                        ready_count += 1;
                    }
                }
            }
            FdKind::None => {
                revents |= POLLERR;
            }
        }

        unsafe { core::ptr::write_volatile(revents_ptr, revents); }
    }

    // If something is ready, return immediately
    if ready_count > 0 {
        return ready_count;
    }

    // If polling stdin and nothing ready, block waiting for UART input
    if polling_stdin {
        // Busy-wait for UART data (simple blocking)
        // A real implementation would put the task to sleep
        loop {
            let has_data = unsafe {
                let fr = (UART_BASE + UART_FR) as *const u32;
                (core::ptr::read_volatile(fr) & UART_FR_RXFE) == 0
            };

            if has_data {
                // Update revents for stdin
                for i in 0..nfds {
                    let pollfd_addr = fds + i * POLLFD_SIZE;
                    let fd = unsafe { core::ptr::read_volatile(pollfd_addr as *const i32) };
                    let events = unsafe { core::ptr::read_volatile((pollfd_addr + 4) as *const i16) } as u16;

                    if fd == 0 && (events & POLLIN) != 0 {
                        let revents_ptr = (pollfd_addr + 6) as *mut u16;
                        unsafe { core::ptr::write_volatile(revents_ptr, POLLIN); }
                        return 1;
                    }
                }
                return 1;
            }

            // Yield to other tasks while waiting
            core::hint::spin_loop();
        }
    }

    // Nothing to poll, return 0
    0
}

/// Linux dirent64 structure
#[repr(C)]
pub struct Dirent64 {
    pub d_ino: u64,
    pub d_off: i64,
    pub d_reclen: u16,
    pub d_type: u8,
    pub d_name: [u8; 256], // Variable length, but we reserve space
}

/// Directory entry types
pub const DT_UNKNOWN: u8 = 0;
pub const DT_REG: u8 = 8;
pub const DT_DIR: u8 = 4;

/// SYS_GETDENTS64 - Get directory entries
fn sys_getdents64(ctx: &mut ExceptionContext, fd: usize, buf: usize, count: usize) -> i64 {
    let current_id = match sched::current() {
        Some(id) => id,
        None => return EBADF,
    };

    // Validate fd
    let fd_entry = unsafe {
        let task = &TASKS[current_id.0];
        if fd >= sched::MAX_FDS || task.fds[fd].kind == FdKind::None {
            return EBADF;
        }
        task.fds[fd]
    };

    // Only works for directories (File kind with directory flag)
    if fd_entry.kind != FdKind::File {
        return ENOTDIR;
    }

    // Create SHM for data transfer
    let shm_id_i64 = shm::sys_shmcreate(count);
    if shm_id_i64 < 0 {
        return ENOMEM;
    }
    let shm_id = shm_id_i64 as usize;

    // Grant VFS access
    shm::sys_shmgrant(shm_id, VFS_TID.0);

    // Set up pending syscall
    unsafe {
        let task = &mut TASKS[current_id.0];
        task.pending_syscall = PendingSyscall::VfsGetdents {
            buf,
            count,
            shm_id,
        };
    }

    // Send VFS_READDIR request
    // data[0] = vnode handle, data[1] = shm_id, data[2] = count
    let msg = Message::new(VFS_READDIR, [fd_entry.handle, shm_id as u64, count as u64, 0]);
    ipc::sys_call(ctx, VFS_TID, msg);

    0 // Placeholder
}

/// Wait options
pub const WNOHANG: u32 = 1;
pub const WUNTRACED: u32 = 2;

/// SYS_WAIT4 - Wait for child process
fn sys_wait4(ctx: &mut ExceptionContext, pid: i32, wstatus: usize, options: u32) -> i64 {
    use sched::task::MAX_TASKS;

    let current_id = match sched::current() {
        Some(id) => id,
        None => return ECHILD,
    };

    unsafe {
        loop {
            // Find a terminated child
            let mut found_child: Option<TaskId> = None;
            let mut has_children = false;

            for i in 0..MAX_TASKS {
                let task = &TASKS[i];
                if task.parent == Some(current_id) {
                    has_children = true;

                    // Check if this child matches the pid filter
                    let matches = if pid == -1 {
                        true // Any child
                    } else if pid > 0 {
                        i == pid as usize
                    } else {
                        true // TODO: process groups not implemented
                    };

                    if matches && task.state == TaskState::Terminated {
                        found_child = Some(TaskId(i));
                        break;
                    }
                }
            }

            if !has_children {
                return ECHILD;
            }

            if let Some(child_id) = found_child {
                // Reap the child
                let child = &mut TASKS[child_id.0];
                let exit_code = child.exit_code;

                // Write status if pointer provided
                if wstatus != 0 {
                    // Linux encodes exit code as (code << 8)
                    let status = (exit_code as u32) << 8;
                    core::ptr::write_volatile(wstatus as *mut i32, status as i32);
                }

                // Free the child task slot
                child.state = TaskState::Free;
                child.parent = None;

                return child_id.0 as i64;
            }

            // No terminated child found
            if options & WNOHANG != 0 {
                return 0; // Non-blocking, no child ready
            }

            // Block waiting for child - child will wake us when it exits
            let task = &mut TASKS[current_id.0];
            task.state = TaskState::WaitBlocked;
            sched::context_switch_blocking(ctx);

            // When we wake up, loop back and try again to find the terminated child
        }
    }
}

/// SYS_BRK - Change data segment size
///
/// This implementation allocates and maps pages on demand when brk grows.
fn sys_brk(addr: usize) -> i64 {
    use crate::mm::frame::{alloc_frame, PAGE_SIZE};
    use crate::mm::PageFlags;

    let current_id = match sched::current() {
        Some(id) => id,
        None => return ENOMEM,
    };

    unsafe {
        let task = &mut TASKS[current_id.0];

        if addr == 0 {
            // Query current brk
            return task.heap_brk as i64;
        }

        // Don't allow shrinking below current heap start
        // (heap_brk is initialized to end of ELF segments)
        let _heap_start = task.heap_brk.min(addr);

        // Allow brk up to 16MB (well below mmap region at 0x10000000)
        const BRK_LIMIT: usize = 0x0100_0000;
        if addr >= BRK_LIMIT {
            return task.heap_brk as i64;
        }

        let old_brk = task.heap_brk;
        let new_brk = addr;

        // If growing, allocate and map new pages
        if new_brk > old_brk {
            let old_page = (old_brk + PAGE_SIZE - 1) / PAGE_SIZE;
            let new_page = (new_brk + PAGE_SIZE - 1) / PAGE_SIZE;

            // Map any new pages needed
            for page_num in old_page..new_page {
                let page_vaddr = page_num * PAGE_SIZE;

                // Allocate a physical frame
                let frame = match alloc_frame() {
                    Some(f) => f,
                    None => return task.heap_brk as i64,
                };

                // Zero the frame
                core::ptr::write_bytes(frame.0 as *mut u8, 0, PAGE_SIZE);

                // Map into the task's address space
                let addr_space = match &mut task.addr_space {
                    Some(aspace) => aspace,
                    None => return task.heap_brk as i64,
                };

                if !addr_space.map_4kb(page_vaddr, frame, PageFlags::user_data()) {
                    return task.heap_brk as i64;
                }

                // TLB invalidation
                core::arch::asm!(
                    "dsb ishst",
                    "tlbi vaae1is, {0}",
                    "dsb ish",
                    "isb",
                    in(reg) page_vaddr >> 12,
                    options(nostack)
                );
            }
        }

        // Update brk
        task.heap_brk = addr;
        addr as i64
    }
}

/// SYS_UNAME - Get system information
fn sys_uname(buf: *mut u8) -> i64 {
    if buf.is_null() {
        return EFAULT;
    }

    // Linux utsname struct: 6 fields of 65 bytes each
    const FIELD_LEN: usize = 65;

    unsafe {
        // sysname
        let sysname = b"Kenix\0";
        core::ptr::copy_nonoverlapping(sysname.as_ptr(), buf, sysname.len());

        // nodename (hostname)
        let nodename = b"kenix\0";
        core::ptr::copy_nonoverlapping(nodename.as_ptr(), buf.add(FIELD_LEN), nodename.len());

        // release
        let release = b"0.1.0\0";
        core::ptr::copy_nonoverlapping(release.as_ptr(), buf.add(FIELD_LEN * 2), release.len());

        // version
        let version = b"#1\0";
        core::ptr::copy_nonoverlapping(version.as_ptr(), buf.add(FIELD_LEN * 3), version.len());

        // machine
        let machine = b"aarch64\0";
        core::ptr::copy_nonoverlapping(machine.as_ptr(), buf.add(FIELD_LEN * 4), machine.len());

        // domainname
        let domainname = b"(none)\0";
        core::ptr::copy_nonoverlapping(domainname.as_ptr(), buf.add(FIELD_LEN * 5), domainname.len());
    }

    ESUCCESS
}

/// SYS_EXECVE - Replace current process with new program
///
/// # Arguments
/// * `ctx` - Exception context (for IPC blocking)
/// * `pathname` - Path to executable (user pointer)
/// * `_argv` - Argument array (currently ignored)
/// * `_envp` - Environment array (currently ignored)
///
/// # Returns
/// * On success: Does not return (current process is replaced)
/// * On failure: Negative error code
fn sys_execve(ctx: &mut ExceptionContext, pathname: usize, argv: usize, _envp: usize) -> i64 {
    use crate::sched::task::TASKS;

    let current_id = match sched::current() {
        Some(id) => id,
        None => return EINVAL,
    };

    // Read pathname from user memory (max 255 chars)
    let path_bytes = unsafe {
        let mut len = 0;
        while len < 255 {
            let c = core::ptr::read_volatile((pathname + len) as *const u8);
            if c == 0 {
                break;
            }
            len += 1;
        }
        core::slice::from_raw_parts(pathname as *const u8, len)
    };

    if path_bytes.is_empty() {
        return ENOENT;
    }

    // Resolve relative paths using cwd
    let mut resolved_path = [0u8; 256];
    let resolved_len: usize;

    // Strip "./" prefix if present
    let (effective_path, effective_len) = if path_bytes.len() >= 2 && path_bytes[0] == b'.' && path_bytes[1] == b'/' {
        (&path_bytes[2..], path_bytes.len() - 2)
    } else {
        (path_bytes, path_bytes.len())
    };

    if effective_len > 0 && effective_path[0] == b'/' {
        // Absolute path - use as-is
        let copy_len = effective_len.min(255);
        resolved_path[..copy_len].copy_from_slice(&effective_path[..copy_len]);
        resolved_len = copy_len;
    } else {
        // Relative path - prepend cwd
        let cwd_len = unsafe {
            let task = &TASKS[current_id.0];
            let mut len = 0;
            while len < sched::MAX_PATH_LEN && len < 200 && task.cwd[len] != 0 {
                resolved_path[len] = task.cwd[len];
                len += 1;
            }
            len
        };

        if cwd_len == 0 || resolved_path[0] != b'/' {
            // No cwd set, use root
            resolved_path[0] = b'/';
            let copy_len = effective_len.min(254);
            resolved_path[1..1 + copy_len].copy_from_slice(&effective_path[..copy_len]);
            resolved_len = 1 + copy_len;
        } else {
            // Append "/" if needed, then path
            let mut pos = cwd_len;
            if pos > 0 && resolved_path[pos - 1] != b'/' && pos < 255 {
                resolved_path[pos] = b'/';
                pos += 1;
            }
            let copy_len = effective_len.min(255 - pos);
            resolved_path[pos..pos + copy_len].copy_from_slice(&effective_path[..copy_len]);
            resolved_len = pos + copy_len;
        }
    }

    // Use resolved path for the rest of the function
    let path_bytes = &resolved_path[..resolved_len];

    // Read argv from user memory
    // argv is a pointer to an array of char* pointers, terminated by NULL
    let mut argv_data = [0u8; 1024];
    let mut argv_offsets = [0u16; 16];
    let mut argc = 0usize;
    let mut data_pos = 0usize;

    if argv != 0 {
        unsafe {
            let argv_ptrs = argv as *const usize;
            // Read up to 15 arguments (leave room for NULL terminator)
            for i in 0..15 {
                let arg_ptr = core::ptr::read_volatile(argv_ptrs.add(i));
                if arg_ptr == 0 {
                    break; // NULL terminator
                }

                // Read the string
                argv_offsets[argc] = data_pos as u16;
                let mut str_len = 0;
                while str_len < 256 && data_pos < 1023 {
                    let c = core::ptr::read_volatile((arg_ptr + str_len) as *const u8);
                    argv_data[data_pos] = c;
                    data_pos += 1;
                    if c == 0 {
                        break;
                    }
                    str_len += 1;
                }
                // Ensure null termination
                if data_pos > 0 && argv_data[data_pos - 1] != 0 {
                    argv_data[data_pos] = 0;
                    data_pos += 1;
                }
                argc += 1;
            }
        }
    }

    // If no argv provided, use pathname basename as argv[0]
    if argc == 0 {
        // Find basename
        let mut last_slash = 0;
        for i in 0..path_bytes.len() {
            if path_bytes[i] == b'/' {
                last_slash = i + 1;
            }
        }
        let basename = &path_bytes[last_slash..];
        let basename_len = basename.len().min(255);
        argv_data[..basename_len].copy_from_slice(&basename[..basename_len]);
        argv_data[basename_len] = 0;
        argv_offsets[0] = 0;
        argc = 1;
    }

    // Create SHM for path transfer
    let shm_id_i64 = shm::sys_shmcreate(256);
    if shm_id_i64 < 0 {
        return ENOMEM;
    }
    let shm_id = shm_id_i64 as usize;

    // Map SHM and copy path
    let shm_addr = shm::sys_shmmap(shm_id, 0);
    if shm_addr < 0 {
        return ENOMEM;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(
            path_bytes.as_ptr(),
            shm_addr as *mut u8,
            path_bytes.len(),
        );
        // Null-terminate
        core::ptr::write_volatile((shm_addr as usize + path_bytes.len()) as *mut u8, 0);
    }

    // Grant VFS access
    shm::sys_shmgrant(shm_id, VFS_TID.0);

    // Set up pending syscall (stage 1: open the executable)
    unsafe {
        let task = &mut TASKS[current_id.0];
        task.pending_syscall = PendingSyscall::ExecveOpen {
            shm_id,
            argv_data,
            argv_offsets,
            argc,
        };
    }

    // Send VFS_OPEN request
    // data[0] = shm_id, data[1] = path_len, data[2] = flags (O_RDONLY = 0)
    let msg = Message::new(VFS_OPEN, [shm_id as u64, path_bytes.len() as u64, 0, 0]);
    ipc::sys_call(ctx, VFS_TID, msg);

    0 // Placeholder - actual return set by complete_pending_syscall (or replaced on success)
}

// ============================================================================
// Signal System Calls (Stubs)
// ============================================================================

/// Signal numbers (Linux-compatible)
pub const SIGCHLD: i32 = 17;

/// Signal action flags
pub const SIG_DFL: u64 = 0;
pub const SIG_IGN: u64 = 1;

/// sigprocmask "how" values
pub const SIG_BLOCK: i32 = 0;
pub const SIG_UNBLOCK: i32 = 1;
pub const SIG_SETMASK: i32 = 2;

/// Sigaction structure (simplified - actual Linux structure is larger)
#[repr(C)]
pub struct Sigaction {
    pub sa_handler: u64,     // Handler function or SIG_DFL/SIG_IGN
    pub sa_flags: u64,       // SA_* flags
    pub sa_restorer: u64,    // Signal trampoline
    pub sa_mask: u64,        // Additional signals to block during handler
}

/// SYS_RT_SIGACTION - Set signal handler (stub)
///
/// This stub accepts and stores handlers but doesn't actually deliver signals yet.
fn sys_rt_sigaction(sig: i32, act: usize, oldact: usize) -> i64 {
    // Validate signal number (1-31, excluding 9=SIGKILL and 19=SIGSTOP)
    if sig < 1 || sig > 31 {
        return EINVAL;
    }
    // SIGKILL and SIGSTOP cannot be caught
    if sig == 9 || sig == 19 {
        return EINVAL;
    }

    let current_id = match sched::current() {
        Some(id) => id,
        None => return EINVAL,
    };

    unsafe {
        let task = &mut TASKS[current_id.0];

        // If oldact is not null, copy current handler to it
        if oldact != 0 {
            let old = oldact as *mut Sigaction;
            (*old).sa_handler = task.signal_handlers[(sig - 1) as usize];
            (*old).sa_flags = 0;
            (*old).sa_restorer = 0;
            (*old).sa_mask = 0;
        }

        // If act is not null, set new handler
        if act != 0 {
            let new = act as *const Sigaction;
            task.signal_handlers[(sig - 1) as usize] = (*new).sa_handler;
            task.signal_restorers[(sig - 1) as usize] = (*new).sa_restorer;
        }
    }

    ESUCCESS
}

/// SYS_RT_SIGPROCMASK - Set signal mask (stub)
///
/// This stub tracks the mask but doesn't actually affect signal delivery yet.
fn sys_rt_sigprocmask(how: i32, set: usize, oldset: usize) -> i64 {
    let current_id = match sched::current() {
        Some(id) => id,
        None => return EINVAL,
    };

    unsafe {
        let task = &mut TASKS[current_id.0];

        // If oldset is not null, return current mask
        if oldset != 0 {
            let oldset_ptr = oldset as *mut u64;
            *oldset_ptr = task.signal_mask;
        }

        // If set is not null, modify mask
        if set != 0 {
            let set_ptr = set as *const u64;
            let new_set = *set_ptr;

            match how {
                SIG_BLOCK => {
                    task.signal_mask |= new_set;
                }
                SIG_UNBLOCK => {
                    task.signal_mask &= !new_set;
                }
                SIG_SETMASK => {
                    task.signal_mask = new_set;
                }
                _ => return EINVAL,
            }
        }
    }

    ESUCCESS
}

/// SYS_KILL - Send signal to process (stub)
///
/// This stub sets the pending bit but doesn't actually deliver the signal yet.
fn sys_kill(pid: i32, sig: i32) -> i64 {
    // Validate signal number
    if sig < 1 || sig > 31 {
        return EINVAL;
    }

    let target_id = if pid > 0 {
        TaskId(pid as usize)
    } else if pid == 0 {
        // Send to all processes in current process group - just current for now
        match sched::current() {
            Some(id) => id,
            None => return EINVAL,
        }
    } else {
        // Negative pid: send to process group - not supported yet
        return EINVAL;
    };

    // Check if target task exists
    if target_id.0 >= sched::task::MAX_TASKS {
        return ESRCH;
    }

    unsafe {
        let task = &mut TASKS[target_id.0];
        if task.state == TaskState::Free || task.state == TaskState::Terminated {
            return ESRCH;
        }

        // Set the signal pending bit
        let sig_bit = 1u64 << (sig - 1);
        task.signal_pending |= sig_bit;
    }

    ESUCCESS
}

/// Set SIGCHLD pending on parent when child exits
///
/// Called from the scheduler when a child task terminates.
pub fn signal_child_exit(parent_id: TaskId) {
    unsafe {
        if parent_id.0 < sched::task::MAX_TASKS {
            let parent = &mut TASKS[parent_id.0];
            if parent.state != TaskState::Free && parent.state != TaskState::Terminated {
                // Set SIGCHLD pending
                let sigchld_bit = 1u64 << (SIGCHLD - 1);
                parent.signal_pending |= sigchld_bit;
            }
        }
    }
}

// ============================================================================
// Signal Delivery (P3)
// ============================================================================

/// Signal frame pushed onto user stack when delivering a signal
///
/// Layout matches Linux's rt_sigframe for AArch64 (simplified)
#[repr(C)]
pub struct SignalFrame {
    /// Saved context (will be restored by sigreturn)
    pub uc_mcontext: SavedContext,
    /// Signal number
    pub sig: u32,
    /// Padding for alignment
    pub _pad: u32,
    /// Original signal mask (to restore after handler)
    pub old_mask: u64,
}

/// Saved user context for signal frame
#[repr(C)]
pub struct SavedContext {
    /// General purpose registers x0-x30
    pub gpr: [u64; 31],
    /// Stack pointer
    pub sp: u64,
    /// Program counter (return address after signal handler)
    pub pc: u64,
    /// Processor state
    pub pstate: u64,
}

/// Check and deliver pending signals (wrapper for backward compatibility)
pub fn check_and_deliver_signals(ctx: &mut ExceptionContext) {
    check_and_deliver_signals_after_syscall(ctx, 0);
}

/// Check and deliver pending signals after a syscall
///
/// Called before returning to user space. If a signal is pending and not masked,
/// set up the signal frame and redirect execution to the handler.
pub fn check_and_deliver_signals_after_syscall(ctx: &mut ExceptionContext, _last_syscall: u16) {
    let current_id = match sched::current() {
        Some(id) => id,
        None => return,
    };

    unsafe {
        let task = &mut TASKS[current_id.0];

        // Find first pending, unmasked signal
        let deliverable = task.signal_pending & !task.signal_mask;
        if deliverable == 0 {
            return; // No signals to deliver
        }

        // Find the lowest numbered signal
        let sig = deliverable.trailing_zeros() + 1;
        if sig > 31 {
            return;
        }

        let handler = task.signal_handlers[(sig - 1) as usize];

        // Check if handler is SIG_IGN
        if handler == SIG_IGN {
            // Clear pending bit and return
            task.signal_pending &= !(1u64 << (sig - 1));
            return;
        }

        // Check if handler is SIG_DFL (default)
        if handler == SIG_DFL {
            // Default actions: most signals terminate the process
            // SIGCHLD is ignored by default
            if sig == SIGCHLD as u32 {
                task.signal_pending &= !(1u64 << (sig - 1));
                return;
            }
            // For other signals with SIG_DFL, just clear and return for now
            // A real implementation would terminate/stop the process
            task.signal_pending &= !(1u64 << (sig - 1));
            return;
        }

        // Clear pending bit
        task.signal_pending &= !(1u64 << (sig - 1));

        // Set up signal frame on user stack
        let frame_size = core::mem::size_of::<SignalFrame>();
        let frame_addr = (ctx.sp as usize - frame_size) & !15; // 16-byte aligned

        let frame = frame_addr as *mut SignalFrame;

        // Save current context
        (*frame).uc_mcontext.gpr.copy_from_slice(&ctx.gpr);
        (*frame).uc_mcontext.sp = ctx.sp;
        (*frame).uc_mcontext.pc = ctx.elr;
        (*frame).uc_mcontext.pstate = ctx.spsr;
        (*frame).sig = sig;
        (*frame).old_mask = task.signal_mask;

        // Block the signal during handler execution (SA_NODEFER not implemented)
        task.signal_mask |= 1u64 << (sig - 1);

        // Set up context to run the signal handler
        ctx.sp = frame_addr as u64;
        ctx.elr = handler;

        // Handler arguments: x0 = signal number
        ctx.gpr[0] = sig as u64;
        // x1 = siginfo_t* (NULL for now)
        ctx.gpr[1] = 0;
        // x2 = ucontext_t* (pointer to signal frame)
        ctx.gpr[2] = frame_addr as u64;

        // Set up link register (x30) to point to sigreturn trampoline
        // Use the restorer provided via sa_restorer in sigaction
        let restorer = task.signal_restorers[(sig - 1) as usize];
        ctx.gpr[30] = restorer;
    }
}

/// SYS_RT_SIGRETURN - Restore context from signal frame
///
/// Called when the signal handler returns to restore the original context.
fn sys_rt_sigreturn(ctx: &mut ExceptionContext) {
    let current_id = match sched::current() {
        Some(id) => id,
        None => return,
    };

    unsafe {
        let task = &mut TASKS[current_id.0];

        // The signal frame is at current SP
        let frame = ctx.sp as *const SignalFrame;

        // Restore context
        ctx.gpr.copy_from_slice(&(*frame).uc_mcontext.gpr);
        ctx.sp = (*frame).uc_mcontext.sp;
        ctx.elr = (*frame).uc_mcontext.pc;
        ctx.spsr = (*frame).uc_mcontext.pstate;

        // Restore signal mask
        task.signal_mask = (*frame).old_mask;
    }
}

// ============================================================================
// musl Startup System Calls (P1)
// ============================================================================

/// SYS_SET_TID_ADDRESS - Set pointer for thread exit TID write
///
/// musl calls this during startup. We store the pointer (for future use
/// when the thread exits to clear it) and return the current task ID.
fn sys_set_tid_address(tidptr: usize) -> i64 {
    let current_id = match sched::current() {
        Some(id) => id,
        None => return EINVAL,
    };

    // Store the tid address for use during exit
    // (When the task exits, we should write 0 to this address and wake futex waiters)
    unsafe {
        let task = &mut TASKS[current_id.0];
        task.clear_child_tid = tidptr;
    }

    // Return current task ID
    current_id.0 as i64
}

/// Resource limit constants (Linux-compatible)
pub const RLIMIT_STACK: i32 = 3;
pub const RLIMIT_NOFILE: i32 = 7;

/// Rlimit structure
#[repr(C)]
pub struct Rlimit {
    pub rlim_cur: u64,  // Soft limit
    pub rlim_max: u64,  // Hard limit
}

/// Special value meaning "unlimited"
pub const RLIM_INFINITY: u64 = !0u64;

/// SYS_PRLIMIT64 - Get/set resource limits
///
/// musl calls this to query stack size and other limits.
/// We return sensible defaults for our microkernel.
fn sys_prlimit64(pid: i32, resource: i32, new_limit: usize, old_limit: usize) -> i64 {
    // For now, only allow querying own process (pid 0 or current pid)
    let current_id = match sched::current() {
        Some(id) => id,
        None => return EINVAL,
    };

    if pid != 0 && pid != current_id.0 as i32 {
        return ESRCH;  // Can't query other processes
    }

    // Return current limits if old_limit is provided
    if old_limit != 0 {
        let rlim = old_limit as *mut Rlimit;
        unsafe {
            match resource {
                RLIMIT_STACK => {
                    // Stack limit: 2MB soft, 2MB hard
                    (*rlim).rlim_cur = 2 * 1024 * 1024;
                    (*rlim).rlim_max = 2 * 1024 * 1024;
                }
                RLIMIT_NOFILE => {
                    // File descriptor limit: MAX_FDS
                    (*rlim).rlim_cur = sched::MAX_FDS as u64;
                    (*rlim).rlim_max = sched::MAX_FDS as u64;
                }
                _ => {
                    // Unknown resource: return infinity (no limit)
                    (*rlim).rlim_cur = RLIM_INFINITY;
                    (*rlim).rlim_max = RLIM_INFINITY;
                }
            }
        }
    }

    // We ignore new_limit for now (don't actually change limits)
    let _ = new_limit;

    ESUCCESS
}

/// SYS_GETRANDOM - Fill buffer with random bytes
///
/// We use the ARM physical counter as a source of entropy.
/// This is not cryptographically secure but sufficient for musl startup.
fn sys_getrandom(buf: usize, buflen: usize, _flags: u32) -> i64 {
    if buf == 0 || buflen == 0 {
        return 0;
    }

    // Limit to reasonable size
    let len = buflen.min(4096);

    // Use timer counter as pseudo-random source
    // XORshift algorithm seeded with counter
    let mut state = timer::read_counter();
    if state == 0 {
        state = 0xdeadbeef_cafebabe;  // Fallback seed
    }

    unsafe {
        let ptr = buf as *mut u8;
        for i in 0..len {
            // Simple xorshift64
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            core::ptr::write_volatile(ptr.add(i), state as u8);
        }
    }

    len as i64
}

// ============================================================================
// Vector I/O System Calls (P2)
// ============================================================================

/// I/O vector structure for readv/writev
#[repr(C)]
pub struct Iovec {
    pub iov_base: usize,  // Pointer to buffer
    pub iov_len: usize,   // Length of buffer
}

/// Maximum number of iovec elements
const IOV_MAX: usize = 1024;

/// SYS_WRITEV - Write from multiple buffers (gather write)
///
/// For console writes, we iterate through the iovec array and write each buffer.
fn sys_writev(ctx: &mut ExceptionContext, fd: usize, iov: usize, iovcnt: usize) -> i64 {
    // Validate iovcnt
    if iovcnt == 0 {
        return 0;
    }
    if iovcnt > IOV_MAX {
        return EINVAL;
    }

    // Get current task's fd table
    let current_id = match sched::current() {
        Some(id) => id,
        None => return EBADF,
    };

    let fd_entry = unsafe {
        let task = &TASKS[current_id.0];
        if fd >= sched::MAX_FDS {
            return EBADF;
        }
        task.fds[fd]
    };

    // Check if fd is valid and writable
    if fd_entry.kind == FdKind::None {
        return EBADF;
    }
    if !fd_entry.flags.writable {
        return EBADF;
    }

    // For console, iterate through iovecs and write each
    if fd_entry.kind == FdKind::Console {
        let mut total: i64 = 0;

        const UART_BASE: usize = 0x0900_0000;
        const UART_DR: usize = 0x000;
        const UART_FR: usize = 0x018;
        const UART_FR_TXFF: u32 = 1 << 5;

        unsafe {
            let iovecs = iov as *const Iovec;
            for i in 0..iovcnt {
                let iov_entry = &*iovecs.add(i);
                let buf = iov_entry.iov_base;
                let len = iov_entry.iov_len.min(4096);

                for j in 0..len {
                    let c = core::ptr::read_volatile((buf + j) as *const u8);
                    let fr = (UART_BASE + UART_FR) as *const u32;
                    while (core::ptr::read_volatile(fr) & UART_FR_TXFF) != 0 {
                        core::hint::spin_loop();
                    }
                    let dr = (UART_BASE + UART_DR) as *mut u8;
                    core::ptr::write_volatile(dr, c);
                }
                total += len as i64;
            }
        }

        return total;
    }

    // For other fd types, fall back to iterating and calling sys_write
    let mut total: i64 = 0;
    unsafe {
        let iovecs = iov as *const Iovec;
        for i in 0..iovcnt {
            let iov_entry = &*iovecs.add(i);
            if iov_entry.iov_len > 0 {
                let ret = sys_write(ctx, fd, iov_entry.iov_base, iov_entry.iov_len);
                if ret < 0 {
                    if total == 0 {
                        return ret;  // Return error if nothing written yet
                    }
                    break;  // Return partial count on error
                }
                total += ret;
            }
        }
    }

    total
}

/// SYS_READV - Read into multiple buffers (scatter read)
///
/// Currently only implemented for console.
fn sys_readv(ctx: &mut ExceptionContext, fd: usize, iov: usize, iovcnt: usize) -> i64 {
    // Validate iovcnt
    if iovcnt == 0 {
        return 0;
    }
    if iovcnt > IOV_MAX {
        return EINVAL;
    }

    // Get current task's fd table
    let current_id = match sched::current() {
        Some(id) => id,
        None => return EBADF,
    };

    let fd_entry = unsafe {
        let task = &TASKS[current_id.0];
        if fd >= sched::MAX_FDS {
            return EBADF;
        }
        task.fds[fd]
    };

    // Check if fd is valid and readable
    if fd_entry.kind == FdKind::None {
        return EBADF;
    }
    if !fd_entry.flags.readable {
        return EBADF;
    }

    // For console and other types, iterate and call sys_read
    let mut total: i64 = 0;
    unsafe {
        let iovecs = iov as *const Iovec;
        for i in 0..iovcnt {
            let iov_entry = &*iovecs.add(i);
            if iov_entry.iov_len > 0 {
                let ret = sys_read(ctx, fd, iov_entry.iov_base, iov_entry.iov_len);
                if ret < 0 {
                    if total == 0 {
                        return ret;  // Return error if nothing read yet
                    }
                    break;  // Return partial count on error
                }
                if ret == 0 {
                    break;  // EOF
                }
                total += ret;
            }
        }
    }

    total
}

// ============================================================================
// Terminal IOCTL Support (P2)
// ============================================================================

/// IOCTL request codes (Linux AArch64)
pub const TCGETS: u64 = 0x5401;          // Get terminal attributes
pub const TCSETS: u64 = 0x5402;          // Set terminal attributes
pub const TIOCGWINSZ: u64 = 0x5413;      // Get window size
pub const TIOCSWINSZ: u64 = 0x5414;      // Set window size
pub const TIOCGPGRP: u64 = 0x540F;       // Get foreground process group
pub const TIOCSPGRP: u64 = 0x5410;       // Set foreground process group
pub const TIOCSCTTY: u64 = 0x540E;       // Make controlling tty
pub const TIOCNOTTY: u64 = 0x5422;       // Give up controlling tty

/// Terminal window size structure
#[repr(C)]
pub struct Winsize {
    pub ws_row: u16,    // Number of rows
    pub ws_col: u16,    // Number of columns
    pub ws_xpixel: u16, // Unused
    pub ws_ypixel: u16, // Unused
}

/// Termios structure (simplified)
#[repr(C)]
pub struct Termios {
    pub c_iflag: u32,   // Input mode flags
    pub c_oflag: u32,   // Output mode flags
    pub c_cflag: u32,   // Control mode flags
    pub c_lflag: u32,   // Local mode flags
    pub c_line: u8,     // Line discipline
    pub c_cc: [u8; 19], // Control characters
}

/// SYS_IOCTL - I/O control
///
/// Handle common terminal ioctls for BusyBox compatibility.
fn sys_ioctl(fd: usize, request: u64, arg: usize) -> i64 {
    let current_id = match sched::current() {
        Some(id) => id,
        None => return EBADF,
    };

    let fd_entry = unsafe {
        let task = &TASKS[current_id.0];
        if fd >= sched::MAX_FDS {
            return EBADF;
        }
        task.fds[fd]
    };

    if fd_entry.kind == FdKind::None {
        return EBADF;
    }

    match request {
        TIOCGWINSZ => {
            // Return a reasonable default window size
            if arg == 0 {
                return EFAULT;
            }
            unsafe {
                let ws = arg as *mut Winsize;
                (*ws).ws_row = 24;      // Standard terminal height
                (*ws).ws_col = 80;      // Standard terminal width
                (*ws).ws_xpixel = 0;
                (*ws).ws_ypixel = 0;
            }
            ESUCCESS
        }
        TCGETS => {
            // Return reasonable default terminal attributes
            if arg == 0 {
                return EFAULT;
            }
            unsafe {
                let termios = arg as *mut Termios;
                // Set reasonable defaults (echo, canonical mode)
                (*termios).c_iflag = 0;
                (*termios).c_oflag = 0;
                (*termios).c_cflag = 0;
                (*termios).c_lflag = 0;
                (*termios).c_line = 0;
                (*termios).c_cc = [0; 19];
            }
            ESUCCESS
        }
        TCSETS | TIOCSWINSZ | TIOCSPGRP | TIOCSCTTY | TIOCNOTTY => {
            // Accept but ignore these settings
            ESUCCESS
        }
        TIOCGPGRP => {
            // Return current task ID as process group
            if arg == 0 {
                return EFAULT;
            }
            unsafe {
                let pgrp = arg as *mut i32;
                *pgrp = current_id.0 as i32;
            }
            ESUCCESS
        }
        _ => {
            // Unknown ioctl - return success (many ioctls can be safely ignored)
            ESUCCESS
        }
    }
}
