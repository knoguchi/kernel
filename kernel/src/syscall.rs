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
use crate::sched::{self, TaskId, Message, TaskState, FileDescriptor, PendingSyscall};
use crate::sched::task::FdFlags;
use crate::ipc;
use crate::shm;
use crate::irq;

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

/// Syscall numbers - Shared Memory
pub const SYS_SHMCREATE: u16 = 10;  // Create shared memory region
pub const SYS_SHMMAP: u16 = 11;     // Map shared memory into current task
pub const SYS_SHMUNMAP: u16 = 12;   // Unmap shared memory from current task
pub const SYS_SHMGRANT: u16 = 13;   // Grant another task access to shared memory

/// Syscall numbers - Kenix-specific
pub const SYS_YIELD: u16 = 0;    // Voluntarily yield CPU
pub const SYS_NOTIFY: u16 = 7;   // Send async notification
pub const SYS_WAIT_NOTIFY: u16 = 8;  // Wait for notification
pub const SYS_GETPID: u16 = 20;  // Get current task ID
pub const SYS_SPAWN: u16 = 21;   // Create new task from ELF

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
pub const SYS_FSTAT: u16 = 80;   // Get file status
pub const SYS_EXIT: u16 = 93;    // Terminate process
pub const SYS_WAIT4: u16 = 260;  // Wait for child process
pub const SYS_BRK: u16 = 214;    // Change data segment size

/// Error codes (Linux-compatible)
pub const ESUCCESS: i64 = 0;   // Success
pub const ENOENT: i64 = -2;    // No such file or directory
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
        SYS_OPENAT => {
            let _dirfd = ctx.gpr[0] as i32;  // AT_FDCWD = -100
            let pathname = ctx.gpr[1] as usize;
            let flags = ctx.gpr[2] as u32;
            let _mode = ctx.gpr[3] as u32;
            ctx.gpr[0] = sys_open(ctx, pathname, flags) as u64;
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
            ctx.gpr[0] = sys_exit(exit_code) as u64;
        }

        SYS_GETPID => {
            ctx.gpr[0] = sys_getpid() as u64;
        }

        SYS_SPAWN => {
            let elf_ptr = ctx.gpr[0] as usize;
            let elf_len = ctx.gpr[1] as usize;
            ctx.gpr[0] = sys_spawn(elf_ptr, elf_len) as u64;
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

        _ => {
            // Unknown syscall
            ctx.gpr[0] = ENOSYS as u64;
        }
    }
}

/// SYS_YIELD - Voluntarily yield the CPU to another task
fn sys_yield() -> i64 {
    sched::yield_cpu();
    ESUCCESS
}

/// SYS_EXIT - Terminate the current task
fn sys_exit(_exit_code: i32) -> i64 {
    sched::exit();
    // Never returns, but need return type for consistency
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
            // Read from UART (blocking single character for now)
            const UART_BASE: usize = 0x0900_0000;
            const UART_DR: usize = 0x000;
            const UART_FR: usize = 0x018;
            const UART_FR_RXFE: u32 = 1 << 4; // RX FIFO empty

            if len == 0 {
                return 0;
            }

            // Wait for a character to be available
            unsafe {
                let fr = (UART_BASE + UART_FR) as *const u32;
                while (core::ptr::read_volatile(fr) & UART_FR_RXFE) != 0 {
                    core::hint::spin_loop();
                }

                // Read the character
                let dr = (UART_BASE + UART_DR) as *const u8;
                let c = core::ptr::read_volatile(dr);

                // Write to user buffer
                core::ptr::write_volatile(buf as *mut u8, c);
            }

            1 // Read one character
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

/// Maximum ELF size we'll accept for spawn (1MB should be plenty for user programs)
const MAX_ELF_SIZE: usize = 1024 * 1024;

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

    // Create the task using the existing ELF loader
    match sched::create_user_task_from_elf("spawned", elf_data) {
        Some(task_id) => task_id.0 as i64,
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

/// SYS_OPENAT - Open a file
///
/// Opens a file and returns a file descriptor.
fn sys_open(ctx: &mut ExceptionContext, pathname: usize, flags: u32) -> i64 {
    let current_id = match sched::current() {
        Some(id) => id,
        None => return EBADF,
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
    let msg = Message::new(VFS_OPEN, [shm_id as u64, path_bytes.len() as u64, flags as u64, 0]);
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
    let mut path_len = 0;
    unsafe {
        while path_len < sched::MAX_PATH_LEN - 1 {
            let c = core::ptr::read_volatile((path + path_len) as *const u8);
            if c == 0 {
                break;
            }
            path_len += 1;
        }
    }

    if path_len == 0 {
        return ENOENT;
    }

    // For now, just update cwd without validating the path exists
    // A proper implementation would call VFS to verify the directory
    unsafe {
        let task = &mut TASKS[current_id.0];

        // Copy new path
        core::ptr::copy_nonoverlapping(
            path as *const u8,
            task.cwd.as_mut_ptr(),
            path_len,
        );
        task.cwd[path_len] = 0; // Null-terminate
    }

    ESUCCESS
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

    // For console fds, return a simple stat
    if fd_entry.kind == FdKind::Console {
        unsafe {
            let stat = statbuf as *mut Stat;
            (*stat) = core::mem::zeroed();
            (*stat).st_mode = 0o020666; // Character device
            (*stat).st_blksize = 4096;
        }
        return ESUCCESS;
    }

    // For pipes
    if fd_entry.kind == FdKind::PipeRead || fd_entry.kind == FdKind::PipeWrite {
        unsafe {
            let stat = statbuf as *mut Stat;
            (*stat) = core::mem::zeroed();
            (*stat).st_mode = 0o010666; // FIFO/pipe
            (*stat).st_blksize = 4096;
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

        // Block waiting for child
        let task = &mut TASKS[current_id.0];
        task.state = TaskState::WaitBlocked;
        sched::context_switch_blocking(ctx);

        // When we wake up, try again (recursive would be cleaner but let's avoid stack growth)
        // For now, just return ECHILD - proper implementation needs a loop or retry
        ECHILD
    }
}

/// SYS_BRK - Change data segment size
fn sys_brk(addr: usize) -> i64 {
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

        // Don't allow shrinking below the default
        if addr < sched::DEFAULT_HEAP_START {
            return task.heap_brk as i64;
        }

        // Don't allow growing into stack region (2MB)
        if addr >= 0x0020_0000 {
            return task.heap_brk as i64;
        }

        // Update brk
        // Note: A proper implementation would allocate physical pages and map them
        // For now we just track the value (memory was already mapped at task creation)
        task.heap_brk = addr;
        addr as i64
    }
}
