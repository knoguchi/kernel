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
use crate::sched::{self, TaskId, Message};
use crate::ipc;
use crate::shm;

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
pub const SYS_GETPID: u16 = 20;  // Get current task ID
pub const SYS_SPAWN: u16 = 21;   // Create new task from ELF

/// Syscall numbers - POSIX-compatible file I/O
pub const SYS_READ: u16 = 63;    // Read from file descriptor
pub const SYS_WRITE: u16 = 64;   // Write to file descriptor
pub const SYS_CLOSE: u16 = 57;   // Close file descriptor
pub const SYS_EXIT: u16 = 93;    // Terminate process

/// Error codes (Linux-compatible)
pub const ESUCCESS: i64 = 0;   // Success
pub const EAGAIN: i64 = -11;   // Resource temporarily unavailable
pub const ENOMEM: i64 = -12;   // Out of memory
pub const EBADF: i64 = -9;     // Bad file descriptor
pub const EFAULT: i64 = -14;   // Bad address
pub const EINVAL: i64 = -22;   // Invalid argument
pub const ENOSYS: i64 = -38;   // Function not implemented

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
            ctx.gpr[0] = sys_read(fd, buf, len) as u64;
        }

        SYS_WRITE => {
            let fd = ctx.gpr[0] as usize;
            let buf = ctx.gpr[1] as usize;
            let len = ctx.gpr[2] as usize;
            ctx.gpr[0] = sys_write(fd, buf, len) as u64;
        }

        SYS_CLOSE => {
            let fd = ctx.gpr[0] as usize;
            ctx.gpr[0] = sys_close(fd) as u64;
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
fn sys_read(fd: usize, buf: usize, len: usize) -> i64 {
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
        _ => EBADF,
    }
}

/// SYS_WRITE - Write to a file descriptor
///
/// Currently supports stdout (fd=1) and stderr (fd=2) to console.
/// Returns number of bytes written, or negative error code.
fn sys_write(fd: usize, buf: usize, len: usize) -> i64 {
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
        _ => EBADF,
    }
}

/// SYS_CLOSE - Close a file descriptor
fn sys_close(fd: usize) -> i64 {
    let current_id = match sched::current() {
        Some(id) => id,
        None => return EBADF,
    };

    unsafe {
        let task = &mut TASKS[current_id.0];
        if task.close_fd(fd) {
            ESUCCESS
        } else {
            EBADF
        }
    }
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
