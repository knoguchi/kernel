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

/// Syscall numbers - Legacy (Linux-compatible)
pub const SYS_YIELD: u16 = 0;    // Kenix-specific
pub const SYS_WRITE: u16 = 64;   // Linux-compatible (will be removed)
pub const SYS_EXIT: u16 = 93;    // Linux-compatible (will be removed)

/// Error codes (Linux-compatible)
pub const ESUCCESS: i64 = 0;   // Success
pub const EBADF: i64 = -9;     // Bad file descriptor
pub const EFAULT: i64 = -14;   // Bad address
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

        // Legacy syscalls (kept for transition period)
        SYS_WRITE => {
            let fd = ctx.gpr[0] as i32;
            let buf = ctx.gpr[1] as usize;
            let len = ctx.gpr[2] as usize;
            ctx.gpr[0] = sys_write(fd, buf, len) as u64;
        }

        SYS_EXIT => {
            let exit_code = ctx.gpr[0] as i32;
            ctx.gpr[0] = sys_exit(exit_code) as u64;
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

/// SYS_WRITE - Write to a file descriptor
///
/// For now, only stdout (fd=1) and stderr (fd=2) are supported,
/// both map to the UART.
fn sys_write(fd: i32, buf: usize, len: usize) -> i64 {
    // Only support stdout and stderr
    if fd != 1 && fd != 2 {
        return EBADF;
    }

    // Limit write size to prevent excessive time in kernel
    let len = len.min(4096);

    // UART base address (QEMU virt PL011)
    const UART_BASE: usize = 0x0900_0000;
    const UART_DR: usize = 0x000;
    const UART_FR: usize = 0x018;
    const UART_FR_TXFF: u32 = 1 << 5;

    // Write bytes from user buffer to UART
    for i in 0..len {
        let c = unsafe {
            // Read byte from user memory
            core::ptr::read_volatile((buf + i) as *const u8)
        };

        // Wait for TX FIFO to have space
        unsafe {
            let fr = (UART_BASE + UART_FR) as *const u32;
            while (core::ptr::read_volatile(fr) & UART_FR_TXFF) != 0 {
                core::hint::spin_loop();
            }
            // Write character
            let dr = (UART_BASE + UART_DR) as *mut u8;
            core::ptr::write_volatile(dr, c);
        }
    }

    len as i64
}
