//! System call dispatcher for Kenix
//!
//! Linux-compatible syscall numbers (AArch64):
//! - 64: SYS_WRITE - Write to file descriptor
//! - 93: SYS_EXIT  - Terminate the current task
//!
//! Kenix-specific syscall numbers (for compatibility):
//! - 0: SYS_YIELD - Voluntarily yield the CPU

use crate::exception::ExceptionContext;
use crate::sched;

/// Syscall numbers (Linux-compatible for AArch64)
pub const SYS_YIELD: u16 = 0;    // Kenix-specific
pub const SYS_WRITE: u16 = 64;   // Linux-compatible
pub const SYS_EXIT: u16 = 93;    // Linux-compatible

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

    let result = match syscall_num {
        SYS_YIELD => {
            sys_yield()
        }
        SYS_WRITE => {
            let fd = ctx.gpr[0] as i32;
            let buf = ctx.gpr[1] as usize;
            let len = ctx.gpr[2] as usize;
            sys_write(fd, buf, len)
        }
        SYS_EXIT => {
            let exit_code = ctx.gpr[0] as i32;
            sys_exit(exit_code)
        }
        _ => {
            // Unknown syscall
            ENOSYS
        }
    };

    // Set return value in x0
    ctx.gpr[0] = result as u64;
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
