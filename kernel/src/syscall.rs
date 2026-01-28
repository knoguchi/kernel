//! System call dispatcher for Kenix
//!
//! Syscall numbers:
//! - 0: SYS_YIELD - Voluntarily yield the CPU
//! - 1: SYS_EXIT  - Terminate the current task

use crate::exception::ExceptionContext;
use crate::sched;

/// Syscall numbers
pub const SYS_YIELD: u16 = 0;
pub const SYS_EXIT: u16 = 1;

/// Error codes
pub const ENOSYS: i64 = -38;  // Function not implemented
pub const ESUCCESS: i64 = 0;  // Success

/// Handle a system call
///
/// # Arguments
/// * `ctx` - Exception context (registers)
/// * `syscall_num` - Syscall number from SVC immediate
///
/// # Returns
/// The return value is placed in ctx.gpr[0] (x0)
pub fn handle_syscall(ctx: &mut ExceptionContext, syscall_num: u16) {
    let result = match syscall_num {
        SYS_YIELD => {
            sys_yield()
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
