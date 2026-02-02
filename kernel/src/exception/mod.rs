//! Exception handling for AArch64 EL1
//!
//! This module sets up the exception vector table and provides handlers
//! for CPU exceptions, interrupts, and syscalls.

mod context;

pub use context::ExceptionContext;

use crate::gic::{self, TIMER_IRQ, IRQ_SPURIOUS};
use crate::timer;
use crate::sched;
use crate::syscall;
use crate::irq;
use crate::mmap;

extern "C" {
    /// Exception vector table defined in vectors.s
    static exception_vectors: u8;
}

/// Initialize exception handling by setting VBAR_EL1
///
/// # Safety
/// Must be called once during kernel initialization, after MMU setup.
pub unsafe fn init() {
    let vectors_addr = &exception_vectors as *const u8 as u64;

    // Set Vector Base Address Register for EL1
    core::arch::asm!(
        "msr vbar_el1, {addr}",
        "isb",
        addr = in(reg) vectors_addr,
        options(nostack, preserves_flags)
    );
}

/// Read the current VBAR_EL1 value
pub fn vbar_el1() -> u64 {
    let value: u64;
    unsafe {
        core::arch::asm!(
            "mrs {}, vbar_el1",
            out(reg) value,
            options(nostack, preserves_flags)
        );
    }
    value
}

/// Exception class names for debug output
fn exception_class_name(ec: u8) -> &'static str {
    match ec {
        0x00 => "Unknown",
        0x01 => "Trapped WFI/WFE",
        0x0E => "Illegal execution state",
        0x15 => "SVC (AArch64)",
        0x18 => "MSR/MRS trap",
        0x20 => "Instruction abort (lower EL)",
        0x21 => "Instruction abort (current EL)",
        0x22 => "PC alignment fault",
        0x24 => "Data abort (lower EL)",
        0x25 => "Data abort (current EL)",
        0x26 => "SP alignment fault",
        0x2C => "FP trap",
        0x2F => "SError",
        0x30 => "Breakpoint (lower EL)",
        0x31 => "Breakpoint (current EL)",
        0x32 => "Software step (lower EL)",
        0x33 => "Software step (current EL)",
        0x34 => "Watchpoint (lower EL)",
        0x35 => "Watchpoint (current EL)",
        0x3C => "BRK instruction",
        _ => "Reserved/Unknown",
    }
}

/// Data fault status code names
fn fault_status_name(dfsc: u8) -> &'static str {
    match dfsc & 0x3F {
        0b000000 => "Address size fault, level 0",
        0b000001 => "Address size fault, level 1",
        0b000010 => "Address size fault, level 2",
        0b000011 => "Address size fault, level 3",
        0b000100 => "Translation fault, level 0",
        0b000101 => "Translation fault, level 1",
        0b000110 => "Translation fault, level 2",
        0b000111 => "Translation fault, level 3",
        0b001001 => "Access flag fault, level 1",
        0b001010 => "Access flag fault, level 2",
        0b001011 => "Access flag fault, level 3",
        0b001101 => "Permission fault, level 1",
        0b001110 => "Permission fault, level 2",
        0b001111 => "Permission fault, level 3",
        0b010000 => "Synchronous external abort",
        0b100001 => "Alignment fault",
        _ => "Unknown fault status",
    }
}

// Import print macros from main module
macro_rules! exception_print {
    ($($arg:tt)*) => {{
        // Access UART directly for exception context
        // This avoids potential deadlocks if we took an exception while holding the UART lock
        use core::fmt::Write;

        // QEMU virt machine PL011 UART
        const UART_BASE: usize = 0x0900_0000;
        const UART_DR: usize = 0x000;
        const UART_FR: usize = 0x018;
        const UART_FR_TXFF: u32 = 1 << 5;

        struct RawUart;

        impl Write for RawUart {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                for c in s.bytes() {
                    unsafe {
                        let fr = (UART_BASE + UART_FR) as *const u32;
                        while (core::ptr::read_volatile(fr) & UART_FR_TXFF) != 0 {
                            core::hint::spin_loop();
                        }
                        let dr = (UART_BASE + UART_DR) as *mut u8;
                        core::ptr::write_volatile(dr, c);
                    }
                }
                Ok(())
            }
        }

        let _ = write!(RawUart, $($arg)*);
    }};
}

macro_rules! exception_println {
    () => { exception_print!("\n") };
    ($($arg:tt)*) => {{ exception_print!($($arg)*); exception_print!("\n"); }};
}

/// Print exception context for debugging
fn print_context(ctx: &ExceptionContext) {
    exception_println!("  Exception Class: {} ({:#04x})",
        exception_class_name(ctx.exception_class()), ctx.exception_class());
    exception_println!("  ESR_EL1:  {:#018x}", ctx.esr);
    exception_println!("  ELR_EL1:  {:#018x}", ctx.elr);
    exception_println!("  SPSR_EL1: {:#018x}", ctx.spsr);
    exception_println!("  FAR_EL1:  {:#018x}", ctx.far);
    exception_println!("  SP:       {:#018x}", ctx.sp);

    if ctx.is_data_abort() || ctx.is_instruction_abort() {
        exception_println!("  Fault: {} ({})",
            fault_status_name(ctx.fault_status_code()),
            if ctx.is_write_fault() { "write" } else { "read" });
    }
}

// ============================================================================
// EL1 Exception Handlers (Kernel Mode)
// ============================================================================

#[no_mangle]
extern "C" fn handle_el1_sync(ctx: &mut ExceptionContext, _exc_type: u64) {
    exception_println!();
    exception_println!("!!! KERNEL EXCEPTION !!!");

    if ctx.is_data_abort() {
        exception_println!("KERNEL DATA ABORT!");
        exception_println!("Faulting address: {:#018x}", ctx.far);
    } else if ctx.is_instruction_abort() {
        exception_println!("KERNEL INSTRUCTION ABORT!");
        exception_println!("Faulting address: {:#018x}", ctx.far);
    } else {
        exception_println!("KERNEL SYNCHRONOUS EXCEPTION!");
    }

    print_context(ctx);
    exception_println!();

    // Kernel exceptions are fatal
    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
extern "C" fn handle_el1_irq(ctx: &mut ExceptionContext, _exc_type: u64) {
    let irq_num = gic::acknowledge();

    if irq_num == IRQ_SPURIOUS {
        return;
    }

    if irq_num == TIMER_IRQ {
        timer::acknowledge_and_reset();
        // Check if we need to reschedule
        let needs_switch = sched::tick();
        // IMPORTANT: Send EOI before context switch because switch_context_and_restore
        // never returns (it does ERET directly)
        gic::end_of_interrupt(irq_num);
        if needs_switch {
            unsafe { sched::context_switch(ctx); }
        }
    } else if irq::handle_irq(irq_num) {
        // IRQ was handled by a registered userspace driver
        // Don't send EOI here - the driver will do it via SYS_IRQ_ACK
        // However, we may need to reschedule if the handler task was woken
        let needs_switch = sched::tick();
        if needs_switch {
            unsafe { sched::context_switch(ctx); }
        }
    } else {
        exception_println!("Unhandled IRQ: {}", irq_num);
        gic::end_of_interrupt(irq_num);
    }
}

#[no_mangle]
extern "C" fn handle_el1_fiq(_ctx: &mut ExceptionContext, _exc_type: u64) {
    exception_println!();
    exception_println!("!!! KERNEL FIQ - NOT IMPLEMENTED !!!");
    exception_println!();

    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
extern "C" fn handle_el1_serror(ctx: &mut ExceptionContext, _exc_type: u64) {
    exception_println!();
    exception_println!("!!! KERNEL SYSTEM ERROR !!!");
    print_context(ctx);
    exception_println!();

    loop {
        core::hint::spin_loop();
    }
}

// ============================================================================
// EL0 Exception Handlers (User Mode)
// ============================================================================

#[no_mangle]
extern "C" fn handle_el0_sync(ctx: &mut ExceptionContext, _exc_type: u64) {
    if ctx.is_svc() {
        // System call from userspace
        let syscall_num = ctx.svc_number();
        syscall::handle_syscall(ctx, syscall_num);
    } else if ctx.is_data_abort() {
        let fault_addr = ctx.far as usize;

        // Check if this is a demand-paging fault for an mmap region
        if fault_addr >= mmap::MMAP_BASE && fault_addr < mmap::MMAP_END {
            let result = mmap::handle_page_fault(fault_addr);
            if result == 0 {
                // Page allocated successfully, resume execution
                return;
            }
        }

        // Not an mmap fault or allocation failed - fatal error
        exception_println!();
        exception_println!("USER DATA ABORT!");
        exception_println!("Faulting address: {:#018x}", ctx.far);
        print_context(ctx);

        // TODO: Send SIGSEGV to process, for now just halt
        loop {
            core::hint::spin_loop();
        }
    } else if ctx.is_instruction_abort() {
        exception_println!();
        exception_println!("USER INSTRUCTION ABORT!");
        exception_println!("Faulting address: {:#018x}", ctx.far);
        print_context(ctx);

        // TODO: Send SIGSEGV to process
        loop {
            core::hint::spin_loop();
        }
    } else {
        exception_println!();
        exception_println!("USER SYNCHRONOUS EXCEPTION!");
        print_context(ctx);

        loop {
            core::hint::spin_loop();
        }
    }
}

#[no_mangle]
extern "C" fn handle_el0_irq(ctx: &mut ExceptionContext, _exc_type: u64) {
    // Handle IRQ same as EL1 (timer tick may trigger reschedule)
    let irq_num = gic::acknowledge();

    if irq_num == IRQ_SPURIOUS {
        return;
    }

    if irq_num == TIMER_IRQ {
        timer::acknowledge_and_reset();
        // Check if we need to reschedule
        let needs_switch = sched::tick();
        // IMPORTANT: Send EOI before context switch because switch_context_and_restore
        // never returns (it does ERET directly)
        gic::end_of_interrupt(irq_num);
        if needs_switch {
            unsafe { sched::context_switch(ctx); }
        }
    } else if irq::handle_irq(irq_num) {
        // IRQ was handled by a registered userspace driver
        // Don't send EOI here - the driver will do it via SYS_IRQ_ACK
        let needs_switch = sched::tick();
        if needs_switch {
            unsafe { sched::context_switch(ctx); }
        }
    } else {
        exception_println!("Unhandled IRQ: {}", irq_num);
        gic::end_of_interrupt(irq_num);
    }
}

#[no_mangle]
extern "C" fn handle_el0_fiq(_ctx: &mut ExceptionContext, _exc_type: u64) {
    exception_println!();
    exception_println!("!!! USER FIQ - NOT IMPLEMENTED !!!");
    exception_println!();

    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
extern "C" fn handle_el0_serror(ctx: &mut ExceptionContext, _exc_type: u64) {
    exception_println!();
    exception_println!("!!! USER SYSTEM ERROR !!!");
    print_context(ctx);
    exception_println!();

    loop {
        core::hint::spin_loop();
    }
}
