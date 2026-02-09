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

// ============================================================================
// Alignment Fault Emulation for SIMD Instructions
// ============================================================================

/// Try to emulate an unaligned memory access
/// Returns true if emulation succeeded, false if not emulatable
fn try_emulate_alignment_fault(ctx: &mut ExceptionContext) -> bool {
    // Read the faulting instruction
    let instr_addr = ctx.elr as *const u32;
    let instr = unsafe { core::ptr::read_volatile(instr_addr) };

    // Try regular GPR unaligned access emulation first (most common)
    if try_emulate_str_imm(ctx, instr) {
        return true;
    }
    if try_emulate_ldr_imm(ctx, instr) {
        return true;
    }
    if try_emulate_stur(ctx, instr) {
        return true;
    }
    if try_emulate_ldur(ctx, instr) {
        return true;
    }
    if try_emulate_str_pre_post(ctx, instr) {
        return true;
    }
    if try_emulate_ldr_pre_post(ctx, instr) {
        return true;
    }
    if try_emulate_stp_gpr(ctx, instr) {
        return true;
    }
    if try_emulate_ldp_gpr(ctx, instr) {
        return true;
    }

    // Try SIMD/FP emulation handlers
    if try_emulate_stur_simd(ctx, instr) {
        return true;
    }
    if try_emulate_ldur_simd(ctx, instr) {
        return true;
    }
    if try_emulate_stp_simd(ctx, instr) {
        return true;
    }
    if try_emulate_ldp_simd(ctx, instr) {
        return true;
    }
    if try_emulate_str_simd_imm(ctx, instr) {
        return true;
    }
    if try_emulate_ldr_simd_imm(ctx, instr) {
        return true;
    }
    if try_emulate_str_simd_reg(ctx, instr) {
        return true;
    }
    if try_emulate_ldr_simd_reg(ctx, instr) {
        return true;
    }

    false
}

/// Emulate STUR (SIMD&FP unscaled immediate)
/// Encoding: size[31:30] 111 1 00 opc[23:22]=00 imm9 00 Rn Rt
fn try_emulate_stur_simd(ctx: &mut ExceptionContext, instr: u32) -> bool {
    let bits_29_27 = (instr >> 27) & 0x7;
    let is_simd = ((instr >> 26) & 0x1) == 1;
    let bits_25_24 = (instr >> 24) & 0x3;
    let bits_11_10 = (instr >> 10) & 0x3;

    // Check for SIMD unscaled immediate store
    if bits_29_27 != 0b111 || !is_simd || bits_25_24 != 0b00 || bits_11_10 != 0b00 {
        return false;
    }

    let size = (instr >> 30) & 0x3;
    let opc = (instr >> 22) & 0x3;
    let imm9 = ((instr >> 12) & 0x1FF) as i32;
    let rn = ((instr >> 5) & 0x1F) as usize;
    let rt = (instr & 0x1F) as usize;

    // Determine register size based on size and opc
    let reg_size = match (opc, size) {
        (0b00, 0b00) => 1,  // B register (8-bit)
        (0b00, 0b01) => 2,  // H register (16-bit)
        (0b00, 0b10) => 4,  // S register (32-bit)
        (0b00, 0b11) => 8,  // D register (64-bit)
        (0b10, 0b00) => 16, // Q register (128-bit)
        _ => return false,
    };

    let offset = if (imm9 & 0x100) != 0 {
        (imm9 | !0x1FF) as i64
    } else {
        imm9 as i64
    };

    let base_addr = get_base_addr(ctx, rn);
    let write_addr = (base_addr + offset) as usize;

    let dest = write_addr as *mut u8;
    unsafe {
        match reg_size {
            16 => {
                let q = read_q_register(rt);
                for i in 0..16 { core::ptr::write_volatile(dest.add(i), q[i]); }
            }
            8 => {
                let d = read_d_register(rt);
                for i in 0..8 { core::ptr::write_volatile(dest.add(i), d[i]); }
            }
            4 => {
                let s = read_s_register(rt);
                for i in 0..4 { core::ptr::write_volatile(dest.add(i), s[i]); }
            }
            2 => {
                let h = read_h_register(rt);
                for i in 0..2 { core::ptr::write_volatile(dest.add(i), h[i]); }
            }
            1 => {
                let b = read_b_register(rt);
                core::ptr::write_volatile(dest, b);
            }
            _ => return false,
        }
    }

    ctx.elr += 4;
    true
}

/// Emulate LDUR (SIMD&FP unscaled immediate)
fn try_emulate_ldur_simd(ctx: &mut ExceptionContext, instr: u32) -> bool {
    let bits_29_27 = (instr >> 27) & 0x7;
    let is_simd = ((instr >> 26) & 0x1) == 1;
    let bits_25_24 = (instr >> 24) & 0x3;
    let bits_11_10 = (instr >> 10) & 0x3;

    if bits_29_27 != 0b111 || !is_simd || bits_25_24 != 0b00 || bits_11_10 != 0b00 {
        return false;
    }

    let size = (instr >> 30) & 0x3;
    let opc = (instr >> 22) & 0x3;
    let imm9 = ((instr >> 12) & 0x1FF) as i32;
    let rn = ((instr >> 5) & 0x1F) as usize;
    let rt = (instr & 0x1F) as usize;

    let reg_size = match (opc, size) {
        (0b01, 0b00) => 1,  // B register
        (0b01, 0b01) => 2,  // H register
        (0b01, 0b10) => 4,  // S register
        (0b01, 0b11) => 8,  // D register
        (0b11, 0b00) => 16, // Q register
        _ => return false,
    };

    let offset = if (imm9 & 0x100) != 0 {
        (imm9 | !0x1FF) as i64
    } else {
        imm9 as i64
    };

    let base_addr = get_base_addr(ctx, rn);
    let read_addr = (base_addr + offset) as usize;

    let src = read_addr as *const u8;
    unsafe {
        match reg_size {
            16 => {
                let mut q = [0u8; 16];
                for i in 0..16 { q[i] = core::ptr::read_volatile(src.add(i)); }
                write_q_register(rt, &q);
            }
            8 => {
                let mut d = [0u8; 8];
                for i in 0..8 { d[i] = core::ptr::read_volatile(src.add(i)); }
                write_d_register(rt, &d);
            }
            4 => {
                let mut s = [0u8; 4];
                for i in 0..4 { s[i] = core::ptr::read_volatile(src.add(i)); }
                write_s_register(rt, &s);
            }
            2 => {
                let mut h = [0u8; 2];
                for i in 0..2 { h[i] = core::ptr::read_volatile(src.add(i)); }
                write_h_register(rt, &h);
            }
            1 => {
                let b = core::ptr::read_volatile(src);
                write_b_register(rt, b);
            }
            _ => return false,
        }
    }

    ctx.elr += 4;
    true
}

/// Emulate STR (immediate, unsigned offset) - GPR
/// Encoding: size[31:30] 111 0 01 opc[23:22]=00 imm12[21:10] Rn[9:5] Rt[4:0]
fn try_emulate_str_imm(ctx: &mut ExceptionContext, instr: u32) -> bool {
    // Check encoding pattern: bits[29:24] = 111001 for unsigned immediate
    let bits_29_24 = (instr >> 24) & 0x3F;
    if bits_29_24 != 0b111001 {
        return false;
    }

    // Check opc for STR (not LDR)
    let opc = (instr >> 22) & 0x3;
    if opc != 0b00 {
        return false;  // 00 = STR, 01 = LDR, others = signed loads
    }

    let size = (instr >> 30) & 0x3;
    let imm12 = ((instr >> 10) & 0xFFF) as u64;
    let rn = ((instr >> 5) & 0x1F) as usize;
    let rt = (instr & 0x1F) as usize;

    // Scale factor based on size
    let scale = 1u64 << size;
    let offset = (imm12 * scale) as i64;

    let base_addr = get_base_addr(ctx, rn);
    let write_addr = (base_addr + offset) as usize;

    let value = if rt == 31 { 0u64 } else { ctx.gpr[rt] };

    let dest = write_addr as *mut u8;
    unsafe {
        match size {
            0b00 => {
                // STRB
                core::ptr::write_volatile(dest, value as u8);
            }
            0b01 => {
                // STRH
                let bytes = (value as u16).to_le_bytes();
                for i in 0..2 { core::ptr::write_volatile(dest.add(i), bytes[i]); }
            }
            0b10 => {
                // STR (32-bit)
                let bytes = (value as u32).to_le_bytes();
                for i in 0..4 { core::ptr::write_volatile(dest.add(i), bytes[i]); }
            }
            0b11 => {
                // STR (64-bit)
                let bytes = value.to_le_bytes();
                for i in 0..8 { core::ptr::write_volatile(dest.add(i), bytes[i]); }
            }
            _ => return false,
        }
    }

    ctx.elr += 4;
    true
}

/// Emulate LDR (immediate, unsigned offset) - GPR
fn try_emulate_ldr_imm(ctx: &mut ExceptionContext, instr: u32) -> bool {
    let bits_29_24 = (instr >> 24) & 0x3F;
    if bits_29_24 != 0b111001 {
        return false;
    }

    let opc = (instr >> 22) & 0x3;
    if opc != 0b01 {
        return false;  // 01 = LDR
    }

    let size = (instr >> 30) & 0x3;
    let imm12 = ((instr >> 10) & 0xFFF) as u64;
    let rn = ((instr >> 5) & 0x1F) as usize;
    let rt = (instr & 0x1F) as usize;

    let scale = 1u64 << size;
    let offset = (imm12 * scale) as i64;

    let base_addr = get_base_addr(ctx, rn);
    let read_addr = (base_addr + offset) as usize;

    let src = read_addr as *const u8;
    let value: u64 = unsafe {
        match size {
            0b00 => core::ptr::read_volatile(src) as u64,
            0b01 => {
                let mut bytes = [0u8; 2];
                for i in 0..2 { bytes[i] = core::ptr::read_volatile(src.add(i)); }
                u16::from_le_bytes(bytes) as u64
            }
            0b10 => {
                let mut bytes = [0u8; 4];
                for i in 0..4 { bytes[i] = core::ptr::read_volatile(src.add(i)); }
                u32::from_le_bytes(bytes) as u64
            }
            0b11 => {
                let mut bytes = [0u8; 8];
                for i in 0..8 { bytes[i] = core::ptr::read_volatile(src.add(i)); }
                u64::from_le_bytes(bytes)
            }
            _ => return false,
        }
    };

    if rt != 31 {
        ctx.gpr[rt] = value;
    }

    ctx.elr += 4;
    true
}

/// Emulate STUR (Store Register Unscaled) - W and X registers
/// Encoding: size[31:30] 111 0 00 0 imm9[20:12] 00 Rn[9:5] Rt[4:0]
fn try_emulate_stur(ctx: &mut ExceptionContext, instr: u32) -> bool {
    // Check encoding pattern for STUR (integer)
    // bits[29:21] = 111000000 for STUR/LDUR class
    let bits_29_21 = (instr >> 21) & 0x1FF;
    if bits_29_21 != 0b111000000 {
        return false;
    }

    // bits[11:10] = 00 for unscaled immediate
    let bits_11_10 = (instr >> 10) & 0x3;
    if bits_11_10 != 0b00 {
        return false;
    }

    let size = (instr >> 30) & 0x3;
    let imm9 = ((instr >> 12) & 0x1FF) as i32;
    let rn = ((instr >> 5) & 0x1F) as usize;
    let rt = (instr & 0x1F) as usize;

    // Sign-extend imm9
    let offset = if (imm9 & 0x100) != 0 {
        (imm9 | !0x1FF) as i64
    } else {
        imm9 as i64
    };

    let base_addr = get_base_addr(ctx, rn);
    let write_addr = (base_addr + offset) as usize;

    // Get register value (use XZR for register 31)
    let value = if rt == 31 { 0u64 } else { ctx.gpr[rt] };

    let dest = write_addr as *mut u8;
    unsafe {
        match size {
            0b00 => {
                // STURB - 8-bit
                core::ptr::write_volatile(dest, value as u8);
            }
            0b01 => {
                // STURH - 16-bit
                let bytes = (value as u16).to_le_bytes();
                for i in 0..2 {
                    core::ptr::write_volatile(dest.add(i), bytes[i]);
                }
            }
            0b10 => {
                // STUR (32-bit)
                let bytes = (value as u32).to_le_bytes();
                for i in 0..4 {
                    core::ptr::write_volatile(dest.add(i), bytes[i]);
                }
            }
            0b11 => {
                // STUR (64-bit)
                let bytes = value.to_le_bytes();
                for i in 0..8 {
                    core::ptr::write_volatile(dest.add(i), bytes[i]);
                }
            }
            _ => return false,
        }
    }

    ctx.elr += 4;
    true
}

/// Emulate LDUR (Load Register Unscaled) - W and X registers
fn try_emulate_ldur(ctx: &mut ExceptionContext, instr: u32) -> bool {
    // Check encoding pattern for LDUR
    let bits_29_21 = (instr >> 21) & 0x1FF;
    if bits_29_21 != 0b111000010 {
        return false;
    }

    let bits_11_10 = (instr >> 10) & 0x3;
    if bits_11_10 != 0b00 {
        return false;
    }

    let size = (instr >> 30) & 0x3;
    let imm9 = ((instr >> 12) & 0x1FF) as i32;
    let rn = ((instr >> 5) & 0x1F) as usize;
    let rt = (instr & 0x1F) as usize;

    let offset = if (imm9 & 0x100) != 0 {
        (imm9 | !0x1FF) as i64
    } else {
        imm9 as i64
    };

    let base_addr = get_base_addr(ctx, rn);
    let read_addr = (base_addr + offset) as usize;

    let src = read_addr as *const u8;
    let value: u64 = unsafe {
        match size {
            0b00 => {
                // LDURB
                core::ptr::read_volatile(src) as u64
            }
            0b01 => {
                // LDURH
                let mut bytes = [0u8; 2];
                for i in 0..2 {
                    bytes[i] = core::ptr::read_volatile(src.add(i));
                }
                u16::from_le_bytes(bytes) as u64
            }
            0b10 => {
                // LDUR (32-bit)
                let mut bytes = [0u8; 4];
                for i in 0..4 {
                    bytes[i] = core::ptr::read_volatile(src.add(i));
                }
                u32::from_le_bytes(bytes) as u64
            }
            0b11 => {
                // LDUR (64-bit)
                let mut bytes = [0u8; 8];
                for i in 0..8 {
                    bytes[i] = core::ptr::read_volatile(src.add(i));
                }
                u64::from_le_bytes(bytes)
            }
            _ => return false,
        }
    };

    // Write to register (except XZR)
    if rt != 31 {
        ctx.gpr[rt] = value;
    }

    ctx.elr += 4;
    true
}

/// Emulate STR pre/post indexed (GPR)
fn try_emulate_str_pre_post(ctx: &mut ExceptionContext, instr: u32) -> bool {
    // STR (pre-indexed/post-indexed): size 111 0 00 0 imm9 01/11 Rn Rt
    let bits_29_21 = (instr >> 21) & 0x1FF;
    if bits_29_21 != 0b111000000 {
        return false;
    }

    let bits_11_10 = (instr >> 10) & 0x3;
    let is_pre_index = bits_11_10 == 0b11;
    let is_post_index = bits_11_10 == 0b01;
    if !is_pre_index && !is_post_index {
        return false;
    }

    let size = (instr >> 30) & 0x3;
    let imm9 = ((instr >> 12) & 0x1FF) as i32;
    let rn = ((instr >> 5) & 0x1F) as usize;
    let rt = (instr & 0x1F) as usize;

    let offset = if (imm9 & 0x100) != 0 {
        (imm9 | !0x1FF) as i64
    } else {
        imm9 as i64
    };

    let base_addr = get_base_addr(ctx, rn);
    let write_addr = if is_post_index {
        base_addr as usize
    } else {
        (base_addr + offset) as usize
    };

    let value = if rt == 31 { 0u64 } else { ctx.gpr[rt] };

    let dest = write_addr as *mut u8;
    unsafe {
        match size {
            0b00 => { core::ptr::write_volatile(dest, value as u8); }
            0b01 => {
                let bytes = (value as u16).to_le_bytes();
                for i in 0..2 { core::ptr::write_volatile(dest.add(i), bytes[i]); }
            }
            0b10 => {
                let bytes = (value as u32).to_le_bytes();
                for i in 0..4 { core::ptr::write_volatile(dest.add(i), bytes[i]); }
            }
            0b11 => {
                let bytes = value.to_le_bytes();
                for i in 0..8 { core::ptr::write_volatile(dest.add(i), bytes[i]); }
            }
            _ => return false,
        }
    }

    // Writeback
    set_base_addr(ctx, rn, base_addr + offset);

    ctx.elr += 4;
    true
}

/// Emulate LDR pre/post indexed (GPR)
fn try_emulate_ldr_pre_post(ctx: &mut ExceptionContext, instr: u32) -> bool {
    let bits_29_21 = (instr >> 21) & 0x1FF;
    if bits_29_21 != 0b111000010 {
        return false;
    }

    let bits_11_10 = (instr >> 10) & 0x3;
    let is_pre_index = bits_11_10 == 0b11;
    let is_post_index = bits_11_10 == 0b01;
    if !is_pre_index && !is_post_index {
        return false;
    }

    let size = (instr >> 30) & 0x3;
    let imm9 = ((instr >> 12) & 0x1FF) as i32;
    let rn = ((instr >> 5) & 0x1F) as usize;
    let rt = (instr & 0x1F) as usize;

    let offset = if (imm9 & 0x100) != 0 {
        (imm9 | !0x1FF) as i64
    } else {
        imm9 as i64
    };

    let base_addr = get_base_addr(ctx, rn);
    let read_addr = if is_post_index {
        base_addr as usize
    } else {
        (base_addr + offset) as usize
    };

    let src = read_addr as *const u8;
    let value: u64 = unsafe {
        match size {
            0b00 => core::ptr::read_volatile(src) as u64,
            0b01 => {
                let mut bytes = [0u8; 2];
                for i in 0..2 { bytes[i] = core::ptr::read_volatile(src.add(i)); }
                u16::from_le_bytes(bytes) as u64
            }
            0b10 => {
                let mut bytes = [0u8; 4];
                for i in 0..4 { bytes[i] = core::ptr::read_volatile(src.add(i)); }
                u32::from_le_bytes(bytes) as u64
            }
            0b11 => {
                let mut bytes = [0u8; 8];
                for i in 0..8 { bytes[i] = core::ptr::read_volatile(src.add(i)); }
                u64::from_le_bytes(bytes)
            }
            _ => return false,
        }
    };

    if rt != 31 {
        ctx.gpr[rt] = value;
    }

    // Writeback
    set_base_addr(ctx, rn, base_addr + offset);

    ctx.elr += 4;
    true
}

/// Emulate STP (GPR store pair)
fn try_emulate_stp_gpr(ctx: &mut ExceptionContext, instr: u32) -> bool {
    // STP (GPR): opc[31:30] 101 0 L[22] imm7 Rt2 Rn Rt
    let bits_29_27 = (instr >> 27) & 0x7;
    let is_simd = ((instr >> 26) & 0x1) == 1;
    let is_load = ((instr >> 22) & 0x1) == 1;

    if bits_29_27 != 0b101 || is_simd || is_load {
        return false;
    }

    let opc = (instr >> 30) & 0x3;
    let addressing_mode = (instr >> 23) & 0x3;
    let imm7 = ((instr >> 15) & 0x7F) as i32;
    let rt2 = ((instr >> 10) & 0x1F) as usize;
    let rn = ((instr >> 5) & 0x1F) as usize;
    let rt = (instr & 0x1F) as usize;

    let (reg_size, scale) = match opc {
        0b00 => (4, 4),   // W registers
        0b10 => (8, 8),   // X registers
        _ => return false,
    };

    let offset = if (imm7 & 0x40) != 0 {
        ((imm7 | !0x7F) * scale) as i64
    } else {
        (imm7 * scale) as i64
    };

    let base_addr = get_base_addr(ctx, rn);
    let (write_addr, writeback_addr) = match addressing_mode {
        0b01 => (base_addr, base_addr + offset),
        0b10 => (base_addr + offset, base_addr),
        0b11 => (base_addr + offset, base_addr + offset),
        _ => return false,
    };

    let val1 = if rt == 31 { 0u64 } else { ctx.gpr[rt] };
    let val2 = if rt2 == 31 { 0u64 } else { ctx.gpr[rt2] };

    let dest = write_addr as usize as *mut u8;
    unsafe {
        match reg_size {
            4 => {
                let bytes1 = (val1 as u32).to_le_bytes();
                let bytes2 = (val2 as u32).to_le_bytes();
                for i in 0..4 { core::ptr::write_volatile(dest.add(i), bytes1[i]); }
                for i in 0..4 { core::ptr::write_volatile(dest.add(4 + i), bytes2[i]); }
            }
            8 => {
                let bytes1 = val1.to_le_bytes();
                let bytes2 = val2.to_le_bytes();
                for i in 0..8 { core::ptr::write_volatile(dest.add(i), bytes1[i]); }
                for i in 0..8 { core::ptr::write_volatile(dest.add(8 + i), bytes2[i]); }
            }
            _ => return false,
        }
    }

    if addressing_mode == 0b01 || addressing_mode == 0b11 {
        set_base_addr(ctx, rn, writeback_addr);
    }

    ctx.elr += 4;
    true
}

/// Emulate LDP (GPR load pair)
fn try_emulate_ldp_gpr(ctx: &mut ExceptionContext, instr: u32) -> bool {
    let bits_29_27 = (instr >> 27) & 0x7;
    let is_simd = ((instr >> 26) & 0x1) == 1;
    let is_load = ((instr >> 22) & 0x1) == 1;

    if bits_29_27 != 0b101 || is_simd || !is_load {
        return false;
    }

    let opc = (instr >> 30) & 0x3;
    let addressing_mode = (instr >> 23) & 0x3;
    let imm7 = ((instr >> 15) & 0x7F) as i32;
    let rt2 = ((instr >> 10) & 0x1F) as usize;
    let rn = ((instr >> 5) & 0x1F) as usize;
    let rt = (instr & 0x1F) as usize;

    let (reg_size, scale) = match opc {
        0b00 => (4, 4),
        0b10 => (8, 8),
        _ => return false,
    };

    let offset = if (imm7 & 0x40) != 0 {
        ((imm7 | !0x7F) * scale) as i64
    } else {
        (imm7 * scale) as i64
    };

    let base_addr = get_base_addr(ctx, rn);
    let (read_addr, writeback_addr) = match addressing_mode {
        0b01 => (base_addr, base_addr + offset),
        0b10 => (base_addr + offset, base_addr),
        0b11 => (base_addr + offset, base_addr + offset),
        _ => return false,
    };

    let src = read_addr as usize as *const u8;
    let (val1, val2): (u64, u64) = unsafe {
        match reg_size {
            4 => {
                let mut bytes1 = [0u8; 4];
                let mut bytes2 = [0u8; 4];
                for i in 0..4 { bytes1[i] = core::ptr::read_volatile(src.add(i)); }
                for i in 0..4 { bytes2[i] = core::ptr::read_volatile(src.add(4 + i)); }
                (u32::from_le_bytes(bytes1) as u64, u32::from_le_bytes(bytes2) as u64)
            }
            8 => {
                let mut bytes1 = [0u8; 8];
                let mut bytes2 = [0u8; 8];
                for i in 0..8 { bytes1[i] = core::ptr::read_volatile(src.add(i)); }
                for i in 0..8 { bytes2[i] = core::ptr::read_volatile(src.add(8 + i)); }
                (u64::from_le_bytes(bytes1), u64::from_le_bytes(bytes2))
            }
            _ => return false,
        }
    };

    if rt != 31 { ctx.gpr[rt] = val1; }
    if rt2 != 31 { ctx.gpr[rt2] = val2; }

    if addressing_mode == 0b01 || addressing_mode == 0b11 {
        set_base_addr(ctx, rn, writeback_addr);
    }

    ctx.elr += 4;
    true
}

/// Get base address from register (handles SP specially)
fn get_base_addr(ctx: &ExceptionContext, rn: usize) -> i64 {
    if rn == 31 {
        ctx.sp as i64
    } else {
        ctx.gpr[rn] as i64
    }
}

/// Set base address register (handles SP specially)
fn set_base_addr(ctx: &mut ExceptionContext, rn: usize, val: i64) {
    if rn == 31 {
        ctx.sp = val as u64;
    } else {
        ctx.gpr[rn] = val as u64;
    }
}

/// Emulate STP (SIMD store pair) - Q and D registers
fn try_emulate_stp_simd(ctx: &mut ExceptionContext, instr: u32) -> bool {
    // STP (SIMD&FP): opc[31:30] 101 V[26]=1 L[22]=0
    let opc = (instr >> 30) & 0x3;
    let is_ldst_pair = ((instr >> 27) & 0x7) == 0b101;
    let is_simd = ((instr >> 26) & 0x1) == 1;
    let is_load = ((instr >> 22) & 0x1) == 1;

    if !is_ldst_pair || !is_simd || is_load {
        return false;
    }

    let rt = (instr & 0x1F) as usize;
    let rn = ((instr >> 5) & 0x1F) as usize;
    let rt2 = ((instr >> 10) & 0x1F) as usize;
    let imm7 = ((instr >> 15) & 0x7F) as i32;
    let addressing_mode = (instr >> 23) & 0x3;

    // Determine register size and scale based on opc
    let (reg_size, scale) = match opc {
        0b00 => (4, 4),   // S registers (32-bit)
        0b01 => (8, 8),   // D registers (64-bit)
        0b10 => (16, 16), // Q registers (128-bit)
        _ => return false,
    };

    // Sign-extend imm7 and scale
    let offset = if (imm7 & 0x40) != 0 {
        ((imm7 | !0x7F) * scale) as i64
    } else {
        (imm7 * scale) as i64
    };

    let base_addr = get_base_addr(ctx, rn);
    let (write_addr, writeback_addr) = match addressing_mode {
        0b01 => (base_addr, base_addr + offset),         // Post-indexed
        0b10 => (base_addr + offset, base_addr),         // Signed offset
        0b11 => (base_addr + offset, base_addr + offset), // Pre-indexed
        _ => return false,
    };

    let dest = write_addr as usize as *mut u8;
    unsafe {
        match reg_size {
            16 => {
                let q1 = read_q_register(rt);
                let q2 = read_q_register(rt2);
                for i in 0..16 { core::ptr::write_volatile(dest.add(i), q1[i]); }
                for i in 0..16 { core::ptr::write_volatile(dest.add(16 + i), q2[i]); }
            }
            8 => {
                let d1 = read_d_register(rt);
                let d2 = read_d_register(rt2);
                for i in 0..8 { core::ptr::write_volatile(dest.add(i), d1[i]); }
                for i in 0..8 { core::ptr::write_volatile(dest.add(8 + i), d2[i]); }
            }
            4 => {
                let s1 = read_s_register(rt);
                let s2 = read_s_register(rt2);
                for i in 0..4 { core::ptr::write_volatile(dest.add(i), s1[i]); }
                for i in 0..4 { core::ptr::write_volatile(dest.add(4 + i), s2[i]); }
            }
            _ => return false,
        }
    }

    if addressing_mode == 0b01 || addressing_mode == 0b11 {
        set_base_addr(ctx, rn, writeback_addr);
    }

    ctx.elr += 4;
    true
}

/// Emulate LDP (SIMD load pair) - Q and D registers
fn try_emulate_ldp_simd(ctx: &mut ExceptionContext, instr: u32) -> bool {
    // LDP (SIMD&FP): opc[31:30] 101 V[26]=1 L[22]=1
    let opc = (instr >> 30) & 0x3;
    let is_ldst_pair = ((instr >> 27) & 0x7) == 0b101;
    let is_simd = ((instr >> 26) & 0x1) == 1;
    let is_load = ((instr >> 22) & 0x1) == 1;

    if !is_ldst_pair || !is_simd || !is_load {
        return false;
    }

    let rt = (instr & 0x1F) as usize;
    let rn = ((instr >> 5) & 0x1F) as usize;
    let rt2 = ((instr >> 10) & 0x1F) as usize;
    let imm7 = ((instr >> 15) & 0x7F) as i32;
    let addressing_mode = (instr >> 23) & 0x3;

    let (reg_size, scale) = match opc {
        0b00 => (4, 4),   // S registers
        0b01 => (8, 8),   // D registers
        0b10 => (16, 16), // Q registers
        _ => return false,
    };

    let offset = if (imm7 & 0x40) != 0 {
        ((imm7 | !0x7F) * scale) as i64
    } else {
        (imm7 * scale) as i64
    };

    let base_addr = get_base_addr(ctx, rn);
    let (read_addr, writeback_addr) = match addressing_mode {
        0b01 => (base_addr, base_addr + offset),
        0b10 => (base_addr + offset, base_addr),
        0b11 => (base_addr + offset, base_addr + offset),
        _ => return false,
    };

    let src = read_addr as usize as *const u8;
    unsafe {
        match reg_size {
            16 => {
                let mut q1 = [0u8; 16];
                let mut q2 = [0u8; 16];
                for i in 0..16 { q1[i] = core::ptr::read_volatile(src.add(i)); }
                for i in 0..16 { q2[i] = core::ptr::read_volatile(src.add(16 + i)); }
                write_q_register(rt, &q1);
                write_q_register(rt2, &q2);
            }
            8 => {
                let mut d1 = [0u8; 8];
                let mut d2 = [0u8; 8];
                for i in 0..8 { d1[i] = core::ptr::read_volatile(src.add(i)); }
                for i in 0..8 { d2[i] = core::ptr::read_volatile(src.add(8 + i)); }
                write_d_register(rt, &d1);
                write_d_register(rt2, &d2);
            }
            4 => {
                let mut s1 = [0u8; 4];
                let mut s2 = [0u8; 4];
                for i in 0..4 { s1[i] = core::ptr::read_volatile(src.add(i)); }
                for i in 0..4 { s2[i] = core::ptr::read_volatile(src.add(4 + i)); }
                write_s_register(rt, &s1);
                write_s_register(rt2, &s2);
            }
            _ => return false,
        }
    }

    if addressing_mode == 0b01 || addressing_mode == 0b11 {
        set_base_addr(ctx, rn, writeback_addr);
    }

    ctx.elr += 4;
    true
}

/// Emulate STR (SIMD store, unsigned immediate offset)
fn try_emulate_str_simd_imm(ctx: &mut ExceptionContext, instr: u32) -> bool {
    // STR (immediate, SIMD&FP): size[31:30] 111 V[26]=1 01 opc[23:22] imm12 Rn Rt
    let bits_29_27 = (instr >> 27) & 0x7;
    let is_simd = ((instr >> 26) & 0x1) == 1;
    let bits_25_24 = (instr >> 24) & 0x3;

    if bits_29_27 != 0b111 || !is_simd || bits_25_24 != 0b01 {
        return false;
    }

    let size = (instr >> 30) & 0x3;
    let opc = (instr >> 22) & 0x3;
    let imm12 = ((instr >> 10) & 0xFFF) as u64;
    let rn = ((instr >> 5) & 0x1F) as usize;
    let rt = (instr & 0x1F) as usize;

    // Determine register size: size + opc[1] determines width
    // For STR: opc=00 (8/16/32/64-bit based on size), opc=10 (128-bit Q)
    let reg_size = match (opc, size) {
        (0b00, 0b00) => 1,  // B register
        (0b00, 0b01) => 2,  // H register
        (0b00, 0b10) => 4,  // S register
        (0b00, 0b11) => 8,  // D register
        (0b10, 0b00) => 16, // Q register
        _ => return false,  // LDR or invalid
    };

    let offset = (imm12 * reg_size as u64) as i64;
    let base_addr = get_base_addr(ctx, rn);
    let write_addr = (base_addr + offset) as usize;

    let dest = write_addr as *mut u8;
    unsafe {
        match reg_size {
            16 => {
                let q = read_q_register(rt);
                for i in 0..16 { core::ptr::write_volatile(dest.add(i), q[i]); }
            }
            8 => {
                let d = read_d_register(rt);
                for i in 0..8 { core::ptr::write_volatile(dest.add(i), d[i]); }
            }
            4 => {
                let s = read_s_register(rt);
                for i in 0..4 { core::ptr::write_volatile(dest.add(i), s[i]); }
            }
            2 => {
                let h = read_h_register(rt);
                for i in 0..2 { core::ptr::write_volatile(dest.add(i), h[i]); }
            }
            1 => {
                let b = read_b_register(rt);
                core::ptr::write_volatile(dest, b);
            }
            _ => return false,
        }
    }

    ctx.elr += 4;
    true
}

/// Emulate LDR (SIMD load, unsigned immediate offset)
fn try_emulate_ldr_simd_imm(ctx: &mut ExceptionContext, instr: u32) -> bool {
    // LDR (immediate, SIMD&FP): size[31:30] 111 V[26]=1 01 opc[23:22] imm12 Rn Rt
    let bits_29_27 = (instr >> 27) & 0x7;
    let is_simd = ((instr >> 26) & 0x1) == 1;
    let bits_25_24 = (instr >> 24) & 0x3;

    if bits_29_27 != 0b111 || !is_simd || bits_25_24 != 0b01 {
        return false;
    }

    let size = (instr >> 30) & 0x3;
    let opc = (instr >> 22) & 0x3;
    let imm12 = ((instr >> 10) & 0xFFF) as u64;
    let rn = ((instr >> 5) & 0x1F) as usize;
    let rt = (instr & 0x1F) as usize;

    // For LDR: opc=01 (8/16/32/64-bit based on size), opc=11 (128-bit Q)
    let reg_size = match (opc, size) {
        (0b01, 0b00) => 1,  // B register
        (0b01, 0b01) => 2,  // H register
        (0b01, 0b10) => 4,  // S register
        (0b01, 0b11) => 8,  // D register
        (0b11, 0b00) => 16, // Q register
        _ => return false,
    };

    let offset = (imm12 * reg_size as u64) as i64;
    let base_addr = get_base_addr(ctx, rn);
    let read_addr = (base_addr + offset) as usize;

    let src = read_addr as *const u8;
    unsafe {
        match reg_size {
            16 => {
                let mut q = [0u8; 16];
                for i in 0..16 { q[i] = core::ptr::read_volatile(src.add(i)); }
                write_q_register(rt, &q);
            }
            8 => {
                let mut d = [0u8; 8];
                for i in 0..8 { d[i] = core::ptr::read_volatile(src.add(i)); }
                write_d_register(rt, &d);
            }
            4 => {
                let mut s = [0u8; 4];
                for i in 0..4 { s[i] = core::ptr::read_volatile(src.add(i)); }
                write_s_register(rt, &s);
            }
            2 => {
                let mut h = [0u8; 2];
                for i in 0..2 { h[i] = core::ptr::read_volatile(src.add(i)); }
                write_h_register(rt, &h);
            }
            1 => {
                let b = core::ptr::read_volatile(src);
                write_b_register(rt, b);
            }
            _ => return false,
        }
    }

    ctx.elr += 4;
    true
}

/// Emulate STR (SIMD store, register offset)
fn try_emulate_str_simd_reg(ctx: &mut ExceptionContext, instr: u32) -> bool {
    // STR (register, SIMD&FP): size[31:30] 111 V[26]=1 00 opc[23:22] 1 Rm option S 10 Rn Rt
    let bits_29_27 = (instr >> 27) & 0x7;
    let is_simd = ((instr >> 26) & 0x1) == 1;
    let bits_25_24 = (instr >> 24) & 0x3;
    let bits_11_10 = (instr >> 10) & 0x3;

    if bits_29_27 != 0b111 || !is_simd || bits_25_24 != 0b00 || bits_11_10 != 0b10 {
        return false;
    }

    let size = (instr >> 30) & 0x3;
    let opc = (instr >> 22) & 0x3;
    let rm = ((instr >> 16) & 0x1F) as usize;
    let option = ((instr >> 13) & 0x7) as u32;
    let s = ((instr >> 12) & 0x1) != 0;
    let rn = ((instr >> 5) & 0x1F) as usize;
    let rt = (instr & 0x1F) as usize;

    // For STR: opc=00 or opc=10
    let reg_size = match (opc, size) {
        (0b00, 0b00) => 1,
        (0b00, 0b01) => 2,
        (0b00, 0b10) => 4,
        (0b00, 0b11) => 8,
        (0b10, 0b00) => 16,
        _ => return false,
    };

    let base_addr = get_base_addr(ctx, rn);
    let mut offset = ctx.gpr[rm] as i64;

    // Handle extend options
    offset = match option {
        0b010 => (offset as u32) as i64,         // UXTW
        0b011 => offset,                          // LSL (or UXTX)
        0b110 => (offset as i32) as i64,         // SXTW
        0b111 => offset,                          // SXTX
        _ => return false,
    };

    // Handle shift
    if s {
        let shift = match reg_size {
            1 => 0, 2 => 1, 4 => 2, 8 => 3, 16 => 4,
            _ => return false,
        };
        offset <<= shift;
    }

    let write_addr = (base_addr + offset) as usize;
    let dest = write_addr as *mut u8;

    unsafe {
        match reg_size {
            16 => { let q = read_q_register(rt); for i in 0..16 { core::ptr::write_volatile(dest.add(i), q[i]); } }
            8 => { let d = read_d_register(rt); for i in 0..8 { core::ptr::write_volatile(dest.add(i), d[i]); } }
            4 => { let s = read_s_register(rt); for i in 0..4 { core::ptr::write_volatile(dest.add(i), s[i]); } }
            2 => { let h = read_h_register(rt); for i in 0..2 { core::ptr::write_volatile(dest.add(i), h[i]); } }
            1 => { let b = read_b_register(rt); core::ptr::write_volatile(dest, b); }
            _ => return false,
        }
    }

    ctx.elr += 4;
    true
}

/// Emulate LDR (SIMD load, register offset)
fn try_emulate_ldr_simd_reg(ctx: &mut ExceptionContext, instr: u32) -> bool {
    let bits_29_27 = (instr >> 27) & 0x7;
    let is_simd = ((instr >> 26) & 0x1) == 1;
    let bits_25_24 = (instr >> 24) & 0x3;
    let bits_11_10 = (instr >> 10) & 0x3;

    if bits_29_27 != 0b111 || !is_simd || bits_25_24 != 0b00 || bits_11_10 != 0b10 {
        return false;
    }

    let size = (instr >> 30) & 0x3;
    let opc = (instr >> 22) & 0x3;
    let rm = ((instr >> 16) & 0x1F) as usize;
    let option = ((instr >> 13) & 0x7) as u32;
    let s = ((instr >> 12) & 0x1) != 0;
    let rn = ((instr >> 5) & 0x1F) as usize;
    let rt = (instr & 0x1F) as usize;

    // For LDR: opc=01 or opc=11
    let reg_size = match (opc, size) {
        (0b01, 0b00) => 1,
        (0b01, 0b01) => 2,
        (0b01, 0b10) => 4,
        (0b01, 0b11) => 8,
        (0b11, 0b00) => 16,
        _ => return false,
    };

    let base_addr = get_base_addr(ctx, rn);
    let mut offset = ctx.gpr[rm] as i64;

    offset = match option {
        0b010 => (offset as u32) as i64,
        0b011 => offset,
        0b110 => (offset as i32) as i64,
        0b111 => offset,
        _ => return false,
    };

    if s {
        let shift = match reg_size {
            1 => 0, 2 => 1, 4 => 2, 8 => 3, 16 => 4,
            _ => return false,
        };
        offset <<= shift;
    }

    let read_addr = (base_addr + offset) as usize;
    let src = read_addr as *const u8;

    unsafe {
        match reg_size {
            16 => { let mut q = [0u8; 16]; for i in 0..16 { q[i] = core::ptr::read_volatile(src.add(i)); } write_q_register(rt, &q); }
            8 => { let mut d = [0u8; 8]; for i in 0..8 { d[i] = core::ptr::read_volatile(src.add(i)); } write_d_register(rt, &d); }
            4 => { let mut s = [0u8; 4]; for i in 0..4 { s[i] = core::ptr::read_volatile(src.add(i)); } write_s_register(rt, &s); }
            2 => { let mut h = [0u8; 2]; for i in 0..2 { h[i] = core::ptr::read_volatile(src.add(i)); } write_h_register(rt, &h); }
            1 => { let b = core::ptr::read_volatile(src); write_b_register(rt, b); }
            _ => return false,
        }
    }

    ctx.elr += 4;
    true
}

/// Read a Q register (128-bit SIMD register) and return as byte array
fn read_q_register(reg: usize) -> [u8; 16] {
    let mut result = [0u8; 16];

    // Read the Q register using assembly
    // We use a match to generate specific code for each register
    unsafe {
        match reg {
            0 => core::arch::asm!("str q0, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            1 => core::arch::asm!("str q1, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            2 => core::arch::asm!("str q2, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            3 => core::arch::asm!("str q3, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            4 => core::arch::asm!("str q4, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            5 => core::arch::asm!("str q5, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            6 => core::arch::asm!("str q6, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            7 => core::arch::asm!("str q7, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            8 => core::arch::asm!("str q8, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            9 => core::arch::asm!("str q9, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            10 => core::arch::asm!("str q10, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            11 => core::arch::asm!("str q11, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            12 => core::arch::asm!("str q12, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            13 => core::arch::asm!("str q13, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            14 => core::arch::asm!("str q14, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            15 => core::arch::asm!("str q15, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            16 => core::arch::asm!("str q16, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            17 => core::arch::asm!("str q17, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            18 => core::arch::asm!("str q18, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            19 => core::arch::asm!("str q19, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            20 => core::arch::asm!("str q20, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            21 => core::arch::asm!("str q21, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            22 => core::arch::asm!("str q22, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            23 => core::arch::asm!("str q23, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            24 => core::arch::asm!("str q24, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            25 => core::arch::asm!("str q25, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            26 => core::arch::asm!("str q26, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            27 => core::arch::asm!("str q27, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            28 => core::arch::asm!("str q28, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            29 => core::arch::asm!("str q29, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            30 => core::arch::asm!("str q30, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            31 => core::arch::asm!("str q31, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            _ => {} // Invalid register, return zeros
        }
    }

    result
}

/// Write a Q register (128-bit SIMD register) from byte array
fn write_q_register(reg: usize, data: &[u8; 16]) {
    unsafe {
        match reg {
            0 => core::arch::asm!("ldr q0, [{ptr}]", ptr = in(reg) data.as_ptr()),
            1 => core::arch::asm!("ldr q1, [{ptr}]", ptr = in(reg) data.as_ptr()),
            2 => core::arch::asm!("ldr q2, [{ptr}]", ptr = in(reg) data.as_ptr()),
            3 => core::arch::asm!("ldr q3, [{ptr}]", ptr = in(reg) data.as_ptr()),
            4 => core::arch::asm!("ldr q4, [{ptr}]", ptr = in(reg) data.as_ptr()),
            5 => core::arch::asm!("ldr q5, [{ptr}]", ptr = in(reg) data.as_ptr()),
            6 => core::arch::asm!("ldr q6, [{ptr}]", ptr = in(reg) data.as_ptr()),
            7 => core::arch::asm!("ldr q7, [{ptr}]", ptr = in(reg) data.as_ptr()),
            8 => core::arch::asm!("ldr q8, [{ptr}]", ptr = in(reg) data.as_ptr()),
            9 => core::arch::asm!("ldr q9, [{ptr}]", ptr = in(reg) data.as_ptr()),
            10 => core::arch::asm!("ldr q10, [{ptr}]", ptr = in(reg) data.as_ptr()),
            11 => core::arch::asm!("ldr q11, [{ptr}]", ptr = in(reg) data.as_ptr()),
            12 => core::arch::asm!("ldr q12, [{ptr}]", ptr = in(reg) data.as_ptr()),
            13 => core::arch::asm!("ldr q13, [{ptr}]", ptr = in(reg) data.as_ptr()),
            14 => core::arch::asm!("ldr q14, [{ptr}]", ptr = in(reg) data.as_ptr()),
            15 => core::arch::asm!("ldr q15, [{ptr}]", ptr = in(reg) data.as_ptr()),
            16 => core::arch::asm!("ldr q16, [{ptr}]", ptr = in(reg) data.as_ptr()),
            17 => core::arch::asm!("ldr q17, [{ptr}]", ptr = in(reg) data.as_ptr()),
            18 => core::arch::asm!("ldr q18, [{ptr}]", ptr = in(reg) data.as_ptr()),
            19 => core::arch::asm!("ldr q19, [{ptr}]", ptr = in(reg) data.as_ptr()),
            20 => core::arch::asm!("ldr q20, [{ptr}]", ptr = in(reg) data.as_ptr()),
            21 => core::arch::asm!("ldr q21, [{ptr}]", ptr = in(reg) data.as_ptr()),
            22 => core::arch::asm!("ldr q22, [{ptr}]", ptr = in(reg) data.as_ptr()),
            23 => core::arch::asm!("ldr q23, [{ptr}]", ptr = in(reg) data.as_ptr()),
            24 => core::arch::asm!("ldr q24, [{ptr}]", ptr = in(reg) data.as_ptr()),
            25 => core::arch::asm!("ldr q25, [{ptr}]", ptr = in(reg) data.as_ptr()),
            26 => core::arch::asm!("ldr q26, [{ptr}]", ptr = in(reg) data.as_ptr()),
            27 => core::arch::asm!("ldr q27, [{ptr}]", ptr = in(reg) data.as_ptr()),
            28 => core::arch::asm!("ldr q28, [{ptr}]", ptr = in(reg) data.as_ptr()),
            29 => core::arch::asm!("ldr q29, [{ptr}]", ptr = in(reg) data.as_ptr()),
            30 => core::arch::asm!("ldr q30, [{ptr}]", ptr = in(reg) data.as_ptr()),
            31 => core::arch::asm!("ldr q31, [{ptr}]", ptr = in(reg) data.as_ptr()),
            _ => {}
        }
    }
}

/// Read a D register (64-bit SIMD register) and return as byte array
fn read_d_register(reg: usize) -> [u8; 8] {
    let mut result = [0u8; 8];
    unsafe {
        match reg {
            0 => core::arch::asm!("str d0, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            1 => core::arch::asm!("str d1, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            2 => core::arch::asm!("str d2, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            3 => core::arch::asm!("str d3, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            4 => core::arch::asm!("str d4, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            5 => core::arch::asm!("str d5, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            6 => core::arch::asm!("str d6, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            7 => core::arch::asm!("str d7, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            8 => core::arch::asm!("str d8, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            9 => core::arch::asm!("str d9, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            10 => core::arch::asm!("str d10, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            11 => core::arch::asm!("str d11, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            12 => core::arch::asm!("str d12, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            13 => core::arch::asm!("str d13, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            14 => core::arch::asm!("str d14, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            15 => core::arch::asm!("str d15, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            16 => core::arch::asm!("str d16, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            17 => core::arch::asm!("str d17, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            18 => core::arch::asm!("str d18, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            19 => core::arch::asm!("str d19, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            20 => core::arch::asm!("str d20, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            21 => core::arch::asm!("str d21, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            22 => core::arch::asm!("str d22, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            23 => core::arch::asm!("str d23, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            24 => core::arch::asm!("str d24, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            25 => core::arch::asm!("str d25, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            26 => core::arch::asm!("str d26, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            27 => core::arch::asm!("str d27, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            28 => core::arch::asm!("str d28, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            29 => core::arch::asm!("str d29, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            30 => core::arch::asm!("str d30, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            31 => core::arch::asm!("str d31, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            _ => {}
        }
    }
    result
}

/// Write a D register (64-bit SIMD register) from byte array
fn write_d_register(reg: usize, data: &[u8; 8]) {
    unsafe {
        match reg {
            0 => core::arch::asm!("ldr d0, [{ptr}]", ptr = in(reg) data.as_ptr()),
            1 => core::arch::asm!("ldr d1, [{ptr}]", ptr = in(reg) data.as_ptr()),
            2 => core::arch::asm!("ldr d2, [{ptr}]", ptr = in(reg) data.as_ptr()),
            3 => core::arch::asm!("ldr d3, [{ptr}]", ptr = in(reg) data.as_ptr()),
            4 => core::arch::asm!("ldr d4, [{ptr}]", ptr = in(reg) data.as_ptr()),
            5 => core::arch::asm!("ldr d5, [{ptr}]", ptr = in(reg) data.as_ptr()),
            6 => core::arch::asm!("ldr d6, [{ptr}]", ptr = in(reg) data.as_ptr()),
            7 => core::arch::asm!("ldr d7, [{ptr}]", ptr = in(reg) data.as_ptr()),
            8 => core::arch::asm!("ldr d8, [{ptr}]", ptr = in(reg) data.as_ptr()),
            9 => core::arch::asm!("ldr d9, [{ptr}]", ptr = in(reg) data.as_ptr()),
            10 => core::arch::asm!("ldr d10, [{ptr}]", ptr = in(reg) data.as_ptr()),
            11 => core::arch::asm!("ldr d11, [{ptr}]", ptr = in(reg) data.as_ptr()),
            12 => core::arch::asm!("ldr d12, [{ptr}]", ptr = in(reg) data.as_ptr()),
            13 => core::arch::asm!("ldr d13, [{ptr}]", ptr = in(reg) data.as_ptr()),
            14 => core::arch::asm!("ldr d14, [{ptr}]", ptr = in(reg) data.as_ptr()),
            15 => core::arch::asm!("ldr d15, [{ptr}]", ptr = in(reg) data.as_ptr()),
            16 => core::arch::asm!("ldr d16, [{ptr}]", ptr = in(reg) data.as_ptr()),
            17 => core::arch::asm!("ldr d17, [{ptr}]", ptr = in(reg) data.as_ptr()),
            18 => core::arch::asm!("ldr d18, [{ptr}]", ptr = in(reg) data.as_ptr()),
            19 => core::arch::asm!("ldr d19, [{ptr}]", ptr = in(reg) data.as_ptr()),
            20 => core::arch::asm!("ldr d20, [{ptr}]", ptr = in(reg) data.as_ptr()),
            21 => core::arch::asm!("ldr d21, [{ptr}]", ptr = in(reg) data.as_ptr()),
            22 => core::arch::asm!("ldr d22, [{ptr}]", ptr = in(reg) data.as_ptr()),
            23 => core::arch::asm!("ldr d23, [{ptr}]", ptr = in(reg) data.as_ptr()),
            24 => core::arch::asm!("ldr d24, [{ptr}]", ptr = in(reg) data.as_ptr()),
            25 => core::arch::asm!("ldr d25, [{ptr}]", ptr = in(reg) data.as_ptr()),
            26 => core::arch::asm!("ldr d26, [{ptr}]", ptr = in(reg) data.as_ptr()),
            27 => core::arch::asm!("ldr d27, [{ptr}]", ptr = in(reg) data.as_ptr()),
            28 => core::arch::asm!("ldr d28, [{ptr}]", ptr = in(reg) data.as_ptr()),
            29 => core::arch::asm!("ldr d29, [{ptr}]", ptr = in(reg) data.as_ptr()),
            30 => core::arch::asm!("ldr d30, [{ptr}]", ptr = in(reg) data.as_ptr()),
            31 => core::arch::asm!("ldr d31, [{ptr}]", ptr = in(reg) data.as_ptr()),
            _ => {}
        }
    }
}

/// Read a S register (32-bit SIMD register) and return as byte array
fn read_s_register(reg: usize) -> [u8; 4] {
    let mut result = [0u8; 4];
    unsafe {
        match reg {
            0 => core::arch::asm!("str s0, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            1 => core::arch::asm!("str s1, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            2 => core::arch::asm!("str s2, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            3 => core::arch::asm!("str s3, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            4 => core::arch::asm!("str s4, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            5 => core::arch::asm!("str s5, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            6 => core::arch::asm!("str s6, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            7 => core::arch::asm!("str s7, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            8 => core::arch::asm!("str s8, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            9 => core::arch::asm!("str s9, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            10 => core::arch::asm!("str s10, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            11 => core::arch::asm!("str s11, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            12 => core::arch::asm!("str s12, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            13 => core::arch::asm!("str s13, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            14 => core::arch::asm!("str s14, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            15 => core::arch::asm!("str s15, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            16 => core::arch::asm!("str s16, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            17 => core::arch::asm!("str s17, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            18 => core::arch::asm!("str s18, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            19 => core::arch::asm!("str s19, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            20 => core::arch::asm!("str s20, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            21 => core::arch::asm!("str s21, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            22 => core::arch::asm!("str s22, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            23 => core::arch::asm!("str s23, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            24 => core::arch::asm!("str s24, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            25 => core::arch::asm!("str s25, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            26 => core::arch::asm!("str s26, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            27 => core::arch::asm!("str s27, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            28 => core::arch::asm!("str s28, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            29 => core::arch::asm!("str s29, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            30 => core::arch::asm!("str s30, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            31 => core::arch::asm!("str s31, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            _ => {}
        }
    }
    result
}

/// Write a S register (32-bit SIMD register) from byte array
fn write_s_register(reg: usize, data: &[u8; 4]) {
    unsafe {
        match reg {
            0 => core::arch::asm!("ldr s0, [{ptr}]", ptr = in(reg) data.as_ptr()),
            1 => core::arch::asm!("ldr s1, [{ptr}]", ptr = in(reg) data.as_ptr()),
            2 => core::arch::asm!("ldr s2, [{ptr}]", ptr = in(reg) data.as_ptr()),
            3 => core::arch::asm!("ldr s3, [{ptr}]", ptr = in(reg) data.as_ptr()),
            4 => core::arch::asm!("ldr s4, [{ptr}]", ptr = in(reg) data.as_ptr()),
            5 => core::arch::asm!("ldr s5, [{ptr}]", ptr = in(reg) data.as_ptr()),
            6 => core::arch::asm!("ldr s6, [{ptr}]", ptr = in(reg) data.as_ptr()),
            7 => core::arch::asm!("ldr s7, [{ptr}]", ptr = in(reg) data.as_ptr()),
            8 => core::arch::asm!("ldr s8, [{ptr}]", ptr = in(reg) data.as_ptr()),
            9 => core::arch::asm!("ldr s9, [{ptr}]", ptr = in(reg) data.as_ptr()),
            10 => core::arch::asm!("ldr s10, [{ptr}]", ptr = in(reg) data.as_ptr()),
            11 => core::arch::asm!("ldr s11, [{ptr}]", ptr = in(reg) data.as_ptr()),
            12 => core::arch::asm!("ldr s12, [{ptr}]", ptr = in(reg) data.as_ptr()),
            13 => core::arch::asm!("ldr s13, [{ptr}]", ptr = in(reg) data.as_ptr()),
            14 => core::arch::asm!("ldr s14, [{ptr}]", ptr = in(reg) data.as_ptr()),
            15 => core::arch::asm!("ldr s15, [{ptr}]", ptr = in(reg) data.as_ptr()),
            16 => core::arch::asm!("ldr s16, [{ptr}]", ptr = in(reg) data.as_ptr()),
            17 => core::arch::asm!("ldr s17, [{ptr}]", ptr = in(reg) data.as_ptr()),
            18 => core::arch::asm!("ldr s18, [{ptr}]", ptr = in(reg) data.as_ptr()),
            19 => core::arch::asm!("ldr s19, [{ptr}]", ptr = in(reg) data.as_ptr()),
            20 => core::arch::asm!("ldr s20, [{ptr}]", ptr = in(reg) data.as_ptr()),
            21 => core::arch::asm!("ldr s21, [{ptr}]", ptr = in(reg) data.as_ptr()),
            22 => core::arch::asm!("ldr s22, [{ptr}]", ptr = in(reg) data.as_ptr()),
            23 => core::arch::asm!("ldr s23, [{ptr}]", ptr = in(reg) data.as_ptr()),
            24 => core::arch::asm!("ldr s24, [{ptr}]", ptr = in(reg) data.as_ptr()),
            25 => core::arch::asm!("ldr s25, [{ptr}]", ptr = in(reg) data.as_ptr()),
            26 => core::arch::asm!("ldr s26, [{ptr}]", ptr = in(reg) data.as_ptr()),
            27 => core::arch::asm!("ldr s27, [{ptr}]", ptr = in(reg) data.as_ptr()),
            28 => core::arch::asm!("ldr s28, [{ptr}]", ptr = in(reg) data.as_ptr()),
            29 => core::arch::asm!("ldr s29, [{ptr}]", ptr = in(reg) data.as_ptr()),
            30 => core::arch::asm!("ldr s30, [{ptr}]", ptr = in(reg) data.as_ptr()),
            31 => core::arch::asm!("ldr s31, [{ptr}]", ptr = in(reg) data.as_ptr()),
            _ => {}
        }
    }
}

/// Read a H register (16-bit SIMD register) and return as byte array
fn read_h_register(reg: usize) -> [u8; 2] {
    let mut result = [0u8; 2];
    unsafe {
        match reg {
            0 => core::arch::asm!("str h0, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            1 => core::arch::asm!("str h1, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            2 => core::arch::asm!("str h2, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            3 => core::arch::asm!("str h3, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            4 => core::arch::asm!("str h4, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            5 => core::arch::asm!("str h5, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            6 => core::arch::asm!("str h6, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            7 => core::arch::asm!("str h7, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            8 => core::arch::asm!("str h8, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            9 => core::arch::asm!("str h9, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            10 => core::arch::asm!("str h10, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            11 => core::arch::asm!("str h11, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            12 => core::arch::asm!("str h12, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            13 => core::arch::asm!("str h13, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            14 => core::arch::asm!("str h14, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            15 => core::arch::asm!("str h15, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            16 => core::arch::asm!("str h16, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            17 => core::arch::asm!("str h17, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            18 => core::arch::asm!("str h18, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            19 => core::arch::asm!("str h19, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            20 => core::arch::asm!("str h20, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            21 => core::arch::asm!("str h21, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            22 => core::arch::asm!("str h22, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            23 => core::arch::asm!("str h23, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            24 => core::arch::asm!("str h24, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            25 => core::arch::asm!("str h25, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            26 => core::arch::asm!("str h26, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            27 => core::arch::asm!("str h27, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            28 => core::arch::asm!("str h28, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            29 => core::arch::asm!("str h29, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            30 => core::arch::asm!("str h30, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            31 => core::arch::asm!("str h31, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            _ => {}
        }
    }
    result
}

/// Write a H register (16-bit SIMD register) from byte array
fn write_h_register(reg: usize, data: &[u8; 2]) {
    unsafe {
        match reg {
            0 => core::arch::asm!("ldr h0, [{ptr}]", ptr = in(reg) data.as_ptr()),
            1 => core::arch::asm!("ldr h1, [{ptr}]", ptr = in(reg) data.as_ptr()),
            2 => core::arch::asm!("ldr h2, [{ptr}]", ptr = in(reg) data.as_ptr()),
            3 => core::arch::asm!("ldr h3, [{ptr}]", ptr = in(reg) data.as_ptr()),
            4 => core::arch::asm!("ldr h4, [{ptr}]", ptr = in(reg) data.as_ptr()),
            5 => core::arch::asm!("ldr h5, [{ptr}]", ptr = in(reg) data.as_ptr()),
            6 => core::arch::asm!("ldr h6, [{ptr}]", ptr = in(reg) data.as_ptr()),
            7 => core::arch::asm!("ldr h7, [{ptr}]", ptr = in(reg) data.as_ptr()),
            8 => core::arch::asm!("ldr h8, [{ptr}]", ptr = in(reg) data.as_ptr()),
            9 => core::arch::asm!("ldr h9, [{ptr}]", ptr = in(reg) data.as_ptr()),
            10 => core::arch::asm!("ldr h10, [{ptr}]", ptr = in(reg) data.as_ptr()),
            11 => core::arch::asm!("ldr h11, [{ptr}]", ptr = in(reg) data.as_ptr()),
            12 => core::arch::asm!("ldr h12, [{ptr}]", ptr = in(reg) data.as_ptr()),
            13 => core::arch::asm!("ldr h13, [{ptr}]", ptr = in(reg) data.as_ptr()),
            14 => core::arch::asm!("ldr h14, [{ptr}]", ptr = in(reg) data.as_ptr()),
            15 => core::arch::asm!("ldr h15, [{ptr}]", ptr = in(reg) data.as_ptr()),
            16 => core::arch::asm!("ldr h16, [{ptr}]", ptr = in(reg) data.as_ptr()),
            17 => core::arch::asm!("ldr h17, [{ptr}]", ptr = in(reg) data.as_ptr()),
            18 => core::arch::asm!("ldr h18, [{ptr}]", ptr = in(reg) data.as_ptr()),
            19 => core::arch::asm!("ldr h19, [{ptr}]", ptr = in(reg) data.as_ptr()),
            20 => core::arch::asm!("ldr h20, [{ptr}]", ptr = in(reg) data.as_ptr()),
            21 => core::arch::asm!("ldr h21, [{ptr}]", ptr = in(reg) data.as_ptr()),
            22 => core::arch::asm!("ldr h22, [{ptr}]", ptr = in(reg) data.as_ptr()),
            23 => core::arch::asm!("ldr h23, [{ptr}]", ptr = in(reg) data.as_ptr()),
            24 => core::arch::asm!("ldr h24, [{ptr}]", ptr = in(reg) data.as_ptr()),
            25 => core::arch::asm!("ldr h25, [{ptr}]", ptr = in(reg) data.as_ptr()),
            26 => core::arch::asm!("ldr h26, [{ptr}]", ptr = in(reg) data.as_ptr()),
            27 => core::arch::asm!("ldr h27, [{ptr}]", ptr = in(reg) data.as_ptr()),
            28 => core::arch::asm!("ldr h28, [{ptr}]", ptr = in(reg) data.as_ptr()),
            29 => core::arch::asm!("ldr h29, [{ptr}]", ptr = in(reg) data.as_ptr()),
            30 => core::arch::asm!("ldr h30, [{ptr}]", ptr = in(reg) data.as_ptr()),
            31 => core::arch::asm!("ldr h31, [{ptr}]", ptr = in(reg) data.as_ptr()),
            _ => {}
        }
    }
}

/// Read a B register (8-bit SIMD register) and return as byte
fn read_b_register(reg: usize) -> u8 {
    let mut result = [0u8; 1];
    unsafe {
        match reg {
            0 => core::arch::asm!("str b0, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            1 => core::arch::asm!("str b1, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            2 => core::arch::asm!("str b2, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            3 => core::arch::asm!("str b3, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            4 => core::arch::asm!("str b4, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            5 => core::arch::asm!("str b5, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            6 => core::arch::asm!("str b6, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            7 => core::arch::asm!("str b7, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            8 => core::arch::asm!("str b8, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            9 => core::arch::asm!("str b9, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            10 => core::arch::asm!("str b10, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            11 => core::arch::asm!("str b11, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            12 => core::arch::asm!("str b12, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            13 => core::arch::asm!("str b13, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            14 => core::arch::asm!("str b14, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            15 => core::arch::asm!("str b15, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            16 => core::arch::asm!("str b16, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            17 => core::arch::asm!("str b17, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            18 => core::arch::asm!("str b18, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            19 => core::arch::asm!("str b19, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            20 => core::arch::asm!("str b20, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            21 => core::arch::asm!("str b21, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            22 => core::arch::asm!("str b22, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            23 => core::arch::asm!("str b23, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            24 => core::arch::asm!("str b24, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            25 => core::arch::asm!("str b25, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            26 => core::arch::asm!("str b26, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            27 => core::arch::asm!("str b27, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            28 => core::arch::asm!("str b28, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            29 => core::arch::asm!("str b29, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            30 => core::arch::asm!("str b30, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            31 => core::arch::asm!("str b31, [{ptr}]", ptr = in(reg) result.as_mut_ptr()),
            _ => {}
        }
    }
    result[0]
}

/// Write a B register (8-bit SIMD register) from byte
fn write_b_register(reg: usize, data: u8) {
    let arr = [data];
    unsafe {
        match reg {
            0 => core::arch::asm!("ldr b0, [{ptr}]", ptr = in(reg) arr.as_ptr()),
            1 => core::arch::asm!("ldr b1, [{ptr}]", ptr = in(reg) arr.as_ptr()),
            2 => core::arch::asm!("ldr b2, [{ptr}]", ptr = in(reg) arr.as_ptr()),
            3 => core::arch::asm!("ldr b3, [{ptr}]", ptr = in(reg) arr.as_ptr()),
            4 => core::arch::asm!("ldr b4, [{ptr}]", ptr = in(reg) arr.as_ptr()),
            5 => core::arch::asm!("ldr b5, [{ptr}]", ptr = in(reg) arr.as_ptr()),
            6 => core::arch::asm!("ldr b6, [{ptr}]", ptr = in(reg) arr.as_ptr()),
            7 => core::arch::asm!("ldr b7, [{ptr}]", ptr = in(reg) arr.as_ptr()),
            8 => core::arch::asm!("ldr b8, [{ptr}]", ptr = in(reg) arr.as_ptr()),
            9 => core::arch::asm!("ldr b9, [{ptr}]", ptr = in(reg) arr.as_ptr()),
            10 => core::arch::asm!("ldr b10, [{ptr}]", ptr = in(reg) arr.as_ptr()),
            11 => core::arch::asm!("ldr b11, [{ptr}]", ptr = in(reg) arr.as_ptr()),
            12 => core::arch::asm!("ldr b12, [{ptr}]", ptr = in(reg) arr.as_ptr()),
            13 => core::arch::asm!("ldr b13, [{ptr}]", ptr = in(reg) arr.as_ptr()),
            14 => core::arch::asm!("ldr b14, [{ptr}]", ptr = in(reg) arr.as_ptr()),
            15 => core::arch::asm!("ldr b15, [{ptr}]", ptr = in(reg) arr.as_ptr()),
            16 => core::arch::asm!("ldr b16, [{ptr}]", ptr = in(reg) arr.as_ptr()),
            17 => core::arch::asm!("ldr b17, [{ptr}]", ptr = in(reg) arr.as_ptr()),
            18 => core::arch::asm!("ldr b18, [{ptr}]", ptr = in(reg) arr.as_ptr()),
            19 => core::arch::asm!("ldr b19, [{ptr}]", ptr = in(reg) arr.as_ptr()),
            20 => core::arch::asm!("ldr b20, [{ptr}]", ptr = in(reg) arr.as_ptr()),
            21 => core::arch::asm!("ldr b21, [{ptr}]", ptr = in(reg) arr.as_ptr()),
            22 => core::arch::asm!("ldr b22, [{ptr}]", ptr = in(reg) arr.as_ptr()),
            23 => core::arch::asm!("ldr b23, [{ptr}]", ptr = in(reg) arr.as_ptr()),
            24 => core::arch::asm!("ldr b24, [{ptr}]", ptr = in(reg) arr.as_ptr()),
            25 => core::arch::asm!("ldr b25, [{ptr}]", ptr = in(reg) arr.as_ptr()),
            26 => core::arch::asm!("ldr b26, [{ptr}]", ptr = in(reg) arr.as_ptr()),
            27 => core::arch::asm!("ldr b27, [{ptr}]", ptr = in(reg) arr.as_ptr()),
            28 => core::arch::asm!("ldr b28, [{ptr}]", ptr = in(reg) arr.as_ptr()),
            29 => core::arch::asm!("ldr b29, [{ptr}]", ptr = in(reg) arr.as_ptr()),
            30 => core::arch::asm!("ldr b30, [{ptr}]", ptr = in(reg) arr.as_ptr()),
            31 => core::arch::asm!("ldr b31, [{ptr}]", ptr = in(reg) arr.as_ptr()),
            _ => {}
        }
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

    // Print some GPRs for debugging
    exception_println!("  x0:  {:#018x}  x1:  {:#018x}", ctx.gpr[0], ctx.gpr[1]);
    exception_println!("  x2:  {:#018x}  x3:  {:#018x}", ctx.gpr[2], ctx.gpr[3]);
    exception_println!("  x19: {:#018x}  x20: {:#018x}", ctx.gpr[19], ctx.gpr[20]);
    exception_println!("  x29: {:#018x}  x30: {:#018x}", ctx.gpr[29], ctx.gpr[30]);

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

/// Debug function called to print x0 value loaded from context
#[no_mangle]
extern "C" fn debug_loaded_x0(x0_value: u64) {
    let task_id = crate::sched::current().map(|t| t.0).unwrap_or(999);
    if task_id >= 10 {
        exception_println!("[debug_x0] task={} loaded x0={:#x}", task_id, x0_value);
    }
}

/// Debug function called between handle_el0_sync and RESTORE_CONTEXT
/// (Can be used for debugging context restoration issues)
#[no_mangle]
extern "C" fn debug_before_restore(_ctx: &ExceptionContext) {
    // Debug hook - currently unused
}

#[no_mangle]
extern "C" fn handle_el0_sync(ctx: &mut ExceptionContext, _exc_type: u64) {
    if ctx.is_svc() {
        // System call from userspace
        let svc_imm = ctx.svc_number();
        // AArch64 Linux convention: syscall number is in x8, not the svc immediate
        let syscall_num = ctx.gpr[8] as u16;
        syscall::handle_syscall(ctx, svc_imm);

        // Check for pending signals before returning to userspace
        // Pass the syscall number so signal delivery can report it
        syscall::check_and_deliver_signals_after_syscall(ctx, syscall_num);

    } else if ctx.is_data_abort() {
        let fault_addr = ctx.far as usize;

        // Only attempt demand paging for translation faults (page not mapped)
        // Alignment faults and permission faults are genuine errors
        if ctx.is_translation_fault() {
            // Check if this is a demand-paging fault for an mmap region
            if fault_addr >= mmap::MMAP_BASE && fault_addr < mmap::MMAP_END {
                let result = mmap::handle_page_fault(fault_addr);
                if result == 0 {
                    // Page allocated successfully, resume execution
                    return;
                }
            }
        }

        // Check for alignment faults that we can emulate
        if ctx.is_alignment_fault() {
            if try_emulate_alignment_fault(ctx) {
                // Successfully emulated, resume execution
                return;
            }
        }

        // Not a handleable fault - fatal error
        exception_println!();
        if ctx.is_alignment_fault() {
            exception_println!("USER ALIGNMENT FAULT (SIGBUS)!");
            exception_println!("The instruction at {:#018x} requires aligned access", ctx.elr);
            exception_println!("but address {:#018x} is not properly aligned", ctx.far);
            exception_println!("(Could not emulate this instruction)");
        } else {
            exception_println!("USER DATA ABORT!");
            // Dump the instruction at ELR to verify memory contents
            let instr_ptr = ctx.elr as *const u32;
            let instr = unsafe { core::ptr::read_volatile(instr_ptr) };
            exception_println!("Instruction at ELR: {:#010x}", instr);
        }
        exception_println!("Faulting address: {:#018x}", ctx.far);

        // Debug: Print TTBR0 to verify correct page table is in use
        let ttbr0: u64;
        unsafe { core::arch::asm!("mrs {}, ttbr0_el1", out(reg) ttbr0); }
        exception_println!("TTBR0_EL1: {:#018x}", ttbr0);

        // Also print task's expected TTBR0
        if let Some(task_id) = crate::sched::current() {
            unsafe {
                let task = &crate::sched::task::TASKS[task_id.0];
                if let Some(ref addr_space) = task.addr_space {
                    exception_println!("Task {} addr_space.ttbr0: {:#018x}", task_id.0, addr_space.ttbr0());

                    // Dump L2 table entries for L1[0] to show mapped 2MB blocks
                    exception_println!("L2 entries for L1[0] (0x0-0x40000000):");
                    let l1_ptr = addr_space.ttbr0() as *const u64;
                    let l1_entry = core::ptr::read_volatile(l1_ptr);
                    if l1_entry & 0b11 == 0b11 {  // Valid table entry
                        let l2_addr = (l1_entry & 0x0000_FFFF_FFFF_F000) as *const u64;
                        for i in 0..8 {  // Print first 8 entries (0-16MB)
                            let l2_entry = core::ptr::read_volatile(l2_addr.add(i));
                            if l2_entry & 1 != 0 {  // Valid
                                let block_type = if l2_entry & 2 == 0 { "BLOCK" } else { "TABLE" };
                                let paddr = l2_entry & 0x0000_FFFF_FFE0_0000;
                                exception_println!("  L2[{}]: {} virt=0x{:x}-0x{:x} paddr=0x{:x}",
                                    i, block_type, i * 0x200000, (i+1) * 0x200000 - 1, paddr);
                            }
                        }
                    }
                } else {
                    exception_println!("Task {} has no addr_space!", task_id.0);
                }
            }
        }

        print_context(ctx);

        // TODO: Send SIGSEGV/SIGBUS to process, for now just halt
        loop {
            core::hint::spin_loop();
        }
    } else if ctx.is_instruction_abort() {
        let task_id = crate::sched::current().map(|t| t.0).unwrap_or(999);
        exception_println!();
        exception_println!("USER INSTRUCTION ABORT! (task {})", task_id);
        exception_println!("Faulting address: {:#018x}", ctx.far);
        print_context(ctx);

        // TODO: Send SIGSEGV to process
        loop {
            core::hint::spin_loop();
        }
    } else {
        // Check if this might be a page fault with unusual EC (EC=0 happens sometimes)
        let fault_addr = ctx.far as usize;
        if fault_addr >= mmap::MMAP_BASE && fault_addr < mmap::MMAP_END {
            // Try to handle as page fault even though EC is unexpected
            let result = mmap::handle_page_fault(fault_addr);
            if result == 0 {
                // Page allocated successfully, resume execution
                return;
            }
        }

        exception_println!();
        exception_println!("USER SYNCHRONOUS EXCEPTION!");
        print_context(ctx);

        // Print all registers to help debug
        exception_println!("  x0={:#x} x1={:#x} x2={:#x} x3={:#x}",
            ctx.gpr[0], ctx.gpr[1], ctx.gpr[2], ctx.gpr[3]);
        exception_println!("  x4={:#x} x5={:#x} x6={:#x} x7={:#x}",
            ctx.gpr[4], ctx.gpr[5], ctx.gpr[6], ctx.gpr[7]);

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
