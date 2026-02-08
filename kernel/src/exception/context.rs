//! Exception context structure for AArch64
//!
//! This structure matches the stack frame layout created by SAVE_CONTEXT in vectors.s

/// Exception context saved on the stack during exception handling.
///
/// Stack frame layout (288 bytes, 16-byte aligned):
/// - 0x000-0x0F0: x0-x30 (31 * 8 = 248 bytes)
/// - 0x0F8: sp (original stack pointer)
/// - 0x100: elr_el1 (return address)
/// - 0x108: spsr_el1 (saved processor status)
/// - 0x110: esr_el1 (exception syndrome)
/// - 0x118: far_el1 (fault address)
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ExceptionContext {
    /// General purpose registers x0-x30
    pub gpr: [u64; 31],
    /// Original stack pointer before exception
    pub sp: u64,
    /// Exception Link Register - return address
    pub elr: u64,
    /// Saved Program Status Register
    pub spsr: u64,
    /// Exception Syndrome Register
    pub esr: u64,
    /// Fault Address Register
    pub far: u64,
}

// Verify the structure size at compile time
const _: () = assert!(core::mem::size_of::<ExceptionContext>() == 288);

impl ExceptionContext {
    /// Get the Exception Class from ESR_EL1
    /// EC is bits [31:26]
    pub fn exception_class(&self) -> u8 {
        ((self.esr >> 26) & 0x3F) as u8
    }

    /// Get the Instruction Specific Syndrome from ESR_EL1
    /// ISS is bits [24:0]
    pub fn instruction_syndrome(&self) -> u32 {
        (self.esr & 0x1FFFFFF) as u32
    }

    /// Check if the exception was caused by an SVC instruction (syscall)
    pub fn is_svc(&self) -> bool {
        self.exception_class() == 0x15 // EC for SVC from AArch64
    }

    /// Check if the exception was a data abort
    pub fn is_data_abort(&self) -> bool {
        let ec = self.exception_class();
        ec == 0x24 || ec == 0x25 // Data abort from lower EL or current EL
    }

    /// Check if the exception was an instruction abort
    pub fn is_instruction_abort(&self) -> bool {
        let ec = self.exception_class();
        ec == 0x20 || ec == 0x21 // Instruction abort from lower EL or current EL
    }

    /// Get the SVC immediate value (syscall number) from ISS
    /// Only valid when is_svc() returns true
    pub fn svc_number(&self) -> u16 {
        (self.esr & 0xFFFF) as u16
    }

    /// Get the Data Fault Status Code from ISS
    /// Only valid for data/instruction aborts
    pub fn fault_status_code(&self) -> u8 {
        (self.esr & 0x3F) as u8
    }

    /// Check if the fault was a write (1) or read (0)
    /// Only valid for data aborts
    pub fn is_write_fault(&self) -> bool {
        (self.esr & (1 << 6)) != 0
    }

    /// Check if this is a translation fault (page not mapped)
    /// These are the faults that can be handled by demand paging
    /// DFSC 0x04-0x07: Translation faults at levels 0-3
    pub fn is_translation_fault(&self) -> bool {
        let dfsc = self.fault_status_code();
        dfsc >= 0x04 && dfsc <= 0x07
    }

    /// Check if this is an alignment fault
    /// DFSC 0x21: Alignment fault
    pub fn is_alignment_fault(&self) -> bool {
        self.fault_status_code() == 0x21
    }

    /// Check if this is a permission fault
    /// DFSC 0x0C-0x0F: Permission faults at levels 0-3
    pub fn is_permission_fault(&self) -> bool {
        let dfsc = self.fault_status_code();
        dfsc >= 0x0C && dfsc <= 0x0F
    }
}
