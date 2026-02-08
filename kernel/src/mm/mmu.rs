//! AArch64 MMU initialization and control
//!
//! Enables the MMU with identity mapping for the Kenix microkernel.
//! Uses 4KB granule with 2MB blocks for efficient mapping.

use super::frame::alloc_frame;
use super::paging::{PageTableEntry, BLOCK_SIZE_2MB, l1_index, l2_index};

/// Kernel's original TTBR0 value, stored at boot time
/// This is needed because during syscalls, TTBR0_EL1 contains the user's page table
static mut KERNEL_TTBR0: u64 = 0;

/// Get the kernel's original TTBR0 value
///
/// # Safety
/// Must be called after init_and_enable()
pub fn kernel_ttbr0() -> u64 {
    unsafe { KERNEL_TTBR0 }
}

/// MAIR_EL1 value:
/// Attr0 (index 0) = 0x00 = Device-nGnRnE
/// Attr1 (index 1) = 0xFF = Normal Write-Back (Inner/Outer Write-Back, Read/Write Allocate)
pub const MAIR_VALUE: u64 = 0x00 | (0xFF << 8);

/// TCR_EL1 value for 39-bit VA, 4KB granule, TTBR0 only
/// T0SZ  = 25 (bits [5:0])   → 39-bit VA for TTBR0 (64 - 25 = 39)
///                             Starts at level 1, allows 2MB blocks at L2
/// EPD0  = 0  (bit 7)        → Enable TTBR0 walks
/// IRGN0 = 01 (bits [9:8])   → Inner Write-Back cacheable
/// ORGN0 = 01 (bits [11:10]) → Outer Write-Back cacheable
/// SH0   = 11 (bits [13:12]) → Inner Shareable
/// TG0   = 00 (bits [15:14]) → 4KB granule for TTBR0
/// EPD1  = 1  (bit 23)       → Disable TTBR1 walks
/// IPS   = 010 (bits [34:32])→ 40-bit PA (1TB physical)
pub const TCR_VALUE: u64 = (25 << 0)         // T0SZ = 25 (39-bit VA, starts at L1)
    | (0b01 << 8)    // IRGN0 = Write-Back
    | (0b01 << 10)   // ORGN0 = Write-Back
    | (0b11 << 12)   // SH0 = Inner Shareable
    | (0b00 << 14)   // TG0 = 4KB
    | (1 << 23)      // EPD1 = disable TTBR1
    | (0b010 << 32); // IPS = 40-bit PA

/// Memory regions to map
const GIC_BASE: u64 = 0x0800_0000;
const UART_BASE: u64 = 0x0900_0000;
const RAM_START: u64 = 0x4000_0000;

/// Initialize page tables and enable the MMU
///
/// # Safety
/// - Must be called only once during boot
/// - Frame allocator must be initialized
/// - Must be running at EL1
/// - Interrupts should be disabled
#[inline(never)]
pub unsafe fn init_and_enable(print_fn: impl Fn(&str, u64)) {
    use core::ptr;

    // Allocate 3 page tables: L1, L2_device, L2_ram
    let l1_frame = alloc_frame().expect("Failed to allocate L1 page table");
    let l2_device_frame = alloc_frame().expect("Failed to allocate L2 device page table");
    let l2_ram_frame = alloc_frame().expect("Failed to allocate L2 RAM page table");

    let l1_addr = l1_frame.as_usize();
    let l2_device_addr = l2_device_frame.as_usize();
    let l2_ram_addr = l2_ram_frame.as_usize();

    print_fn("  L1 table at: ", l1_addr as u64);
    print_fn("  L2 device table at: ", l2_device_addr as u64);
    print_fn("  L2 RAM table at: ", l2_ram_addr as u64);

    // Zero all tables using volatile writes
    let l1_ptr = l1_addr as *mut u64;
    let l2_device_ptr = l2_device_addr as *mut u64;
    let l2_ram_ptr = l2_ram_addr as *mut u64;

    for i in 0..512 {
        ptr::write_volatile(l1_ptr.add(i), 0);
        ptr::write_volatile(l2_device_ptr.add(i), 0);
        ptr::write_volatile(l2_ram_ptr.add(i), 0);
    }

    // Fill L2 device table: map GIC (0x08000000) and UART (0x09000000)
    // GIC at 0x08000000: index = 0x08000000 >> 21 = 64
    // UART at 0x09000000: index = 0x09000000 >> 21 = 72
    let gic_l2_idx = l2_index(GIC_BASE as usize);
    let uart_l2_idx = l2_index(UART_BASE as usize);

    let gic_entry = PageTableEntry::block_2mb_device(GIC_BASE);
    let uart_entry = PageTableEntry::block_2mb_device(UART_BASE);
    ptr::write_volatile(l2_device_ptr.add(gic_l2_idx), gic_entry.raw());
    ptr::write_volatile(l2_device_ptr.add(uart_l2_idx), uart_entry.raw());

    // Fill L2 RAM table: map 0x40000000 - 0x80000000 (1GB = 512 * 2MB entries)
    for i in 0..512 {
        let paddr = RAM_START + (i as u64 * BLOCK_SIZE_2MB as u64);
        let entry = PageTableEntry::block_2mb_normal(paddr);
        ptr::write_volatile(l2_ram_ptr.add(i), entry.raw());
    }

    // Fill L1 table:
    // Entry[0] → L2_device (covers 0x00000000 - 0x40000000)
    // Entry[1] → L2_ram (covers 0x40000000 - 0x80000000)
    let l1_device_idx = l1_index(0x0000_0000);
    let l1_ram_idx = l1_index(RAM_START as usize);

    let l1_device_entry = PageTableEntry::table(l2_device_addr as u64);
    let l1_ram_entry = PageTableEntry::table(l2_ram_addr as u64);
    ptr::write_volatile(l1_ptr.add(l1_device_idx), l1_device_entry.raw());
    ptr::write_volatile(l1_ptr.add(l1_ram_idx), l1_ram_entry.raw());

    // Memory barrier: ensure all page table writes are complete
    core::arch::asm!("dsb ishst", options(nostack, preserves_flags));

    // Configure MMU registers
    write_mair_el1(MAIR_VALUE);
    write_tcr_el1(TCR_VALUE);
    write_ttbr0_el1(l1_addr as u64);

    // Store kernel's TTBR0 for later use by address space creation
    KERNEL_TTBR0 = l1_addr as u64;

    // Instruction barrier after register writes
    core::arch::asm!("isb", options(nostack, preserves_flags));

    // Invalidate TLB
    core::arch::asm!(
        "tlbi vmalle1is",
        options(nostack, preserves_flags)
    );

    // Barriers before enabling MMU
    core::arch::asm!(
        "dsb ish",
        "isb",
        options(nostack, preserves_flags)
    );

    // Enable MMU via SCTLR_EL1
    let mut sctlr = read_sctlr_el1();
    sctlr |= SCTLR_M;  // Enable MMU
    sctlr |= SCTLR_C;  // Enable data cache
    sctlr |= SCTLR_I;  // Enable instruction cache
    // Disable alignment checking (helps with some unaligned accesses)
    sctlr &= !SCTLR_A;   // Disable alignment check for EL1
    sctlr &= !SCTLR_SA;  // Disable stack alignment check for EL1
    sctlr &= !SCTLR_SA0; // Disable stack alignment check for EL0
    write_sctlr_el1(sctlr);

    // Final instruction barrier
    core::arch::asm!("isb", options(nostack, preserves_flags));
}

// SCTLR_EL1 bits
const SCTLR_M: u64 = 1 << 0;  // MMU enable
const SCTLR_A: u64 = 1 << 1;  // Alignment check enable for EL1
const SCTLR_C: u64 = 1 << 2;  // Data cache enable
const SCTLR_SA: u64 = 1 << 3; // Stack alignment check enable for EL1
const SCTLR_SA0: u64 = 1 << 4; // Stack alignment check enable for EL0
const SCTLR_I: u64 = 1 << 12; // Instruction cache enable

// System register access functions

#[inline]
unsafe fn read_sctlr_el1() -> u64 {
    let val: u64;
    core::arch::asm!(
        "mrs {}, sctlr_el1",
        out(reg) val,
        options(nostack, preserves_flags)
    );
    val
}

#[inline]
unsafe fn write_sctlr_el1(val: u64) {
    core::arch::asm!(
        "msr sctlr_el1, {}",
        in(reg) val,
        options(nostack, preserves_flags)
    );
}

#[inline]
unsafe fn write_mair_el1(val: u64) {
    core::arch::asm!(
        "msr mair_el1, {}",
        in(reg) val,
        options(nostack, preserves_flags)
    );
}

#[inline]
unsafe fn write_tcr_el1(val: u64) {
    core::arch::asm!(
        "msr tcr_el1, {}",
        in(reg) val,
        options(nostack, preserves_flags)
    );
}

#[inline]
unsafe fn write_ttbr0_el1(val: u64) {
    core::arch::asm!(
        "msr ttbr0_el1, {}",
        in(reg) val,
        options(nostack, preserves_flags)
    );
}
