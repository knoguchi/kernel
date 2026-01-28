//! Per-task address space management
//!
//! Each process has its own address space with:
//! - Separate user-space mappings (TTBR0_EL1)
//! - Shared kernel mappings (copied from kernel page table)

use super::frame::{alloc_frame, free_frame, PhysAddr};
use super::paging::{PageTableEntry, MATTR_NORMAL, MATTR_DEVICE, ENTRIES_PER_TABLE, l1_index, l2_index};
use core::ptr;

/// Page flags for mapping
#[derive(Clone, Copy)]
pub struct PageFlags {
    /// Memory attribute (Normal or Device)
    pub mattr: u64,
    /// Writable
    pub writable: bool,
    /// Executable
    pub executable: bool,
    /// User accessible (EL0)
    pub user: bool,
}

impl PageFlags {
    pub const fn kernel_code() -> Self {
        Self {
            mattr: MATTR_NORMAL,
            writable: false,
            executable: true,
            user: false,
        }
    }

    pub const fn kernel_data() -> Self {
        Self {
            mattr: MATTR_NORMAL,
            writable: true,
            executable: false,
            user: false,
        }
    }

    pub const fn user_code() -> Self {
        Self {
            mattr: MATTR_NORMAL,
            writable: false,
            executable: true,
            user: true,
        }
    }

    pub const fn user_data() -> Self {
        Self {
            mattr: MATTR_NORMAL,
            writable: true,
            executable: false,
            user: true,
        }
    }

    pub const fn device() -> Self {
        Self {
            mattr: MATTR_DEVICE,
            writable: true,
            executable: false,
            user: false,
        }
    }
}

/// Per-task address space
pub struct AddressSpace {
    /// L1 page table physical address (TTBR0_EL1)
    ttbr0: PhysAddr,
    /// L2 tables (up to 4 for 4GB address space with 1GB per L1 entry)
    l2_tables: [Option<PhysAddr>; 4],
}

impl AddressSpace {
    /// Create a new address space by cloning kernel mappings
    ///
    /// # Safety
    /// Requires the kernel page tables to be initialized
    pub unsafe fn new() -> Option<Self> {
        // Allocate L1 table
        let l1_frame = alloc_frame()?;

        // Zero the L1 table
        let l1_ptr = l1_frame.0 as *mut u64;
        for i in 0..ENTRIES_PER_TABLE {
            ptr::write_volatile(l1_ptr.add(i), 0);
        }

        let mut addr_space = Self {
            ttbr0: l1_frame,
            l2_tables: [None; 4],
        };

        // Clone kernel mappings from the current TTBR0
        // We copy the L1 entries that map kernel space (0x40000000 and above)
        let kernel_ttbr0 = read_ttbr0_el1();
        let kernel_l1_ptr = kernel_ttbr0 as *const u64;

        // Copy L1 entries 1-3 (covers 0x40000000 - 0xFFFFFFFF)
        // Entry 0 is device space, entry 1 is RAM
        for i in 0..4 {
            let entry = ptr::read_volatile(kernel_l1_ptr.add(i));
            ptr::write_volatile(l1_ptr.add(i), entry);
        }

        Some(addr_space)
    }

    /// Create a new address space for a user process
    ///
    /// This creates fresh L2 tables for user space and copies kernel mappings
    /// (device and RAM) so that syscalls and interrupts can execute kernel code.
    /// User code/data will be mapped separately via map_2mb().
    ///
    /// # Safety
    /// Requires the kernel page tables to be initialized
    pub unsafe fn new_for_user() -> Option<Self> {
        // Allocate L1 table
        let l1_frame = alloc_frame()?;

        // Zero the L1 table
        let l1_ptr = l1_frame.0 as *mut u64;
        for i in 0..ENTRIES_PER_TABLE {
            ptr::write_volatile(l1_ptr.add(i), 0);
        }

        let mut addr_space = Self {
            ttbr0: l1_frame,
            l2_tables: [None; 4],
        };

        // Get kernel page tables
        let kernel_ttbr0 = read_ttbr0_el1();
        let kernel_l1_ptr = kernel_ttbr0 as *const u64;

        // Allocate new L2 tables and copy kernel mappings
        // L1[0] covers 0x00000000 - 0x40000000 (device region + user space)
        // L1[1] covers 0x40000000 - 0x80000000 (RAM)

        // For L1[0]: Create new L2 table, copy device mappings (GIC, UART)
        let l2_0_frame = alloc_frame()?;
        let l2_0_ptr = l2_0_frame.0 as *mut u64;
        for i in 0..ENTRIES_PER_TABLE {
            ptr::write_volatile(l2_0_ptr.add(i), 0);
        }

        // Get kernel's L2 device table and copy device entries
        let kernel_l1_0_entry = ptr::read_volatile(kernel_l1_ptr.add(0));
        if (kernel_l1_0_entry & 0b11) == 0b11 {
            // It's a table descriptor, get the L2 table address
            let kernel_l2_0_addr = (kernel_l1_0_entry & 0x0000_FFFF_FFFF_F000) as *const u64;
            // Copy device entries (GIC at index 64, UART at index 72)
            // Actually, copy all entries to preserve any device mappings
            for i in 0..ENTRIES_PER_TABLE {
                let entry = ptr::read_volatile(kernel_l2_0_addr.add(i));
                ptr::write_volatile(l2_0_ptr.add(i), entry);
            }
        }

        // Set L1[0] to point to our new L2 table
        let l1_0_entry = PageTableEntry::table(l2_0_frame.0 as u64);
        ptr::write_volatile(l1_ptr.add(0), l1_0_entry.as_u64());
        addr_space.l2_tables[0] = Some(l2_0_frame);

        // For L1[1]: Copy the kernel RAM L2 table (or just copy L1 entry for 1GB block)
        // The kernel uses L2 tables for RAM too, so let's just copy the L1 entry directly
        // This shares the kernel's L2 table (read-only for our purposes)
        let kernel_l1_1_entry = ptr::read_volatile(kernel_l1_ptr.add(1));
        ptr::write_volatile(l1_ptr.add(1), kernel_l1_1_entry);
        // Note: We don't track this in l2_tables since it's shared with kernel

        Some(addr_space)
    }

    /// Get the TTBR0 value for this address space
    pub fn ttbr0(&self) -> u64 {
        self.ttbr0.0 as u64
    }

    /// Get the physical address of the L1 table
    pub fn l1_table(&self) -> PhysAddr {
        self.ttbr0
    }

    /// Map a 2MB block at the given virtual address
    ///
    /// # Safety
    /// The caller must ensure the physical address is valid
    pub unsafe fn map_2mb(&mut self, vaddr: usize, paddr: PhysAddr, flags: PageFlags) -> bool {
        let l1_idx = l1_index(vaddr);
        let l2_idx = l2_index(vaddr);

        // Ensure we have an L2 table for this L1 index
        if self.l2_tables[l1_idx].is_none() {
            // Allocate a new L2 table
            if let Some(l2_frame) = alloc_frame() {
                let l2_ptr = l2_frame.0 as *mut u64;
                for i in 0..ENTRIES_PER_TABLE {
                    ptr::write_volatile(l2_ptr.add(i), 0);
                }

                // Update L1 entry to point to new L2 table
                let l1_ptr = self.ttbr0.0 as *mut u64;
                let l1_entry = PageTableEntry::table(l2_frame.0 as u64);
                ptr::write_volatile(l1_ptr.add(l1_idx), l1_entry.as_u64());

                self.l2_tables[l1_idx] = Some(l2_frame);
            } else {
                return false;
            }
        }

        // Create the L2 entry
        let l2_frame = self.l2_tables[l1_idx].unwrap();
        let l2_ptr = l2_frame.0 as *mut u64;

        let entry = make_block_entry(paddr.0 as u64, flags);
        ptr::write_volatile(l2_ptr.add(l2_idx), entry);

        true
    }

    /// Unmap a 2MB block at the given virtual address
    pub unsafe fn unmap_2mb(&mut self, vaddr: usize) {
        let l1_idx = l1_index(vaddr);
        let l2_idx = l2_index(vaddr);

        if let Some(l2_frame) = self.l2_tables[l1_idx] {
            let l2_ptr = l2_frame.0 as *mut u64;
            ptr::write_volatile(l2_ptr.add(l2_idx), 0);
        }
    }
}

impl Drop for AddressSpace {
    fn drop(&mut self) {
        // Free L2 tables
        for l2 in self.l2_tables.iter() {
            if let Some(frame) = l2 {
                free_frame(*frame);
            }
        }
        // Free L1 table
        free_frame(self.ttbr0);
    }
}

/// Create a 2MB block descriptor with the given flags
fn make_block_entry(paddr: u64, flags: PageFlags) -> u64 {
    const VALID: u64 = 1 << 0;
    const BLOCK: u64 = 0 << 1;
    const AF: u64 = 1 << 10;
    const SH_INNER: u64 = 0b11 << 8;
    const UXN: u64 = 1 << 54;
    const PXN: u64 = 1 << 53;

    let mut entry = VALID | BLOCK | AF | SH_INNER;

    // Memory attribute index
    entry |= flags.mattr << 2;

    // Address (2MB aligned)
    entry |= paddr & 0x0000_FFFF_FFE0_0000;

    // Access permissions
    if flags.user {
        // AP[2:1] = 01 for user read-only, 00 for user read-write
        if !flags.writable {
            entry |= 0b01 << 6; // Read-only
        }
        // For user-accessible, AP[2:1] = 01 (EL0 read-only) or 00 (EL0/1 read-write)
    } else {
        // Kernel-only
        if !flags.writable {
            entry |= 0b10 << 6; // EL1 read-only
        }
    }

    // Execute permissions
    if !flags.executable || flags.user {
        entry |= PXN; // No kernel execute
    }
    if !flags.executable || !flags.user {
        entry |= UXN; // No user execute
    }

    entry
}

/// Read current TTBR0_EL1
#[inline]
unsafe fn read_ttbr0_el1() -> u64 {
    let val: u64;
    core::arch::asm!(
        "mrs {}, ttbr0_el1",
        out(reg) val,
        options(nostack, preserves_flags)
    );
    val
}

/// Write TTBR0_EL1
#[inline]
pub unsafe fn write_ttbr0_el1(val: u64) {
    core::arch::asm!(
        "msr ttbr0_el1, {}",
        "isb",
        in(reg) val,
        options(nostack, preserves_flags)
    );
}

/// Invalidate TLB
#[inline]
pub unsafe fn invalidate_tlb() {
    core::arch::asm!(
        "tlbi vmalle1",
        "dsb ish",
        "isb",
        options(nostack, preserves_flags)
    );
}
