//! AArch64 page table structures for 4KB granule
#![allow(dead_code)]
//!
//! Page table format for 4KB granule with 2MB blocks:
//! - L1 entry covers 1GB (512 * 2MB = 1GB)
//! - L2 entry covers 2MB blocks
//!
//! Entry format (for block descriptors):
//! [63:52] Upper attributes (UXN, PXN, etc.)
//! [51:48] Reserved
//! [47:21] Output address (2MB aligned for L2 blocks)
//! [20:12] Reserved (must be zero for blocks)
//! [11:2]  Lower attributes (AF, SH, AP, AttrIndx)
//! [1]     Type: 0=block, 1=table
//! [0]     Valid bit

use super::frame::PAGE_SIZE;

/// Memory attribute index for Device-nGnRnE (MAIR Attr0)
pub const MATTR_DEVICE: u64 = 0;
/// Memory attribute index for Normal Write-Back (MAIR Attr1)
pub const MATTR_NORMAL: u64 = 1;

/// Block descriptor flags
const VALID: u64 = 1 << 0;
const BLOCK: u64 = 0 << 1;  // Type bit: 0 = block
const TABLE: u64 = 1 << 1;  // Type bit: 1 = table

/// Access Flag (must be set to avoid access fault)
const AF: u64 = 1 << 10;

/// Shareability: Inner Shareable
const SH_INNER: u64 = 0b11 << 8;

/// Access Permissions: Read/Write at EL1
const AP_RW_EL1: u64 = 0b00 << 6;

/// Unprivileged Execute Never (block userspace execution)
const UXN: u64 = 1 << 54;

/// Privileged Execute Never
const PXN: u64 = 1 << 53;

/// Page table entry for AArch64 4KB granule
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct PageTableEntry(pub u64);

impl PageTableEntry {
    /// Create an invalid (empty) entry
    pub const fn invalid() -> Self {
        Self(0)
    }

    /// Create a 2MB block entry for Normal memory (RAM)
    /// AttrIndx = 1 (Normal Write-Back from MAIR Attr1)
    pub fn block_2mb_normal(paddr: u64) -> Self {
        let attr_indx = MATTR_NORMAL << 2;
        Self(
            VALID
                | BLOCK
                | (paddr & 0x0000_FFFF_FFE0_0000) // 2MB aligned address
                | attr_indx
                | AF
                | SH_INNER
                | AP_RW_EL1
                | UXN // No userspace execution
        )
    }

    /// Create a 2MB block entry for Device memory (UART, GIC)
    /// AttrIndx = 0 (Device-nGnRnE from MAIR Attr0)
    pub fn block_2mb_device(paddr: u64) -> Self {
        let attr_indx = MATTR_DEVICE << 2;
        Self(
            VALID
                | BLOCK
                | (paddr & 0x0000_FFFF_FFE0_0000) // 2MB aligned address
                | attr_indx
                | AF
                | AP_RW_EL1
                | UXN
                | PXN // No execution on device memory
        )
    }

    /// Create a table descriptor pointing to next level page table
    pub fn table(next_table_paddr: u64) -> Self {
        Self(
            VALID
                | TABLE
                | (next_table_paddr & 0x0000_FFFF_FFFF_F000) // 4KB aligned
        )
    }

    /// Check if entry is valid
    pub fn is_valid(&self) -> bool {
        (self.0 & VALID) != 0
    }

    /// Get raw value
    pub fn as_u64(&self) -> u64 {
        self.0
    }

    /// Get raw value (alias for as_u64)
    pub fn raw(&self) -> u64 {
        self.0
    }

    /// Check if entry is a table descriptor (bits [1:0] == 0b11 for non-L3)
    /// In L2, this means it points to an L3 table
    pub fn is_table(&self) -> bool {
        self.is_valid() && (self.0 & 0b10) != 0
    }

    /// Check if entry is a block descriptor (bits [1:0] == 0b01)
    /// In L2, this means a 2MB block mapping
    pub fn is_block(&self) -> bool {
        self.is_valid() && (self.0 & 0b10) == 0
    }

    /// Check if entry is a page descriptor (bits [1:0] == 0b11)
    /// In L3, this means a 4KB page mapping
    pub fn is_page(&self) -> bool {
        self.is_valid() && (self.0 & 0b10) != 0 // L3 uses type bit 1
    }

    /// Get the physical address from a table descriptor
    pub fn table_addr(&self) -> u64 {
        self.0 & 0x0000_FFFF_FFFF_F000
    }

    /// Extract the PageFlags from this entry
    pub fn page_flags(&self) -> super::address_space::PageFlags {
        let ap = (self.0 >> 6) & 0b11; // AP bits
        let uxn = (self.0 >> 54) & 1; // UXN bit
        let pxn = (self.0 >> 53) & 1; // PXN bit
        let mattr = (self.0 >> 2) & 0b111; // AttrIndx bits

        let user = match ap {
            0b00 => false, // EL1 R/W, EL0 no access
            0b01 => true,  // EL1 R/W, EL0 R/W
            0b10 => false, // EL1 R/O, EL0 no access
            0b11 => true,  // EL1 R/O, EL0 R/O
            _ => false, // Should not happen
        };

        let writable = match ap {
            0b00 | 0b01 => true, // R/W
            0b10 | 0b11 => false, // R/O
            _ => false,
        };

        let executable = !((uxn != 0 && user) || (pxn != 0 && !user));

        super::address_space::PageFlags {
            mattr,
            writable,
            executable,
            user,
        }
    }
}

/// 512 entries per table (4KB aligned, 4KB size)
#[repr(C, align(4096))]
pub struct PageTable {
    pub entries: [PageTableEntry; 512],
}

impl PageTable {
    /// Create an empty page table with all invalid entries
    pub const fn new() -> Self {
        Self {
            entries: [PageTableEntry::invalid(); 512],
        }
    }

    /// Zero all entries (useful for allocated tables)
    pub fn clear(&mut self) {
        for entry in self.entries.iter_mut() {
            *entry = PageTableEntry::invalid();
        }
    }
}

/// Size of a 2MB block
pub const BLOCK_SIZE_2MB: usize = 2 * 1024 * 1024;

/// Number of entries per page table
pub const ENTRIES_PER_TABLE: usize = 512;

/// Extract L1 index from virtual address (bits [38:30])
/// Each L1 entry covers 1GB (512 * 2MB)
#[inline]
pub fn l1_index(va: usize) -> usize {
    (va >> 30) & 0x1FF
}

/// Extract L2 index from virtual address (bits [29:21])
/// Each L2 entry covers 2MB
#[inline]
pub fn l2_index(va: usize) -> usize {
    (va >> 21) & 0x1FF
}

/// Extract L3 index from virtual address (bits [20:12])
/// Each L3 entry covers 4KB
#[inline]
pub fn l3_index(va: usize) -> usize {
    (va >> 12) & 0x1FF
}

/// Number of entries per L3 table (same as other levels)
pub const ENTRIES_PER_L3: usize = 512;

/// Size of a 4KB page
pub const PAGE_SIZE_4KB: usize = 4096;

// Compile-time checks
const _: () = assert!(core::mem::size_of::<PageTable>() == PAGE_SIZE);
const _: () = assert!(core::mem::align_of::<PageTable>() == PAGE_SIZE);
