//! Per-task address space management
//!
//! Each process has its own address space with:
//! - Separate user-space mappings (TTBR0_EL1)
//! - Shared kernel mappings (copied from kernel page table)

use super::frame::{alloc_frame, free_frame, PhysAddr, PAGE_SIZE};
use super::paging::{PageTableEntry, MATTR_NORMAL, MATTR_DEVICE, ENTRIES_PER_TABLE, l1_index, l2_index, l3_index, BLOCK_SIZE_2MB};
use super::KERNEL_VIRT_OFFSET; // Import KERNEL_VIRT_OFFSET
use core::ptr;
use alloc::vec::Vec; // For AddressSpaceBuilder

/// AddressSpaceBuilder is a helper struct to manage allocated frames during
/// the cloning of an AddressSpace. Its Drop implementation ensures that
/// any partially allocated resources are freed if the build process fails.
struct AddressSpaceBuilder {
    ttbr0: Option<PhysAddr>,
    l2_tables: Vec<PhysAddr>,
    l3_tables: Vec<PhysAddr>,
    data_pages: Vec<PhysAddr>, // For copied user data pages
}

impl AddressSpaceBuilder {
    fn new() -> Self {
        Self {
            ttbr0: None,
            l2_tables: Vec::new(),
            l3_tables: Vec::new(),
            data_pages: Vec::new(),
        }
    }

    /// Convert the builder into a complete AddressSpace, consuming itself.
    fn build(self, l2_arr: [Option<PhysAddr>; MAX_L1_ENTRIES], l3_arr: [Option<PhysAddr>; L3_TABLES_COUNT]) -> AddressSpace {
        let ttbr0 = self.ttbr0.expect("TTBR0 should be set for a successful build");

        // Transfer data_pages to data_blocks array
        let mut data_blocks = [None; MAX_DATA_BLOCKS];
        for (i, page) in self.data_pages.iter().enumerate() {
            if i < MAX_DATA_BLOCKS {
                data_blocks[i] = Some(*page);
            }
        }

        // Don't free resources when dropped, as ownership is transferred
        core::mem::forget(self);
        AddressSpace {
            ttbr0,
            l2_tables: l2_arr,
            l3_tables: l3_arr,
            data_blocks,
        }
    }
}

impl Drop for AddressSpaceBuilder {
    fn drop(&mut self) {
        if let Some(ttbr0_frame) = self.ttbr0 {
            free_frame(ttbr0_frame);
        }
        for frame in self.l2_tables.iter() {
            free_frame(*frame);
        }
        for frame in self.l3_tables.iter() {
            free_frame(*frame);
        }
        for frame in self.data_pages.iter() {
            free_frame(*frame);
        }
    }
}

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

    /// User-accessible device memory (for servers that need MMIO access)
    pub const fn user_device() -> Self {
        Self {
            mattr: MATTR_DEVICE,
            writable: true,
            executable: false,
            user: true,
        }
    }

    /// User code and data (RWX) - used when 2MB blocks contain both
    /// executable code and writable data sections.
    /// Note: W+X is less secure but required for 2MB granularity with mixed segments
    pub const fn user_code_data() -> Self {
        Self {
            mattr: MATTR_NORMAL,
            writable: true,
            executable: true,
            user: true,
        }
    }
}

/// Maximum L1 entries we track (4GB address space)
const MAX_L1_ENTRIES: usize = 4;

/// Only track L3 tables for L1[0] (user space), not for kernel RAM (L1[1-3])
/// This reduces struct size from ~32KB to ~8KB
const L3_TABLES_COUNT: usize = ENTRIES_PER_TABLE; // 512 entries for L1[0] only

/// Maximum number of 2MB data blocks tracked per address space
const MAX_DATA_BLOCKS: usize = 16;

/// Per-task address space
pub struct AddressSpace {
    /// L1 page table physical address (TTBR0_EL1)
    ttbr0: PhysAddr,
    /// L2 tables (up to 4 for 4GB address space with 1GB per L1 entry)
    l2_tables: [Option<PhysAddr>; MAX_L1_ENTRIES],
    /// L3 tables for L1[0] only (user space region 0x00000000-0x40000000)
    /// Only allocated when 4KB mapping is needed in that 2MB region
    /// Index = l2_idx (0-511)
    l3_tables: [Option<PhysAddr>; L3_TABLES_COUNT],
    /// 2MB data blocks owned by this address space (freed on drop)
    data_blocks: [Option<PhysAddr>; MAX_DATA_BLOCKS],
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

        let addr_space = Self {
            ttbr0: l1_frame,
            l2_tables: [None; MAX_L1_ENTRIES],
            l3_tables: [None; L3_TABLES_COUNT],
            data_blocks: [None; MAX_DATA_BLOCKS],
        };

        // Clone kernel mappings from the kernel's TTBR0
        // We copy the L1 entries that map kernel space (0x40000000 and above)
        let kernel_ttbr0 = super::kernel_ttbr0();
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
            l2_tables: [None; MAX_L1_ENTRIES],
            l3_tables: [None; L3_TABLES_COUNT],
            data_blocks: [None; MAX_DATA_BLOCKS],
        };

        // Allocate new L2 tables with necessary mappings
        // L1[0] covers 0x00000000 - 0x40000000 (device region + user space)
        // L1[1] covers 0x40000000 - 0x80000000 (RAM)

        // For L1[0]: Create new L2 table with device mappings (GIC, UART)
        // We create it from scratch to avoid read-from-kernel-memory issues
        const GIC_BASE: u64 = 0x0800_0000;
        const UART_BASE: u64 = 0x0900_0000;

        let l2_0_frame = alloc_frame()?;
        let l2_0_ptr = l2_0_frame.0 as *mut u64;

        // Zero all entries first
        for i in 0..ENTRIES_PER_TABLE {
            ptr::write_volatile(l2_0_ptr.add(i), 0);
        }

        // Map GIC at index 64 (0x08000000 >> 21 = 64)
        let gic_l2_idx = l2_index(GIC_BASE as usize);
        let gic_entry = PageTableEntry::block_2mb_device(GIC_BASE);
        ptr::write_volatile(l2_0_ptr.add(gic_l2_idx), gic_entry.raw());

        // Map UART at index 72 (0x09000000 >> 21 = 72)
        let uart_l2_idx = l2_index(UART_BASE as usize);
        let uart_entry = PageTableEntry::block_2mb_device(UART_BASE);
        ptr::write_volatile(l2_0_ptr.add(uart_l2_idx), uart_entry.raw());

        // Set L1[0] to point to our new L2 table
        let l1_0_entry = PageTableEntry::table(l2_0_frame.0 as u64);
        ptr::write_volatile(l1_ptr.add(0), l1_0_entry.as_u64());
        addr_space.l2_tables[0] = Some(l2_0_frame);

        // For L1[1]: Create a fresh L2 RAM table with identity mapping
        // We create it from scratch to avoid any read-from-kernel-memory issues
        // RAM region: 0x40000000 - 0x80000000 (512 * 2MB blocks)
        const RAM_START: u64 = 0x4000_0000;
        const BLOCK_SIZE_2MB: u64 = 2 * 1024 * 1024;

        let l2_1_frame = alloc_frame()?;
        let l2_1_ptr = l2_1_frame.0 as *mut u64;

        // Initialize all 512 entries for the RAM region
        for i in 0..512 {
            let paddr = RAM_START + (i as u64 * BLOCK_SIZE_2MB);
            let entry = PageTableEntry::block_2mb_normal(paddr);
            ptr::write_volatile(l2_1_ptr.add(i), entry.raw());
        }

        // Set L1[1] to point to our new L2 table
        let l1_1_entry = PageTableEntry::table(l2_1_frame.0 as u64);
        ptr::write_volatile(l1_ptr.add(1), l1_1_entry.as_u64());
        addr_space.l2_tables[1] = Some(l2_1_frame);

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

    /// Get a reference to the array of L2 table physical addresses.
    pub fn get_l2_tables(&self) -> &[Option<PhysAddr>; MAX_L1_ENTRIES] {
        &self.l2_tables
    }

    /// Get a reference to the array of L3 table physical addresses.
    pub fn get_l3_tables(&self) -> &[Option<PhysAddr>; L3_TABLES_COUNT] {
        &self.l3_tables
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

    /// Track a 2MB data block for cleanup on drop
    /// Returns true if the block was successfully tracked, false if no slots available
    pub fn track_data_block(&mut self, paddr: PhysAddr) -> bool {
        for slot in self.data_blocks.iter_mut() {
            if slot.is_none() {
                *slot = Some(paddr);
                return true;
            }
        }
        false
    }

    /// Helper to compute flat index for l3_tables array
    #[inline]
    fn l3_table_index(l1_idx: usize, l2_idx: usize) -> usize {
        l1_idx * ENTRIES_PER_TABLE + l2_idx
    }

    /// Map a single 4KB page at the given virtual address
    ///
    /// This allocates an L3 table if needed and creates a 4KB page mapping.
    /// Cannot mix with 2MB block mappings in the same 2MB region.
    ///
    /// # Safety
    /// The caller must ensure the physical address is valid
    pub unsafe fn map_4kb(&mut self, vaddr: usize, paddr: PhysAddr, flags: PageFlags) -> bool {
        let l1_idx = l1_index(vaddr);
        let l2_idx = l2_index(vaddr);
        let l3_idx = l3_index(vaddr);

        // Bounds check
        if l1_idx >= MAX_L1_ENTRIES {
            return false;
        }

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

        let l2_frame = self.l2_tables[l1_idx].unwrap();
        let l2_ptr = l2_frame.0 as *mut u64;

        // Read current L2 entry
        let l2_entry_val = ptr::read_volatile(l2_ptr.add(l2_idx));

        // Check if L2 entry is already a 2MB block (can't mix with 4KB pages)
        // Valid bit set (bit 0) and block type (bit 1 = 0)
        if l2_entry_val != 0 && (l2_entry_val & 0b10) == 0 {
            // It's a valid block descriptor, can't add 4KB pages here
            return false;
        }

        // Ensure L3 table exists for this 2MB region
        let l3_table_idx = Self::l3_table_index(l1_idx, l2_idx);
        if self.l3_tables[l3_table_idx].is_none() {
            let l3_frame = alloc_frame();
            if l3_frame.is_none() {
                return false;
            }
            let l3_frame = l3_frame.unwrap();

            // Zero the L3 table
            ptr::write_bytes(l3_frame.0 as *mut u8, 0, PAGE_SIZE);
            self.l3_tables[l3_table_idx] = Some(l3_frame);

            // Update L2 entry to point to L3 table
            let l2_table_entry = PageTableEntry::table(l3_frame.0 as u64);
            ptr::write_volatile(l2_ptr.add(l2_idx), l2_table_entry.as_u64());
        }

        // Write L3 entry (4KB page descriptor)
        let l3_frame = self.l3_tables[l3_table_idx].unwrap();
        let l3_ptr = l3_frame.0 as *mut u64;
        let entry = make_page_entry(paddr.0 as u64, flags);
        ptr::write_volatile(l3_ptr.add(l3_idx), entry);

        true
    }

    /// Unmap a single 4KB page at the given virtual address
    pub unsafe fn unmap_4kb(&mut self, vaddr: usize) {
        let l1_idx = l1_index(vaddr);
        let l2_idx = l2_index(vaddr);
        let l3_idx = l3_index(vaddr);

        if l1_idx >= MAX_L1_ENTRIES {
            return;
        }

        let l3_table_idx = Self::l3_table_index(l1_idx, l2_idx);
        if let Some(l3_frame) = self.l3_tables[l3_table_idx] {
            let l3_ptr = l3_frame.0 as *mut u64;
            ptr::write_volatile(l3_ptr.add(l3_idx), 0); // Invalid entry
        }
    }

    /// Translate a virtual address to its physical address
    ///
    /// Returns None if the address is not mapped.
    /// Only works for 4KB pages in the mmap region (assumes L3 table exists).
    pub fn virt_to_phys(&self, vaddr: usize) -> Option<PhysAddr> {
        let l1_idx = l1_index(vaddr);
        let l2_idx = l2_index(vaddr);
        let l3_idx = l3_index(vaddr);

        if l1_idx >= MAX_L1_ENTRIES {
            return None;
        }

        let l3_table_idx = Self::l3_table_index(l1_idx, l2_idx);
        let l3_frame = self.l3_tables[l3_table_idx]?;

        // Read the L3 entry
        unsafe {
            let l3_ptr = l3_frame.0 as *const u64;
            let entry = ptr::read_volatile(l3_ptr.add(l3_idx));

            // Check if entry is valid (bit 0 set)
            if entry & 1 == 0 {
                return None;
            }

            // Extract physical address (bits 47:12 contain the physical frame number)
            let phys_addr = (entry & 0x0000_FFFF_FFFF_F000) as usize;
            // Add the page offset
            let offset = vaddr & 0xFFF;
            Some(PhysAddr(phys_addr + offset))
        }
    }

    /// Creates a new AddressSpace by duplicating an existing one for a fork operation.
    ///
    /// This performs a deep copy of user-space mappings and their underlying
    /// physical memory, but shares kernel mappings.
    ///
    /// # Safety
    /// - Requires proper memory management (alloc_frame, free_frame).
    /// - Assumes the kernel mappings (0xC000_0000 and above) are shared.
    pub unsafe fn clone_for_fork(parent_as: &AddressSpace) -> Option<Self> {
        let mut builder = AddressSpaceBuilder::new();
        let mut child_l2_tables_arr: [Option<PhysAddr>; MAX_L1_ENTRIES] = [None; MAX_L1_ENTRIES];
        let mut child_l3_tables_arr: [Option<PhysAddr>; L3_TABLES_COUNT] = [None; L3_TABLES_COUNT];

        // 1. Allocate new L1 table for the child
        let child_l1_frame = alloc_frame()?;
        builder.ttbr0 = Some(child_l1_frame); // Track L1 table in builder
        let child_l1_ptr = (child_l1_frame.0) as *mut PageTableEntry;
        
        // Zero out the new L1 table
        for i in 0..ENTRIES_PER_TABLE {
            ptr::write_volatile(child_l1_ptr.add(i), PageTableEntry::invalid());
        }

        // Get parent's L1 table
        let parent_l1_ptr = (parent_as.ttbr0.0) as *const PageTableEntry;

        // --- Re-create initial device and RAM mappings for L1[0] and L1[1] ---
        const GIC_BASE: u64 = 0x0800_0000;
        const UART_BASE: u64 = 0x0900_0000;
        const RAM_START: u64 = 0x4000_0000;

        // For L1[0]: Create new L2 table with device mappings (GIC, UART)
        let child_l2_0_frame = alloc_frame()?;
        builder.l2_tables.push(child_l2_0_frame); // Track L2 table in builder
        let child_l2_0_ptr = (child_l2_0_frame.0) as *mut PageTableEntry;
        for i in 0..ENTRIES_PER_TABLE {
            ptr::write_volatile(child_l2_0_ptr.add(i), PageTableEntry::invalid());
        }
        
        let gic_l2_idx = l2_index(GIC_BASE as usize);
        let gic_entry = PageTableEntry::block_2mb_device(GIC_BASE);
        ptr::write_volatile(child_l2_0_ptr.add(gic_l2_idx), gic_entry);

        let uart_l2_idx = l2_index(UART_BASE as usize);
        let uart_entry = PageTableEntry::block_2mb_device(UART_BASE);
        ptr::write_volatile(child_l2_0_ptr.add(uart_l2_idx), uart_entry);

        let l1_0_entry = PageTableEntry::table(child_l2_0_frame.0 as u64);
        ptr::write_volatile(child_l1_ptr.add(0), l1_0_entry);
        child_l2_tables_arr[0] = Some(child_l2_0_frame);

        // For L1[1]: Create a fresh L2 RAM table with identity mapping
        let child_l2_1_frame = alloc_frame()?;
        builder.l2_tables.push(child_l2_1_frame); // Track L2 table in builder
        let child_l2_1_ptr = (child_l2_1_frame.0) as *mut PageTableEntry;
        for i in 0..ENTRIES_PER_TABLE {
            ptr::write_volatile(child_l2_1_ptr.add(i), PageTableEntry::invalid());
        }

        for i in 0..512 {
            let paddr = RAM_START + (i as u64 * BLOCK_SIZE_2MB as u64);
            let entry = PageTableEntry::block_2mb_normal(paddr);
            ptr::write_volatile(child_l2_1_ptr.add(i), entry);
        }
        let l1_1_entry = PageTableEntry::table(child_l2_1_frame.0 as u64);
        ptr::write_volatile(child_l1_ptr.add(1), l1_1_entry);
        child_l2_tables_arr[1] = Some(child_l2_1_frame);
        // --- End of re-creation ---


        // Now, deep copy user space mappings in L1[0] only (0x00000000 - 0x40000000)
        // L1[1] (RAM identity mapping) is shared and was already set up above
        // We only need to copy the user data blocks in L1[0]
        for l1_idx in 0..1 {  // Only L1[0] contains user-specific data
            let parent_l1_entry = ptr::read_volatile(parent_l1_ptr.add(l1_idx));

            if parent_l1_entry.is_valid() && parent_l1_entry.is_table() { // Parent has an L2 table
                let parent_l2_frame = parent_as.l2_tables[l1_idx].unwrap(); // Assume it's tracked
                let parent_l2_ptr = (parent_l2_frame.0) as *const PageTableEntry;

                let child_l2_frame = alloc_frame()?; // New L2 table for child
                builder.l2_tables.push(child_l2_frame); // Track L2 table
                let child_l2_ptr = (child_l2_frame.0) as *mut PageTableEntry;
                for i in 0..ENTRIES_PER_TABLE {
                    ptr::write_volatile(child_l2_ptr.add(i), PageTableEntry::invalid());
                }
                let child_l1_entry = PageTableEntry::table(child_l2_frame.0 as u64);
                ptr::write_volatile(child_l1_ptr.add(l1_idx), child_l1_entry);
                child_l2_tables_arr[l1_idx] = Some(child_l2_frame);


                for l2_idx in 0..ENTRIES_PER_TABLE {
                    let parent_l2_entry = ptr::read_volatile(parent_l2_ptr.add(l2_idx));

                    if parent_l2_entry.is_valid() {
                        if parent_l2_entry.is_table() { // Parent has an L3 table
                            let parent_l3_frame = parent_as.l3_tables[AddressSpace::l3_table_index(l1_idx, l2_idx)].unwrap(); // Assume tracked
                            let parent_l3_ptr = (parent_l3_frame.0) as *const PageTableEntry;

                            let child_l3_frame = alloc_frame()?; // New L3 table for child
                            builder.l3_tables.push(child_l3_frame); // Track L3 table
                            let child_l3_ptr = (child_l3_frame.0) as *mut PageTableEntry;
                            for i in 0..ENTRIES_PER_TABLE {
                                ptr::write_volatile(child_l3_ptr.add(i), PageTableEntry::invalid());
                            }
                            let child_l2_entry = PageTableEntry::table(child_l3_frame.0 as u64);
                            ptr::write_volatile(child_l2_ptr.add(l2_idx), child_l2_entry);
                            child_l3_tables_arr[AddressSpace::l3_table_index(l1_idx, l2_idx)] = Some(child_l3_frame);

                            for l3_idx in 0..ENTRIES_PER_TABLE {
                                let parent_l3_entry = ptr::read_volatile(parent_l3_ptr.add(l3_idx));

                                if parent_l3_entry.is_valid() && parent_l3_entry.is_page() {
                                    // It's a 4KB page, deep copy its content
                                    let parent_paddr = PhysAddr(parent_l3_entry.table_addr() as usize);
                                    let child_paddr = alloc_frame()?; // New physical page for child
                                    builder.data_pages.push(child_paddr); // Track data page

                                    // Copy content
                                    let parent_kvaddr = (parent_paddr.0) as *const u8;
                                    let child_kvaddr = (child_paddr.0) as *mut u8;
                                    ptr::copy_nonoverlapping(parent_kvaddr, child_kvaddr, PAGE_SIZE);

                                    // Create new L3 entry for child with reconstructed flags
                                    let child_l3_entry = make_page_entry(child_paddr.0 as u64, parent_l3_entry.page_flags());
                                    ptr::write_volatile(child_l3_ptr.add(l3_idx), PageTableEntry(child_l3_entry));
                                }
                            }
                        } else if parent_l2_entry.is_block() { // Parent has a 2MB block mapping
                            let parent_paddr_2mb = PhysAddr(parent_l2_entry.table_addr() as usize);

                            // Skip device memory regions (below RAM_START).
                            // Device mappings are already set up earlier and shouldn't be copied.
                            if parent_paddr_2mb.0 < RAM_START as usize {
                                // Just copy the entry as-is for device memory (shared mapping)
                                ptr::write_volatile(child_l2_ptr.add(l2_idx), parent_l2_entry);
                                continue;
                            }

                            // Allocate contiguous frames for a 2MB block for the child
                            let child_paddr_2mb = super::frame::alloc_frames_in_2mb_block(BLOCK_SIZE_2MB / PAGE_SIZE)?;
                            builder.data_pages.push(child_paddr_2mb);

                            // Copy content of the 2MB block
                            let parent_kvaddr_2mb = (parent_paddr_2mb.0) as *const u8;
                            let child_kvaddr_2mb = (child_paddr_2mb.0) as *mut u8;
                            ptr::copy_nonoverlapping(parent_kvaddr_2mb, child_kvaddr_2mb, BLOCK_SIZE_2MB);

                            // Create new L2 block entry for child with reconstructed flags
                            let child_l2_entry = make_block_entry(child_paddr_2mb.0 as u64, parent_l2_entry.page_flags());
                            ptr::write_volatile(child_l2_ptr.add(l2_idx), PageTableEntry(child_l2_entry));
                        }
                    }
                }
            }
        }

        Some(builder.build(child_l2_tables_arr, child_l3_tables_arr))
    }

}

impl Drop for AddressSpace {
    fn drop(&mut self) {
        // Free data blocks (2MB blocks of user data)
        for block in self.data_blocks.iter() {
            if let Some(block_addr) = block {
                // Each 2MB block = 512 pages of 4KB each
                for i in 0..512 {
                    free_frame(PhysAddr(block_addr.0 + i * 4096));
                }
            }
        }
        // Free L3 tables
        for l3 in self.l3_tables.iter() {
            if let Some(frame) = l3 {
                free_frame(*frame);
            }
        }
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

    // Access permissions (AP[2:1] bits at position [7:6])
    // AArch64 AP encoding for stage 1:
    //   00: EL1 R/W, EL0 no access
    //   01: EL1 R/W, EL0 R/W
    //   10: EL1 R/O, EL0 no access
    //   11: EL1 R/O, EL0 R/O
    if flags.user {
        if flags.writable {
            entry |= 0b01 << 6; // EL0/EL1 read-write
        } else {
            entry |= 0b11 << 6; // EL0/EL1 read-only
        }
    } else {
        // Kernel-only (EL0 no access)
        if !flags.writable {
            entry |= 0b10 << 6; // EL1 read-only
        }
        // writable kernel: AP = 00 (EL1 R/W, EL0 no access)
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

/// Create a 4KB page descriptor with the given flags (for L3 entries)
///
/// L3 page descriptors use bits [1:0] = 0b11 (valid + page type)
fn make_page_entry(paddr: u64, flags: PageFlags) -> u64 {
    const VALID: u64 = 1 << 0;
    const PAGE: u64 = 1 << 1;  // L3 page type (bit 1 = 1)
    const AF: u64 = 1 << 10;
    const SH_INNER: u64 = 0b11 << 8;
    const UXN: u64 = 1 << 54;
    const PXN: u64 = 1 << 53;

    let mut entry = VALID | PAGE | AF | SH_INNER;

    // Memory attribute index
    entry |= flags.mattr << 2;

    // Address (4KB aligned)
    entry |= paddr & 0x0000_FFFF_FFFF_F000;

    // Access permissions (same encoding as block entries)
    if flags.user {
        if flags.writable {
            entry |= 0b01 << 6; // EL0/EL1 read-write
        } else {
            entry |= 0b11 << 6; // EL0/EL1 read-only
        }
    } else {
        if !flags.writable {
            entry |= 0b10 << 6; // EL1 read-only
        }
    }

    // Execute permissions
    if !flags.executable || flags.user {
        entry |= PXN;
    }
    if !flags.executable || !flags.user {
        entry |= UXN;
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
