//! Shared Memory (SHM) support for Kenix
//!
//! Provides shared memory regions that can be mapped into multiple task
//! address spaces for high-bandwidth IPC.
//!
//! Syscalls:
//! - sys_shmcreate(size) -> shm_id: Create a new shared memory region
//! - sys_shmmap(shm_id, vaddr_hint) -> vaddr: Map region into current task
//! - sys_shmunmap(shm_id) -> result: Unmap region from current task
//! - sys_shmgrant(shm_id, task_id) -> result: Grant another task access

use crate::mm::frame::{alloc_frame, free_frame, PhysAddr, PAGE_SIZE};
use crate::sched::{TaskId, current};
use crate::sched::task::{TASKS, MAX_TASKS, TaskState};
use core::ptr;

/// Maximum number of shared memory regions
pub const MAX_SHM_REGIONS: usize = 64;

/// Maximum pages per shared memory region (256 pages = 1MB max)
const MAX_SHM_PAGES: usize = 256;

/// Base virtual address for shared memory mappings
/// This is in the user address space, after code and stack regions
const SHM_VADDR_BASE: usize = 0x0100_0000; // 16MB

/// Shared memory region ID
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShmId(pub usize);

/// Error codes for shared memory operations
pub const SHM_OK: i64 = 0;
pub const SHM_ERR_INVALID: i64 = -1;
pub const SHM_ERR_NO_MEMORY: i64 = -2;
pub const SHM_ERR_PERMISSION: i64 = -3;
pub const SHM_ERR_ALREADY_MAPPED: i64 = -4;
pub const SHM_ERR_NOT_MAPPED: i64 = -5;
pub const SHM_ERR_NO_SLOTS: i64 = -6;

/// Shared memory region descriptor
pub struct ShmRegion {
    /// Whether this slot is in use
    pub in_use: bool,
    /// Region ID
    pub id: ShmId,
    /// Physical frames backing this region (4KB each)
    pub frames: [Option<PhysAddr>; MAX_SHM_PAGES],
    /// Number of allocated frames
    pub num_frames: usize,
    /// Total size in bytes (rounded up to 4KB)
    pub size: usize,
    /// Owner task ID (creator)
    pub owner: TaskId,
    /// Which tasks have been granted access
    pub granted: [bool; MAX_TASKS],
    /// Mapped virtual address per task (None if not mapped)
    pub mapped_vaddr: [Option<usize>; MAX_TASKS],
}

impl ShmRegion {
    /// Create an empty region slot
    pub const fn empty() -> Self {
        Self {
            in_use: false,
            id: ShmId(0),
            frames: [None; MAX_SHM_PAGES],
            num_frames: 0,
            size: 0,
            owner: TaskId(0),
            granted: [false; MAX_TASKS],
            mapped_vaddr: [None; MAX_TASKS],
        }
    }
}

/// Global shared memory region table
pub static mut SHM_REGIONS: [ShmRegion; MAX_SHM_REGIONS] = {
    const EMPTY: ShmRegion = ShmRegion::empty();
    [EMPTY; MAX_SHM_REGIONS]
};

/// Next virtual address hint for each task (for auto-allocation)
static mut NEXT_SHM_VADDR: [usize; MAX_TASKS] = [SHM_VADDR_BASE; MAX_TASKS];

/// Find a free shared memory region slot
fn find_free_shm_slot() -> Option<usize> {
    unsafe {
        for (i, region) in SHM_REGIONS.iter().enumerate() {
            if !region.in_use {
                return Some(i);
            }
        }
    }
    None
}

/// Create a new shared memory region
///
/// # Arguments
/// * `size` - Size in bytes (will be rounded up to 4KB alignment)
///
/// # Returns
/// * `ShmId` on success, negative error code on failure
pub fn sys_shmcreate(size: usize) -> i64 {
    let owner = match current() {
        Some(id) => id,
        None => return SHM_ERR_INVALID,
    };

    if size == 0 {
        return SHM_ERR_INVALID;
    }

    // Round up to 4KB pages
    let size_aligned = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let num_pages = size_aligned / PAGE_SIZE;

    if num_pages > MAX_SHM_PAGES {
        return SHM_ERR_NO_MEMORY;
    }

    // Find a free slot
    let slot_idx = match find_free_shm_slot() {
        Some(idx) => idx,
        None => return SHM_ERR_NO_SLOTS,
    };

    unsafe {
        let region = &mut SHM_REGIONS[slot_idx];

        // Allocate physical frames
        for i in 0..num_pages {
            match alloc_frame() {
                Some(frame) => {
                    // Zero the frame
                    ptr::write_bytes(frame.0 as *mut u8, 0, PAGE_SIZE);
                    region.frames[i] = Some(frame);
                }
                None => {
                    // Allocation failed, free already allocated frames
                    for j in 0..i {
                        if let Some(f) = region.frames[j] {
                            free_frame(f);
                            region.frames[j] = None;
                        }
                    }
                    return SHM_ERR_NO_MEMORY;
                }
            }
        }

        // Initialize the region
        region.in_use = true;
        region.id = ShmId(slot_idx);
        region.num_frames = num_pages;
        region.size = size_aligned;
        region.owner = owner;

        // Grant owner access
        region.granted[owner.0] = true;

        // Return the region ID
        slot_idx as i64
    }
}

/// Map a shared memory region into the current task's address space
///
/// # Arguments
/// * `shm_id` - Shared memory region ID
/// * `vaddr_hint` - Suggested virtual address (0 for auto-allocation, must be 4KB aligned)
///
/// # Returns
/// * Virtual address on success, negative error code on failure
pub fn sys_shmmap(shm_id: usize, vaddr_hint: usize) -> i64 {
    let task_id = match current() {
        Some(id) => id,
        None => return SHM_ERR_INVALID,
    };

    if shm_id >= MAX_SHM_REGIONS {
        return SHM_ERR_INVALID;
    }

    unsafe {
        let region = &mut SHM_REGIONS[shm_id];

        if !region.in_use {
            return SHM_ERR_INVALID;
        }

        // Check permission
        if !region.granted[task_id.0] {
            return SHM_ERR_PERMISSION;
        }

        // Check if already mapped
        if region.mapped_vaddr[task_id.0].is_some() {
            return SHM_ERR_ALREADY_MAPPED;
        }

        // Determine virtual address
        let vaddr = if vaddr_hint != 0 {
            // Use hint (4KB aligned)
            vaddr_hint & !(PAGE_SIZE - 1)
        } else {
            // Auto-allocate
            let addr = NEXT_SHM_VADDR[task_id.0];
            NEXT_SHM_VADDR[task_id.0] += region.size;
            addr
        };

        // Get the task's page table
        let task = &mut TASKS[task_id.0];
        if task.state == TaskState::Free {
            return SHM_ERR_INVALID;
        }

        let page_table_addr = task.page_table.0;
        if page_table_addr == 0 {
            return SHM_ERR_INVALID;
        }

        // Map each frame as a 4KB page
        // We need to directly manipulate the page tables since we can't easily
        // get a mutable reference to the AddressSpace
        for i in 0..region.num_frames {
            if let Some(frame) = region.frames[i] {
                let page_vaddr = vaddr + i * PAGE_SIZE;
                if !map_4kb_direct(page_table_addr, page_vaddr, frame) {
                    // Unmap already mapped pages on failure
                    for j in 0..i {
                        let unmap_vaddr = vaddr + j * PAGE_SIZE;
                        unmap_4kb_direct(page_table_addr, unmap_vaddr);
                    }
                    return SHM_ERR_NO_MEMORY;
                }
            }
        }

        // Record the mapping
        region.mapped_vaddr[task_id.0] = Some(vaddr);

        vaddr as i64
    }
}

/// Unmap a shared memory region from the current task's address space
///
/// # Arguments
/// * `shm_id` - Shared memory region ID
///
/// # Returns
/// * 0 on success, negative error code on failure
pub fn sys_shmunmap(shm_id: usize) -> i64 {
    let task_id = match current() {
        Some(id) => id,
        None => return SHM_ERR_INVALID,
    };

    if shm_id >= MAX_SHM_REGIONS {
        return SHM_ERR_INVALID;
    }

    unsafe {
        let region = &mut SHM_REGIONS[shm_id];

        if !region.in_use {
            return SHM_ERR_INVALID;
        }

        // Check if mapped
        let vaddr = match region.mapped_vaddr[task_id.0] {
            Some(v) => v,
            None => return SHM_ERR_NOT_MAPPED,
        };

        // Get task's page table
        let task = &TASKS[task_id.0];
        let page_table_addr = task.page_table.0;

        if page_table_addr != 0 {
            // Unmap each page
            for i in 0..region.num_frames {
                let page_vaddr = vaddr + i * PAGE_SIZE;
                unmap_4kb_direct(page_table_addr, page_vaddr);
            }
        }

        // Clear mapping record
        region.mapped_vaddr[task_id.0] = None;

        // Invalidate TLB
        invalidate_tlb();

        SHM_OK
    }
}

/// Grant another task permission to map the shared memory region
///
/// # Arguments
/// * `shm_id` - Shared memory region ID
/// * `target_task` - Task ID to grant access to
///
/// # Returns
/// * 0 on success, negative error code on failure
pub fn sys_shmgrant(shm_id: usize, target_task: usize) -> i64 {
    let caller = match current() {
        Some(id) => id,
        None => return SHM_ERR_INVALID,
    };

    if shm_id >= MAX_SHM_REGIONS || target_task >= MAX_TASKS {
        return SHM_ERR_INVALID;
    }

    unsafe {
        let region = &mut SHM_REGIONS[shm_id];

        if !region.in_use {
            return SHM_ERR_INVALID;
        }

        // Only owner can grant access
        if region.owner != caller {
            return SHM_ERR_PERMISSION;
        }

        // Check target task exists
        let target = &TASKS[target_task];
        if target.state == TaskState::Free {
            return SHM_ERR_INVALID;
        }

        region.granted[target_task] = true;

        SHM_OK
    }
}

/// Direct 4KB page mapping without AddressSpace struct
///
/// This directly manipulates page tables given the L1 table address.
unsafe fn map_4kb_direct(l1_addr: usize, vaddr: usize, paddr: PhysAddr) -> bool {
    use crate::mm::paging::{l1_index, l2_index, l3_index, PageTableEntry, ENTRIES_PER_TABLE};

    let l1_idx = l1_index(vaddr);
    let l2_idx = l2_index(vaddr);
    let l3_idx = l3_index(vaddr);

    let l1_ptr = l1_addr as *mut u64;

    // Get or create L2 table
    let l1_entry = ptr::read_volatile(l1_ptr.add(l1_idx));
    let l2_addr = if l1_entry == 0 {
        // Need to allocate L2 table
        let l2_frame = match alloc_frame() {
            Some(f) => f,
            None => return false,
        };
        ptr::write_bytes(l2_frame.0 as *mut u8, 0, PAGE_SIZE);
        let l1_new = PageTableEntry::table(l2_frame.0 as u64);
        ptr::write_volatile(l1_ptr.add(l1_idx), l1_new.as_u64());
        l2_frame.0
    } else {
        // L1 entry exists, extract L2 address
        (l1_entry & 0x0000_FFFF_FFFF_F000) as usize
    };

    let l2_ptr = l2_addr as *mut u64;

    // Get or create L3 table
    let l2_entry = ptr::read_volatile(l2_ptr.add(l2_idx));

    // Check if it's a 2MB block (can't mix with 4KB)
    if l2_entry != 0 && (l2_entry & 0b10) == 0 {
        return false; // Already a 2MB block
    }

    let l3_addr = if l2_entry == 0 {
        // Need to allocate L3 table
        let l3_frame = match alloc_frame() {
            Some(f) => f,
            None => return false,
        };
        ptr::write_bytes(l3_frame.0 as *mut u8, 0, PAGE_SIZE);
        let l2_new = PageTableEntry::table(l3_frame.0 as u64);
        ptr::write_volatile(l2_ptr.add(l2_idx), l2_new.as_u64());
        l3_frame.0
    } else {
        // L2 table entry exists, extract L3 address
        (l2_entry & 0x0000_FFFF_FFFF_F000) as usize
    };

    let l3_ptr = l3_addr as *mut u64;

    // Create 4KB page entry (user, writable, non-executable)
    let page_entry = make_page_entry_shm(paddr.0 as u64);
    ptr::write_volatile(l3_ptr.add(l3_idx), page_entry);

    true
}

/// Unmap a 4KB page directly given L1 table address
unsafe fn unmap_4kb_direct(l1_addr: usize, vaddr: usize) {
    use crate::mm::paging::{l1_index, l2_index, l3_index};

    let l1_idx = l1_index(vaddr);
    let l2_idx = l2_index(vaddr);
    let l3_idx = l3_index(vaddr);

    let l1_ptr = l1_addr as *mut u64;
    let l1_entry = ptr::read_volatile(l1_ptr.add(l1_idx));

    if l1_entry == 0 {
        return;
    }

    let l2_addr = (l1_entry & 0x0000_FFFF_FFFF_F000) as usize;
    let l2_ptr = l2_addr as *mut u64;
    let l2_entry = ptr::read_volatile(l2_ptr.add(l2_idx));

    if l2_entry == 0 || (l2_entry & 0b10) == 0 {
        return; // No L3 table or it's a 2MB block
    }

    let l3_addr = (l2_entry & 0x0000_FFFF_FFFF_F000) as usize;
    let l3_ptr = l3_addr as *mut u64;

    // Clear the L3 entry
    ptr::write_volatile(l3_ptr.add(l3_idx), 0);
}

/// Create a 4KB page entry for shared memory (user RW, non-executable)
fn make_page_entry_shm(paddr: u64) -> u64 {
    const VALID: u64 = 1 << 0;
    const PAGE: u64 = 1 << 1;
    const AF: u64 = 1 << 10;
    const SH_INNER: u64 = 0b11 << 8;
    const UXN: u64 = 1 << 54;
    const PXN: u64 = 1 << 53;
    const MATTR_NORMAL: u64 = 1;

    // User read-write, non-executable
    VALID | PAGE | AF | SH_INNER
        | (MATTR_NORMAL << 2)           // Normal memory
        | (paddr & 0x0000_FFFF_FFFF_F000) // 4KB aligned address
        | (0b01 << 6)                   // AP = EL0/EL1 R/W
        | UXN | PXN                     // Non-executable
}

/// Invalidate TLB
#[inline]
unsafe fn invalidate_tlb() {
    core::arch::asm!(
        "tlbi vmalle1",
        "dsb ish",
        "isb",
        options(nostack, preserves_flags)
    );
}
