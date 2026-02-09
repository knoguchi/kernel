//! Memory-mapped region management for anonymous mmap
//!
//! This module implements anonymous mmap with demand paging for user processes.
//! Key constraints:
//! - Only anonymous mappings (MAP_ANONYMOUS) - no file-backed mmap initially
//! - Use 4KB pages for mmap regions
//! - Track mmap regions per task
//! - Page fault handler allocates pages on demand

use crate::mm::frame::{alloc_frame, free_frame, PhysAddr, PAGE_SIZE};
use crate::mm::address_space::PageFlags;
use crate::sched::task::TASKS;
use crate::sched;
use alloc::vec::Vec;

/// MMAP memory region: 0x10000000 - 0x30000000 (256MB to 768MB)
/// Starts high to avoid conflicting with brk heap (which is below 16MB)
pub const MMAP_BASE: usize = 0x1000_0000;
pub const MMAP_END: usize = 0x3000_0000;

/// mmap protection flags (Linux-compatible)
pub const PROT_NONE: u32 = 0x0;
pub const PROT_READ: u32 = 0x1;
pub const PROT_WRITE: u32 = 0x2;
pub const PROT_EXEC: u32 = 0x4;

/// mmap flags (Linux-compatible)
pub const MAP_SHARED: u32 = 0x01;
pub const MAP_PRIVATE: u32 = 0x02;
pub const MAP_FIXED: u32 = 0x10;
pub const MAP_ANONYMOUS: u32 = 0x20;
pub const MAP_ANON: u32 = MAP_ANONYMOUS;

/// mmap failure return value
pub const MAP_FAILED: usize = usize::MAX;

/// Maximum number of mmap regions per task
pub const MAX_MMAP_REGIONS: usize = 16;

/// A memory-mapped region
#[derive(Clone)]
pub struct MmapRegion {
    /// Virtual address start (page-aligned)
    pub vaddr: usize,
    /// Length in bytes (page-aligned)
    pub len: usize,
    /// Protection flags (PROT_READ | PROT_WRITE | PROT_EXEC)
    pub prot: u32,
    /// Mapping flags (MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED)
    pub flags: u32,
    /// Bitmap of which pages are allocated (for demand paging)
    /// Each bit represents one 4KB page
    pub allocated_pages: Vec<bool>,
    /// For file-backed mappings: VFS vnode handle (0 = anonymous)
    pub file_vnode: u64,
    /// For file-backed mappings: offset in file
    pub file_offset: i64,
}

impl MmapRegion {
    /// Create a new anonymous mmap region
    pub fn new(vaddr: usize, len: usize, prot: u32, flags: u32) -> Self {
        Self::new_with_file(vaddr, len, prot, flags, 0, 0)
    }

    /// Create a new mmap region (possibly file-backed)
    pub fn new_with_file(vaddr: usize, len: usize, prot: u32, flags: u32, file_vnode: u64, file_offset: i64) -> Self {
        let num_pages = (len + PAGE_SIZE - 1) / PAGE_SIZE;
        let mut allocated_pages = Vec::with_capacity(num_pages);
        for _ in 0..num_pages {
            allocated_pages.push(false);
        }
        Self {
            vaddr,
            len,
            prot,
            flags,
            allocated_pages,
            file_vnode,
            file_offset,
        }
    }

    /// Check if this is a file-backed mapping
    pub fn is_file_backed(&self) -> bool {
        self.file_vnode != 0
    }

    /// Check if an address falls within this region
    pub fn contains(&self, addr: usize) -> bool {
        addr >= self.vaddr && addr < self.vaddr + self.len
    }

    /// Get the page index for an address within this region
    pub fn page_index(&self, addr: usize) -> usize {
        (addr - self.vaddr) / PAGE_SIZE
    }

    /// Check if a page at the given index is allocated
    pub fn is_page_allocated(&self, page_idx: usize) -> bool {
        page_idx < self.allocated_pages.len() && self.allocated_pages[page_idx]
    }

    /// Mark a page as allocated
    pub fn mark_allocated(&mut self, page_idx: usize) {
        if page_idx < self.allocated_pages.len() {
            self.allocated_pages[page_idx] = true;
        }
    }

    /// Convert prot flags to PageFlags
    pub fn to_page_flags(&self) -> PageFlags {
        PageFlags {
            mattr: 0, // Normal memory
            writable: (self.prot & PROT_WRITE) != 0,
            executable: (self.prot & PROT_EXEC) != 0,
            user: true,
        }
    }
}

/// Per-task mmap state
pub struct MmapState {
    /// Active mmap regions
    pub regions: Vec<MmapRegion>,
    /// Next free address hint for allocation
    pub next_addr: usize,
}

impl MmapState {
    /// Create a new empty mmap state
    pub const fn new() -> Self {
        Self {
            regions: Vec::new(),
            next_addr: MMAP_BASE,
        }
    }

    /// Find a free region of the requested size
    pub fn find_free_region(&self, len: usize) -> Option<usize> {
        let aligned_len = (len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let mut addr = self.next_addr;

        // Simple linear search for a gap
        'outer: loop {
            if addr + aligned_len > MMAP_END {
                // Wrap around and try from the beginning
                if self.next_addr == MMAP_BASE {
                    return None; // No space
                }
                addr = MMAP_BASE;
            }

            // Check if this range overlaps any existing region
            for region in &self.regions {
                if addr < region.vaddr + region.len && addr + aligned_len > region.vaddr {
                    // Overlap - skip past this region
                    addr = (region.vaddr + region.len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
                    continue 'outer;
                }
            }

            // Found a free region
            return Some(addr);
        }
    }

    /// Add a new mmap region
    pub fn add_region(&mut self, region: MmapRegion) {
        // Update next_addr hint
        let region_end = region.vaddr + region.len;
        if region_end > self.next_addr && region_end < MMAP_END {
            self.next_addr = region_end;
        }
        self.regions.push(region);
    }

    /// Find region containing the given address
    pub fn find_region(&self, addr: usize) -> Option<&MmapRegion> {
        self.regions.iter().find(|r| r.contains(addr))
    }

    /// Find region containing the given address (mutable)
    pub fn find_region_mut(&mut self, addr: usize) -> Option<&mut MmapRegion> {
        self.regions.iter_mut().find(|r| r.contains(addr))
    }

    /// Remove region(s) overlapping with the given range
    /// Returns the physical pages that need to be freed
    pub fn remove_region(&mut self, addr: usize, len: usize) -> Vec<PhysAddr> {
        let pages_to_free = Vec::new();
        let end = addr + len;

        // Find and remove overlapping regions
        self.regions.retain(|region| {
            let region_end = region.vaddr + region.len;

            // Check if region overlaps with unmap range
            if region.vaddr < end && region_end > addr {
                // This region overlaps - for now, just remove the whole region
                // A proper implementation would handle partial unmaps
                // TODO: Handle partial unmaps by splitting regions
                false
            } else {
                true
            }
        });

        pages_to_free
    }
}

/// Handle a page fault for an mmap region
///
/// Returns 0 on success (page allocated), or negative error code on failure.
pub fn handle_page_fault(fault_addr: usize) -> i64 {
    // Allow faults in the extended mmap range (heap region + mmap region)
    // This supports MAP_FIXED at addresses below MMAP_BASE
    const HEAP_MIN: usize = 0x0020_0000; // Same as in sys_mmap
    if fault_addr < HEAP_MIN || fault_addr >= MMAP_END {
        return -1; // Outside valid mmap range
    }

    let current_id = match sched::current() {
        Some(id) => id,
        None => return -1,
    };

    unsafe {
        let task = &mut TASKS[current_id.0];

        // Find the mmap region containing this address
        let region = match task.mmap_state.find_region_mut(fault_addr) {
            Some(r) => r,
            None => {
                crate::println!("[fault] t={} no region for {:#x}, have {} regions",
                    current_id.0, fault_addr, task.mmap_state.regions.len());
                return -1;
            }
        };

        let page_idx = region.page_index(fault_addr);

        // Check if page is already allocated (shouldn't happen, but safety check)
        if region.is_page_allocated(page_idx) {
            return -1; // Page already allocated, shouldn't fault
        }

        // Allocate a physical page
        let phys_frame = match alloc_frame() {
            Some(f) => f,
            None => return -12, // ENOMEM
        };

        // Zero the page
        core::ptr::write_bytes(phys_frame.0 as *mut u8, 0, PAGE_SIZE);

        // Map the page in the task's address space
        let page_vaddr = (fault_addr / PAGE_SIZE) * PAGE_SIZE;
        let page_flags = region.to_page_flags();

        let addr_space = match &mut task.addr_space {
            Some(aspace) => aspace,
            None => {
                free_frame(phys_frame);
                return -1;
            }
        };

        if !addr_space.map_4kb(page_vaddr, phys_frame, page_flags) {
            free_frame(phys_frame);
            return -12; // ENOMEM
        }

        // Mark the page as allocated
        region.mark_allocated(page_idx);

        // Invalidate TLB for this address
        core::arch::asm!(
            "dsb ishst",
            "tlbi vaae1is, {0}",
            "dsb ish",
            "isb",
            in(reg) page_vaddr >> 12,
            options(nostack)
        );

        0 // Success
    }
}

/// System call: mmap
///
/// addr: Hint address (ignored unless MAP_FIXED)
/// len: Length of mapping
/// prot: Protection flags
/// flags: Mapping flags
/// fd: File descriptor (must be -1 for MAP_ANONYMOUS)
/// offset: File offset (must be 0 for MAP_ANONYMOUS)
///
/// Returns: Virtual address of mapping, or MAP_FAILED on error
pub fn sys_mmap(addr: usize, len: usize, prot: u32, flags: u32, fd: i32, offset: i64) -> i64 {
    let task_id = sched::current().map(|id| id.0).unwrap_or(999);
    crate::println!("[mmap] t={} addr={:#x} len={} prot={:#x} flags={:#x}",
        task_id, addr, len, prot, flags);

    // Validate arguments
    if len == 0 {
        return -22; // EINVAL
    }

    // Only support anonymous mappings for now
    if (flags & MAP_ANONYMOUS) == 0 {
        return -22; // EINVAL - only anonymous mappings supported
    }

    if fd != -1 || offset != 0 {
        return -22; // EINVAL - fd must be -1, offset must be 0 for anonymous
    }

    // Must have either MAP_PRIVATE or MAP_SHARED
    if (flags & (MAP_PRIVATE | MAP_SHARED)) == 0 {
        return -22; // EINVAL
    }

    let current_id = match sched::current() {
        Some(id) => id,
        None => return -22,
    };

    let aligned_len = (len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    unsafe {
        let task = &mut TASKS[current_id.0];

        // Determine the virtual address
        let vaddr = if (flags & MAP_FIXED) != 0 {
            // MAP_FIXED: use the requested address exactly
            let aligned_addr = addr & !(PAGE_SIZE - 1);
            // Allow MAP_FIXED in:
            // 1. The heap region: 0x200000 (below typical ELF) to MMAP_BASE
            // 2. The mmap region: MMAP_BASE to MMAP_END
            const HEAP_MIN: usize = 0x0020_0000; // 2MB - below typical ELF at 0x400000
            if aligned_addr < HEAP_MIN || aligned_addr + aligned_len > MMAP_END {
                crate::println!("[mmap] t={} FIXED addr {:#x} outside range, fail", task_id, aligned_addr);
                return -22; // EINVAL - outside valid range
            }
            // Remove any existing mappings in this range (for mmap region)
            if aligned_addr >= MMAP_BASE {
                task.mmap_state.remove_region(aligned_addr, aligned_len);
            }
            aligned_addr
        } else {
            // Find a free region
            match task.mmap_state.find_free_region(aligned_len) {
                Some(a) => a,
                None => return -12, // ENOMEM
            }
        };

        // Check for maximum regions
        if task.mmap_state.regions.len() >= MAX_MMAP_REGIONS {
            return -12; // ENOMEM
        }

        // Create the region (pages will be allocated on demand)
        let region = MmapRegion::new(vaddr, aligned_len, prot, flags);
        task.mmap_state.add_region(region);

        crate::println!("[mmap] t={} -> {:#x}", task_id, vaddr);
        vaddr as i64
    }
}

/// System call: munmap
///
/// addr: Start address of mapping to unmap
/// len: Length to unmap
///
/// Returns: 0 on success, negative error on failure
pub fn sys_munmap(addr: usize, len: usize) -> i64 {
    if len == 0 {
        return -22; // EINVAL
    }

    // Address must be page-aligned
    if addr & (PAGE_SIZE - 1) != 0 {
        return -22; // EINVAL
    }

    let current_id = match sched::current() {
        Some(id) => id,
        None => return -22,
    };

    let aligned_len = (len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    unsafe {
        let task = &mut TASKS[current_id.0];

        // Find and process the region(s) to unmap
        let regions_to_process: Vec<_> = task.mmap_state.regions.iter()
            .filter(|r| {
                let region_end = r.vaddr + r.len;
                let unmap_end = addr + aligned_len;
                r.vaddr < unmap_end && region_end > addr
            })
            .map(|r| (r.vaddr, r.len, r.allocated_pages.clone()))
            .collect();

        let addr_space = match &mut task.addr_space {
            Some(aspace) => aspace,
            None => return -22,
        };

        // Unmap pages and free frames
        for (region_vaddr, region_len, allocated_pages) in regions_to_process {
            let num_pages = region_len / PAGE_SIZE;
            for i in 0..num_pages {
                if allocated_pages[i] {
                    let page_vaddr = region_vaddr + i * PAGE_SIZE;
                    // Unmap the page (this doesn't free the frame in current implementation)
                    addr_space.unmap_4kb(page_vaddr);
                    // TODO: Track and free the physical frame
                }
            }
        }

        // Remove the region from tracking
        task.mmap_state.remove_region(addr, aligned_len);

        // Invalidate TLB
        core::arch::asm!(
            "dsb ishst",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            options(nostack)
        );

        0
    }
}

/// System call: mprotect
///
/// Change protection on a region of memory.
/// addr must be page-aligned.
pub fn sys_mprotect(addr: usize, len: usize, prot: u32) -> i64 {
    // Validate arguments
    if addr & (PAGE_SIZE - 1) != 0 {
        return -22; // EINVAL - addr must be page-aligned
    }
    if len == 0 {
        return 0; // Success for zero length
    }

    let current_id = match sched::current() {
        Some(id) => id,
        None => return -22,
    };

    let aligned_len = (len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let end_addr = addr + aligned_len;

    unsafe {
        let task = &mut TASKS[current_id.0];

        // Find regions that overlap with this range and update their prot
        for region in task.mmap_state.regions.iter_mut() {
            let region_end = region.vaddr + region.len;

            // Check if region overlaps with the mprotect range
            if region.vaddr < end_addr && region_end > addr {
                let old_prot = region.prot;

                // Update the region's protection
                // NOTE: For already-allocated pages, this won't update the page table entries.
                // Those pages would need to be unmapped and re-faulted to get new permissions.
                // For demand-paging (musl's typical pattern), pages are allocated AFTER mprotect,
                // so this works correctly.
                region.prot = prot;

                // For already-allocated pages that need permission changes,
                // unmap them so they'll be re-faulted with correct permissions
                if old_prot != prot {
                    let addr_space = match &mut task.addr_space {
                        Some(aspace) => aspace,
                        None => return -22,
                    };

                    let num_pages = region.len / PAGE_SIZE;
                    for i in 0..num_pages {
                        if region.allocated_pages[i] {
                            let page_vaddr = region.vaddr + i * PAGE_SIZE;
                            // Unmap the page - it will be re-allocated on next access
                            addr_space.unmap_4kb(page_vaddr);
                            region.allocated_pages[i] = false;
                        }
                    }
                }
            }
        }

        // Note: if no region found, return success anyway for compatibility (Linux behavior)
        // This can happen for brk/stack regions

        // Invalidate TLB
        core::arch::asm!(
            "dsb ishst",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            options(nostack)
        );

        0
    }
}
