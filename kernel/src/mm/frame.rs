/// Page size: 4KB
pub const PAGE_SIZE: usize = 4096;

/// 2MB block size (for page table block mappings)
pub const BLOCK_SIZE_2MB: usize = 2 * 1024 * 1024;

/// Pages per 2MB block (2MB / 4KB = 512)
const PAGES_PER_2MB_BLOCK: usize = BLOCK_SIZE_2MB / PAGE_SIZE;

/// Maximum number of pages (1GB / 4KB = 262144)
const MAX_PAGES: usize = 262144;

/// Bitmap size in bytes (262144 / 8 = 32768 = 32KB)
const BITMAP_SIZE: usize = MAX_PAGES / 8;

/// Physical address newtype wrapper
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysAddr(pub usize);

impl PhysAddr {
    pub const fn new(addr: usize) -> Self {
        Self(addr)
    }

    pub const fn as_usize(&self) -> usize {
        self.0
    }
}

/// Bitmap-based physical frame allocator
pub struct FrameAllocator {
    bitmap: [u8; BITMAP_SIZE],
    memory_start: usize,
    memory_end: usize,
    next_free: usize,
    used_count: usize,
    initialized: bool,
}

impl FrameAllocator {
    /// Create a new uninitialized frame allocator
    pub const fn new() -> Self {
        Self {
            bitmap: [0; BITMAP_SIZE],
            memory_start: 0,
            memory_end: 0,
            next_free: 0,
            used_count: 0,
            initialized: false,
        }
    }


    /// Allocate a single physical frame
    pub fn alloc(&mut self) -> Option<PhysAddr> {
        if !self.initialized {
            return None;
        }

        let total_pages = (self.memory_end - self.memory_start) / PAGE_SIZE;

        // Start searching from next_free hint
        for i in self.next_free..total_pages {
            if !self.get_bit(i) {
                self.set_bit(i, true);
                self.next_free = i + 1;
                self.used_count += 1;
                return Some(PhysAddr::new(self.memory_start + i * PAGE_SIZE));
            }
        }

        // Wrap around and search from beginning
        for i in 0..self.next_free {
            if !self.get_bit(i) {
                self.set_bit(i, true);
                self.next_free = i + 1;
                self.used_count += 1;
                return Some(PhysAddr::new(self.memory_start + i * PAGE_SIZE));
            }
        }

        None // Out of memory
    }

    /// Allocate multiple contiguous frames that are all within the same 2MB block.
    /// This is needed for 2MB block mappings in page tables.
    /// Returns the starting PhysAddr of the allocated region, or None if not possible.
    pub fn alloc_contiguous_in_2mb_block(&mut self, count: usize) -> Option<PhysAddr> {
        if !self.initialized || count == 0 {
            return None;
        }

        // Can't allocate more than a 2MB block worth of pages
        if count > PAGES_PER_2MB_BLOCK {
            return None;
        }

        let total_pages = (self.memory_end - self.memory_start) / PAGE_SIZE;

        // Start searching from next_free
        let mut search_start = self.next_free;

        // Search for a contiguous region within a single 2MB block
        for _ in 0..2 {
            // Two passes: from next_free to end, then from 0 to next_free
            let search_end = if search_start == self.next_free {
                total_pages
            } else {
                self.next_free
            };

            let mut i = search_start;
            while i < search_end {
                // Calculate the 2MB block this page belongs to
                let page_addr = self.memory_start + i * PAGE_SIZE;
                let block_base = page_addr & !(BLOCK_SIZE_2MB - 1);
                let offset_in_block = page_addr - block_base;
                let page_offset_in_block = offset_in_block / PAGE_SIZE;

                // How many pages remain in this 2MB block?
                let pages_remaining_in_block = PAGES_PER_2MB_BLOCK - page_offset_in_block;

                if pages_remaining_in_block < count {
                    // Not enough room in this block, skip to next 2MB block
                    i += pages_remaining_in_block;
                    continue;
                }

                // Check if 'count' contiguous pages starting at i are all free
                let mut all_free = true;
                for j in 0..count {
                    if i + j >= total_pages || self.get_bit(i + j) {
                        all_free = false;
                        break;
                    }
                }

                if all_free {
                    // Found a suitable region, allocate all pages
                    for j in 0..count {
                        self.set_bit(i + j, true);
                    }
                    self.next_free = i + count;
                    self.used_count += count;
                    return Some(PhysAddr::new(self.memory_start + i * PAGE_SIZE));
                }

                i += 1;
            }

            // Second pass: search from beginning
            search_start = 0;
        }

        None // No suitable contiguous region found
    }

    /// Allocate contiguous frames at the START of a 2MB block.
    /// This is needed when mapping ELFs linked at virtual address 0 with 2MB block mappings,
    /// because virtual 0 maps to the physical 2MB block base.
    /// Returns the starting PhysAddr (which will be 2MB-aligned), or None if not possible.
    pub fn alloc_at_2mb_boundary(&mut self, count: usize) -> Option<PhysAddr> {
        if !self.initialized || count == 0 {
            return None;
        }

        // Can't allocate more than a 2MB block worth of pages
        if count > PAGES_PER_2MB_BLOCK {
            return None;
        }

        let total_pages = (self.memory_end - self.memory_start) / PAGE_SIZE;

        // Find the first 2MB boundary in our memory range
        let first_2mb_boundary = (self.memory_start + BLOCK_SIZE_2MB - 1) & !(BLOCK_SIZE_2MB - 1);
        let first_boundary_page = (first_2mb_boundary - self.memory_start) / PAGE_SIZE;

        // Iterate through all 2MB boundaries
        let mut i = first_boundary_page;
        while i < total_pages {
            // Check if 'count' contiguous pages starting at i are all free
            let mut all_free = true;
            for j in 0..count {
                if i + j >= total_pages || self.get_bit(i + j) {
                    all_free = false;
                    break;
                }
            }

            if all_free {
                // Found a suitable region at a 2MB boundary.
                // Mark the ENTIRE 2MB block as used to prevent fragmentation.
                for j in 0..PAGES_PER_2MB_BLOCK {
                    if i + j < total_pages {
                        self.set_bit(i + j, true);
                    }
                }
                self.used_count += PAGES_PER_2MB_BLOCK.min(total_pages - i);
                return Some(PhysAddr::new(self.memory_start + i * PAGE_SIZE));
            }

            // Skip to next 2MB boundary
            i += PAGES_PER_2MB_BLOCK;
        }

        None // No suitable 2MB-aligned region found
    }

    /// Free a physical frame
    pub fn free(&mut self, addr: PhysAddr) {
        if !self.initialized {
            return;
        }

        let addr_val = addr.as_usize();
        if addr_val < self.memory_start || addr_val >= self.memory_end {
            return; // Invalid address
        }

        let page_index = (addr_val - self.memory_start) / PAGE_SIZE;

        // Only decrement if page was actually allocated
        if self.get_bit(page_index) {
            self.set_bit(page_index, false);
            self.used_count -= 1;
        }

        // Update hint if this freed page is before current hint
        if page_index < self.next_free {
            self.next_free = page_index;
        }
    }

    /// Get the number of free pages (O(1))
    pub fn free_count(&self) -> usize {
        if !self.initialized {
            return 0;
        }
        self.total_pages() - self.used_count
    }

    /// Get total number of pages
    pub fn total_pages(&self) -> usize {
        if !self.initialized {
            return 0;
        }
        (self.memory_end - self.memory_start) / PAGE_SIZE
    }

    /// Get a bit from the bitmap (true = allocated)
    fn get_bit(&self, index: usize) -> bool {
        let byte_index = index / 8;
        let bit_offset = index % 8;
        (self.bitmap[byte_index] & (1 << bit_offset)) != 0
    }

    /// Set a bit in the bitmap
    fn set_bit(&mut self, index: usize, value: bool) {
        let byte_index = index / 8;
        let bit_offset = index % 8;
        if value {
            self.bitmap[byte_index] |= 1 << bit_offset;
        } else {
            self.bitmap[byte_index] &= !(1 << bit_offset);
        }
    }
}

/// Global frame allocator instance
/// Safety: Single-core during boot, no locking needed yet
static mut ALLOCATOR: FrameAllocator = FrameAllocator::new();

/// Sync point using MMIO write
/// Required to prevent optimization issues on bare-metal AArch64
#[inline(never)]
fn sync_point() {
    // Write a character to UART - acts as memory sync point
    unsafe {
        core::ptr::write_volatile(0x0900_0030 as *mut u32, 0x101);
        core::ptr::write_volatile(0x0900_0000 as *mut u8, b'.');
    }
}

/// Initialize the global allocator directly
#[inline(never)]
pub fn init_allocator(memory_start: usize, memory_end: usize, kernel_end: usize) {
    sync_point(); // 1

    // Work directly with the static via raw pointer
    let alloc_ptr = core::ptr::addr_of_mut!(ALLOCATOR);
    sync_point(); // 2

    unsafe {
        (*alloc_ptr).memory_start = memory_start;
        sync_point(); // 3
        (*alloc_ptr).memory_end = memory_end;
        sync_point(); // 4

        // Calculate how many pages the kernel occupies
        let kernel_pages = (kernel_end - memory_start + PAGE_SIZE - 1) / PAGE_SIZE;

        // Mark kernel pages as allocated - set full bytes when possible
        let full_bytes = kernel_pages / 8;
        for i in 0..full_bytes {
            (*alloc_ptr).bitmap[i] = 0xFF;
        }
        sync_point();

        (*alloc_ptr).next_free = kernel_pages;
        (*alloc_ptr).used_count = kernel_pages;
        (*alloc_ptr).initialized = true;
        sync_point();
    }
}

/// Allocate a frame from the global allocator
pub fn alloc_frame() -> Option<PhysAddr> {
    unsafe { ALLOCATOR.alloc() }
}

/// Allocate multiple contiguous frames within the same 2MB block
pub fn alloc_frames_in_2mb_block(count: usize) -> Option<PhysAddr> {
    unsafe { ALLOCATOR.alloc_contiguous_in_2mb_block(count) }
}

/// Allocate frames at the START of a 2MB block (for ELFs linked at virtual address 0)
pub fn alloc_frames_at_2mb_boundary(count: usize) -> Option<PhysAddr> {
    unsafe { ALLOCATOR.alloc_at_2mb_boundary(count) }
}

/// Free a frame to the global allocator
pub fn free_frame(addr: PhysAddr) {
    unsafe { ALLOCATOR.free(addr) }
}

/// Get total pages
pub fn total_pages() -> usize {
    unsafe { ALLOCATOR.total_pages() }
}

/// Get free pages count
pub fn free_pages() -> usize {
    unsafe { ALLOCATOR.free_count() }
}
