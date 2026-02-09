pub mod frame;
pub mod paging;
mod mmu;
pub mod address_space;

pub const KERNEL_VIRT_OFFSET: usize = 0xC000_0000;

pub use frame::{alloc_frame, free_frame, total_pages, free_pages, PhysAddr, PAGE_SIZE};
pub use address_space::{AddressSpace, PageFlags};
#[allow(unused_imports)]
pub use paging::{l1_index, l2_index, l3_index, PageTableEntry, ENTRIES_PER_TABLE, BLOCK_SIZE_2MB};
pub use mmu::kernel_ttbr0;

/// Initialize the physical memory allocator
#[inline(never)]
pub fn init(memory_start: usize, memory_end: usize, kernel_end: usize) {
    frame::init_allocator(memory_start, memory_end, kernel_end);
}

/// Initialize and enable the MMU with identity mapping
///
/// # Safety
/// - Must be called after mm::init()
/// - Must be running at EL1
/// - Interrupts should be disabled
#[inline(never)]
pub unsafe fn enable_mmu(print_fn: impl Fn(&str, u64)) {
    mmu::init_and_enable(print_fn);
}
