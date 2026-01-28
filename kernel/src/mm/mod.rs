pub mod frame;
mod paging;
mod mmu;
pub mod address_space;

pub use frame::{alloc_frame, free_frame, total_pages, free_pages, PhysAddr};
pub use address_space::{AddressSpace, PageFlags};

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
