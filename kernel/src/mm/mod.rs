mod frame;

pub use frame::{alloc_frame, free_frame, total_pages, free_pages, PhysAddr};

/// Initialize the physical memory allocator
#[inline(never)]
pub fn init(memory_start: usize, memory_end: usize, kernel_end: usize) {
    frame::init_allocator(memory_start, memory_end, kernel_end);
}
