use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;

/// Simple bump allocator for kernel heap.
/// This is a quick and dirty allocator - it doesn't support deallocation.
/// For a real kernel, you'd want a proper allocator like linked_list_allocator.
pub struct BumpAllocator {
    heap: UnsafeCell<HeapState>,
}

struct HeapState {
    heap_start: usize,
    heap_end: usize,
    next: usize,
}

// Kernel heap: 256KB (larger sizes break other code paths)
const HEAP_SIZE: usize = 256 * 1024;
static mut HEAP_MEMORY: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

impl BumpAllocator {
    pub const fn new() -> Self {
        Self {
            heap: UnsafeCell::new(HeapState {
                heap_start: 0,
                heap_end: 0,
                next: 0,
            }),
        }
    }

    fn init(&self) {
        unsafe {
            let state = &mut *self.heap.get();
            if state.heap_start == 0 {
                state.heap_start = HEAP_MEMORY.as_ptr() as usize;
                state.heap_end = state.heap_start + HEAP_SIZE;
                state.next = state.heap_start;
            }
        }
    }
}

unsafe impl GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.init();

        let state = &mut *self.heap.get();

        // Align the next pointer
        let alloc_start = (state.next + layout.align() - 1) & !(layout.align() - 1);
        let alloc_end = alloc_start.saturating_add(layout.size());

        if alloc_end > state.heap_end {
            // Out of memory
            core::ptr::null_mut()
        } else {
            state.next = alloc_end;
            alloc_start as *mut u8
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // Bump allocator doesn't support deallocation.
        // Memory is "leaked" until the kernel restarts.
        // For a real kernel, use a proper allocator.
    }
}

unsafe impl Sync for BumpAllocator {}

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator::new();
