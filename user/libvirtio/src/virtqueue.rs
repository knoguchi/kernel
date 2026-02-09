//! VirtIO virtqueue implementation
//!
//! A virtqueue consists of:
//! - Descriptor table: array of buffer descriptors
//! - Available ring: driver writes available descriptor indices
//! - Used ring: device writes completed descriptor indices

#![allow(dead_code)]

use core::sync::atomic::{fence, Ordering};

/// Maximum queue size we support
pub const MAX_QUEUE_SIZE: usize = 16;

/// Descriptor flags
pub mod desc_flags {
    pub const NEXT: u16 = 1;      // Buffer continues in next descriptor
    pub const WRITE: u16 = 2;     // Buffer is device-writable (vs read-only)
    pub const INDIRECT: u16 = 4;  // Buffer contains indirect descriptors
}

/// Virtqueue descriptor
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VirtqDesc {
    /// Physical address of buffer
    pub addr: u64,
    /// Length of buffer
    pub len: u32,
    /// Descriptor flags
    pub flags: u16,
    /// Index of next descriptor if NEXT flag set
    pub next: u16,
}

/// Available ring header (driver writes, device reads)
#[repr(C)]
pub struct VirtqAvail {
    pub flags: u16,
    pub idx: u16,
    pub ring: [u16; MAX_QUEUE_SIZE],
    // event_idx follows but we don't use it
}

/// Used ring element
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VirtqUsedElem {
    /// Index of start of used descriptor chain
    pub id: u32,
    /// Total length written to buffer
    pub len: u32,
}

/// Used ring header (device writes, driver reads)
#[repr(C)]
pub struct VirtqUsed {
    pub flags: u16,
    pub idx: u16,
    pub ring: [VirtqUsedElem; MAX_QUEUE_SIZE],
    // event_idx follows but we don't use it
}

/// Virtqueue state
pub struct Virtqueue {
    /// Number of descriptors
    pub size: u16,
    /// Descriptor table
    pub desc: *mut VirtqDesc,
    /// Available ring
    pub avail: *mut VirtqAvail,
    /// Used ring
    pub used: *mut VirtqUsed,
    /// Index of next free descriptor
    free_head: u16,
    /// Number of free descriptors
    num_free: u16,
    /// Last seen used index
    pub last_used_idx: u16,
    /// Free list (indices of free descriptors)
    free_list: [u16; MAX_QUEUE_SIZE],
}

impl Virtqueue {
    /// Initialize a virtqueue in the provided memory region
    ///
    /// The memory must be at least `memory_size(size)` bytes and aligned.
    pub unsafe fn init(memory: *mut u8, size: u16) -> Self {
        let size_usize = size as usize;

        // Calculate offsets
        let desc_size = size_usize * core::mem::size_of::<VirtqDesc>();
        let avail_size = 6 + 2 * size_usize; // flags + idx + ring[size] + used_event
        let used_offset = align_up(desc_size + avail_size, 4);

        let desc = memory as *mut VirtqDesc;
        let avail = memory.add(desc_size) as *mut VirtqAvail;
        let used = memory.add(used_offset) as *mut VirtqUsed;

        // Zero memory
        core::ptr::write_bytes(memory, 0, Self::memory_size(size));

        // Initialize free list
        let mut free_list = [0u16; MAX_QUEUE_SIZE];
        for i in 0..size_usize {
            free_list[i] = i as u16;
        }

        Virtqueue {
            size,
            desc,
            avail,
            used,
            free_head: 0,
            num_free: size,
            last_used_idx: 0,
            free_list,
        }
    }

    /// Calculate memory size needed for a virtqueue
    pub fn memory_size(size: u16) -> usize {
        let size_usize = size as usize;
        let desc_size = size_usize * core::mem::size_of::<VirtqDesc>();
        let avail_size = 6 + 2 * size_usize;
        let used_offset = align_up(desc_size + avail_size, 4);
        let used_size = 6 + 8 * size_usize;
        used_offset + used_size
    }

    /// Get descriptor table physical address
    pub fn desc_addr(&self) -> u64 {
        self.desc as u64
    }

    /// Get available ring physical address
    pub fn avail_addr(&self) -> u64 {
        self.avail as u64
    }

    /// Get used ring physical address
    pub fn used_addr(&self) -> u64 {
        self.used as u64
    }

    /// Allocate a descriptor from the free list
    pub fn alloc_desc(&mut self) -> Option<u16> {
        if self.num_free == 0 {
            return None;
        }
        let idx = self.free_list[self.free_head as usize];
        self.free_head = (self.free_head + 1) % self.size;
        self.num_free -= 1;
        Some(idx)
    }

    /// Free a descriptor back to the free list
    pub fn free_desc(&mut self, idx: u16) {
        let tail = (self.free_head + self.num_free) % self.size;
        self.free_list[tail as usize] = idx;
        self.num_free += 1;
    }

    /// Set up a descriptor
    pub unsafe fn set_desc(&mut self, idx: u16, addr: u64, len: u32, flags: u16, next: u16) {
        let desc = &mut *self.desc.add(idx as usize);
        desc.addr = addr;
        desc.len = len;
        desc.flags = flags;
        desc.next = next;
    }

    /// Submit a descriptor chain to the available ring
    pub unsafe fn submit(&mut self, head: u16) {
        let avail = &mut *self.avail;
        let idx = avail.idx;
        avail.ring[(idx % self.size) as usize] = head;
        fence(Ordering::SeqCst);
        avail.idx = idx.wrapping_add(1);
        fence(Ordering::SeqCst);
    }

    /// Check if there are used buffers to process
    pub fn has_used(&self) -> bool {
        unsafe {
            fence(Ordering::SeqCst);
            (*self.used).idx != self.last_used_idx
        }
    }

    /// Pop a used buffer (returns descriptor head index and length)
    pub unsafe fn pop_used(&mut self) -> Option<(u16, u32)> {
        fence(Ordering::SeqCst);
        let used = &*self.used;
        if used.idx == self.last_used_idx {
            return None;
        }

        let elem = &used.ring[(self.last_used_idx % self.size) as usize];
        let id = elem.id as u16;
        let len = elem.len;
        self.last_used_idx = self.last_used_idx.wrapping_add(1);

        Some((id, len))
    }
}

/// Align value up to alignment
fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}
