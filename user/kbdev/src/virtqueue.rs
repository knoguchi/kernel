//! VirtIO virtqueue implementation

#![allow(dead_code)]

use core::sync::atomic::{fence, Ordering};

pub const MAX_QUEUE_SIZE: usize = 16;

pub mod desc_flags {
    pub const NEXT: u16 = 1;
    pub const WRITE: u16 = 2;
    pub const INDIRECT: u16 = 4;
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VirtqDesc {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

#[repr(C)]
pub struct VirtqAvail {
    pub flags: u16,
    pub idx: u16,
    pub ring: [u16; MAX_QUEUE_SIZE],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VirtqUsedElem {
    pub id: u32,
    pub len: u32,
}

#[repr(C)]
pub struct VirtqUsed {
    pub flags: u16,
    pub idx: u16,
    pub ring: [VirtqUsedElem; MAX_QUEUE_SIZE],
}

pub struct Virtqueue {
    pub size: u16,
    pub desc: *mut VirtqDesc,
    pub avail: *mut VirtqAvail,
    pub used: *mut VirtqUsed,
    free_head: u16,
    num_free: u16,
    pub last_used_idx: u16,
    free_list: [u16; MAX_QUEUE_SIZE],
}

impl Virtqueue {
    pub unsafe fn init(memory: *mut u8, size: u16) -> Self {
        let size_usize = size as usize;

        let desc_size = size_usize * core::mem::size_of::<VirtqDesc>();
        let avail_size = 6 + 2 * size_usize;
        let used_offset = align_up(desc_size + avail_size, 4);

        let desc = memory as *mut VirtqDesc;
        let avail = memory.add(desc_size) as *mut VirtqAvail;
        let used = memory.add(used_offset) as *mut VirtqUsed;

        core::ptr::write_bytes(memory, 0, Self::memory_size(size));

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

    pub fn memory_size(size: u16) -> usize {
        let size_usize = size as usize;
        let desc_size = size_usize * core::mem::size_of::<VirtqDesc>();
        let avail_size = 6 + 2 * size_usize;
        let used_offset = align_up(desc_size + avail_size, 4);
        let used_size = 6 + 8 * size_usize;
        used_offset + used_size
    }

    pub fn desc_addr(&self) -> u64 {
        self.desc as u64
    }

    pub fn avail_addr(&self) -> u64 {
        self.avail as u64
    }

    pub fn used_addr(&self) -> u64 {
        self.used as u64
    }

    pub fn alloc_desc(&mut self) -> Option<u16> {
        if self.num_free == 0 {
            return None;
        }
        let idx = self.free_list[self.free_head as usize];
        self.free_head = (self.free_head + 1) % self.size;
        self.num_free -= 1;
        Some(idx)
    }

    pub fn free_desc(&mut self, idx: u16) {
        let tail = (self.free_head + self.num_free) % self.size;
        self.free_list[tail as usize] = idx;
        self.num_free += 1;
    }

    pub unsafe fn set_desc(&mut self, idx: u16, addr: u64, len: u32, flags: u16, next: u16) {
        let desc = &mut *self.desc.add(idx as usize);
        desc.addr = addr;
        desc.len = len;
        desc.flags = flags;
        desc.next = next;
    }

    pub unsafe fn submit(&mut self, head: u16) {
        let avail = &mut *self.avail;
        let idx = avail.idx;
        avail.ring[(idx % self.size) as usize] = head;
        fence(Ordering::SeqCst);
        avail.idx = idx.wrapping_add(1);
        fence(Ordering::SeqCst);
    }

    pub fn has_used(&self) -> bool {
        unsafe {
            fence(Ordering::SeqCst);
            (*self.used).idx != self.last_used_idx
        }
    }

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

fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}
