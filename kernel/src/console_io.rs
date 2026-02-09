//! Kernel↔Console Server I/O Ring Buffer
//!
//! This module provides a shared ring buffer for communication between
//! the kernel and the console server. This allows syscall writes to be
//! forwarded to the console server for framebuffer output.

use crate::mm::PhysAddr;
use crate::sched::task::TaskId;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Ring buffer size (4KB - fits in one page)
pub const RING_BUFFER_SIZE: usize = 4096;

/// Data area size (buffer size minus header)
pub const RING_DATA_SIZE: usize = RING_BUFFER_SIZE - 64;

/// Virtual address where console server maps the ring buffer
pub const CONSOLE_RING_VADDR: usize = 0x2000_0000;

/// Notification bit for console output ready
pub const NOTIFY_OUTPUT_READY: u64 = 1;

/// Notification bit for input available
pub const NOTIFY_INPUT_READY: u64 = 2;

/// Ring buffer header (64 bytes)
/// Placed at the start of the shared page
#[repr(C)]
pub struct RingBufferHeader {
    /// Output ring: write index (kernel writes, console reads)
    pub out_write: AtomicUsize,
    /// Output ring: read index
    pub out_read: AtomicUsize,
    /// Input ring: write index (console writes, kernel reads)
    pub in_write: AtomicUsize,
    /// Input ring: read index
    pub in_read: AtomicUsize,
    /// Reserved for future use
    _reserved: [u64; 4],
}

/// Global console ring buffer physical address
static mut CONSOLE_RING_PADDR: Option<PhysAddr> = None;

/// Set the console ring buffer physical address (called during console server creation)
pub fn set_ring_buffer(paddr: PhysAddr) {
    unsafe {
        CONSOLE_RING_PADDR = Some(paddr);
    }
}

/// Get the console ring buffer physical address
pub fn get_ring_buffer() -> Option<PhysAddr> {
    unsafe { CONSOLE_RING_PADDR }
}

/// Write data to the output ring buffer (kernel → console)
/// Returns number of bytes written
pub fn write_output(data: &[u8]) -> usize {
    let paddr = match get_ring_buffer() {
        Some(p) => p,
        None => return 0,
    };

    let header = paddr.0 as *mut RingBufferHeader;
    let data_base = (paddr.0 + 64) as *mut u8; // Data starts after 64-byte header
    let half_size = (RING_DATA_SIZE / 2) as usize; // Output uses first half

    unsafe {
        let write_idx = (*header).out_write.load(Ordering::Acquire);
        let read_idx = (*header).out_read.load(Ordering::Acquire);

        // Calculate available space
        let used = if write_idx >= read_idx {
            write_idx - read_idx
        } else {
            half_size - read_idx + write_idx
        };
        let available = half_size - used - 1; // Leave one byte to distinguish full from empty

        let to_write = data.len().min(available);
        if to_write == 0 {
            return 0;
        }

        // Write data to ring buffer
        for i in 0..to_write {
            let idx = (write_idx + i) % half_size;
            *data_base.add(idx) = data[i];
        }

        // Update write index
        let new_write = (write_idx + to_write) % half_size;
        (*header).out_write.store(new_write, Ordering::Release);

        to_write
    }
}

/// Notify the console server that output is ready
pub fn notify_console() {
    use crate::sched::task::CONSOLE_SERVER_TID;
    use crate::syscall::sys_notify_internal;

    let _ = sys_notify_internal(CONSOLE_SERVER_TID, NOTIFY_OUTPUT_READY);
}

/// Write to console and notify (convenience function)
pub fn write_and_notify(data: &[u8]) -> usize {
    let written = write_output(data);
    if written > 0 {
        notify_console();
    }
    written
}
