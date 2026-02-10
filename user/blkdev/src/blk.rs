//! VirtIO block device protocol
//!
//! Implements the VirtIO block device specification.

#![allow(dead_code)]

use libvirtio::mmio::{VirtioMmio, status, device_id};
use libvirtio::virtqueue::{Virtqueue, desc_flags, MAX_QUEUE_SIZE};
use core::sync::atomic::{fence, Ordering};

/// Block sector size
pub const SECTOR_SIZE: usize = 512;

/// VirtIO block request types
pub mod request_type {
    pub const IN: u32 = 0;       // Read
    pub const OUT: u32 = 1;      // Write
    pub const FLUSH: u32 = 4;    // Flush
    pub const GET_ID: u32 = 8;   // Get device ID
}

/// VirtIO block status codes
pub mod blk_status {
    pub const OK: u8 = 0;
    pub const IOERR: u8 = 1;
    pub const UNSUPP: u8 = 2;
}

/// VirtIO block feature bits
pub mod features {
    pub const SIZE_MAX: u64 = 1 << 1;
    pub const SEG_MAX: u64 = 1 << 2;
    pub const GEOMETRY: u64 = 1 << 4;
    pub const RO: u64 = 1 << 5;
    pub const BLK_SIZE: u64 = 1 << 6;
    pub const FLUSH: u64 = 1 << 9;
    pub const TOPOLOGY: u64 = 1 << 10;
    pub const CONFIG_WCE: u64 = 1 << 11;
    pub const DISCARD: u64 = 1 << 13;
    pub const WRITE_ZEROES: u64 = 1 << 14;
}

/// VirtIO block device configuration (from config space)
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VirtioBlkConfig {
    /// Capacity in 512-byte sectors
    pub capacity: u64,
    /// Size max (if SIZE_MAX feature)
    pub size_max: u32,
    /// Segment max (if SEG_MAX feature)
    pub seg_max: u32,
    /// Geometry (if GEOMETRY feature)
    pub geometry: VirtioBlkGeometry,
    /// Block size (if BLK_SIZE feature)
    pub blk_size: u32,
}

/// Disk geometry
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VirtioBlkGeometry {
    pub cylinders: u16,
    pub heads: u8,
    pub sectors: u8,
}

/// VirtIO block request header
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VirtioBlkReqHeader {
    pub req_type: u32,
    pub reserved: u32,
    pub sector: u64,
}

/// VirtIO block device driver
pub struct VirtioBlk {
    mmio: VirtioMmio,
    queue: Virtqueue,
    /// Memory for virtqueue structures
    queue_mem: [u8; 4096],
    /// Request header buffer
    req_header: VirtioBlkReqHeader,
    /// Status byte buffer
    status_byte: u8,
    /// Device capacity in sectors
    capacity: u64,
    /// Physical base for VA->PA conversion
    phys_base: u64,
}

impl VirtioBlk {
    /// Create a new uninitialized block device
    pub const fn new(mmio_base: usize) -> Self {
        Self {
            mmio: VirtioMmio::new(mmio_base),
            queue: unsafe { core::mem::zeroed() },
            queue_mem: [0; 4096],
            req_header: VirtioBlkReqHeader {
                req_type: 0,
                reserved: 0,
                sector: 0,
            },
            status_byte: 0,
            capacity: 0,
            phys_base: 0,
        }
    }

    /// Set physical base for VA->PA conversion
    pub fn set_phys_base(&mut self, phys_base: u64) {
        self.phys_base = phys_base;
    }

    /// Convert virtual address to physical for DMA
    #[inline]
    fn va_to_pa(&self, va: u64) -> u64 {
        libkenix::va_to_pa(va, self.phys_base)
    }

    /// Initialize the block device
    ///
    /// Returns true on success, false on failure.
    pub fn init(&mut self) -> bool {
        use libkenix::uart;

        // Scan virtio-mmio slots to find block device
        // QEMU virt machine has 32 virtio-mmio slots starting at 0x0a000000, 0x200 apart
        const VIRTIO_BASE: usize = 0x0a00_0000;
        const SLOT_SIZE: usize = 0x200;
        const NUM_SLOTS: usize = 32;

        let mut found_slot: Option<usize> = None;
        for slot in 0..NUM_SLOTS {
            let base = VIRTIO_BASE + slot * SLOT_SIZE;
            let mmio = VirtioMmio::new(base);

            if mmio.is_valid() && mmio.device_id() == device_id::BLOCK {
                uart::print("[blkdev] found at slot ");
                // Print slot number as two digits
                let d1 = (slot / 10) as u8 + b'0';
                let d2 = (slot % 10) as u8 + b'0';
                let buf = if slot >= 10 { [d1, d2] } else { [d2, b' '] };
                let s = unsafe { core::str::from_utf8_unchecked(&buf[..if slot >= 10 { 2 } else { 1 }]) };
                uart::print(s);
                uart::println("");
                found_slot = Some(slot);
                break;
            }
        }

        let slot = match found_slot {
            Some(s) => s,
            None => {
                uart::println("[blkdev] no block device found");
                return false;
            }
        };

        // Update our MMIO base to the found device
        self.mmio = VirtioMmio::new(VIRTIO_BASE + slot * SLOT_SIZE);

        // Reset device
        self.mmio.reset();

        // Set ACKNOWLEDGE status bit
        self.mmio.set_status(status::ACKNOWLEDGE);

        // Set DRIVER status bit
        self.mmio.set_status(status::ACKNOWLEDGE | status::DRIVER);

        // Read device features
        let _features_lo = self.mmio.device_features(0);
        let features_hi = self.mmio.device_features(1);


        // VIRTIO_F_VERSION_1 (bit 32 = bit 0 in features[1]) is MANDATORY for VirtIO 1.0+
        // We must acknowledge it if the device advertises it (modern device)
        const VIRTIO_F_VERSION_1: u32 = 1 << 0;  // Bit 0 in the high word = bit 32 overall

        // Only negotiate features that the device actually offers
        // For now, we don't need any low-word features
        self.mmio.set_driver_features(0, 0);

        // Set VIRTIO_F_VERSION_1 if device offers it (mandatory for modern devices)
        let driver_features_hi = if features_hi & VIRTIO_F_VERSION_1 != 0 {
            VIRTIO_F_VERSION_1
        } else {
            0  // Legacy device - don't set any high features
        };
        self.mmio.set_driver_features(1, driver_features_hi);

        // Set FEATURES_OK
        self.mmio.set_status(status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK);

        // Check FEATURES_OK is still set
        if (self.mmio.status() & status::FEATURES_OK) == 0 {
            uart::println("[blkdev] features not OK");
            self.mmio.set_status(status::FAILED);
            return false;
        }

        // Read configuration
        self.capacity = self.mmio.read_config::<u64>(0);

        // Set up virtqueue 0
        self.mmio.select_queue(0);
        let max_size = self.mmio.queue_max_size();
        if max_size == 0 {
            uart::println("[blkdev] queue max size is 0");
            self.mmio.set_status(status::FAILED);
            return false;
        }

        let queue_size = (max_size as u16).min(MAX_QUEUE_SIZE as u16);

        // Initialize virtqueue in our memory buffer
        self.queue = unsafe {
            Virtqueue::init(self.queue_mem.as_mut_ptr(), queue_size)
        };

        // Configure queue - use physical addresses
        let desc_pa = self.va_to_pa(self.queue.desc_addr());
        let avail_pa = self.va_to_pa(self.queue.avail_addr());
        let used_pa = self.va_to_pa(self.queue.used_addr());

        self.mmio.set_queue_size(queue_size as u32);
        self.mmio.set_queue_desc(desc_pa);
        self.mmio.set_queue_driver(avail_pa);
        self.mmio.set_queue_device(used_pa);
        self.mmio.set_queue_ready(true);

        // Set DRIVER_OK
        self.mmio.set_status(status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK | status::DRIVER_OK);

        true
    }

    /// Get device capacity in sectors
    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Read sectors from the device
    ///
    /// # Arguments
    /// * `sector` - Starting sector number
    /// * `buf` - Buffer to read into (must be multiple of SECTOR_SIZE)
    ///
    /// # Returns
    /// Number of bytes read, or negative error code
    pub fn read(&mut self, sector: u64, buf: &mut [u8]) -> isize {
        if buf.len() % SECTOR_SIZE != 0 {
            return -1;
        }

        let num_sectors = buf.len() / SECTOR_SIZE;
        if sector + num_sectors as u64 > self.capacity {
            return -1;
        }

        // Set up request header
        self.req_header.req_type = request_type::IN;
        self.req_header.reserved = 0;
        self.req_header.sector = sector;
        self.status_byte = 0xff; // Will be overwritten by device

        // Allocate descriptors
        let desc0 = match self.queue.alloc_desc() {
            Some(d) => d,
            None => return -1,
        };
        let desc1 = match self.queue.alloc_desc() {
            Some(d) => d,
            None => {
                self.queue.free_desc(desc0);
                return -1;
            }
        };
        let desc2 = match self.queue.alloc_desc() {
            Some(d) => d,
            None => {
                self.queue.free_desc(desc0);
                self.queue.free_desc(desc1);
                return -1;
            }
        };

        // Compute physical addresses before the unsafe block (to avoid borrow issues)
        let header_pa = self.va_to_pa(&self.req_header as *const _ as u64);
        let buf_pa = self.va_to_pa(buf.as_mut_ptr() as u64);
        let status_pa = self.va_to_pa(&self.status_byte as *const _ as u64);

        unsafe {
            // Descriptor 0: request header (device reads) - use physical address
            self.queue.set_desc(
                desc0,
                header_pa,
                core::mem::size_of::<VirtioBlkReqHeader>() as u32,
                desc_flags::NEXT,
                desc1,
            );

            // Descriptor 1: data buffer (device writes) - use physical address
            self.queue.set_desc(
                desc1,
                buf_pa,
                buf.len() as u32,
                desc_flags::WRITE | desc_flags::NEXT,
                desc2,
            );

            // Descriptor 2: status byte (device writes) - use physical address
            self.queue.set_desc(
                desc2,
                status_pa,
                1,
                desc_flags::WRITE,
                0,
            );

            // Submit request
            self.queue.submit(desc0);
        }

        // Notify device
        fence(Ordering::SeqCst);
        self.mmio.notify_queue(0);

        // Wait for completion - yield CPU instead of busy-spin
        let mut timeout = 100000u32;
        while !self.queue.has_used() && timeout > 0 {
            timeout -= 1;
            libkenix::syscall::yield_cpu();
        }
        if timeout == 0 {
            return -5; // Timeout error
        }

        // Process completion
        let (_head, _len) = unsafe { self.queue.pop_used().unwrap() };

        // Free descriptors
        self.queue.free_desc(desc0);
        self.queue.free_desc(desc1);
        self.queue.free_desc(desc2);

        // Check status
        if self.status_byte != blk_status::OK {
            return -2;
        }

        buf.len() as isize
    }

    /// Write sectors to the device
    ///
    /// # Arguments
    /// * `sector` - Starting sector number
    /// * `buf` - Buffer to write from (must be multiple of SECTOR_SIZE)
    ///
    /// # Returns
    /// Number of bytes written, or negative error code
    pub fn write(&mut self, sector: u64, buf: &[u8]) -> isize {
        if buf.len() % SECTOR_SIZE != 0 {
            return -1;
        }

        let num_sectors = buf.len() / SECTOR_SIZE;
        if sector + num_sectors as u64 > self.capacity {
            return -1;
        }

        // Set up request header
        self.req_header.req_type = request_type::OUT;
        self.req_header.reserved = 0;
        self.req_header.sector = sector;
        self.status_byte = 0xff;

        // Allocate descriptors
        let desc0 = match self.queue.alloc_desc() {
            Some(d) => d,
            None => return -1,
        };
        let desc1 = match self.queue.alloc_desc() {
            Some(d) => d,
            None => {
                self.queue.free_desc(desc0);
                return -1;
            }
        };
        let desc2 = match self.queue.alloc_desc() {
            Some(d) => d,
            None => {
                self.queue.free_desc(desc0);
                self.queue.free_desc(desc1);
                return -1;
            }
        };

        // Compute physical addresses before the unsafe block (to avoid borrow issues)
        let header_pa = self.va_to_pa(&self.req_header as *const _ as u64);
        let buf_pa = self.va_to_pa(buf.as_ptr() as u64);
        let status_pa = self.va_to_pa(&self.status_byte as *const _ as u64);

        unsafe {
            // Descriptor 0: request header (device reads) - use physical address
            self.queue.set_desc(
                desc0,
                header_pa,
                core::mem::size_of::<VirtioBlkReqHeader>() as u32,
                desc_flags::NEXT,
                desc1,
            );

            // Descriptor 1: data buffer (device reads) - use physical address
            self.queue.set_desc(
                desc1,
                buf_pa,
                buf.len() as u32,
                desc_flags::NEXT,
                desc2,
            );

            // Descriptor 2: status byte (device writes) - use physical address
            self.queue.set_desc(
                desc2,
                status_pa,
                1,
                desc_flags::WRITE,
                0,
            );

            // Submit request
            self.queue.submit(desc0);
        }

        // Notify device
        fence(Ordering::SeqCst);
        self.mmio.notify_queue(0);

        // Wait for completion - yield CPU instead of busy-spin
        let mut timeout = 100000u32;
        while !self.queue.has_used() && timeout > 0 {
            timeout -= 1;
            libkenix::syscall::yield_cpu();
        }
        if timeout == 0 {
            return -5; // Timeout error
        }

        // Process completion
        let (_head, _len) = unsafe { self.queue.pop_used().unwrap() };

        // Free descriptors
        self.queue.free_desc(desc0);
        self.queue.free_desc(desc1);
        self.queue.free_desc(desc2);

        // Check status
        if self.status_byte != blk_status::OK {
            return -2;
        }

        buf.len() as isize
    }

    /// Acknowledge interrupt
    pub fn ack_interrupt(&mut self) {
        let status = self.mmio.interrupt_status();
        self.mmio.interrupt_ack(status);
    }
}
