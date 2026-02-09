//! VirtIO MMIO transport layer
//!
//! Provides access to VirtIO device registers via memory-mapped I/O.
//! Based on VirtIO 1.1 specification, MMIO transport.

#![allow(dead_code)]

use core::ptr::{read_volatile, write_volatile};

/// VirtIO MMIO base address (QEMU virt machine first virtio slot)
pub const VIRTIO_MMIO_BASE: usize = 0x0a00_0000;

/// VirtIO MMIO register offsets
pub mod regs {
    pub const MAGIC_VALUE: usize = 0x000;
    pub const VERSION: usize = 0x004;
    pub const DEVICE_ID: usize = 0x008;
    pub const VENDOR_ID: usize = 0x00c;
    pub const DEVICE_FEATURES: usize = 0x010;
    pub const DEVICE_FEATURES_SEL: usize = 0x014;
    pub const DRIVER_FEATURES: usize = 0x020;
    pub const DRIVER_FEATURES_SEL: usize = 0x024;
    pub const QUEUE_SEL: usize = 0x030;
    pub const QUEUE_NUM_MAX: usize = 0x034;
    pub const QUEUE_NUM: usize = 0x038;
    pub const QUEUE_READY: usize = 0x044;
    pub const QUEUE_NOTIFY: usize = 0x050;
    pub const INTERRUPT_STATUS: usize = 0x060;
    pub const INTERRUPT_ACK: usize = 0x064;
    pub const STATUS: usize = 0x070;
    pub const QUEUE_DESC_LOW: usize = 0x080;
    pub const QUEUE_DESC_HIGH: usize = 0x084;
    pub const QUEUE_DRIVER_LOW: usize = 0x090;
    pub const QUEUE_DRIVER_HIGH: usize = 0x094;
    pub const QUEUE_DEVICE_LOW: usize = 0x0a0;
    pub const QUEUE_DEVICE_HIGH: usize = 0x0a4;
    pub const CONFIG: usize = 0x100;
}

/// VirtIO device status bits
pub mod status {
    pub const ACKNOWLEDGE: u32 = 1;
    pub const DRIVER: u32 = 2;
    pub const DRIVER_OK: u32 = 4;
    pub const FEATURES_OK: u32 = 8;
    pub const DEVICE_NEEDS_RESET: u32 = 64;
    pub const FAILED: u32 = 128;
}

/// VirtIO device IDs
pub mod device_id {
    pub const INPUT: u32 = 18;
}

/// VirtIO MMIO magic value
pub const VIRTIO_MAGIC: u32 = 0x74726976; // "virt" in little endian

/// VirtIO MMIO device handle
pub struct VirtioMmio {
    base: usize,
}

impl VirtioMmio {
    pub const fn new(base: usize) -> Self {
        Self { base }
    }

    pub fn read32(&self, offset: usize) -> u32 {
        unsafe { read_volatile((self.base + offset) as *const u32) }
    }

    pub fn write32(&self, offset: usize, value: u32) {
        unsafe { write_volatile((self.base + offset) as *mut u32, value) }
    }

    pub fn read_config<T: Copy>(&self, offset: usize) -> T {
        unsafe { read_volatile((self.base + regs::CONFIG + offset) as *const T) }
    }

    pub fn is_valid(&self) -> bool {
        self.read32(regs::MAGIC_VALUE) == VIRTIO_MAGIC
    }

    pub fn device_id(&self) -> u32 {
        self.read32(regs::DEVICE_ID)
    }

    pub fn version(&self) -> u32 {
        self.read32(regs::VERSION)
    }

    pub fn status(&self) -> u32 {
        self.read32(regs::STATUS)
    }

    pub fn set_status(&self, status: u32) {
        self.write32(regs::STATUS, status);
    }

    pub fn reset(&self) {
        self.write32(regs::STATUS, 0);
    }

    pub fn device_features(&self, index: u32) -> u32 {
        self.write32(regs::DEVICE_FEATURES_SEL, index);
        self.read32(regs::DEVICE_FEATURES)
    }

    pub fn set_driver_features(&self, index: u32, features: u32) {
        self.write32(regs::DRIVER_FEATURES_SEL, index);
        self.write32(regs::DRIVER_FEATURES, features);
    }

    pub fn select_queue(&self, index: u32) {
        self.write32(regs::QUEUE_SEL, index);
    }

    pub fn queue_max_size(&self) -> u32 {
        self.read32(regs::QUEUE_NUM_MAX)
    }

    pub fn set_queue_size(&self, size: u32) {
        self.write32(regs::QUEUE_NUM, size);
    }

    pub fn set_queue_desc(&self, addr: u64) {
        self.write32(regs::QUEUE_DESC_LOW, addr as u32);
        self.write32(regs::QUEUE_DESC_HIGH, (addr >> 32) as u32);
    }

    pub fn set_queue_driver(&self, addr: u64) {
        self.write32(regs::QUEUE_DRIVER_LOW, addr as u32);
        self.write32(regs::QUEUE_DRIVER_HIGH, (addr >> 32) as u32);
    }

    pub fn set_queue_device(&self, addr: u64) {
        self.write32(regs::QUEUE_DEVICE_LOW, addr as u32);
        self.write32(regs::QUEUE_DEVICE_HIGH, (addr >> 32) as u32);
    }

    pub fn set_queue_ready(&self, ready: bool) {
        self.write32(regs::QUEUE_READY, if ready { 1 } else { 0 });
    }

    pub fn notify_queue(&self, queue_index: u32) {
        self.write32(regs::QUEUE_NOTIFY, queue_index);
    }

    pub fn interrupt_status(&self) -> u32 {
        self.read32(regs::INTERRUPT_STATUS)
    }

    pub fn interrupt_ack(&self, status: u32) {
        self.write32(regs::INTERRUPT_ACK, status);
    }
}
