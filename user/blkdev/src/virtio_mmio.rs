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
    pub const MAGIC_VALUE: usize = 0x000;        // Magic value "virt"
    pub const VERSION: usize = 0x004;            // Device version
    pub const DEVICE_ID: usize = 0x008;          // Virtio subsystem device ID
    pub const VENDOR_ID: usize = 0x00c;          // Virtio subsystem vendor ID
    pub const DEVICE_FEATURES: usize = 0x010;    // Device features
    pub const DEVICE_FEATURES_SEL: usize = 0x014; // Device feature selection
    pub const DRIVER_FEATURES: usize = 0x020;    // Driver features
    pub const DRIVER_FEATURES_SEL: usize = 0x024; // Driver feature selection
    pub const QUEUE_SEL: usize = 0x030;          // Queue selection
    pub const QUEUE_NUM_MAX: usize = 0x034;      // Max queue size
    pub const QUEUE_NUM: usize = 0x038;          // Queue size
    pub const QUEUE_READY: usize = 0x044;        // Queue ready
    pub const QUEUE_NOTIFY: usize = 0x050;       // Queue notify
    pub const INTERRUPT_STATUS: usize = 0x060;   // Interrupt status
    pub const INTERRUPT_ACK: usize = 0x064;      // Interrupt acknowledge
    pub const STATUS: usize = 0x070;             // Device status
    pub const QUEUE_DESC_LOW: usize = 0x080;     // Queue descriptor table (low)
    pub const QUEUE_DESC_HIGH: usize = 0x084;    // Queue descriptor table (high)
    pub const QUEUE_DRIVER_LOW: usize = 0x090;   // Queue available ring (low)
    pub const QUEUE_DRIVER_HIGH: usize = 0x094;  // Queue available ring (high)
    pub const QUEUE_DEVICE_LOW: usize = 0x0a0;   // Queue used ring (low)
    pub const QUEUE_DEVICE_HIGH: usize = 0x0a4;  // Queue used ring (high)
    pub const CONFIG: usize = 0x100;             // Configuration space
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
    pub const BLOCK: u32 = 2;
}

/// VirtIO MMIO magic value
pub const VIRTIO_MAGIC: u32 = 0x74726976; // "virt" in little endian

/// VirtIO MMIO device handle
pub struct VirtioMmio {
    base: usize,
}

impl VirtioMmio {
    /// Create a new VirtIO MMIO handle
    pub const fn new(base: usize) -> Self {
        Self { base }
    }

    /// Read a 32-bit register
    pub fn read32(&self, offset: usize) -> u32 {
        unsafe { read_volatile((self.base + offset) as *const u32) }
    }

    /// Write a 32-bit register
    pub fn write32(&self, offset: usize, value: u32) {
        unsafe { write_volatile((self.base + offset) as *mut u32, value) }
    }

    /// Read from configuration space
    pub fn read_config<T: Copy>(&self, offset: usize) -> T {
        unsafe { read_volatile((self.base + regs::CONFIG + offset) as *const T) }
    }

    /// Check if this is a valid VirtIO device
    pub fn is_valid(&self) -> bool {
        self.read32(regs::MAGIC_VALUE) == VIRTIO_MAGIC
    }

    /// Get device ID
    pub fn device_id(&self) -> u32 {
        self.read32(regs::DEVICE_ID)
    }

    /// Get device version
    pub fn version(&self) -> u32 {
        self.read32(regs::VERSION)
    }

    /// Read current device status
    pub fn status(&self) -> u32 {
        self.read32(regs::STATUS)
    }

    /// Set device status
    pub fn set_status(&self, status: u32) {
        self.write32(regs::STATUS, status);
    }

    /// Reset the device
    pub fn reset(&self) {
        self.write32(regs::STATUS, 0);
    }

    /// Read device features (32-bit word at index)
    pub fn device_features(&self, index: u32) -> u32 {
        self.write32(regs::DEVICE_FEATURES_SEL, index);
        self.read32(regs::DEVICE_FEATURES)
    }

    /// Write driver features (32-bit word at index)
    pub fn set_driver_features(&self, index: u32, features: u32) {
        self.write32(regs::DRIVER_FEATURES_SEL, index);
        self.write32(regs::DRIVER_FEATURES, features);
    }

    /// Select a virtqueue
    pub fn select_queue(&self, index: u32) {
        self.write32(regs::QUEUE_SEL, index);
    }

    /// Get maximum queue size
    pub fn queue_max_size(&self) -> u32 {
        self.read32(regs::QUEUE_NUM_MAX)
    }

    /// Set queue size
    pub fn set_queue_size(&self, size: u32) {
        self.write32(regs::QUEUE_NUM, size);
    }

    /// Set queue descriptor table address
    pub fn set_queue_desc(&self, addr: u64) {
        self.write32(regs::QUEUE_DESC_LOW, addr as u32);
        self.write32(regs::QUEUE_DESC_HIGH, (addr >> 32) as u32);
    }

    /// Set queue available ring address
    pub fn set_queue_driver(&self, addr: u64) {
        self.write32(regs::QUEUE_DRIVER_LOW, addr as u32);
        self.write32(regs::QUEUE_DRIVER_HIGH, (addr >> 32) as u32);
    }

    /// Set queue used ring address
    pub fn set_queue_device(&self, addr: u64) {
        self.write32(regs::QUEUE_DEVICE_LOW, addr as u32);
        self.write32(regs::QUEUE_DEVICE_HIGH, (addr >> 32) as u32);
    }

    /// Mark queue as ready
    pub fn set_queue_ready(&self, ready: bool) {
        self.write32(regs::QUEUE_READY, if ready { 1 } else { 0 });
    }

    /// Notify device about queue updates
    pub fn notify_queue(&self, queue_index: u32) {
        self.write32(regs::QUEUE_NOTIFY, queue_index);
    }

    /// Read interrupt status
    pub fn interrupt_status(&self) -> u32 {
        self.read32(regs::INTERRUPT_STATUS)
    }

    /// Acknowledge interrupt
    pub fn interrupt_ack(&self, status: u32) {
        self.write32(regs::INTERRUPT_ACK, status);
    }
}
