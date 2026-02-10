//! VirtIO network device protocol
//!
//! Implements the VirtIO network device specification.

#![allow(dead_code)]

use libvirtio::mmio::{VirtioMmio, status, device_id};
use libvirtio::virtqueue::{Virtqueue, desc_flags, MAX_QUEUE_SIZE};
use core::sync::atomic::{fence, Ordering};

/// Maximum packet size (MTU + Ethernet header)
pub const MAX_PACKET_SIZE: usize = 1514;

/// VirtIO net header size
pub const VIRTIO_NET_HDR_SIZE: usize = 12;

/// VirtIO-net feature bits
pub mod features {
    pub const CSUM: u64 = 1 << 0;           // Host handles checksums
    pub const GUEST_CSUM: u64 = 1 << 1;     // Guest handles checksums
    pub const MAC: u64 = 1 << 5;            // Device has given MAC address
    pub const GSO: u64 = 1 << 6;            // Deprecated GSO
    pub const GUEST_TSO4: u64 = 1 << 7;     // Guest can receive TSOv4
    pub const GUEST_TSO6: u64 = 1 << 8;     // Guest can receive TSOv6
    pub const GUEST_ECN: u64 = 1 << 9;      // Guest can receive TSO with ECN
    pub const GUEST_UFO: u64 = 1 << 10;     // Guest can receive UFO
    pub const HOST_TSO4: u64 = 1 << 11;     // Host can receive TSOv4
    pub const HOST_TSO6: u64 = 1 << 12;     // Host can receive TSOv6
    pub const HOST_ECN: u64 = 1 << 13;      // Host can receive TSO with ECN
    pub const HOST_UFO: u64 = 1 << 14;      // Host can receive UFO
    pub const MRG_RXBUF: u64 = 1 << 15;     // Merge receive buffers
    pub const STATUS: u64 = 1 << 16;        // Status field in config
    pub const CTRL_VQ: u64 = 1 << 17;       // Control VQ
    pub const CTRL_RX: u64 = 1 << 18;       // Control RX mode
    pub const CTRL_VLAN: u64 = 1 << 19;     // Control VLAN filtering
    pub const GUEST_ANNOUNCE: u64 = 1 << 21; // Guest can announce
}

/// VirtIO-net header (prepended to each packet)
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VirtioNetHdr {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
    pub num_buffers: u16,  // Only if MRG_RXBUF
}

/// VirtIO-net GSO types
pub mod gso_type {
    pub const NONE: u8 = 0;
    pub const TCPV4: u8 = 1;
    pub const UDP: u8 = 3;
    pub const TCPV6: u8 = 4;
    pub const ECN: u8 = 0x80;
}

/// VirtIO network device driver
pub struct VirtioNet {
    mmio: VirtioMmio,
    /// RX queue (queue 0)
    rx_queue: Virtqueue,
    /// TX queue (queue 1)
    tx_queue: Virtqueue,
    /// Memory for RX virtqueue structures
    rx_queue_mem: [u8; 4096],
    /// Memory for TX virtqueue structures
    tx_queue_mem: [u8; 4096],
    /// RX packet buffer
    rx_buf: [u8; MAX_PACKET_SIZE + VIRTIO_NET_HDR_SIZE],
    /// TX packet buffer (with header)
    tx_buf: [u8; MAX_PACKET_SIZE + VIRTIO_NET_HDR_SIZE],
    /// MAC address
    pub mac: [u8; 6],
    /// Link status (if STATUS feature)
    pub link_up: bool,
    /// Physical base for VA->PA conversion
    phys_base: u64,
    /// Whether device was initialized successfully
    initialized: bool,
}

impl VirtioNet {
    /// Create a new uninitialized network device
    pub const fn new(mmio_base: usize) -> Self {
        Self {
            mmio: VirtioMmio::new(mmio_base),
            rx_queue: unsafe { core::mem::zeroed() },
            tx_queue: unsafe { core::mem::zeroed() },
            rx_queue_mem: [0; 4096],
            tx_queue_mem: [0; 4096],
            rx_buf: [0; MAX_PACKET_SIZE + VIRTIO_NET_HDR_SIZE],
            tx_buf: [0; MAX_PACKET_SIZE + VIRTIO_NET_HDR_SIZE],
            mac: [0; 6],
            link_up: false,
            phys_base: 0,
            initialized: false,
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

    /// Initialize the network device
    ///
    /// Returns true on success, false on failure.
    pub fn init(&mut self) -> bool {
        use libkenix::uart;

        // Scan virtio-mmio slots to find network device
        const VIRTIO_BASE: usize = 0x0a00_0000;
        const SLOT_SIZE: usize = 0x200;
        const NUM_SLOTS: usize = 32;

        let mut found_slot: Option<usize> = None;
        for slot in 0..NUM_SLOTS {
            let base = VIRTIO_BASE + slot * SLOT_SIZE;
            let mmio = VirtioMmio::new(base);

            if mmio.is_valid() && mmio.device_id() == device_id::NET {
                uart::print("[netdev] found at slot ");
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
                uart::println("[netdev] no network device found");
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
        let features_lo = self.mmio.device_features(0);
        let features_hi = self.mmio.device_features(1);

        // VIRTIO_F_VERSION_1 (bit 32)
        const VIRTIO_F_VERSION_1: u32 = 1 << 0;

        // We need MAC feature to read MAC address
        let has_mac = (features_lo & (features::MAC as u32)) != 0;

        // Set driver features - we don't need any advanced features
        self.mmio.set_driver_features(0, 0);
        let driver_features_hi = if features_hi & VIRTIO_F_VERSION_1 != 0 {
            VIRTIO_F_VERSION_1
        } else {
            0
        };
        self.mmio.set_driver_features(1, driver_features_hi);

        // Set FEATURES_OK
        self.mmio.set_status(status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK);

        // Check FEATURES_OK is still set
        if (self.mmio.status() & status::FEATURES_OK) == 0 {
            uart::println("[netdev] features not OK");
            self.mmio.set_status(status::FAILED);
            return false;
        }

        // Read MAC address from config space
        if has_mac {
            for i in 0..6 {
                self.mac[i] = self.mmio.read_config_byte(i);
            }
        }

        // Set up RX queue (queue 0)
        self.mmio.select_queue(0);
        let rx_max_size = self.mmio.queue_max_size();
        if rx_max_size == 0 {
            uart::println("[netdev] RX queue max size is 0");
            self.mmio.set_status(status::FAILED);
            return false;
        }

        let rx_queue_size = (rx_max_size as u16).min(MAX_QUEUE_SIZE as u16);
        self.rx_queue = unsafe {
            Virtqueue::init(self.rx_queue_mem.as_mut_ptr(), rx_queue_size)
        };

        let rx_desc_pa = self.va_to_pa(self.rx_queue.desc_addr());
        let rx_avail_pa = self.va_to_pa(self.rx_queue.avail_addr());
        let rx_used_pa = self.va_to_pa(self.rx_queue.used_addr());

        self.mmio.set_queue_size(rx_queue_size as u32);
        self.mmio.set_queue_desc(rx_desc_pa);
        self.mmio.set_queue_driver(rx_avail_pa);
        self.mmio.set_queue_device(rx_used_pa);
        self.mmio.set_queue_ready(true);

        // Set up TX queue (queue 1)
        self.mmio.select_queue(1);
        let tx_max_size = self.mmio.queue_max_size();
        if tx_max_size == 0 {
            uart::println("[netdev] TX queue max size is 0");
            self.mmio.set_status(status::FAILED);
            return false;
        }

        let tx_queue_size = (tx_max_size as u16).min(MAX_QUEUE_SIZE as u16);
        self.tx_queue = unsafe {
            Virtqueue::init(self.tx_queue_mem.as_mut_ptr(), tx_queue_size)
        };

        let tx_desc_pa = self.va_to_pa(self.tx_queue.desc_addr());
        let tx_avail_pa = self.va_to_pa(self.tx_queue.avail_addr());
        let tx_used_pa = self.va_to_pa(self.tx_queue.used_addr());

        self.mmio.set_queue_size(tx_queue_size as u32);
        self.mmio.set_queue_desc(tx_desc_pa);
        self.mmio.set_queue_driver(tx_avail_pa);
        self.mmio.set_queue_device(tx_used_pa);
        self.mmio.set_queue_ready(true);

        // Set DRIVER_OK
        self.mmio.set_status(status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK | status::DRIVER_OK);

        // Prime RX queue with one buffer
        self.prime_rx();

        self.link_up = true;
        self.initialized = true;

        true
    }

    /// Prime the RX queue with a receive buffer
    fn prime_rx(&mut self) {
        let desc_idx = match self.rx_queue.alloc_desc() {
            Some(d) => d,
            None => return,
        };

        let buf_pa = self.va_to_pa(self.rx_buf.as_ptr() as u64);

        unsafe {
            self.rx_queue.set_desc(
                desc_idx,
                buf_pa,
                self.rx_buf.len() as u32,
                desc_flags::WRITE,
                0,
            );
            self.rx_queue.submit(desc_idx);
        }

        self.mmio.notify_queue(0);
    }

    /// Send a packet
    ///
    /// # Arguments
    /// * `data` - Packet data (without VirtIO header)
    ///
    /// # Returns
    /// Number of bytes sent, or negative error code
    pub fn send(&mut self, data: &[u8]) -> isize {
        if !self.initialized || data.len() > MAX_PACKET_SIZE {
            return -1;
        }

        // Allocate descriptor
        let desc_idx = match self.tx_queue.alloc_desc() {
            Some(d) => d,
            None => return -1,
        };

        // Prepare header (all zeros for simple case)
        let header = VirtioNetHdr::default();
        unsafe {
            core::ptr::copy_nonoverlapping(
                &header as *const _ as *const u8,
                self.tx_buf.as_mut_ptr(),
                VIRTIO_NET_HDR_SIZE,
            );
        }

        // Copy packet data after header
        self.tx_buf[VIRTIO_NET_HDR_SIZE..VIRTIO_NET_HDR_SIZE + data.len()]
            .copy_from_slice(data);

        let total_len = VIRTIO_NET_HDR_SIZE + data.len();
        let buf_pa = self.va_to_pa(self.tx_buf.as_ptr() as u64);

        unsafe {
            self.tx_queue.set_desc(
                desc_idx,
                buf_pa,
                total_len as u32,
                0, // Read-only for device
                0,
            );
            self.tx_queue.submit(desc_idx);
        }

        fence(Ordering::SeqCst);
        self.mmio.notify_queue(1);

        // Wait for completion - yield CPU instead of busy-spin
        let mut timeout = 100000u32;
        while !self.tx_queue.has_used() && timeout > 0 {
            timeout -= 1;
            libkenix::syscall::yield_cpu();
        }
        if timeout == 0 {
            return -5; // Timeout error
        }

        let (_head, _len) = unsafe { self.tx_queue.pop_used().unwrap() };
        self.tx_queue.free_desc(desc_idx);

        data.len() as isize
    }

    /// Receive a packet
    ///
    /// # Arguments
    /// * `buf` - Buffer to receive packet data into (without VirtIO header)
    ///
    /// # Returns
    /// Number of bytes received, or negative error code, or 0 if no packet
    pub fn recv(&mut self, buf: &mut [u8]) -> isize {
        if !self.initialized {
            return -1;
        }

        // Check if there's a received packet
        if !self.rx_queue.has_used() {
            return 0; // No packet available
        }

        let (head, len) = unsafe { self.rx_queue.pop_used().unwrap() };
        self.rx_queue.free_desc(head);

        // Skip VirtIO header
        let packet_len = (len as usize).saturating_sub(VIRTIO_NET_HDR_SIZE);
        let copy_len = packet_len.min(buf.len());

        buf[..copy_len].copy_from_slice(
            &self.rx_buf[VIRTIO_NET_HDR_SIZE..VIRTIO_NET_HDR_SIZE + copy_len]
        );

        // Re-prime RX queue
        self.prime_rx();

        copy_len as isize
    }

    /// Acknowledge interrupt
    pub fn ack_interrupt(&mut self) {
        let status = self.mmio.interrupt_status();
        self.mmio.interrupt_ack(status);
    }

    /// Check if initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}
