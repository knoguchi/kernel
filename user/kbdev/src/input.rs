//! VirtIO Input device driver
//!
//! Handles keyboard input via virtio-input device.

use libvirtio::mmio::{VirtioMmio, device_id, status, VIRTIO_MMIO_BASE};
use libvirtio::virtqueue::{Virtqueue, desc_flags, MAX_QUEUE_SIZE};
use libkenix::uart;

/// VirtIO input event (matches Linux input_event structure)
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VirtioInputEvent {
    pub type_: u16,
    pub code: u16,
    pub value: u32,
}

/// Event types (from Linux input.h)
pub mod event_type {
    pub const EV_SYN: u16 = 0x00;
    pub const EV_KEY: u16 = 0x01;
    pub const EV_REL: u16 = 0x02;
    pub const EV_ABS: u16 = 0x03;
}

/// VirtIO Input configuration select values
pub mod config_select {
    pub const VIRTIO_INPUT_CFG_UNSET: u8 = 0x00;
    pub const VIRTIO_INPUT_CFG_ID_NAME: u8 = 0x01;
    pub const VIRTIO_INPUT_CFG_ID_SERIAL: u8 = 0x02;
    pub const VIRTIO_INPUT_CFG_ID_DEVIDS: u8 = 0x03;
    pub const VIRTIO_INPUT_CFG_PROP_BITS: u8 = 0x10;
    pub const VIRTIO_INPUT_CFG_EV_BITS: u8 = 0x11;
    pub const VIRTIO_INPUT_CFG_ABS_INFO: u8 = 0x12;
}

/// Queue indices
const EVENTQ: u32 = 0;
const STATUSQ: u32 = 1;

/// Number of event buffers to keep ready
const NUM_EVENT_BUFFERS: usize = 8;

/// VirtIO Input device
pub struct VirtioInput {
    mmio: VirtioMmio,
    eventq: Option<Virtqueue>,
    phys_base: u64,
    initialized: bool,
}

/// Static memory for virtqueue
static mut EVENTQ_MEM: [u8; 4096] = [0; 4096];

/// Event buffers for receiving input events
static mut EVENT_BUFFERS: [VirtioInputEvent; NUM_EVENT_BUFFERS] =
    [VirtioInputEvent { type_: 0, code: 0, value: 0 }; NUM_EVENT_BUFFERS];

impl VirtioInput {
    pub const fn new(base: usize) -> Self {
        Self {
            mmio: VirtioMmio::new(base),
            eventq: None,
            phys_base: 0,
            initialized: false,
        }
    }

    pub fn set_phys_base(&mut self, phys_base: u64) {
        self.phys_base = phys_base;
    }

    /// Convert virtual address to physical address
    fn virt_to_phys(&self, vaddr: usize) -> u64 {
        // Our code is mapped at vaddr 0, phys at phys_base
        self.phys_base + vaddr as u64
    }

    /// Initialize the virtio-input device
    pub fn init(&mut self) -> bool {
        // Scan virtio-mmio slots to find input device
        const NUM_SLOTS: usize = 32;
        const SLOT_SIZE: usize = 0x200;
        const VIRTIO_BASE: usize = VIRTIO_MMIO_BASE;

        let mut found_slot: Option<usize> = None;
        for slot in 0..NUM_SLOTS {
            let base = VIRTIO_BASE + slot * SLOT_SIZE;
            let mmio = VirtioMmio::new(base);

            if mmio.is_valid() && mmio.device_id() == device_id::INPUT {
                uart::print("[kbdev] found at slot ");
                let digit = (slot as u8) + b'0';
                uart::print(unsafe { core::str::from_utf8_unchecked(&[digit]) });
                uart::println("");
                found_slot = Some(slot);
                break;
            }
        }

        let slot = match found_slot {
            Some(s) => s,
            None => {
                uart::println("[kbdev] No virtio-input device found");
                return false;
            }
        };

        self.mmio = VirtioMmio::new(VIRTIO_BASE + slot * SLOT_SIZE);

        // Reset device
        self.mmio.reset();

        // Set ACKNOWLEDGE status
        self.mmio.set_status(status::ACKNOWLEDGE);

        // Set DRIVER status
        self.mmio.set_status(status::ACKNOWLEDGE | status::DRIVER);

        // Read device features (we don't need any special features)
        let _features = self.mmio.device_features(0);

        // Set driver features (accept defaults)
        self.mmio.set_driver_features(0, 0);

        // Set FEATURES_OK
        self.mmio.set_status(status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK);

        // Check FEATURES_OK is still set
        if (self.mmio.status() & status::FEATURES_OK) == 0 {
            uart::println("[kbdev] Device rejected features");
            self.mmio.set_status(status::FAILED);
            return false;
        }

        // Set up eventq (queue 0) for receiving events
        self.mmio.select_queue(EVENTQ);
        let max_size = self.mmio.queue_max_size();
        if max_size == 0 {
            uart::println("[kbdev] Queue 0 not available");
            self.mmio.set_status(status::FAILED);
            return false;
        }

        let queue_size = max_size.min(MAX_QUEUE_SIZE as u32) as u16;

        unsafe {
            let eventq = Virtqueue::init(EVENTQ_MEM.as_mut_ptr(), queue_size);

            // Set queue addresses (convert to physical)
            let desc_phys = self.virt_to_phys(eventq.desc_addr() as usize);
            let avail_phys = self.virt_to_phys(eventq.avail_addr() as usize);
            let used_phys = self.virt_to_phys(eventq.used_addr() as usize);

            self.mmio.set_queue_size(queue_size as u32);
            self.mmio.set_queue_desc(desc_phys);
            self.mmio.set_queue_driver(avail_phys);
            self.mmio.set_queue_device(used_phys);
            self.mmio.set_queue_ready(true);

            self.eventq = Some(eventq);
        }

        // Set DRIVER_OK to finish initialization
        self.mmio.set_status(
            status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK | status::DRIVER_OK
        );

        // Pre-populate event queue with buffers
        self.refill_event_buffers();

        self.initialized = true;
        uart::println("[kbdev] VirtIO-input ready");
        true
    }

    /// Refill the event queue with empty buffers
    fn refill_event_buffers(&mut self) {
        // Cache phys_base before mutable borrow of eventq
        let phys_base = self.phys_base;

        let eventq = match &mut self.eventq {
            Some(q) => q,
            None => return,
        };

        unsafe {
            for i in 0..NUM_EVENT_BUFFERS {
                if let Some(desc_idx) = eventq.alloc_desc() {
                    let buf_vaddr = EVENT_BUFFERS.as_ptr().add(i) as usize;
                    let buf_phys = phys_base + buf_vaddr as u64;

                    eventq.set_desc(
                        desc_idx,
                        buf_phys,
                        core::mem::size_of::<VirtioInputEvent>() as u32,
                        desc_flags::WRITE,
                        0,
                    );
                    eventq.submit(desc_idx);
                }
            }
        }

        // Notify device
        self.mmio.notify_queue(EVENTQ);
    }

    /// Poll for input events
    /// Returns Some(event) if an event is available, None otherwise
    pub fn poll_event(&mut self) -> Option<VirtioInputEvent> {
        // Cache phys_base before mutable borrow of eventq
        let phys_base = self.phys_base;

        let eventq = match &mut self.eventq {
            Some(q) => q,
            None => return None,
        };

        unsafe {
            if let Some((desc_idx, _len)) = eventq.pop_used() {
                // Get the event from the buffer
                let buf_idx = desc_idx as usize % NUM_EVENT_BUFFERS;
                let event = EVENT_BUFFERS[buf_idx];

                // Resubmit the buffer
                let buf_vaddr = EVENT_BUFFERS.as_ptr().add(buf_idx) as usize;
                let buf_phys = phys_base + buf_vaddr as u64;
                eventq.set_desc(
                    desc_idx,
                    buf_phys,
                    core::mem::size_of::<VirtioInputEvent>() as u32,
                    desc_flags::WRITE,
                    0,
                );
                eventq.submit(desc_idx);
                self.mmio.notify_queue(EVENTQ);

                // Acknowledge interrupt
                let int_status = self.mmio.interrupt_status();
                if int_status != 0 {
                    self.mmio.interrupt_ack(int_status);
                }

                return Some(event);
            }
        }

        None
    }

    /// Check if device has pending events
    pub fn has_event(&self) -> bool {
        if let Some(ref eventq) = self.eventq {
            eventq.has_used()
        } else {
            false
        }
    }
}
