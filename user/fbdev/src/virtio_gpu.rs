//! VirtIO GPU driver for Kenix
//!
//! Implements basic 2D framebuffer using virtio-gpu protocol.

use libvirtio::mmio::{VirtioMmio, status, VIRTIO_MMIO_BASE};
use libvirtio::virtqueue::{Virtqueue, desc_flags, MAX_QUEUE_SIZE};
use libkenix::uart;
use core::sync::atomic::{fence, Ordering};

/// VirtIO GPU device ID
pub const VIRTIO_GPU_DEVICE_ID: u32 = 16;

/// GPU command types
#[repr(u32)]
#[derive(Clone, Copy)]
pub enum GpuCmd {
    GetDisplayInfo = 0x0100,
    ResourceCreate2d = 0x0101,
    ResourceUnref = 0x0102,
    SetScanout = 0x0103,
    ResourceFlush = 0x0104,
    TransferToHost2d = 0x0105,
    ResourceAttachBacking = 0x0106,
    ResourceDetachBacking = 0x0107,
}

/// GPU response types
#[repr(u32)]
#[derive(Clone, Copy, PartialEq)]
pub enum GpuResp {
    OkNodata = 0x1100,
    OkDisplayInfo = 0x1101,
    OkCapsetInfo = 0x1102,
    OkCapset = 0x1103,
    OkEdid = 0x1104,
    ErrUnspec = 0x1200,
    ErrOutOfMemory = 0x1201,
    ErrInvalidScanoutId = 0x1202,
    ErrInvalidResourceId = 0x1203,
    ErrInvalidContextId = 0x1204,
    ErrInvalidParameter = 0x1205,
}

/// Pixel formats
#[repr(u32)]
#[derive(Clone, Copy)]
pub enum GpuFormat {
    B8G8R8A8Unorm = 1,
    B8G8R8X8Unorm = 2,
    A8R8G8B8Unorm = 3,
    X8R8G8B8Unorm = 4,
    R8G8B8A8Unorm = 67,
    X8B8G8R8Unorm = 68,
}

/// Control header (all commands start with this)
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CtrlHdr {
    pub cmd_type: u32,
    pub flags: u32,
    pub fence_id: u64,
    pub ctx_id: u32,
    pub ring_idx: u8,
    pub padding: [u8; 3],
}

/// Rectangle
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct GpuRect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

/// Display info for one scanout
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DisplayOne {
    pub r: GpuRect,
    pub enabled: u32,
    pub flags: u32,
}

/// Response to GET_DISPLAY_INFO
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RespDisplayInfo {
    pub hdr: CtrlHdr,
    pub pmodes: [DisplayOne; 16],
}

impl Default for RespDisplayInfo {
    fn default() -> Self {
        Self {
            hdr: CtrlHdr::default(),
            pmodes: [DisplayOne::default(); 16],
        }
    }
}

/// RESOURCE_CREATE_2D command
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ResourceCreate2d {
    pub hdr: CtrlHdr,
    pub resource_id: u32,
    pub format: u32,
    pub width: u32,
    pub height: u32,
}

/// SET_SCANOUT command
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SetScanout {
    pub hdr: CtrlHdr,
    pub r: GpuRect,
    pub scanout_id: u32,
    pub resource_id: u32,
}

/// RESOURCE_ATTACH_BACKING command
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ResourceAttachBacking {
    pub hdr: CtrlHdr,
    pub resource_id: u32,
    pub nr_entries: u32,
}

/// Memory entry for backing
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MemEntry {
    pub addr: u64,
    pub length: u32,
    pub padding: u32,
}

/// TRANSFER_TO_HOST_2D command
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TransferToHost2d {
    pub hdr: CtrlHdr,
    pub r: GpuRect,
    pub offset: u64,
    pub resource_id: u32,
    pub padding: u32,
}

/// RESOURCE_FLUSH command
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ResourceFlush {
    pub hdr: CtrlHdr,
    pub r: GpuRect,
    pub resource_id: u32,
    pub padding: u32,
}

/// Queue indices
const CONTROLQ: u32 = 0;
const CURSORQ: u32 = 1;

/// Static memory for virtqueue
static mut CTRLQ_MEM: [u8; 4096] = [0; 4096];

/// Command/response buffer (needs to be in same 2MB block as code for VA->PA)
static mut CMD_BUF: [u8; 4096] = [0; 4096];

/// Framebuffer (allocated from the 2MB code block)
/// 800x600x4 = 1,920,000 bytes, fits in 2MB
pub const FB_WIDTH: u32 = 800;
pub const FB_HEIGHT: u32 = 600;
pub const FB_STRIDE: u32 = FB_WIDTH * 4;
pub const FB_SIZE: usize = (FB_WIDTH * FB_HEIGHT * 4) as usize;

static mut FRAMEBUFFER: [u8; FB_SIZE] = [0; FB_SIZE];

/// VirtIO GPU device
pub struct VirtioGpu {
    mmio: VirtioMmio,
    ctrlq: Option<Virtqueue>,
    phys_base: u64,
    pub width: u32,
    pub height: u32,
    resource_id: u32,
    initialized: bool,
}

impl VirtioGpu {
    pub const fn new() -> Self {
        Self {
            mmio: VirtioMmio::new(VIRTIO_MMIO_BASE),
            ctrlq: None,
            phys_base: 0,
            width: 0,
            height: 0,
            resource_id: 1,
            initialized: false,
        }
    }

    pub fn set_phys_base(&mut self, phys_base: u64) {
        self.phys_base = phys_base;
    }

    /// Convert virtual address to physical address
    fn virt_to_phys(&self, vaddr: usize) -> u64 {
        self.phys_base + vaddr as u64
    }

    /// Find and initialize virtio-gpu device
    pub fn init(&mut self) -> bool {
        const NUM_SLOTS: usize = 32;
        const SLOT_SIZE: usize = 0x200;

        // Find virtio-gpu device
        let mut found_slot: Option<usize> = None;
        for slot in 0..NUM_SLOTS {
            let base = VIRTIO_MMIO_BASE + slot * SLOT_SIZE;
            let mmio = VirtioMmio::new(base);

            if mmio.is_valid() && mmio.device_id() == VIRTIO_GPU_DEVICE_ID {
                uart::print("[virtio-gpu] found at slot ");
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
                uart::println("[virtio-gpu] No device found");
                return false;
            }
        };

        self.mmio = VirtioMmio::new(VIRTIO_MMIO_BASE + slot * SLOT_SIZE);

        // Standard virtio initialization
        self.mmio.reset();
        self.mmio.set_status(status::ACKNOWLEDGE);
        self.mmio.set_status(status::ACKNOWLEDGE | status::DRIVER);

        let _features = self.mmio.device_features(0);
        self.mmio.set_driver_features(0, 0);

        self.mmio.set_status(status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK);

        if (self.mmio.status() & status::FEATURES_OK) == 0 {
            uart::println("[virtio-gpu] Features rejected");
            self.mmio.set_status(status::FAILED);
            return false;
        }

        // Set up control queue
        self.mmio.select_queue(CONTROLQ);
        let max_size = self.mmio.queue_max_size();
        if max_size == 0 {
            uart::println("[virtio-gpu] No control queue");
            return false;
        }

        let queue_size = max_size.min(MAX_QUEUE_SIZE as u32) as u16;

        unsafe {
            let ctrlq = Virtqueue::init(CTRLQ_MEM.as_mut_ptr(), queue_size);

            let desc_phys = self.virt_to_phys(ctrlq.desc_addr() as usize);
            let avail_phys = self.virt_to_phys(ctrlq.avail_addr() as usize);
            let used_phys = self.virt_to_phys(ctrlq.used_addr() as usize);

            self.mmio.set_queue_size(queue_size as u32);
            self.mmio.set_queue_desc(desc_phys);
            self.mmio.set_queue_driver(avail_phys);
            self.mmio.set_queue_device(used_phys);
            self.mmio.set_queue_ready(true);

            self.ctrlq = Some(ctrlq);
        }

        // Set DRIVER_OK
        self.mmio.set_status(
            status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK | status::DRIVER_OK
        );

        // Get display info
        if !self.get_display_info() {
            uart::println("[virtio-gpu] Failed to get display info");
            return false;
        }

        // Create resource
        if !self.create_resource() {
            uart::println("[virtio-gpu] Failed to create resource");
            return false;
        }

        // Attach backing
        if !self.attach_backing() {
            uart::println("[virtio-gpu] Failed to attach backing");
            return false;
        }

        // Set scanout
        if !self.set_scanout() {
            uart::println("[virtio-gpu] Failed to set scanout");
            return false;
        }

        self.initialized = true;
        uart::println("[virtio-gpu] Initialized");
        true
    }

    /// Send command and wait for response
    fn send_cmd(&mut self, cmd: &[u8], resp: &mut [u8]) -> bool {
        // Cache phys_base before mutable borrow of ctrlq
        let phys_base = self.phys_base;

        let ctrlq = match &mut self.ctrlq {
            Some(q) => q,
            None => return false,
        };

        unsafe {
            // Copy command to buffer
            let cmd_offset = 0usize;
            let resp_offset = 2048usize;

            core::ptr::copy_nonoverlapping(
                cmd.as_ptr(),
                CMD_BUF.as_mut_ptr().add(cmd_offset),
                cmd.len()
            );

            // Zero response area
            core::ptr::write_bytes(CMD_BUF.as_mut_ptr().add(resp_offset), 0, resp.len());

            let cmd_phys = phys_base + CMD_BUF.as_ptr().add(cmd_offset) as u64;
            let resp_phys = phys_base + CMD_BUF.as_ptr().add(resp_offset) as u64;

            // Allocate 2 descriptors for command chain
            let desc0 = match ctrlq.alloc_desc() {
                Some(d) => d,
                None => return false,
            };
            let desc1 = match ctrlq.alloc_desc() {
                Some(d) => d,
                None => {
                    ctrlq.free_desc(desc0);
                    return false;
                }
            };

            // Set up command descriptor (device reads)
            ctrlq.set_desc(desc0, cmd_phys, cmd.len() as u32, desc_flags::NEXT, desc1);

            // Set up response descriptor (device writes)
            ctrlq.set_desc(desc1, resp_phys, resp.len() as u32, desc_flags::WRITE, 0);

            // Submit
            ctrlq.submit(desc0);
            fence(Ordering::SeqCst);

            // Notify device
            self.mmio.notify_queue(CONTROLQ);

            // Wait for completion - yield CPU instead of busy-spin to avoid deadlocks
            // Use a higher timeout since each yield allows a full scheduler cycle
            let mut timeout = 10000u32;
            while !ctrlq.has_used() && timeout > 0 {
                timeout -= 1;
                libkenix::syscall::yield_cpu();  // Yield instead of spin to allow other tasks to run
            }

            if timeout == 0 {
                uart::println("[virtio-gpu] Command timeout");
                return false;
            }

            // Pop used
            let _ = ctrlq.pop_used();

            // Free descriptors
            ctrlq.free_desc(desc0);
            ctrlq.free_desc(desc1);

            // Copy response back
            core::ptr::copy_nonoverlapping(
                CMD_BUF.as_ptr().add(resp_offset),
                resp.as_mut_ptr(),
                resp.len()
            );
        }

        true
    }

    fn get_display_info(&mut self) -> bool {
        let mut cmd = CtrlHdr::default();
        cmd.cmd_type = GpuCmd::GetDisplayInfo as u32;

        let mut resp = RespDisplayInfo::default();

        let cmd_bytes = unsafe {
            core::slice::from_raw_parts(&cmd as *const _ as *const u8, core::mem::size_of::<CtrlHdr>())
        };
        let resp_bytes = unsafe {
            core::slice::from_raw_parts_mut(&mut resp as *mut _ as *mut u8, core::mem::size_of::<RespDisplayInfo>())
        };

        if !self.send_cmd(cmd_bytes, resp_bytes) {
            return false;
        }

        if resp.hdr.cmd_type != GpuResp::OkDisplayInfo as u32 {
            uart::println("[virtio-gpu] Bad display info response");
            return false;
        }

        // Use first enabled display
        for i in 0..16 {
            if resp.pmodes[i].enabled != 0 {
                self.width = resp.pmodes[i].r.width;
                self.height = resp.pmodes[i].r.height;
                uart::print("[virtio-gpu] Display: ");
                // Just use fixed 800x600 for now
                self.width = FB_WIDTH;
                self.height = FB_HEIGHT;
                uart::println("800x600");
                return true;
            }
        }

        // No display enabled, use default
        self.width = FB_WIDTH;
        self.height = FB_HEIGHT;
        true
    }

    fn create_resource(&mut self) -> bool {
        let mut cmd = ResourceCreate2d::default();
        cmd.hdr.cmd_type = GpuCmd::ResourceCreate2d as u32;
        cmd.resource_id = self.resource_id;
        cmd.format = GpuFormat::X8R8G8B8Unorm as u32;
        cmd.width = self.width;
        cmd.height = self.height;

        let mut resp = CtrlHdr::default();

        let cmd_bytes = unsafe {
            core::slice::from_raw_parts(&cmd as *const _ as *const u8, core::mem::size_of::<ResourceCreate2d>())
        };
        let resp_bytes = unsafe {
            core::slice::from_raw_parts_mut(&mut resp as *mut _ as *mut u8, core::mem::size_of::<CtrlHdr>())
        };

        if !self.send_cmd(cmd_bytes, resp_bytes) {
            return false;
        }

        resp.cmd_type == GpuResp::OkNodata as u32
    }

    fn attach_backing(&mut self) -> bool {
        // Command + 1 memory entry
        #[repr(C)]
        struct AttachCmd {
            hdr: ResourceAttachBacking,
            entry: MemEntry,
        }

        let fb_phys = self.virt_to_phys(unsafe { FRAMEBUFFER.as_ptr() } as usize);

        let mut cmd = AttachCmd {
            hdr: ResourceAttachBacking {
                hdr: CtrlHdr {
                    cmd_type: GpuCmd::ResourceAttachBacking as u32,
                    ..Default::default()
                },
                resource_id: self.resource_id,
                nr_entries: 1,
            },
            entry: MemEntry {
                addr: fb_phys,
                length: FB_SIZE as u32,
                padding: 0,
            },
        };

        let mut resp = CtrlHdr::default();

        let cmd_bytes = unsafe {
            core::slice::from_raw_parts(&cmd as *const _ as *const u8, core::mem::size_of::<AttachCmd>())
        };
        let resp_bytes = unsafe {
            core::slice::from_raw_parts_mut(&mut resp as *mut _ as *mut u8, core::mem::size_of::<CtrlHdr>())
        };

        if !self.send_cmd(cmd_bytes, resp_bytes) {
            return false;
        }

        resp.cmd_type == GpuResp::OkNodata as u32
    }

    fn set_scanout(&mut self) -> bool {
        let mut cmd = SetScanout::default();
        cmd.hdr.cmd_type = GpuCmd::SetScanout as u32;
        cmd.r = GpuRect {
            x: 0,
            y: 0,
            width: self.width,
            height: self.height,
        };
        cmd.scanout_id = 0;
        cmd.resource_id = self.resource_id;

        let mut resp = CtrlHdr::default();

        let cmd_bytes = unsafe {
            core::slice::from_raw_parts(&cmd as *const _ as *const u8, core::mem::size_of::<SetScanout>())
        };
        let resp_bytes = unsafe {
            core::slice::from_raw_parts_mut(&mut resp as *mut _ as *mut u8, core::mem::size_of::<CtrlHdr>())
        };

        if !self.send_cmd(cmd_bytes, resp_bytes) {
            return false;
        }

        resp.cmd_type == GpuResp::OkNodata as u32
    }

    /// Transfer framebuffer region to host and flush
    pub fn flush(&mut self, x: u32, y: u32, width: u32, height: u32) -> bool {
        if !self.initialized {
            return false;
        }

        // Transfer to host
        let mut transfer = TransferToHost2d::default();
        transfer.hdr.cmd_type = GpuCmd::TransferToHost2d as u32;
        transfer.r = GpuRect { x, y, width, height };
        transfer.offset = ((y * FB_STRIDE) + (x * 4)) as u64;
        transfer.resource_id = self.resource_id;

        let mut resp = CtrlHdr::default();

        let cmd_bytes = unsafe {
            core::slice::from_raw_parts(&transfer as *const _ as *const u8, core::mem::size_of::<TransferToHost2d>())
        };
        let resp_bytes = unsafe {
            core::slice::from_raw_parts_mut(&mut resp as *mut _ as *mut u8, core::mem::size_of::<CtrlHdr>())
        };

        if !self.send_cmd(cmd_bytes, resp_bytes) {
            return false;
        }

        if resp.cmd_type != GpuResp::OkNodata as u32 {
            return false;
        }

        // Flush
        let mut flush = ResourceFlush::default();
        flush.hdr.cmd_type = GpuCmd::ResourceFlush as u32;
        flush.r = GpuRect { x, y, width, height };
        flush.resource_id = self.resource_id;

        let cmd_bytes = unsafe {
            core::slice::from_raw_parts(&flush as *const _ as *const u8, core::mem::size_of::<ResourceFlush>())
        };
        let resp_bytes = unsafe {
            core::slice::from_raw_parts_mut(&mut resp as *mut _ as *mut u8, core::mem::size_of::<CtrlHdr>())
        };

        if !self.send_cmd(cmd_bytes, resp_bytes) {
            return false;
        }

        resp.cmd_type == GpuResp::OkNodata as u32
    }

    /// Get framebuffer pointer
    pub fn framebuffer(&self) -> *mut u8 {
        unsafe { FRAMEBUFFER.as_mut_ptr() }
    }

    /// Put a pixel
    pub fn put_pixel(&mut self, x: u32, y: u32, color: u32) {
        if x >= self.width || y >= self.height {
            return;
        }
        let offset = ((y * FB_STRIDE) + (x * 4)) as usize;
        unsafe {
            let ptr = FRAMEBUFFER.as_mut_ptr().add(offset) as *mut u32;
            *ptr = color;
        }
    }

    /// Clear screen
    pub fn clear(&mut self, color: u32) {
        unsafe {
            let ptr = FRAMEBUFFER.as_mut_ptr() as *mut u32;
            for i in 0..(FB_WIDTH * FB_HEIGHT) as usize {
                *ptr.add(i) = color;
            }
        }
        self.flush(0, 0, self.width, self.height);
    }
}
