//! QEMU ramfb (RAM framebuffer) driver
//!
//! ramfb is a simple framebuffer configured via fw_cfg.
//! The guest allocates memory for the framebuffer and tells
//! QEMU about it through the "etc/ramfb" fw_cfg file.

use crate::fwcfg::FwCfg;

/// ramfb configuration structure (written to fw_cfg)
/// Note: We construct bytes manually for DMA to avoid stack allocation issues
#[repr(C, packed)]
#[allow(dead_code)]
pub struct RamfbCfg {
    pub addr: u64,      // Framebuffer physical address (BE)
    pub fourcc: u32,    // Pixel format (BE)
    pub flags: u32,     // Flags (BE, should be 0)
    pub width: u32,     // Display width in pixels (BE)
    pub height: u32,    // Display height in pixels (BE)
    pub stride: u32,    // Bytes per scanline (BE)
}

/// Pixel formats (FourCC codes)
pub const DRM_FORMAT_XRGB8888: u32 = 0x34325258; // 'XR24' - XRGB8888 (32bpp)
pub const DRM_FORMAT_RGB565: u32 = 0x36314752;   // 'RG16' - RGB565 (16bpp)

/// Default resolution
pub const DEFAULT_WIDTH: u32 = 800;
pub const DEFAULT_HEIGHT: u32 = 600;
pub const DEFAULT_BPP: u32 = 32;

/// ramfb driver
pub struct Ramfb {
    fb_vaddr: usize,    // Virtual address of framebuffer
    fb_paddr: u64,      // Physical address of framebuffer
    width: u32,
    height: u32,
    stride: u32,
    bpp: u32,           // Bits per pixel
}

impl Ramfb {
    /// Initialize ramfb with the given framebuffer memory
    ///
    /// # Arguments
    /// * `fwcfg` - fw_cfg interface
    /// * `fb_paddr` - Physical address of allocated framebuffer memory
    /// * `fb_vaddr` - Virtual address of framebuffer memory
    /// * `phys_base` - Physical base for DMA operations
    ///
    /// # Returns
    /// Some(Ramfb) if initialization succeeded, None otherwise
    /// Initialize ramfb with the given framebuffer memory
    ///
    /// # Arguments
    /// * `fwcfg` - fw_cfg interface
    /// * `selector` - fw_cfg selector for etc/ramfb (from find_file)
    /// * `fb_paddr` - Physical address of allocated framebuffer memory
    /// * `fb_vaddr` - Virtual address of framebuffer memory
    /// * `phys_base` - Physical base for DMA operations
    pub fn init_with_selector(
        fwcfg: &FwCfg,
        selector: u16,
        fb_paddr: u64,
        fb_vaddr: usize,
        phys_base: u64,
    ) -> Self {
        use libkenix::uart;

        uart::print_hex("[ramfb] Writing config to selector=", selector as u64);
        uart::print_hex("[ramfb] fb_paddr=", fb_paddr);

        let width = DEFAULT_WIDTH;
        let height = DEFAULT_HEIGHT;
        let bpp = DEFAULT_BPP;
        let stride = width * (bpp / 8);

        // Create the ramfb configuration as bytes
        // RamfbCfg is 28 bytes: u64 + u32 + u32 + u32 + u32 + u32
        // All values must be big-endian
        let mut cfg_bytes = [0u8; 28];

        // addr (u64 BE) at offset 0
        cfg_bytes[0..8].copy_from_slice(&fb_paddr.to_be_bytes());

        // fourcc (u32 BE) at offset 8
        cfg_bytes[8..12].copy_from_slice(&DRM_FORMAT_XRGB8888.to_be_bytes());

        // flags (u32 BE) at offset 12 - already zero

        // width (u32 BE) at offset 16
        cfg_bytes[16..20].copy_from_slice(&width.to_be_bytes());

        // height (u32 BE) at offset 20
        cfg_bytes[20..24].copy_from_slice(&height.to_be_bytes());

        // stride (u32 BE) at offset 24
        cfg_bytes[24..28].copy_from_slice(&stride.to_be_bytes());

        // Write configuration to fw_cfg using DMA
        unsafe {
            fwcfg.dma_write(selector, &cfg_bytes, phys_base);
        }

        uart::println("[ramfb] DMA write complete");

        Self {
            fb_vaddr,
            fb_paddr,
            width,
            height,
            stride,
            bpp,
        }
    }

    /// Initialize ramfb (legacy interface that finds the file)
    pub fn init(
        fwcfg: &FwCfg,
        fb_paddr: u64,
        fb_vaddr: usize,
        phys_base: u64,
    ) -> Option<Self> {
        let (selector, _size) = fwcfg.find_file(b"etc/ramfb")?;
        Some(Self::init_with_selector(fwcfg, selector, fb_paddr, fb_vaddr, phys_base))
    }

    /// Get framebuffer width
    pub fn width(&self) -> u32 {
        self.width
    }

    /// Get framebuffer height
    pub fn height(&self) -> u32 {
        self.height
    }

    /// Get bytes per pixel
    pub fn bytes_per_pixel(&self) -> u32 {
        self.bpp / 8
    }

    /// Get stride (bytes per row)
    pub fn stride(&self) -> u32 {
        self.stride
    }

    /// Clear the entire screen with a color
    pub fn clear(&mut self, color: u32) {
        let fb = self.fb_vaddr as *mut u32;
        let pixels = (self.stride / 4) * self.height;

        for i in 0..pixels {
            unsafe {
                fb.add(i as usize).write_volatile(color);
            }
        }
    }

    /// Set a single pixel
    pub fn put_pixel(&mut self, x: u32, y: u32, color: u32) {
        if x >= self.width || y >= self.height {
            return;
        }

        let offset = (y * self.stride / 4 + x) as usize;
        let fb = self.fb_vaddr as *mut u32;

        unsafe {
            fb.add(offset).write_volatile(color);
        }
    }

    /// Fill a rectangle with a color
    pub fn fill_rect(&mut self, x: u32, y: u32, w: u32, h: u32, color: u32) {
        let x_end = (x + w).min(self.width);
        let y_end = (y + h).min(self.height);

        let fb = self.fb_vaddr as *mut u32;
        let stride_pixels = self.stride / 4;

        for py in y..y_end {
            let row_offset = (py * stride_pixels) as usize;
            for px in x..x_end {
                unsafe {
                    fb.add(row_offset + px as usize).write_volatile(color);
                }
            }
        }
    }

    /// Get a mutable pointer to the framebuffer
    pub fn framebuffer(&self) -> *mut u32 {
        self.fb_vaddr as *mut u32
    }
}

/// Common colors (XRGB8888 format)
pub mod colors {
    pub const BLACK: u32 = 0x00000000;
    pub const WHITE: u32 = 0x00FFFFFF;
    pub const RED: u32 = 0x00FF0000;
    pub const GREEN: u32 = 0x0000FF00;
    pub const BLUE: u32 = 0x000000FF;
    pub const YELLOW: u32 = 0x00FFFF00;
    pub const CYAN: u32 = 0x0000FFFF;
    pub const MAGENTA: u32 = 0x00FF00FF;
    pub const GRAY: u32 = 0x00808080;
    pub const DARK_GRAY: u32 = 0x00404040;
    pub const LIGHT_GRAY: u32 = 0x00C0C0C0;
}
