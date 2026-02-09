//! QEMU fw_cfg interface for ARM/AArch64
//!
//! The fw_cfg device provides a way for guests to configure QEMU devices.
//! On ARM/AArch64, it uses MMIO at 0x09020000.

use core::ptr::{read_volatile, write_volatile};

/// fw_cfg MMIO base address for ARM/AArch64
const FWCFG_BASE: usize = 0x0902_0000;

/// fw_cfg register offsets
const FWCFG_SELECTOR: usize = 0x8;  // Selector register (2 bytes, write-only)
const FWCFG_DMA: usize = 0x10;      // DMA address register (8 bytes)

/// fw_cfg selector values
pub const FW_CFG_SIGNATURE: u16 = 0x0000;
pub const FW_CFG_FILE_DIR: u16 = 0x0019;

/// fw_cfg DMA control bits
const FW_CFG_DMA_CTL_ERROR: u32 = 0x01;
const FW_CFG_DMA_CTL_SELECT: u32 = 0x08;
const FW_CFG_DMA_CTL_WRITE: u32 = 0x10;

/// DMA access structure - must be in static memory for correct physical address calculation
/// Must be 8-byte aligned per fw_cfg DMA specification
#[repr(C, align(8))]
struct FwCfgDmaAccess {
    control: u32,   // BE
    length: u32,    // BE
    address: u64,   // BE
}

/// Static DMA buffer - in .bss section which is part of the code block
/// This ensures phys_base calculation works correctly
/// The FwCfgDmaAccess struct has align(8) so this is properly aligned
static mut DMA_ACCESS: FwCfgDmaAccess = FwCfgDmaAccess {
    control: 0,
    length: 0,
    address: 0,
};

/// Wrapper struct to ensure 8-byte alignment for DMA data buffer
#[repr(C, align(8))]
struct DmaDataBuf([u8; 64]);

/// Static buffer for DMA data (64 bytes should be enough for ramfb config)
static mut DMA_DATA_BUF: DmaDataBuf = DmaDataBuf([0u8; 64]);

/// fw_cfg file directory entry
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct FwCfgFile {
    pub size: u32,      // BE - file size
    pub select: u16,    // BE - selector key
    pub reserved: u16,
    pub name: [u8; 56], // null-terminated file name
}

/// fw_cfg interface
pub struct FwCfg {
    base: usize,
}

impl FwCfg {
    /// Create a new fw_cfg interface
    pub const fn new() -> Self {
        Self { base: FWCFG_BASE }
    }

    /// Select a fw_cfg item
    pub fn select(&self, key: u16) {
        unsafe {
            let selector = (self.base + FWCFG_SELECTOR) as *mut u16;
            // Selector is written in big-endian
            write_volatile(selector, key.to_be());
        }
    }

    /// Read a single byte from the selected fw_cfg item
    pub fn read_byte(&self) -> u8 {
        unsafe {
            let data = self.base as *const u8;
            read_volatile(data)
        }
    }

    /// Read bytes from the selected fw_cfg item
    pub fn read_bytes(&self, buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            *byte = self.read_byte();
        }
    }

    /// Read a big-endian u16
    pub fn read_be16(&self) -> u16 {
        let mut buf = [0u8; 2];
        self.read_bytes(&mut buf);
        u16::from_be_bytes(buf)
    }

    /// Read a big-endian u32
    pub fn read_be32(&self) -> u32 {
        let mut buf = [0u8; 4];
        self.read_bytes(&mut buf);
        u32::from_be_bytes(buf)
    }

    /// Check if fw_cfg is available by reading signature
    /// Returns the signature bytes for debugging
    pub fn read_signature(&self) -> [u8; 4] {
        self.select(FW_CFG_SIGNATURE);
        let mut sig = [0u8; 4];
        self.read_bytes(&mut sig);
        sig
    }

    /// Check if fw_cfg is available by reading signature
    pub fn is_available(&self) -> bool {
        let sig = self.read_signature();
        // QEMU fw_cfg signature is "QEMU"
        &sig == b"QEMU"
    }

    /// Find a file by name and return its selector
    pub fn find_file(&self, name: &[u8]) -> Option<(u16, u32)> {
        // Read file directory
        self.select(FW_CFG_FILE_DIR);

        // First u32 is the number of files (BE)
        let count = self.read_be32();

        // Read each file entry
        for _ in 0..count {
            let mut entry = FwCfgFile {
                size: 0,
                select: 0,
                reserved: 0,
                name: [0; 56],
            };

            // Read entry fields
            entry.size = self.read_be32();
            entry.select = self.read_be16();
            let _ = self.read_be16(); // reserved
            self.read_bytes(&mut entry.name);

            // Compare name (name is null-terminated)
            let mut match_len = 0;
            for (i, &c) in name.iter().enumerate() {
                if i >= entry.name.len() || entry.name[i] != c {
                    break;
                }
                match_len = i + 1;
            }

            // Check if full name matched and entry name is null-terminated
            if match_len == name.len() &&
               (match_len >= entry.name.len() || entry.name[match_len] == 0) {
                return Some((entry.select, entry.size));
            }
        }

        None
    }

    /// Write data to a fw_cfg file using DMA
    ///
    /// Uses static buffers to ensure correct physical address calculation.
    /// Max data length is 64 bytes.
    ///
    /// # Safety
    /// This function uses static mutable buffers and is not thread-safe.
    pub unsafe fn dma_write(&self, selector: u16, data: &[u8], phys_base: u64) {
        let len = data.len().min(64);

        // Copy data to static buffer (in .bss, so part of code block)
        for i in 0..len {
            DMA_DATA_BUF.0[i] = data[i];
        }

        // Calculate physical address of data buffer
        let data_vaddr = DMA_DATA_BUF.0.as_ptr() as usize;
        let data_paddr = data_vaddr as u64 + phys_base;

        // Set up DMA access structure in static memory
        DMA_ACCESS.control = (FW_CFG_DMA_CTL_SELECT | FW_CFG_DMA_CTL_WRITE | ((selector as u32) << 16)).to_be();
        DMA_ACCESS.length = (len as u32).to_be();
        DMA_ACCESS.address = data_paddr.to_be();

        // Memory barrier to ensure writes are visible
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

        // Calculate physical address of DMA structure
        let dma_vaddr = core::ptr::addr_of!(DMA_ACCESS) as usize;
        let dma_paddr = dma_vaddr as u64 + phys_base;

        // Write DMA address to trigger the operation (big-endian)
        let dma_reg = (self.base + FWCFG_DMA) as *mut u64;
        write_volatile(dma_reg, dma_paddr.to_be());

        // Poll for completion (control field becomes 0 when done)
        let mut timeout = 100000u32;
        loop {
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            let control = u32::from_be(core::ptr::read_volatile(&DMA_ACCESS.control));
            if control == 0 {
                break;
            }
            if control & FW_CFG_DMA_CTL_ERROR != 0 {
                // DMA error
                break;
            }
            timeout -= 1;
            if timeout == 0 {
                // Timeout - DMA taking too long
                break;
            }
            libkenix::syscall::yield_cpu();
        }
    }
}
