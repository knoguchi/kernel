//! BIOS Parameter Block parsing for FAT32
//!
//! The BPB is located at the beginning of the boot sector and contains
//! filesystem metadata needed to navigate the FAT structure.

#![allow(dead_code)]

use super::SECTOR_SIZE;

/// BIOS Parameter Block for FAT32
#[derive(Clone, Copy, Debug)]
pub struct BiosParameterBlock {
    /// Bytes per sector (typically 512)
    pub bytes_per_sector: u16,
    /// Sectors per cluster (power of 2, 1-128)
    pub sectors_per_cluster: u8,
    /// Reserved sectors before first FAT
    pub reserved_sectors: u16,
    /// Number of FATs (typically 2)
    pub num_fats: u8,
    /// Sectors per FAT (FAT32 extended)
    pub fat_size_32: u32,
    /// Root directory cluster
    pub root_cluster: u32,
    /// Total sectors (if fits in 16 bits)
    pub total_sectors_16: u16,
    /// Total sectors (32-bit)
    pub total_sectors_32: u32,
}

impl BiosParameterBlock {
    /// Parse BPB from boot sector
    pub fn parse(sector: &[u8; SECTOR_SIZE]) -> Option<Self> {
        // Check boot sector signature
        if sector[510] != 0x55 || sector[511] != 0xAA {
            return None;
        }

        // Read BPB fields
        let bytes_per_sector = u16::from_le_bytes([sector[11], sector[12]]);
        let sectors_per_cluster = sector[13];
        let reserved_sectors = u16::from_le_bytes([sector[14], sector[15]]);
        let num_fats = sector[16];
        let total_sectors_16 = u16::from_le_bytes([sector[19], sector[20]]);
        let total_sectors_32 = u32::from_le_bytes([
            sector[32], sector[33], sector[34], sector[35],
        ]);

        // FAT32-specific fields (at offset 36+)
        let fat_size_32 = u32::from_le_bytes([
            sector[36], sector[37], sector[38], sector[39],
        ]);
        let root_cluster = u32::from_le_bytes([
            sector[44], sector[45], sector[46], sector[47],
        ]);

        // Basic validation
        if bytes_per_sector != 512 {
            // We only support 512-byte sectors
            return None;
        }
        if sectors_per_cluster == 0 || sectors_per_cluster > 128 {
            return None;
        }
        if num_fats == 0 {
            return None;
        }
        if fat_size_32 == 0 {
            return None;
        }

        Some(BiosParameterBlock {
            bytes_per_sector,
            sectors_per_cluster,
            reserved_sectors,
            num_fats,
            fat_size_32,
            root_cluster,
            total_sectors_16,
            total_sectors_32,
        })
    }

    /// Get total sectors
    pub fn total_sectors(&self) -> u32 {
        if self.total_sectors_16 != 0 {
            self.total_sectors_16 as u32
        } else {
            self.total_sectors_32
        }
    }
}
