//! FAT32 filesystem implementation

#![allow(dead_code)]

pub mod bpb;
pub mod fat;
pub mod dir;
pub mod file;

pub use bpb::BiosParameterBlock;
pub use fat::FatTable;
pub use dir::{DirEntry, DirIterator};
pub use file::Fat32File;

/// Sector size in bytes
pub const SECTOR_SIZE: usize = 512;

/// FAT32 filesystem
pub struct Fat32 {
    /// BIOS parameter block
    pub bpb: BiosParameterBlock,
    /// First sector of the FAT table
    pub fat_start: u32,
    /// First sector of the data region
    pub data_start: u32,
    /// First cluster of root directory
    pub root_cluster: u32,
    /// Sectors per cluster
    pub sectors_per_cluster: u8,
}

impl Fat32 {
    /// Create a new FAT32 filesystem from the boot sector
    pub fn new(boot_sector: &[u8; SECTOR_SIZE]) -> Option<Self> {
        let bpb = BiosParameterBlock::parse(boot_sector)?;

        // Calculate key offsets
        let fat_start = bpb.reserved_sectors as u32;
        let fat_size = bpb.fat_size_32;
        let num_fats = bpb.num_fats as u32;
        let data_start = fat_start + (fat_size * num_fats);

        Some(Fat32 {
            fat_start,
            data_start,
            root_cluster: bpb.root_cluster,
            sectors_per_cluster: bpb.sectors_per_cluster,
            bpb,
        })
    }

    /// Convert a cluster number to a sector number
    pub fn cluster_to_sector(&self, cluster: u32) -> u32 {
        // Clusters start at 2
        self.data_start + (cluster - 2) * self.sectors_per_cluster as u32
    }

    /// Get the sector number for a FAT entry
    pub fn fat_sector_for_cluster(&self, cluster: u32) -> u32 {
        self.fat_start + (cluster * 4) / SECTOR_SIZE as u32
    }

    /// Get the offset within a sector for a FAT entry
    pub fn fat_offset_for_cluster(&self, cluster: u32) -> usize {
        ((cluster * 4) % SECTOR_SIZE as u32) as usize
    }
}
