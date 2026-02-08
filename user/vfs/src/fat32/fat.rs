//! FAT (File Allocation Table) operations
//!
//! The FAT is a linked list where each entry points to the next cluster
//! in a file's chain, or contains a special marker.

#![allow(dead_code)]

use super::SECTOR_SIZE;

/// End of chain marker
pub const FAT_EOC: u32 = 0x0FFF_FFF8;
/// Free cluster marker
pub const FAT_FREE: u32 = 0x0000_0000;
/// Bad cluster marker
pub const FAT_BAD: u32 = 0x0FFF_FFF7;

/// FAT table operations
pub struct FatTable;

impl FatTable {
    /// Read a FAT entry from a sector buffer
    ///
    /// # Arguments
    /// * `sector_data` - The FAT sector containing the entry
    /// * `offset` - Offset within the sector to the entry
    ///
    /// # Returns
    /// The cluster number (masked to 28 bits)
    pub fn read_entry(sector_data: &[u8; SECTOR_SIZE], offset: usize) -> u32 {
        if offset + 4 > SECTOR_SIZE {
            return FAT_EOC;
        }

        let entry = u32::from_le_bytes([
            sector_data[offset],
            sector_data[offset + 1],
            sector_data[offset + 2],
            sector_data[offset + 3],
        ]);

        // Mask to 28 bits (upper 4 bits are reserved)
        entry & 0x0FFF_FFFF
    }

    /// Check if a FAT entry marks end of chain
    pub fn is_end_of_chain(entry: u32) -> bool {
        entry >= FAT_EOC
    }

    /// Check if a FAT entry marks a free cluster
    pub fn is_free(entry: u32) -> bool {
        entry == FAT_FREE
    }

    /// Check if a FAT entry marks a bad cluster
    pub fn is_bad(entry: u32) -> bool {
        entry == FAT_BAD
    }
}
