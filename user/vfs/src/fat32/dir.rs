//! FAT32 directory entry parsing
//!
//! Directory entries are 32 bytes each and contain file metadata.
//! Long filenames (LFN) use multiple entries before the short name entry.

/// Directory entry size in bytes
pub const DIR_ENTRY_SIZE: usize = 32;

/// Directory entry attributes
pub mod attr {
    pub const READ_ONLY: u8 = 0x01;
    pub const HIDDEN: u8 = 0x02;
    pub const SYSTEM: u8 = 0x04;
    pub const VOLUME_ID: u8 = 0x08;
    pub const DIRECTORY: u8 = 0x10;
    pub const ARCHIVE: u8 = 0x20;
    pub const LONG_NAME: u8 = 0x0F;
}

/// A parsed directory entry
#[derive(Clone, Copy)]
pub struct DirEntry {
    /// Short filename (8.3 format, space-padded)
    pub name: [u8; 11],
    /// File attributes
    pub attributes: u8,
    /// First cluster (high 16 bits)
    pub first_cluster_hi: u16,
    /// First cluster (low 16 bits)
    pub first_cluster_lo: u16,
    /// File size in bytes
    pub file_size: u32,
}

impl DirEntry {
    /// Parse a directory entry from raw bytes
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < DIR_ENTRY_SIZE {
            return None;
        }

        // Check for end of directory
        if data[0] == 0x00 {
            return None;
        }

        // Check for deleted entry
        if data[0] == 0xE5 {
            return None;
        }

        let mut name = [0u8; 11];
        name.copy_from_slice(&data[0..11]);

        let attributes = data[11];
        let first_cluster_hi = u16::from_le_bytes([data[20], data[21]]);
        let first_cluster_lo = u16::from_le_bytes([data[26], data[27]]);
        let file_size = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);

        Some(DirEntry {
            name,
            attributes,
            first_cluster_hi,
            first_cluster_lo,
            file_size,
        })
    }

    /// Get the first cluster number
    pub fn first_cluster(&self) -> u32 {
        ((self.first_cluster_hi as u32) << 16) | (self.first_cluster_lo as u32)
    }

    /// Check if this is a directory
    pub fn is_directory(&self) -> bool {
        (self.attributes & attr::DIRECTORY) != 0
    }

    /// Check if this is a long filename entry
    pub fn is_long_name(&self) -> bool {
        (self.attributes & attr::LONG_NAME) == attr::LONG_NAME
    }

    /// Check if this is a volume label
    pub fn is_volume_label(&self) -> bool {
        (self.attributes & attr::VOLUME_ID) != 0
    }

    /// Get the short filename as a string slice
    /// Returns (name, extension) tuple
    pub fn short_name(&self) -> ([u8; 8], [u8; 3]) {
        let mut name = [0u8; 8];
        let mut ext = [0u8; 3];
        name.copy_from_slice(&self.name[0..8]);
        ext.copy_from_slice(&self.name[8..11]);
        (name, ext)
    }

    /// Compare with a filename (case-insensitive, 8.3 format)
    pub fn matches_name(&self, target: &[u8]) -> bool {
        // Build the full 8.3 name from target
        let mut target_83 = [b' '; 11];

        // Find the dot position
        let dot_pos = target.iter().position(|&c| c == b'.');

        let (name_part, ext_part) = match dot_pos {
            Some(pos) => (&target[..pos], &target[pos + 1..]),
            None => (target, &[] as &[u8]),
        };

        // Copy name (up to 8 chars)
        let name_len = name_part.len().min(8);
        for i in 0..name_len {
            target_83[i] = to_upper(name_part[i]);
        }

        // Copy extension (up to 3 chars)
        let ext_len = ext_part.len().min(3);
        for i in 0..ext_len {
            target_83[8 + i] = to_upper(ext_part[i]);
        }

        // Compare (case-insensitive)
        for i in 0..11 {
            let a = to_upper(self.name[i]);
            let b = target_83[i];
            if a != b {
                return false;
            }
        }

        true
    }
}

/// Convert a character to uppercase
fn to_upper(c: u8) -> u8 {
    if c >= b'a' && c <= b'z' {
        c - 32
    } else {
        c
    }
}

/// Iterator over directory entries in a cluster chain
pub struct DirIterator<'a> {
    /// Data buffer (one cluster)
    pub data: &'a [u8],
    /// Current offset in the buffer
    pub offset: usize,
}

impl<'a> DirIterator<'a> {
    /// Create a new directory iterator
    pub fn new(data: &'a [u8]) -> Self {
        DirIterator { data, offset: 0 }
    }
}

impl<'a> Iterator for DirIterator<'a> {
    type Item = DirEntry;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.offset + DIR_ENTRY_SIZE > self.data.len() {
                return None;
            }

            let entry_data = &self.data[self.offset..];

            // Check for end of directory
            if entry_data[0] == 0x00 {
                return None;
            }

            self.offset += DIR_ENTRY_SIZE;

            // Skip deleted entries
            if entry_data[0] == 0xE5 {
                continue;
            }

            if let Some(entry) = DirEntry::parse(entry_data) {
                // Skip long filename entries and volume labels
                if entry.is_long_name() || entry.is_volume_label() {
                    continue;
                }
                return Some(entry);
            }
        }
    }
}
