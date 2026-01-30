//! FAT32 file operations
//!
//! Handles reading file data by following the cluster chain.

use super::dir::DirEntry;

/// A FAT32 file handle
#[derive(Clone, Copy)]
pub struct Fat32File {
    /// First cluster of the file
    pub first_cluster: u32,
    /// File size in bytes
    pub size: u32,
    /// Current read position
    pub position: u32,
    /// Current cluster being read
    pub current_cluster: u32,
    /// Position within current cluster
    pub cluster_offset: u32,
}

impl Fat32File {
    /// Create a file handle from a directory entry
    pub fn from_dir_entry(entry: &DirEntry) -> Self {
        Fat32File {
            first_cluster: entry.first_cluster(),
            size: entry.file_size,
            position: 0,
            current_cluster: entry.first_cluster(),
            cluster_offset: 0,
        }
    }

    /// Get the remaining bytes in the file
    pub fn remaining(&self) -> u32 {
        self.size.saturating_sub(self.position)
    }

    /// Check if we're at end of file
    pub fn is_eof(&self) -> bool {
        self.position >= self.size
    }

    /// Seek to a position in the file
    /// Note: This resets the cluster chain traversal from the beginning
    pub fn seek(&mut self, position: u32) {
        self.position = position.min(self.size);
        // Reset cluster tracking - the actual cluster will need to be found
        // by following the chain from the beginning
        self.current_cluster = self.first_cluster;
        self.cluster_offset = 0;
    }

    /// Advance position after reading
    pub fn advance(&mut self, bytes: u32, cluster_size: u32) {
        self.position += bytes;
        self.cluster_offset += bytes;

        // Check if we've moved past the current cluster
        if self.cluster_offset >= cluster_size {
            self.cluster_offset = 0;
            // current_cluster will be updated by the caller after reading FAT
        }
    }

    /// Update the current cluster (called after reading FAT)
    pub fn set_current_cluster(&mut self, cluster: u32) {
        self.current_cluster = cluster;
    }
}
