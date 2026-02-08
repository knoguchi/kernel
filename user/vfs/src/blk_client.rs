//! Block device client for VFS
//!
//! Communicates with the blkdev server via IPC to read/write disk sectors.

use libkenix::ipc::{self, Message};
use libkenix::shm;
use libkenix::msg::{BLK_READ, BLK_WRITE, BLK_INFO};
use libkenix::tasks::BLKDEV;

/// Sector size in bytes
pub const SECTOR_SIZE: usize = 512;

/// Block device client
pub struct BlkClient {
    /// Shared memory region for data transfer
    shm_id: Option<u64>,
    /// Mapped address of shared memory
    shm_addr: Option<usize>,
    /// Size of shared memory region
    shm_size: usize,
    /// Device capacity in sectors
    capacity: u64,
}

impl BlkClient {
    /// Create a new block device client
    pub const fn new() -> Self {
        BlkClient {
            shm_id: None,
            shm_addr: None,
            shm_size: 0,
            capacity: 0,
        }
    }

    /// Initialize the client (get device info and allocate SHM)
    pub fn init(&mut self) -> bool {
        // Get device info
        let mut msg = Message::new(BLK_INFO, [0; 4]);
        ipc::call(BLKDEV, &mut msg);

        if (msg.tag as i64) < 0 {
            return false;
        }

        self.capacity = msg.data[0];

        // Allocate shared memory for transfers (128KB = 256 sectors)
        let size = 131072;
        let shm_id = shm::create(size);
        if shm_id < 0 {
            return false;
        }

        let shm_addr = shm::map(shm_id as u64, 0);
        if shm_addr < 0 {
            return false;
        }

        // Grant blkdev access to our SHM
        if shm::grant(shm_id as u64, BLKDEV) < 0 {
            shm::unmap(shm_id as u64);
            return false;
        }

        self.shm_id = Some(shm_id as u64);
        self.shm_addr = Some(shm_addr as usize);
        self.shm_size = size;

        true
    }

    /// Get device capacity in sectors
    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Read sectors from the device
    ///
    /// # Arguments
    /// * `sector` - Starting sector number
    /// * `buf` - Buffer to read into (must be multiple of SECTOR_SIZE)
    ///
    /// # Returns
    /// Number of bytes read, or negative error code
    pub fn read(&self, sector: u64, buf: &mut [u8]) -> isize {
        let shm_id = match self.shm_id {
            Some(id) => id,
            None => return -1,
        };
        let shm_addr = match self.shm_addr {
            Some(addr) => addr,
            None => return -1,
        };

        if buf.len() % SECTOR_SIZE != 0 {
            return -1;
        }

        let count = buf.len() / SECTOR_SIZE;
        if count * SECTOR_SIZE > self.shm_size {
            return -1; // Request too large
        }

        // Send read request
        let mut msg = Message::new(BLK_READ, [sector, count as u64, shm_id, 0]);
        ipc::call(BLKDEV, &mut msg);

        let result = msg.tag as i64;
        if result < 0 {
            return result as isize;
        }

        // Copy data from shared memory to user buffer
        let bytes_read = result as usize;
        unsafe {
            core::ptr::copy_nonoverlapping(
                shm_addr as *const u8,
                buf.as_mut_ptr(),
                bytes_read.min(buf.len()),
            );
        }

        bytes_read as isize
    }

    /// Write sectors to the device
    ///
    /// # Arguments
    /// * `sector` - Starting sector number
    /// * `buf` - Buffer to write from (must be multiple of SECTOR_SIZE)
    ///
    /// # Returns
    /// Number of bytes written, or negative error code
    pub fn write(&self, sector: u64, buf: &[u8]) -> isize {
        let shm_id = match self.shm_id {
            Some(id) => id,
            None => return -1,
        };
        let shm_addr = match self.shm_addr {
            Some(addr) => addr,
            None => return -1,
        };

        if buf.len() % SECTOR_SIZE != 0 {
            return -1;
        }

        let count = buf.len() / SECTOR_SIZE;
        if count * SECTOR_SIZE > self.shm_size {
            return -1;
        }

        // Copy data to shared memory
        unsafe {
            core::ptr::copy_nonoverlapping(
                buf.as_ptr(),
                shm_addr as *mut u8,
                buf.len(),
            );
        }

        // Send write request
        let mut msg = Message::new(BLK_WRITE, [sector, count as u64, shm_id, 0]);
        ipc::call(BLKDEV, &mut msg);

        msg.tag as isize
    }

    /// Read a single sector
    pub fn read_sector(&self, sector: u64, buf: &mut [u8; SECTOR_SIZE]) -> bool {
        self.read(sector, buf) == SECTOR_SIZE as isize
    }
}
