//! Block device server for Kenix
//!
//! Provides block device access via IPC using VirtIO-blk driver.

#![no_std]
#![no_main]

mod blk;

use libkenix::ipc::{self, Message, TASK_ANY};
use libkenix::msg::{BLK_READ, BLK_WRITE, BLK_INFO, ERR_OK, ERR_IO, ERR_INVAL};
use libkenix::shm;
use libkenix::syscall;
use libkenix::uart;
use libkenix::VIRTIO_BLK_IRQ;
use blk::{VirtioBlk, SECTOR_SIZE};
use libvirtio::mmio::VIRTIO_MMIO_BASE;

/// Block device server state
static mut BLOCK_DEV: VirtioBlk = VirtioBlk::new(VIRTIO_MMIO_BASE);

/// Physical base address of our 2MB code block (passed in x0 by kernel)
static mut PHYS_BASE: u64 = 0;

/// Bounce buffer for DMA - internal to blkdev so has known physical address
/// Size: 256 sectors = 128KB (increased for better performance)
static mut BOUNCE_BUF: [u8; 131072] = [0; 131072];

// ============================================================================
// SHM Cache - avoid repeated map/unmap overhead
// ============================================================================

const MAX_CACHED_SHM: usize = 8;

#[derive(Clone, Copy)]
struct CachedShm {
    shm_id: u64,
    addr: usize,
}

static mut SHM_CACHE: [Option<CachedShm>; MAX_CACHED_SHM] = [None; MAX_CACHED_SHM];
static mut SHM_CACHE_LRU: [u8; MAX_CACHED_SHM] = [0; MAX_CACHED_SHM];

/// Get a cached SHM mapping or map it and cache it
fn get_or_map_shm(shm_id: u64) -> Option<usize> {
    unsafe {
        // First, check if already cached
        for i in 0..MAX_CACHED_SHM {
            if let Some(ref entry) = SHM_CACHE[i] {
                if entry.shm_id == shm_id {
                    // Update LRU - this entry is now most recently used
                    let old_lru = SHM_CACHE_LRU[i];
                    for j in 0..MAX_CACHED_SHM {
                        if SHM_CACHE_LRU[j] > old_lru {
                            SHM_CACHE_LRU[j] -= 1;
                        }
                    }
                    SHM_CACHE_LRU[i] = (MAX_CACHED_SHM - 1) as u8;
                    return Some(entry.addr);
                }
            }
        }

        // Not cached - need to map it
        let addr = shm::map(shm_id, 0);
        if addr < 0 {
            return None;
        }

        // Find a slot to cache it (prefer empty slot, then LRU)
        let mut slot = None;
        let mut min_lru = u8::MAX;

        for i in 0..MAX_CACHED_SHM {
            if SHM_CACHE[i].is_none() {
                slot = Some(i);
                break;
            }
            if SHM_CACHE_LRU[i] < min_lru {
                min_lru = SHM_CACHE_LRU[i];
                slot = Some(i);
            }
        }

        if let Some(i) = slot {
            // Evict old entry if present
            if let Some(ref old) = SHM_CACHE[i] {
                shm::unmap(old.shm_id);
            }

            // Update LRU counters
            for j in 0..MAX_CACHED_SHM {
                if SHM_CACHE[j].is_some() {
                    SHM_CACHE_LRU[j] = SHM_CACHE_LRU[j].saturating_sub(1);
                }
            }

            SHM_CACHE[i] = Some(CachedShm {
                shm_id,
                addr: addr as usize,
            });
            SHM_CACHE_LRU[i] = (MAX_CACHED_SHM - 1) as u8;
        }

        Some(addr as usize)
    }
}

// ============================================================================
// Block Cache - reduces disk I/O for repeated reads
// ============================================================================

/// Number of sectors to cache (256 sectors = 128KB)
const CACHE_SECTORS: usize = 256;

/// Block cache data
static mut BLOCK_CACHE: [u8; CACHE_SECTORS * SECTOR_SIZE] = [0; CACHE_SECTORS * SECTOR_SIZE];

/// Cache tags: sector number for each cache slot (u64::MAX = invalid)
static mut CACHE_TAGS: [u64; CACHE_SECTORS] = [u64::MAX; CACHE_SECTORS];

/// Direct-mapped cache lookup
fn cache_lookup(sector: u64) -> Option<&'static [u8]> {
    let slot = (sector as usize) % CACHE_SECTORS;
    unsafe {
        if CACHE_TAGS[slot] == sector {
            let start = slot * SECTOR_SIZE;
            Some(&BLOCK_CACHE[start..start + SECTOR_SIZE])
        } else {
            None
        }
    }
}

/// Insert sector data into cache
fn cache_insert(sector: u64, data: &[u8]) {
    if data.len() != SECTOR_SIZE {
        return;
    }
    let slot = (sector as usize) % CACHE_SECTORS;
    unsafe {
        let start = slot * SECTOR_SIZE;
        BLOCK_CACHE[start..start + SECTOR_SIZE].copy_from_slice(data);
        CACHE_TAGS[slot] = sector;
    }
}

/// Insert multiple consecutive sectors into cache
fn cache_insert_range(start_sector: u64, data: &[u8], count: usize) {
    for i in 0..count {
        let sector = start_sector + i as u64;
        let offset = i * SECTOR_SIZE;
        if offset + SECTOR_SIZE <= data.len() {
            cache_insert(sector, &data[offset..offset + SECTOR_SIZE]);
        }
    }
}

/// Invalidate cache entries for a range of sectors (for write consistency)
fn cache_invalidate_range(start_sector: u64, count: usize) {
    for i in 0..count {
        let sector = start_sector + i as u64;
        let slot = (sector as usize) % CACHE_SECTORS;
        unsafe {
            if CACHE_TAGS[slot] == sector {
                CACHE_TAGS[slot] = u64::MAX;
            }
        }
    }
}

/// Convert a virtual address to physical address for DMA
#[inline]
#[allow(dead_code)]
fn va_to_pa(va: u64) -> u64 {
    unsafe { libkenix::va_to_pa(va, PHYS_BASE) }
}

#[no_mangle]
pub extern "C" fn _start(phys_base: u64) -> ! {
    // Store the physical base for VA->PA conversion
    unsafe {
        PHYS_BASE = phys_base;
        BLOCK_DEV.set_phys_base(phys_base);
    }

    uart::println("[blkdev] Starting...");

    // Initialize block device
    let init_ok = unsafe { BLOCK_DEV.init() };

    if !init_ok {
        uart::println("[blkdev] VirtIO init failed");
        syscall::exit(1);
    }

    let _capacity = unsafe { BLOCK_DEV.capacity() };
    uart::println("[blkdev] VirtIO ready");

    // Register for IRQ handling
    let irq_result = syscall::irq_register(VIRTIO_BLK_IRQ);
    if irq_result < 0 {
        uart::println("[blkdev] IRQ registration failed");
        // Continue anyway - we can poll
    }

    // Main server loop
    #[allow(unused_variables, unused_assignments)]
    let mut read_count = 0u32;
    loop {
        // Wait for message
        let recv = ipc::recv(TASK_ANY);
        let _sender = recv.sender;
        let msg = recv.msg;

        match msg.tag {
            BLK_READ => {
                #[allow(unused_assignments)]
                { read_count += 1; }
                // BLK_READ: data[0] = sector, data[1] = count, data[2] = shm_id
                let sector = msg.data[0];
                let count = msg.data[1] as usize;
                let shm_id = msg.data[2];
                let total_bytes = count * SECTOR_SIZE;

                // Check if request fits in bounce buffer (now 128KB)
                if total_bytes > 131072 {
                    let reply = Message::new(ERR_INVAL as u64, [0; 4]);
                    ipc::reply(&reply);
                    continue;
                }

                // Get cached SHM mapping (avoids map/unmap overhead)
                let buf_addr = match get_or_map_shm(shm_id) {
                    Some(addr) => addr,
                    None => {
                        let reply = Message::new(ERR_INVAL as u64, [0; 4]);
                        ipc::reply(&reply);
                        continue;
                    }
                };

                let shm_buf = unsafe {
                    core::slice::from_raw_parts_mut(buf_addr as *mut u8, total_bytes)
                };

                // Try to satisfy request from block cache first
                let mut all_cached = true;
                for i in 0..count {
                    let sec = sector + i as u64;
                    if let Some(cached_data) = cache_lookup(sec) {
                        let offset = i * SECTOR_SIZE;
                        shm_buf[offset..offset + SECTOR_SIZE].copy_from_slice(cached_data);
                    } else {
                        all_cached = false;
                        break;
                    }
                }

                if all_cached {
                    // All sectors were in cache - no disk I/O needed
                    let reply = Message::new(total_bytes as u64, [0; 4]);
                    ipc::reply(&reply);
                    continue;
                }

                // Cache miss - read from disk into bounce buffer
                let bounce = unsafe { &mut BOUNCE_BUF[..total_bytes] };
                let result = unsafe { BLOCK_DEV.read(sector, bounce) };

                // If successful, copy from bounce buffer to SHM and update cache
                if result >= 0 {
                    shm_buf.copy_from_slice(bounce);

                    // Update block cache with the data we just read
                    cache_insert_range(sector, bounce, count);
                }

                // Note: SHM stays mapped in cache for reuse

                // Send reply
                let reply = if result >= 0 {
                    Message::new(result as u64, [0; 4])
                } else {
                    Message::new(ERR_IO as u64, [0; 4])
                };
                ipc::reply(&reply);
            }

            BLK_WRITE => {
                // BLK_WRITE: data[0] = sector, data[1] = count, data[2] = shm_id
                let sector = msg.data[0];
                let count = msg.data[1] as usize;
                let shm_id = msg.data[2];
                let total_bytes = count * SECTOR_SIZE;

                // Check if request fits in bounce buffer (now 128KB)
                if total_bytes > 131072 {
                    let reply = Message::new(ERR_INVAL as u64, [0; 4]);
                    ipc::reply(&reply);
                    continue;
                }

                // Get cached SHM mapping (avoids map/unmap overhead)
                let buf_addr = match get_or_map_shm(shm_id) {
                    Some(addr) => addr,
                    None => {
                        let reply = Message::new(ERR_INVAL as u64, [0; 4]);
                        ipc::reply(&reply);
                        continue;
                    }
                };

                // Copy from SHM to bounce buffer
                let shm_buf = unsafe {
                    core::slice::from_raw_parts(buf_addr as *const u8, total_bytes)
                };
                let bounce = unsafe { &mut BOUNCE_BUF[..total_bytes] };
                bounce.copy_from_slice(shm_buf);

                // Write from bounce buffer
                let result = unsafe { BLOCK_DEV.write(sector, bounce) };

                // Invalidate cache for written sectors to maintain consistency
                if result >= 0 {
                    cache_invalidate_range(sector, count);
                }

                // Note: SHM stays mapped in cache for reuse

                // Send reply
                let reply = if result >= 0 {
                    Message::new(result as u64, [0; 4])
                } else {
                    Message::new(ERR_IO as u64, [0; 4])
                };
                ipc::reply(&reply);
            }

            BLK_INFO => {
                // BLK_INFO: returns capacity and sector size
                let cap = unsafe { BLOCK_DEV.capacity() };
                let reply = Message::new(ERR_OK as u64, [cap, SECTOR_SIZE as u64, 0, 0]);
                ipc::reply(&reply);
            }

            _ => {
                // Unknown message
                let reply = Message::new(ERR_INVAL as u64, [0; 4]);
                ipc::reply(&reply);
            }
        }
    }
}
