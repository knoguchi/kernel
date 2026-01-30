//! Block device server for Kenix
//!
//! Provides block device access via IPC using VirtIO-blk driver.

#![no_std]
#![no_main]

mod virtio_mmio;
mod virtqueue;
mod blk;

use libkenix::ipc::{self, Message, TASK_ANY};
use libkenix::msg::{BLK_READ, BLK_WRITE, BLK_INFO, ERR_OK, ERR_IO, ERR_INVAL};
use libkenix::shm;
use libkenix::syscall;
use libkenix::console;
use libkenix::VIRTIO_BLK_IRQ;
use blk::{VirtioBlk, SECTOR_SIZE};
use virtio_mmio::VIRTIO_MMIO_BASE;

/// Block device server state
static mut BLOCK_DEV: VirtioBlk = VirtioBlk::new(VIRTIO_MMIO_BASE);

/// Physical base address of our 2MB code block (passed in x0 by kernel)
static mut PHYS_BASE: u64 = 0;

/// Bounce buffer for DMA - internal to blkdev so has known physical address
/// Size: 8 sectors = 4KB (matches SHM allocation)
static mut BOUNCE_BUF: [u8; 4096] = [0; 4096];

/// Convert a virtual address to physical address for DMA
#[inline]
fn va_to_pa(va: u64) -> u64 {
    // Our address space: VA 0 maps to PA PHYS_BASE
    // So PA = VA + PHYS_BASE
    unsafe { va + PHYS_BASE }
}

#[no_mangle]
pub extern "C" fn _start(phys_base: u64) -> ! {
    // Store the physical base for VA->PA conversion
    unsafe {
        PHYS_BASE = phys_base;
        BLOCK_DEV.set_phys_base(phys_base);
    }

    console::println("[blkdev] Starting...");

    // Initialize block device
    let init_ok = unsafe { BLOCK_DEV.init() };

    if !init_ok {
        console::println("[blkdev] VirtIO init failed");
        syscall::exit(1);
    }

    let _capacity = unsafe { BLOCK_DEV.capacity() };
    console::println("[blkdev] VirtIO ready");

    // Register for IRQ handling
    let irq_result = syscall::irq_register(VIRTIO_BLK_IRQ);
    if irq_result < 0 {
        console::println("[blkdev] IRQ registration failed");
        // Continue anyway - we can poll
    }

    // Main server loop
    loop {
        // Wait for message
        let recv = ipc::recv(TASK_ANY);
        let sender = recv.sender;
        let msg = recv.msg;

        match msg.tag {
            BLK_READ => {
                // BLK_READ: data[0] = sector, data[1] = count, data[2] = shm_id
                let sector = msg.data[0];
                let count = msg.data[1] as usize;
                let shm_id = msg.data[2];
                let total_bytes = count * SECTOR_SIZE;

                // Check if request fits in bounce buffer
                if total_bytes > 4096 {
                    let reply = Message::new(ERR_INVAL as u64, [0; 4]);
                    ipc::reply(&reply);
                    continue;
                }

                // Map the shared memory buffer for copying
                let buf_addr = shm::map(shm_id, 0);
                if buf_addr < 0 {
                    let reply = Message::new(ERR_INVAL as u64, [0; 4]);
                    ipc::reply(&reply);
                    continue;
                }

                // Read into bounce buffer (which has known physical address)
                let bounce = unsafe { &mut BOUNCE_BUF[..total_bytes] };
                let result = unsafe { BLOCK_DEV.read(sector, bounce) };

                // If successful, copy from bounce buffer to SHM
                if result >= 0 {
                    let shm_buf = unsafe {
                        core::slice::from_raw_parts_mut(buf_addr as *mut u8, total_bytes)
                    };
                    shm_buf.copy_from_slice(bounce);
                }

                // Unmap shared memory
                shm::unmap(shm_id);

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

                // Check if request fits in bounce buffer
                if total_bytes > 4096 {
                    let reply = Message::new(ERR_INVAL as u64, [0; 4]);
                    ipc::reply(&reply);
                    continue;
                }

                // Map the shared memory buffer
                let buf_addr = shm::map(shm_id, 0);
                if buf_addr < 0 {
                    let reply = Message::new(ERR_INVAL as u64, [0; 4]);
                    ipc::reply(&reply);
                    continue;
                }

                // Copy from SHM to bounce buffer
                let shm_buf = unsafe {
                    core::slice::from_raw_parts(buf_addr as *const u8, total_bytes)
                };
                let bounce = unsafe { &mut BOUNCE_BUF[..total_bytes] };
                bounce.copy_from_slice(shm_buf);

                // Write from bounce buffer
                let result = unsafe { BLOCK_DEV.write(sector, bounce) };

                // Unmap shared memory
                shm::unmap(shm_id);

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
