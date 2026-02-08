//! Network device server for Kenix
//!
//! Provides network device access via IPC using VirtIO-net driver.

#![no_std]
#![no_main]

mod virtio_mmio;
mod virtqueue;
mod net;

use libkenix::ipc::{self, Message, TASK_ANY};
use libkenix::msg::{NET_SEND, NET_RECV, NET_INFO, ERR_OK, ERR_IO, ERR_INVAL};
use libkenix::shm;
use libkenix::syscall;
use libkenix::console;
use libkenix::VIRTIO_NET_IRQ;
use net::VirtioNet;
use virtio_mmio::VIRTIO_MMIO_BASE;

/// Network device server state
static mut NET_DEV: VirtioNet = VirtioNet::new(VIRTIO_MMIO_BASE);

/// Physical base address of our 2MB code block (passed in x0 by kernel)
static mut PHYS_BASE: u64 = 0;

/// Bounce buffer for TX - internal to netdev so has known physical address
static mut TX_BOUNCE: [u8; 2048] = [0; 2048];

/// Bounce buffer for RX
static mut RX_BOUNCE: [u8; 2048] = [0; 2048];

#[no_mangle]
pub extern "C" fn _start(phys_base: u64) -> ! {
    // Store the physical base for VA->PA conversion
    unsafe {
        PHYS_BASE = phys_base;
        NET_DEV.set_phys_base(phys_base);
    }

    console::println("[netdev] Starting...");

    // Initialize network device
    let init_ok = unsafe { NET_DEV.init() };

    if !init_ok {
        console::println("[netdev] VirtIO-net init failed");
        syscall::exit(1);
    }

    // Print MAC address
    let mac = unsafe { NET_DEV.mac };
    console::print("[netdev] MAC: ");
    print_mac(&mac);
    console::println("");

    console::println("[netdev] VirtIO-net ready");

    // Register for IRQ handling
    let irq_result = syscall::irq_register(VIRTIO_NET_IRQ);
    if irq_result < 0 {
        console::println("[netdev] IRQ registration failed");
        // Continue anyway - we can poll
    }

    // Main server loop
    loop {
        // Wait for message
        let recv = ipc::recv(TASK_ANY);
        let _sender = recv.sender;
        let msg = recv.msg;

        match msg.tag {
            NET_SEND => {
                // NET_SEND: data[0] = shm_id, data[1] = offset, data[2] = len
                let shm_id = msg.data[0];
                let offset = msg.data[1] as usize;
                let len = msg.data[2] as usize;

                // Validate length
                if len > 1514 {
                    let reply = Message::new(ERR_INVAL as u64, [0; 4]);
                    ipc::reply(&reply);
                    continue;
                }

                // Map shared memory
                let buf_addr = shm::map(shm_id, 0);
                if buf_addr < 0 {
                    let reply = Message::new(ERR_INVAL as u64, [0; 4]);
                    ipc::reply(&reply);
                    continue;
                }

                // Copy to bounce buffer
                unsafe {
                    let src = (buf_addr as usize + offset) as *const u8;
                    for i in 0..len {
                        TX_BOUNCE[i] = *src.add(i);
                    }
                }

                // Send packet
                let result = unsafe { NET_DEV.send(&TX_BOUNCE[..len]) };

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

            NET_RECV => {
                // NET_RECV: data[0] = shm_id, data[1] = offset, data[2] = max_len
                let shm_id = msg.data[0];
                let offset = msg.data[1] as usize;
                let max_len = msg.data[2] as usize;

                // Validate length
                if max_len > 2048 {
                    let reply = Message::new(ERR_INVAL as u64, [0; 4]);
                    ipc::reply(&reply);
                    continue;
                }

                // Map shared memory
                let buf_addr = shm::map(shm_id, 0);
                if buf_addr < 0 {
                    let reply = Message::new(ERR_INVAL as u64, [0; 4]);
                    ipc::reply(&reply);
                    continue;
                }

                // Receive packet into bounce buffer
                let result = unsafe { NET_DEV.recv(&mut RX_BOUNCE[..max_len]) };

                // If successful, copy to SHM
                if result > 0 {
                    unsafe {
                        let dst = (buf_addr as usize + offset) as *mut u8;
                        for i in 0..result as usize {
                            *dst.add(i) = RX_BOUNCE[i];
                        }
                    }
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

            NET_INFO => {
                // NET_INFO: returns MAC address and link status
                let mac = unsafe { NET_DEV.mac };
                let link_up = unsafe { if NET_DEV.link_up { 1u64 } else { 0u64 } };

                // Pack MAC into data[0..1]
                let mac_lo = (mac[0] as u64)
                    | ((mac[1] as u64) << 8)
                    | ((mac[2] as u64) << 16)
                    | ((mac[3] as u64) << 24)
                    | ((mac[4] as u64) << 32)
                    | ((mac[5] as u64) << 40);

                let reply = Message::new(ERR_OK as u64, [mac_lo, link_up, 0, 0]);
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

/// Print MAC address in hex
fn print_mac(mac: &[u8; 6]) {
    for (i, byte) in mac.iter().enumerate() {
        if i > 0 {
            console::print(":");
        }
        print_hex_byte(*byte);
    }
}

/// Print a byte in hex
fn print_hex_byte(b: u8) {
    const HEX: &[u8] = b"0123456789abcdef";
    let buf = [HEX[(b >> 4) as usize], HEX[(b & 0xf) as usize]];
    syscall::write(1, &buf);
}
