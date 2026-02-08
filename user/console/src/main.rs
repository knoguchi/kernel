//! Console Server for Kenix
//!
//! User-space server that handles console I/O via IPC.
//! Receives MSG_WRITE messages and writes to the UART.
//! The UART MMIO region is mapped into this task's address space.
//! Also supports MSG_SHM_WRITE for large data via shared memory.

#![no_std]
#![no_main]

use libkenix::ipc::{self, Message, TASK_ANY};
use libkenix::shm::{self, ShmId, SHM_ERR_INVALID};
use libkenix::msg::*;

// ============================================================================
// UART Driver (PL011)
// ============================================================================

/// QEMU virt machine PL011 UART base address
/// This address is mapped into console server's address space by the kernel
const UART_BASE: usize = 0x09000000;

/// UART Data Register
const UART_DR: *mut u8 = UART_BASE as *mut u8;

/// UART Flag Register
const UART_FR: *const u32 = (UART_BASE + 0x018) as *const u32;

/// TX FIFO full flag
const UART_FR_TXFF: u32 = 1 << 5;

/// RX FIFO empty flag
const UART_FR_RXFE: u32 = 1 << 4;

/// Write a single character to UART
fn uart_putc(c: u8) {
    unsafe {
        // Wait for TX FIFO to have space
        while (*UART_FR & UART_FR_TXFF) != 0 {
            // Spin
        }
        *UART_DR = c;
    }
}

/// Write a buffer to UART
fn uart_write(buf: &[u8]) -> usize {
    for &c in buf {
        uart_putc(c);
    }
    buf.len()
}

/// Print a string directly to UART (bypassing IPC)
fn uart_print(s: &str) {
    for c in s.bytes() {
        uart_putc(c);
    }
}

/// Check if there's data available to read
fn uart_has_data() -> bool {
    unsafe { (*UART_FR & UART_FR_RXFE) == 0 }
}

/// Read a single character from UART (non-blocking, returns None if no data)
fn uart_getc() -> Option<u8> {
    unsafe {
        if (*UART_FR & UART_FR_RXFE) != 0 {
            return None; // RX FIFO empty
        }
        Some(*UART_DR)
    }
}

/// Read from UART into buffer (blocking until at least 1 byte or newline)
fn uart_read(buf: &mut [u8]) -> usize {
    if buf.is_empty() {
        return 0;
    }

    let mut count = 0;

    // Block until we get at least one character
    loop {
        if let Some(c) = uart_getc() {
            // Echo the character back
            uart_putc(c);

            // Handle backspace
            if c == 0x7f || c == 0x08 {
                if count > 0 {
                    count -= 1;
                    // Erase character on terminal
                    uart_putc(0x08); // backspace
                    uart_putc(b' '); // space
                    uart_putc(0x08); // backspace
                }
                continue;
            }

            // Handle enter (CR or LF)
            if c == b'\r' || c == b'\n' {
                uart_putc(b'\n');
                if count < buf.len() {
                    buf[count] = b'\n';
                    count += 1;
                }
                break;
            }

            // Store character
            if count < buf.len() {
                buf[count] = c;
                count += 1;
            }

            // Buffer full
            if count >= buf.len() {
                break;
            }
        } else {
            // No data - yield CPU briefly then retry
            // (In a real system we'd use interrupts)
            libkenix::syscall::yield_cpu();
        }
    }

    count
}

// ============================================================================
// Client SHM Tracking
// ============================================================================

const MAX_CLIENTS: usize = 64;

struct ClientShm {
    shm_id: ShmId,
    mapped_addr: usize,
    valid: bool,
}

impl ClientShm {
    const fn empty() -> Self {
        Self {
            shm_id: 0,
            mapped_addr: 0,
            valid: false,
        }
    }
}

static mut CLIENT_SHM: [ClientShm; MAX_CLIENTS] = [const { ClientShm::empty() }; MAX_CLIENTS];

/// Get or map SHM for a client
fn get_client_shm(client_id: usize, shm_id: ShmId) -> Option<usize> {
    if client_id >= MAX_CLIENTS {
        return None;
    }

    unsafe {
        let client = &mut CLIENT_SHM[client_id];

        // Check if already mapped
        if client.valid && client.shm_id == shm_id {
            return Some(client.mapped_addr);
        }

        // Unmap old one if different
        if client.valid {
            shm::unmap(client.shm_id);
            client.valid = false;
        }

        // Map the new one
        let addr = shm::map(shm_id, 0);
        if addr < 0 {
            return None;
        }

        client.shm_id = shm_id;
        client.mapped_addr = addr as usize;
        client.valid = true;

        Some(addr as usize)
    }
}

// ============================================================================
// Console Server Main
// ============================================================================

#[no_mangle]
pub extern "C" fn _start() -> ! {
    main()
}

fn main() -> ! {
    // Print startup message directly to UART
    uart_print("[console] Server started\n");

    // Main message processing loop
    loop {
        // Wait for a message from any task
        let recv = ipc::recv(TASK_ANY);

        if recv.msg.tag == MSG_READ {
            // MSG_READ: data[0] = max length to read
            let max_len = recv.msg.data[0] as usize;
            let max_len = if max_len > 24 { 24 } else { max_len };

            // Read from UART into reply buffer
            let mut reply = Message::new(0, [0, 0, 0, 0]);
            let data_ptr = reply.data[1..].as_mut_ptr() as *mut u8;
            let buf = unsafe { core::slice::from_raw_parts_mut(data_ptr, max_len) };

            let bytes_read = uart_read(buf);
            reply.tag = bytes_read as u64;
            reply.data[0] = bytes_read as u64;

            ipc::reply(&reply);
        } else if recv.msg.tag == MSG_WRITE {
            // MSG_WRITE: data[0] = length, data[1-3] = inline string data (up to 24 bytes)
            let len = recv.msg.data[0] as usize;
            let len = if len > 24 { 24 } else { len };

            // Get pointer to inline data
            let data_ptr = recv.msg.data[1..].as_ptr() as *const u8;
            let buf = unsafe { core::slice::from_raw_parts(data_ptr, len) };

            // Write to UART
            let written = uart_write(buf);

            // Reply with number of bytes written
            let reply = Message::new(written as u64, [0, 0, 0, 0]);
            ipc::reply(&reply);
        } else if recv.msg.tag == MSG_SHM_WRITE {
            // MSG_SHM_WRITE: data[0]=shm_id, data[1]=offset, data[2]=len
            let shm_id = recv.msg.data[0];
            let offset = recv.msg.data[1] as usize;
            let len = recv.msg.data[2] as usize;

            // Get mapped address for this client's SHM
            match get_client_shm(recv.sender, shm_id) {
                Some(shm_base) => {
                    // Write from SHM to UART
                    let buf = unsafe {
                        core::slice::from_raw_parts((shm_base + offset) as *const u8, len)
                    };
                    let written = uart_write(buf);

                    // Reply with number of bytes written
                    let reply = Message::new(written as u64, [0, 0, 0, 0]);
                    ipc::reply(&reply);
                }
                None => {
                    // Failed to map SHM
                    let reply = Message::new(SHM_ERR_INVALID as u64, [0, 0, 0, 0]);
                    ipc::reply(&reply);
                }
            }
        } else if recv.msg.tag == MSG_EXIT {
            // MSG_EXIT: client wants to terminate
            // Just reply with success
            let reply = Message::new(IPC_OK as u64, [0, 0, 0, 0]);
            ipc::reply(&reply);
        } else {
            // Unknown message - reply with error
            let reply = Message::new(IPC_ERR_INVALID as u64, [0, 0, 0, 0]);
            ipc::reply(&reply);
        }
    }
}
