//! Init Process for Kenix
//!
//! User-space init program that runs in EL0 (user mode)
//! and uses IPC to communicate with services.

#![no_std]
#![no_main]

use libkenix::ipc::{self, Message};
use libkenix::shm::{self, ShmId};
use libkenix::syscall;
use libkenix::msg::*;
use libkenix::tasks;

// ============================================================================
// Console Client (IPC-based printing)
// ============================================================================

/// Print a short string (up to 24 bytes) via inline IPC
fn print(s: &str) {
    let bytes = s.as_bytes();
    let len = bytes.len().min(24);

    // data[0] = length, data[1-3] hold up to 24 bytes of string data
    let mut msg = Message::new(MSG_WRITE, [len as u64, 0, 0, 0]);

    // Copy string into data[1-3]
    let data_ptr = msg.data[1..].as_mut_ptr() as *mut u8;
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), data_ptr, len);
    }

    ipc::call(tasks::CONSOLE, &mut msg);
}

/// Print a hex byte
fn print_hex_byte(b: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let hex = [HEX[(b >> 4) as usize], HEX[(b & 0xf) as usize]];
    syscall::write(1, &hex);
}

/// Print a number in hex
fn print_hex(n: u64) {
    print("0x");
    for i in (0..16).rev() {
        let nibble = ((n >> (i * 4)) & 0xf) as u8;
        let c = if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 };
        syscall::write(1, &[c]);
    }
}

/// Print a long string via shared memory IPC
fn print_shm(shm_id: ShmId, shm_buf: *mut u8, s: &str) {
    let bytes = s.as_bytes();
    let len = bytes.len();

    // Copy string to shared memory buffer
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), shm_buf, len);
    }

    // Send SHM write message
    let mut msg = Message::new(MSG_SHM_WRITE, [shm_id, 0, len as u64, 0]);
    ipc::call(tasks::CONSOLE, &mut msg);
}

// ============================================================================
// VFS Client Functions
// ============================================================================

/// Open a file via VFS server
/// Returns file handle (>= 0) or error (< 0)
fn vfs_open(path: &str) -> i64 {
    let path_bytes = path.as_bytes();
    let len = path_bytes.len();
    if len > 31 {
        return ERR_INVAL;
    }

    // Pack path into message: data[0] byte 0 = length, bytes 1-31 = path
    let mut msg = Message::new(VFS_OPEN, [0, 0, 0, 0]);

    // Set length in first byte and copy path
    let data_ptr = msg.data.as_mut_ptr() as *mut u8;
    unsafe {
        *data_ptr = len as u8;
        core::ptr::copy_nonoverlapping(path_bytes.as_ptr(), data_ptr.add(1), len);
    }

    ipc::call(tasks::VFS, &mut msg);

    // Reply tag contains result (handle or error)
    msg.tag as i64
}

/// Read from file via VFS server
/// Returns bytes read (>= 0) or error (< 0)
/// Data is returned in buf (max 32 bytes)
fn vfs_read(handle: i64, buf: &mut [u8]) -> i64 {
    let len = buf.len().min(32);

    let mut msg = Message::new(VFS_READ, [handle as u64, len as u64, 0, 0]);
    ipc::call(tasks::VFS, &mut msg);

    let result = msg.tag as i64;
    if result > 0 {
        // Copy data from reply
        let n = (result as usize).min(32);
        let data_ptr = msg.data.as_ptr() as *const u8;
        unsafe {
            core::ptr::copy_nonoverlapping(data_ptr, buf.as_mut_ptr(), n);
        }
    }
    result
}

/// Close file via VFS server
fn vfs_close(handle: i64) -> i64 {
    let mut msg = Message::new(VFS_CLOSE, [handle as u64, 0, 0, 0]);
    ipc::call(tasks::VFS, &mut msg);
    msg.tag as i64
}

// ============================================================================
// Main
// ============================================================================

#[no_mangle]
pub extern "C" fn _start() -> ! {
    main()
}

fn main() -> ! {
    // Test basic inline IPC first
    print("Hello via IPC!\n");
    print("Init running in EL0\n");
    print("IPC works!\n");

    // Test POSIX write() syscall
    syscall::write(1, b"write() syscall works!\n");

    // ========================================
    // Test VFS Server
    // ========================================
    print("\n--- VFS Test ---\n");

    // Open /hello.txt
    let fd = vfs_open("/hello.txt");
    print("vfs_open returned: ");
    print_hex(fd as u64);
    print("\n");

    if fd < 0 {
        print("vfs_open failed!\n");
    } else {
        // Read file contents
        let mut buf = [0u8; 33];
        let n = vfs_read(fd, &mut buf[..32]);
        print("vfs_read returned: ");
        print_hex(n as u64);
        print("\n");

        if n > 0 && n < 32 {
            let n = n as usize;
            print("Content: [");
            // Print content via write syscall
            syscall::write(1, &buf[..n]);
            print("]\n");

            // Also show raw bytes
            print("Raw bytes: ");
            for i in 0..n.min(8) {
                print_hex_byte(buf[i]);
                print(" ");
            }
            print("\n");
        }

        // Close file
        vfs_close(fd);
        print("Closed file\n");
    }

    // Try opening non-existent file
    let fd = vfs_open("/noexist.txt");
    if fd < 0 {
        print("Open /noexist.txt: ENOENT (OK)\n");
    }

    print("--- VFS Test Done ---\n\n");

    // ========================================
    // Test Shared Memory
    // ========================================

    // Create shared memory for long strings
    let shm_id = shm::create(4096);
    if shm_id < 0 {
        print("SHM create failed!\n");
        syscall::exit(1);
    }
    let shm_id = shm_id as ShmId;

    // Grant console server (task 1) access
    if shm::grant(shm_id, tasks::CONSOLE) < 0 {
        print("SHM grant failed!\n");
        syscall::exit(1);
    }

    // Map the shared memory
    let shm_addr = shm::map(shm_id, 0);
    if shm_addr < 0 {
        print("SHM map failed!\n");
        syscall::exit(1);
    }
    let shm_buf = shm_addr as *mut u8;

    // Now we can print long strings via shared memory!
    print_shm(
        shm_id,
        shm_buf,
        "This is a much longer string that exceeds the 24-byte inline limit \
         and demonstrates shared memory IPC working correctly!\n",
    );

    print_shm(
        shm_id,
        shm_buf,
        "Shared memory enables efficient transfer of large data between \
         tasks without copying through the kernel message registers.\n",
    );

    // Clean up
    shm::unmap(shm_id);

    print("SHM test complete!\n");

    syscall::exit(0);
}
