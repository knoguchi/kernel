//! Init Process for Kenix
//!
//! User-space init program that runs in EL0 (user mode)
//! and uses IPC to communicate with services.

#![no_std]
#![no_main]

use libkenix::ipc::{self, Message};
use libkenix::syscall;
use libkenix::msg::*;
use libkenix::tasks;

// Embed the hello program directly
static HELLO_ELF: &[u8] = include_bytes!("../data/hello.elf");

// ============================================================================
// Console Client (IPC-based printing)
// ============================================================================

/// Print a short string (up to 24 bytes) via inline IPC
fn print(s: &str) {
    let bytes = s.as_bytes();
    let len = bytes.len().min(24);

    let mut msg = Message::new(MSG_WRITE, [len as u64, 0, 0, 0]);
    let data_ptr = msg.data[1..].as_mut_ptr() as *mut u8;
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), data_ptr, len);
    }

    ipc::call(tasks::CONSOLE, &mut msg);
}

/// Print a number in decimal
fn print_num(n: usize) {
    if n == 0 {
        syscall::write(1, b"0");
        return;
    }

    let mut buf = [0u8; 20];
    let mut i = 20;
    let mut num = n;
    while num > 0 && i > 0 {
        i -= 1;
        buf[i] = b'0' + (num % 10) as u8;
        num /= 10;
    }
    syscall::write(1, &buf[i..]);
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

// ============================================================================
// VFS Client Functions
// ============================================================================

/// Open a file via VFS server
fn vfs_open(path: &str) -> i64 {
    let path_bytes = path.as_bytes();
    let len = path_bytes.len();
    if len > 31 {
        return ERR_INVAL;
    }

    let mut msg = Message::new(VFS_OPEN, [0, 0, 0, 0]);
    let data_ptr = msg.data.as_mut_ptr() as *mut u8;
    unsafe {
        *data_ptr = len as u8;
        core::ptr::copy_nonoverlapping(path_bytes.as_ptr(), data_ptr.add(1), len);
    }

    ipc::call(tasks::VFS, &mut msg);
    msg.tag as i64
}

/// Read from file via VFS (inline, max 32 bytes)
fn vfs_read(handle: i64, buf: &mut [u8]) -> i64 {
    let len = buf.len().min(32);

    let mut msg = Message::new(VFS_READ, [handle as u64, len as u64, 0, 0]);
    ipc::call(tasks::VFS, &mut msg);

    let result = msg.tag as i64;
    if result > 0 {
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
    print("=== Init Process ===\n");
    print("Testing IPC, VFS, Spawn\n\n");

    // ========================================
    // Test basic VFS
    // ========================================
    print("--- Basic VFS Test ---\n");

    let fd = vfs_open("/hello.txt");
    if fd >= 0 {
        let mut buf = [0u8; 32];
        let n = vfs_read(fd, &mut buf);
        if n > 0 {
            print("Read /hello.txt: ");
            syscall::write(1, &buf[..n as usize]);
        }
        vfs_close(fd);
    }

    // ========================================
    // Test FAT32 disk access
    // ========================================
    print("\n--- FAT32 Disk Test ---\n");

    let disk_fd = vfs_open("/disk/hello.txt");
    if disk_fd >= 0 {
        print("Opened /disk/hello.txt (fd=");
        print_num(disk_fd as usize);
        print(")\n");

        let mut buf = [0u8; 32];
        let n = vfs_read(disk_fd, &mut buf);
        if n > 0 {
            print("Read from disk: ");
            syscall::write(1, &buf[..n as usize]);
            print("\n");
        } else {
            print("Read failed: ");
            print_num((-n) as usize);
            print("\n");
        }
        vfs_close(disk_fd);
    } else if disk_fd == ERR_NOENT {
        print("No disk file (disk not mounted?)\n");
    } else {
        print("Failed to open /disk/hello.txt: ");
        print_num((-disk_fd) as usize);
        print("\n");
    }

    // ========================================
    // Spawn hello from embedded ELF
    // ========================================
    print("\n--- Spawn Test ---\n");

    print("Embedded hello.elf size: ");
    print_num(HELLO_ELF.len());
    print(" bytes\n");

    // Verify ELF magic
    if HELLO_ELF.len() < 4 || &HELLO_ELF[0..4] != [0x7f, b'E', b'L', b'F'] {
        print("ERROR: Invalid ELF magic!\n");
        syscall::exit(1);
    }
    print("ELF magic verified\n");

    print("Spawning hello...\n\n");

    let child_pid = syscall::spawn(HELLO_ELF);

    if child_pid >= 0 {
        print("\n--- Spawn successful! ---\n");
        print("Child PID: ");
        print_num(child_pid as usize);
        print("\n");
    } else {
        print("Spawn failed with error: ");
        print_hex(child_pid as u64);
        print("\n");
    }

    // Wait a bit for child to run
    for _ in 0..100 {
        syscall::yield_cpu();
    }

    print("\n=== Init complete ===\n");
    syscall::exit(0);
}
