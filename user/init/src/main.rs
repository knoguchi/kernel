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
    // Test Pipe
    // ========================================
    print("\n--- Pipe Test ---\n");

    let (read_fd, write_fd) = syscall::pipe();
    if read_fd >= 0 && write_fd >= 0 {
        print("Created pipe: read_fd=");
        print_num(read_fd as usize);
        print(", write_fd=");
        print_num(write_fd as usize);
        print("\n");

        // Write to pipe
        let test_data = b"Hello, pipe!";
        let written = syscall::write(write_fd as usize, test_data);
        print("Wrote ");
        print_num(written as usize);
        print(" bytes to pipe\n");

        // Read from pipe
        let mut buf = [0u8; 32];
        let read_count = syscall::read(read_fd as usize, &mut buf);
        if read_count > 0 {
            print("Read from pipe: ");
            syscall::write(1, &buf[..read_count as usize]);
            print("\n");
        } else {
            print("Read failed: ");
            print_num((-read_count) as usize);
            print("\n");
        }

        // Close pipe ends
        syscall::close(read_fd as usize);
        syscall::close(write_fd as usize);
        print("Pipe closed\n");
    } else {
        print("Failed to create pipe: ");
        print_num((-read_fd) as usize);
        print("\n");
    }

    // ========================================
    // Test dup syscall
    // ========================================
    print("\n--- Dup Test ---\n");

    // Duplicate stdout
    let dup_fd = syscall::dup(1);
    if dup_fd >= 0 {
        print("dup(1) returned fd ");
        print_num(dup_fd as usize);
        print("\n");
        // Write to duplicated fd
        syscall::write(dup_fd as usize, b"Hello via dup'd fd!\n");
        syscall::close(dup_fd as usize);
    } else {
        print("dup failed: ");
        print_num((-dup_fd) as usize);
        print("\n");
    }

    // Test dup2 to redirect
    let dup2_result = syscall::dup2(1, 10);
    if dup2_result >= 0 {
        print("dup2(1, 10) returned ");
        print_num(dup2_result as usize);
        print("\n");
        syscall::write(10, b"Hello via fd 10!\n");
        syscall::close(10);
    } else {
        print("dup2 failed: ");
        print_num((-dup2_result) as usize);
        print("\n");
    }

    // ========================================
    // Test getcwd/chdir
    // ========================================
    print("\n--- Cwd Test ---\n");

    let mut cwd_buf = [0u8; 256];
    let cwd_result = syscall::getcwd(&mut cwd_buf);
    if cwd_result > 0 {
        print("getcwd: ");
        // Find null terminator
        let len = cwd_buf.iter().position(|&c| c == 0).unwrap_or(cwd_buf.len());
        syscall::write(1, &cwd_buf[..len]);
        print("\n");
    } else {
        print("getcwd failed\n");
    }

    // Change to /disk
    let chdir_result = syscall::chdir(b"/disk\0");
    if chdir_result == 0 {
        print("chdir(/disk) succeeded\n");

        // Check new cwd
        let cwd_result = syscall::getcwd(&mut cwd_buf);
        if cwd_result > 0 {
            print("getcwd: ");
            let len = cwd_buf.iter().position(|&c| c == 0).unwrap_or(cwd_buf.len());
            syscall::write(1, &cwd_buf[..len]);
            print("\n");
        }
    } else {
        print("chdir failed\n");
    }

    // ========================================
    // Test brk
    // ========================================
    print("\n--- Brk Test ---\n");

    let initial_brk = syscall::brk(0);
    print("Initial brk: 0x");
    print_hex(initial_brk as u64);
    print("\n");

    let new_brk = syscall::brk(initial_brk + 4096);
    print("After brk(+4096): 0x");
    print_hex(new_brk as u64);
    print("\n");

    // ========================================
    // Test execve (error cases only - can't replace init!)
    // ========================================
    print("\n--- Execve Test ---\n");

    // Test execve with non-existent file (should fail with ENOENT)
    let noent_path = b"/nonexistent\0";
    let argv: [*const u8; 2] = [noent_path.as_ptr(), core::ptr::null()];
    let envp: [*const u8; 1] = [core::ptr::null()];

    let result = syscall::execve(noent_path.as_ptr(), argv.as_ptr(), envp.as_ptr());
    if result == -2 {  // ENOENT
        print("execve(/nonexistent): ENOENT (expected)\n");
    } else {
        print("execve(/nonexistent): error ");
        print_num((-result) as usize);
        print("\n");
    }

    // Test execve with a directory (should fail)
    let dir_path = b"/disk\0";
    let argv_dir: [*const u8; 2] = [dir_path.as_ptr(), core::ptr::null()];
    let result = syscall::execve(dir_path.as_ptr(), argv_dir.as_ptr(), envp.as_ptr());
    print("execve(/disk): error ");
    print_num((-result) as usize);
    print(" (expected EISDIR or similar)\n");

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
