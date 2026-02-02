//! Test program for Phase 1 & 2 BusyBox Support
//!
//! Tests: clock_gettime, mmap/munmap, signal stubs, complete stat,
//!        set_tid_address, getrandom, prlimit64

#![no_std]
#![no_main]

extern crate libkenix;

use libkenix::syscall::{self, Timespec, Stat, Sigaction, Rlimit, Iovec, Winsize};
use libkenix::console;

fn print_num(n: i64) {
    if n < 0 {
        syscall::write(1, b"-");
        print_num(-n);
        return;
    }
    if n >= 10 {
        print_num(n / 10);
    }
    let digit = (n % 10) as u8 + b'0';
    syscall::write(1, &[digit]);
}

fn print_hex_byte(b: u8) {
    let hi = b >> 4;
    let lo = b & 0xf;
    let c1 = if hi < 10 { b'0' + hi } else { b'a' + hi - 10 };
    let c2 = if lo < 10 { b'0' + lo } else { b'a' + lo - 10 };
    syscall::write(1, &[c1, c2]);
}

fn test_clock_gettime() {
    console::print("[TEST] clock_gettime: ");

    let mut ts = Timespec::default();
    let ret = syscall::clock_gettime(syscall::CLOCK_MONOTONIC, &mut ts);

    if ret == 0 {
        console::print("OK (");
        print_num(ts.tv_sec);
        console::print(".");
        // Print first 3 digits of nsec
        print_num(ts.tv_nsec / 1_000_000);
        console::print("s)\n");
    } else {
        console::print("FAILED (ret=");
        print_num(ret as i64);
        console::print(")\n");
    }
}

fn test_mmap() {
    console::print("[TEST] mmap: ");

    // Try to mmap 4KB anonymous memory
    let addr = syscall::mmap(
        0,      // addr hint (NULL = let kernel choose)
        4096,   // size
        syscall::PROT_READ | syscall::PROT_WRITE,
        syscall::MAP_PRIVATE | syscall::MAP_ANONYMOUS,
        -1,     // fd (must be -1 for MAP_ANONYMOUS)
        0,      // offset
    );

    if addr < 0 || addr as usize == syscall::MAP_FAILED {
        console::print("FAILED to allocate (ret=");
        print_num(addr as i64);
        console::print(")\n");
        return;
    }

    console::print("allocated at 0x");
    // Print address in hex
    for i in (0..8).rev() {
        print_hex_byte(((addr as u64 >> (i * 8)) & 0xff) as u8);
    }
    console::print(" ");

    // Write to the memory (this triggers demand paging)
    let ptr = addr as *mut u8;
    unsafe {
        // Write pattern
        for i in 0..16 {
            *ptr.add(i) = 0xAA;
        }
        // Read back and verify
        let mut ok = true;
        for i in 0..16 {
            if *ptr.add(i) != 0xAA {
                ok = false;
                break;
            }
        }
        if ok {
            console::print("write/read OK ");
        } else {
            console::print("write/read FAILED ");
        }
    }

    // Unmap
    let ret = syscall::munmap(addr as usize, 4096);
    if ret == 0 {
        console::print("munmap OK\n");
    } else {
        console::print("munmap FAILED\n");
    }
}

fn test_stat() {
    console::print("[TEST] fstat: ");

    // Use stdout (fd 1) which is always open
    let mut stat = Stat::default();
    let ret = syscall::fstat(1, &mut stat);

    if ret == 0 {
        console::print("OK mode=0o");
        // Print mode in octal (simplified)
        print_num((stat.st_mode & 0o777) as i64);
        console::print(" nlink=");
        print_num(stat.st_nlink as i64);
        console::print(" blksize=");
        print_num(stat.st_blksize as i64);
        console::print("\n");
    } else {
        console::print("FAILED (ret=");
        print_num(ret as i64);
        console::print(")\n");
    }
}

fn test_signal() {
    console::print("[TEST] signals: ");

    // Test sigaction - set SIGCHLD to SIG_IGN
    let act = Sigaction {
        sa_handler: syscall::SIG_IGN,
        sa_flags: 0,
        sa_restorer: 0,
        sa_mask: 0,
    };

    let ret = syscall::sigaction(syscall::SIGCHLD, Some(&act), None);
    if ret == 0 {
        console::print("sigaction OK ");
    } else {
        console::print("sigaction FAILED ");
    }

    // Test sigprocmask
    let mut oldset: u64 = 0;
    let ret = syscall::sigprocmask(syscall::SIG_SETMASK, None, Some(&mut oldset));
    if ret == 0 {
        console::print("sigprocmask OK ");
    } else {
        console::print("sigprocmask FAILED ");
    }

    // Test kill (send signal to self)
    let pid = syscall::getpid();
    let ret = syscall::kill(pid as i32, 1); // SIGHUP
    if ret == 0 {
        console::print("kill OK\n");
    } else {
        console::print("kill FAILED\n");
    }
}

fn test_fork_wait() {
    console::print("[TEST] fork/wait: ");

    let pid = syscall::fork();
    if pid < 0 {
        console::print("fork FAILED\n");
        return;
    }

    if pid == 0 {
        // Child process - exit with code 42
        syscall::exit(42);
    } else {
        // Parent process
        console::print("forked pid=");
        print_num(pid as i64);
        console::print(" ");

        let (wpid, status) = syscall::waitpid(-1, 0);
        if wpid == pid {
            // Extract exit code: bits 8-15 contain exit status for normal exit
            let exit_code = (status >> 8) & 0xff;
            console::print("exit=");
            print_num(exit_code as i64);
            if exit_code == 42 {
                console::print(" OK\n");
            } else {
                console::print(" WRONG (expected 42)\n");
            }
        } else {
            console::print("waitpid FAILED\n");
        }
    }
}

// ============================================================================
// Phase 2 Tests: musl startup syscalls
// ============================================================================

fn test_set_tid_address() {
    console::print("[TEST] set_tid_address: ");

    let mut tid: i32 = 0;
    let ret = syscall::set_tid_address(&mut tid as *mut i32);

    // Should return current task ID (positive)
    if ret > 0 {
        console::print("OK tid=");
        print_num(ret as i64);
        console::print("\n");
    } else {
        console::print("FAILED (ret=");
        print_num(ret as i64);
        console::print(")\n");
    }
}

fn test_getrandom() {
    console::print("[TEST] getrandom: ");

    let mut buf = [0u8; 16];
    let ret = syscall::getrandom(&mut buf, 0);

    if ret == 16 {
        console::print("OK got ");
        print_num(ret as i64);
        console::print(" bytes: ");
        // Print first 4 bytes in hex
        for i in 0..4 {
            print_hex_byte(buf[i]);
        }
        console::print("...\n");
    } else {
        console::print("FAILED (ret=");
        print_num(ret as i64);
        console::print(")\n");
    }
}

fn test_prlimit64() {
    console::print("[TEST] prlimit64: ");

    let mut rlim = Rlimit { rlim_cur: 0, rlim_max: 0 };

    // Query stack limit
    let ret = syscall::prlimit64(0, syscall::RLIMIT_STACK, None, Some(&mut rlim));

    if ret == 0 {
        console::print("OK stack_cur=");
        print_num((rlim.rlim_cur / 1024) as i64);
        console::print("KB max=");
        print_num((rlim.rlim_max / 1024) as i64);
        console::print("KB\n");
    } else {
        console::print("FAILED (ret=");
        print_num(ret as i64);
        console::print(")\n");
    }
}

fn test_writev() {
    console::print("[TEST] writev: ");

    // Create an iovec array with multiple buffers
    let buf1 = b"Hello, ";
    let buf2 = b"writev ";
    let buf3 = b"world!\n";

    let iovecs = [
        Iovec { iov_base: buf1.as_ptr(), iov_len: buf1.len() },
        Iovec { iov_base: buf2.as_ptr(), iov_len: buf2.len() },
        Iovec { iov_base: buf3.as_ptr(), iov_len: buf3.len() },
    ];

    let ret = syscall::writev(1, &iovecs);

    if ret > 0 {
        console::print("[TEST] writev: OK wrote ");
        print_num(ret as i64);
        console::print(" bytes\n");
    } else {
        console::print("[TEST] writev: FAILED (ret=");
        print_num(ret as i64);
        console::print(")\n");
    }
}

fn test_ioctl() {
    console::print("[TEST] ioctl TIOCGWINSZ: ");

    let mut ws = Winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    let ret = syscall::ioctl(1, syscall::TIOCGWINSZ, &mut ws as *mut Winsize as usize);

    if ret == 0 {
        console::print("OK ");
        print_num(ws.ws_col as i64);
        console::print("x");
        print_num(ws.ws_row as i64);
        console::print("\n");
    } else {
        console::print("FAILED (ret=");
        print_num(ret as i64);
        console::print(")\n");
    }
}

// Global flag set by signal handler
static mut SIGNAL_RECEIVED: bool = false;

// Signal handler - must call sigreturn at the end
extern "C" fn signal_handler(_sig: i32) {
    // Note: In a real system, we should only use async-signal-safe functions here
    unsafe {
        SIGNAL_RECEIVED = true;
    }
    // Return from signal handler
    syscall::sigreturn();
}

fn test_signal_delivery() {
    console::print("[TEST] signal delivery: ");

    // Reset flag
    unsafe {
        SIGNAL_RECEIVED = false;
    }

    // Set up handler for SIGUSR1 (signal 10)
    const SIGUSR1: i32 = 10;

    let act = Sigaction {
        sa_handler: signal_handler as u64,
        sa_flags: 0,
        sa_restorer: 0,
        sa_mask: 0,
    };

    let ret = syscall::sigaction(SIGUSR1, Some(&act), None);
    if ret != 0 {
        console::print("sigaction FAILED\n");
        return;
    }

    // Send SIGUSR1 to self
    let pid = syscall::getpid();
    let ret = syscall::kill(pid as i32, SIGUSR1);
    if ret != 0 {
        console::print("kill FAILED\n");
        return;
    }

    // The signal should be delivered on the next syscall return
    // Make a harmless syscall to trigger signal delivery
    syscall::getpid();

    // Check if handler was called
    let received = unsafe { SIGNAL_RECEIVED };
    if received {
        console::print("OK handler called\n");
    } else {
        console::print("FAILED handler not called\n");
    }
}

fn test_mmap_file() {
    console::print("[TEST] file mmap: opening... ");

    // Open a file (/hello.txt exists on the ramfs with content "Hello!\n")
    let fd = syscall::open(b"/hello.txt\0", 0); // O_RDONLY
    console::print("got fd=");
    print_num(fd as i64);
    console::print(" ");

    if fd < 0 {
        console::print("FAILED\n");
        return;
    }

    // mmap the first 4KB of the file
    let addr = syscall::mmap(
        0,      // addr hint (NULL = let kernel choose)
        4096,   // size
        syscall::PROT_READ,
        syscall::MAP_PRIVATE, // No MAP_ANONYMOUS - file-backed
        fd as i32,
        0,      // offset
    );

    if addr < 0 || addr as usize == syscall::MAP_FAILED {
        console::print("mmap FAILED (ret=");
        print_num(addr as i64);
        console::print(")\n");
        syscall::close(fd as usize);
        return;
    }

    console::print("mapped at 0x");
    for i in (0..8).rev() {
        print_hex_byte(((addr as u64 >> (i * 8)) & 0xff) as u8);
    }
    console::print(" ");

    // Check for "Hello" at the start of the file
    let ptr = addr as *const u8;
    unsafe {
        let bytes = [*ptr, *ptr.add(1), *ptr.add(2), *ptr.add(3), *ptr.add(4), *ptr.add(5)];
        if bytes[0] == b'H' && bytes[1] == b'e' && bytes[2] == b'l' && bytes[3] == b'l' && bytes[4] == b'o' {
            console::print("content OK (Hello) ");
        } else {
            console::print("wrong content: ");
            for b in &bytes {
                print_hex_byte(*b);
            }
            console::print(" ");
        }
    }

    // Unmap
    let ret = syscall::munmap(addr as usize, 4096);
    if ret == 0 {
        console::print("munmap OK ");
    } else {
        console::print("munmap FAILED ");
    }

    // Close file
    syscall::close(fd as usize);
    console::print("\n");
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    console::println("\n=== Phase 1 BusyBox Support Tests ===\n");

    test_clock_gettime();
    test_stat();
    test_mmap();
    test_signal();
    test_fork_wait();

    console::println("\n=== Phase 2 musl Startup Tests ===\n");

    test_set_tid_address();
    test_getrandom();
    test_prlimit64();
    test_writev();
    test_ioctl();
    test_signal_delivery();
    test_mmap_file();

    console::println("\n=== Tests Complete ===\n");
    syscall::exit(0);
}
