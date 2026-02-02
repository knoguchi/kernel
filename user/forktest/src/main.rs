//! Test program for Phase 1 BusyBox Support
//!
//! Tests: clock_gettime, mmap/munmap, signal stubs, and complete stat

#![no_std]
#![no_main]

extern crate libkenix;

use libkenix::syscall::{self, Timespec, Stat, Sigaction};
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

#[no_mangle]
pub extern "C" fn _start() -> ! {
    console::println("\n=== Phase 1 BusyBox Support Tests ===\n");

    test_clock_gettime();
    test_stat();
    test_mmap();
    test_signal();
    test_fork_wait();

    console::println("\n=== Tests Complete ===\n");
    syscall::exit(0);
}
