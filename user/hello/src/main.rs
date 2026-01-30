//! Hello - A minimal spawnable program for Kenix
//!
//! This program demonstrates dynamic process creation via spawn().

#![no_std]
#![no_main]

use libkenix::syscall;
use libkenix::ipc::{self, Message};
use libkenix::msg::MSG_WRITE;
use libkenix::tasks;

/// Print via IPC to console server
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

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Get our PID to show we're a new task
    let pid = syscall::getpid();

    print("[hello] I was spawned!\n");
    print("[hello] My PID is: ");

    // Print PID as single digit (we know it's small)
    let digit = (pid as u8) + b'0';
    syscall::write(1, &[digit, b'\n']);

    print("[hello] Goodbye!\n");

    syscall::exit(0);
}
