//! Keyboard device server for Kenix
//!
//! Provides keyboard input via VirtIO-input driver.
//! Forwards key events to the console server.

#![no_std]
#![no_main]

mod virtio_mmio;
mod virtqueue;
mod input;

use libkenix::ipc::{self, Message};
use libkenix::msg::KB_REGISTER;
use libkenix::shm;
use libkenix::syscall;
use libkenix::uart;
use libkenix::tasks;
use input::{VirtioInput, event_type};
use virtio_mmio::VIRTIO_MMIO_BASE;

/// Keyboard device state
static mut KB_DEV: VirtioInput = VirtioInput::new(VIRTIO_MMIO_BASE);

/// Physical base address of our 2MB code block (passed in x0 by kernel)
static mut PHYS_BASE: u64 = 0;

/// Shared memory buffer for keyboard input
/// Layout: [head: u32, tail: u32, data: [u8; 248]]
static mut KB_SHM_ADDR: usize = 0;

/// Push a character to the keyboard SHM buffer
fn kb_shm_push(c: u8) {
    unsafe {
        if KB_SHM_ADDR == 0 {
            return;
        }

        let head_ptr = KB_SHM_ADDR as *mut u32;
        let tail_ptr = (KB_SHM_ADDR + 4) as *const u32;
        let data_ptr = (KB_SHM_ADDR + 8) as *mut u8;

        let head = core::ptr::read_volatile(head_ptr) as usize;
        let tail = core::ptr::read_volatile(tail_ptr) as usize;

        let next_head = (head + 1) % 248;
        if next_head == tail {
            return;  // Buffer full
        }

        *data_ptr.add(head) = c;
        core::ptr::write_volatile(head_ptr, next_head as u32);
    }
}

/// Linux scancode to ASCII lookup table (basic US keyboard layout)
/// Index is the Linux KEY_* code, value is ASCII (0 = no mapping)
static SCANCODE_TO_ASCII: [u8; 128] = [
    0, 0, b'1', b'2', b'3', b'4', b'5', b'6',     // 0-7
    b'7', b'8', b'9', b'0', b'-', b'=', 0x08, b'\t',  // 8-15 (0x08 = backspace)
    b'q', b'w', b'e', b'r', b't', b'y', b'u', b'i',   // 16-23
    b'o', b'p', b'[', b']', b'\n', 0, b'a', b's',     // 24-31 (29 = ctrl)
    b'd', b'f', b'g', b'h', b'j', b'k', b'l', b';',   // 32-39
    b'\'', b'`', 0, b'\\', b'z', b'x', b'c', b'v',    // 40-47 (42 = lshift)
    b'b', b'n', b'm', b',', b'.', b'/', 0, b'*',      // 48-55 (54 = rshift)
    0, b' ', 0, 0, 0, 0, 0, 0,                        // 56-63 (56=lalt, 58=caps, 59-68=F1-F10)
    0, 0, 0, 0, 0, 0, 0, b'7',                        // 64-71 (numpad 7)
    b'8', b'9', b'-', b'4', b'5', b'6', b'+', b'1',   // 72-79 (numpad)
    b'2', b'3', b'0', b'.', 0, 0, 0, 0,               // 80-87
    0, 0, 0, 0, 0, 0, 0, 0,                           // 88-95
    0, 0, 0, 0, 0, 0, 0, 0,                           // 96-103
    0, 0, 0, 0, 0, 0, 0, 0,                           // 104-111
    0, 0, 0, 0, 0, 0, 0, 0,                           // 112-119
    0, 0, 0, 0, 0, 0, 0, 0,                           // 120-127
];

/// Shifted characters lookup (for when shift is held)
static SCANCODE_TO_ASCII_SHIFT: [u8; 128] = [
    0, 0, b'!', b'@', b'#', b'$', b'%', b'^',     // 0-7
    b'&', b'*', b'(', b')', b'_', b'+', 0x08, b'\t',  // 8-15
    b'Q', b'W', b'E', b'R', b'T', b'Y', b'U', b'I',   // 16-23
    b'O', b'P', b'{', b'}', b'\n', 0, b'A', b'S',     // 24-31
    b'D', b'F', b'G', b'H', b'J', b'K', b'L', b':',   // 32-39
    b'"', b'~', 0, b'|', b'Z', b'X', b'C', b'V',      // 40-47
    b'B', b'N', b'M', b'<', b'>', b'?', 0, b'*',      // 48-55
    0, b' ', 0, 0, 0, 0, 0, 0,                        // 56-63
    0, 0, 0, 0, 0, 0, 0, b'7',                        // 64-71
    b'8', b'9', b'-', b'4', b'5', b'6', b'+', b'1',   // 72-79
    b'2', b'3', b'0', b'.', 0, 0, 0, 0,               // 80-87
    0, 0, 0, 0, 0, 0, 0, 0,                           // 88-95
    0, 0, 0, 0, 0, 0, 0, 0,                           // 96-103
    0, 0, 0, 0, 0, 0, 0, 0,                           // 104-111
    0, 0, 0, 0, 0, 0, 0, 0,                           // 112-119
    0, 0, 0, 0, 0, 0, 0, 0,                           // 120-127
];

/// Linux key codes for modifier keys
const KEY_LEFTSHIFT: u16 = 42;
const KEY_RIGHTSHIFT: u16 = 54;
const KEY_LEFTCTRL: u16 = 29;
const KEY_RIGHTCTRL: u16 = 97;

/// Modifier key state
static mut SHIFT_HELD: bool = false;
static mut CTRL_HELD: bool = false;

#[no_mangle]
pub extern "C" fn _start(phys_base: u64) -> ! {
    unsafe {
        PHYS_BASE = phys_base;
    }

    uart::println("[kbdev] Starting...");

    unsafe {
        KB_DEV.set_phys_base(phys_base);

        if !KB_DEV.init() {
            uart::println("[kbdev] No keyboard device found (running in -nographic mode?)");
            // Just yield forever - no keyboard events to process
            loop {
                syscall::yield_cpu();
            }
        }
    }

    // Create shared memory for keyboard input
    let shm_id = shm::create(256);  // 256 bytes: 8 bytes header + 248 bytes ring buffer
    if shm_id < 0 {
        uart::println("[kbdev] Failed to create SHM");
        loop { syscall::yield_cpu(); }
    }
    let shm_id = shm_id as u64;

    // Map SHM in our address space
    let addr = shm::map(shm_id, 0);
    if addr < 0 {
        uart::println("[kbdev] Failed to map SHM");
        loop { syscall::yield_cpu(); }
    }
    unsafe {
        KB_SHM_ADDR = addr as usize;
        // Initialize ring buffer: head=0, tail=0
        let head_ptr = KB_SHM_ADDR as *mut u32;
        let tail_ptr = (KB_SHM_ADDR + 4) as *mut u32;
        *head_ptr = 0;
        *tail_ptr = 0;
    }

    // Grant SHM to console and register
    if shm::grant(shm_id, tasks::CONSOLE) < 0 {
        uart::println("[kbdev] Failed to grant SHM to console");
        loop { syscall::yield_cpu(); }
    }

    // Register with console
    let mut reg_msg = Message::new(KB_REGISTER, [shm_id, 0, 0, 0]);
    ipc::call(tasks::CONSOLE, &mut reg_msg);

    // Main loop: poll for keyboard events and forward to console
    loop {
        unsafe {
            while let Some(event) = KB_DEV.poll_event() {
                handle_event(event);
            }
        }

        // Yield CPU when no events
        syscall::yield_cpu();
    }
}

/// Handle a keyboard event
fn handle_event(event: input::VirtioInputEvent) {
    // Only handle key events
    if event.type_ != event_type::EV_KEY {
        return;
    }

    let code = event.code;
    let pressed = event.value != 0; // 1 = press, 0 = release, 2 = repeat

    // Track modifier keys
    unsafe {
        match code {
            KEY_LEFTSHIFT | KEY_RIGHTSHIFT => {
                SHIFT_HELD = pressed;
                return;
            }
            KEY_LEFTCTRL | KEY_RIGHTCTRL => {
                CTRL_HELD = pressed;
                return;
            }
            _ => {}
        }
    }

    // Only process key presses (not releases)
    // Also handle repeat (value == 2)
    if event.value == 0 {
        return;
    }

    // Convert scancode to ASCII
    let code_idx = code as usize;
    if code_idx >= 128 {
        return;
    }

    let ascii = unsafe {
        if CTRL_HELD {
            // Ctrl+key: send control character (ASCII 1-26 for A-Z)
            let base = SCANCODE_TO_ASCII[code_idx];
            if base >= b'a' && base <= b'z' {
                base - b'a' + 1  // Ctrl+A = 1, Ctrl+B = 2, etc.
            } else if base >= b'A' && base <= b'Z' {
                base - b'A' + 1
            } else {
                0
            }
        } else if SHIFT_HELD {
            SCANCODE_TO_ASCII_SHIFT[code_idx]
        } else {
            SCANCODE_TO_ASCII[code_idx]
        }
    };

    if ascii == 0 {
        return;
    }

    // Push character to shared memory buffer (console polls this)
    kb_shm_push(ascii);
}

