//! fbdev - Framebuffer device server for Kenix
//!
//! This server provides framebuffer access via QEMU's ramfb device.
//! It initializes the ramfb through fw_cfg and provides an IPC interface
//! for pixel and text operations.

#![no_std]
#![no_main]

mod fwcfg;
mod ramfb;
mod font;

use libkenix::{console, ipc, msg, shm};
use fwcfg::FwCfg;
use ramfb::{Ramfb, colors};
use font::TextConsole;

/// Fixed virtual address for framebuffer (kernel maps this for us)
const FRAMEBUFFER_VADDR: usize = 0x2000_0000;

/// Global state
static mut RAMFB: Option<Ramfb> = None;
static mut CONSOLE: Option<TextConsole> = None;
static mut PHYS_BASE: u64 = 0;

/// Entry point - receives phys_base in x0 and fb_phys in x1
#[no_mangle]
pub extern "C" fn _start(phys_base: u64, fb_phys: u64) -> ! {
    unsafe {
        PHYS_BASE = phys_base;
    }

    console::println("[fbdev] Starting framebuffer server...");
    console::print_hex("[fbdev] phys_base=", phys_base);
    console::print_hex("[fbdev] fb_phys=", fb_phys);

    // Initialize fw_cfg
    let fwcfg = FwCfg::new();

    console::println("[fbdev] Checking fw_cfg...");

    // Read signature once and use it for both debug and check
    let sig = fwcfg.read_signature();
    console::print("[fbdev] fw_cfg signature: ");
    for &b in &sig {
        if b >= 0x20 && b < 0x7f {
            // Print as character
            let mut buf = [0u8; 1];
            buf[0] = b;
            console::print(unsafe { core::str::from_utf8_unchecked(&buf) });
        } else {
            console::print("?");
        }
    }
    console::println("");

    // Compare byte by byte
    let expected = b"QEMU";
    let matches = sig[0] == expected[0] && sig[1] == expected[1]
               && sig[2] == expected[2] && sig[3] == expected[3];

    if !matches {
        console::print("[fbdev] Mismatch: ");
        console::print_hex("got[0]=", sig[0] as u64);
        console::print_hex(" exp[0]=", expected[0] as u64);
        console::println("");
        console::println("[fbdev] ERROR: fw_cfg not available (expected 'QEMU')");
        loop {
            libkenix::syscall::yield_cpu();
        }
    }

    console::println("[fbdev] fw_cfg available, looking for etc/ramfb...");

    // Check if ramfb file exists
    let ramfb_selector = match fwcfg.find_file(b"etc/ramfb") {
        Some((selector, size)) => {
            console::print_hex("[fbdev] Found etc/ramfb selector=", selector as u64);
            console::print_hex("[fbdev] etc/ramfb size=", size as u64);
            selector
        }
        None => {
            console::println("[fbdev] ERROR: etc/ramfb not found in fw_cfg");
            console::println("[fbdev] Make sure QEMU was started with -device ramfb");
            loop {
                libkenix::syscall::yield_cpu();
            }
        }
    };

    // Initialize ramfb using the selector we already found
    console::println("[fbdev] Initializing ramfb...");
    let mut fb = Ramfb::init_with_selector(&fwcfg, ramfb_selector, fb_phys, FRAMEBUFFER_VADDR, phys_base);
    console::println("[fbdev] ramfb initialized");
    console::print_hex("[fbdev] Resolution: ", fb.width() as u64);
    console::print_hex("[fbdev] x ", fb.height() as u64);

    // Clear screen to dark gray
    fb.clear(colors::DARK_GRAY);

    // Create text console
    let text_console = TextConsole::new(
        fb.width(),
        fb.height(),
        colors::LIGHT_GRAY,
        colors::DARK_GRAY,
    );

    unsafe {
        CONSOLE = Some(text_console);
        RAMFB = Some(fb);
    }

    // Print welcome message on framebuffer
    unsafe {
        if let (Some(fb), Some(con)) = (&mut RAMFB, &mut CONSOLE) {
            con.print(fb, b"Kenix Microkernel v0.1.0\n");
            con.print(fb, b"Framebuffer Console Ready\n");
            con.print(fb, b"Resolution: 800x600 @ 32bpp\n");
            con.print(fb, b"\n");
        }
    }

    console::println("[fbdev] Starting IPC server loop...");

    // Main IPC server loop
    loop {
        let recv = ipc::recv(ipc::TASK_ANY);
        handle_message(recv.sender, &recv.msg);
    }
}

fn handle_message(sender: usize, msg: &ipc::Message) {
    let mut reply = ipc::Message::empty();

    match msg.tag {
        msg::FB_INIT => {
            // Return framebuffer info: [width, height, bpp, stride]
            unsafe {
                if let Some(fb) = &RAMFB {
                    reply.tag = msg::ERR_OK as u64;
                    reply.data[0] = fb.width() as u64;
                    reply.data[1] = fb.height() as u64;
                    reply.data[2] = fb.bytes_per_pixel() as u64 * 8;
                    reply.data[3] = fb.stride() as u64;
                } else {
                    reply.tag = msg::ERR_IO as u64;
                }
            }
        }

        msg::FB_CLEAR => {
            // Clear screen with color: data[0] = color
            let color = msg.data[0] as u32;
            unsafe {
                if let Some(fb) = &mut RAMFB {
                    fb.clear(color);
                    reply.tag = msg::ERR_OK as u64;
                } else {
                    reply.tag = msg::ERR_IO as u64;
                }
            }
        }

        msg::FB_PIXEL => {
            // Set pixel: data[0] = x, data[1] = y, data[2] = color
            let x = msg.data[0] as u32;
            let y = msg.data[1] as u32;
            let color = msg.data[2] as u32;
            unsafe {
                if let Some(fb) = &mut RAMFB {
                    fb.put_pixel(x, y, color);
                    reply.tag = msg::ERR_OK as u64;
                } else {
                    reply.tag = msg::ERR_IO as u64;
                }
            }
        }

        msg::FB_RECT => {
            // Fill rectangle: data[0] = x|(y<<16), data[1] = w|(h<<16), data[2] = color
            let xy = msg.data[0];
            let wh = msg.data[1];
            let color = msg.data[2] as u32;
            let x = (xy & 0xFFFF) as u32;
            let y = ((xy >> 16) & 0xFFFF) as u32;
            let w = (wh & 0xFFFF) as u32;
            let h = ((wh >> 16) & 0xFFFF) as u32;
            unsafe {
                if let Some(fb) = &mut RAMFB {
                    fb.fill_rect(x, y, w, h, color);
                    reply.tag = msg::ERR_OK as u64;
                } else {
                    reply.tag = msg::ERR_IO as u64;
                }
            }
        }

        msg::FB_PUTCHAR => {
            // Put character: data[0] = col, data[1] = row, data[2] = char, data[3] = fg|(bg<<32)
            let col = msg.data[0] as u32;
            let row = msg.data[1] as u32;
            let c = msg.data[2] as u8;
            let colors = msg.data[3];
            let fg = (colors & 0xFFFFFFFF) as u32;
            let bg = ((colors >> 32) & 0xFFFFFFFF) as u32;

            unsafe {
                if let Some(fb) = &mut RAMFB {
                    let px = col * font::FONT_WIDTH;
                    let py = row * font::FONT_HEIGHT;
                    font::draw_char(fb, px, py, c, fg, bg);
                    reply.tag = msg::ERR_OK as u64;
                } else {
                    reply.tag = msg::ERR_IO as u64;
                }
            }
        }

        msg::FB_PRINT => {
            // Print string from SHM: data[0] = shm_id, data[1] = len
            let shm_id = msg.data[0];
            let len = msg.data[1] as usize;

            // Map the shared memory
            let addr = shm::map(shm_id, 0);
            if addr < 0 {
                reply.tag = msg::ERR_IO as u64;
            } else {
                unsafe {
                    if let (Some(fb), Some(con)) = (&mut RAMFB, &mut CONSOLE) {
                        let buf = core::slice::from_raw_parts(addr as *const u8, len);
                        con.print(fb, buf);
                        reply.tag = msg::ERR_OK as u64;
                    } else {
                        reply.tag = msg::ERR_IO as u64;
                    }
                }
                // Unmap the shared memory
                let _ = shm::unmap(shm_id);
            }
        }

        msg::FB_SCROLL => {
            // Scroll up one line
            unsafe {
                if let (Some(fb), Some(con)) = (&mut RAMFB, &CONSOLE) {
                    con.scroll(fb);
                    reply.tag = msg::ERR_OK as u64;
                } else {
                    reply.tag = msg::ERR_IO as u64;
                }
            }
        }

        msg::FB_CURSOR_SET => {
            // Set cursor position: data[0] = col, data[1] = row
            let col = msg.data[0] as u32;
            let row = msg.data[1] as u32;
            unsafe {
                if let Some(con) = &mut CONSOLE {
                    con.set_cursor(col, row);
                    reply.tag = msg::ERR_OK as u64;
                } else {
                    reply.tag = msg::ERR_IO as u64;
                }
            }
        }

        msg::FB_CURSOR_GET => {
            // Get cursor position: returns [col, row]
            unsafe {
                if let Some(con) = &CONSOLE {
                    let (col, row) = con.cursor();
                    reply.tag = msg::ERR_OK as u64;
                    reply.data[0] = col as u64;
                    reply.data[1] = row as u64;
                } else {
                    reply.tag = msg::ERR_IO as u64;
                }
            }
        }

        _ => {
            // Unknown message type
            reply.tag = msg::ERR_INVAL as u64;
        }
    }

    let _ = ipc::reply(&reply);
}
