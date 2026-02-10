//! fbdev - Framebuffer device server for Kenix
//!
//! This server provides framebuffer access via either:
//! - VirtIO-GPU (preferred, supports keyboard input routing)
//! - QEMU's ramfb device (fallback)

#![no_std]
#![no_main]

mod fwcfg;
mod ramfb;
mod font;
mod virtio_gpu;

use libkenix::{uart, ipc, msg, shm, tasks};
use fwcfg::FwCfg;
use ramfb::{Ramfb, colors};
use font::TextConsole;
use virtio_gpu::VirtioGpu;

/// Fixed virtual address for framebuffer (kernel maps this for us)
const FRAMEBUFFER_VADDR: usize = 0x2000_0000;

/// Framebuffer backend type
enum FbBackend {
    VirtioGpu(VirtioGpu),
    Ramfb(Ramfb),
}

/// Global state
static mut BACKEND: Option<FbBackend> = None;
static mut CONSOLE: Option<TextConsole> = None;
static mut PHYS_BASE: u64 = 0;
static mut FB_PRINT_SHM_ADDR: usize = 0;

/// Entry point - receives phys_base in x0 and fb_phys in x1
#[no_mangle]
pub extern "C" fn _start(phys_base: u64, fb_phys: u64) -> ! {
    unsafe {
        PHYS_BASE = phys_base;
    }

    uart::println("[fbdev] Starting framebuffer server...");
    uart::print_hex("[fbdev] phys_base=", phys_base);

    // Try virtio-gpu first
    let mut gpu = VirtioGpu::new();
    gpu.set_phys_base(phys_base);

    if gpu.init() {
        uart::println("[fbdev] Using VirtIO-GPU backend");

        // Clear to dark gray
        gpu.clear(colors::DARK_GRAY);

        // Create text console
        let text_console = TextConsole::new(
            gpu.width,
            gpu.height,
            colors::LIGHT_GRAY,
            colors::DARK_GRAY,
        );

        unsafe {
            CONSOLE = Some(text_console);
            BACKEND = Some(FbBackend::VirtioGpu(gpu));
        }
    } else {
        uart::println("[fbdev] VirtIO-GPU not found, trying ramfb...");
        uart::print_hex("[fbdev] fb_phys=", fb_phys);

        // Fall back to ramfb
        let fwcfg = FwCfg::new();

        uart::println("[fbdev] Checking fw_cfg...");

        let sig = fwcfg.read_signature();
        uart::print("[fbdev] fw_cfg signature: ");
        for &b in &sig {
            if b >= 0x20 && b < 0x7f {
                let mut buf = [0u8; 1];
                buf[0] = b;
                uart::print(unsafe { core::str::from_utf8_unchecked(&buf) });
            } else {
                uart::print("?");
            }
        }
        uart::println("");

        let expected = b"QEMU";
        let matches = sig[0] == expected[0] && sig[1] == expected[1]
                   && sig[2] == expected[2] && sig[3] == expected[3];

        if !matches {
            uart::println("[fbdev] ERROR: Neither virtio-gpu nor ramfb available");
            loop {
                libkenix::syscall::yield_cpu();
            }
        }

        uart::println("[fbdev] fw_cfg available, looking for etc/ramfb...");

        let ramfb_selector = match fwcfg.find_file(b"etc/ramfb") {
            Some((selector, size)) => {
                uart::print_hex("[fbdev] Found etc/ramfb selector=", selector as u64);
                uart::print_hex("[fbdev] etc/ramfb size=", size as u64);
                selector
            }
            None => {
                uart::println("[fbdev] ERROR: etc/ramfb not found in fw_cfg");
                loop {
                    libkenix::syscall::yield_cpu();
                }
            }
        };

        uart::println("[fbdev] Initializing ramfb...");
        let mut fb = Ramfb::init_with_selector(&fwcfg, ramfb_selector, fb_phys, FRAMEBUFFER_VADDR, phys_base);
        uart::println("[fbdev] ramfb initialized");
        uart::print_hex("[fbdev] Resolution: ", fb.width() as u64);
        uart::print_hex("[fbdev] x ", fb.height() as u64);

        fb.clear(colors::DARK_GRAY);

        let text_console = TextConsole::new(
            fb.width(),
            fb.height(),
            colors::LIGHT_GRAY,
            colors::DARK_GRAY,
        );

        unsafe {
            CONSOLE = Some(text_console);
            BACKEND = Some(FbBackend::Ramfb(fb));
        }
    }

    // Print welcome message on framebuffer
    unsafe {
        if let Some(con) = &mut CONSOLE {
            match &mut BACKEND {
                Some(FbBackend::VirtioGpu(gpu)) => {
                    con.print_gpu(gpu, b"Kenix Microkernel v0.1.0\n");
                    con.print_gpu(gpu, b"VirtIO-GPU Console Ready\n");
                    con.print_gpu(gpu, b"Resolution: 800x600 @ 32bpp\n");
                    con.print_gpu(gpu, b"\n");
                }
                Some(FbBackend::Ramfb(fb)) => {
                    con.print(fb, b"Kenix Microkernel v0.1.0\n");
                    con.print(fb, b"Framebuffer Console Ready\n");
                    con.print(fb, b"Resolution: 800x600 @ 32bpp\n");
                    con.print(fb, b"\n");
                }
                None => {}
            }
        }
    }

    uart::println("[fbdev] Starting IPC server loop...");

    // Register with console for output forwarding
    let shm_id = shm::create(4096);
    if shm_id >= 0 {
        let shm_id_u64 = shm_id as u64;
        // Map the SHM in our address space so we can read from it
        let addr = shm::map(shm_id_u64, 0);
        if addr >= 0 {
            unsafe { FB_PRINT_SHM_ADDR = addr as usize; }
            if shm::grant(shm_id_u64, tasks::CONSOLE) >= 0 {
                let mut reg_msg = ipc::Message::new(msg::FB_REGISTER, [shm_id_u64, 0, 0, 0]);
                let _ = ipc::call(tasks::CONSOLE, &mut reg_msg);
                // Note: Don't call uart::println here - it would deadlock with
                // the buffer replay that console does immediately after registration.
                // Print directly to framebuffer instead:
                unsafe {
                    if let Some(con) = &mut CONSOLE {
                        match &mut BACKEND {
                            Some(FbBackend::VirtioGpu(gpu)) => {
                                con.print_gpu(gpu, b"[fbdev] Registered with console\n");
                            }
                            Some(FbBackend::Ramfb(fb)) => {
                                con.print(fb, b"[fbdev] Registered with console\n");
                            }
                            None => {}
                        }
                    }
                }
            }
        }
    }

    // Main IPC server loop
    loop {
        let recv = ipc::recv(ipc::TASK_ANY);
        handle_message(recv.sender, &recv.msg);
    }
}

fn handle_message(_sender: usize, msg: &ipc::Message) {
    let mut reply = ipc::Message::empty();

    match msg.tag {
        msg::FB_INIT => {
            unsafe {
                match &BACKEND {
                    Some(FbBackend::VirtioGpu(gpu)) => {
                        reply.tag = msg::ERR_OK as u64;
                        reply.data[0] = gpu.width as u64;
                        reply.data[1] = gpu.height as u64;
                        reply.data[2] = 32; // bpp
                        reply.data[3] = (gpu.width * 4) as u64; // stride
                    }
                    Some(FbBackend::Ramfb(fb)) => {
                        reply.tag = msg::ERR_OK as u64;
                        reply.data[0] = fb.width() as u64;
                        reply.data[1] = fb.height() as u64;
                        reply.data[2] = fb.bytes_per_pixel() as u64 * 8;
                        reply.data[3] = fb.stride() as u64;
                    }
                    None => {
                        reply.tag = msg::ERR_IO as u64;
                    }
                }
            }
        }

        msg::FB_CLEAR => {
            let color = msg.data[0] as u32;
            unsafe {
                match &mut BACKEND {
                    Some(FbBackend::VirtioGpu(gpu)) => {
                        gpu.clear(color);
                        reply.tag = msg::ERR_OK as u64;
                    }
                    Some(FbBackend::Ramfb(fb)) => {
                        fb.clear(color);
                        reply.tag = msg::ERR_OK as u64;
                    }
                    None => {
                        reply.tag = msg::ERR_IO as u64;
                    }
                }
            }
        }

        msg::FB_PIXEL => {
            let x = msg.data[0] as u32;
            let y = msg.data[1] as u32;
            let color = msg.data[2] as u32;
            unsafe {
                match &mut BACKEND {
                    Some(FbBackend::VirtioGpu(gpu)) => {
                        gpu.put_pixel(x, y, color);
                        // Flush small region
                        gpu.flush(x, y, 1, 1);
                        reply.tag = msg::ERR_OK as u64;
                    }
                    Some(FbBackend::Ramfb(fb)) => {
                        fb.put_pixel(x, y, color);
                        reply.tag = msg::ERR_OK as u64;
                    }
                    None => {
                        reply.tag = msg::ERR_IO as u64;
                    }
                }
            }
        }

        msg::FB_RECT => {
            let xy = msg.data[0];
            let wh = msg.data[1];
            let color = msg.data[2] as u32;
            let x = (xy & 0xFFFF) as u32;
            let y = ((xy >> 16) & 0xFFFF) as u32;
            let w = (wh & 0xFFFF) as u32;
            let h = ((wh >> 16) & 0xFFFF) as u32;
            unsafe {
                match &mut BACKEND {
                    Some(FbBackend::VirtioGpu(gpu)) => {
                        // Fill rect manually
                        for py in y..(y + h) {
                            for px in x..(x + w) {
                                gpu.put_pixel(px, py, color);
                            }
                        }
                        gpu.flush(x, y, w, h);
                        reply.tag = msg::ERR_OK as u64;
                    }
                    Some(FbBackend::Ramfb(fb)) => {
                        fb.fill_rect(x, y, w, h, color);
                        reply.tag = msg::ERR_OK as u64;
                    }
                    None => {
                        reply.tag = msg::ERR_IO as u64;
                    }
                }
            }
        }

        msg::FB_PUTCHAR => {
            let col = msg.data[0] as u32;
            let row = msg.data[1] as u32;
            let c = msg.data[2] as u8;
            let colors = msg.data[3];
            let fg = (colors & 0xFFFFFFFF) as u32;
            let bg = ((colors >> 32) & 0xFFFFFFFF) as u32;

            unsafe {
                match &mut BACKEND {
                    Some(FbBackend::VirtioGpu(gpu)) => {
                        let px = col * font::FONT_WIDTH;
                        let py = row * font::FONT_HEIGHT;
                        font::draw_char_gpu(gpu, px, py, c, fg, bg);
                        gpu.flush(px, py, font::FONT_WIDTH, font::FONT_HEIGHT);
                        reply.tag = msg::ERR_OK as u64;
                    }
                    Some(FbBackend::Ramfb(fb)) => {
                        let px = col * font::FONT_WIDTH;
                        let py = row * font::FONT_HEIGHT;
                        font::draw_char(fb, px, py, c, fg, bg);
                        reply.tag = msg::ERR_OK as u64;
                    }
                    None => {
                        reply.tag = msg::ERR_IO as u64;
                    }
                }
            }
        }

        msg::FB_PRINT => {
            // FB_PRINT uses the same SHM we registered with console
            // Just read from our already-mapped fb_print_shm_addr
            let len = msg.data[1] as usize;

            unsafe {
                if FB_PRINT_SHM_ADDR == 0 {
                    reply.tag = msg::ERR_IO as u64;
                } else {
                    let print_len = len;  // Full buffer
                    match (&mut BACKEND, &mut CONSOLE) {
                        (Some(FbBackend::VirtioGpu(gpu)), Some(con)) => {
                            let buf = core::slice::from_raw_parts(FB_PRINT_SHM_ADDR as *const u8, print_len);
                            con.print_gpu(gpu, buf);
                            reply.tag = msg::ERR_OK as u64;
                        }
                        (Some(FbBackend::Ramfb(fb)), Some(con)) => {
                            let buf = core::slice::from_raw_parts(FB_PRINT_SHM_ADDR as *const u8, print_len);
                            con.print(fb, buf);
                            reply.tag = msg::ERR_OK as u64;
                        }
                        _ => {
                            reply.tag = msg::ERR_IO as u64;
                        }
                    }
                }
            }
            /*
            unsafe {
                if FB_PRINT_SHM_ADDR == 0 {
                    reply.tag = msg::ERR_IO as u64;
                } else {
                    match (&mut BACKEND, &mut CONSOLE) {
                        (Some(FbBackend::VirtioGpu(gpu)), Some(con)) => {
                            let buf = core::slice::from_raw_parts(FB_PRINT_SHM_ADDR as *const u8, len);
                            con.print_gpu(gpu, buf);
                            reply.tag = msg::ERR_OK as u64;
                        }
                        (Some(FbBackend::Ramfb(fb)), Some(con)) => {
                            let buf = core::slice::from_raw_parts(FB_PRINT_SHM_ADDR as *const u8, len);
                            con.print(fb, buf);
                            reply.tag = msg::ERR_OK as u64;
                        }
                        _ => {
                            reply.tag = msg::ERR_IO as u64;
                        }
                    }
                }
            }
            */
        }

        msg::FB_SCROLL => {
            unsafe {
                match (&mut BACKEND, &CONSOLE) {
                    (Some(FbBackend::VirtioGpu(gpu)), Some(con)) => {
                        con.scroll_gpu(gpu);
                        reply.tag = msg::ERR_OK as u64;
                    }
                    (Some(FbBackend::Ramfb(fb)), Some(con)) => {
                        con.scroll(fb);
                        reply.tag = msg::ERR_OK as u64;
                    }
                    _ => {
                        reply.tag = msg::ERR_IO as u64;
                    }
                }
            }
        }

        msg::FB_CURSOR_SET => {
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

        msg::FB_BLIT => {
            // Blit 32bpp pixel data from shared memory to framebuffer
            // data[0] = shm_id, data[1] = x|(y<<16), data[2] = w|(h<<16), data[3] = stride
            let shm_id = msg.data[0];
            let xy = msg.data[1];
            let wh = msg.data[2];
            let src_stride = msg.data[3] as usize;
            let x = (xy & 0xFFFF) as u32;
            let y = ((xy >> 16) & 0xFFFF) as u32;
            let w = (wh & 0xFFFF) as usize;
            let h = ((wh >> 16) & 0xFFFF) as usize;

            // Map the shared memory
            let shm_addr = shm::map(shm_id, 0);
            if shm_addr < 0 {
                reply.tag = msg::ERR_IO as u64;
            } else {
                let src = shm_addr as *const u32;
                unsafe {
                    match &mut BACKEND {
                        Some(FbBackend::VirtioGpu(gpu)) => {
                            // Copy pixels to GPU framebuffer
                            let src_stride_pixels = src_stride / 4;
                            for row in 0..h {
                                for col in 0..w {
                                    let pixel = *src.add(row * src_stride_pixels + col);
                                    gpu.put_pixel(x + col as u32, y + row as u32, pixel);
                                }
                            }
                            gpu.flush(x, y, w as u32, h as u32);
                            reply.tag = msg::ERR_OK as u64;
                        }
                        Some(FbBackend::Ramfb(fb)) => {
                            let src_stride_pixels = src_stride / 4;
                            for row in 0..h {
                                for col in 0..w {
                                    let pixel = *src.add(row * src_stride_pixels + col);
                                    fb.put_pixel(x + col as u32, y + row as u32, pixel);
                                }
                            }
                            reply.tag = msg::ERR_OK as u64;
                        }
                        None => {
                            reply.tag = msg::ERR_IO as u64;
                        }
                    }
                }
                // Unmap shared memory (pass shm_id, not shm_addr!)
                let _ = shm::unmap(shm_id);
            }
        }

        _ => {
            reply.tag = msg::ERR_INVAL as u64;
        }
    }

    let _ = ipc::reply(&reply);
}
