#![no_std]
#![no_main]
#![feature(linkage)]

use core::panic::PanicInfo;
use core::fmt::Write;
use spin::Mutex;

mod exception;
mod mm;

// Memory intrinsics required by compiler
#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn memset(dest: *mut u8, c: i32, n: usize) -> *mut u8 {
    let c = c as u8;
    for i in 0..n {
        *dest.add(i) = c;
    }
    dest
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    for i in 0..n {
        *dest.add(i) = *src.add(i);
    }
    dest
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn memmove(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if src < dest as *const u8 {
        // Copy backwards
        for i in (0..n).rev() {
            *dest.add(i) = *src.add(i);
        }
    } else {
        // Copy forwards
        for i in 0..n {
            *dest.add(i) = *src.add(i);
        }
    }
    dest
}

#[no_mangle]
#[linkage = "weak"]
pub unsafe extern "C" fn memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    for i in 0..n {
        let a = *s1.add(i);
        let b = *s2.add(i);
        if a != b {
            return a as i32 - b as i32;
        }
    }
    0
}

// QEMU virt machine PL011 UART base address. Raspberry Pi base address is different.
const UART_BASE: usize = 0x0900_0000;

// PL011 register offsets
const UART_DR: usize = 0x000;   // Data register
const UART_FR: usize = 0x018;   // Flag register
const UART_CR: usize = 0x030;   // Control register

// Flag register bits
const UART_FR_TXFF: u32 = 1 << 5;  // TX FIFO full

// Control register bits
const UART_CR_UARTEN: u32 = 1 << 0;  // UART enable
const UART_CR_TXE: u32 = 1 << 8;     // TX enable

// Memory layout for QEMU virt machine
const RAM_START: usize = 0x4000_0000;
const RAM_END: usize = 0x8000_0000; // 1GB RAM

extern "C" {
    static __kernel_end: u8;
}

struct Uart {
    base: usize,
    initialized: bool,
}

impl Uart {
    const fn new(base: usize) -> Self {
        Self { base, initialized: false }
    }

    fn init(&mut self) {
        if self.initialized {
            return;
        }
        unsafe {
            // Enable UART and TX
            let cr = (self.base + UART_CR) as *mut u32;
            core::ptr::write_volatile(cr, UART_CR_UARTEN | UART_CR_TXE);
        }
        self.initialized = true;
    }

    fn putc(&mut self, c: u8) {
        self.init();
        unsafe {
            // Wait until TX FIFO is not full
            let fr = (self.base + UART_FR) as *const u32;
            while (core::ptr::read_volatile(fr) & UART_FR_TXFF) != 0 {
                core::hint::spin_loop();
            }
            // Write character
            let dr = (self.base + UART_DR) as *mut u8;
            core::ptr::write_volatile(dr, c);
        }
    }
}

impl Write for Uart {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for c in s.bytes() {
            self.putc(c);
        }
        Ok(())
    }
}

unsafe impl Send for Uart {}

static UART: Mutex<Uart> = Mutex::new(Uart::new(UART_BASE));

macro_rules! print {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        write!(UART.lock(), $($arg)*).unwrap()
    }};
}

macro_rules! println {
    () => { print!("\n") };
    ($($arg:tt)*) => {{ print!($($arg)*); print!("\n"); }};
}

#[no_mangle]
pub extern "C" fn kernel_main() -> ! {
    println!("=================================");
    println!("  Kenix Microkernel v0.1.0");
    println!("  AArch64 / QEMU virt");
    println!("=================================");
    println!();

    // Initialize physical memory allocator
    let kernel_end = unsafe { &__kernel_end as *const u8 as usize };

    println!("Initializing physical memory allocator...");
    println!("  Memory: {:#010x} - {:#010x} ({} MB)",
             RAM_START, RAM_END, (RAM_END - RAM_START) / (1024 * 1024));
    println!("  Kernel ends at: {:#010x}", kernel_end);

    mm::init(RAM_START, RAM_END, kernel_end);
    println!("  Total pages: {}", mm::total_pages());
    println!("  Free pages: {}", mm::free_pages());
    println!();

    // Test allocation
    println!("Allocating test frames...");
    let frame0 = mm::alloc_frame();
    let frame1 = mm::alloc_frame();
    let frame2 = mm::alloc_frame();

    if let Some(f) = frame0 {
        println!("  Frame 0: {:#010x}", f.as_usize());
    }
    if let Some(f) = frame1 {
        println!("  Frame 1: {:#010x}", f.as_usize());
    }
    if let Some(f) = frame2 {
        println!("  Frame 2: {:#010x}", f.as_usize());
    }
    println!();

    // Test freeing
    println!("Freeing test frames...");
    if let Some(f) = frame0 {
        mm::free_frame(f);
    }
    if let Some(f) = frame1 {
        mm::free_frame(f);
    }
    if let Some(f) = frame2 {
        mm::free_frame(f);
    }

    println!("  Free pages after freeing: {}", mm::free_pages());
    println!();
    println!("Physical memory allocator ready!");
    println!();

    // Enable MMU with identity mapping
    println!("Enabling MMU...");
    unsafe {
        mm::enable_mmu(|msg, addr| {
            println!("{}{:#010x}", msg, addr);
        });
    }
    println!("MMU enabled - identity mapping active");
    println!("  UART: Device-nGnRnE");
    println!("  RAM: Normal Write-Back cacheable");
    println!();

    // Set up exception vectors
    println!("Setting up exception vectors...");
    unsafe { exception::init(); }
    println!("  VBAR_EL1: {:#018x}", exception::vbar_el1());
    println!("Exception handling ready!");
    println!();

    // Uncomment to test exception handling:
    // println!("Testing exception handler with null pointer access...");
    // unsafe { core::ptr::read_volatile(0 as *const u8); }

    println!("TODO:");
    println!("  - IPC");
    println!("  - Scheduler");

    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("KERNEL PANIC: {}", info);
    loop {
        core::hint::spin_loop();
    }
}
