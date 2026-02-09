#![no_std]
#![no_main]
#![feature(linkage)]

extern crate alloc;

use core::panic::PanicInfo;
use core::fmt::Write;
use spin::Mutex;

mod exception;
mod mm;
mod gic;
mod timer;
mod sched;
mod syscall;
mod elf;
mod ipc;
mod shm;
mod irq;
mod allocator;
mod mmap;

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
    // Console server ELF (created first, gets task ID 1)
    static __console_elf_start: u8;
    static __console_elf_end: u8;
    // Init program ELF (created second, gets task ID 2)
    static __init_elf_start: u8;
    static __init_elf_end: u8;
    // VFS server ELF (created third, gets task ID 3)
    static __vfs_elf_start: u8;
    static __vfs_elf_end: u8;
    // Block device server ELF (created fourth, gets task ID 4)
    static __blkdev_elf_start: u8;
    static __blkdev_elf_end: u8;
    // Network device server ELF (created fifth, gets task ID 5)
    static __netdev_elf_start: u8;
    static __netdev_elf_end: u8;
    // Pipe server ELF (created sixth, gets task ID 6)
    static __pipeserv_elf_start: u8;
    static __pipeserv_elf_end: u8;
    // Framebuffer device server ELF (created seventh, gets task ID 7)
    static __fbdev_elf_start: u8;
    static __fbdev_elf_end: u8;
    // Keyboard device server ELF (created eighth, gets task ID 8)
    static __kbdev_elf_start: u8;
    static __kbdev_elf_end: u8;
    // Forktest ELF
    static __forktest_elf_start: u8;
    static __forktest_elf_end: u8;
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

pub static UART: Mutex<Uart> = Mutex::new(Uart::new(UART_BASE));

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        write!($crate::UART.lock(), $($arg)*).unwrap()
    }};
}

#[macro_export]
macro_rules! println {
    () => { $crate::print!("\n") };
    ($($arg:tt)*) => {{ $crate::print!($($arg)*); $crate::print!("\n"); }};
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

    // Initialize GIC
    println!("Initializing GIC...");
    unsafe { gic::init(); }
    println!("  GICD at {:#010x}, GICC at {:#010x}", 0x0800_0000u32, 0x0801_0000u32);
    println!();

    // Initialize timer
    println!("Initializing timer...");
    unsafe { timer::init(); }
    println!("  Frequency: {} Hz", timer::frequency());
    println!("  Tick interval: 10ms");
    println!();

    // Enable timer IRQ in GIC
    gic::enable_irq(gic::TIMER_IRQ);

    // Initialize scheduler
    println!("Initializing scheduler...");
    unsafe { sched::init(); }
    println!("  Created idle task (id=0)");
    println!();

    // Create console server (task ID 1) - must be first!
    println!("Creating console server...");
    let console_start = unsafe { &__console_elf_start as *const u8 };
    let console_end = unsafe { &__console_elf_end as *const u8 };
    let console_size = console_end as usize - console_start as usize;
    let console_data = unsafe { core::slice::from_raw_parts(console_start, console_size) };

    println!("  Console ELF at {:#010x}, size {} bytes", console_start as usize, console_size);

    if let Some(id) = sched::create_console_server_from_elf("console", console_data) {
        println!("  Created console server (id={}) - runs in EL0 with UART access", id.0);
    } else {
        println!("  ERROR: Failed to create console server!");
    }
    println!();

    // Create init task from ELF
    println!("Creating init task...");
    let init_start = unsafe { &__init_elf_start as *const u8 };
    let init_end = unsafe { &__init_elf_end as *const u8 };
    let init_size = init_end as usize - init_start as usize;
    let init_data = unsafe { core::slice::from_raw_parts(init_start, init_size) };

    println!("  Init ELF at {:#010x}, size {} bytes", init_start as usize, init_size);

    // Parse ELF to show info
    if let Ok(elf_file) = elf::ElfFile::parse(init_data) {
        println!("  Entry point: {:#010x}", elf_file.entry_point());
        println!("  PT_LOAD segments: {}", elf_file.load_segment_count());
        for (i, phdr) in elf_file.load_segments().enumerate() {
            println!("    Segment {}: vaddr={:#010x}, filesz={}, memsz={}, flags={}",
                i, phdr.p_vaddr, phdr.p_filesz, phdr.p_memsz, elf::flags_to_str(phdr.p_flags));
        }
    }

    if let Some(id) = sched::create_user_task_from_elf("init", init_data) {
        println!("  Created init task (id={}) - runs in EL0", id.0);
    } else {
        println!("  ERROR: Failed to create init task!");
    }
    println!();

    // Create VFS server (task ID 3)
    println!("Creating VFS server...");
    let vfs_start = unsafe { &__vfs_elf_start as *const u8 };
    let vfs_end = unsafe { &__vfs_elf_end as *const u8 };
    let vfs_size = vfs_end as usize - vfs_start as usize;
    let vfs_data = unsafe { core::slice::from_raw_parts(vfs_start, vfs_size) };

    println!("  VFS ELF at {:#010x}, size {} bytes", vfs_start as usize, vfs_size);

    if let Some(id) = sched::create_user_task_from_elf("vfs", vfs_data) {
        println!("  Created VFS server (id={}) - runs in EL0", id.0);
    } else {
        println!("  ERROR: Failed to create VFS server!");
    }
    println!();

    // Create blkdev server (task ID 4)
    println!("Creating blkdev server...");
    let blkdev_start = unsafe { &__blkdev_elf_start as *const u8 };
    let blkdev_end = unsafe { &__blkdev_elf_end as *const u8 };
    let blkdev_size = blkdev_end as usize - blkdev_start as usize;
    let blkdev_data = unsafe { core::slice::from_raw_parts(blkdev_start, blkdev_size) };

    println!("  Blkdev ELF at {:#010x}, size {} bytes", blkdev_start as usize, blkdev_size);

    if let Some(id) = sched::create_blkdev_server_from_elf("blkdev", blkdev_data) {
        println!("  Created blkdev server (id={}) - runs in EL0 with VirtIO access", id.0);
    } else {
        println!("  ERROR: Failed to create blkdev server!");
    }
    println!();

    // Create netdev server (task ID 5)
    println!("Creating netdev server...");
    let netdev_start = unsafe { &__netdev_elf_start as *const u8 };
    let netdev_end = unsafe { &__netdev_elf_end as *const u8 };
    let netdev_size = netdev_end as usize - netdev_start as usize;
    let netdev_data = unsafe { core::slice::from_raw_parts(netdev_start, netdev_size) };

    println!("  Netdev ELF at {:#010x}, size {} bytes", netdev_start as usize, netdev_size);

    if let Some(id) = sched::create_netdev_server_from_elf("netdev", netdev_data) {
        println!("  Created netdev server (id={}) - runs in EL0 with VirtIO access", id.0);
    } else {
        println!("  ERROR: Failed to create netdev server!");
    }
    println!();

    // Create pipeserv server (task ID 6)
    println!("Creating pipeserv server...");
    let pipeserv_start = unsafe { &__pipeserv_elf_start as *const u8 };
    let pipeserv_end = unsafe { &__pipeserv_elf_end as *const u8 };
    let pipeserv_size = pipeserv_end as usize - pipeserv_start as usize;
    let pipeserv_data = unsafe { core::slice::from_raw_parts(pipeserv_start, pipeserv_size) };

    println!("  Pipeserv ELF at {:#010x}, size {} bytes", pipeserv_start as usize, pipeserv_size);

    if let Some(id) = sched::create_user_task_from_elf("pipeserv", pipeserv_data) {
        println!("  Created pipeserv server (id={}) - runs in EL0", id.0);
    } else {
        println!("  ERROR: Failed to create pipeserv server!");
    }
    println!();

    // Create fbdev server (task ID 7)
    println!("Creating fbdev server...");
    let fbdev_start = unsafe { &__fbdev_elf_start as *const u8 };
    let fbdev_end = unsafe { &__fbdev_elf_end as *const u8 };
    let fbdev_size = fbdev_end as usize - fbdev_start as usize;
    let fbdev_data = unsafe { core::slice::from_raw_parts(fbdev_start, fbdev_size) };

    println!("  Fbdev ELF at {:#010x}, size {} bytes", fbdev_start as usize, fbdev_size);

    if let Some(id) = sched::create_fbdev_server_from_elf("fbdev", fbdev_data) {
        println!("  Created fbdev server (id={}) - runs in EL0 with ramfb access", id.0);
    } else {
        println!("  ERROR: Failed to create fbdev server!");
    }
    println!();

    // Create kbdev server (task ID 8)
    println!("Creating kbdev server...");
    let kbdev_start = unsafe { &__kbdev_elf_start as *const u8 };
    let kbdev_end = unsafe { &__kbdev_elf_end as *const u8 };
    let kbdev_size = kbdev_end as usize - kbdev_start as usize;
    let kbdev_data = unsafe { core::slice::from_raw_parts(kbdev_start, kbdev_size) };

    println!("  Kbdev ELF at {:#010x}, size {} bytes", kbdev_start as usize, kbdev_size);

    if let Some(id) = sched::create_kbdev_server_from_elf("kbdev", kbdev_data) {
        println!("  Created kbdev server (id={}) - runs in EL0 with VirtIO-input access", id.0);
    } else {
        println!("  ERROR: Failed to create kbdev server!");
    }
    println!();

    // Forktest is now spawned by init, not created at kernel init time
    // This avoids race conditions between init and forktest both using VFS

    // Start timer (10ms tick)
    timer::start(10);

    // Start scheduler and enable interrupts
    println!("Starting scheduler...");
    sched::start();

    // This is now the "idle task" - just loop waiting for interrupts
    // Timer interrupts will preemptively switch to other tasks
    loop {
        unsafe {
            core::arch::asm!("wfi", options(nostack, preserves_flags));
        }
    }
}

/// Test task A - prints 'A' repeatedly
fn task_a() {
    loop {
        print!("A");
        // Small delay
        for _ in 0..100000 {
            core::hint::spin_loop();
        }
    }
}

/// Test task B - prints 'B' repeatedly
fn task_b() {
    loop {
        print!("B");
        // Small delay
        for _ in 0..100000 {
            core::hint::spin_loop();
        }
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("KERNEL PANIC: {}", info);
    loop {
        core::hint::spin_loop();
    }
}
