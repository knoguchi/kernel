#![no_main]
#![no_std]

extern crate alloc;

use log::info;
use uefi::prelude::*;
use uefi::mem::memory_map::MemoryMap;
use uefi::table::boot::MemoryType;

#[entry]
fn main() -> Status {
    uefi::helpers::init().unwrap();

    info!("=================================");
    info!("  Kenix Microkernel Bootloader");
    info!("=================================");
    info!("");
    info!("UEFI boot successful!");

    // print memory map
    let memory_map = boot::memory_map(MemoryType::LOADER_DATA).unwrap();

    let mut total_pages = 0u64;
    for desc in memory_map.entries() {
        if desc.ty == MemoryType::CONVENTIONAL {
            total_pages += desc.page_count;
        }
    }
    info!("Available memory: {} MB", (total_pages * 4096) / (1024 * 1024));

    info!("");
    info!("Next: Load kernel...");

    // stop here for now
    loop {
        core::hint::spin_loop();
    }
}
