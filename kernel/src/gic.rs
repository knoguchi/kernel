//! GICv2 Driver for ARM Generic Interrupt Controller
//!
//! QEMU virt machine memory map:
//! - GICD (Distributor): 0x0800_0000
//! - GICC (CPU Interface): 0x0801_0000

use core::ptr;

/// GIC Distributor base address (QEMU virt)
const GICD_BASE: usize = 0x0800_0000;
/// GIC CPU Interface base address (QEMU virt)
const GICC_BASE: usize = 0x0801_0000;

/// EL1 Physical Timer IRQ (PPI, ID 30)
pub const TIMER_IRQ: u32 = 30;

// GICD Register Offsets
const GICD_CTLR: usize = 0x000;      // Distributor Control Register
const GICD_ISENABLER: usize = 0x100; // Interrupt Set-Enable Registers (banked per 32 IRQs)
const GICD_ICENABLER: usize = 0x180; // Interrupt Clear-Enable Registers
const GICD_IPRIORITYR: usize = 0x400; // Interrupt Priority Registers
const GICD_ITARGETSR: usize = 0x800; // Interrupt Target Registers
const GICD_ICFGR: usize = 0xC00;     // Interrupt Configuration Registers

// GICC Register Offsets
const GICC_CTLR: usize = 0x000;  // CPU Interface Control Register
const GICC_PMR: usize = 0x004;   // Interrupt Priority Mask Register
const GICC_IAR: usize = 0x00C;   // Interrupt Acknowledge Register
const GICC_EOIR: usize = 0x010;  // End of Interrupt Register

// GICD_CTLR bits
const GICD_CTLR_ENABLE: u32 = 1 << 0;

// GICC_CTLR bits
const GICC_CTLR_ENABLE: u32 = 1 << 0;

/// Spurious IRQ number (indicates no pending interrupt)
pub const IRQ_SPURIOUS: u32 = 1023;

/// GICv2 driver instance
pub struct Gic {
    gicd_base: usize,
    gicc_base: usize,
}

impl Gic {
    /// Initialize the GIC
    ///
    /// # Safety
    /// Must be called once during kernel initialization
    pub unsafe fn init() -> Self {
        let gic = Self {
            gicd_base: GICD_BASE,
            gicc_base: GICC_BASE,
        };

        // Disable distributor while configuring
        gic.write_gicd(GICD_CTLR, 0);

        // Set priority mask to allow all priorities (lower = higher priority)
        gic.write_gicc(GICC_PMR, 0xFF);

        // Enable CPU interface
        gic.write_gicc(GICC_CTLR, GICC_CTLR_ENABLE);

        // Enable distributor
        gic.write_gicd(GICD_CTLR, GICD_CTLR_ENABLE);

        gic
    }

    /// Enable a specific IRQ
    pub fn enable_irq(&self, irq: u32) {
        // IRQs 0-31 are PPIs/SGIs (banked), 32+ are SPIs
        let reg_index = (irq / 32) as usize;
        let bit_offset = irq % 32;

        unsafe {
            let reg_addr = self.gicd_base + GICD_ISENABLER + (reg_index * 4);
            ptr::write_volatile(reg_addr as *mut u32, 1 << bit_offset);
        }

        // Set priority (lower = higher priority, use middle priority)
        self.set_priority(irq, 0x80);

        // For SPIs (IRQ >= 32), set target to CPU 0
        if irq >= 32 {
            self.set_target(irq, 0x01);
        }
    }

    /// Disable a specific IRQ
    pub fn disable_irq(&self, irq: u32) {
        let reg_index = (irq / 32) as usize;
        let bit_offset = irq % 32;

        unsafe {
            let reg_addr = self.gicd_base + GICD_ICENABLER + (reg_index * 4);
            ptr::write_volatile(reg_addr as *mut u32, 1 << bit_offset);
        }
    }

    /// Acknowledge an interrupt (read IAR)
    /// Returns the IRQ number (or IRQ_SPURIOUS if none pending)
    pub fn acknowledge(&self) -> u32 {
        unsafe { self.read_gicc(GICC_IAR) }
    }

    /// Signal end of interrupt handling
    pub fn end_of_interrupt(&self, irq: u32) {
        unsafe {
            self.write_gicc(GICC_EOIR, irq);
        }
    }

    /// Set priority for an IRQ (0 = highest, 255 = lowest)
    fn set_priority(&self, irq: u32, priority: u8) {
        let reg_index = (irq / 4) as usize;
        let byte_offset = (irq % 4) as usize;

        unsafe {
            let reg_addr = self.gicd_base + GICD_IPRIORITYR + (reg_index * 4);
            let mut val = ptr::read_volatile(reg_addr as *const u32);
            val &= !(0xFF << (byte_offset * 8));
            val |= (priority as u32) << (byte_offset * 8);
            ptr::write_volatile(reg_addr as *mut u32, val);
        }
    }

    /// Set CPU target for an SPI (bitmask of target CPUs)
    fn set_target(&self, irq: u32, target: u8) {
        let reg_index = (irq / 4) as usize;
        let byte_offset = (irq % 4) as usize;

        unsafe {
            let reg_addr = self.gicd_base + GICD_ITARGETSR + (reg_index * 4);
            let mut val = ptr::read_volatile(reg_addr as *const u32);
            val &= !(0xFF << (byte_offset * 8));
            val |= (target as u32) << (byte_offset * 8);
            ptr::write_volatile(reg_addr as *mut u32, val);
        }
    }

    /// Read GICD register
    unsafe fn read_gicd(&self, offset: usize) -> u32 {
        ptr::read_volatile((self.gicd_base + offset) as *const u32)
    }

    /// Write GICD register
    unsafe fn write_gicd(&self, offset: usize, value: u32) {
        ptr::write_volatile((self.gicd_base + offset) as *mut u32, value);
    }

    /// Read GICC register
    unsafe fn read_gicc(&self, offset: usize) -> u32 {
        ptr::read_volatile((self.gicc_base + offset) as *const u32)
    }

    /// Write GICC register
    unsafe fn write_gicc(&self, offset: usize, value: u32) {
        ptr::write_volatile((self.gicc_base + offset) as *mut u32, value);
    }
}

// Global GIC instance
static mut GIC: Option<Gic> = None;

/// Initialize the global GIC instance
///
/// # Safety
/// Must be called once during kernel initialization
pub unsafe fn init() {
    GIC = Some(Gic::init());
}

/// Enable a specific IRQ
pub fn enable_irq(irq: u32) {
    unsafe {
        if let Some(ref gic) = GIC {
            gic.enable_irq(irq);
        }
    }
}

/// Acknowledge an interrupt
pub fn acknowledge() -> u32 {
    unsafe {
        GIC.as_ref().map(|g| g.acknowledge()).unwrap_or(IRQ_SPURIOUS)
    }
}

/// Signal end of interrupt
pub fn end_of_interrupt(irq: u32) {
    unsafe {
        if let Some(ref gic) = GIC {
            gic.end_of_interrupt(irq);
        }
    }
}
