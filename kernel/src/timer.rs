//! ARM Generic Timer Driver
//!
//! Uses the EL1 Physical Timer (CNTP) for scheduler ticks.
//! System registers:
//! - CNTFRQ_EL0: Counter frequency (read-only)
//! - CNTP_CTL_EL0: Physical timer control
//! - CNTP_TVAL_EL0: Timer value (countdown)
//! - CNTP_CVAL_EL0: Compare value (absolute)

/// Timer control register bits
const CNTP_CTL_ENABLE: u64 = 1 << 0;  // Timer enabled
const CNTP_CTL_IMASK: u64 = 1 << 1;   // Interrupt masked
const CNTP_CTL_ISTATUS: u64 = 1 << 2; // Interrupt status (read-only)

/// ARM Generic Timer
pub struct Timer {
    frequency: u64,
    ticks_per_interval: u64,
}

impl Timer {
    /// Initialize the timer
    ///
    /// # Safety
    /// Must be called once during kernel initialization
    pub unsafe fn init() -> Self {
        let frequency = read_cntfrq_el0();

        // Disable timer initially
        write_cntp_ctl_el0(0);

        Timer {
            frequency,
            ticks_per_interval: 0,
        }
    }

    /// Get the timer frequency in Hz
    pub fn frequency(&self) -> u64 {
        self.frequency
    }

    /// Start the timer with a periodic interval
    ///
    /// # Arguments
    /// * `interval_ms` - Interval in milliseconds
    pub fn start_periodic(&mut self, interval_ms: u64) {
        // Calculate ticks for the interval
        self.ticks_per_interval = (self.frequency * interval_ms) / 1000;

        unsafe {
            // Set the countdown value
            write_cntp_tval_el0(self.ticks_per_interval);

            // Enable timer, unmask interrupt
            write_cntp_ctl_el0(CNTP_CTL_ENABLE);
        }
    }

    /// Stop the timer
    pub fn stop(&self) {
        unsafe {
            write_cntp_ctl_el0(0);
        }
    }

    /// Acknowledge timer interrupt and reset for next tick
    pub fn acknowledge_and_reset(&self) {
        unsafe {
            // Writing TVAL clears the interrupt condition
            write_cntp_tval_el0(self.ticks_per_interval);
        }
    }

    /// Check if timer interrupt is pending
    pub fn is_pending(&self) -> bool {
        unsafe {
            (read_cntp_ctl_el0() & CNTP_CTL_ISTATUS) != 0
        }
    }
}

// System register access functions

#[inline]
unsafe fn read_cntfrq_el0() -> u64 {
    let val: u64;
    core::arch::asm!(
        "mrs {}, cntfrq_el0",
        out(reg) val,
        options(nostack, preserves_flags)
    );
    val
}

#[inline]
unsafe fn read_cntp_ctl_el0() -> u64 {
    let val: u64;
    core::arch::asm!(
        "mrs {}, cntp_ctl_el0",
        out(reg) val,
        options(nostack, preserves_flags)
    );
    val
}

#[inline]
unsafe fn write_cntp_ctl_el0(val: u64) {
    core::arch::asm!(
        "msr cntp_ctl_el0, {}",
        in(reg) val,
        options(nostack, preserves_flags)
    );
}

#[inline]
unsafe fn write_cntp_tval_el0(val: u64) {
    core::arch::asm!(
        "msr cntp_tval_el0, {}",
        in(reg) val,
        options(nostack, preserves_flags)
    );
}

// Global Timer instance
static mut TIMER: Option<Timer> = None;

/// Initialize the global timer instance
///
/// # Safety
/// Must be called once during kernel initialization
pub unsafe fn init() {
    TIMER = Some(Timer::init());
}

/// Get timer frequency
pub fn frequency() -> u64 {
    unsafe {
        TIMER.as_ref().map(|t| t.frequency()).unwrap_or(0)
    }
}

/// Start the timer with specified interval in milliseconds
pub fn start(interval_ms: u64) {
    unsafe {
        if let Some(ref mut timer) = TIMER {
            timer.start_periodic(interval_ms);
        }
    }
}

/// Stop the timer
pub fn stop() {
    unsafe {
        if let Some(ref timer) = TIMER {
            timer.stop();
        }
    }
}

/// Acknowledge timer interrupt and reset for next tick
pub fn acknowledge_and_reset() {
    unsafe {
        if let Some(ref timer) = TIMER {
            timer.acknowledge_and_reset();
        }
    }
}
