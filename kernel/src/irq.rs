//! IRQ routing for userspace drivers
//!
//! This module provides IRQ-to-task routing so userspace device drivers
//! can handle hardware interrupts. When an IRQ fires, the kernel wakes
//! the registered task and sets a pending flag.

use crate::sched::{TaskId, TaskState, enqueue_task};
use crate::sched::task::TASKS;

/// Maximum number of IRQs we can route
pub const MAX_IRQS: usize = 128;

/// VirtIO block device IRQ (SPI 48 = IRQ 80 in GIC numbering)
/// QEMU virt machine: first virtio device uses SPI 48
pub const VIRTIO_BLK_IRQ: u32 = 48 + 32; // SPI offset = 32

/// IRQ handler entry
#[derive(Clone, Copy)]
pub struct IrqHandler {
    /// Task ID to wake when IRQ fires (None = no handler)
    pub task_id: Option<TaskId>,
    /// Whether an IRQ is pending (not yet acknowledged)
    pub pending: bool,
}

impl IrqHandler {
    pub const fn empty() -> Self {
        Self {
            task_id: None,
            pending: false,
        }
    }
}

/// Global IRQ routing table
pub static mut IRQ_HANDLERS: [IrqHandler; MAX_IRQS] = [IrqHandler::empty(); MAX_IRQS];

/// Register a task as the handler for an IRQ
///
/// # Arguments
/// * `irq` - IRQ number (GIC interrupt ID)
/// * `task_id` - Task to wake when IRQ fires
///
/// # Returns
/// * 0 on success
/// * -1 if IRQ number is invalid
/// * -2 if IRQ already has a handler
pub fn register_irq_handler(irq: u32, task_id: TaskId) -> i64 {
    if irq as usize >= MAX_IRQS {
        return -1; // Invalid IRQ
    }

    unsafe {
        let handler = &mut IRQ_HANDLERS[irq as usize];
        if handler.task_id.is_some() {
            return -2; // Already registered
        }

        handler.task_id = Some(task_id);
        handler.pending = false;
    }

    // Enable the IRQ in the GIC
    crate::gic::enable_irq(irq);

    0
}

/// Unregister a task from an IRQ
pub fn unregister_irq_handler(irq: u32) -> i64 {
    if irq as usize >= MAX_IRQS {
        return -1;
    }

    unsafe {
        let handler = &mut IRQ_HANDLERS[irq as usize];
        handler.task_id = None;
        handler.pending = false;
    }

    0
}

/// Handle an IRQ by waking the registered task
///
/// Called from the exception handler when a non-timer IRQ fires.
///
/// # Returns
/// * true if a handler was found and the task was woken
/// * false if no handler registered
pub fn handle_irq(irq: u32) -> bool {
    if irq as usize >= MAX_IRQS {
        return false;
    }

    unsafe {
        let handler = &mut IRQ_HANDLERS[irq as usize];

        if let Some(task_id) = handler.task_id {
            // Mark IRQ as pending
            handler.pending = true;

            // Wake the task if it's blocked waiting for this IRQ
            let task = &mut TASKS[task_id.0];
            if task.state == TaskState::IrqBlocked {
                task.state = TaskState::Ready;
                enqueue_task(task_id);
            }

            return true;
        }
    }

    false
}

/// Check if an IRQ is pending for the current task
pub fn is_irq_pending(irq: u32) -> bool {
    if irq as usize >= MAX_IRQS {
        return false;
    }

    unsafe {
        IRQ_HANDLERS[irq as usize].pending
    }
}

/// Acknowledge an IRQ (clear pending flag)
///
/// Called by userspace after handling the IRQ.
pub fn acknowledge_irq(irq: u32) -> i64 {
    if irq as usize >= MAX_IRQS {
        return -1;
    }

    unsafe {
        let handler = &mut IRQ_HANDLERS[irq as usize];
        handler.pending = false;
    }

    // Send EOI to GIC
    crate::gic::end_of_interrupt(irq);

    0
}

/// Wait for an IRQ to fire
///
/// If the IRQ is already pending, returns immediately.
/// Otherwise, blocks the task until the IRQ fires.
///
/// # Returns
/// * 0 if IRQ fired
/// * -1 if invalid IRQ
/// * -2 if task is not the registered handler
pub fn wait_for_irq(irq: u32, task_id: TaskId) -> i64 {
    if irq as usize >= MAX_IRQS {
        return -1;
    }

    unsafe {
        let handler = &IRQ_HANDLERS[irq as usize];

        // Verify this task owns the IRQ
        if handler.task_id != Some(task_id) {
            return -2;
        }

        // If already pending, return immediately
        if handler.pending {
            return 0;
        }
    }

    // Need to block - this is handled by the syscall dispatcher
    // Return a special value to indicate blocking is needed
    1 // Signal to syscall handler to block
}
