//! Preemptive round-robin scheduler for Kenix
//!
//! This module implements a simple round-robin scheduler with:
//! - Preemptive scheduling via timer interrupts
//! - Cooperative yield support
//! - Per-task kernel stacks and page tables
//!
//! Context switch strategy:
//! - Tasks save their full ExceptionContext when interrupted
//! - Scheduler swaps the SP to point to a different task's saved context
//! - The exception return (ERET) restores the new task's context

pub mod task;

pub use task::{TaskId, TaskState, KERNEL_STACK_SIZE};

use crate::mm::{self, PhysAddr};
use crate::exception::ExceptionContext;
use task::{TASKS, DEFAULT_TIME_SLICE};

// External assembly functions
extern "C" {
    /// Switch to a new task's stack and restore its context (never returns)
    fn switch_context_and_restore(new_sp: usize) -> !;
}

/// Scheduler state
pub struct Scheduler {
    /// Currently running task (None before scheduler starts)
    current: Option<TaskId>,
    /// Head of ready queue (linked list)
    ready_head: Option<TaskId>,
    /// Tail of ready queue (for O(1) enqueue)
    ready_tail: Option<TaskId>,
    /// Idle task ID (always task 0)
    idle_task: TaskId,
    /// Total context switches (for debugging)
    switch_count: u64,
    /// Whether scheduler is running
    running: bool,
}

impl Scheduler {
    /// Create a new scheduler
    pub const fn new() -> Self {
        Self {
            current: None,
            ready_head: None,
            ready_tail: None,
            idle_task: TaskId(0),
            switch_count: 0,
            running: false,
        }
    }

    /// Add a task to the ready queue
    pub fn enqueue(&mut self, task_id: TaskId) {
        unsafe {
            let task = &mut TASKS[task_id.0];
            task.state = TaskState::Ready;
            task.next = None;

            if let Some(tail_id) = self.ready_tail {
                TASKS[tail_id.0].next = Some(task_id);
                self.ready_tail = Some(task_id);
            } else {
                // Queue was empty
                self.ready_head = Some(task_id);
                self.ready_tail = Some(task_id);
            }
        }
    }

    /// Remove and return the next task from the ready queue
    pub fn dequeue(&mut self) -> Option<TaskId> {
        if let Some(head_id) = self.ready_head {
            unsafe {
                let head = &mut TASKS[head_id.0];
                self.ready_head = head.next;
                head.next = None;

                if self.ready_head.is_none() {
                    self.ready_tail = None;
                }
            }
            Some(head_id)
        } else {
            None
        }
    }

    /// Handle a timer tick
    /// Returns true if a reschedule is needed
    pub fn tick(&mut self) -> bool {
        if !self.running {
            return false;
        }

        if let Some(current_id) = self.current {
            unsafe {
                let task = &mut TASKS[current_id.0];
                if task.time_slice > 0 {
                    task.time_slice -= 1;
                }

                // Reschedule if time slice expired and there are other ready tasks
                if task.time_slice == 0 && self.ready_head.is_some() {
                    return true;
                }
            }
        }
        false
    }

    /// Get currently running task
    pub fn current(&self) -> Option<TaskId> {
        self.current
    }

    /// Perform context switch during exception handling
    ///
    /// This is called from the exception handler when a timer tick triggers rescheduling.
    /// The ctx parameter points to the interrupted task's saved context on the stack.
    ///
    /// # Safety
    /// Must be called from an exception handler with ctx pointing to the saved context.
    pub unsafe fn context_switch(&mut self, ctx: &mut ExceptionContext) {
        let current_id = self.current;

        // Save current task's context and put it back in ready queue
        if let Some(id) = current_id {
            let task = &mut TASKS[id.0];
            // Store the SP that points to the exception context
            task.kernel_stack_top = ctx as *const _ as usize;
            task.state = TaskState::Ready;
            task.time_slice = DEFAULT_TIME_SLICE;
            self.enqueue(id);
        }

        // Get next task to run
        let next_id = self.dequeue().unwrap_or(self.idle_task);

        let next_task = &mut TASKS[next_id.0];
        next_task.state = TaskState::Running;
        next_task.time_slice = DEFAULT_TIME_SLICE;
        self.current = Some(next_id);
        self.switch_count += 1;

        // If we're switching to a different task, switch to its stack and restore context
        if current_id != Some(next_id) {
            // Switch page table if needed
            if next_task.page_table.0 != 0 {
                let ttbr0 = next_task.page_table.0 as u64;
                core::arch::asm!(
                    "msr ttbr0_el1, {0}",
                    "isb",
                    "tlbi vmalle1",
                    "dsb ish",
                    "isb",
                    in(reg) ttbr0,
                    options(nostack)
                );
            }

            // Switch to the new task's stack and restore its context
            // This function never returns - it does ERET directly
            let new_sp = next_task.kernel_stack_top;
            switch_context_and_restore(new_sp);
        }
    }

    /// Voluntarily yield the CPU
    pub fn yield_cpu(&mut self) {
        if let Some(current_id) = self.current {
            unsafe {
                TASKS[current_id.0].time_slice = 0;
            }
        }
    }

    /// Terminate the current task
    pub fn exit_current(&mut self) {
        if let Some(current_id) = self.current {
            unsafe {
                let task = &mut TASKS[current_id.0];
                task.state = TaskState::Terminated;
                self.current = None;
            }
        }
    }

    /// Get switch count for debugging
    pub fn switch_count(&self) -> u64 {
        self.switch_count
    }

    /// Check if scheduler is running
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Mark scheduler as running
    pub fn set_running(&mut self) {
        self.running = true;
    }
}

// Global scheduler instance
static mut SCHEDULER: Scheduler = Scheduler::new();

/// Size of ExceptionContext structure (must match vectors.s)
const EXCEPTION_CONTEXT_SIZE: usize = 288;

/// Initialize the scheduler and create the idle task
///
/// # Safety
/// Must be called once during kernel initialization
pub unsafe fn init() {
    // Create idle task (task 0)
    // The idle task uses the kernel's boot stack
    let idle = &mut TASKS[0];
    idle.id = TaskId(0);
    idle.state = TaskState::Running; // Idle task starts as "running"
    idle.set_name("idle");
    idle.page_table = PhysAddr(0); // Use kernel page table
    idle.entry_point = idle_task_entry as *const () as usize;
    idle.kernel_stack_top = 0; // Will be set when we first switch away
    idle.time_slice = DEFAULT_TIME_SLICE;

    SCHEDULER.idle_task = TaskId(0);
    SCHEDULER.current = Some(TaskId(0)); // We're currently in the "idle" context
    SCHEDULER.running = true;
}

/// Create a new kernel task
///
/// Sets up a fake ExceptionContext on the task's stack so that when we
/// switch to it via RESTORE_CONTEXT/ERET, it starts at the entry point.
pub fn create_task(name: &str, entry_point: fn()) -> Option<TaskId> {
    let task_id = task::find_free_slot()?;

    // Allocate kernel stack (4 pages = 16KB)
    let stack_pages = KERNEL_STACK_SIZE / mm::frame::PAGE_SIZE;
    let mut stack_base = PhysAddr(0);

    for i in 0..stack_pages {
        if let Some(frame) = mm::alloc_frame() {
            if i == 0 {
                stack_base = frame;
            }
        } else {
            return None;
        }
    }

    let entry_addr = entry_point as *const () as usize;

    unsafe {
        let task = &mut TASKS[task_id.0];
        task.id = task_id;
        task.state = TaskState::Ready;
        task.set_name(name);
        task.kernel_stack_base = stack_base;
        task.page_table = PhysAddr(0); // Use kernel page table for now
        task.entry_point = entry_addr;
        task.time_slice = DEFAULT_TIME_SLICE;
        task.next = None;

        // Calculate stack top (16-byte aligned)
        let stack_top = stack_base.0 + KERNEL_STACK_SIZE;

        // Set up a fake ExceptionContext at the top of the stack
        // When we switch to this task, RESTORE_CONTEXT will pop this and ERET
        let ctx_addr = stack_top - EXCEPTION_CONTEXT_SIZE;
        let ctx = ctx_addr as *mut ExceptionContext;

        // Zero the context first
        core::ptr::write_bytes(ctx, 0, 1);

        // Set up the context so ERET goes to the entry point
        (*ctx).elr = entry_addr as u64; // Return address
        // SPSR: EL1h (M=0b00101=5), IRQs enabled (I=0), FIQ enabled (F=0)
        // D=1, A=1, I=0, F=0, M=5 → 0b0011_0000_0101 = 0x305
        (*ctx).spsr = 0x305;
        // Set stack pointer to just below the context (for the task to use)
        (*ctx).sp = ctx_addr as u64;

        // The task's saved SP points to this fake context
        task.kernel_stack_top = ctx_addr;

        // Enqueue to ready queue
        SCHEDULER.enqueue(task_id);
    }

    Some(task_id)
}

/// Start the scheduler - just enable timer, tasks will switch on interrupt
///
/// Call this after init() and create_task() calls. The current execution
/// continues as the "idle task" until a timer interrupt causes a switch.
pub fn start() {
    // IRQs will be enabled, timer will fire, and we'll switch to a real task
    unsafe {
        core::arch::asm!("msr daifclr, #2", options(nostack, preserves_flags));
    }
}

/// Handle timer tick (called from IRQ handler)
/// Returns true if a reschedule is needed
pub fn tick() -> bool {
    unsafe { SCHEDULER.tick() }
}

/// Perform a context switch (called from IRQ handler)
/// The ctx parameter is the interrupted task's saved context
pub unsafe fn context_switch(ctx: &mut ExceptionContext) {
    SCHEDULER.context_switch(ctx);
}

/// Yield the current task's time slice
pub fn yield_cpu() {
    unsafe {
        SCHEDULER.yield_cpu();
    }
}

/// Exit the current task
pub fn exit() -> ! {
    unsafe {
        SCHEDULER.exit_current();
    }
    // Should never return, but just in case
    loop {
        core::hint::spin_loop();
    }
}

/// Get current task ID
pub fn current() -> Option<TaskId> {
    unsafe { SCHEDULER.current() }
}

/// Idle task entry point (fallback, normally we run in boot context)
fn idle_task_entry() {
    loop {
        unsafe {
            core::arch::asm!("wfi", options(nostack, preserves_flags));
        }
    }
}
