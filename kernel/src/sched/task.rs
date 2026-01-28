//! Task structure and related types for the scheduler
//!
//! Each task represents a schedulable unit with its own:
//! - Kernel stack (for syscalls and interrupts)
//! - Page table (address space)
//! - Saved context (registers)

use crate::mm::PhysAddr;

/// Maximum number of tasks in the system
pub const MAX_TASKS: usize = 64;

/// Kernel stack size per task (16KB)
pub const KERNEL_STACK_SIZE: usize = 16 * 1024;

/// Default time slice in timer ticks
pub const DEFAULT_TIME_SLICE: u32 = 1;

/// Task identifier (index into task table)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskId(pub usize);

impl TaskId {
    pub const fn new(id: usize) -> Self {
        Self(id)
    }

    pub const fn as_usize(&self) -> usize {
        self.0
    }
}

/// Task state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TaskState {
    /// Task is not allocated
    Free = 0,
    /// Task is ready to run
    Ready = 1,
    /// Task is currently running
    Running = 2,
    /// Task is blocked (waiting for I/O, IPC, etc.)
    Blocked = 3,
    /// Task has terminated
    Terminated = 4,
}

/// Saved CPU context for context switching
/// This is separate from ExceptionContext and contains callee-saved registers
#[repr(C)]
pub struct TaskContext {
    // Callee-saved registers (x19-x30)
    pub x19: u64,
    pub x20: u64,
    pub x21: u64,
    pub x22: u64,
    pub x23: u64,
    pub x24: u64,
    pub x25: u64,
    pub x26: u64,
    pub x27: u64,
    pub x28: u64,
    pub x29: u64, // Frame pointer
    pub x30: u64, // Link register (return address)
    // Stack pointer saved separately during switch
}

impl TaskContext {
    pub const fn new() -> Self {
        Self {
            x19: 0, x20: 0, x21: 0, x22: 0,
            x23: 0, x24: 0, x25: 0, x26: 0,
            x27: 0, x28: 0, x29: 0, x30: 0,
        }
    }
}

/// Task Control Block
#[repr(C)]
pub struct Task {
    /// Task identifier
    pub id: TaskId,
    /// Current state
    pub state: TaskState,
    /// Pointer to saved context on kernel stack
    pub context_ptr: *mut TaskContext,
    /// Physical address of kernel stack base (bottom of stack)
    pub kernel_stack_base: PhysAddr,
    /// Top of kernel stack (initial SP value)
    pub kernel_stack_top: usize,
    /// Page table physical address (TTBR0_EL1)
    pub page_table: PhysAddr,
    /// Entry point address (for new tasks)
    pub entry_point: usize,
    /// Remaining time slice (decremented each tick)
    pub time_slice: u32,
    /// Link to next task in ready queue
    pub next: Option<TaskId>,
    /// Task name for debugging
    pub name: [u8; 16],
}

impl Task {
    /// Create a new uninitialized task slot
    pub const fn empty() -> Self {
        Self {
            id: TaskId(0),
            state: TaskState::Free,
            context_ptr: core::ptr::null_mut(),
            kernel_stack_base: PhysAddr(0),
            kernel_stack_top: 0,
            page_table: PhysAddr(0),
            entry_point: 0,
            time_slice: DEFAULT_TIME_SLICE,
            next: None,
            name: [0; 16],
        }
    }

    /// Set the task name
    pub fn set_name(&mut self, name: &str) {
        let bytes = name.as_bytes();
        let len = bytes.len().min(15);
        self.name[..len].copy_from_slice(&bytes[..len]);
        self.name[len] = 0;
    }

    /// Get the task name as a string
    pub fn name_str(&self) -> &str {
        let len = self.name.iter().position(|&c| c == 0).unwrap_or(16);
        // Safety: We only store valid UTF-8 strings
        unsafe { core::str::from_utf8_unchecked(&self.name[..len]) }
    }
}

/// Global task table
pub static mut TASKS: [Task; MAX_TASKS] = {
    const EMPTY: Task = Task::empty();
    [EMPTY; MAX_TASKS]
};

/// Find a free task slot
pub fn find_free_slot() -> Option<TaskId> {
    unsafe {
        for (i, task) in TASKS.iter().enumerate() {
            if task.state == TaskState::Free {
                return Some(TaskId(i));
            }
        }
    }
    None
}

/// Get a reference to a task by ID
pub fn get_task(id: TaskId) -> Option<&'static Task> {
    if id.0 < MAX_TASKS {
        unsafe { Some(&TASKS[id.0]) }
    } else {
        None
    }
}

/// Get a mutable reference to a task by ID
pub fn get_task_mut(id: TaskId) -> Option<&'static mut Task> {
    if id.0 < MAX_TASKS {
        unsafe { Some(&mut TASKS[id.0]) }
    } else {
        None
    }
}
