//! Task structure and related types for the scheduler
//!
//! Each task represents a schedulable unit with its own:
//! - Kernel stack (for syscalls and interrupts)
//! - Page table (address space)
//! - Saved context (registers)
//! - IPC state (message passing)

use crate::mm::PhysAddr;

/// Maximum number of tasks in the system
pub const MAX_TASKS: usize = 64;

/// Maximum number of file descriptors per task
pub const MAX_FDS: usize = 32;

/// Console server task ID (well-known, created first after idle)
pub const CONSOLE_SERVER_TID: TaskId = TaskId(1);

/// File descriptor kind
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdKind {
    /// Not in use
    None,
    /// Console (stdin/stdout/stderr)
    Console,
    /// Pipe (future)
    Pipe,
    /// VFS-managed file (future)
    File,
}

/// File descriptor flags
#[derive(Debug, Clone, Copy)]
pub struct FdFlags {
    pub readable: bool,
    pub writable: bool,
}

impl FdFlags {
    pub const fn read_only() -> Self {
        Self { readable: true, writable: false }
    }
    pub const fn write_only() -> Self {
        Self { readable: false, writable: true }
    }
    pub const fn read_write() -> Self {
        Self { readable: true, writable: true }
    }
}

/// File descriptor entry
#[derive(Debug, Clone, Copy)]
pub struct FileDescriptor {
    pub kind: FdKind,
    pub flags: FdFlags,
    /// Server task ID (for IPC-based I/O)
    pub server: TaskId,
    /// Server-side handle (vnode, pipe id, etc.)
    pub handle: u64,
}

impl FileDescriptor {
    pub const fn empty() -> Self {
        Self {
            kind: FdKind::None,
            flags: FdFlags { readable: false, writable: false },
            server: TaskId(0),
            handle: 0,
        }
    }

    pub const fn console_stdin() -> Self {
        Self {
            kind: FdKind::Console,
            flags: FdFlags::read_only(),
            server: CONSOLE_SERVER_TID,
            handle: 0,
        }
    }

    pub const fn console_stdout() -> Self {
        Self {
            kind: FdKind::Console,
            flags: FdFlags::write_only(),
            server: CONSOLE_SERVER_TID,
            handle: 1,
        }
    }

    pub const fn console_stderr() -> Self {
        Self {
            kind: FdKind::Console,
            flags: FdFlags::write_only(),
            server: CONSOLE_SERVER_TID,
            handle: 2,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.kind != FdKind::None
    }
}

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

    /// Special value meaning "any task" for receive operations
    pub const ANY: TaskId = TaskId(usize::MAX);

    /// Check if this is the "any" sentinel value
    pub const fn is_any(&self) -> bool {
        self.0 == usize::MAX
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
    /// Task is blocked waiting for receiver to accept message
    SendBlocked = 3,
    /// Task is blocked waiting for a sender
    RecvBlocked = 4,
    /// Task is blocked waiting for reply (after sys_call)
    ReplyBlocked = 5,
    /// Task has terminated
    Terminated = 6,
}

/// IPC Message structure
///
/// Messages are small (fit in registers) for fast path, with optional
/// buffer pointer for larger data transfers.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Message {
    /// Message type/opcode (e.g., MSG_WRITE, MSG_EXIT)
    pub tag: u64,
    /// 4 words of inline data (32 bytes)
    pub data: [u64; 4],
}

impl Message {
    /// Create an empty message
    pub const fn empty() -> Self {
        Self {
            tag: 0,
            data: [0; 4],
        }
    }

    /// Create a message with tag and data
    pub const fn new(tag: u64, data: [u64; 4]) -> Self {
        Self { tag, data }
    }
}

/// IPC state for a task
#[derive(Debug, Clone, Copy)]
pub struct IpcState {
    /// Head of queue of tasks waiting to send to this task
    pub sender_queue_head: Option<TaskId>,
    /// Tail of queue of tasks waiting to send to this task
    pub sender_queue_tail: Option<TaskId>,

    /// Link for being in another task's sender queue
    pub sender_next: Option<TaskId>,

    /// Task we're waiting for a reply from (for sys_call)
    pub reply_to: Option<TaskId>,

    /// Task that called us (for sys_reply)
    pub caller: Option<TaskId>,

    /// Source task ID filter for receive (-1 = any)
    pub recv_from: Option<TaskId>,

    /// Pending message (when sender is blocked or message received)
    pub pending_msg: Message,
}

impl IpcState {
    /// Create empty IPC state
    pub const fn empty() -> Self {
        Self {
            sender_queue_head: None,
            sender_queue_tail: None,
            sender_next: None,
            reply_to: None,
            caller: None,
            recv_from: None,
            pending_msg: Message::empty(),
        }
    }
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
    /// IPC state (message passing)
    pub ipc: IpcState,
    /// File descriptor table
    pub fds: [FileDescriptor; MAX_FDS],
}

impl Task {
    /// Create a new uninitialized task slot
    pub const fn empty() -> Self {
        const EMPTY_FD: FileDescriptor = FileDescriptor::empty();
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
            ipc: IpcState::empty(),
            fds: [EMPTY_FD; MAX_FDS],
        }
    }

    /// Initialize standard file descriptors (stdin, stdout, stderr)
    /// Call this when creating a user task
    pub fn init_stdio(&mut self) {
        self.fds[0] = FileDescriptor::console_stdin();
        self.fds[1] = FileDescriptor::console_stdout();
        self.fds[2] = FileDescriptor::console_stderr();
    }

    /// Get a file descriptor by number
    pub fn get_fd(&self, fd: usize) -> Option<&FileDescriptor> {
        if fd < MAX_FDS && self.fds[fd].is_valid() {
            Some(&self.fds[fd])
        } else {
            None
        }
    }

    /// Allocate a new file descriptor, returns the fd number
    pub fn alloc_fd(&mut self) -> Option<usize> {
        for i in 0..MAX_FDS {
            if !self.fds[i].is_valid() {
                return Some(i);
            }
        }
        None
    }

    /// Close a file descriptor
    pub fn close_fd(&mut self, fd: usize) -> bool {
        if fd < MAX_FDS && self.fds[fd].is_valid() {
            self.fds[fd] = FileDescriptor::empty();
            true
        } else {
            false
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

/// Add a task to another task's sender queue
///
/// # Safety
/// Caller must ensure task IDs are valid and not already in a queue.
pub unsafe fn enqueue_sender(receiver_id: TaskId, sender_id: TaskId) {
    let receiver = &mut TASKS[receiver_id.0];
    let sender = &mut TASKS[sender_id.0];

    sender.ipc.sender_next = None;

    if let Some(tail_id) = receiver.ipc.sender_queue_tail {
        TASKS[tail_id.0].ipc.sender_next = Some(sender_id);
        receiver.ipc.sender_queue_tail = Some(sender_id);
    } else {
        // Queue was empty
        receiver.ipc.sender_queue_head = Some(sender_id);
        receiver.ipc.sender_queue_tail = Some(sender_id);
    }
}

/// Remove and return the first task from a task's sender queue
///
/// # Safety
/// Caller must ensure task ID is valid.
pub unsafe fn dequeue_sender(receiver_id: TaskId) -> Option<TaskId> {
    let receiver = &mut TASKS[receiver_id.0];

    if let Some(head_id) = receiver.ipc.sender_queue_head {
        let head = &mut TASKS[head_id.0];
        receiver.ipc.sender_queue_head = head.ipc.sender_next;
        head.ipc.sender_next = None;

        if receiver.ipc.sender_queue_head.is_none() {
            receiver.ipc.sender_queue_tail = None;
        }
        Some(head_id)
    } else {
        None
    }
}

/// Remove a specific task from a receiver's sender queue
///
/// Returns true if the task was found and removed.
///
/// # Safety
/// Caller must ensure task IDs are valid.
pub unsafe fn remove_from_sender_queue(receiver_id: TaskId, sender_id: TaskId) -> bool {
    let receiver = &mut TASKS[receiver_id.0];

    let mut prev: Option<TaskId> = None;
    let mut current = receiver.ipc.sender_queue_head;

    while let Some(curr_id) = current {
        if curr_id == sender_id {
            let curr_task = &mut TASKS[curr_id.0];
            let next = curr_task.ipc.sender_next;
            curr_task.ipc.sender_next = None;

            if let Some(prev_id) = prev {
                TASKS[prev_id.0].ipc.sender_next = next;
            } else {
                receiver.ipc.sender_queue_head = next;
            }

            if receiver.ipc.sender_queue_tail == Some(sender_id) {
                receiver.ipc.sender_queue_tail = prev;
            }
            return true;
        }
        prev = current;
        current = TASKS[curr_id.0].ipc.sender_next;
    }
    false
}

/// Find a sender in the queue matching the filter (or any if filter is None)
///
/// # Safety
/// Caller must ensure task ID is valid.
pub unsafe fn find_sender(receiver_id: TaskId, from_filter: Option<TaskId>) -> Option<TaskId> {
    let receiver = &TASKS[receiver_id.0];
    let mut current = receiver.ipc.sender_queue_head;

    while let Some(curr_id) = current {
        // If no filter or filter matches, return this sender
        if from_filter.is_none() || from_filter == Some(curr_id) {
            return Some(curr_id);
        }
        current = TASKS[curr_id.0].ipc.sender_next;
    }
    None
}
