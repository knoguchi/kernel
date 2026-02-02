//! Task structure and related types for the scheduler
//!
//! Each task represents a schedulable unit with its own:
//! - Kernel stack (for syscalls and interrupts)
//! - Page table (address space)
//! - Saved context (registers)
//! - IPC state (message passing)

use crate::mm::PhysAddr;
use crate::mm::frame::{alloc_frame, free_frame};
use crate::mm::address_space::AddressSpace;
use crate::mmap::MmapState;
use alloc::vec::Vec;

/// Maximum number of tasks in the system
pub const MAX_TASKS: usize = 64;

/// Maximum number of file descriptors per task
pub const MAX_FDS: usize = 32;

/// Maximum path length
pub const MAX_PATH_LEN: usize = 64;

/// Default heap start address (after code/data)
pub const DEFAULT_HEAP_START: usize = 0x0010_0000;  // 1MB

/// Console server task ID (well-known, created first after idle)
pub const CONSOLE_SERVER_TID: TaskId = TaskId(1);

/// File descriptor kind
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdKind {
    /// Not in use
    None,
    /// Console (stdin/stdout/stderr)
    Console,
    /// Pipe read end
    PipeRead,
    /// Pipe write end
    PipeWrite,
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

/// Kernel stack size per task (128KB - needs to be large due to AddressSpace struct ~32KB)
pub const KERNEL_STACK_SIZE: usize = 128 * 1024;

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

/// Pending syscall that needs IPC reply to complete
#[derive(Debug, Clone, Copy)]
pub enum PendingSyscall {
    /// No pending syscall
    None,
    /// Pipe create: waiting for pipeserv to return pipe_id
    /// Reply will allocate fds and return (read_fd, write_fd)
    PipeCreate,
    /// Pipe read: waiting for pipeserv to fill SHM buffer
    PipeRead {
        /// User buffer address to copy data to
        user_buf: usize,
        /// Maximum bytes to read
        max_len: usize,
        /// SHM ID for data transfer
        shm_id: usize,
    },
    /// Pipe write: waiting for pipeserv to consume SHM buffer
    PipeWrite {
        /// SHM ID for data transfer (needs cleanup)
        shm_id: usize,
    },
    /// Pipe close: waiting for pipeserv acknowledgment
    PipeClose,
    /// VFS open: waiting for VFS to return vnode handle
    VfsOpen {
        /// Pre-allocated fd number
        fd: usize,
        /// Open flags (O_RDONLY, O_WRONLY, etc.)
        flags: u32,
        /// SHM ID containing path (needs cleanup)
        shm_id: usize,
    },
    /// VFS stat: waiting for VFS to return file info
    VfsStat {
        /// User buffer for stat structure
        statbuf: usize,
    },
    /// VFS getdents: waiting for VFS to fill directory entries
    VfsGetdents {
        /// User buffer for dirent64 structures
        buf: usize,
        /// Buffer size
        count: usize,
        /// SHM ID for data transfer
        shm_id: usize,
    },
    /// VFS read: waiting for VFS to fill SHM buffer with file data
    VfsRead {
        /// User buffer address to copy data to
        user_buf: usize,
        /// Maximum bytes to read
        max_len: usize,
        /// SHM ID for data transfer
        shm_id: usize,
    },
    /// VFS write: waiting for VFS to consume SHM buffer
    VfsWrite {
        /// SHM ID for data transfer (needs cleanup)
        shm_id: usize,
    },
    /// Execve stage 1: waiting for VFS to open the executable file
    ExecveOpen {
        /// SHM ID containing path (needs cleanup)
        shm_id: usize,
    },
    /// Execve stage 2: waiting for VFS to read the executable file contents
    ExecveRead {
        /// VFS vnode handle for the executable
        vnode: u64,
        /// SHM ID for file data transfer
        shm_id: usize,
    },
}

impl PendingSyscall {
    pub const fn is_none(&self) -> bool {
        matches!(self, PendingSyscall::None)
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
    /// Task is blocked waiting for an IRQ
    IrqBlocked = 7,
    /// Task is blocked waiting for notification bits
    NotifyBlocked = 8,
    /// Task is blocked waiting for pipe data
    PipeBlocked = 9,
    /// Task is blocked waiting for child to exit (waitpid)
    WaitBlocked = 10,
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
    pub addr_space: Option<AddressSpace>,
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
    /// Pending notification bits (set by notify())
    pub notify_pending: u64,
    /// Notification bits the task is waiting for
    pub notify_waiting: u64,
    /// Pending syscall waiting for IPC reply to complete
    pub pending_syscall: PendingSyscall,
    /// Current working directory (null-terminated)
    pub cwd: [u8; MAX_PATH_LEN],
    /// Parent task ID (None for init and system tasks)
    pub parent: Option<TaskId>,
    /// Current heap break (end of data segment)
    pub heap_brk: usize,
    /// Exit code (set when task terminates)
    pub exit_code: i32,
    /// Tasks waiting for this task to exit (for waitpid)
    pub wait_queue: Option<TaskId>,
    /// Memory-mapped regions state
    pub mmap_state: MmapState,
    /// Signal mask (blocked signals, bitmask)
    pub signal_mask: u64,
    /// Pending signals (bitmask)
    pub signal_pending: u64,
    /// Signal handlers (SIG_DFL=0, SIG_IGN=1, or handler address)
    pub signal_handlers: [u64; 32],
}

impl Task {
    /// Create a new uninitialized task slot
    pub const fn empty() -> Self {
        const EMPTY_FD: FileDescriptor = FileDescriptor::empty();
        // Default cwd is "/" (root)
        const DEFAULT_CWD: [u8; MAX_PATH_LEN] = {
            let mut cwd = [0u8; MAX_PATH_LEN];
            cwd[0] = b'/';
            cwd
        };
        Self {
            id: TaskId(0),
            state: TaskState::Free,
            context_ptr: core::ptr::null_mut(),
            kernel_stack_base: PhysAddr(0),
            kernel_stack_top: 0,
            addr_space: None,
            entry_point: 0,
            time_slice: DEFAULT_TIME_SLICE,
            next: None,
            name: [0; 16],
            ipc: IpcState::empty(),
            fds: [EMPTY_FD; MAX_FDS],
            notify_pending: 0,
            notify_waiting: 0,
            pending_syscall: PendingSyscall::None,
            cwd: DEFAULT_CWD,
            parent: None,
            heap_brk: DEFAULT_HEAP_START,
            exit_code: 0,
            wait_queue: None,
            mmap_state: MmapState::new(),
            signal_mask: 0,
            signal_pending: 0,
            signal_handlers: [0; 32],
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

/// Unblock all tasks waiting to send to a task that is exiting
///
/// When a task exits, any tasks in SendBlocked waiting to send to it
/// need to be woken up with an error.
///
/// # Safety
/// Caller must ensure exiting_task_id is valid.
pub unsafe fn wake_blocked_senders(exiting_task_id: TaskId) {
    use crate::exception::ExceptionContext;
    use super::enqueue_task;

    let exiting_task = &mut TASKS[exiting_task_id.0];

    // Process all tasks in the sender queue
    while let Some(sender_id) = exiting_task.ipc.sender_queue_head {
        let sender = &mut TASKS[sender_id.0];
        exiting_task.ipc.sender_queue_head = sender.ipc.sender_next;
        sender.ipc.sender_next = None;

        // Set error return value in sender's saved context
        if sender.state == TaskState::SendBlocked || sender.state == TaskState::ReplyBlocked {
            let sender_ctx = sender.kernel_stack_top as *mut ExceptionContext;
            if !sender_ctx.is_null() {
                // Return error code in x0 (IPC_ERR_TASK_TERMINATED = -10)
                (*sender_ctx).gpr[0] = (-10i64) as u64;
            }
            sender.state = TaskState::Ready;
            enqueue_task(sender_id);
        }
    }
    exiting_task.ipc.sender_queue_tail = None;

    // Also check if any task is in ReplyBlocked waiting for a reply from this task
    for i in 0..MAX_TASKS {
        let task = &mut TASKS[i];
        if task.state == TaskState::ReplyBlocked && task.ipc.reply_to == Some(exiting_task_id) {
            let task_ctx = task.kernel_stack_top as *mut ExceptionContext;
            if !task_ctx.is_null() {
                (*task_ctx).gpr[0] = (-10i64) as u64;
            }
            task.state = TaskState::Ready;
            enqueue_task(TaskId(i));
        }
    }
}

/// Allocate physical frames for a kernel stack (KERNEL_STACK_SIZE)
///
/// Returns the physical address of the base of the allocated stack,
/// or None if allocation fails.
pub fn alloc_kernel_stack_frames() -> Option<PhysAddr> {
    let stack_pages = KERNEL_STACK_SIZE / crate::mm::frame::PAGE_SIZE;
    let mut allocated_frames = Vec::new(); // Use Vec to manage allocated frames for cleanup

    for _i in 0..stack_pages {
        if let Some(frame) = alloc_frame() {
            allocated_frames.push(frame);
        } else {
            // Allocation failed, free all previously allocated frames
            for frame in allocated_frames {
                free_frame(frame);
            }
            return None;
        }
    }
    // Return the base address (first frame)
    allocated_frames.first().copied()
}

/// Free physical frames previously allocated for a kernel stack.
///
/// # Arguments
/// * `stack_base` - The physical address of the base of the kernel stack.
pub fn free_kernel_stack_frames(stack_base: PhysAddr) {
    let stack_pages = KERNEL_STACK_SIZE / crate::mm::frame::PAGE_SIZE;
    for i in 0..stack_pages {
        free_frame(PhysAddr(stack_base.0 + i * crate::mm::frame::PAGE_SIZE));
    }
}
