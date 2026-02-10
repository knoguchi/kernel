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

pub use task::{TaskId, TaskState, Message, KERNEL_STACK_SIZE, FileDescriptor, MAX_FDS, PendingSyscall, MAX_PATH_LEN};

use crate::mm::{self, PhysAddr, AddressSpace, PageFlags, PAGE_SIZE};
use crate::exception::ExceptionContext;
use crate::elf::{ElfFile, PF_W, PF_X};
use task::{TASKS, DEFAULT_TIME_SLICE};

/// User virtual address space constants
/// User code is mapped at 0x00100000 (1MB) to match user.ld linker script
const USER_CODE_VADDR_BASE: usize = 0x0010_0000;  // 1MB - matches user.ld
const USER_STACK_VADDR_BASE: usize = 0x0020_0000; // 2MB (separate 2MB block)

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

                // Only decrement time slice for running tasks (not blocked ones)
                if task.state == TaskState::Running {
                    if task.time_slice > 0 {
                        task.time_slice -= 1;
                    }

                    // Reschedule if time slice expired and there are other ready tasks
                    if task.time_slice == 0 && self.ready_head.is_some() {
                        return true;
                    }
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
        // (but only if it was Running - blocked tasks stay blocked)
        // Note: idle task (0) is never put in the ready queue - it runs when queue is empty
        if let Some(id) = current_id {
            let task = &mut TASKS[id.0];
            // Store the SP that points to the exception context
            task.kernel_stack_top = ctx as *const _ as usize;

            // Only re-enqueue if the task was running (not IPC blocked)
            // Never enqueue idle task - it's the fallback when queue is empty
            if task.state == TaskState::Running && id != self.idle_task {
                task.state = TaskState::Ready;
                task.time_slice = DEFAULT_TIME_SLICE;
                self.enqueue(id);
            }
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
            if let Some(ref addr_space) = next_task.addr_space {
                let ttbr0 = addr_space.ttbr0();
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

            // Complete pending Wait4 syscall by writing exit status to wstatus and reaping child.
            // This must happen AFTER TTBR0 is loaded so we can write to the task's user memory.
            if let task::PendingSyscall::Wait4 { wstatus, exit_status, child_id } = next_task.pending_syscall {
                if wstatus != 0 {
                    // Linux encodes exit code as (exit_code & 0xff) << 8
                    let status = ((exit_status & 0xff) << 8) as i32;
                    core::ptr::write_volatile(wstatus as *mut i32, status);
                }
                // Reap the child now that wait4 is completing
                if child_id != 0 && child_id < task::MAX_TASKS {
                    let child = &mut TASKS[child_id];
                    if child.state == TaskState::Terminated {
                        child.state = TaskState::Free;
                        child.parent = None;
                    }
                }
                next_task.pending_syscall = task::PendingSyscall::None;
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

    /// Context switch when current task is blocking (IPC)
    ///
    /// The caller has already set the current task's state to a blocked state.
    /// We save the context and switch to the next ready task without
    /// re-enqueuing the current task.
    ///
    /// # Safety
    /// Must be called from an exception handler with ctx pointing to the saved context.
    pub unsafe fn context_switch_blocking(&mut self, ctx: &mut ExceptionContext) {
        let current_id = self.current;

        // Save current task's context (but don't re-enqueue - it's blocked)
        if let Some(id) = current_id {
            let task = &mut TASKS[id.0];
            task.kernel_stack_top = ctx as *const _ as usize;
            // State is already set by caller (SendBlocked, RecvBlocked, etc.)
        }

        // Get next task to run
        let next_id = self.dequeue().unwrap_or(self.idle_task);

        let next_task = &mut TASKS[next_id.0];
        next_task.state = TaskState::Running;
        next_task.time_slice = DEFAULT_TIME_SLICE;
        self.current = Some(next_id);
        self.switch_count += 1;

        // Always reload TTBR0 from the task's addr_space.
        // This is important because the task's address space might have been
        // replaced (e.g., by execve) since we last ran it. Even if we're
        // "switching" to the same task, the address space could be different.
        if let Some(ref addr_space) = next_task.addr_space {
            let ttbr0 = addr_space.ttbr0();
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

        // Complete pending Wait4 syscall by writing exit status to wstatus and reaping child.
        // This must happen AFTER TTBR0 is loaded so we can write to the task's user memory.
        if let task::PendingSyscall::Wait4 { wstatus, exit_status, child_id } = next_task.pending_syscall {
            crate::println!("[ctx_switch_blocking] task={} writing wstatus=0x{:x} at 0x{:x} child={}",
                next_id.0, ((exit_status & 0xff) << 8) as u32, wstatus, child_id);
            // Debug: print the saved context that will be restored
            let saved_ctx = next_task.kernel_stack_top as *const ExceptionContext;
            if !saved_ctx.is_null() {
                crate::println!("[ctx_switch_blocking] restoring context at 0x{:x}: elr=0x{:x} sp=0x{:x}",
                    next_task.kernel_stack_top, (*saved_ctx).elr, (*saved_ctx).sp);
                crate::println!("[ctx_switch_blocking] saved x0=0x{:x} x1=0x{:x} x2=0x{:x} x30=0x{:x}",
                    (*saved_ctx).gpr[0], (*saved_ctx).gpr[1], (*saved_ctx).gpr[2], (*saved_ctx).gpr[30]);
            }
            if wstatus != 0 {
                // Linux encodes exit code as (exit_code & 0xff) << 8
                let status = ((exit_status & 0xff) << 8) as i32;
                core::ptr::write_volatile(wstatus as *mut i32, status);
            }
            // Reap the child now that wait4 is completing
            if child_id != 0 && child_id < task::MAX_TASKS {
                let child = &mut TASKS[child_id];
                if child.state == TaskState::Terminated {
                    child.state = TaskState::Free;
                    child.parent = None;
                    crate::println!("[ctx_switch_blocking] reaped child {}", child_id);
                }
            }
            next_task.pending_syscall = task::PendingSyscall::None;
        }

        // Switch to new task's stack (only needed when switching to a different task)
        if current_id != Some(next_id) {
            let new_sp = next_task.kernel_stack_top;
            switch_context_and_restore(new_sp);
        }
    }

    /// Terminate the current task
    pub fn exit_current(&mut self, exit_code: i32) {
        if let Some(current_id) = self.current {
            unsafe {
                let parent_id_opt = TASKS[current_id.0].parent;

                // Wake up any tasks waiting to send to or waiting for reply from this task
                task::wake_blocked_senders(current_id);

                // Clean up SHM regions owned by this task
                crate::shm::cleanup_task_shm(current_id);

                let task = &mut TASKS[current_id.0];

                // Drop the address space to free all its data blocks
                // (code, stack, and any other 2MB blocks)
                if let Some(addr_space) = task.addr_space.take() {
                    drop(addr_space);
                }

                task.exit_code = exit_code;

                // Signal parent and wake if waiting (WaitBlocked)
                if let Some(parent_id) = parent_id_opt {
                    let parent = &mut TASKS[parent_id.0];

                    if parent.state == TaskState::WaitBlocked {
                        // Parent was already waiting - wait4 will return the child info.
                        // Don't set SIGCHLD since wait4 provides all the info.
                        // Parent was blocked in wait4. Set up the return value.
                        // The parent's saved ExceptionContext is at kernel_stack_top.
                        crate::println!("[exit_current] child {} exit, parent {} kernel_stack_top=0x{:x}",
                            current_id.0, parent_id.0, parent.kernel_stack_top);
                        let parent_ctx = parent.kernel_stack_top as *mut crate::exception::ExceptionContext;
                        if !parent_ctx.is_null() {
                            // Debug: print parent's saved context before modifying
                            crate::println!("[exit_current] parent ctx: elr=0x{:x} sp=0x{:x}",
                                (*parent_ctx).elr, (*parent_ctx).sp);
                            crate::println!("[exit_current] parent ctx: x0=0x{:x} x1=0x{:x} x2=0x{:x} x30=0x{:x}",
                                (*parent_ctx).gpr[0], (*parent_ctx).gpr[1], (*parent_ctx).gpr[2], (*parent_ctx).gpr[30]);
                            // Set return value (x0) = child's pid
                            crate::println!("[exit_current] setting parent {} gpr[0] = {} (was 0x{:x})",
                                parent_id.0, current_id.0, (*parent_ctx).gpr[0]);
                            (*parent_ctx).gpr[0] = current_id.0 as u64;
                        }

                        // Update the pending syscall with the exit status and child ID so that
                        // context_switch can write wstatus and reap the child
                        if let task::PendingSyscall::Wait4 { ref mut exit_status, ref mut child_id, .. } = parent.pending_syscall {
                            *exit_status = exit_code;
                            *child_id = current_id.0;
                        }

                        // Leave child as Terminated (zombie) for now.
                        // It will be reaped by context_switch after writing wstatus.
                        // This allows SIGCHLD handler to also call waitpid and see the zombie.
                        task.state = TaskState::Terminated;

                        parent.state = TaskState::Ready;
                        enqueue_task(parent_id);
                    } else {
                        // Parent is not waiting - set SIGCHLD pending and leave child as zombie
                        const SIGCHLD_BIT: u64 = 1 << 16; // SIGCHLD = 17, bit = 17-1 = 16
                        parent.signal_pending |= SIGCHLD_BIT;
                        task.state = TaskState::Terminated;
                    }
                } else {
                    // No parent - just mark as free
                    task.state = TaskState::Free;
                }

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
    idle.addr_space = None; // Idle task initially runs in kernel's address space
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
        task.addr_space = None; // Kernel tasks initially run in kernel's address space
        task.entry_point = entry_addr;
        task.time_slice = DEFAULT_TIME_SLICE;
        task.next = None;
        task.ipc = task::IpcState::empty(); // Reset IPC state for reused slots

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

/// 2MB block size for page mapping
const BLOCK_SIZE_2MB: usize = 2 * 1024 * 1024;

/// Create a user-mode task that runs in EL0
///
/// # Arguments
/// * `name` - Task name for debugging
/// * `code_paddr` - Physical address of the user code
/// * `code_size` - Size of the user code in bytes
///
/// # Returns
/// The TaskId if successful, None if allocation failed
pub fn create_user_task(name: &str, code_paddr: PhysAddr, code_size: usize) -> Option<TaskId> {
    let task_id = task::find_free_slot()?;

    // Create user address space (includes kernel mappings for syscalls)
    let mut addr_space = unsafe { AddressSpace::new_for_user()? };

    // For 2MB block mapping, we need to work with 2MB-aligned physical addresses.
    // Allocate enough frames to cover a 2MB region and copy user code to the start.
    // This is wasteful but necessary with 2MB granularity.
    //
    // Strategy: Allocate multiple 4KB frames to form a 2MB region.
    // For simplicity, we'll just allocate frames starting from the first one
    // and use the 2MB-aligned base of that first frame.

    // Allocate the first frame
    let first_frame = mm::alloc_frame()?;

    // Calculate the 2MB-aligned base containing this frame
    let phys_base_2mb = PhysAddr(first_frame.0 & !(BLOCK_SIZE_2MB - 1));
    let offset_in_block = first_frame.0 - phys_base_2mb.0;

    // For a proper solution, we'd need to ensure we own all pages in the 2MB block.
    // For now, we'll copy user code to the frame we allocated and use its offset.

    unsafe {
        // Zero the frame first
        core::ptr::write_bytes(first_frame.0 as *mut u8, 0, mm::frame::PAGE_SIZE);
        // Copy user code to this frame
        core::ptr::copy_nonoverlapping(
            code_paddr.0 as *const u8,
            first_frame.0 as *mut u8,
            code_size.min(mm::frame::PAGE_SIZE),
        );
    }

    // Map the 2MB block at virtual address 0x00000000
    // The user code will be at virtual offset_in_block (matching physical layout)
    unsafe {
        if !addr_space.map_2mb(USER_CODE_VADDR_BASE, phys_base_2mb, PageFlags::user_code()) {
            return None;
        }
    }

    // Entry point is at the offset within the 2MB block
    // Virtual offset_in_block maps to physical first_frame
    let user_entry_point = USER_CODE_VADDR_BASE + offset_in_block;

    // Allocate user stack at start of a 2MB block.
    // This ensures each task has its own exclusive 2MB stack region.
    let stack_frame = mm::frame::alloc_frames_at_2mb_boundary(1)?;
    let stack_phys_base_2mb = stack_frame; // first_frame IS the 2MB block base

    unsafe {
        // Zero the entire 2MB stack block
        core::ptr::write_bytes(stack_frame.0 as *mut u8, 0, BLOCK_SIZE_2MB);
        if !addr_space.map_2mb(USER_STACK_VADDR_BASE, stack_phys_base_2mb, PageFlags::user_data()) {
            return None;
        }
    }

    // Stack grows down from top of 2MB region
    let user_stack_top = USER_STACK_VADDR_BASE + BLOCK_SIZE_2MB - 16;

    // Allocate kernel stack for syscalls/interrupts (4 pages = 16KB)
    let stack_pages = KERNEL_STACK_SIZE / mm::frame::PAGE_SIZE;
    let mut kernel_stack_base = PhysAddr(0);

    for i in 0..stack_pages {
        if let Some(frame) = mm::alloc_frame() {
            if i == 0 {
                kernel_stack_base = frame;
            }
        } else {
            return None;
        }
    }

    unsafe {
        let task = &mut TASKS[task_id.0];
        task.id = task_id;
        task.state = TaskState::Ready;
        task.set_name(name);
        task.kernel_stack_base = kernel_stack_base;
        // Store the AddressSpace directly
        task.addr_space = Some(addr_space);
        task.entry_point = user_entry_point;
        task.time_slice = DEFAULT_TIME_SLICE;
        task.next = None;
        task.ipc = task::IpcState::empty(); // Reset IPC state for reused slots
        task.mmap_state = crate::mmap::MmapState::new(); // Reset mmap state
        task.init_stdio(); // Initialize stdin/stdout/stderr

        // Calculate kernel stack top (16-byte aligned)
        let kernel_stack_top = kernel_stack_base.0 + KERNEL_STACK_SIZE;

        // Set up a fake ExceptionContext at the top of the kernel stack
        // When we switch to this task, RESTORE_CONTEXT will pop this and ERET to EL0
        let ctx_addr = kernel_stack_top - EXCEPTION_CONTEXT_SIZE;
        let ctx = ctx_addr as *mut ExceptionContext;

        // Zero the context first
        core::ptr::write_bytes(ctx, 0, 1);

        // Set up the context for EL0 entry
        (*ctx).elr = user_entry_point as u64;  // Entry point in user space

        // SPSR for EL0t mode (user mode, thread stack pointer)
        // Bits: D=0, A=0, I=0, F=0, M[4:0]=0b00000 (EL0t)
        (*ctx).spsr = 0x000;  // EL0t with all interrupts enabled

        // User stack pointer
        (*ctx).sp = user_stack_top as u64;

        // The task's saved SP points to this fake context
        task.kernel_stack_top = ctx_addr;

        // Enqueue to ready queue
        SCHEDULER.enqueue(task_id);

    }

    Some(task_id)
}

/// Maximum number of code frames per user task (2MB max code size for BusyBox)
const MAX_CODE_FRAMES: usize = 512;

/// Create a user-mode task from an ELF binary
///
/// This function parses the ELF file, maps each PT_LOAD segment with
/// appropriate permissions, and sets up the task to start at the ELF entry point.
///
/// # Arguments
/// * `name` - Task name for debugging
/// * `elf_data` - Raw ELF file data
///
/// # Returns
/// The TaskId if successful, None if parsing or allocation failed
pub fn create_user_task_from_elf(name: &str, elf_data: &[u8]) -> Option<TaskId> {
    // Parse ELF header
    let elf = match ElfFile::parse(elf_data) {
        Ok(e) => e,
        Err(_e) => {
            return None;
        }
    };

    let task_id = task::find_free_slot()?;

    // Create user address space (includes kernel mappings for syscalls)
    let mut addr_space = unsafe { AddressSpace::new_for_user()? };

    // Collect info about all PT_LOAD segments to determine which 2MB blocks we need
    // Track which 2MB blocks need to be mapped and their combined flags
    // For simplicity with 2MB granularity, we'll use a single block for all user code
    // and copy all segments to the appropriate offsets within that block.

    // Find the range of all segments
    let mut min_vaddr = usize::MAX;
    let mut max_vaddr = 0usize;

    for phdr in elf.load_segments() {
        let vaddr = phdr.p_vaddr as usize;
        let memsz = phdr.p_memsz as usize;
        if memsz == 0 {
            continue;
        }
        min_vaddr = min_vaddr.min(vaddr);
        max_vaddr = max_vaddr.max(vaddr + memsz);
    }

    if min_vaddr == usize::MAX {
        // No segments to load
        return None;
    }

    // Calculate 2MB-aligned virtual address range
    // This is critical: even if code_size < 2MB, if the code spans a 2MB boundary,
    // we need to map multiple 2MB blocks
    let block_base = min_vaddr & !(BLOCK_SIZE_2MB - 1);
    let virt_end = (max_vaddr + BLOCK_SIZE_2MB - 1) & !(BLOCK_SIZE_2MB - 1);
    let num_2mb_blocks = (virt_end - block_base) / BLOCK_SIZE_2MB;

    // Check limits - we support up to 4 2MB blocks (8MB total)
    const MAX_CODE_2MB_BLOCKS: usize = 4;
    if num_2mb_blocks > MAX_CODE_2MB_BLOCKS {
        // Code too large
        return None;
    }

    // Calculate how many 4KB frames we need
    let num_frames = num_2mb_blocks * 512; // 512 pages per 2MB block

    // Allocate code frames at the START of a 2MB block.
    // Since ELFs are linked at virtual address 0 and we map virtual 0 to phys_base_2mb,
    // the code must be at the start of the physical block.
    let first_frame = mm::frame::alloc_frames_at_2mb_boundary(num_frames)?;
    let phys_base_2mb = first_frame; // first_frame IS the 2MB block base

    // Zero ALL allocated memory (ensures .bss is zeroed)
    unsafe {
        core::ptr::write_bytes(phys_base_2mb.0 as *mut u8, 0, num_2mb_blocks * BLOCK_SIZE_2MB);
    }

    // Copy all segments directly into the 2MB physical block
    // The segment at virtual address `vaddr` is placed at physical offset `vaddr - block_base`
    // since we'll map virtual block_base -> physical phys_base_2mb
    for phdr in elf.load_segments() {
        let vaddr = phdr.p_vaddr as usize;
        let filesz = phdr.p_filesz as usize;

        if filesz == 0 { // Empty segment
            continue;
        }

        // Get segment data from ELF
        let segment_data = elf.segment_data(phdr).ok()?;

        // Calculate destination physical address relative to the 2MB block base
        let offset_in_block = vaddr - block_base;
        let dest_paddr = phys_base_2mb.0 + offset_in_block;

        unsafe {
            core::ptr::copy_nonoverlapping(
                segment_data.as_ptr(),
                dest_paddr as *mut u8,
                filesz,
            );
            // .bss section (if memsz > filesz) is already zeroed by the initial memset
        }
    }

    // Determine page flags based on combined segment flags
    // If any segment is executable, we need execute permission
    // If any segment is writable, we need write permission
    // With 2MB granularity, we may need both R+W+X if segments are mixed
    // With 2MB granularity, we use RWX for all user code blocks.
    // The ELF segments may not properly mark .bss as writable, and user programs
    // need to write to global variables. Using RWX is less secure but necessary.
    let flags = PageFlags::user_code_data();

    // Map ALL 2MB code blocks at the correct virtual addresses
    // Linux binaries are typically linked at 0x400000 (4MB), not 0
    for block_idx in 0..num_2mb_blocks {
        let block_vaddr = block_base + block_idx * BLOCK_SIZE_2MB;
        let block_paddr = PhysAddr(phys_base_2mb.0 + block_idx * BLOCK_SIZE_2MB);
        unsafe {
            if !addr_space.map_2mb(block_vaddr, block_paddr, flags) {
                return None;
            }
        }
        // Track each code block for cleanup when address space is dropped
        addr_space.track_data_block(block_paddr);
    }

    // Allocate user stack at start of a 2MB block (just like code).
    // This ensures each task has its own exclusive 2MB stack region.
    let stack_frame = mm::frame::alloc_frames_at_2mb_boundary(1)?;
    let stack_phys_base_2mb = stack_frame; // first_frame IS the 2MB block base

    unsafe {
        // Zero the entire 2MB stack block
        core::ptr::write_bytes(stack_frame.0 as *mut u8, 0, BLOCK_SIZE_2MB);
        if !addr_space.map_2mb(USER_STACK_VADDR_BASE, stack_phys_base_2mb, PageFlags::user_data()) {
            return None;
        }
    }
    // Track stack block for cleanup
    addr_space.track_data_block(stack_phys_base_2mb);

    // Get the ELF entry point
    let user_entry_point = elf.entry_point() as usize;

    // Set up the user stack with Linux ABI (argc, argv, envp, auxv)
    // Stack layout (growing downward):
    // [top of 2MB] random_bytes(16) | "busybox\0" | padding | auxv[] | envp[] | argv[] | argc
    // SP points to argc

    let stack_virt_top = USER_STACK_VADDR_BASE + BLOCK_SIZE_2MB;
    let _stack_phys_top = stack_phys_base_2mb.0 + BLOCK_SIZE_2MB;

    // Calculate physical address from virtual offset
    let virt_to_phys = |vaddr: usize| -> usize {
        stack_phys_base_2mb.0 + (vaddr - USER_STACK_VADDR_BASE)
    };

    // Start from top of stack and work down
    let mut sp = stack_virt_top;

    unsafe {
        // 1. Random bytes at top (for AT_RANDOM) - 16 bytes
        sp -= 16;
        let random_vaddr = sp;
        let random_paddr = virt_to_phys(sp);
        // Use simple pseudo-random values (task_id based)
        let random_ptr = random_paddr as *mut u64;
        *random_ptr = 0xDEADBEEF12345678u64;
        *random_ptr.add(1) = 0xCAFEBABE87654321u64;

        // 2. Program name string "busybox"
        sp -= 16; // "busybox\0" padded to 16 bytes
        let prog_name_vaddr = sp;
        let prog_name_paddr = virt_to_phys(sp);
        // Use "sh" as argv[0] so BusyBox runs the shell applet
        let prog_name = b"sh\0";
        core::ptr::copy_nonoverlapping(prog_name.as_ptr(), prog_name_paddr as *mut u8, prog_name.len());

        // 3. Align to 16 bytes
        sp = sp & !15;

        // 4. Set up auxiliary vector (auxv)
        // Each entry is two u64s: type and value
        // Linux auxv types
        const AT_NULL: u64 = 0;
        const AT_PHDR: u64 = 3;    // Program header address
        const AT_PHENT: u64 = 4;   // Program header entry size
        const AT_PHNUM: u64 = 5;   // Number of program headers
        const AT_PAGESZ: u64 = 6;  // Page size
        const AT_ENTRY: u64 = 9;   // Entry point
        const AT_UID: u64 = 11;
        const AT_EUID: u64 = 12;
        const AT_GID: u64 = 13;
        const AT_EGID: u64 = 14;
        const AT_RANDOM: u64 = 25; // Random bytes pointer

        // Get ELF header info for auxv
        let phdr_addr = block_base + elf.header().e_phoff as usize;
        let phent = elf.header().e_phentsize as u64;
        let phnum = elf.header().e_phnum as u64;

        // Build auxv array - AT_NULL must be LAST (highest address after writing)
        // We write in reverse order, so AT_NULL at the end of array goes to highest address
        let auxv: [(u64, u64); 11] = [
            (AT_PHDR, phdr_addr as u64),
            (AT_PHENT, phent),
            (AT_PHNUM, phnum),
            (AT_PAGESZ, PAGE_SIZE as u64),
            (AT_ENTRY, user_entry_point as u64),
            (AT_UID, 0),
            (AT_EUID, 0),
            (AT_GID, 0),
            (AT_EGID, 0),
            (AT_RANDOM, random_vaddr as u64),
            (AT_NULL, 0),  // Must be last - terminates the auxv array
        ];

        // Write auxv (each entry is 16 bytes)
        for (at_type, at_val) in auxv.iter().rev() {
            sp -= 16;
            let ptr = virt_to_phys(sp) as *mut u64;
            *ptr = *at_type;
            *ptr.add(1) = *at_val;
        }

        // 5. envp[] = { NULL }
        sp -= 8;
        *(virt_to_phys(sp) as *mut u64) = 0;

        // 6. argv[] = { prog_name, NULL }
        sp -= 8;
        *(virt_to_phys(sp) as *mut u64) = 0; // NULL terminator
        sp -= 8;
        *(virt_to_phys(sp) as *mut u64) = prog_name_vaddr as u64;

        // 7. argc = 1
        sp -= 8;
        *(virt_to_phys(sp) as *mut u64) = 1;
    }

    // Final stack pointer points to argc
    let user_stack_top = sp;

    // Note: For Linux binaries (block_base >= 2MB), we don't pre-map heap.
    // musl will use mmap and brk to manage memory dynamically.
    // The mmap region starts at 0x100000 (MMAP_BASE) and mmap page fault
    // handler will allocate pages on demand.

    // Allocate kernel stack for syscalls/interrupts
    let stack_pages = KERNEL_STACK_SIZE / mm::frame::PAGE_SIZE;
    let mut kernel_stack_base = PhysAddr(0);

    for i in 0..stack_pages {
        if let Some(frame) = mm::alloc_frame() {
            if i == 0 {
                kernel_stack_base = frame;
            }
        } else {
            return None;
        }
    }

    unsafe {
        let task = &mut TASKS[task_id.0];
        task.id = task_id;
        task.state = TaskState::Ready;
        task.set_name(name);
        task.kernel_stack_base = kernel_stack_base;
        task.addr_space = Some(addr_space);
        task.entry_point = user_entry_point;
        task.time_slice = DEFAULT_TIME_SLICE;
        task.next = None;
        task.ipc = task::IpcState::empty(); // Reset IPC state for reused slots
        task.mmap_state = crate::mmap::MmapState::new(); // Reset mmap state
        // Set heap_brk to end of mapped 2MB blocks, but ensure it doesn't conflict with stack.
        // Stack is at USER_STACK_VADDR_BASE for 2MB. Heap must start after both code and stack.
        let heap_start_after_stack = USER_STACK_VADDR_BASE + BLOCK_SIZE_2MB;
        task.heap_brk = virt_end.max(heap_start_after_stack);
        task.init_stdio(); // Initialize stdin/stdout/stderr

        // Calculate kernel stack top (16-byte aligned)
        let kernel_stack_top = kernel_stack_base.0 + KERNEL_STACK_SIZE;

        // Set up a fake ExceptionContext at the top of the kernel stack
        let ctx_addr = kernel_stack_top - EXCEPTION_CONTEXT_SIZE;
        let ctx = ctx_addr as *mut ExceptionContext;

        // Zero the context first
        core::ptr::write_bytes(ctx, 0, 1);

        // Set up the context for EL0 entry
        (*ctx).elr = user_entry_point as u64;
        (*ctx).spsr = 0x000;  // EL0t with all interrupts enabled
        (*ctx).sp = user_stack_top as u64;

        // The task's saved SP points to this fake context
        task.kernel_stack_top = ctx_addr;

        // Enqueue to ready queue
        SCHEDULER.enqueue(task_id);
    }

    Some(task_id)
}

/// UART base address for QEMU virt machine (console server needs this)
const UART_MMIO_BASE: usize = 0x0900_0000;

/// VirtIO MMIO base address for QEMU virt machine (blkdev server needs this)
const VIRTIO_MMIO_BASE: usize = 0x0a00_0000;

/// Create the console server from ELF with UART MMIO access
///
/// This is a specialized function for the console server that maps the UART
/// MMIO region into the task's address space so it can do direct I/O.
///
/// # Arguments
/// * `name` - Task name for debugging
/// * `elf_data` - Raw ELF file data
///
/// # Returns
/// The TaskId if successful, None if parsing or allocation failed
pub fn create_console_server_from_elf(name: &str, elf_data: &[u8]) -> Option<TaskId> {
    // Parse ELF header
    let elf = match ElfFile::parse(elf_data) {
        Ok(e) => e,
        Err(_e) => {
            return None;
        }
    };

    let task_id = task::find_free_slot()?;

    // Create user address space
    let mut addr_space = unsafe { AddressSpace::new_for_user()? };

    // Find the range of all segments (same as create_user_task_from_elf)
    let mut min_vaddr = usize::MAX;
    let mut max_vaddr = 0usize;
    let mut has_executable = false;
    let mut has_writable = false;

    for phdr in elf.load_segments() {
        let vaddr = phdr.p_vaddr as usize;
        let memsz = phdr.p_memsz as usize;
        if memsz == 0 {
            continue;
        }
        min_vaddr = min_vaddr.min(vaddr);
        max_vaddr = max_vaddr.max(vaddr + memsz);
        if phdr.p_flags & PF_X != 0 {
            has_executable = true;
        }
        if phdr.p_flags & PF_W != 0 {
            has_writable = true;
        }
    }

    if min_vaddr == usize::MAX {
        return None;
    }

    let block_base = min_vaddr & !(BLOCK_SIZE_2MB - 1);

    // Calculate how many 4KB frames we need for the code
    let code_size = max_vaddr - min_vaddr;
    let num_frames = (code_size + mm::frame::PAGE_SIZE - 1) / mm::frame::PAGE_SIZE;

    if num_frames > MAX_CODE_FRAMES {
        return None;
    }

    // Allocate code frames at the START of a 2MB block (like other servers).
    // This ensures all frames are contiguous and within the same 2MB region.
    let first_frame = mm::frame::alloc_frames_at_2mb_boundary(num_frames)?;
    let phys_base_2mb = first_frame; // first_frame IS the 2MB block base

    // Zero the entire 2MB block (ensures .bss is zeroed)
    unsafe {
        core::ptr::write_bytes(phys_base_2mb.0 as *mut u8, 0, BLOCK_SIZE_2MB);
    }

    // Copy all segments directly into the 2MB physical block
    for phdr in elf.load_segments() {
        let vaddr = phdr.p_vaddr as usize;
        let filesz = phdr.p_filesz as usize;

        if filesz == 0 {
            continue;
        }

        let segment_data = elf.segment_data(phdr).ok()?;
        let offset_in_block = vaddr - block_base;
        let dest_paddr = phys_base_2mb.0 + offset_in_block;

        unsafe {
            core::ptr::copy_nonoverlapping(
                segment_data.as_ptr(),
                dest_paddr as *mut u8,
                filesz,
            );
        }
    }

    // Determine page flags based on combined segment flags
    // With 2MB granularity, we may need both R+W+X if segments are mixed
    let flags = if has_executable && has_writable {
        // Need both execute and write - use RWX
        PageFlags::user_code_data()
    } else if has_executable {
        PageFlags::user_code()
    } else if has_writable {
        PageFlags::user_data()
    } else {
        PageFlags::user_code()
    };

    // Map the code block at its proper virtual address (0x400000)
    unsafe {
        if !addr_space.map_2mb(block_base, phys_base_2mb, flags) {
            return None;
        }
    }

    // Map UART MMIO region for console server
    // The UART at 0x09000000 is within the 2MB block starting at 0x08000000.
    // We map the entire 2MB block containing the UART with device memory attributes.
    // Virtual 0x08000000 -> Physical 0x08000000 (so UART at 0x09000000 works)
    unsafe {
        let uart_block_base = UART_MMIO_BASE & !(BLOCK_SIZE_2MB - 1); // 0x08000000
        if !addr_space.map_2mb(uart_block_base, PhysAddr(uart_block_base), PageFlags::user_device()) {
            return None;
        }
    }

    // Allocate user stack at start of a 2MB block (like create_user_task_from_elf).
    // This ensures each task has its own exclusive 2MB stack region.
    let stack_frame = mm::frame::alloc_frames_at_2mb_boundary(1)?;
    let stack_phys_base_2mb = stack_frame; // first_frame IS the 2MB block base

    unsafe {
        // Zero the entire 2MB stack block
        core::ptr::write_bytes(stack_frame.0 as *mut u8, 0, BLOCK_SIZE_2MB);
        if !addr_space.map_2mb(USER_STACK_VADDR_BASE, stack_phys_base_2mb, PageFlags::user_data()) {
            return None;
        }
    }

    // Stack grows down from top of 2MB region
    let user_stack_top = USER_STACK_VADDR_BASE + BLOCK_SIZE_2MB - 16;
    let user_entry_point = elf.entry_point() as usize;

    // Allocate kernel stack
    let stack_pages = KERNEL_STACK_SIZE / mm::frame::PAGE_SIZE;
    let mut kernel_stack_base = PhysAddr(0);

    for i in 0..stack_pages {
        if let Some(frame) = mm::alloc_frame() {
            if i == 0 {
                kernel_stack_base = frame;
            }
        } else {
            return None;
        }
    }

    unsafe {
        let task = &mut TASKS[task_id.0];
        task.id = task_id;
        task.state = TaskState::Ready;
        task.set_name(name);
        task.kernel_stack_base = kernel_stack_base;
        task.addr_space = Some(addr_space);
        task.entry_point = user_entry_point;
        task.time_slice = DEFAULT_TIME_SLICE;
        task.next = None;
        task.ipc = task::IpcState::empty();

        let kernel_stack_top = kernel_stack_base.0 + KERNEL_STACK_SIZE;
        let ctx_addr = kernel_stack_top - EXCEPTION_CONTEXT_SIZE;
        let ctx = ctx_addr as *mut ExceptionContext;

        core::ptr::write_bytes(ctx, 0, 1);
        (*ctx).elr = user_entry_point as u64;
        (*ctx).spsr = 0x000;
        (*ctx).sp = user_stack_top as u64;

        task.kernel_stack_top = ctx_addr;

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

/// Add a task to the ready queue (public interface for IPC)
pub fn enqueue_task(task_id: TaskId) {
    unsafe {
        SCHEDULER.enqueue(task_id);
    }
}

/// Perform a blocking context switch (task is already marked as blocked)
///
/// Unlike `context_switch` which re-enqueues the current task as Ready,
/// this assumes the caller has already set the current task's state
/// to a blocked state (SendBlocked, RecvBlocked, ReplyBlocked).
///
/// # Safety
/// Must be called from exception context with ctx pointing to saved context.
pub unsafe fn context_switch_blocking(ctx: &mut ExceptionContext) {
    SCHEDULER.context_switch_blocking(ctx);
}

/// Exit the current task (with context switch to next task)
///
/// # Safety
/// Must be called from exception context with ctx pointing to saved context.
pub unsafe fn exit_with_switch(ctx: &mut ExceptionContext, exit_code: i32) {
    SCHEDULER.exit_current(exit_code);
    context_switch_blocking(ctx);
    // Never returns
}

/// Exit the current task (legacy - spins forever, deprecated)
pub fn exit() -> ! {
    unsafe {
        SCHEDULER.exit_current(0);
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

/// Create the blkdev server from ELF with VirtIO MMIO access
///
/// This is a specialized function for the block device server that maps the VirtIO
/// MMIO region into the task's address space so it can access the virtio-blk device.
///
/// # Arguments
/// * `name` - Task name for debugging
/// * `elf_data` - Raw ELF file data
///
/// # Returns
/// The TaskId if successful, None if parsing or allocation failed
pub fn create_blkdev_server_from_elf(name: &str, elf_data: &[u8]) -> Option<TaskId> {
    // Parse ELF header
    let elf = match ElfFile::parse(elf_data) {
        Ok(e) => e,
        Err(_e) => {
            return None;
        }
    };

    let task_id = task::find_free_slot()?;

    // Create user address space
    let mut addr_space = unsafe { AddressSpace::new_for_user()? };

    // Find the range of all segments
    let mut min_vaddr = usize::MAX;
    let mut max_vaddr = 0usize;

    for phdr in elf.load_segments() {
        let vaddr = phdr.p_vaddr as usize;
        let memsz = phdr.p_memsz as usize;
        if memsz == 0 {
            continue;
        }
        min_vaddr = min_vaddr.min(vaddr);
        max_vaddr = max_vaddr.max(vaddr + memsz);
    }

    if min_vaddr == usize::MAX {
        return None;
    }

    let block_base = min_vaddr & !(BLOCK_SIZE_2MB - 1);

    // Calculate how many 4KB frames we need for the code
    let code_size = max_vaddr - min_vaddr;
    let num_frames = (code_size + mm::frame::PAGE_SIZE - 1) / mm::frame::PAGE_SIZE;

    if num_frames > MAX_CODE_FRAMES {
        return None;
    }

    // Allocate code frames at the START of a 2MB block (like console server).
    // This ensures all frames are contiguous and within the same 2MB region.
    let first_frame = mm::frame::alloc_frames_at_2mb_boundary(num_frames)?;
    let phys_base_2mb = first_frame; // first_frame IS the 2MB block base

    // Zero the entire 2MB block (ensures .bss is zeroed)
    unsafe {
        core::ptr::write_bytes(phys_base_2mb.0 as *mut u8, 0, BLOCK_SIZE_2MB);
    }

    // Copy all segments directly into the 2MB physical block
    for phdr in elf.load_segments() {
        let vaddr = phdr.p_vaddr as usize;
        let filesz = phdr.p_filesz as usize;

        if filesz == 0 {
            continue;
        }

        let segment_data = elf.segment_data(phdr).ok()?;
        let offset_in_block = vaddr - block_base;
        let dest_paddr = phys_base_2mb.0 + offset_in_block;

        unsafe {
            core::ptr::copy_nonoverlapping(
                segment_data.as_ptr(),
                dest_paddr as *mut u8,
                filesz,
            );
        }
    }

    // Use RWX flags for user code block (2MB granularity requires combined permissions)
    let flags = PageFlags::user_code_data();

    // Map the code block at its proper virtual address
    unsafe {
        if !addr_space.map_2mb(block_base, phys_base_2mb, flags) {
            return None;
        }
    }

    // Map VirtIO MMIO region for blkdev server
    // VirtIO MMIO at 0x0a000000 is in a 2MB block starting at 0x0a000000
    // We map the entire 2MB block with device memory attributes
    unsafe {
        let virtio_block_base = VIRTIO_MMIO_BASE & !(BLOCK_SIZE_2MB - 1);
        if !addr_space.map_2mb(virtio_block_base, PhysAddr(virtio_block_base), PageFlags::user_device()) {
            return None;
        }
    }

    // Allocate user stack at start of a 2MB block (like create_user_task_from_elf).
    // This ensures each task has its own exclusive 2MB stack region.
    let stack_frame = mm::frame::alloc_frames_at_2mb_boundary(1)?;
    let stack_phys_base_2mb = stack_frame; // first_frame IS the 2MB block base

    unsafe {
        // Zero the entire 2MB stack block
        core::ptr::write_bytes(stack_frame.0 as *mut u8, 0, BLOCK_SIZE_2MB);
        if !addr_space.map_2mb(USER_STACK_VADDR_BASE, stack_phys_base_2mb, PageFlags::user_data()) {
            return None;
        }
    }

    // Stack grows down from top of 2MB region
    let user_stack_top = USER_STACK_VADDR_BASE + BLOCK_SIZE_2MB - 16;
    // Entry point is directly from ELF since we allocate at 2MB boundary (offset = 0)
    let user_entry_point = elf.entry_point() as usize;

    // Allocate kernel stack
    let stack_pages = KERNEL_STACK_SIZE / mm::frame::PAGE_SIZE;
    let mut kernel_stack_base = PhysAddr(0);

    for i in 0..stack_pages {
        if let Some(frame) = mm::alloc_frame() {
            if i == 0 {
                kernel_stack_base = frame;
            }
        } else {
            return None;
        }
    }

    unsafe {
        let task = &mut TASKS[task_id.0];
        task.id = task_id;
        task.state = TaskState::Ready;
        task.set_name(name);
        task.kernel_stack_base = kernel_stack_base;
        task.addr_space = Some(addr_space);
        task.entry_point = user_entry_point;
        task.time_slice = DEFAULT_TIME_SLICE;
        task.next = None;
        task.ipc = task::IpcState::empty();
        task.init_stdio(); // Initialize stdin/stdout/stderr for blkdev

        let kernel_stack_top = kernel_stack_base.0 + KERNEL_STACK_SIZE;
        let ctx_addr = kernel_stack_top - EXCEPTION_CONTEXT_SIZE;
        let ctx = ctx_addr as *mut ExceptionContext;

        core::ptr::write_bytes(ctx, 0, 1);
        (*ctx).elr = user_entry_point as u64;
        (*ctx).spsr = 0x000;
        (*ctx).sp = user_stack_top as u64;
        // Pass physical base in x0 for VA->PA conversion in VirtIO driver
        (*ctx).gpr[0] = phys_base_2mb.0 as u64;

        task.kernel_stack_top = ctx_addr;

        SCHEDULER.enqueue(task_id);
    }

    Some(task_id)
}

/// Create a network device server task from an ELF binary
///
/// Similar to create_blkdev_server_from_elf but for network device.
/// Maps the VirtIO MMIO region for network device access.
///
/// # Arguments
/// * `name` - Task name for debugging
/// * `elf_data` - Raw bytes of the ELF executable
///
/// # Returns
/// The TaskId if successful, None if parsing or allocation failed
pub fn create_netdev_server_from_elf(name: &str, elf_data: &[u8]) -> Option<TaskId> {
    // Parse ELF header
    let elf = match ElfFile::parse(elf_data) {
        Ok(e) => e,
        Err(_e) => {
            return None;
        }
    };

    let task_id = task::find_free_slot()?;

    // Create user address space
    let mut addr_space = unsafe { AddressSpace::new_for_user()? };

    // Find the range of all segments
    let mut min_vaddr = usize::MAX;
    let mut max_vaddr = 0usize;

    for phdr in elf.load_segments() {
        let vaddr = phdr.p_vaddr as usize;
        let memsz = phdr.p_memsz as usize;
        if memsz == 0 {
            continue;
        }
        min_vaddr = min_vaddr.min(vaddr);
        max_vaddr = max_vaddr.max(vaddr + memsz);
    }

    if min_vaddr == usize::MAX {
        return None;
    }

    let block_base = min_vaddr & !(BLOCK_SIZE_2MB - 1);

    // Calculate how many 4KB frames we need for the code
    let code_size = max_vaddr - min_vaddr;
    let num_frames = (code_size + mm::frame::PAGE_SIZE - 1) / mm::frame::PAGE_SIZE;

    if num_frames > MAX_CODE_FRAMES {
        return None;
    }

    // Allocate code frames at the START of a 2MB block (like console server).
    // This ensures all frames are contiguous and within the same 2MB region.
    let first_frame = mm::frame::alloc_frames_at_2mb_boundary(num_frames)?;
    let phys_base_2mb = first_frame; // first_frame IS the 2MB block base

    // Zero the entire 2MB block (ensures .bss is zeroed)
    unsafe {
        core::ptr::write_bytes(phys_base_2mb.0 as *mut u8, 0, BLOCK_SIZE_2MB);
    }

    // Copy all segments directly into the 2MB physical block
    for phdr in elf.load_segments() {
        let vaddr = phdr.p_vaddr as usize;
        let filesz = phdr.p_filesz as usize;

        if filesz == 0 {
            continue;
        }

        let segment_data = elf.segment_data(phdr).ok()?;
        let offset_in_block = vaddr - block_base;
        let dest_paddr = phys_base_2mb.0 + offset_in_block;

        unsafe {
            core::ptr::copy_nonoverlapping(
                segment_data.as_ptr(),
                dest_paddr as *mut u8,
                filesz,
            );
        }
    }

    // Use RWX flags for user code block (2MB granularity requires combined permissions)
    let flags = PageFlags::user_code_data();

    // Map the code block at its proper virtual address
    unsafe {
        if !addr_space.map_2mb(block_base, phys_base_2mb, flags) {
            return None;
        }
    }

    // Map VirtIO MMIO region for netdev server
    // VirtIO MMIO at 0x0a000000 is in a 2MB block starting at 0x0a000000
    // We map the entire 2MB block with device memory attributes
    unsafe {
        let virtio_block_base = VIRTIO_MMIO_BASE & !(BLOCK_SIZE_2MB - 1);
        if !addr_space.map_2mb(virtio_block_base, PhysAddr(virtio_block_base), PageFlags::user_device()) {
            return None;
        }
    }

    // Allocate user stack at start of a 2MB block (like create_user_task_from_elf).
    // This ensures each task has its own exclusive 2MB stack region.
    let stack_frame = mm::frame::alloc_frames_at_2mb_boundary(1)?;
    let stack_phys_base_2mb = stack_frame; // first_frame IS the 2MB block base

    unsafe {
        // Zero the entire 2MB stack block
        core::ptr::write_bytes(stack_frame.0 as *mut u8, 0, BLOCK_SIZE_2MB);
        if !addr_space.map_2mb(USER_STACK_VADDR_BASE, stack_phys_base_2mb, PageFlags::user_data()) {
            return None;
        }
    }

    // Stack grows down from top of 2MB region
    let user_stack_top = USER_STACK_VADDR_BASE + BLOCK_SIZE_2MB - 16;
    let user_entry_point = elf.entry_point() as usize;

    // Allocate kernel stack
    let stack_pages = KERNEL_STACK_SIZE / mm::frame::PAGE_SIZE;
    let mut kernel_stack_base = PhysAddr(0);

    for i in 0..stack_pages {
        if let Some(frame) = mm::alloc_frame() {
            if i == 0 {
                kernel_stack_base = frame;
            }
        } else {
            return None;
        }
    }

    unsafe {
        let task = &mut TASKS[task_id.0];
        task.id = task_id;
        task.state = TaskState::Ready;
        task.set_name(name);
        task.kernel_stack_base = kernel_stack_base;
        task.addr_space = Some(addr_space);
        task.entry_point = user_entry_point;
        task.time_slice = DEFAULT_TIME_SLICE;
        task.next = None;
        task.ipc = task::IpcState::empty();
        task.init_stdio(); // Initialize stdin/stdout/stderr for netdev

        let kernel_stack_top = kernel_stack_base.0 + KERNEL_STACK_SIZE;
        let ctx_addr = kernel_stack_top - EXCEPTION_CONTEXT_SIZE;
        let ctx = ctx_addr as *mut ExceptionContext;

        core::ptr::write_bytes(ctx, 0, 1);
        (*ctx).elr = user_entry_point as u64;
        (*ctx).spsr = 0x000;
        (*ctx).sp = user_stack_top as u64;
        // Pass physical base in x0 for VA->PA conversion in VirtIO driver
        (*ctx).gpr[0] = phys_base_2mb.0 as u64;

        task.kernel_stack_top = ctx_addr;

        SCHEDULER.enqueue(task_id);
    }

    Some(task_id)
}

/// Replace an existing task's address space with a new ELF image (for execve).
/// Preserves: task id, kernel stack, file descriptors, parent, cwd
/// Resets: address space, entry point, heap, IPC state, notifications
/// Returns entry_point on success, or negative error code.
pub fn replace_task_with_elf(
    task_id: TaskId,
    elf_data: &[u8],
    argv_data: &[u8; 1024],
    argv_offsets: &[u16; 16],
    argc: usize,
) -> Result<usize, i64> {
    use crate::elf::Elf64Header;

    // Parse ELF header
    if elf_data.len() < core::mem::size_of::<Elf64Header>() {
        return Err(-1); // EPERM - invalid ELF
    }

    let elf_header = unsafe { &*(elf_data.as_ptr() as *const Elf64Header) };

    // Verify ELF magic
    if &elf_header.e_ident[0..4] != b"\x7fELF" {
        return Err(-1); // Invalid ELF magic
    }

    let entry_point = elf_header.e_entry as usize;

    // Find the range of memory needed for all LOAD segments
    let mut min_vaddr = usize::MAX;
    let mut max_vaddr = 0usize;

    let ph_offset = elf_header.e_phoff as usize;
    let ph_size = elf_header.e_phentsize as usize;
    let ph_count = elf_header.e_phnum as usize;

    for i in 0..ph_count {
        let ph_start = ph_offset + i * ph_size;
        if ph_start + ph_size > elf_data.len() {
            break;
        }
        let phdr = unsafe { &*(elf_data.as_ptr().add(ph_start) as *const crate::elf::Elf64Phdr) };

        // PT_LOAD = 1
        if phdr.p_type == 1 {
            let seg_start = phdr.p_vaddr as usize;
            let seg_end = seg_start + phdr.p_memsz as usize;
            if seg_start < min_vaddr {
                min_vaddr = seg_start;
            }
            if seg_end > max_vaddr {
                max_vaddr = seg_end;
            }
        }
    }

    if min_vaddr == usize::MAX {
        return Err(-1); // No loadable segments
    }

    // Calculate 2MB-aligned virtual address range
    // This is critical: even if code_size < 2MB, if the code spans a 2MB boundary,
    // we need to map multiple 2MB blocks
    let virt_base = min_vaddr & !(BLOCK_SIZE_2MB - 1);
    let virt_end = (max_vaddr + BLOCK_SIZE_2MB - 1) & !(BLOCK_SIZE_2MB - 1);
    let num_2mb_blocks = (virt_end - virt_base) / BLOCK_SIZE_2MB;

    // Check limits - we support up to 4 2MB blocks (8MB total)
    const MAX_CODE_2MB_BLOCKS: usize = 4;
    if num_2mb_blocks > MAX_CODE_2MB_BLOCKS {
        return Err(-12); // ENOMEM - ELF too large
    }

    // Calculate how many frames we need (4KB pages)
    let num_code_frames = num_2mb_blocks * 512; // 512 pages per 2MB block

    // Allocate frames at a 2MB boundary - this is critical because we zero the entire
    // memory region. Using alloc_frames_in_2mb_block could return frames in the middle of a
    // 2MB block, and zeroing from the block base would corrupt other allocations (like SHM).
    let first_frame = match mm::frame::alloc_frames_at_2mb_boundary(num_code_frames) {
        Some(frame) => frame,
        None => return Err(-12), // ENOMEM
    };
    // first_frame is already 2MB-aligned when using alloc_frames_at_2mb_boundary
    let phys_base_2mb = first_frame;

    // Debug: print addresses to understand allocation
    let elf_phys_start = elf_data.as_ptr() as usize;
    let elf_phys_end = elf_phys_start + elf_data.len();
    let code_phys_start = phys_base_2mb.0;
    let code_phys_end = code_phys_start + num_2mb_blocks * BLOCK_SIZE_2MB;
    crate::println!("[execve] elf={:#x}-{:#x} code={:#x}-{:#x} virt={:#x}-{:#x} blocks={}",
        elf_phys_start, elf_phys_end, code_phys_start, code_phys_end,
        virt_base, virt_end, num_2mb_blocks);

    // Check ELF magic BEFORE zeroing
    crate::println!("[execve] pre-zero magic={:02x}{:02x}{:02x}{:02x}",
        elf_data[0], elf_data[1], elf_data[2], elf_data[3]);

    // Zero ALL allocated memory (not just one 2MB block)
    unsafe {
        core::ptr::write_bytes(phys_base_2mb.0 as *mut u8, 0, num_2mb_blocks * BLOCK_SIZE_2MB);
    }

    // Check ELF magic AFTER zeroing
    crate::println!("[execve] post-zero magic={:02x}{:02x}{:02x}{:02x}",
        elf_data[0], elf_data[1], elf_data[2], elf_data[3]);

    // Load LOAD segments into the allocated memory
    for i in 0..ph_count {
        let ph_start = ph_offset + i * ph_size;
        if ph_start + ph_size > elf_data.len() {
            break;
        }
        let phdr = unsafe { &*(elf_data.as_ptr().add(ph_start) as *const crate::elf::Elf64Phdr) };

        if phdr.p_type == 1 {
            let file_offset = phdr.p_offset as usize;
            let file_size = phdr.p_filesz as usize;
            let mem_size = phdr.p_memsz as usize;
            let vaddr = phdr.p_vaddr as usize;

            crate::println!("[execve] PT_LOAD: vaddr=0x{:x} filesz=0x{:x} memsz=0x{:x}",
                vaddr, file_size, mem_size);

            // Calculate physical offset from the base of our allocation
            // vaddr is relative to virt_base, not min_vaddr
            let phys_offset = vaddr - virt_base;
            let dest_addr = phys_base_2mb.0 + phys_offset;

            if file_offset + file_size <= elf_data.len() {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        elf_data.as_ptr().add(file_offset),
                        dest_addr as *mut u8,
                        file_size,
                    );
                }
            }

            // Explicitly zero BSS region (memsz - filesz bytes after the copied data)
            // This should already be zero from the initial memset, but let's be explicit
            if mem_size > file_size {
                let bss_start = dest_addr + file_size;
                let bss_size = mem_size - file_size;
                unsafe {
                    core::ptr::write_bytes(bss_start as *mut u8, 0, bss_size);
                }
                crate::println!("[execve] zeroing BSS: 0x{:x} - 0x{:x} ({} bytes)",
                    bss_start, bss_start + bss_size, bss_size);
            }
        }
    }

    let mut new_addr_space = match unsafe { AddressSpace::new_for_user() } {
        Some(as_) => as_,
        None => return Err(-12), // ENOMEM - couldn't create address space
    };

    // Map ALL 2MB code blocks at the aligned virtual addresses
    // Use user_code_data (RWX) since the blocks contain both code and writable data
    for block_idx in 0..num_2mb_blocks {
        let block_vaddr = virt_base + block_idx * BLOCK_SIZE_2MB;
        let block_paddr = PhysAddr(phys_base_2mb.0 + block_idx * BLOCK_SIZE_2MB);
        unsafe {
            if !new_addr_space.map_2mb(block_vaddr, block_paddr, PageFlags::user_code_data()) {
                return Err(-12); // ENOMEM
            }
        }
        // Track each code block for cleanup when address space is dropped
        new_addr_space.track_data_block(block_paddr);
    }

    // Allocate a separate 2MB stack block at a 2MB boundary (same reason as code block)
    let stack_frame = match mm::frame::alloc_frames_at_2mb_boundary(512) {
        Some(frame) => frame,
        None => return Err(-12), // ENOMEM
    };
    // stack_frame is already 2MB-aligned
    let stack_phys_base_2mb = stack_frame;

    // Zero the stack to avoid leaking data from previous allocations
    unsafe {
        core::ptr::write_bytes(stack_phys_base_2mb.0 as *mut u8, 0, BLOCK_SIZE_2MB);
    }

    // Map stack at USER_STACK_VADDR_BASE
    unsafe {
        if !new_addr_space.map_2mb(USER_STACK_VADDR_BASE, stack_phys_base_2mb, PageFlags::user_data()) {
            return Err(-12); // ENOMEM
        }
    }

    // Track stack block for cleanup when address space is dropped
    new_addr_space.track_data_block(stack_phys_base_2mb);

    // Set up the user stack with Linux ABI (argc, argv, envp, auxv)
    let stack_virt_top = USER_STACK_VADDR_BASE + BLOCK_SIZE_2MB;

    // Calculate physical address from virtual offset
    let virt_to_phys = |vaddr: usize| -> usize {
        stack_phys_base_2mb.0 + (vaddr - USER_STACK_VADDR_BASE)
    };

    // Start from top of stack and work down
    let mut sp = stack_virt_top;

    unsafe {
        // 1. Random bytes at top (for AT_RANDOM) - 16 bytes
        sp -= 16;
        let random_vaddr = sp;
        let random_paddr = virt_to_phys(sp);
        let random_ptr = random_paddr as *mut u64;
        *random_ptr = 0xDEADBEEF12345678u64;
        *random_ptr.add(1) = 0xCAFEBABE87654321u64;

        // 2. Copy all argv strings to stack and record their virtual addresses
        let mut argv_vaddrs: [usize; 16] = [0; 16];
        let actual_argc = argc.min(16);

        for i in (0..actual_argc).rev() {
            let offset = argv_offsets[i] as usize;
            // Find string length
            let mut str_len = 0;
            while offset + str_len < 1024 && argv_data[offset + str_len] != 0 {
                str_len += 1;
            }
            // Allocate space on stack (aligned to 8 bytes)
            sp -= (str_len + 1 + 7) & !7;
            argv_vaddrs[i] = sp;
            let str_paddr = virt_to_phys(sp);
            // Copy string including null terminator
            for j in 0..=str_len {
                let c = if offset + j < 1024 { argv_data[offset + j] } else { 0 };
                core::ptr::write((str_paddr + j) as *mut u8, c);
            }
        }

        // 3. Align to 16 bytes
        sp = sp & !15;

        // 4. Set up auxiliary vector (auxv)
        const AT_NULL: u64 = 0;
        const AT_PHDR: u64 = 3;
        const AT_PHENT: u64 = 4;
        const AT_PHNUM: u64 = 5;
        const AT_PAGESZ: u64 = 6;
        const AT_ENTRY: u64 = 9;
        const AT_UID: u64 = 11;
        const AT_EUID: u64 = 12;
        const AT_GID: u64 = 13;
        const AT_EGID: u64 = 14;
        const AT_RANDOM: u64 = 25;

        // Get ELF header info for auxv
        let elf_header = &*(elf_data.as_ptr() as *const crate::elf::Elf64Header);
        let phdr_addr = virt_base + elf_header.e_phoff as usize;
        let phent = elf_header.e_phentsize as u64;
        let phnum = elf_header.e_phnum as u64;

        let auxv: [(u64, u64); 11] = [
            (AT_PHDR, phdr_addr as u64),
            (AT_PHENT, phent),
            (AT_PHNUM, phnum),
            (AT_PAGESZ, PAGE_SIZE as u64),
            (AT_ENTRY, entry_point as u64),
            (AT_UID, 0),
            (AT_EUID, 0),
            (AT_GID, 0),
            (AT_EGID, 0),
            (AT_RANDOM, random_vaddr as u64),
            (AT_NULL, 0),
        ];

        // Write auxv (each entry is 16 bytes)
        for (at_type, at_val) in auxv.iter().rev() {
            sp -= 16;
            let ptr = virt_to_phys(sp) as *mut u64;
            *ptr = *at_type;
            *ptr.add(1) = *at_val;
        }

        // 5. envp[] = { NULL }
        sp -= 8;
        *(virt_to_phys(sp) as *mut u64) = 0;

        // 6. argv[] = { argv[0], argv[1], ..., NULL }
        sp -= 8;
        *(virt_to_phys(sp) as *mut u64) = 0; // NULL terminator
        for i in (0..actual_argc).rev() {
            sp -= 8;
            *(virt_to_phys(sp) as *mut u64) = argv_vaddrs[i] as u64;
        }

        // 7. argc
        sp -= 8;
        *(virt_to_phys(sp) as *mut u64) = actual_argc as u64;
    }

    // Update the task
    unsafe {
        let task = &mut TASKS[task_id.0];

        // Reset mmap state for the new process image
        task.mmap_state = crate::mmap::MmapState::new();

        // Replace old address space with new one (old one will be dropped and its
        // data_blocks will be freed automatically)
        task.addr_space = Some(new_addr_space);
        task.entry_point = entry_point;

        // Set heap_brk to end of mapped 2MB blocks, but ensure it doesn't conflict with stack.
        // Stack is at USER_STACK_VADDR_BASE for 2MB. Heap must start after both code and stack.
        let heap_start_after_stack = USER_STACK_VADDR_BASE + BLOCK_SIZE_2MB;
        task.heap_brk = virt_end.max(heap_start_after_stack);
        crate::println!("[execve] task={} virt_end=0x{:x} heap_brk=0x{:x}",
            task_id.0, virt_end, task.heap_brk);

        // Reset IPC state
        task.ipc = task::IpcState::empty();
        task.pending_syscall = task::PendingSyscall::None;

        // Reset notifications
        task.notify_pending = 0;
        task.notify_waiting = 0;

        // Reset time slice
        task.time_slice = DEFAULT_TIME_SLICE;

        // Set up exception context for new entry point
        let kernel_stack_top = task.kernel_stack_base.0 + KERNEL_STACK_SIZE;
        let ctx_addr = kernel_stack_top - EXCEPTION_CONTEXT_SIZE;
        let ctx = ctx_addr as *mut ExceptionContext;

        core::ptr::write_bytes(ctx, 0, 1);
        (*ctx).elr = entry_point as u64;
        (*ctx).spsr = 0x000; // EL0, interrupts enabled
        (*ctx).sp = sp as u64; // SP points to argc on the stack

        task.kernel_stack_top = ctx_addr;
    }

    Ok(entry_point)
}

/// fw_cfg MMIO base address (within UART 2MB block at 0x08000000)
const FWCFG_MMIO_BASE: usize = 0x0902_0000;

/// Fixed virtual address for framebuffer in fbdev's address space
const FRAMEBUFFER_VADDR: usize = 0x2000_0000;

/// Create the fbdev server from ELF with fw_cfg MMIO and framebuffer access
///
/// This is a specialized function for the framebuffer device server that:
/// 1. Maps the fw_cfg MMIO region (same 2MB block as UART)
/// 2. Allocates a 2MB block for framebuffer memory
/// 3. Maps framebuffer into fbdev's address space
/// 4. Passes phys_base in x0 and fb_phys in x1
///
/// # Arguments
/// * `name` - Task name for debugging
/// * `elf_data` - Raw ELF file data
///
/// # Returns
/// The TaskId if successful, None if parsing or allocation failed
pub fn create_fbdev_server_from_elf(name: &str, elf_data: &[u8]) -> Option<TaskId> {
    // Parse ELF header
    let elf = match ElfFile::parse(elf_data) {
        Ok(e) => e,
        Err(_e) => {
            return None;
        }
    };

    let task_id = task::find_free_slot()?;

    // Create user address space
    let mut addr_space = unsafe { AddressSpace::new_for_user()? };

    // Find the range of all segments
    let mut min_vaddr = usize::MAX;
    let mut max_vaddr = 0usize;

    for phdr in elf.load_segments() {
        let vaddr = phdr.p_vaddr as usize;
        let memsz = phdr.p_memsz as usize;
        if memsz == 0 {
            continue;
        }
        min_vaddr = min_vaddr.min(vaddr);
        max_vaddr = max_vaddr.max(vaddr + memsz);
    }

    if min_vaddr == usize::MAX {
        return None;
    }

    let block_base = min_vaddr & !(BLOCK_SIZE_2MB - 1);

    // Calculate how many 4KB frames we need for the code
    let code_size = max_vaddr - min_vaddr;
    let num_frames = (code_size + mm::frame::PAGE_SIZE - 1) / mm::frame::PAGE_SIZE;

    if num_frames > MAX_CODE_FRAMES {
        return None;
    }

    // Allocate code frames at the START of a 2MB block (like console server).
    // This ensures all frames are contiguous and within the same 2MB region.
    let first_frame = mm::frame::alloc_frames_at_2mb_boundary(num_frames)?;
    let phys_base_2mb = first_frame; // first_frame IS the 2MB block base

    // Zero the entire 2MB block (ensures .bss is zeroed)
    unsafe {
        core::ptr::write_bytes(phys_base_2mb.0 as *mut u8, 0, BLOCK_SIZE_2MB);
    }

    // Copy all segments directly into the 2MB physical block
    for phdr in elf.load_segments() {
        let vaddr = phdr.p_vaddr as usize;
        let filesz = phdr.p_filesz as usize;

        if filesz == 0 {
            continue;
        }

        let segment_data = elf.segment_data(phdr).ok()?;
        let offset_in_block = vaddr - block_base;
        let dest_paddr = phys_base_2mb.0 + offset_in_block;

        unsafe {
            core::ptr::copy_nonoverlapping(
                segment_data.as_ptr(),
                dest_paddr as *mut u8,
                filesz,
            );
        }
    }

    // Use RWX flags for user code block (2MB granularity requires combined permissions)
    let flags = PageFlags::user_code_data();

    // Map the code block at its proper virtual address
    unsafe {
        if !addr_space.map_2mb(block_base, phys_base_2mb, flags) {
            return None;
        }
    }

    // Map fw_cfg MMIO region (same 2MB block as UART)
    // fw_cfg is at 0x09020000, UART is at 0x09000000 - both in 2MB block 0x09000000
    unsafe {
        let fwcfg_block_base = FWCFG_MMIO_BASE & !(BLOCK_SIZE_2MB - 1); // 0x09000000
        if !addr_space.map_2mb(fwcfg_block_base, PhysAddr(fwcfg_block_base), PageFlags::user_device()) {
            return None;
        }
    }

    // Map VirtIO MMIO region for virtio-gpu
    // VirtIO MMIO at 0x0a000000 is in a 2MB block starting at 0x0a000000
    unsafe {
        let virtio_block_base = VIRTIO_MMIO_BASE & !(BLOCK_SIZE_2MB - 1);
        if !addr_space.map_2mb(virtio_block_base, PhysAddr(virtio_block_base), PageFlags::user_device()) {
            return None;
        }
    }

    // Allocate 2MB block for framebuffer (800*600*4 = 1.92MB fits in one block)
    // Use alloc_frames_at_2mb_boundary to get a clean 2MB block
    let fb_frame = mm::frame::alloc_frames_at_2mb_boundary(512)?; // 512 frames = 2MB
    let fb_phys = fb_frame.0 as u64;

    // Zero the framebuffer
    unsafe {
        core::ptr::write_bytes(fb_frame.0 as *mut u8, 0, BLOCK_SIZE_2MB);
    }

    // Map framebuffer at FRAMEBUFFER_VADDR
    unsafe {
        if !addr_space.map_2mb(FRAMEBUFFER_VADDR, fb_frame, PageFlags::user_data()) {
            return None;
        }
    }

    // Allocate user stack at start of a 2MB block (like create_user_task_from_elf).
    // This ensures each task has its own exclusive 2MB stack region.
    let stack_frame = mm::frame::alloc_frames_at_2mb_boundary(1)?;
    let stack_phys_base_2mb = stack_frame; // first_frame IS the 2MB block base

    unsafe {
        // Zero the entire 2MB stack block
        core::ptr::write_bytes(stack_frame.0 as *mut u8, 0, BLOCK_SIZE_2MB);
        if !addr_space.map_2mb(USER_STACK_VADDR_BASE, stack_phys_base_2mb, PageFlags::user_data()) {
            return None;
        }
    }

    // Stack grows down from top of 2MB region
    let user_stack_top = USER_STACK_VADDR_BASE + BLOCK_SIZE_2MB - 16;
    // Entry point is directly from ELF since we allocate at 2MB boundary (offset = 0)
    let user_entry_point = elf.entry_point() as usize;

    // Allocate kernel stack
    let stack_pages = KERNEL_STACK_SIZE / mm::frame::PAGE_SIZE;
    let mut kernel_stack_base = PhysAddr(0);

    for i in 0..stack_pages {
        if let Some(frame) = mm::alloc_frame() {
            if i == 0 {
                kernel_stack_base = frame;
            }
        } else {
            return None;
        }
    }

    unsafe {
        let task = &mut TASKS[task_id.0];
        task.id = task_id;
        task.state = TaskState::Ready;
        task.set_name(name);
        task.kernel_stack_base = kernel_stack_base;
        task.addr_space = Some(addr_space);
        task.entry_point = user_entry_point;
        task.time_slice = DEFAULT_TIME_SLICE;
        task.next = None;
        task.ipc = task::IpcState::empty();
        task.init_stdio();

        let kernel_stack_top = kernel_stack_base.0 + KERNEL_STACK_SIZE;
        let ctx_addr = kernel_stack_top - EXCEPTION_CONTEXT_SIZE;
        let ctx = ctx_addr as *mut ExceptionContext;

        core::ptr::write_bytes(ctx, 0, 1);
        (*ctx).elr = user_entry_point as u64;
        (*ctx).spsr = 0x000;
        (*ctx).sp = user_stack_top as u64;
        // Pass physical base in x0 for VA->PA conversion
        (*ctx).gpr[0] = phys_base_2mb.0 as u64;
        // Pass framebuffer physical address in x1
        (*ctx).gpr[1] = fb_phys;

        task.kernel_stack_top = ctx_addr;

        SCHEDULER.enqueue(task_id);
    }

    Some(task_id)
}

/// Create keyboard device server from ELF image.
/// This server handles VirtIO-input keyboard input.
/// Maps VirtIO MMIO region for virtio-keyboard-device access.
///
/// # Arguments
/// * `name` - Task name
/// * `elf_data` - Raw ELF file data
///
/// # Returns
/// The TaskId if successful, None if parsing or allocation failed
pub fn create_kbdev_server_from_elf(name: &str, elf_data: &[u8]) -> Option<TaskId> {
    // Parse ELF header
    let elf = match ElfFile::parse(elf_data) {
        Ok(e) => e,
        Err(_e) => {
            return None;
        }
    };

    let task_id = task::find_free_slot()?;

    // Create user address space
    let mut addr_space = unsafe { AddressSpace::new_for_user()? };

    // Find the range of all segments
    let mut min_vaddr = usize::MAX;
    let mut max_vaddr = 0usize;

    for phdr in elf.load_segments() {
        let vaddr = phdr.p_vaddr as usize;
        let memsz = phdr.p_memsz as usize;
        if memsz == 0 {
            continue;
        }
        min_vaddr = min_vaddr.min(vaddr);
        max_vaddr = max_vaddr.max(vaddr + memsz);
    }

    if min_vaddr == usize::MAX {
        return None;
    }

    let block_base = min_vaddr & !(BLOCK_SIZE_2MB - 1);

    // Calculate how many 4KB frames we need for the code
    let code_size = max_vaddr - min_vaddr;
    let num_frames = (code_size + mm::frame::PAGE_SIZE - 1) / mm::frame::PAGE_SIZE;

    if num_frames > MAX_CODE_FRAMES {
        return None;
    }

    // Allocate code frames at the START of a 2MB block.
    // This ensures all frames are contiguous and within the same 2MB region.
    let first_frame = mm::frame::alloc_frames_at_2mb_boundary(num_frames)?;
    let phys_base_2mb = first_frame; // first_frame IS the 2MB block base

    // Zero the entire 2MB block (ensures .bss is zeroed)
    unsafe {
        core::ptr::write_bytes(phys_base_2mb.0 as *mut u8, 0, BLOCK_SIZE_2MB);
    }

    // Copy all segments directly into the 2MB physical block
    for phdr in elf.load_segments() {
        let vaddr = phdr.p_vaddr as usize;
        let filesz = phdr.p_filesz as usize;

        if filesz == 0 {
            continue;
        }

        let segment_data = elf.segment_data(phdr).ok()?;
        let offset_in_block = vaddr - block_base;
        let dest_paddr = phys_base_2mb.0 + offset_in_block;

        unsafe {
            core::ptr::copy_nonoverlapping(
                segment_data.as_ptr(),
                dest_paddr as *mut u8,
                filesz,
            );
        }
    }

    // Use RWX flags for user code block (2MB granularity requires combined permissions)
    let flags = PageFlags::user_code_data();

    // Map the code block at its proper virtual address
    unsafe {
        if !addr_space.map_2mb(block_base, phys_base_2mb, flags) {
            return None;
        }
    }

    // Map VirtIO MMIO region for virtio-keyboard-device
    // VirtIO MMIO at 0x0a000000 is in a 2MB block starting at 0x0a000000
    unsafe {
        let virtio_block_base = VIRTIO_MMIO_BASE & !(BLOCK_SIZE_2MB - 1);
        if !addr_space.map_2mb(virtio_block_base, PhysAddr(virtio_block_base), PageFlags::user_device()) {
            return None;
        }
    }

    // Allocate user stack at start of a 2MB block (like create_user_task_from_elf).
    // This ensures each task has its own exclusive 2MB stack region.
    let stack_frame = mm::frame::alloc_frames_at_2mb_boundary(1)?;
    let stack_phys_base_2mb = stack_frame; // first_frame IS the 2MB block base

    unsafe {
        // Zero the entire 2MB stack block
        core::ptr::write_bytes(stack_frame.0 as *mut u8, 0, BLOCK_SIZE_2MB);
        if !addr_space.map_2mb(USER_STACK_VADDR_BASE, stack_phys_base_2mb, PageFlags::user_data()) {
            return None;
        }
    }

    // Stack grows down from top of 2MB region
    let user_stack_top = USER_STACK_VADDR_BASE + BLOCK_SIZE_2MB - 16;
    // Entry point is directly from ELF since we allocate at 2MB boundary (offset = 0)
    let user_entry_point = elf.entry_point() as usize;

    // Allocate kernel stack
    let stack_pages = KERNEL_STACK_SIZE / mm::frame::PAGE_SIZE;
    let mut kernel_stack_base = PhysAddr(0);

    for i in 0..stack_pages {
        if let Some(frame) = mm::alloc_frame() {
            if i == 0 {
                kernel_stack_base = frame;
            }
        } else {
            return None;
        }
    }

    unsafe {
        let task = &mut TASKS[task_id.0];
        task.id = task_id;
        task.state = TaskState::Ready;
        task.set_name(name);
        task.kernel_stack_base = kernel_stack_base;
        task.addr_space = Some(addr_space);
        task.entry_point = user_entry_point;
        task.time_slice = DEFAULT_TIME_SLICE;
        task.next = None;
        task.ipc = task::IpcState::empty();
        task.init_stdio();

        let kernel_stack_top = kernel_stack_base.0 + KERNEL_STACK_SIZE;
        let ctx_addr = kernel_stack_top - EXCEPTION_CONTEXT_SIZE;
        let ctx = ctx_addr as *mut ExceptionContext;

        core::ptr::write_bytes(ctx, 0, 1);
        (*ctx).elr = user_entry_point as u64;
        (*ctx).spsr = 0x000;
        (*ctx).sp = user_stack_top as u64;
        // Pass physical base in x0 for VA->PA conversion in VirtIO driver
        (*ctx).gpr[0] = phys_base_2mb.0 as u64;

        task.kernel_stack_top = ctx_addr;

        SCHEDULER.enqueue(task_id);
    }

    Some(task_id)
}
