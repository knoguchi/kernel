//! Synchronous message-passing IPC for Kenix microkernel
//!
//! This module implements L4-style synchronous IPC with:
//! - `send`: Block until receiver accepts message
//! - `recv`: Block until sender sends message
//! - `call`: Send message and block for reply (RPC)
//! - `reply`: Reply to a caller and return immediately

use crate::sched::task::{
    TaskId, TaskState, Message, TASKS, MAX_TASKS, PendingSyscall,
    enqueue_sender, find_sender, remove_from_sender_queue,
    FileDescriptor, FdKind, FdFlags,
};
use crate::sched::{self, current};
use crate::exception::ExceptionContext;
use crate::shm;
use crate::timer;

/// Result of completing a pending syscall
enum PendingSyscallResult {
    /// Syscall is complete, return these values to userspace
    Complete(i64, Option<i64>),
    /// Syscall needs to continue with another IPC call (multi-stage operation)
    Continue {
        new_pending: PendingSyscall,
        target: TaskId,
        msg: Message,
    },
}

/// VFS server task ID for multi-stage operations
const VFS_TID: TaskId = TaskId(3);

/// VFS IPC message tags for multi-stage operations
const VFS_READ_SHM: u64 = 110;

/// Write sys_recv return values to a task's saved exception context
///
/// When a task is woken from RecvBlocked, we must set up the return
/// registers in its saved context before scheduling it, because
/// the context switch restores directly to user space via ERET.
unsafe fn set_recv_return(task_id: TaskId, sender_id: TaskId, msg: &Message) {
    let task = &TASKS[task_id.0];
    // The task's kernel_stack_top points to its saved ExceptionContext
    let ctx = task.kernel_stack_top as *mut ExceptionContext;
    if !ctx.is_null() {
        // SYS_RECV returns: x0=sender_id, x1=tag, x2-x5=data
        (*ctx).gpr[0] = sender_id.0 as u64;
        (*ctx).gpr[1] = msg.tag;
        (*ctx).gpr[2] = msg.data[0];
        (*ctx).gpr[3] = msg.data[1];
        (*ctx).gpr[4] = msg.data[2];
        (*ctx).gpr[5] = msg.data[3];
    }
}

/// Write sys_call return values (reply) to a task's saved exception context
unsafe fn set_call_return(task_id: TaskId, reply: &Message) {
    let task = &TASKS[task_id.0];
    let ctx = task.kernel_stack_top as *mut ExceptionContext;
    if !ctx.is_null() {
        // SYS_CALL returns: x0=reply_tag, x1-x4=reply_data
        (*ctx).gpr[0] = reply.tag;
        (*ctx).gpr[1] = reply.data[0];
        (*ctx).gpr[2] = reply.data[1];
        (*ctx).gpr[3] = reply.data[2];
        (*ctx).gpr[4] = reply.data[3];
    }
}

/// Message tag values for built-in services
pub const MSG_WRITE: u64 = 1;      // Console write request
pub const MSG_EXIT: u64 = 2;       // Process exit
pub const MSG_YIELD: u64 = 3;      // Yield time slice

/// IPC result codes
pub const IPC_OK: i64 = 0;
pub const IPC_ERR_INVALID_TASK: i64 = -1;
pub const IPC_ERR_TASK_DEAD: i64 = -2;
pub const IPC_ERR_WOULD_BLOCK: i64 = -3;
pub const IPC_ERR_NOT_WAITING: i64 = -4;

/// Check if a task ID is valid and the task is not terminated
fn is_valid_task(id: TaskId) -> bool {
    if id.0 >= MAX_TASKS {
        return false;
    }
    unsafe {
        let task = &TASKS[id.0];
        task.state != TaskState::Free && task.state != TaskState::Terminated
    }
}

/// Send a message to a destination task (blocking)
///
/// The sender blocks until the receiver calls recv() and accepts the message.
///
/// # Arguments
/// * `ctx` - Exception context of the calling task
/// * `dest` - Destination task ID
/// * `msg` - Message to send
///
/// # Returns
/// IPC_OK on success, error code on failure
pub fn sys_send(ctx: &mut ExceptionContext, dest: TaskId, msg: Message) -> i64 {
    let sender_id = match current() {
        Some(id) => id,
        None => return IPC_ERR_INVALID_TASK,
    };

    if !is_valid_task(dest) {
        return IPC_ERR_INVALID_TASK;
    }

    unsafe {
        let dest_task = &mut TASKS[dest.0];
        let sender_task = &mut TASKS[sender_id.0];

        // Store the message in sender's pending_msg
        sender_task.ipc.pending_msg = msg;

        // Check if receiver is already waiting (RecvBlocked)
        if dest_task.state == TaskState::RecvBlocked {
            // Check if receiver is waiting for us specifically or any sender
            let recv_from = dest_task.ipc.recv_from;
            if recv_from.is_none() || recv_from == Some(sender_id) {
                // Direct transfer: copy message to receiver
                dest_task.ipc.pending_msg = msg;
                dest_task.ipc.caller = Some(sender_id);

                // Set up return values in receiver's saved context
                set_recv_return(dest, sender_id, &msg);

                // Wake up receiver
                dest_task.state = TaskState::Ready;
                sched::enqueue_task(dest);

                // Sender continues (non-blocking fast path)
                return IPC_OK;
            }
        }

        // Receiver is not waiting for us - we must block
        sender_task.state = TaskState::SendBlocked;
        enqueue_sender(dest, sender_id);

        // Trigger context switch to another task
        sched::context_switch_blocking(ctx);
    }

    // When we wake up, the send completed successfully
    IPC_OK
}

/// Receive a message (blocking)
///
/// The receiver blocks until a sender sends a message.
///
/// # Arguments
/// * `ctx` - Exception context of the calling task
/// * `from` - Source task ID filter (None = accept from any task)
///
/// # Returns
/// (sender_id, message) tuple. Sender ID returned in x0, message in registers.
pub fn sys_recv(ctx: &mut ExceptionContext, from: Option<TaskId>) -> (TaskId, Message) {
    let receiver_id = match current() {
        Some(id) => id,
        None => return (TaskId(0), Message::empty()),
    };

    // Validate from filter if specified
    if let Some(from_id) = from {
        if !from_id.is_any() && !is_valid_task(from_id) {
            // Invalid source filter - return empty
            return (TaskId(0), Message::empty());
        }
    }

    unsafe {
        let receiver_task = &mut TASKS[receiver_id.0];

        // Normalize the from filter (TaskId::ANY means None)
        let from_filter = match from {
            Some(id) if id.is_any() => None,
            other => other,
        };

        // Check if there's already a sender waiting
        if let Some(sender_id) = find_sender(receiver_id, from_filter) {
            // Remove sender from queue
            remove_from_sender_queue(receiver_id, sender_id);

            let sender_task = &mut TASKS[sender_id.0];

            // Copy message from sender
            let msg = sender_task.ipc.pending_msg;
            receiver_task.ipc.pending_msg = msg;
            receiver_task.ipc.caller = Some(sender_id);

            // Wake up sender if it was SendBlocked
            if sender_task.state == TaskState::SendBlocked {
                // Check if sender is doing sys_call (waiting for reply) or sys_send
                if sender_task.ipc.reply_to.is_some() {
                    // sys_call pattern: sender should wait for reply
                    // Transition to ReplyBlocked, don't wake yet
                    sender_task.state = TaskState::ReplyBlocked;
                } else {
                    // sys_send pattern: sender can continue
                    // Set sender's return value (IPC_OK = 0 in x0)
                    let sender_ctx = sender_task.kernel_stack_top as *mut ExceptionContext;
                    if !sender_ctx.is_null() {
                        (*sender_ctx).gpr[0] = IPC_OK as u64;
                    }
                    sender_task.state = TaskState::Ready;
                    sched::enqueue_task(sender_id);
                }
            }

            return (sender_id, msg);
        }

        // No sender waiting - we must block
        receiver_task.state = TaskState::RecvBlocked;
        receiver_task.ipc.recv_from = from_filter;

        // Trigger context switch
        sched::context_switch_blocking(ctx);

        // When we wake up, message is in our pending_msg
        let msg = receiver_task.ipc.pending_msg;
        let sender_id = receiver_task.ipc.caller.unwrap_or(TaskId(0));
        (sender_id, msg)
    }
}

/// Call: Send message and wait for reply (RPC pattern)
///
/// This combines send + recv for the common client-server pattern.
/// The caller blocks until the server calls reply().
///
/// # Arguments
/// * `ctx` - Exception context of the calling task
/// * `dest` - Destination task ID (server)
/// * `msg` - Request message
///
/// # Returns
/// Reply message from server
pub fn sys_call(ctx: &mut ExceptionContext, dest: TaskId, msg: Message) -> Message {
    let caller_id = match current() {
        Some(id) => id,
        None => return Message::empty(),
    };

    if !is_valid_task(dest) {
        return Message::empty();
    }

    unsafe {
        let dest_task = &mut TASKS[dest.0];
        let caller_task = &mut TASKS[caller_id.0];

        // Store message in caller's pending_msg
        caller_task.ipc.pending_msg = msg;
        caller_task.ipc.reply_to = Some(dest);

        // Check if receiver is already waiting
        if dest_task.state == TaskState::RecvBlocked {
            let recv_from = dest_task.ipc.recv_from;
            if recv_from.is_none() || recv_from == Some(caller_id) {
                // Direct transfer
                dest_task.ipc.pending_msg = msg;
                dest_task.ipc.caller = Some(caller_id);

                // Set up return values in receiver's saved context
                set_recv_return(dest, caller_id, &msg);

                // Wake up receiver
                dest_task.state = TaskState::Ready;
                sched::enqueue_task(dest);

                // Caller blocks waiting for reply
                caller_task.state = TaskState::ReplyBlocked;

                // Context switch
                sched::context_switch_blocking(ctx);

                // When we wake, reply is in pending_msg
                return caller_task.ipc.pending_msg;
            }
        }

        // Receiver not waiting - queue ourselves and block
        caller_task.state = TaskState::SendBlocked;
        enqueue_sender(dest, caller_id);

        // Context switch - we'll wake when receiver processes us
        sched::context_switch_blocking(ctx);

        // Woken up - check if reply was already delivered
        // If reply_to is None, the reply was delivered while we were in ReplyBlocked
        // If reply_to is Some, we need to wait for the reply
        if caller_task.ipc.reply_to.is_some() {
            // Reply not yet delivered - make sure we're ReplyBlocked and wait
            if caller_task.state != TaskState::ReplyBlocked {
                caller_task.state = TaskState::ReplyBlocked;
            }
            sched::context_switch_blocking(ctx);
        }

        // Reply received
        caller_task.ipc.pending_msg
    }
}

/// Reply to a caller (non-blocking)
///
/// Sends a reply to a task that called us with sys_call().
///
/// # Arguments
/// * `msg` - Reply message
///
/// # Returns
/// IPC_OK on success, error code on failure
pub fn sys_reply(msg: Message) -> i64 {
    let server_id = match current() {
        Some(id) => id,
        None => return IPC_ERR_INVALID_TASK,
    };

    unsafe {
        let server_task = &TASKS[server_id.0];

        // Get the caller we need to reply to
        let caller_id = match server_task.ipc.caller {
            Some(id) => id,
            None => return IPC_ERR_NOT_WAITING,
        };

        if !is_valid_task(caller_id) {
            return IPC_ERR_TASK_DEAD;
        }

        let caller_task = &mut TASKS[caller_id.0];

        // Caller must be waiting for our reply
        if caller_task.state != TaskState::ReplyBlocked || caller_task.ipc.reply_to != Some(server_id) {
            return IPC_ERR_NOT_WAITING;
        }

        // Transfer reply message
        caller_task.ipc.pending_msg = msg;
        caller_task.ipc.reply_to = None;

        // Check if this reply completes a pending syscall
        let pending = caller_task.pending_syscall;
        let result = complete_pending_syscall(caller_id, pending, &msg);

        match result {
            PendingSyscallResult::Complete(x0_val, x1_opt) => {
                // Set up return values in caller's saved context
                if !pending.is_none() {
                    // Pending syscall - set x0 (and optionally x1) directly
                    let task = &TASKS[caller_id.0];
                    let ctx = task.kernel_stack_top as *mut ExceptionContext;
                    if !ctx.is_null() {
                        (*ctx).gpr[0] = x0_val as u64;
                        if let Some(x1_val) = x1_opt {
                            (*ctx).gpr[1] = x1_val as u64;
                        }
                    }
                } else {
                    // Normal IPC - use standard return format
                    set_call_return(caller_id, &msg);
                }

                // Clear pending syscall
                let caller_task = &mut TASKS[caller_id.0];
                caller_task.pending_syscall = PendingSyscall::None;

                // Wake up caller
                caller_task.state = TaskState::Ready;
                sched::enqueue_task(caller_id);
            }
            PendingSyscallResult::Continue { new_pending, target, msg: next_msg } => {
                // Multi-stage syscall - caller stays blocked, chain to next IPC
                let caller_task = &mut TASKS[caller_id.0];
                caller_task.pending_syscall = new_pending;

                // Store the message in caller's pending_msg (for receiver to pick up)
                caller_task.ipc.pending_msg = next_msg;
                caller_task.ipc.reply_to = Some(target);

                let target_task = &mut TASKS[target.0];
                let target_state = target_task.state;

                // Wake target if it's waiting for messages
                if target_state == TaskState::RecvBlocked {
                    // Target is blocked waiting - deliver message directly
                    target_task.ipc.pending_msg = next_msg;
                    target_task.ipc.caller = Some(caller_id);
                    caller_task.state = TaskState::ReplyBlocked;

                    target_task.state = TaskState::Ready;
                    sched::enqueue_task(target);
                } else {
                    // Target is busy - add caller to sender queue
                    // When target calls recv(), it will find us
                    // Use ReplyBlocked (not SendBlocked) so recv won't wake us -
                    // we want to stay blocked until the reply comes
                    caller_task.state = TaskState::ReplyBlocked;
                    enqueue_sender(target, caller_id);
                }
            }
        }

        // Clear our caller field
        let server_task = &mut TASKS[server_id.0];
        server_task.ipc.caller = None;
    }

    IPC_OK
}

/// Complete a pending syscall using the IPC reply from a server
///
/// Returns PendingSyscallResult indicating whether to wake the caller or continue with another IPC
unsafe fn complete_pending_syscall(caller_id: TaskId, pending: PendingSyscall, reply: &Message) -> PendingSyscallResult {
    match pending {
        PendingSyscall::None => {
            // No pending syscall, use reply tag directly
            PendingSyscallResult::Complete(reply.tag as i64, None)
        }
        PendingSyscall::PipeCreate => {
            let pipe_id = reply.tag as i64;

            // Check if pipeserv returned an error
            if pipe_id < 0 {
                return PendingSyscallResult::Complete(pipe_id, Some(pipe_id)); // Both fds are error
            }

            let caller_task = &mut TASKS[caller_id.0];

            // Allocate read fd
            let read_fd = match caller_task.alloc_fd() {
                Some(fd) => fd,
                None => return PendingSyscallResult::Complete(-12, Some(-12)), // ENOMEM
            };
            caller_task.fds[read_fd] = FileDescriptor {
                kind: FdKind::PipeRead,
                flags: FdFlags::read_only(),
                server: TaskId(6), // PIPESERV_TID
                handle: pipe_id as u64,
            };

            // Allocate write fd
            let write_fd = match caller_task.alloc_fd() {
                Some(fd) => fd,
                None => {
                    caller_task.close_fd(read_fd);
                    return PendingSyscallResult::Complete(-12, Some(-12)); // ENOMEM
                }
            };
            caller_task.fds[write_fd] = FileDescriptor {
                kind: FdKind::PipeWrite,
                flags: FdFlags::write_only(),
                server: TaskId(6), // PIPESERV_TID
                handle: pipe_id as u64,
            };

            PendingSyscallResult::Complete(read_fd as i64, Some(write_fd as i64))
        }
        PendingSyscall::PipeRead { user_buf, max_len: _, shm_id } => {
            let bytes_read = reply.tag as i64;

            if bytes_read > 0 {
                // Get physical address of SHM (kernel has identity mapping)
                let shm_phys = shm::get_shm_phys_addr(shm_id);
                if shm_phys != 0 {
                    let caller_task = &TASKS[caller_id.0];
                    let caller_ttbr0 = caller_task.addr_space.as_ref().map(|aspace| aspace.ttbr0()).unwrap_or(0);

                    // Save current TTBR0 and switch to caller's page table
                    let saved_ttbr0: u64;
                    core::arch::asm!(
                        "mrs {0}, ttbr0_el1",
                        "msr ttbr0_el1, {1}",
                        "isb",
                        "dsb sy",
                        "tlbi vmalle1is",
                        "dsb sy",
                        "isb",
                        out(reg) saved_ttbr0,
                        in(reg) caller_ttbr0,
                    );

                    // Now we can access the caller's address space
                    core::ptr::copy_nonoverlapping(
                        shm_phys as *const u8,
                        user_buf as *mut u8,
                        bytes_read as usize,
                    );

                    // Restore original page table
                    core::arch::asm!(
                        "msr ttbr0_el1, {0}",
                        "isb",
                        "dsb sy",
                        "tlbi vmalle1is",
                        "dsb sy",
                        "isb",
                        in(reg) saved_ttbr0,
                    );
                }
            }

            // Clean up: unmap from caller's space if mapped, then destroy SHM
            shm::sys_shmunmap_for_task(caller_id, shm_id);

            PendingSyscallResult::Complete(bytes_read, None)
        }
        PendingSyscall::PipeWrite { shm_id } => {
            let bytes_written = reply.tag as i64;

            // Clean up: unmap from caller's space if mapped
            shm::sys_shmunmap_for_task(caller_id, shm_id);

            PendingSyscallResult::Complete(bytes_written, None)
        }
        PendingSyscall::PipeClose => {
            // Just return success
            PendingSyscallResult::Complete(0, None)
        }
        PendingSyscall::VfsOpen { fd, flags, shm_id } => {
            let vnode = reply.tag as i64;

            // Clean up SHM used for path
            shm::sys_shmunmap_for_task(caller_id, shm_id);

            // Check if VFS returned an error
            if vnode < 0 {
                // Release the pre-allocated fd
                let caller_task = &mut TASKS[caller_id.0];
                caller_task.close_fd(fd);
                return PendingSyscallResult::Complete(vnode, None); // Return the error code
            }

            // Set up the file descriptor
            let caller_task = &mut TASKS[caller_id.0];
            let is_dir = (reply.data[0] & 1) != 0; // VFS tells us if it's a directory

            caller_task.fds[fd] = FileDescriptor {
                kind: FdKind::File,
                flags: FdFlags {
                    readable: (flags & 3) != 1, // Not O_WRONLY
                    writable: (flags & 3) != 0, // Not O_RDONLY
                },
                server: TaskId(3), // VFS_TID
                handle: vnode as u64,
            };

            let _ = is_dir; // We track this in handle for now
            PendingSyscallResult::Complete(fd as i64, None)
        }
        PendingSyscall::VfsStat { statbuf } => {
            let result = reply.tag as i64;

            if result == 0 {
                // VFS returns stat info in reply.data:
                // data[0] = size
                // data[1] = mode (S_IFREG/S_IFDIR | permissions)
                // data[2] = device (1=ramfs, 2=FAT32)
                // data[3] = inode
                let caller_task = &TASKS[caller_id.0];
                let caller_ttbr0 = caller_task.addr_space.as_ref().map(|aspace| aspace.ttbr0()).unwrap_or(0);

                // Switch to caller's address space to write stat
                let saved_ttbr0: u64;
                core::arch::asm!(
                    "mrs {0}, ttbr0_el1",
                    "msr ttbr0_el1, {1}",
                    "isb", "dsb sy", "tlbi vmalle1is", "dsb sy", "isb",
                    out(reg) saved_ttbr0,
                    in(reg) caller_ttbr0,
                );

                // Get time since boot for timestamps
                let time_ns = timer::get_time_ns();
                let time_sec = (time_ns / 1_000_000_000) as i64;
                let time_nsec = (time_ns % 1_000_000_000) as i64;

                let size = reply.data[0] as i64;
                let mode = reply.data[1] as u32;
                let device = reply.data[2];
                let inode = reply.data[3];

                // Write complete stat structure (128 bytes)
                // Zero the whole structure first
                let stat_ptr = statbuf as *mut u64;
                for i in 0..16 {
                    core::ptr::write_volatile(stat_ptr.add(i), 0);
                }

                // st_dev at offset 0
                core::ptr::write_volatile(stat_ptr.add(0), device);
                // st_ino at offset 8
                core::ptr::write_volatile(stat_ptr.add(1), inode);
                // st_mode at offset 16 (u32), st_nlink at offset 20 (u32)
                core::ptr::write_volatile((statbuf + 16) as *mut u32, mode);
                core::ptr::write_volatile((statbuf + 20) as *mut u32, 1); // st_nlink = 1
                // st_uid at offset 24 (u32), st_gid at offset 28 (u32) - already 0 (root)
                // st_rdev at offset 32 - already 0
                // __pad1 at offset 40 - already 0
                // st_size at offset 48
                core::ptr::write_volatile((statbuf + 48) as *mut i64, size);
                // st_blksize at offset 56
                core::ptr::write_volatile((statbuf + 56) as *mut i32, 512);
                // __pad2 at offset 60 - already 0
                // st_blocks at offset 64 (blocks = (size + 511) / 512)
                let blocks = (size + 511) / 512;
                core::ptr::write_volatile((statbuf + 64) as *mut i64, blocks);
                // st_atime at offset 72, st_atime_nsec at offset 80
                core::ptr::write_volatile((statbuf + 72) as *mut i64, time_sec);
                core::ptr::write_volatile((statbuf + 80) as *mut i64, time_nsec);
                // st_mtime at offset 88, st_mtime_nsec at offset 96
                core::ptr::write_volatile((statbuf + 88) as *mut i64, time_sec);
                core::ptr::write_volatile((statbuf + 96) as *mut i64, time_nsec);
                // st_ctime at offset 104, st_ctime_nsec at offset 112
                core::ptr::write_volatile((statbuf + 104) as *mut i64, time_sec);
                core::ptr::write_volatile((statbuf + 112) as *mut i64, time_nsec);
                // __unused at offset 120 - already 0

                // Restore page table
                core::arch::asm!(
                    "msr ttbr0_el1, {0}",
                    "isb", "dsb sy", "tlbi vmalle1is", "dsb sy", "isb",
                    in(reg) saved_ttbr0,
                );
            }

            PendingSyscallResult::Complete(result, None)
        }
        PendingSyscall::VfsGetdents { buf, count: _, shm_id } => {
            let bytes_read = reply.tag as i64;

            if bytes_read > 0 {
                // Copy from SHM to user buffer
                let shm_phys = shm::get_shm_phys_addr(shm_id);
                if shm_phys != 0 {
                    let caller_task = &TASKS[caller_id.0];
                    let caller_ttbr0 = caller_task.addr_space.as_ref().map(|aspace| aspace.ttbr0()).unwrap_or(0);

                    let saved_ttbr0: u64;
                    core::arch::asm!(
                        "mrs {0}, ttbr0_el1",
                        "msr ttbr0_el1, {1}",
                        "isb", "dsb sy", "tlbi vmalle1is", "dsb sy", "isb",
                        out(reg) saved_ttbr0,
                        in(reg) caller_ttbr0,
                    );

                    core::ptr::copy_nonoverlapping(
                        shm_phys as *const u8,
                        buf as *mut u8,
                        bytes_read as usize,
                    );

                    core::arch::asm!(
                        "msr ttbr0_el1, {0}",
                        "isb", "dsb sy", "tlbi vmalle1is", "dsb sy", "isb",
                        in(reg) saved_ttbr0,
                    );
                }
            }

            // Clean up SHM
            shm::sys_shmunmap_for_task(caller_id, shm_id);

            PendingSyscallResult::Complete(bytes_read, None)
        }
        PendingSyscall::VfsRead { user_buf, max_len: _, shm_id } => {
            let bytes_read = reply.tag as i64;

            if bytes_read > 0 {
                // Copy from SHM to user buffer
                let shm_phys = shm::get_shm_phys_addr(shm_id);
                if shm_phys != 0 {
                    let caller_task = &TASKS[caller_id.0];
                    let caller_ttbr0 = caller_task.addr_space.as_ref().map(|aspace| aspace.ttbr0()).unwrap_or(0);

                    let saved_ttbr0: u64;
                    core::arch::asm!(
                        "mrs {0}, ttbr0_el1",
                        "msr ttbr0_el1, {1}",
                        "isb", "dsb sy", "tlbi vmalle1is", "dsb sy", "isb",
                        out(reg) saved_ttbr0,
                        in(reg) caller_ttbr0,
                    );

                    core::ptr::copy_nonoverlapping(
                        shm_phys as *const u8,
                        user_buf as *mut u8,
                        bytes_read as usize,
                    );

                    core::arch::asm!(
                        "msr ttbr0_el1, {0}",
                        "isb", "dsb sy", "tlbi vmalle1is", "dsb sy", "isb",
                        in(reg) saved_ttbr0,
                    );
                }
            }

            // Don't clean up SHM if it's the task's cached I/O SHM (for performance)
            // The SHM is reused across multiple reads to avoid allocation overhead
            let is_cached_shm = {
                let caller_task = &TASKS[caller_id.0];
                caller_task.io_shm_id == Some(shm_id)
            };
            if !is_cached_shm {
                shm::sys_shmunmap_for_task(caller_id, shm_id);
            }

            PendingSyscallResult::Complete(bytes_read, None)
        }
        PendingSyscall::VfsWrite { shm_id } => {
            let bytes_written = reply.tag as i64;

            // Clean up SHM
            shm::sys_shmunmap_for_task(caller_id, shm_id);

            PendingSyscallResult::Complete(bytes_written, None)
        }
        PendingSyscall::ExecveOpen { shm_id, argv_data, argv_offsets, argc } => {
            // Stage 1: VFS_OPEN completed - get vnode and read the ELF
            let vnode = reply.tag as i64;

            // Clean up path SHM
            shm::sys_shmunmap_for_task(caller_id, shm_id);

            // Check if VFS returned an error
            if vnode < 0 {
                return PendingSyscallResult::Complete(vnode, None); // Return the error (ENOENT, etc.)
            }

            // Create SHM for reading the ELF file (2MB for larger binaries like BusyBox)
            const EXECVE_SHM_SIZE: usize = 2 * 1024 * 1024;
            let data_shm_id = shm::sys_shmcreate(EXECVE_SHM_SIZE);
            if data_shm_id < 0 {
                // Close the vnode via VFS_CLOSE
                // For now, just return error (vnode will leak)
                return PendingSyscallResult::Complete(-12, None); // ENOMEM
            }
            let data_shm_id = data_shm_id as usize;

            // Grant VFS access to the SHM
            shm::sys_shmgrant(data_shm_id, VFS_TID.0);

            // Chain to stage 2: read the ELF file via VFS_READ_SHM
            // VFS expects: [handle, shm_id, shm_offset, max_len]
            let msg = Message::new(VFS_READ_SHM, [
                vnode as u64,             // vnode handle
                data_shm_id as u64,       // SHM ID for data
                0,                        // shm_offset = 0 (write at start of SHM)
                EXECVE_SHM_SIZE as u64,   // max bytes to read
            ]);

            PendingSyscallResult::Continue {
                new_pending: PendingSyscall::ExecveRead {
                    vnode: vnode as u64,
                    shm_id: data_shm_id,
                    argv_data,
                    argv_offsets,
                    argc,
                },
                target: VFS_TID,
                msg,
            }
        }
        PendingSyscall::ExecveRead { vnode, shm_id, argv_data, argv_offsets, argc } => {
            // Stage 2: VFS_READ_SHM completed - parse ELF and replace the task
            let bytes_read = reply.tag as i64;

            // Close the vnode (we don't need it anymore)
            // For simplicity, we do this synchronously by sending VFS_CLOSE
            // But since we can't do another IPC here easily, we'll skip closing for now
            // TODO: proper cleanup
            let _ = vnode;

            if bytes_read <= 0 {
                // Read failed
                shm::sys_shmunmap_for_task(caller_id, shm_id);
                return PendingSyscallResult::Complete(-5, None); // EIO
            }

            // SHM frames may NOT be physically contiguous, but we need contiguous
            // memory to parse the ELF. Allocate a temporary contiguous buffer.
            let num_pages = ((bytes_read as usize) + crate::mm::frame::PAGE_SIZE - 1)
                / crate::mm::frame::PAGE_SIZE;

            // Allocate contiguous frames for the temporary ELF buffer
            let temp_buffer_phys = match crate::mm::frame::alloc_frames_in_2mb_block(num_pages) {
                Some(addr) => addr,
                None => {
                    shm::sys_shmunmap_for_task(caller_id, shm_id);
                    return PendingSyscallResult::Complete(-12, None); // ENOMEM
                }
            };

            // Copy SHM (non-contiguous frames) to contiguous buffer
            let copied = shm::copy_shm_to_buffer(
                shm_id,
                temp_buffer_phys.0 as *mut u8,
                bytes_read as usize
            );

            if copied < bytes_read as usize {
                // Copy failed, free temp buffer
                for i in 0..num_pages {
                    crate::mm::frame::free_frame(crate::mm::frame::PhysAddr::new(
                        temp_buffer_phys.0 + i * crate::mm::frame::PAGE_SIZE
                    ));
                }
                shm::sys_shmunmap_for_task(caller_id, shm_id);
                return PendingSyscallResult::Complete(-5, None); // EIO
            }

            // Now we have contiguous ELF data in temp_buffer_phys
            let elf_data = core::slice::from_raw_parts(temp_buffer_phys.0 as *const u8, bytes_read as usize);

            // Replace the current task with the new ELF, passing the full argv
            let result = crate::sched::replace_task_with_elf(caller_id, elf_data, &argv_data, &argv_offsets, argc);

            // Free the temporary buffer (always, regardless of success/failure)
            for i in 0..num_pages {
                crate::mm::frame::free_frame(crate::mm::frame::PhysAddr::new(
                    temp_buffer_phys.0 + i * crate::mm::frame::PAGE_SIZE
                ));
            }

            // Clean up SHM
            shm::sys_shmunmap_for_task(caller_id, shm_id);

            match result {
                Ok(entry_point) => {
                    // Set the entry point in the task's saved context
                    let task = &TASKS[caller_id.0];
                    let ctx = task.kernel_stack_top as *mut ExceptionContext;
                    if !ctx.is_null() {
                        (*ctx).elr = entry_point as u64;
                        // execve doesn't return on success - execution starts fresh
                    }

                    // Return 0 but note: caller won't actually see this because
                    // execution will start from the new entry point
                    PendingSyscallResult::Complete(0, None)
                }
                Err(e) => {
                    PendingSyscallResult::Complete(e, None)
                }
            }
        }
        PendingSyscall::MmapFile { vaddr, len, vnode: _, shm_id } => {
            // File-backed mmap: VFS_READ_SHM completed - copy data to mapped pages
            let bytes_read = reply.tag as i64;

            if bytes_read < 0 {
                // Read failed - cleanup (pages already mapped, will be zero-filled)
                shm::sys_shmunmap_for_task(caller_id, shm_id);
                // Return error - caller should munmap the region
                return PendingSyscallResult::Complete(bytes_read, None);
            }

            // Get SHM physical address (source of file data)
            let shm_phys = shm::get_shm_phys_addr(shm_id);
            if shm_phys != 0 && bytes_read > 0 {
                let caller_task = &TASKS[caller_id.0];
                let addr_space = match &caller_task.addr_space {
                    Some(aspace) => aspace,
                    None => {
                        shm::sys_shmunmap_for_task(caller_id, shm_id);
                        return PendingSyscallResult::Complete(-1, None);
                    }
                };

                // Copy data from SHM to mapped region, page by page
                // We use physical addresses to avoid permission issues (user pages may be read-only)
                let copy_len = if (bytes_read as usize) < len { bytes_read as usize } else { len };
                let mut copied = 0usize;

                while copied < copy_len {
                    let page_vaddr = vaddr + copied;
                    let page_offset = page_vaddr & 0xFFF; // Offset within the page
                    let bytes_this_page = core::cmp::min(
                        crate::mm::frame::PAGE_SIZE - page_offset,
                        copy_len - copied
                    );

                    // Get physical address of this page
                    if let Some(phys_addr) = addr_space.virt_to_phys(page_vaddr) {
                        // Copy using physical address (kernel has identity mapping)
                        core::ptr::copy_nonoverlapping(
                            (shm_phys + copied) as *const u8,
                            phys_addr.0 as *mut u8,
                            bytes_this_page,
                        );
                    }

                    copied += bytes_this_page;
                }
            }

            // Clean up SHM
            shm::sys_shmunmap_for_task(caller_id, shm_id);

            // Return the virtual address of the mapped region
            PendingSyscallResult::Complete(vaddr as i64, None)
        }
    }
}

/// Wake a task from IPC blocked state (used by scheduler)
///
/// This is called when a task needs to be woken after IPC completion.
pub fn wake_task(task_id: TaskId) {
    if !is_valid_task(task_id) {
        return;
    }

    unsafe {
        let task = &mut TASKS[task_id.0];
        match task.state {
            TaskState::SendBlocked | TaskState::RecvBlocked | TaskState::ReplyBlocked => {
                task.state = TaskState::Ready;
                sched::enqueue_task(task_id);
            }
            _ => {}
        }
    }
}
