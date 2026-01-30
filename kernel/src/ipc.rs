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
                // Set sender's return value (IPC_OK = 0 in x0)
                let sender_ctx = sender_task.kernel_stack_top as *mut ExceptionContext;
                if !sender_ctx.is_null() {
                    (*sender_ctx).gpr[0] = IPC_OK as u64;
                }
                sender_task.state = TaskState::Ready;
                sched::enqueue_task(sender_id);
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

        // Context switch
        sched::context_switch_blocking(ctx);

        // Woken up after send completed, now wait for reply
        // The sender may have transitioned us directly to ReplyBlocked,
        // or we need to transition now
        if caller_task.state != TaskState::ReplyBlocked {
            caller_task.state = TaskState::ReplyBlocked;
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
        let (x0_val, x1_opt) = complete_pending_syscall(caller_id, pending, &msg);

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

        // Clear our caller field
        let server_task = &mut TASKS[server_id.0];
        server_task.ipc.caller = None;
    }

    IPC_OK
}

/// Complete a pending syscall using the IPC reply from a server
///
/// Returns (x0_value, optional_x1_value) for the syscall return
unsafe fn complete_pending_syscall(caller_id: TaskId, pending: PendingSyscall, reply: &Message) -> (i64, Option<i64>) {
    match pending {
        PendingSyscall::None => {
            // No pending syscall, use reply tag directly
            (reply.tag as i64, None)
        }
        PendingSyscall::PipeCreate => {
            let pipe_id = reply.tag as i64;

            // Check if pipeserv returned an error
            if pipe_id < 0 {
                return (pipe_id, Some(pipe_id)); // Both fds are error
            }

            let caller_task = &mut TASKS[caller_id.0];

            // Allocate read fd
            let read_fd = match caller_task.alloc_fd() {
                Some(fd) => fd,
                None => return (-12, Some(-12)), // ENOMEM
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
                    return (-12, Some(-12)); // ENOMEM
                }
            };
            caller_task.fds[write_fd] = FileDescriptor {
                kind: FdKind::PipeWrite,
                flags: FdFlags::write_only(),
                server: TaskId(6), // PIPESERV_TID
                handle: pipe_id as u64,
            };

            (read_fd as i64, Some(write_fd as i64))
        }
        PendingSyscall::PipeRead { user_buf, max_len: _, shm_id } => {
            let bytes_read = reply.tag as i64;

            if bytes_read > 0 {
                // Get physical address of SHM (kernel has identity mapping)
                let shm_phys = shm::get_shm_phys_addr(shm_id);
                if shm_phys != 0 {
                    // We need to copy to the caller's address space, but we're
                    // currently running in the server's context. Temporarily
                    // switch to the caller's page table for the copy.
                    let caller_task = &TASKS[caller_id.0];
                    let caller_ttbr0 = caller_task.page_table.0 as u64;

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

            (bytes_read, None)
        }
        PendingSyscall::PipeWrite { shm_id } => {
            let bytes_written = reply.tag as i64;

            // Clean up: unmap from caller's space if mapped
            shm::sys_shmunmap_for_task(caller_id, shm_id);

            (bytes_written, None)
        }
        PendingSyscall::PipeClose => {
            // Just return success
            (0, None)
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
                return (vnode, None); // Return the error code
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
            (fd as i64, None)
        }
        PendingSyscall::VfsStat { statbuf } => {
            let result = reply.tag as i64;

            if result == 0 {
                // VFS returns stat info in reply.data
                // data[0] = size, data[1] = mode, data[2] = inode
                let caller_task = &TASKS[caller_id.0];
                let caller_ttbr0 = caller_task.page_table.0 as u64;

                // Switch to caller's address space to write stat
                let saved_ttbr0: u64;
                core::arch::asm!(
                    "mrs {0}, ttbr0_el1",
                    "msr ttbr0_el1, {1}",
                    "isb", "dsb sy", "tlbi vmalle1is", "dsb sy", "isb",
                    out(reg) saved_ttbr0,
                    in(reg) caller_ttbr0,
                );

                // Write minimal stat info
                let stat_ptr = statbuf as *mut u64;
                // Zero the whole structure first (128 bytes for stat)
                for i in 0..16 {
                    core::ptr::write_volatile(stat_ptr.add(i), 0);
                }
                // st_ino at offset 8
                core::ptr::write_volatile(stat_ptr.add(1), reply.data[2]);
                // st_mode at offset 16 (u32)
                core::ptr::write_volatile((statbuf + 16) as *mut u32, reply.data[1] as u32);
                // st_size at offset 48
                core::ptr::write_volatile((statbuf + 48) as *mut i64, reply.data[0] as i64);
                // st_blksize at offset 56
                core::ptr::write_volatile((statbuf + 56) as *mut i32, 4096);

                // Restore page table
                core::arch::asm!(
                    "msr ttbr0_el1, {0}",
                    "isb", "dsb sy", "tlbi vmalle1is", "dsb sy", "isb",
                    in(reg) saved_ttbr0,
                );
            }

            (result, None)
        }
        PendingSyscall::VfsGetdents { buf, count: _, shm_id } => {
            let bytes_read = reply.tag as i64;

            if bytes_read > 0 {
                // Copy from SHM to user buffer
                let shm_phys = shm::get_shm_phys_addr(shm_id);
                if shm_phys != 0 {
                    let caller_task = &TASKS[caller_id.0];
                    let caller_ttbr0 = caller_task.page_table.0 as u64;

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

            (bytes_read, None)
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
