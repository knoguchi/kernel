//! Synchronous message-passing IPC for Kenix microkernel
//!
//! This module implements L4-style synchronous IPC with:
//! - `send`: Block until receiver accepts message
//! - `recv`: Block until sender sends message
//! - `call`: Send message and block for reply (RPC)
//! - `reply`: Reply to a caller and return immediately

use crate::sched::task::{
    TaskId, TaskState, Message, TASKS, MAX_TASKS,
    enqueue_sender, find_sender, remove_from_sender_queue,
};
use crate::sched::{self, current};
use crate::exception::ExceptionContext;

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

        // Set up return values in caller's saved context
        set_call_return(caller_id, &msg);

        // Wake up caller
        caller_task.state = TaskState::Ready;
        sched::enqueue_task(caller_id);

        // Clear our caller field
        let server_task = &mut TASKS[server_id.0];
        server_task.ipc.caller = None;
    }

    IPC_OK
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
