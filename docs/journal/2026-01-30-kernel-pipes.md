# 2026-01-30: Userspace Pipes via IPC Reply Redirection

## Summary

Implemented userspace pipes using a pipeserv server and fixed a fundamental IPC bug that prevented syscall handlers from calling userspace servers. The fix uses "pending syscall" tracking where the kernel defers syscall completion until the server replies.

## The IPC Context Switch Bug

When a syscall handler calls `ipc::sys_call()`, it eventually calls `context_switch_blocking()` which:

1. Saves current context
2. Switches to another task
3. The other task (pipeserv) handles the request and replies
4. The blocked task is resumed via `switch_context_and_restore`

The problem: `switch_context_and_restore` ends with `ERET` which returns directly to userspace. All kernel code after `context_switch_blocking()` is never executed:

```rust
fn sys_read(...) {
    // ... setup ...
    let reply = ipc::sys_call(ctx, PIPESERV_TID, msg);  // Blocks here
    // THIS CODE NEVER RUNS - ERET goes straight to userspace
    let bytes_read = reply.tag;
    // Copy data to user buffer - never happens!
}
```

## The Solution: Pending Syscall Tracking

Instead of trying to continue after `sys_call()` returns, we:

1. **Before sending**: Record what syscall is pending and what needs to happen when reply arrives
2. **During IPC**: Block normally waiting for reply
3. **In sys_reply handler**: Check if the caller has a pending syscall and complete it

### PendingSyscall Enum

Added to `kernel/src/sched/task.rs`:

```rust
pub enum PendingSyscall {
    None,
    PipeCreate,
    PipeRead { user_buf: usize, max_len: usize, shm_id: usize },
    PipeWrite { shm_id: usize },
    PipeClose,
}
```

### Modified sys_reply

In `kernel/src/ipc.rs`, `sys_reply()` now checks for pending syscalls:

```rust
pub fn sys_reply(ctx: &mut ExceptionContext, to: TaskId, reply: Message) {
    // ... existing reply logic ...

    // Check if caller has pending syscall to complete
    let pending = core::mem::replace(&mut caller.pending_syscall, PendingSyscall::None);
    if !pending.is_none() {
        let (x0, x1_opt) = complete_pending_syscall(caller_id, pending, &reply);
        caller.context_ptr.as_mut().x0 = x0 as u64;
        if let Some(x1) = x1_opt {
            caller.context_ptr.as_mut().x1 = x1 as u64;
        }
    }
}
```

### Page Table Switch for Cross-Address-Space Copy

The tricky part: when pipeserv replies with data in shared memory, the kernel needs to copy that data to the caller's user buffer. But at this point we're running in pipeserv's address space, not the caller's.

Solution: Temporarily switch to the caller's page table:

```rust
fn complete_pending_syscall(caller_id: TaskId, pending: PendingSyscall, reply: &Message) -> (i64, Option<i64>) {
    match pending {
        PendingSyscall::PipeRead { user_buf, max_len: _, shm_id } => {
            let bytes_read = reply.tag as i64;
            if bytes_read > 0 {
                let shm_phys = shm::get_shm_phys_addr(shm_id);
                let caller_ttbr0 = TASKS[caller_id.0].page_table.0 as u64;

                let saved_ttbr0: u64;
                // Switch to caller's page table
                core::arch::asm!(
                    "mrs {0}, ttbr0_el1",
                    "msr ttbr0_el1, {1}",
                    "isb", "dsb sy", "tlbi vmalle1is", "dsb sy", "isb",
                    out(reg) saved_ttbr0, in(reg) caller_ttbr0,
                );

                // Copy data to caller's buffer
                core::ptr::copy_nonoverlapping(
                    shm_phys as *const u8,
                    user_buf as *mut u8,
                    bytes_read as usize
                );

                // Restore pipeserv's page table
                core::arch::asm!(
                    "msr ttbr0_el1, {0}",
                    "isb", "dsb sy", "tlbi vmalle1is", "dsb sy", "isb",
                    in(reg) saved_ttbr0,
                );
            }
            shm::sys_shmunmap_for_task(caller_id, shm_id);
            (bytes_read, None)
        }
        // ... other cases
    }
}
```

## Pipeserv Implementation

The userspace pipeserv server at `user/pipeserv/` handles:

- `PIPE_CREATE` (500) - Create new pipe, return pipe_id
- `PIPE_READ` (501) - Read from pipe via shared memory
- `PIPE_WRITE` (502) - Write to pipe via shared memory
- `PIPE_CLOSE` (503) - Close pipe end

Each pipe has a 4KB circular buffer managed entirely in userspace.

## Other Issues Fixed

### Frame Allocation Across 2MB Boundaries

pipeserv needed 66 frames (264KB) for its static pipe buffers. Added `alloc_frames_in_2mb_block()` to keep frames within the same 2MB block for page table mappings.

### MAX_CODE_FRAMES Too Small

Increased from 16 (64KB) to 128 (512KB) to accommodate larger userspace programs.

### FD Allocation Bug

Initial `sys_pipe()` allocated both fds before setting up FileDescriptors:

```rust
let read_fd = task.alloc_fd();   // Returns 3
let write_fd = task.alloc_fd();  // Returns 3 again! (slot still empty)
```

Fix: Set up each FileDescriptor immediately after allocation.

## Test Results

```
--- Pipe Test ---
[pipeserv] PIPE_CREATE
Created pipe: read_fd=3, write_fd=4
Wrote 12 bytes to pipe
Read from pipe: Hello, pipe!
Pipe closed
```

## Files Changed

### New Files
- `user/pipeserv/` - Userspace pipe server

### Modified Files
- `kernel/src/sched/task.rs` - Added `PendingSyscall` enum and field in Task
- `kernel/src/ipc.rs` - Added pending syscall completion in `sys_reply()`
- `kernel/src/shm.rs` - Added `get_shm_phys_addr()`, task-specific map/unmap
- `kernel/src/syscall.rs` - Syscalls set pending_syscall before IPC
- `kernel/src/sched/mod.rs` - Increased MAX_CODE_FRAMES, exported PendingSyscall

## Lessons Learned

1. **IPC reply redirection**: When syscall handlers need to call userspace servers, the completion logic must happen in the reply handler, not after the call returns.

2. **Page table awareness**: Kernel code runs in one address space but may need to access another task's memory. Temporary page table switches are necessary.

3. **Microkernel philosophy preserved**: Pipes remain in userspace as intended. The kernel just needed a small addition (pending syscall tracking) to enable this pattern.

## Status

- [x] Async notifications (SYS_NOTIFY, SYS_WAIT_NOTIFY)
- [x] Userspace pipes via pipeserv
- [x] VirtIO-net driver (netdev server)
