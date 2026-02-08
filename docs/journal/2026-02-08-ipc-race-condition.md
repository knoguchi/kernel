# IPC Race Condition: Second ls Command Freezes

**Date:** 2026-02-08

## Summary

Running `ls` twice in the BusyBox shell caused the second invocation to freeze after
printing just "." - the directory listing never completed. The root cause was a race
condition in the IPC subsystem where `sys_recv` incorrectly woke up senders using the
`sys_call` (RPC) pattern, causing the reply to be lost.

## Symptom

```
/ # ls
disk       hello.txt  test.txt    <- First ls works
/ # ls
.                                  <- Second ls prints "." and freezes
```

The second `ls` would stat "/" twice but never call `openat()` to open the directory.
This suggested the stat result was being corrupted or lost.

## Investigation

### Initial Debugging

Added trace output to kernel syscalls and VFS operations. The trace revealed:

**First ls (works):**
```
[syscall] t=8 num=79  (fstatat)
[vfs:stat] path="/"
[reply] to t=8 state=ReplyBlocked  <- Correct state!
[stat] mode=40755                   <- Directory mode written
[syscall] t=8 num=56  (openat)     <- Opens directory
```

**Second ls (breaks):**
```
[syscall] t=8 num=79  (fstatat)
[vfs:stat] path="/"
[reply] to t=8 state=Ready         <- WRONG STATE!
[syscall] t=8 num=79  (fstatat)    <- No stat result, tries again
```

The critical difference: when VFS replied to the first stat of the second `ls`, task 8
was in `Ready` state instead of `ReplyBlocked`. This caused the reply to fail silently.

### Tracing the State Transition

Added debug to `sys_call` and `sys_reply`:

```
[sys_call] t=8 dest=3 dest_state=RecvBlocked  <- First ls: VFS waiting
[sys_call] t=8 dest=3 dest_state=Ready        <- Second ls: VFS busy!
```

The difference: in the first `ls`, VFS was already `RecvBlocked` (waiting for messages).
In the second `ls`, VFS was `Ready` (just finished processing something).

When the destination is not `RecvBlocked`, `sys_call` takes a different code path:
1. Sender goes `SendBlocked`
2. Enqueues in receiver's sender queue
3. Context switches

### Root Cause: sys_recv State Bug

In `sys_recv`, when the receiver (VFS) found a waiting sender:

```rust
// BUG: Always woke sender, even for sys_call pattern
if sender_task.state == TaskState::SendBlocked {
    sender_task.state = TaskState::Ready;  // WRONG!
    sched::enqueue_task(sender_id);
}
```

This caused a race condition:
1. Task 8 calls `sys_call`, goes `SendBlocked`
2. VFS receives, sets task 8 to `Ready`, enqueues it
3. Task 8 runs, sees state is `Ready` not `ReplyBlocked`
4. Task 8 sets itself to `ReplyBlocked`, blocks again
5. VFS processes and tries to reply
6. **But VFS may reply BEFORE step 4 completes!**
7. Reply fails because task 8 wasn't `ReplyBlocked` at that moment

The window between VFS setting task 8 to `Ready` and task 8 transitioning to
`ReplyBlocked` was the race condition.

## The Fix

### Fix 1: sys_recv - Keep RPC Senders Blocked

Check if the sender is using `sys_call` (by checking `reply_to.is_some()`). If so,
transition to `ReplyBlocked` instead of `Ready`, and don't enqueue:

```rust
if sender_task.state == TaskState::SendBlocked {
    if sender_task.ipc.reply_to.is_some() {
        // sys_call pattern: sender should wait for reply
        sender_task.state = TaskState::ReplyBlocked;
        // Don't enqueue - will be woken by reply
    } else {
        // sys_send pattern: sender can continue
        sender_task.state = TaskState::Ready;
        sched::enqueue_task(sender_id);
    }
}
```

### Fix 2: sys_call - Check if Reply Already Delivered

After waking from `SendBlocked`, check if the reply was already delivered (indicated
by `reply_to` being cleared by `sys_reply`):

```rust
// After context_switch_blocking:
if caller_task.ipc.reply_to.is_some() {
    // Reply not yet delivered - wait for it
    if caller_task.state != TaskState::ReplyBlocked {
        caller_task.state = TaskState::ReplyBlocked;
    }
    sched::context_switch_blocking(ctx);
}
// If reply_to is None, reply was already delivered, continue
```

## Correct Flow After Fix

1. Task 8 calls `sys_call`, VFS is `Ready` (not `RecvBlocked`)
2. Task 8 goes `SendBlocked`, enqueues in VFS's sender queue
3. Context switch to VFS
4. VFS calls `recv`, finds task 8 in queue
5. VFS sees task 8 has `reply_to` set, transitions to `ReplyBlocked` (not `Ready`)
6. VFS processes request
7. VFS calls `reply`
8. `sys_reply` finds task 8 in `ReplyBlocked`, delivers reply, wakes task 8
9. Task 8 resumes in `sys_call`, `reply_to` is `None`, returns immediately

No race condition: task 8 stays blocked until the reply is delivered.

## Lessons Learned

1. **IPC state machines are subtle** - The interaction between `SendBlocked`,
   `ReplyBlocked`, and `Ready` states must be carefully coordinated across
   `sys_send`, `sys_call`, `sys_recv`, and `sys_reply`.

2. **sys_call vs sys_send semantics** - `sys_call` (RPC) requires the sender to
   stay blocked until the reply arrives. `sys_send` (fire-and-forget) can wake
   the sender immediately after delivery.

3. **Race windows matter** - Even a small window where state is inconsistent can
   cause intermittent failures. The bug only manifested when VFS was busy (not
   `RecvBlocked`) when the second `ls` started.

4. **Debug output saved the day** - Tracing state at key points (sender state in
   `sys_reply`, destination state in `sys_call`) immediately revealed the bug.

## Files Modified

- `kernel/src/ipc.rs`
  - `sys_recv`: Keep `sys_call` senders in `ReplyBlocked` instead of `Ready`
  - `sys_call`: Check `reply_to` to see if reply was already delivered

## Result

Multiple `ls` commands now work correctly:

```
/ # ls
disk       hello.txt  test.txt
/ # ls
disk       hello.txt  test.txt
/ # ls /disk
BIN        DATA       HELLO.TXT  TEST.TXT
```
