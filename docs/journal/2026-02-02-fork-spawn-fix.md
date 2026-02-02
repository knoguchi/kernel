# Fork and Spawn Crash Fix

**Date:** 2026-02-02

## Problem

Spawned tasks were crashing with a translation fault. Task 8 (spawned hello.elf)
would crash at ELR=0x808 trying to read from a garbage address.

## Investigation

The root cause was found through debugging:

1. Fork was getting the same `phys_base_2mb=0x40400000` as init
2. This is init's memory block, not a freshly allocated one
3. Something was freeing init's memory during fork cleanup

## Root Cause

The `clone_for_fork()` function in `mm/address_space.rs` was iterating over
`L1[0..l1_index(KERNEL_VIRT_OFFSET)]` to copy user mappings. Since
`KERNEL_VIRT_OFFSET = 0xC0000000` and `l1_index()` returns 3, this was
copying L1[0], L1[1], and L1[2].

The problem: **L1[1] contains the kernel RAM identity mapping** (512 x 2MB
blocks = 1GB of RAM at 0x40000000-0x80000000).

When fork tried to "copy" L1[1]:
1. It tried to allocate 512 x 2MB = 1GB for the child (ENOMEM)
2. If it had succeeded, it would add init's physical addresses to the
   builder's `data_pages` vector
3. When the builder was dropped (fork cleanup), it would free those pages
4. This freed init's code/data at 0x40400000
5. Next spawn got that "free" memory and wrote hello.elf there
6. But init's page tables still pointed to 0x40400000 - now corrupted

## Fix

### 1. Fix fork to only copy L1[0] (`mm/address_space.rs:522`)

```rust
// Before:
for l1_idx in 0..l1_index(KERNEL_VIRT_OFFSET) {  // L1[0], L1[1], L1[2]

// After:
for l1_idx in 0..1 {  // Only L1[0] contains user-specific data
```

Only L1[0] (0x00000000 - 0x40000000) contains user-specific data that needs
to be deep-copied. L1[1] (kernel RAM identity mapping) is already set up as
a shared mapping earlier in the function.

### 2. Fix exit to wake waiting parent (`sched/mod.rs:246-268`)

The `exit_current()` function wasn't:
- Saving the exit code to the task
- Waking up the parent if it was WaitBlocked (waiting in waitpid)

```rust
pub fn exit_current(&mut self, exit_code: i32) {
    if let Some(current_id) = self.current {
        unsafe {
            task::wake_blocked_senders(current_id);

            let task = &mut TASKS[current_id.0];
            task.exit_code = exit_code;  // Save exit code
            task.state = TaskState::Terminated;

            // Wake up parent if it's waiting for us
            if let Some(parent_id) = task.parent {
                let parent = &mut TASKS[parent_id.0];
                if parent.state == TaskState::WaitBlocked {
                    parent.state = TaskState::Ready;
                    enqueue_task(parent_id);
                }
            }

            self.current = None;
        }
    }
}
```

### 3. Fix sys_wait4 to retry after waking (`syscall.rs:1489-1561`)

The original `sys_wait4` would return ECHILD after being woken up. Changed
to loop and find the terminated child:

```rust
fn sys_wait4(...) -> i64 {
    unsafe {
        loop {
            // Find terminated child...
            if let Some(child_id) = found_child {
                // Reap and return
                return child_id.0 as i64;
            }

            if options & WNOHANG != 0 {
                return 0;
            }

            // Block waiting for child
            task.state = TaskState::WaitBlocked;
            sched::context_switch_blocking(ctx);
            // Loop back and try again
        }
    }
}
```

## Testing

All tests pass:

```
--- Fork Test ---
[parent] fork() returned child PID=8
[child] I'm the child! PID=8
[parent] Child exited with status=0

--- Spawn Test ---
[hello] I was spawned!
[hello] My PID is: 9
[hello] Goodbye!

=== Init complete ===
```

## Files Modified

- `kernel/src/mm/address_space.rs` - Fix clone_for_fork L1 range
- `kernel/src/sched/mod.rs` - Fix exit_current to save code and wake parent
- `kernel/src/syscall.rs` - Fix sys_wait4 retry loop, remove debug prints

## Lessons Learned

1. **Be careful with page table iteration ranges** - L1 indices map to 1GB
   regions, and the kernel's identity mapping at L1[1] should never be
   deep-copied.

2. **Resource cleanup on failure paths** - The AddressSpaceBuilder's Drop
   implementation was working correctly, but it was being given the wrong
   data (parent's addresses instead of newly allocated child addresses).

3. **waitpid needs cooperation** - The child's exit() must actively wake
   the waiting parent; it's not automatic.
