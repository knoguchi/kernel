# Address Space Memory Corruption: Second Command Freezes

**Date:** 2026-02-08

## Summary

Running `./ls` twice from `/disk/bin` caused the second invocation to complete but
then freeze (no shell prompt returned). The root cause was a bug in `AddressSpace::Drop`
that treated all data blocks as 2MB blocks, even when some were single 4KB pages from
fork. This caused massive over-freeing of physical memory, corrupting the parent shell's
page tables.

## Symptom

```
/disk/bin # ./ls
BUSYBOX  CAT  LS  SH  TEST
[1]+  Done                       ./ls
/disk/bin # ./ls
BUSYBOX  CAT  LS  SH  TEST
                                  <- No "[1]+ Done", no prompt, frozen
```

The second `ls` would execute correctly (output appeared) but the shell never regained
control. The system was stuck trying to switch back to the shell process.

## Investigation

### Initial Debugging

Added debug output to track context switches. The trace showed:

1. Task 8 (second `ls`) exits successfully
2. Parent task 7 (shell) is woken and enqueued
3. Scheduler dequeues task 7 and attempts to switch to it
4. System hangs during page table switch (TTBR0 update)

The hang occurred after setting TTBR0 to 0x41944000 (shell's page table).

### Scheduler Bug: Idle Task in Ready Queue

First discovery: the idle task (task 0) was being added to the ready queue during
normal context switches. When exiting task 8 tried to switch to the next task, it
dequeued the idle task instead of the parent (task 7).

**Fix:** Modified `context_switch` to skip enqueuing the idle task:

```rust
// Never enqueue idle task - it's the fallback when queue is empty
if task.state == TaskState::Running && id != self.idle_task {
    task.state = TaskState::Ready;
    self.enqueue(id);
}
```

### The Real Bug: Address Space Corruption

After fixing the scheduler, task 7 was being properly dequeued and scheduled. But
the system still froze during the TTBR0 switch. Added targeted debug:

```
[WARN] Freeing frame 0x41944000!
[WARN] Freeing frame 0x41944000!
...
[csb] 99 -> 7, ttbr0=0x41944000    <- Trying to use freed page table!
```

Task 7's page table (at 0x41944000) was being freed DURING task 8's exit!

### Tracing the Free

The address 0x41944000 was being freed when dropping an address space with these
data blocks:

```
[AS drop] data_block[4]=0x41804000
[AS drop] data_block[5]=0x41805000
...
```

These addresses (0x41804000, etc.) are NOT 2MB-aligned - they're single 4KB pages
allocated during `clone_for_fork`. But the `Drop` implementation was treating them
as 2MB blocks:

```rust
// BUG: Assumed all data_blocks were 2MB blocks
for block in self.data_blocks.iter() {
    if let Some(block_addr) = block {
        for i in 0..512 {  // WRONG! Not all blocks are 2MB
            free_frame(PhysAddr(block_addr.0 + i * 4096));
        }
    }
}
```

For `data_block[4]=0x41804000`, this would free:
- 0x41804000, 0x41805000, ..., up to 0x41A04000

The range 0x41804000 to 0x41A04000 includes 0x41944000 - the shell's page table!

### Root Cause

During `clone_for_fork`, both 4KB pages (for L3 table entries) and 2MB blocks
(for block mappings) were pushed to the same `data_pages` vector:

```rust
// 4KB page for L3 mapping
builder.data_pages.push(child_paddr);     // e.g., 0x41804000

// 2MB block for block mapping
builder.data_pages.push(child_paddr_2mb); // e.g., 0x42000000
```

These were transferred to `data_blocks` in the final `AddressSpace`, but the `Drop`
impl couldn't distinguish between them.

## The Fix

Modified `Drop for AddressSpace` to check alignment:

```rust
impl Drop for AddressSpace {
    fn drop(&mut self) {
        for block in self.data_blocks.iter() {
            if let Some(block_addr) = block {
                if (block_addr.0 & (BLOCK_SIZE_2MB - 1)) == 0 {
                    // 2MB-aligned: it's a 2MB block, free all 512 pages
                    for i in 0..512 {
                        free_frame(PhysAddr(block_addr.0 + i * 4096));
                    }
                } else {
                    // Not 2MB-aligned: it's a single 4KB page
                    free_frame(*block_addr);
                }
            }
        }
        // ... free L3, L2, L1 tables ...
    }
}
```

This uses the physical address alignment to determine whether each entry is a
2MB block (aligned) or a 4KB page (not aligned).

## Additional Fixes in This Session

### Relative Path Resolution in execve

`./ls` from `/disk/bin` would fail with "not found" because `sys_execve` didn't
resolve relative paths using the current working directory.

**Fix:** Added path resolution to `sys_execve`:
- Strip `./` prefix if present
- For relative paths, prepend the task's `cwd`
- Construct absolute path before sending to VFS

### Scheduler: Idle Task Exclusion

The idle task was being added to the ready queue on every context switch, which
caused it to be dequeued instead of actual runnable tasks.

**Fix:** Skip enqueuing task 0 (idle) in `context_switch`.

## Correct Flow After Fixes

1. Shell (task 7) forks to create task 8
2. `clone_for_fork` allocates new 4KB pages, stores in `data_pages`
3. Task 8 does `execve`, old address space is dropped
4. `Drop` correctly frees only the actual 4KB pages (not 512 pages each)
5. Task 8 runs `ls`, prints output, exits
6. Scheduler wakes task 7, enqueues it
7. `exit_with_switch` dequeues task 7 (not idle task)
8. TTBR0 switch to 0x41944000 succeeds (page table intact!)
9. Shell prints `[1]+ Done` and shows prompt

## Lessons Learned

1. **Heterogeneous collections need metadata** - When storing items of different
   sizes in the same array, you need a way to distinguish them. Using alignment
   as a discriminator works here but is fragile.

2. **Debug prints at the right level** - Printing "Freeing frame 0x41944000"
   immediately revealed the corruption source.

3. **Multiple bugs can mask each other** - The scheduler bug (idle in queue)
   made the memory corruption harder to diagnose because parent wake-up was
   already broken.

4. **Physical memory corruption is insidious** - The freed pages weren't
   immediately reused, so the first `ls` worked. Only when enough allocations
   happened did the corruption manifest.

## Files Modified

- `kernel/src/mm/address_space.rs`
  - `Drop for AddressSpace`: Check alignment to determine block size

- `kernel/src/sched/mod.rs`
  - `context_switch`: Don't enqueue idle task
  - `exit_current`: Clean up debug output

- `kernel/src/syscall.rs`
  - `sys_execve`: Add relative path resolution using cwd

## Result

Multiple commands now work correctly from any directory:

```
/disk/bin # ./ls
BUSYBOX  CAT  LS  SH  TEST
[1]+  Done                       ./ls
/disk/bin # ./ls
BUSYBOX  CAT  LS  SH  TEST
[1]+  Done                       ./ls
/disk/bin # ./ls
BUSYBOX  CAT  LS  SH  TEST
[1]+  Done                       ./ls
```
