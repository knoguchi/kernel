# The Auxv Order Bug: How AT_PAGESZ=0 Broke BusyBox mmap

**Date:** 2026-02-02

## Summary

BusyBox crashed on startup because its mprotect() call received address 0 instead of the
mmap return value (0x10000000). After extensive debugging, the root cause was traced to
the auxiliary vector (auxv) being written in the wrong order, causing musl libc to never
read AT_PAGESZ and leaving its internal `page_size` variable as 0.

## Symptom

BusyBox called:
```
mmap(0, 0x8000, PROT_NONE, ...) -> returns 0x10000000  (correct)
mprotect(0, 4096, PROT_READ|PROT_WRITE)  <- should be 0x10000000!
```

The kernel correctly set `ctx.gpr[0] = 0x10000000` in the mmap syscall handler, but
userspace received 0 in x0 for the next syscall.

## Investigation

### Initial Hypothesis: Context Save/Restore Bug
Spent hours tracing through:
- SAVE_CONTEXT_EL/RESTORE_CONTEXT macros in vectors.s
- ExceptionContext struct layout verification
- Debug prints at every stage of syscall handling
- IRQ interference checks

All showed the kernel was correctly saving 0x10000000 to context and restoring it.

### Key Observation: x3 = 0x10001000
The mprotect call showed:
- x0 = 0 (wrong)
- x3 = 0x10001000 = mmap_result + PAGE_SIZE (interesting!)

This suggested BusyBox was receiving the mmap result, doing calculations with it,
then passing the wrong value to mprotect.

### BusyBox Disassembly
Disassembled the mprotect wrapper at 0x4bafdc:
```asm
4bafe0: adrp    x4, 0x521000
4baff0: ldr     x4, [x4, #0xb80]     // x4 = page_size from .bss
4baffc: neg     x4, x4               // x4 = -page_size (for alignment mask)
4bb004: and     x0, x3, x4           // x0 = addr & ~(page_size-1)
```

If `page_size = 0`, then:
- `neg 0` = 0
- `and addr, 0` = 0

The wrapper zeroes the address when page_size is 0!

### Root Cause: Auxv Order
musl reads AT_PAGESZ from the auxiliary vector during startup. In the kernel's
`create_user_task_from_elf()`:

```rust
// WRONG ORDER - AT_NULL was first in array
let auxv: [(u64, u64); 11] = [
    (AT_NULL, 0),       // Index 0
    (AT_PAGESZ, 4096),  // Index 3
    ...
];

// Written with iter().rev()
for (key, val) in auxv.iter().rev() {
    push(val); push(key);
}
```

Since we iterate in reverse, AT_NULL (index 0) was written LAST, meaning it ended
up at the LOWEST address in memory. But auxv is read from low to high addresses.

musl saw: `AT_NULL` at the start → stopped reading → never saw `AT_PAGESZ`

## The Fix

Reorder the array so AT_NULL is at index 10 (last):
```rust
let auxv: [(u64, u64); 11] = [
    (AT_PHDR, phdr_addr as u64),
    (AT_PHENT, phent),
    (AT_PHNUM, phnum),
    (AT_PAGESZ, 4096),
    (AT_ENTRY, user_entry_point as u64),
    (AT_UID, 0),
    (AT_EUID, 0),
    (AT_GID, 0),
    (AT_EGID, 0),
    (AT_RANDOM, random_vaddr as u64),
    (AT_NULL, 0),  // Must be LAST - terminates the auxv array
];
```

After `iter().rev()`, AT_NULL is written first (highest address), and the array
terminates correctly at the low-address end.

## Lessons Learned

1. **Read the source code** - Disassembling the mprotect wrapper immediately
   revealed the page_size issue, which could have been found much earlier.

2. **Trust intermediate values** - x3 = 0x10001000 was a huge clue. The mmap
   return value WAS being received; the problem was in how it was being used.

3. **Auxv order matters** - The auxiliary vector must be terminated by AT_NULL
   at the highest address when read sequentially. When writing in reverse order,
   put AT_NULL last in the source array.

4. **musl libc internals** - musl initializes `page_size` from AT_PAGESZ during
   `__init_libc()`. If it's 0 or missing, alignment calculations fail silently.

## Files Modified

- `kernel/src/sched/mod.rs` - Reordered auxv array (one-line fix!)

## Result

After the fix, mprotect receives the correct address:
```
mprotect(0x10001000, 4096, PROT_READ|PROT_WRITE)
```

BusyBox progresses further but now hits an alignment fault at 0x100033e8, which
is a separate issue to debug.
