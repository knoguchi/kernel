# Journal: Debugging Kernel Stack Overflow in Spawn

**Date:** 2026-01-29

## Problem Statement

The kernel would freeze when trying to spawn userland applications via the `sys_spawn` syscall. The init process would call spawn with an embedded ELF binary, but execution would hang without any output or crash.

Key observation: Spawning worked when called directly from kernel initialization (e.g., creating the init, console, and VFS tasks), but failed when triggered from a syscall context.

## Investigation Process

### Phase 1: Tracing the Hang Location

Added debug prints throughout `create_user_task_from_elf()` to narrow down where execution stopped:

```rust
println!("[create_task_elf] START: {}", name);
println!("[create_task_elf] ELF parsed OK");
println!("[create_task_elf] Calling new_for_user...");
```

Discovery: The function `AddressSpace::new_for_user()` would complete (printed "DONE" at the end), but code immediately after the call never executed.

### Phase 2: Suspecting Return Value Issues

Added direct UART writes (bypassing any buffering) at the very end of `new_for_user()`:

```rust
unsafe {
    let uart = 0x0900_0000 as *mut u8;
    core::ptr::write_volatile(uart, b'[');
    core::ptr::write_volatile(uart, b'R');
    core::ptr::write_volatile(uart, b'E');
    core::ptr::write_volatile(uart, b'T');
    core::ptr::write_volatile(uart, b']');
}
```

Result: `[RET]` printed successfully, confirming the function completed but something failed during return.

### Phase 3: Stack Pointer Analysis

Added stack pointer tracking before and after the function call:

```rust
let sp_before: usize;
unsafe { core::arch::asm!("mov {}, sp", out(reg) sp_before); }

let addr_space_result = unsafe { AddressSpace::new_for_user() };

let sp_after: usize;
unsafe { core::arch::asm!("mov {}, sp", out(reg) sp_after); }

println!("SP before: {:#x}, after: {:#x}, diff: {}",
         sp_before, sp_after, sp_before - sp_after);
```

**Key finding:** Stack usage was approximately 65KB!

### Phase 4: Identifying the Root Cause

Examined `AddressSpace` struct in `kernel/src/mm/address_space.rs`:

```rust
pub struct AddressSpace {
    ttbr0: PhysAddr,                                          // 8 bytes
    l2_tables: [Option<PhysAddr>; MAX_L1_ENTRIES],           // 64 bytes
    l3_tables: [Option<PhysAddr>; MAX_L1_ENTRIES * ENTRIES_PER_TABLE], // ~32KB!
}
```

The `l3_tables` array had 2048 entries (4 L1 entries * 512 L2 entries), each being 16 bytes (`Option<PhysAddr>`), totaling ~32KB.

Checked `KERNEL_STACK_SIZE` in `kernel/src/sched/task.rs`:

```rust
pub const KERNEL_STACK_SIZE: usize = 16 * 1024;  // Only 16KB!
```

**Root cause confirmed:** Trying to return a ~32KB struct (plus ~33KB function overhead) with only 16KB of stack space caused a stack overflow.

## Why It Worked During Boot

During kernel initialization, tasks are created using the kernel's main stack, which is much larger (set up by the bootloader/UEFI). But when spawning via syscall, execution happens on the per-task kernel stack, which was only 16KB.

## The Fix

### Primary Fix: Increase Kernel Stack Size

```rust
// kernel/src/sched/task.rs
/// Kernel stack size per task (128KB - needs to be large due to AddressSpace struct ~32KB)
pub const KERNEL_STACK_SIZE: usize = 128 * 1024;
```

### Optimization: Reduce AddressSpace Struct Size

The `l3_tables` array was tracking L3 tables for the entire 4GB address space (L1[0-3]), but we only need to track L3 tables for L1[0] (user space region 0x00000000-0x40000000). The kernel RAM region (L1[1]) uses 2MB blocks and doesn't need L3 table tracking.

```rust
// kernel/src/mm/address_space.rs

/// Only track L3 tables for L1[0] (user space), not for kernel RAM (L1[1-3])
/// This reduces struct size from ~32KB to ~8KB
const L3_TABLES_COUNT: usize = ENTRIES_PER_TABLE; // 512 entries for L1[0] only

pub struct AddressSpace {
    ttbr0: PhysAddr,
    l2_tables: [Option<PhysAddr>; MAX_L1_ENTRIES],
    l3_tables: [Option<PhysAddr>; L3_TABLES_COUNT],  // Now ~8KB instead of ~32KB
}
```

## Cleanup

After fixing the issue, removed all debug prints from:
- `kernel/src/sched/mod.rs` - `create_user_task_from_elf()`
- `kernel/src/syscall.rs` - `sys_spawn()`
- `kernel/src/mm/address_space.rs` - `new_for_user()`

## Lessons Learned

1. **Stack overflow symptoms can be subtle** - No crash, no error message, just a hang. The function completes but corrupts the return path.

2. **Different execution contexts have different stack sizes** - Code that works during boot may fail in syscall context due to smaller per-task stacks.

3. **Large structs on the stack are dangerous** - The 32KB `AddressSpace` struct was returned by value, consuming stack space for both the return value and any local variables.

4. **Direct UART writes bypass all abstractions** - When debugging hangs, `write_volatile` to the UART base address is the most reliable way to trace execution.

5. **Stack pointer tracking reveals hidden costs** - Inline assembly to read SP before/after calls quickly reveals stack usage.

## Test Results

After the fix:
```
--- Spawn Test ---
Embedded hello.elf size:5568 bytes
ELF magic verified
Spawning hello...

--- Spawn successful! -[hello] I was spawned!
Child PID: [hello] My PID is: 44
[hello] Goodbye!
```

## Files Modified

| File | Change |
|------|--------|
| `kernel/src/sched/task.rs` | `KERNEL_STACK_SIZE`: 16KB -> 128KB |
| `kernel/src/mm/address_space.rs` | `l3_tables`: 2048 -> 512 entries |
| `kernel/src/sched/mod.rs` | Removed debug prints |
| `kernel/src/syscall.rs` | Removed debug prints |

## Future Considerations

- Consider allocating `AddressSpace` on the heap using `Box` to avoid large stack allocations
- Could reduce `KERNEL_STACK_SIZE` to 64KB now that struct is smaller (currently 128KB for safety)
- Add stack canaries or guard pages to detect stack overflow earlier
