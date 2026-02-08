# BusyBox Interactive Shell Working

**Date:** 2026-02-07

## Summary

BusyBox now runs interactively on Kenix! The shell displays a `/ #` prompt and
accepts commands. This was achieved by implementing SIMD alignment fault emulation
in the kernel and adding proper ppoll support for blocking on stdin.

## Problem

BusyBox was crashing with alignment faults due to musl libc's SIMD-optimized
memset/memcpy routines. Even after loading successfully, the shell would exit
immediately because ppoll returned 0 (no events) instead of waiting for input.

## Solution

### 1. SIMD Alignment Fault Emulation

Instead of requiring BusyBox to be recompiled with `-mstrict-align`, we added
instruction emulation in the kernel's exception handler. When an alignment fault
occurs on a SIMD instruction, the kernel:

1. Reads the faulting instruction
2. Decodes it (GPR or SIMD, load or store, register size)
3. Performs the memory access byte-by-byte (no alignment required)
4. Advances PC and returns to user space

Emulated instruction types:
- **GPR**: STR/LDR immediate, STUR/LDUR, STP/LDP, pre/post-indexed
- **SIMD**: STUR/LDUR, STP/LDP, STR/LDR immediate, STR/LDR register
- Supports all sizes: B (8-bit), H (16-bit), S (32-bit), D (64-bit), Q (128-bit)

Key code in `kernel/src/exception/mod.rs`:

```rust
fn try_emulate_alignment_fault(ctx: &mut ExceptionContext) -> bool {
    let instr = unsafe { *(ctx.elr as *const u32) };

    // Try each instruction type
    if try_emulate_stur_simd(ctx, instr) { return true; }
    if try_emulate_ldur_simd(ctx, instr) { return true; }
    if try_emulate_stp_simd(ctx, instr) { return true; }
    // ... more handlers

    false
}
```

### 2. ppoll Syscall Implementation

The shell needs to wait for keyboard input. Implemented proper ppoll that:
- Checks if stdin (fd 0) is in the poll set
- If UART has data, returns immediately with POLLIN
- If no data, busy-waits until UART receives a character
- Returns 1 with POLLIN set when data arrives

```rust
fn sys_ppoll(fds: usize, nfds: usize) -> i64 {
    // Check if polling stdin
    if polling_stdin {
        loop {
            let has_data = /* check UART_FR_RXFE */;
            if has_data {
                // Set POLLIN and return
                return 1;
            }
            core::hint::spin_loop();
        }
    }
    0
}
```

### 3. Additional Syscalls

Added stubs for syscalls BusyBox calls during startup:
- `getpgid` (155) - Returns task ID as process group
- `setpgid` (154) - Stub, returns success
- `fstatat` (79) - Returns ENOENT for now
- `sched_getaffinity` (123) - Returns CPU 0 mask
- `sched_setaffinity` (122) - Stub, returns success

## Why QEMU Faults on Unaligned SIMD

Research revealed interesting findings:

1. **SCTLR_EL1.A is not enough** - We already disable alignment checking, but
   SIMD instructions have separate alignment requirements

2. **MMU must be enabled** - ARM64 requires MMU enabled for unaligned SIMD to
   work. We have MMU enabled.

3. **QEMU is stricter than real hardware** - Real Cortex-A72 likely handles
   unaligned SIMD gracefully. QEMU's emulation appears more strict.

4. **Memory type matters** - Device memory always requires alignment. Our user
   pages use Normal memory type (MATTR_NORMAL).

The emulation provides a safety net that works regardless of the underlying
hardware's strictness.

## Testing

```
/ # echo hello
hello
/ # exit
busybox exited status=0
```

Note: Characters appear doubled (`eecchhoo`) because both the kernel console
and BusyBox echo input. This is a minor cosmetic issue.

## Files Modified

- `kernel/src/exception/mod.rs` - SIMD alignment fault emulation (~600 lines)
- `kernel/src/syscall.rs` - ppoll, getpgid, setpgid, fstatat, sched_* syscalls
- `Makefile` - Removed `make run` UEFI target (not a goal anymore)

## Performance

The alignment emulation only triggers during musl's memory initialization (first
few hundred instructions). Normal execution doesn't hit alignment faults, so
there's no ongoing performance impact.

## What's Next

- Fix double-echo (terminal mode handling)
- Implement more BusyBox applets (ls, cat, etc. need working getdents, open)
- Proper blocking I/O instead of busy-wait in ppoll

## References

- [ARM AArch64 Alignment](https://devblogs.microsoft.com/oldnewthing/20220810-00/?p=106958)
- [ARM SoC Alignment Notes](https://cwshu.github.io/arm_virt_notes/notes/misc/alignment_fault.html)
- [seL4 Alignment Issue](https://github.com/seL4/seL4/issues/1339)
