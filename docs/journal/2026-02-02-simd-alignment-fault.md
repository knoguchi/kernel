# SIMD Alignment Fault: Why BusyBox Crashes on AArch64

**Date:** 2026-02-02

## Summary

BusyBox and toybox crash with alignment faults (SIGBUS) when running on Kenix.
The root cause is that musl libc's memset/memcpy routines use SIMD instructions
(`stp q0, q0`) that require 16-byte alignment. These instructions fault on AArch64
regardless of the SCTLR_EL1.A alignment checking bit.

## Symptom

After successfully loading BusyBox via execve, it crashes almost immediately:

```
USER ALIGNMENT FAULT (SIGBUS)!
The instruction at 0x00000000004019f0 requires aligned access
but address 0x0000000010000fd8 is not properly aligned
Faulting address: 0x0000000010000fd8
Fault: Alignment fault (write)
```

The faulting address `0x10000fd8` is 8-byte aligned but not 16-byte aligned.

## Investigation

### Initial Hypothesis: SCTLR.A Not Disabled

First checked if alignment checking was enabled in SCTLR_EL1:
```rust
sctlr &= !SCTLR_A;   // Disable alignment check for EL1
sctlr &= !SCTLR_SA;  // Disable stack alignment check for EL1
sctlr &= !SCTLR_SA0; // Disable stack alignment check for EL0
```

These bits were correctly cleared, but the fault persisted.

### Tried CPU "max"

Changed QEMU from `-cpu cortex-a72` to `-cpu max` to enable all CPU features.
The crash location changed slightly but the alignment fault remained.

### Disassembly Analysis

Disassembled the crash location and found musl's memset using:
```asm
stp q0, q0, [x0]     ; Store pair of 128-bit SIMD registers
```

The `stp q0, q0` instruction stores two 128-bit (16-byte) values and **requires**
the target address to be 16-byte aligned on all AArch64 implementations.

### Research Findings

Key findings from ARM documentation and community reports:
1. SCTLR_EL1.A only affects basic load/store instructions
2. SIMD store pairs (`stp qN, qN`) **always** require 16-byte alignment
3. This is architectural - cannot be disabled on any AArch64 implementation
4. x86/x86_64 handles unaligned SIMD gracefully (penalty but no fault)
5. Solution: compile with `-mstrict-align` or `-mno-neon`

## Root Cause

musl libc is compiled with SIMD optimizations for memset/memcpy. These use
`stp q0, q0` for fast memory operations. When the heap allocator returns an
8-byte aligned (but not 16-byte aligned) address, the optimized memset faults.

The issue is NOT in our kernel - it's in how the BusyBox binary was compiled.
Alpine's BusyBox uses musl with SIMD optimizations enabled.

## Verification: Custom Aligned Binary

Created a minimal test program compiled with `-mstrict-align`:
```c
void _start(void) {
    const char msg[] = "Hello from aligned C!\n";
    // syscall to write and exit
    __asm__ volatile("svc #0" ...);
}
```

Compiled with:
```bash
aarch64-elf-gcc -O2 -mstrict-align -nostdlib -static -o test_align.elf test.c
```

This binary ran successfully on Kenix, printing "Hello from aligned C!"

## Solutions

1. **Build BusyBox with strict alignment**
   ```bash
   export CFLAGS="-mstrict-align -fno-tree-vectorize"
   make ARCH=arm64 CROSS_COMPILE=aarch64-linux-musl-
   ```

2. **Use `-mno-neon`** to disable SIMD entirely

3. **Find prebuilt binary** compiled for older ARM cores without SIMD

## Lessons Learned

1. **Architecture matters** - x86 and AArch64 have fundamentally different
   alignment semantics for SIMD. Code that works on x86 may crash on ARM.

2. **SCTLR.A is not enough** - It only affects scalar loads/stores. SIMD
   instructions have their own alignment requirements.

3. **C library optimization flags matter** - A binary's crash behavior depends
   heavily on how its libc was compiled.

4. **Disassembly reveals truth** - Examining the actual instruction at the
   fault address immediately identified the SIMD store pair.

## Files Modified

- `Makefile` - Temporarily changed CPU from cortex-a72 to max (testing)
- `user/init/src/main.rs` - Added test cases for disk execve

## Result

- execve from FAT32 disk: **Working**
- Custom aligned binary: **Working**
- BusyBox/toybox: **Requires recompilation with alignment flags**

The kernel's execve, VFS, and memory management are fully functional. The
BusyBox crash is a userspace issue requiring a properly compiled binary.

## Performance Note

During testing, we observed that reading BusyBox (~1.9MB) from disk via VFS
takes about 4 minutes due to single-threaded VFS making one IPC call per
512-byte sector read. This is a known limitation of our current microkernel
design and not related to the alignment issue.

## References

- [ARM AArch64 Memory Alignment](https://devblogs.microsoft.com/oldnewthing/20220810-00/?p=106958)
- [seL4 Alignment Faults Issue](https://github.com/seL4/seL4/issues/1339)
- [Unaligned Memory Access on Various CPUs](https://blog.vitlabuda.cz/2025/01/22/unaligned-memory-access-on-various-cpu-architectures.html)
