# Phase 1 BusyBox Support

**Date:** 2026-02-02

## Goal

Implement the minimum syscalls needed to run statically-linked BusyBox with musl libc.

## New Syscalls Implemented

### clock_gettime (113)

Reads the ARM physical counter (CNTPCT_EL0) and converts to timespec using the
counter frequency (CNTFRQ_EL0).

```rust
// kernel/src/timer.rs
pub fn read_counter() -> u64 {
    let cnt: u64;
    unsafe {
        core::arch::asm!("mrs {}, cntpct_el0", out(reg) cnt);
    }
    cnt
}

pub fn get_time_ns() -> u64 {
    let freq = frequency();
    let cnt = read_counter();
    (cnt as u128 * 1_000_000_000 / freq as u128) as u64
}
```

Supports CLOCK_REALTIME, CLOCK_MONOTONIC, and CLOCK_BOOTTIME (all return time
since boot).

### mmap/munmap (222/215)

Anonymous memory mapping with demand paging. Key design:

- **Memory region**: 0x10000000 - 0x30000000 (512MB)
- **Page size**: 4KB (cannot mix with 2MB blocks)
- **Demand paging**: Pages allocated on first access via page fault handler
- **Per-task tracking**: `MmapRegion` struct tracks vaddr, len, prot, allocated pages

```rust
// kernel/src/mmap.rs
pub struct MmapRegion {
    pub vaddr: usize,
    pub len: usize,
    pub prot: u32,
    pub flags: u32,
    pub allocated_pages: Vec<bool>,
}
```

Page fault handler in `exception/mod.rs`:
```rust
if fault_addr >= mmap::MMAP_BASE && fault_addr < mmap::MMAP_END {
    let result = mmap::handle_page_fault(fault_addr);
    if result == 0 {
        return; // Page allocated, resume execution
    }
}
```

### Signal Stubs (134/135/129)

Minimal signal support for musl compatibility:

- **rt_sigaction**: Stores handlers but doesn't deliver signals
- **rt_sigprocmask**: Tracks mask but doesn't affect delivery
- **kill**: Sets pending bit but doesn't deliver
- **SIGCHLD**: Automatically set on parent when child exits

Per-task signal state added to Task struct:
```rust
pub signal_mask: u64,           // Blocked signals
pub signal_pending: u64,        // Pending signals
pub signal_handlers: [u64; 32], // Handler addresses
```

### Complete stat Structure

Updated VFS stat handling to fill all fields:

| Field | Value |
|-------|-------|
| st_dev | 1 (ramfs), 2 (FAT32) |
| st_ino | Inode number |
| st_mode | S_IFREG/S_IFDIR \| permissions |
| st_nlink | 1 |
| st_uid/gid | 0 (root) |
| st_size | File size |
| st_blksize | 512 |
| st_blocks | (size + 511) / 512 |
| st_atime/mtime/ctime | Boot time from timer |

## Files Modified

| File | Changes |
|------|---------|
| kernel/src/mmap.rs | **NEW** - MmapRegion, demand paging |
| kernel/src/main.rs | Add `mod mmap;` |
| kernel/src/timer.rs | Add `read_counter()`, `get_time_ns()` |
| kernel/src/syscall.rs | Add clock_gettime, mmap, signal syscalls |
| kernel/src/ipc.rs | Complete stat structure in VfsStat handler |
| kernel/src/exception/mod.rs | Page fault handler for mmap |
| kernel/src/sched/task.rs | Add mmap_state, signal fields to Task |
| kernel/src/sched/mod.rs | Set SIGCHLD on child exit |
| user/vfs/src/main.rs | Return proper st_mode, st_dev in handle_stat |
| user/libkenix/src/lib.rs | Add syscall wrappers |
| user/forktest/src/main.rs | Test suite for new syscalls |
| user/init/src/main.rs | Embed and run forktest |
| Makefile | Copy forktest.elf to init/data |

## Testing

New test program `forktest` tests all features:

```
=== Phase 1 BusyBox Support Tests ===

[TEST] clock_gettime: OK (1.619s)
[TEST] fstat: OK mode=0o666 nlink=1 blksize=4096
[TEST] mmap: allocated at 0x0000000010000000 write/read OK munmap OK
[TEST] signals: sigaction OK sigprocmask OK kill OK
[TEST] fork/wait: forked pid=10 exit=42 OK

=== Tests Complete ===
```

Run with: `make run-kernel`

## Future Work (Phase 2)

- **Signal delivery**: Construct signal frame, modify ELR to handler, sigreturn
- **File-backed mmap**: Map files into memory
- **mprotect**: Actually change page table permissions
- **Copy-on-write**: For fork() efficiency

## Notes

- Exit status from waitpid encodes exit code in bits 8-15: `exit_code = (status >> 8) & 0xff`
- Console (fd 1) stat returns mode 0o020666 (character device)
- mmap only supports MAP_ANONYMOUS | MAP_PRIVATE currently
