# Phase 2 musl/BusyBox Support Complete

**Date:** 2026-02-02

## Summary

Completed all Phase 2 syscalls needed for musl libc startup and basic BusyBox operation.
All tests pass including signal delivery and file-backed mmap.

## Features Implemented

### P1: musl Startup Syscalls
- `set_tid_address` - Returns current task ID, stores clear_child_tid pointer
- `getrandom` - Fills buffer with random bytes from ARM counter + XOR hash
- `prlimit64` - Query/set resource limits (stack limit: 2MB)

### P2: I/O Enhancements
- `writev` - Scatter-gather write from multiple buffers
- `readv` - Scatter-gather read into multiple buffers
- `ioctl TIOCGWINSZ` - Return terminal window size (80x24 default)

### P3: Signal Delivery
- Full signal delivery to user handlers via stack frame
- `sigreturn` syscall to restore context after handler
- Signal frame contains saved registers, signal number, siginfo
- Handler receives signal number in x0

### P4: File-backed mmap
- `mmap()` with file descriptor pre-loads file content
- Uses VFS IPC to read file data into SHM
- Copies to physical pages via `virt_to_phys()` translation
- Works with read-only mappings (writes via physical address)

## Key Bug Fixes

### VFS MAX_CLIENTS Too Small
- **Problem:** VFS server had `MAX_CLIENTS = 8`, but forktest ran as task 9
- **Symptom:** `open()` returned EINVAL (-22)
- **Fix:** Increased `MAX_CLIENTS` to 32

### File mmap Permission Fault
- **Problem:** Kernel tried to write file content to read-only user pages
- **Symptom:** Data abort on permission fault when copying file data
- **Fix:** Added `virt_to_phys()` to translate user virtual addresses to physical,
  then write via kernel's identity mapping (bypasses page permissions)

### Build Dependencies
- **Problem:** Changing user ELF files didn't trigger kernel rebuild
- **Fix:** Added user ELF files to `kernel/build.rs` rerun-if-changed

## Files Modified

### Kernel
- `kernel/src/syscall.rs` - Added P1/P2 syscalls, file mmap handler
- `kernel/src/ipc.rs` - MmapFile completion handler with virt_to_phys
- `kernel/src/mm/address_space.rs` - Added `virt_to_phys()` page table walker
- `kernel/src/sched/task.rs` - Added MmapFile pending syscall variant
- `kernel/src/exception/mod.rs` - Signal delivery, sigreturn
- `kernel/build.rs` - Added user ELF dependencies

### User Space
- `user/vfs/src/main.rs` - Increased MAX_CLIENTS to 32
- `user/forktest/src/main.rs` - Phase 2 test suite
- `user/libkenix/src/syscall.rs` - New syscall wrappers

## Test Results

```
=== Phase 1 BusyBox Support Tests ===
[TEST] clock_gettime: OK (1.642s)
[TEST] fstat: OK mode=0o438 nlink=1 blksize=4096
[TEST] mmap: allocated at 0x0000000010000000 write/read OK munmap OK
[TEST] signals: sigaction OK sigprocmask OK kill OK
[TEST] fork/wait: forked pid=10 exit=42 OK

=== Phase 2 musl Startup Tests ===
[TEST] set_tid_address: OK tid=9
[TEST] getrandom: OK got 16 bytes: f7d84b2b...
[TEST] prlimit64: OK stack_cur=2048KB max=2048KB
[TEST] writev: Hello, writev world!
[TEST] writev: OK wrote 21 bytes
[TEST] ioctl TIOCGWINSZ: OK 80x24
[TEST] signal delivery: OK handler called
[TEST] file mmap: got fd=3 mapped at 0x10001000 content OK (Hello) munmap OK
```

## Architecture Notes

### Signal Delivery Stack Frame
```
User Stack (grows down):
  [padding for 16-byte alignment]
  siginfo_t (128 bytes)
  ucontext_t with saved registers
  <- SP points here when handler called

Handler prototype: void handler(int sig)
  x0 = signal number
  x30 (LR) = sigreturn trampoline (not used, handler calls sigreturn explicitly)
```

### File mmap Flow
```
1. User calls mmap(fd, ...)
2. Kernel allocates physical pages, maps them (possibly read-only)
3. Kernel sends VFS_READ_SHM to read file content into SHM
4. On VFS reply, kernel walks page tables to get physical addresses
5. Copies file data to physical pages (bypasses page permissions)
6. Returns virtual address to user
```

## Next Steps

- [ ] Run actual BusyBox binary
- [ ] Add more syscalls as needed (fstatat, newfstatat, etc.)
- [ ] Implement nanosleep for sleep commands
- [ ] Copy-on-write for fork()
