# Kenix

A microkernel written in Rust for AArch64, featuring L4-style synchronous IPC,
user-space device drivers, and a VFS layer with FAT32 support.

## Current Status

The kernel boots on QEMU virt and runs multiple user-space servers:
- **Console server** - UART driver, handles stdin/stdout
- **VFS server** - Virtual filesystem with ramfs and FAT32
- **Block device server** - VirtIO-blk driver
- **Network device server** - VirtIO-net driver
- **Init process** - System tests and process spawning

Tested features: IPC, shared memory, pipes, file operations, process spawn/execve,
mmap/munmap (anonymous and file-backed), clock_gettime, signal delivery, writev/readv.

## Target

- QEMU virt (dev)
- Raspberry Pi 4/5 (planned)
- ARM Chromebook (planned)

## Prerequisites

```bash
# Rust nightly
rustup override set nightly
rustup component add rust-src

# QEMU
brew install qemu  # macOS
apt install qemu-system-aarch64  # Linux

# mtools (for FAT32 disk images)
brew install mtools  # macOS
apt install mtools   # Linux
```

## Build & Run

```bash
# Build the kernel and user-space programs
make

# Run on QEMU (recommended - direct kernel boot)
make run-kernel

# Run with UEFI bootloader (WIP - currently a stub)
make fetch-ovmf
make run
```

### Sample Output

```
[console] Server started
[vfs] Server started
[blkdev] VirtIO ready
[netdev] MAC: 52:54:00:12:34:56
[pipeserv] ok, ready!

=== Init Process ===
Testing IPC, VFS, Spawn
--- Basic VFS Test ---
Read /hello.txt: Hello from ramfs!
--- Pipe Test ---
Created pipe: read_fd=3, write_fd=4
Read from pipe: Hello, pipe!
--- Fork Test ---
[parent] fork() returned child PID=8
[child] I'm the child! PID=8
[parent] Child exited with status=0
--- Spawn Test ---
[hello] I was spawned!
[hello] My PID is: 9

--- Phase 1 BusyBox Tests ---
=== Phase 1 BusyBox Support Tests ===
[TEST] clock_gettime: OK (1.619s)
[TEST] fstat: OK mode=0o666 nlink=1 blksize=4096
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
=== Tests Complete ===

=== Init complete ===
```

## Project Structure

```
kenix/
├── boot/               # UEFI bootloader
├── kernel/             # Microkernel core
│   └── src/
│       ├── main.rs        # Kernel entry point
│       ├── mm/            # Memory management (paging, frames)
│       ├── sched/         # Scheduler and task management
│       ├── exception/     # Exception/interrupt handling
│       ├── ipc.rs         # IPC syscalls
│       ├── shm.rs         # Shared memory
│       ├── syscall.rs     # Syscall dispatcher
│       ├── gic.rs         # ARM GIC driver
│       ├── timer.rs       # ARM timer driver
│       ├── elf.rs         # ELF loader
│       ├── irq.rs         # IRQ-to-task routing
│       ├── pipe.rs        # Kernel-level pipes
│       └── mmap.rs        # Anonymous mmap with demand paging
├── user/               # User-space programs (all Rust)
│   ├── libkenix/          # Shared runtime library
│   │   ├── Cargo.toml
│   │   └── src/lib.rs        # Syscalls, IPC, SHM wrappers
│   ├── console/           # Console server
│   │   ├── Cargo.toml
│   │   └── src/main.rs       # UART driver, IPC message loop
│   ├── init/              # Init process
│   │   ├── Cargo.toml
│   │   └── src/main.rs       # System tests, VFS client
│   ├── vfs/               # VFS server
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs       # VFS server, mount points
│   │       ├── blk_client.rs # Block device IPC client
│   │       └── fat32/        # FAT32 filesystem
│   ├── blkdev/            # Block device server
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs       # IPC server loop
│   │       ├── virtio_mmio.rs # VirtIO MMIO registers
│   │       ├── virtqueue.rs  # Virtqueue management
│   │       └── blk.rs        # VirtIO-blk protocol
│   ├── netdev/            # Network device server
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs       # IPC server loop
│   │       ├── virtio_mmio.rs # VirtIO MMIO registers
│   │       ├── virtqueue.rs  # Virtqueue management
│   │       └── net.rs        # VirtIO-net protocol
│   ├── pipeserv/          # Pipe server (unused, kernel pipes preferred)
│   │   ├── Cargo.toml
│   │   └── src/main.rs
│   ├── hello/             # Test program for spawn
│   │   ├── Cargo.toml
│   │   └── src/main.rs
│   ├── forktest/          # Phase 1 BusyBox support tests
│   │   ├── Cargo.toml
│   │   └── src/main.rs
│   ├── user.ld            # Shared linker script
│   ├── aarch64-kenix-user.json  # Custom target spec
│   └── Cargo.toml         # Workspace root
├── docs/               # Documentation
│   ├── syscalls.md        # System call reference
│   ├── ipc-protocols.md   # IPC message formats
│   └── journal/           # Development notes
├── scripts/            # Build scripts
│   └── create_disk.sh     # FAT32 disk image creation
└── Makefile
```

## Roadmap

### Core Kernel
- [x] UEFI boot
- [x] UART output
- [x] Physical memory management (frame allocator)
- [x] Paging (MMU, 2MB blocks)
- [x] 4KB page support (L3 tables)
- [x] Exception handler
- [x] Preemptive scheduler (round-robin, timer-based)

### User Space
- [x] User-space tasks (EL0)
- [x] ELF loader
- [x] Syscall interface
- [x] Pure Rust user-space (libkenix)

### IPC
- [x] Synchronous IPC (call/recv/reply)
- [x] Inline message passing (24 bytes)
- [x] Shared memory IPC
- [x] Asynchronous notifications (notify/wait_notify)

### Servers
- [x] Console server (UART)
- [x] VFS server (ramfs + FAT32)
- [x] Block device server (VirtIO-blk)
- [x] Network device server (VirtIO-net)
- [x] FAT32 filesystem

### File Descriptors
- [x] Per-task fd table
- [x] stdin/stdout/stderr
- [x] read() syscall
- [x] write() syscall
- [x] close() syscall
- [x] pipe() syscall (kernel-level pipes)
- [x] dup/dup2/dup3 syscalls

### Process Management
- [x] spawn() syscall (create process from ELF in memory)
- [x] execve() syscall (execute program from VFS path)
- [x] getpid() syscall
- [x] exit() syscall
- [x] brk() syscall (heap management)
- [x] getcwd/chdir syscalls (working directory)
- [x] fork() syscall (copy-on-write not yet implemented, full copy)
- [x] wait/waitpid syscalls

### Memory Management
- [x] Anonymous mmap/munmap with demand paging
- [x] mprotect (stub)
- [x] File-backed mmap (pre-faulted)
- [ ] Copy-on-write (COW)
- [ ] Swapping

### Signals
- [x] Signal state tracking (mask, pending, handlers)
- [x] sigaction/sigprocmask/kill syscalls
- [x] SIGCHLD on child exit
- [x] Signal delivery to user handlers
- [x] sigreturn syscall

### Phase 2 musl/BusyBox Support
- [x] set_tid_address syscall
- [x] getrandom syscall
- [x] prlimit64 syscall
- [x] writev/readv syscalls
- [x] ioctl TIOCGWINSZ (terminal size)

### Time
- [x] clock_gettime (CLOCK_MONOTONIC, CLOCK_REALTIME)
- [ ] nanosleep
- [ ] timer_create/timer_settime

### Hardware Support
- [x] VirtIO-blk driver (block device)
- [x] VirtIO-net driver (network)
- [x] ARM GIC (Generic Interrupt Controller)
- [x] ARM timer interrupts (preemption)
- [ ] VirtIO interrupt-driven I/O
- [ ] Raspberry Pi 4/5 support
- [ ] ARM Chromebook support

### Security & Robustness
- [ ] Capability-based security
- [ ] Resource limits
- [ ] Watchdog / task monitoring

### Developer Experience
- [ ] GDB stub for kernel debugging
- [ ] Kernel symbols for crash dumps
- [ ] Performance tracing
