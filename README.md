# Kenix

Micro kernel written in Rust for AArch64

## Target

- QEMU virt (dev)
- Raspberry Pi 4/5 (planned)
- ARM Chromebook (planned)

## Prerequisits

```bash
# Rust nightly
rustup override set nightly
rustup component add rust-src

# QEMU
brew install qemu  # macOS
apt install qemu-system-aarch64  # Linux
```

## build & run

```bash
# get UEFI firmware
make fetch-ovmf

# exec via UEFI bootloader
make run

# exec without UEFI
make run-kernel
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
│       └── elf.rs         # ELF loader
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
│   │   └── src/main.rs       # RAM filesystem
│   ├── user.ld            # Shared linker script
│   ├── aarch64-kenix-user.json  # Custom target spec
│   └── Cargo.toml         # Workspace root
├── docs/               # Documentation
│   ├── syscalls.md        # System call reference
│   └── ipc-protocols.md   # IPC message formats
├── journal/            # Development notes
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
- [ ] Asynchronous notifications

### Servers
- [x] Console server (UART)
- [x] VFS server (ramfs)
- [ ] Block device driver
- [ ] RAM disk
- [ ] FAT32 filesystem

### File Descriptors
- [x] Per-task fd table
- [x] stdin/stdout/stderr
- [x] read() syscall
- [x] write() syscall
- [x] close() syscall
- [ ] dup/dup2
- [ ] pipe

### Memory Management
- [ ] Demand paging
- [ ] Copy-on-write (COW)
- [ ] Swapping

### Hardware Support
- [ ] Interrupts beyond timer (keyboard, network)
- [ ] Virtio drivers (block, network)
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
