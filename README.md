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
├── boot/           # UEFI bootloader
├── kernel/         # Microkernel core
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
├── user/           # User-space programs
│   ├── init.c            # Init process
│   ├── console.c         # Console server
│   ├── ipc.h             # IPC syscall wrappers
│   └── shm.h             # SHM syscall wrappers
├── journal/        # Development notes
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

### IPC
- [x] Synchronous IPC (call/recv/reply)
- [x] Inline message passing (24 bytes)
- [x] Shared memory IPC
- [ ] Asynchronous notifications

### Servers
- [x] Console server (UART)
- [ ] VFS server
- [ ] Block device driver
- [ ] RAM disk
- [ ] FAT32 filesystem

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
