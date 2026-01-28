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

## project tree

```
kenix/
├── boot/
├── kernel/
└── Makefile
```

## Roadmap

- [x] UEFI boot
- [x] UART output
- [ ] physical memory management
- [ ] paging
- [ ] exception handler
- [ ] IPC
- [ ] scheduler
- [ ] userspace
