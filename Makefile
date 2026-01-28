.PHONY: all boot kernel user clean run

QEMU = qemu-system-aarch64
# Use QEMU's bundled UEFI firmware (Homebrew location)
OVMF = /opt/homebrew/share/qemu/edk2-aarch64-code.fd

# Use Rust's LLVM tools for cross-compilation
RUST_LLVM_BIN = $(shell find ~/.rustup/toolchains -path "*nightly*" -name "rust-lld" -type f 2>/dev/null | head -1 | xargs dirname)
RUST_LLD = $(RUST_LLVM_BIN)/rust-lld
RUST_OBJCOPY = $(RUST_LLVM_BIN)/llvm-objcopy

all: boot kernel

boot:
	cd boot && cargo +nightly build --release --target aarch64-unknown-uefi
	mkdir -p esp/EFI/BOOT
	cp target/aarch64-unknown-uefi/release/kenix-boot.efi esp/EFI/BOOT/BOOTAA64.EFI

# Build user-space programs using clang and Rust's LLVM tools
# The kernel loads ELF directly, no need for raw binary conversion
user:
	# Build init program
	clang --target=aarch64-unknown-none -c -o user/crt0.o user/crt0.s
	clang --target=aarch64-unknown-none -ffreestanding -nostdlib -O2 -c -o user/init.o user/init.c
	$(RUST_LLD) -flavor gnu -T user/user.ld -o user/init.elf user/crt0.o user/init.o
	# Build console server
	clang --target=aarch64-unknown-none -c -o user/crt0_console.o user/crt0_console.s
	clang --target=aarch64-unknown-none -ffreestanding -nostdlib -O2 -c -o user/console.o user/console.c
	$(RUST_LLD) -flavor gnu -T user/user.ld -o user/console.elf user/crt0_console.o user/console.o

kernel: user
	cd kernel && cargo +nightly build --release --target aarch64-kenix.json -Zbuild-std=core,alloc
	cp target/aarch64-kenix/release/kenix-kernel kernel.elf

run: all
	$(QEMU) \
		-M virt \
		-cpu cortex-a72 \
		-m 1G \
		-bios $(OVMF) \
		-drive format=raw,file=fat:rw:esp \
		-nographic \
		-serial mon:stdio

run-kernel: kernel
	$(QEMU) \
		-M virt \
		-cpu cortex-a72 \
		-m 1G \
		-kernel kernel.elf \
		-nographic \
		-serial mon:stdio

clean:
	rm -rf esp kernel.elf
	rm -f user/crt0.o user/init.o user/init.elf
	rm -f user/crt0_console.o user/console.o user/console.elf
	cd boot && cargo clean
	cd kernel && cargo clean

# Note: UEFI firmware is provided by QEMU (Homebrew) at /opt/homebrew/share/qemu/
# For other installations, set OVMF to the path of your edk2-aarch64-code.fd
