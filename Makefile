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

# Build all user-space programs (all Rust now)
# Build hello first since init embeds it via include_bytes!
user:
	cd user && cargo +nightly build --release --target aarch64-kenix-user.json -Zbuild-std=core -p libkenix -p hello
	mkdir -p user/init/data
	cp user/target/aarch64-kenix-user/release/hello user/init/data/hello.elf
	cd user && cargo +nightly build --release --target aarch64-kenix-user.json -Zbuild-std=core
	cp user/target/aarch64-kenix-user/release/console user/console.elf
	cp user/target/aarch64-kenix-user/release/init user/init.elf
	cp user/target/aarch64-kenix-user/release/vfs user/vfs.elf
	cp user/target/aarch64-kenix-user/release/hello user/hello.elf

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
	rm -f user/console.elf user/init.elf user/vfs.elf
	cd boot && cargo clean
	cd kernel && cargo clean
	cd user && cargo clean 2>/dev/null || true

# Note: UEFI firmware is provided by QEMU (Homebrew) at /opt/homebrew/share/qemu/
# For other installations, set OVMF to the path of your edk2-aarch64-code.fd
