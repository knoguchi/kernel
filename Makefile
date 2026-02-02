.PHONY: all boot kernel user clean run disk

QEMU = qemu-system-aarch64
DISK_IMG = disk.img
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
# Build hello and forktest first since init embeds them via include_bytes!
user:
	cd user && cargo +nightly build --release --target aarch64-kenix-user.json -Zbuild-std=core -p libkenix -p hello -p forktest
	mkdir -p user/init/data
	cp user/target/aarch64-kenix-user/release/hello user/init/data/hello.elf
	cp user/target/aarch64-kenix-user/release/forktest user/init/data/forktest.elf
	cp user/target/aarch64-kenix-user/release/forktest user/forktest.elf
	cd user && cargo +nightly build --release --target aarch64-kenix-user.json -Zbuild-std=core
	cp user/target/aarch64-kenix-user/release/console user/console.elf
	cp user/target/aarch64-kenix-user/release/init user/init.elf
	cp user/target/aarch64-kenix-user/release/vfs user/vfs.elf
	cp user/target/aarch64-kenix-user/release/hello user/hello.elf
	cp user/target/aarch64-kenix-user/release/blkdev user/blkdev.elf
	cp user/target/aarch64-kenix-user/release/netdev user/netdev.elf
	cp user/target/aarch64-kenix-user/release/pipeserv user/pipeserv.elf

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

disk: $(DISK_IMG)

$(DISK_IMG):
	./scripts/create_disk.sh $(DISK_IMG) 32

run-kernel: kernel $(DISK_IMG)
	$(QEMU) \
		-M virt \
		-cpu cortex-a72 \
		-m 1G \
		-global virtio-mmio.force-legacy=false \
		-device virtio-blk-device,drive=disk0 \
		-drive file=$(DISK_IMG),format=raw,if=none,id=disk0 \
		-device virtio-net-device,netdev=net0 \
		-netdev user,id=net0 \
		-kernel kernel.elf \
		-nographic \
		-serial mon:stdio

clean:
	rm -rf esp kernel.elf $(DISK_IMG)
	rm -f user/console.elf user/init.elf user/vfs.elf user/hello.elf user/blkdev.elf user/netdev.elf user/pipeserv.elf user/forktest.elf
	cd boot && cargo clean

# Note: UEFI firmware is provided by QEMU (Homebrew) at /opt/homebrew/share/qemu/
# For other installations, set OVMF to the path of your edk2-aarch64-code.fd
