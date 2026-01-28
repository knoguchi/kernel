.PHONY: all boot kernel clean run

QEMU = qemu-system-aarch64
OVMF = QEMU_EFI.fd

all: boot kernel

boot:
	cd boot && cargo +nightly build --release --target aarch64-unknown-uefi
	mkdir -p esp/EFI/BOOT
	cp target/aarch64-unknown-uefi/release/kenix-boot.efi esp/EFI/BOOT/BOOTAA64.EFI

kernel:
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
	cd boot && cargo clean
	cd kernel && cargo clean

# download OVMF firmware
fetch-ovmf:
	curl -LO https://retrage.github.io/edk2-nightly/bin/RELEASEAVRCH64_QEMU_EFI.fd
	mv RELEASEAVRCH64_QEMU_EFI.fd $(OVMF)
