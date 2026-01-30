# Journal: VirtIO-blk Driver and FAT32 Filesystem

**Date:** 2026-01-29

## Problem Statement

The VirtIO-blk driver was hanging when attempting to read from the block device. After submitting a request to the virtqueue, the device never completed it - `used.idx` stayed at 0 indefinitely.

Debug output showed:
```
[blkdev] version=1
[blkdev] features_lo=0x31006ed4
[blkdev] features_hi=0x0
[blkdev] avail.idx after=1
[blkdev] notified device
[blkdev] used.idx=0 last_used_idx=0
[blkdev] still waiting...
```

## Investigation Process

### Phase 1: Initial Analysis

The driver was correctly:
- Finding the VirtIO block device at slot 31
- Negotiating features
- Setting up the virtqueue
- Submitting requests
- Notifying the device

But the device never processed the request (`used.idx` never changed).

### Phase 2: VirtIO MMIO Version Mismatch

Key observation: `version=1` indicated the device was using **legacy** VirtIO MMIO transport.

The driver code used VirtIO MMIO v2 (modern) register layout:
```rust
// virtio_mmio.rs - Modern register offsets
pub const QUEUE_DESC_LOW: usize = 0x080;
pub const QUEUE_DESC_HIGH: usize = 0x084;
pub const QUEUE_DRIVER_LOW: usize = 0x090;
pub const QUEUE_DRIVER_HIGH: usize = 0x094;
pub const QUEUE_DEVICE_LOW: usize = 0x0a0;
pub const QUEUE_DEVICE_HIGH: usize = 0x0a4;
```

Legacy VirtIO MMIO uses a completely different register layout with `QUEUE_PFN` instead of split 64-bit addresses.

### Phase 3: Feature Negotiation Issue

The code was setting `VIRTIO_F_VERSION_1` even when the device didn't advertise it:
```rust
// OLD (broken)
self.mmio.set_driver_features(1, VIRTIO_F_VERSION_1);  // Always set
```

But `features_hi=0x0` meant the device didn't support this feature (legacy device).

## The Fix

### Fix 1: Force Modern VirtIO MMIO in QEMU

Modified `Makefile` to add `-global virtio-mmio.force-legacy=false`:

```makefile
run-kernel: kernel $(DISK_IMG)
	$(QEMU) \
		-M virt \
		-cpu cortex-a72 \
		-m 1G \
		-global virtio-mmio.force-legacy=false \
		-device virtio-blk-device,drive=disk0 \
		-drive file=$(DISK_IMG),format=raw,if=none,id=disk0 \
		-kernel kernel.elf \
		-nographic \
		-serial mon:stdio
```

### Fix 2: Conditional Feature Negotiation

Modified `blk.rs` to only set `VIRTIO_F_VERSION_1` if device offers it:

```rust
// NEW (fixed)
const VIRTIO_F_VERSION_1: u32 = 1 << 0;  // Bit 0 in high word = bit 32 overall

let driver_features_hi = if features_hi & VIRTIO_F_VERSION_1 != 0 {
    VIRTIO_F_VERSION_1
} else {
    0  // Legacy device - don't set any high features
};
self.mmio.set_driver_features(1, driver_features_hi);
```

## Results After Fix

```
[blkdev] version=2
[blkdev] features_hi=0x0000000000000101
[blkdev] VirtIO ready
...
Read from disk: Hello from FAT32!
```

- `version=2` - Now using modern VirtIO MMIO
- `features_hi=0x101` - Device advertises VIRTIO_F_VERSION_1 (bit 0) and VIRTIO_F_RING_PACKED (bit 8)
- Requests complete successfully

## Architecture Summary

```
+-------------+      IPC       +-------------+      IPC       +-------------+
|   Client    | ------------->|  VFS Server | ------------->|   blkdev    |
|   (init)    |   VFS_READ    |   (FAT32)   |   BLK_READ    |   server    |
+-------------+               +-------------+               +-------------+
                                    |                             |
                                    +-------- SHM buffer ---------+
                                                  |
                                                  v
                                          +-------------+
                                          | virtio-blk  |
                                          |   device    |
                                          +-------------+
```

**Key components:**
- **blkdev server (userspace)**: VirtIO-blk driver, maps MMIO at 0x0a003e00
- **VFS server**: FAT32 filesystem, uses blkdev via IPC
- **Shared memory**: Used for data transfer between VFS and blkdev

## Files Created

| File | Purpose |
|------|---------|
| `user/blkdev/src/main.rs` | Block device IPC server |
| `user/blkdev/src/virtio_mmio.rs` | VirtIO MMIO register access |
| `user/blkdev/src/virtqueue.rs` | Virtqueue (descriptor ring) management |
| `user/blkdev/src/blk.rs` | VirtIO-blk protocol implementation |
| `user/vfs/src/fat32/mod.rs` | FAT32 filesystem |
| `user/vfs/src/fat32/bpb.rs` | BIOS Parameter Block parsing |
| `user/vfs/src/fat32/fat.rs` | FAT table operations |
| `user/vfs/src/fat32/dir.rs` | Directory entry parsing |
| `user/vfs/src/blk_client.rs` | Block device IPC client |
| `kernel/src/irq.rs` | IRQ-to-task routing |
| `scripts/create_disk.sh` | FAT32 disk image creation |

## Files Modified

| File | Change |
|------|--------|
| `Makefile` | Added `-global virtio-mmio.force-legacy=false`, disk target |
| `kernel/src/main.rs` | Create blkdev server as task 4 |
| `kernel/src/sched/mod.rs` | Added `create_blkdev_server_from_elf()` |
| `kernel/src/syscall.rs` | Added `SYS_IRQ_WAIT`, `SYS_IRQ_ACK` |
| `kernel/src/user_code.s` | Embedded blkdev.elf |
| `user/vfs/src/main.rs` | FAT32 integration, block device client |
| `user/libkenix/src/lib.rs` | Added `BLK_READ`, `BLK_WRITE`, `BLK_INFO` constants |
| `user/Cargo.toml` | Added blkdev workspace member |

## Lessons Learned

1. **VirtIO MMIO has two incompatible versions** - Legacy (v1) and modern (v2) use different register layouts. Check `version` register first.

2. **QEMU defaults to legacy transport** - Use `-global virtio-mmio.force-legacy=false` to get modern transport.

3. **Feature negotiation must match device capabilities** - Don't set feature bits the device doesn't advertise.

4. **Physical addresses for DMA** - VirtIO requires physical addresses in descriptors. User-space drivers need kernel-provided physical base.

## Test Output

```
[blkdev] Starting...
[blkdev] found at slot O
[blkdev] VirtIO ready
[vfs] Block device connected
[vfs] FAT32 filesystem mounted at /disk/
Read from disk: Hello from FAT32!
```
