# ramfb Framebuffer Implementation

**Date:** 2026-02-08

## Summary

Added a framebuffer device server (`fbdev`) that uses QEMU's ramfb device to provide
graphical display output. The server initializes the framebuffer via the fw_cfg
interface and provides an IPC API for pixel and text operations.

## Architecture

Following the microkernel design, the framebuffer is implemented as a user-space
server that:
1. Initializes ramfb via QEMU's fw_cfg interface
2. Manages framebuffer memory allocated by the kernel
3. Provides IPC interface for pixel and text operations
4. Includes a built-in 8x16 VGA bitmap font for text rendering

### Hardware Interface

**QEMU ramfb** is a simple framebuffer configured via fw_cfg:
- Framebuffer memory allocated from guest RAM
- Configuration written via fw_cfg DMA
- No hardware acceleration

**fw_cfg on ARM/AArch64:**
- MMIO Base: `0x09020000`
- Data Register: offset 0x0 (8 bytes)
- Selector Register: offset 0x8 (2 bytes, write-only)
- DMA Address Register: offset 0x10 (8 bytes)
- All multi-byte values are **big-endian**

### ramfb Configuration Structure

```rust
struct RamfbCfg {
    addr: u64,      // Framebuffer physical address (BE)
    fourcc: u32,    // Pixel format 'XR24' (BE)
    flags: u32,     // 0 (BE)
    width: u32,     // Display width (BE)
    height: u32,    // Display height (BE)
    stride: u32,    // Bytes per line (BE)
}
```

### Display Configuration
- Resolution: 800x600
- Format: XR24 (XRGB8888, 32bpp)
- Framebuffer size: 800 * 600 * 4 = 1,920,000 bytes
- Text console: 100 columns x 37 rows

## Implementation Details

### Kernel Support

Added `create_fbdev_server_from_elf()` in `kernel/src/sched/mod.rs`:
1. Maps fw_cfg MMIO region (0x09020000, same 2MB block as UART at 0x09000000)
2. Allocates 2MB contiguous block for framebuffer
3. Maps framebuffer at fixed VA 0x20000000 in fbdev's address space
4. Passes `phys_base` in x0 and `fb_phys` in x1 registers

### User-Space Server

**Files created:**
- `user/fbdev/src/main.rs` - Entry point, IPC server loop
- `user/fbdev/src/fwcfg.rs` - fw_cfg interface (select, read, DMA write)
- `user/fbdev/src/ramfb.rs` - ramfb initialization and pixel operations
- `user/fbdev/src/font.rs` - 8x16 VGA bitmap font (4KB), TextConsole struct

### IPC Protocol

Message types added to `user/libkenix/src/lib.rs`:

| Tag | Name | Description |
|-----|------|-------------|
| 400 | FB_INIT | Get FB info -> [width, height, bpp, stride] |
| 401 | FB_CLEAR | Clear screen: data[0]=color |
| 402 | FB_PIXEL | Set pixel: data[0]=x, data[1]=y, data[2]=color |
| 403 | FB_RECT | Fill rect: data[0]=x|(y<<16), data[1]=w|(h<<16), data[2]=color |
| 404 | FB_PUTCHAR | Put char: data[0]=col, data[1]=row, data[2]=char, data[3]=fg|(bg<<32) |
| 405 | FB_PRINT | Print string: data[0]=shm_id, data[1]=len |
| 406 | FB_SCROLL | Scroll up one line |
| 407 | FB_CURSOR_SET | Set cursor: data[0]=col, data[1]=row |
| 408 | FB_CURSOR_GET | Get cursor: returns [col, row] |

## Bugs Encountered and Fixed

### 1. fw_cfg Signature Double-Read

**Problem:** fw_cfg data register auto-advances after each read. Reading the
signature twice (once for debug, once for validation) caused the second read
to get different data.

**Fix:** Read signature once and reuse the result for both debug output and
validation.

### 2. DMA Physical Address Calculation

**Problem:** DMA buffers on the stack have different physical addresses than
the code segment. Using `phys_base` (code segment base) to calculate stack
buffer physical addresses gave incorrect addresses.

**Fix:** Use static buffers in the .bss section for DMA operations. Since .bss
is part of the code block, `phys_base` calculation works correctly.

```rust
// Static DMA buffers - in .bss, so phys_base calculation works
static mut DMA_ACCESS: FwCfgDmaAccess = ...;
static mut DMA_DATA_BUF: DmaDataBuf = ...;
```

### 3. Big-Endian Byte Construction

**Problem:** Used `.to_be().to_ne_bytes()` which double-converts:
- `value.to_be()` swaps bytes to big-endian representation
- `.to_ne_bytes()` then interprets that as native-endian

**Fix:** Use `.to_be_bytes()` directly to get big-endian byte array:

```rust
// Wrong
let addr_be = fb_paddr.to_be().to_ne_bytes();

// Correct
cfg_bytes[0..8].copy_from_slice(&fb_paddr.to_be_bytes());
```

### 4. DMA Structure Alignment

**Problem:** fw_cfg DMA requires 8-byte aligned access structure.

**Fix:** Added `#[repr(C, align(8))]` to DMA structures.

## Files Modified

| File | Change |
|------|--------|
| `user/fbdev/*` | New framebuffer server |
| `kernel/src/sched/mod.rs` | Added `create_fbdev_server_from_elf()` |
| `kernel/src/main.rs` | Create fbdev at boot |
| `kernel/src/user_code.s` | Embed fbdev ELF |
| `kernel/build.rs` | Add fbdev.elf dependency |
| `user/libkenix/src/lib.rs` | FB_* message constants, FBDEV task ID |
| `user/Cargo.toml` | Add fbdev to workspace |
| `Makefile` | Build fbdev, add `-device ramfb`, add `run-kernel-fb` target |

## Running

```bash
# With graphical display (shows framebuffer window)
make run-kernel-fb

# Serial only (framebuffer initialized but not visible)
make run-kernel
```

## Result

The framebuffer displays:
```
Kenix Microkernel v0.1.0
Framebuffer Console Ready
Resolution: 800x600 @ 32bpp
```

Text console supports:
- Character output with foreground/background colors
- Cursor positioning
- Automatic line wrapping
- Scrolling when reaching bottom of screen
- Tab characters (8-column alignment)

## Future Work

- [ ] Connect framebuffer to VFS as `/dev/fb0`
- [ ] Support console output redirection to framebuffer
- [ ] Hardware cursor
- [ ] Multiple resolutions
- [ ] VirtIO-gpu support for acceleration
