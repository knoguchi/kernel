# Framebuffer Console IPC Integration

**Date:** 2026-02-08

## Problem

The shell prompt and command output were only appearing on UART (serial console),
not on the graphical framebuffer window. Users expected to see output in the QEMU
GUI when running `make run-kernel-fb`.

## Root Cause Analysis

### Issue 1: sys_writev Bypassing Console Server

The kernel's `sys_writev` implementation for `FdKind::Console` was writing directly
to UART, completely bypassing the console server's IPC-based output path:

```rust
// OLD CODE - Direct UART writes
if fd_entry.kind == FdKind::Console {
    for i in 0..iovcnt {
        // Write directly to UART_DR register
        for j in 0..len {
            let c = core::ptr::read_volatile((buf + j) as *const u8);
            core::ptr::write_volatile(UART_DR as *mut u8, c);
        }
    }
    return total;
}
```

BusyBox uses `writev()` for all output, so shell prompts and command output never
went through the console server, which handles framebuffer forwarding.

### Issue 2: Race Condition Between fbdev and Shell

Even after fixing `writev`, the shell prompt often didn't appear on the framebuffer.
Debug output revealed a race condition:

```
[fbdev] Starting IPC server loop...
[fbdev] Creating SHM for FB registration...
[fbdev] SHM created, mapping...
/ #     <-- Shell prompt appears BEFORE fbdev finishes registration!
```

The sequence was:
1. fbdev starts initialization (VirtIO/ramfb setup)
2. init forks and starts shell
3. Shell prints prompt via IPC to console
4. Console receives it, but `fb_ready=false` (fbdev hasn't registered yet)
5. fbdev eventually registers, but too late

## Solution

### Fix 1: Route writev Through sys_write

Changed `sys_writev` to call `sys_write` for each iovec element instead of
special-casing console writes:

```rust
// NEW CODE - Use sys_write which properly goes through IPC
// For all fd types (including Console), iterate and call sys_write
// This ensures console output goes through IPC to console server
let mut total: i64 = 0;
for i in 0..iovcnt {
    let ret = sys_write(ctx, fd, iov_entry.iov_base, iov_entry.iov_len);
    if ret < 0 { break; }
    total += ret;
}
```

### Fix 2: Wait for fbdev Before Starting Shell

Added synchronization in init to wait for fbdev readiness:

```rust
/// Wait for fbdev to be ready by sending FB_INIT and waiting for response.
/// This ensures fbdev has completed initialization and registered with console
/// before we start the shell, so all shell output appears on the framebuffer.
fn wait_for_fbdev() {
    let mut msg = Message::new(FB_INIT, [0, 0, 0, 0]);
    ipc::call(tasks::FBDEV, &mut msg);
}

fn main() -> ! {
    print("=== Kenix Init ===\n");
    wait_for_fbdev();  // Block until fbdev is ready
    print("Running BusyBox from disk...\n\n");
    run_busybox_shell();
    // ...
}
```

The key insight: fbdev only enters its main IPC loop (where it can receive FB_INIT)
**after** it has registered with console. So waiting for FB_INIT response guarantees
fbdev registration is complete.

## Data Flow After Fixes

```
Shell write("/ # ")
    │
    ▼
sys_writev() → sys_write() → FdKind::Console
    │
    ▼
IPC: MSG_WRITE to Console Server (Task 1)
    │
    ▼
Console Server receives MSG_WRITE
    ├── Write to UART (serial output)
    └── if fb_ready:
            │
            ▼
        IPC: FB_PRINT to fbdev (Task 7)
            │
            ▼
        fbdev renders text to framebuffer
```

## Files Modified

- `kernel/src/syscall.rs`: Removed direct UART path in `sys_writev`, now calls `sys_write`
- `user/init/src/main.rs`: Added `wait_for_fbdev()` function and call before shell start
- `user/console/src/main.rs`: Cleaned up debug output
- `user/fbdev/src/main.rs`: Cleaned up debug output

## Testing

```bash
make run-kernel-fb
```

Results:
- `[console] Framebuffer registered` appears before shell output
- Shell prompt `/ # ` visible in QEMU framebuffer window
- Command output (echo, ls, cat) appears on both UART and framebuffer

## Lessons Learned

1. **Always check all syscall variants**: `write()` was fixed to use IPC, but
   `writev()` was forgotten and still had the old direct-UART path.

2. **Server initialization order matters**: In a microkernel, user-space servers
   depend on each other. Need explicit synchronization points rather than hoping
   the scheduler runs them in the right order.

3. **IPC as synchronization**: The blocking `ipc::call()` naturally provides
   synchronization - the caller blocks until the server is ready to respond.
