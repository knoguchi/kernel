// User-space init program for Kenix
// Runs in EL0 (user mode) and uses syscalls to interact with kernel
//
// Linux-compatible syscall numbers:
// - SYS_WRITE = 64
// - SYS_EXIT = 93

.section .text
.global _start

_start:
    // SYS_WRITE(fd=1, buf=msg, len=21)
    mov     x0, #1              // fd = stdout
    adr     x1, msg             // buf = message (PC-relative)
    mov     x2, #21             // len = 21
    mov     x8, #64             // SYS_WRITE
    svc     #0

    // SYS_EXIT(code=0)
    mov     x0, #0              // exit code = 0
    mov     x8, #93             // SYS_EXIT
    svc     #0

    // Should not reach here, but just in case
1:  wfi
    b       1b

.section .rodata
msg:
    .ascii "Hello from userland!\n"
