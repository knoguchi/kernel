// Minimal C runtime startup for Kenix userspace
// Sets up the environment and calls main()

.section .text._start
.global _start

_start:
    // Clear frame pointer for clean backtraces
    mov     x29, #0
    mov     x30, #0

    // Call main()
    bl      main

    // If main returns, call exit with return value
    mov     x8, #93         // SYS_EXIT
    svc     #0

    // Should never reach here
1:  wfi
    b       1b
