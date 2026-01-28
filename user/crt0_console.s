// Minimal C runtime startup for Kenix console server
// Sets up the environment and calls console_main()

.section .text._start
.global _start

_start:
    // Clear frame pointer for clean backtraces
    mov     x29, #0
    mov     x30, #0

    // Call console_main()
    bl      console_main

    // If console_main returns (it shouldn't), loop forever
1:  wfi
    b       1b
