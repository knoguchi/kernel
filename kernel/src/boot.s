.section .text._start
.global _start

_start:
    // Check if we're on core 0, park other cores
    mrs     x0, mpidr_el1
    and     x0, x0, #3
    cbnz    x0, park

    // Enable FP/SIMD access (CPACR_EL1.FPEN = 0b11)
    // The Rust compiler may generate SIMD instructions
    mov     x0, #(3 << 20)
    msr     cpacr_el1, x0
    isb

    // Set up stack pointer (stack grows down, place at kernel load address)
    ldr     x0, =_stack_top
    mov     sp, x0

    // Clear BSS
    ldr     x0, =__bss_start
    ldr     x1, =__bss_end
clear_bss:
    cmp     x0, x1
    b.ge    bss_done
    str     xzr, [x0], #8
    b       clear_bss
bss_done:

    // Jump to Rust kernel_main
    bl      kernel_main

    // Should never return, but just in case
park:
    wfe
    b       park
