ENTRY(_start)

SECTIONS
{
    . = 0x40080000;  /* QEMU virt kernel load address */

    .text : {
        *(.text._start)
        *(.text*)
    }

    .vectors : ALIGN(0x800) {
        __exception_vectors_start = .;
        *(.text.vectors)
        __exception_vectors_end = .;
    }

    .rodata : ALIGN(4K) {
        *(.rodata*)
    }

    .data : ALIGN(4K) {
        *(.data*)
    }

    .bss : ALIGN(4K) {
        __bss_start = .;
        *(.bss*)
        *(COMMON)
        __bss_end = .;
    }

    /* Embedded user-space init program */
    .user_code : ALIGN(4K) {
        __user_code_start = .;
        KEEP(*(.user_code))
        __user_code_end = .;
    }

    /* Stack: 256KB, grows downward (increased from 64KB to prevent overflow) */
    . = ALIGN(16);
    _stack_bottom = .;
    . += 256K;
    _stack_top = .;

    /* Kernel end symbol - aligned to page boundary */
    . = ALIGN(4K);
    __kernel_end = .;

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note*)
    }
}
