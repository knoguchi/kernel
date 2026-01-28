ENTRY(_start)

SECTIONS
{
    . = 0x40080000;  /* QEMU virt kernel load address */

    .text : {
        *(.text._start)
        *(.text*)
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

    /* Stack: 64KB, grows downward */
    . = ALIGN(16);
    _stack_bottom = .;
    . += 64K;
    _stack_top = .;

    /* Kernel end symbol - aligned to page boundary */
    . = ALIGN(4K);
    __kernel_end = .;

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note*)
    }
}
