/* Linker script for user-space programs */

ENTRY(_start)

SECTIONS
{
    /* User code loads at virtual address 0x00100000 */
    . = 0x00100000;

    .text : {
        *(.text._start)
        *(.text*)
    }

    .rodata : ALIGN(16) {
        *(.rodata*)
    }

    .data : ALIGN(16) {
        *(.data*)
    }

    .bss : ALIGN(16) {
        *(.bss*)
        *(COMMON)
    }

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note*)
    }
}
