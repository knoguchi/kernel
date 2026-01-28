/* Linker script for user-space programs */
/* Code is linked at offset 0 for simplicity with 2MB block mapping */

ENTRY(_start)

SECTIONS
{
    /* User code loads at virtual address 0x00000000 */
    /* The actual runtime address depends on the physical frame offset */
    . = 0x00000000;

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
