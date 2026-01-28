// Embedded user-space programs
// This file includes the compiled user ELFs into the kernel image

.section .user_code, "a"

// Console server ELF (must be created first to get task ID 1)
.global __console_elf_start
.global __console_elf_end
__console_elf_start:
.incbin "../user/console.elf"
__console_elf_end:

// Init program ELF
.global __init_elf_start
.global __init_elf_end
__init_elf_start:
.incbin "../user/init.elf"
__init_elf_end:
