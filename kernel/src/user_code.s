// Embedded user-space programs
// This file includes the compiled user ELFs into the kernel image

.section .user_code, "a"

// Console server ELF (must be created first to get task ID 1)
.global __console_elf_start
.global __console_elf_end
__console_elf_start:
.incbin "../user/console.elf"
__console_elf_end:

// Init program ELF (task ID 2)
.global __init_elf_start
.global __init_elf_end
__init_elf_start:
.incbin "../user/init.elf"
__init_elf_end:

// VFS server ELF (task ID 3)
.global __vfs_elf_start
.global __vfs_elf_end
__vfs_elf_start:
.incbin "../user/vfs.elf"
__vfs_elf_end:

// Block device server ELF (task ID 4)
.global __blkdev_elf_start
.global __blkdev_elf_end
__blkdev_elf_start:
.incbin "../user/blkdev.elf"
__blkdev_elf_end:

// Network device server ELF (task ID 5)
.global __netdev_elf_start
.global __netdev_elf_end
__netdev_elf_start:
.incbin "../user/netdev.elf"
__netdev_elf_end:

// Pipe server ELF (task ID 6)
.global __pipeserv_elf_start
.global __pipeserv_elf_end
__pipeserv_elf_start:
.incbin "../user/pipeserv.elf"
__pipeserv_elf_end:

// Framebuffer device server ELF (task ID 7)
.global __fbdev_elf_start
.global __fbdev_elf_end
__fbdev_elf_start:
.incbin "../user/fbdev.elf"
__fbdev_elf_end:

// Keyboard device server ELF (task ID 8)
.global __kbdev_elf_start
.global __kbdev_elf_end
__kbdev_elf_start:
.incbin "../user/kbdev.elf"
__kbdev_elf_end:

// Forktest ELF
.global __forktest_elf_start
.global __forktest_elf_end
__forktest_elf_start:
.incbin "../user/forktest.elf"
__forktest_elf_end:
