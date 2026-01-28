// Embedded user-space init program
// This file includes the compiled user binary into the kernel image

.section .user_code, "a"
.global __user_code_embedded_start
.global __user_code_embedded_end

__user_code_embedded_start:
.incbin "../user/init.bin"
__user_code_embedded_end:
