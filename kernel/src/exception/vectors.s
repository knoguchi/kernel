// AArch64 Exception Vector Table for Kenix Microkernel
// Vector table must be 2KB (0x800) aligned
// Each entry is 128 bytes (0x80), 16 entries total
//
// NOTE: Each vector entry only has 128 bytes, which is not enough for
// the full save/restore sequence. So each entry just branches to the
// actual handler code located after the vector table.

// ============================================================================
// Context save/restore macros
// Stack frame layout (288 bytes, 16-byte aligned):
//   0x000 - 0x0F0: x0-x30 (31 * 8 = 248 bytes)
//   0x0F8:         sp (original)
//   0x100:         elr_el1 (return address)
//   0x108:         spsr_el1 (saved status)
//   0x110:         esr_el1 (exception syndrome)
//   0x118:         far_el1 (fault address)
// Total: 288 bytes (0x120)
// ============================================================================

.macro SAVE_CONTEXT
    // Allocate stack frame
    sub     sp, sp, #288

    // Save general purpose registers x0-x29
    stp     x0, x1, [sp, #0x00]
    stp     x2, x3, [sp, #0x10]
    stp     x4, x5, [sp, #0x20]
    stp     x6, x7, [sp, #0x30]
    stp     x8, x9, [sp, #0x40]
    stp     x10, x11, [sp, #0x50]
    stp     x12, x13, [sp, #0x60]
    stp     x14, x15, [sp, #0x70]
    stp     x16, x17, [sp, #0x80]
    stp     x18, x19, [sp, #0x90]
    stp     x20, x21, [sp, #0xa0]
    stp     x22, x23, [sp, #0xb0]
    stp     x24, x25, [sp, #0xc0]
    stp     x26, x27, [sp, #0xd0]
    stp     x28, x29, [sp, #0xe0]

    // Save x30 (lr)
    str     x30, [sp, #0xf0]

    // Save original sp (before we allocated the frame)
    add     x0, sp, #288
    str     x0, [sp, #0xf8]

    // Save exception registers
    mrs     x0, elr_el1
    mrs     x1, spsr_el1
    stp     x0, x1, [sp, #0x100]

    mrs     x0, esr_el1
    mrs     x1, far_el1
    stp     x0, x1, [sp, #0x110]
.endm

.macro RESTORE_CONTEXT
    // Restore exception registers
    ldp     x0, x1, [sp, #0x100]
    msr     elr_el1, x0
    msr     spsr_el1, x1

    // Note: esr_el1 and far_el1 are read-only, no need to restore

    // Restore x30 (lr)
    ldr     x30, [sp, #0xf0]

    // Restore general purpose registers x0-x29
    ldp     x0, x1, [sp, #0x00]
    ldp     x2, x3, [sp, #0x10]
    ldp     x4, x5, [sp, #0x20]
    ldp     x6, x7, [sp, #0x30]
    ldp     x8, x9, [sp, #0x40]
    ldp     x10, x11, [sp, #0x50]
    ldp     x12, x13, [sp, #0x60]
    ldp     x14, x15, [sp, #0x70]
    ldp     x16, x17, [sp, #0x80]
    ldp     x18, x19, [sp, #0x90]
    ldp     x20, x21, [sp, #0xa0]
    ldp     x22, x23, [sp, #0xb0]
    ldp     x24, x25, [sp, #0xc0]
    ldp     x26, x27, [sp, #0xd0]
    ldp     x28, x29, [sp, #0xe0]

    // Deallocate stack frame
    add     sp, sp, #288

    // Return from exception
    eret
.endm

// ============================================================================
// Exception Vector Table
// Each entry is exactly 128 bytes (0x80) and just branches to the handler
// ============================================================================

.section .text.vectors
.balign 0x800
.global exception_vectors
exception_vectors:

// Current EL with SP_EL0 (offset 0x000 - 0x180)
.balign 0x80
    b       exception_stub          // 0x000: Sync
.balign 0x80
    b       exception_stub          // 0x080: IRQ
.balign 0x80
    b       exception_stub          // 0x100: FIQ
.balign 0x80
    b       exception_stub          // 0x180: SError

// Current EL with SP_ELx (offset 0x200 - 0x380)
.balign 0x80
    b       el1_sync_handler        // 0x200: Sync
.balign 0x80
    b       el1_irq_handler         // 0x280: IRQ
.balign 0x80
    b       el1_fiq_handler         // 0x300: FIQ
.balign 0x80
    b       el1_serror_handler      // 0x380: SError

// Lower EL, AArch64 (offset 0x400 - 0x580)
.balign 0x80
    b       el0_sync_handler        // 0x400: Sync
.balign 0x80
    b       el0_irq_handler         // 0x480: IRQ
.balign 0x80
    b       el0_fiq_handler         // 0x500: FIQ
.balign 0x80
    b       el0_serror_handler      // 0x580: SError

// Lower EL, AArch32 (offset 0x600 - 0x780)
.balign 0x80
    b       exception_stub          // 0x600: Sync
.balign 0x80
    b       exception_stub          // 0x680: IRQ
.balign 0x80
    b       exception_stub          // 0x700: FIQ
.balign 0x80
    b       exception_stub          // 0x780: SError

// ============================================================================
// Actual exception handlers (outside the vector table)
// ============================================================================

.section .text

// switch_context_and_restore: Called from Rust context_switch
// x0 = new SP (pointing to the new task's ExceptionContext)
// This function does NOT return - it switches stack and does ERET
.global switch_context_and_restore
switch_context_and_restore:
    mov     sp, x0
    RESTORE_CONTEXT
    // RESTORE_CONTEXT ends with ERET, so we never return

// EL1 Sync handler
el1_sync_handler:
    SAVE_CONTEXT
    mov     x0, sp              // ctx pointer
    mov     x1, #0              // exception type: sync
    bl      handle_el1_sync
    RESTORE_CONTEXT

// EL1 IRQ handler
el1_irq_handler:
    SAVE_CONTEXT
    mov     x0, sp
    mov     x1, #1              // exception type: irq
    bl      handle_el1_irq
    RESTORE_CONTEXT

// EL1 FIQ handler
el1_fiq_handler:
    SAVE_CONTEXT
    mov     x0, sp
    mov     x1, #2              // exception type: fiq
    bl      handle_el1_fiq
    RESTORE_CONTEXT

// EL1 SError handler
el1_serror_handler:
    SAVE_CONTEXT
    mov     x0, sp
    mov     x1, #3              // exception type: serror
    bl      handle_el1_serror
    RESTORE_CONTEXT

// EL0 Sync handler
el0_sync_handler:
    SAVE_CONTEXT
    mov     x0, sp
    mov     x1, #0              // exception type: sync
    bl      handle_el0_sync
    RESTORE_CONTEXT

// EL0 IRQ handler
el0_irq_handler:
    SAVE_CONTEXT
    mov     x0, sp
    mov     x1, #1              // exception type: irq
    bl      handle_el0_irq
    RESTORE_CONTEXT

// EL0 FIQ handler
el0_fiq_handler:
    SAVE_CONTEXT
    mov     x0, sp
    mov     x1, #2              // exception type: fiq
    bl      handle_el0_fiq
    RESTORE_CONTEXT

// EL0 SError handler
el0_serror_handler:
    SAVE_CONTEXT
    mov     x0, sp
    mov     x1, #3              // exception type: serror
    bl      handle_el0_serror
    RESTORE_CONTEXT

// Stub for unused vectors
exception_stub:
    b       exception_stub      // Infinite loop
