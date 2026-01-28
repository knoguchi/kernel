// Context switch assembly for Kenix scheduler
//
// This file implements low-level context switching between tasks.
// The switch saves callee-saved registers and swaps stacks/page tables.

.section .text

// ============================================================================
// task_switch - Switch from current task to next task
// ============================================================================
//
// Arguments:
//   x0: Pointer to current task's SP storage (*mut usize)
//   x1: Next task's SP value
//   x2: Next task's TTBR0_EL1 value (page table)
//
// This function:
//   1. Saves callee-saved registers (x19-x30) on current stack
//   2. Saves current SP to *x0
//   3. Switches page tables (if different)
//   4. Loads new SP from x1
//   5. Restores callee-saved registers from new stack
//   6. Returns to caller (now in context of new task)
//
// Note: Caller-saved registers (x0-x18) are NOT saved here.
// They are saved/restored by the exception entry/exit code.

.global task_switch
.type task_switch, @function
task_switch:
    // Save callee-saved registers on current stack
    // TaskContext layout: x19-x30 (12 registers × 8 bytes = 96 bytes)
    stp     x19, x20, [sp, #-96]!
    stp     x21, x22, [sp, #16]
    stp     x23, x24, [sp, #32]
    stp     x25, x26, [sp, #48]
    stp     x27, x28, [sp, #64]
    stp     x29, x30, [sp, #80]

    // Save current stack pointer to *x0
    mov     x3, sp
    str     x3, [x0]

    // Check if we need to switch page tables (x2 != 0 means switch)
    cbz     x2, .Lskip_ttbr_switch

    // Switch page tables
    msr     ttbr0_el1, x2
    isb

    // Invalidate TLB for VMID (all entries for this ASID)
    tlbi    vmalle1
    dsb     ish
    isb

.Lskip_ttbr_switch:
    // Switch to new stack
    mov     sp, x1

    // Restore callee-saved registers from new stack
    ldp     x29, x30, [sp, #80]
    ldp     x27, x28, [sp, #64]
    ldp     x25, x26, [sp, #48]
    ldp     x23, x24, [sp, #32]
    ldp     x21, x22, [sp, #16]
    ldp     x19, x20, [sp], #96

    // Return to caller (now in context of new task)
    ret

.size task_switch, . - task_switch

// ============================================================================
// task_switch_first - Start running a task for the first time
// ============================================================================
//
// Arguments:
//   x0: New task's SP value (pointing to initial context)
//   x1: New task's TTBR0_EL1 value (page table)
//   x2: Entry point address
//   x3: SPSR_EL1 value (processor state for the new task)
//
// This is called when switching to a task that has never run before.
// It sets up ELR_EL1/SPSR_EL1 and does ERET to start the task.

.global task_switch_first
.type task_switch_first, @function
task_switch_first:
    // Switch page tables if provided
    cbz     x1, .Lskip_ttbr_first

    msr     ttbr0_el1, x1
    isb
    tlbi    vmalle1
    dsb     ish
    isb

.Lskip_ttbr_first:
    // Switch to new stack
    mov     sp, x0

    // Set up return address and processor state
    msr     elr_el1, x2
    msr     spsr_el1, x3

    // Clear all general purpose registers for clean start
    mov     x0, #0
    mov     x1, #0
    mov     x2, #0
    mov     x3, #0
    mov     x4, #0
    mov     x5, #0
    mov     x6, #0
    mov     x7, #0
    mov     x8, #0
    mov     x9, #0
    mov     x10, #0
    mov     x11, #0
    mov     x12, #0
    mov     x13, #0
    mov     x14, #0
    mov     x15, #0
    mov     x16, #0
    mov     x17, #0
    mov     x18, #0
    mov     x19, #0
    mov     x20, #0
    mov     x21, #0
    mov     x22, #0
    mov     x23, #0
    mov     x24, #0
    mov     x25, #0
    mov     x26, #0
    mov     x27, #0
    mov     x28, #0
    mov     x29, #0
    mov     x30, #0

    // Return from exception to start the new task
    eret

.size task_switch_first, . - task_switch_first

// ============================================================================
// get_current_sp - Get the current stack pointer
// ============================================================================
//
// Returns: Current SP value in x0
//
// Useful for saving the initial SP when setting up a new task

.global get_current_sp
.type get_current_sp, @function
get_current_sp:
    mov     x0, sp
    ret

.size get_current_sp, . - get_current_sp
