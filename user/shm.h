// Shared Memory API for Kenix userspace
#ifndef _KENIX_SHM_H
#define _KENIX_SHM_H

// Shared memory region ID type
typedef unsigned long ShmId;

// Syscall numbers
#define SYS_SHMCREATE 10
#define SYS_SHMMAP    11
#define SYS_SHMUNMAP  12
#define SYS_SHMGRANT  13

// Error codes
#define SHM_OK            0
#define SHM_ERR_INVALID  -1
#define SHM_ERR_NO_MEMORY -2
#define SHM_ERR_PERMISSION -3
#define SHM_ERR_ALREADY_MAPPED -4
#define SHM_ERR_NOT_MAPPED -5
#define SHM_ERR_NO_SLOTS -6

// Create a new shared memory region
// size: Size in bytes (will be rounded up to 4KB page alignment)
// Returns: Shared memory ID on success, negative error code on failure
static inline long sys_shmcreate(unsigned long size) {
    register unsigned long x0 __asm__("x0") = size;
    register unsigned long x8 __asm__("x8") = SYS_SHMCREATE;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory");
    return (long)x0;
}

// Map a shared memory region into the current task's address space
// id: Shared memory region ID
// hint: Suggested virtual address (0 for auto-allocation, must be 4KB aligned)
// Returns: Virtual address of the mapped region on success, negative error code on failure
static inline void* sys_shmmap(ShmId id, void *hint) {
    register unsigned long x0 __asm__("x0") = id;
    register unsigned long x1 __asm__("x1") = (unsigned long)hint;
    register unsigned long x8 __asm__("x8") = SYS_SHMMAP;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x8) : "memory");
    return (void*)x0;
}

// Unmap a shared memory region from the current task's address space
// id: Shared memory region ID
// Returns: 0 on success, negative error code on failure
static inline long sys_shmunmap(ShmId id) {
    register unsigned long x0 __asm__("x0") = id;
    register unsigned long x8 __asm__("x8") = SYS_SHMUNMAP;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory");
    return (long)x0;
}

// Grant another task permission to map the shared memory region
// id: Shared memory region ID
// task_id: Task ID to grant access to
// Returns: 0 on success, negative error code on failure
static inline long sys_shmgrant(ShmId id, unsigned long task_id) {
    register unsigned long x0 __asm__("x0") = id;
    register unsigned long x1 __asm__("x1") = task_id;
    register unsigned long x8 __asm__("x8") = SYS_SHMGRANT;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x8) : "memory");
    return (long)x0;
}

#endif // _KENIX_SHM_H
