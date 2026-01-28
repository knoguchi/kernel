// User-space init program for Kenix
// Runs in EL0 (user mode) and uses IPC to communicate with services

#include "ipc.h"
#include "shm.h"

// Console server task ID (created first, so it's task 1)
// Task 0 is idle, task 1 is console, task 2 is init (us)
#define CONSOLE_SERVER 1

// Legacy syscall for exit (until we have a proper exit server)
#define SYS_EXIT_LEGACY 93

static inline void exit_legacy(int code) {
    register long x0 __asm__("x0") = code;
    register long x8 __asm__("x8") = SYS_EXIT_LEGACY;
    __asm__ volatile(
        "svc #0"
        : "+r"(x0)
        : "r"(x8)
        : "memory"
    );
    __builtin_unreachable();
}

// Calculate string length
static unsigned long strlen(const char *s) {
    unsigned long len = 0;
    while (*s++) len++;
    return len;
}

// Copy memory
static void memcpy(void *dst, const void *src, unsigned long n) {
    unsigned char *d = dst;
    const unsigned char *s = src;
    while (n--) *d++ = *s++;
}

// Print a short string (up to 24 bytes) via inline IPC
static void print(const char *s) {
    unsigned long len = strlen(s);

    // data[0] = length, data[1-3] hold up to 24 bytes of string data
    Message msg = {
        .tag = MSG_WRITE,
        .data = {len, 0, 0, 0}
    };

    // Copy string into data[1-3] (up to 24 bytes)
    unsigned char *dest = (unsigned char *)&msg.data[1];
    unsigned long copy_len = len > 24 ? 24 : len;
    memcpy(dest, s, copy_len);

    sys_call(CONSOLE_SERVER, &msg);
}

// Print a long string via shared memory IPC
// shm: Shared memory region ID (already created and granted to console)
// buf: Mapped shared memory buffer
// s: String to print
static void print_shm(ShmId shm, char *buf, const char *s) {
    unsigned long len = strlen(s);

    // Copy string to shared memory buffer
    memcpy(buf, s, len);

    // Send SHM write message
    Message msg = {
        .tag = MSG_SHM_WRITE,
        .data = {shm, 0, len, 0}  // shm_id, offset, length
    };

    sys_call(CONSOLE_SERVER, &msg);
}

int main(void) {
    // Test basic inline IPC first
    print("Hello via IPC!\n");
    print("Init running in EL0\n");
    print("IPC works!\n");

#if 1  // Set to 1 to test SHM, 0 to skip
    // Create shared memory for long strings
    long shm_id = sys_shmcreate(4096);  // 4KB buffer
    if (shm_id < 0) {
        print("SHM create failed!\n");
        exit_legacy(1);
    }

    // Grant console server (task 1) access
    if (sys_shmgrant(shm_id, CONSOLE_SERVER) < 0) {
        print("SHM grant failed!\n");
        exit_legacy(1);
    }

    // Map the shared memory
    char *shm_buf = (char*)sys_shmmap(shm_id, (void*)0);
    if ((long)shm_buf < 0) {
        print("SHM map failed!\n");
        exit_legacy(1);
    }

    // Now we can print long strings via shared memory!
    print_shm(shm_id, shm_buf,
        "This is a much longer string that exceeds the 24-byte inline limit "
        "and demonstrates shared memory IPC working correctly!\n");

    print_shm(shm_id, shm_buf,
        "Shared memory enables efficient transfer of large data between "
        "tasks without copying through the kernel message registers.\n");

    // Clean up
    sys_shmunmap(shm_id);

    print("SHM test complete!\n");
#endif

    exit_legacy(0);
    return 0;
}
