// User-space init program for Kenix
// Runs in EL0 (user mode) and uses IPC to communicate with services

#include "ipc.h"

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

// Print a string to console server via IPC
// For strings up to 32 bytes, we copy them inline into the message data.
// This avoids cross-address-space pointer issues.
static void print(const char *s) {
    unsigned long len = strlen(s);

    // data[0] = length, data[1-3] hold up to 24 bytes of string data
    // For larger strings, we'd need shared memory
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

int main(void) {
    print("Hello via IPC!\n");        // 15 chars + newline = 16
    print("Init running in EL0\n");   // 19 chars + newline = 20
    print("IPC works!\n");            // 10 chars + newline = 11
    exit_legacy(0);
    return 0;
}
