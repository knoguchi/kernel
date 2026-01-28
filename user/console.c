// Console server for Kenix
// User-space server that handles console I/O via IPC
//
// This server receives MSG_WRITE messages and writes to the UART.
// The UART MMIO region is mapped into this task's address space.
// Also supports MSG_SHM_WRITE for large data via shared memory.

#include "ipc.h"
#include "shm.h"

// QEMU virt machine PL011 UART
// This address is mapped into console server's address space by the kernel
#define UART_BASE 0x09000000UL
#define UART_DR   (*(volatile unsigned char*)(UART_BASE + 0x000))
#define UART_FR   (*(volatile unsigned int*)(UART_BASE + 0x018))
#define UART_FR_TXFF (1 << 5)  // TX FIFO full

// Write a single character to UART
static void uart_putc(char c) {
    // Wait for TX FIFO to have space
    while (UART_FR & UART_FR_TXFF) {
        // Spin
    }
    UART_DR = c;
}

// Write a buffer to UART
static unsigned long uart_write(const char *buf, unsigned long len) {
    for (unsigned long i = 0; i < len; i++) {
        uart_putc(buf[i]);
    }
    return len;
}

// Track mapped SHM regions per client (simple approach: one per client)
#define MAX_CLIENTS 64
static struct {
    ShmId shm_id;
    void *mapped_addr;
    int valid;
} client_shm[MAX_CLIENTS];

// Get or map SHM for a client
static void* get_client_shm(unsigned long client_id, ShmId shm_id) {
    if (client_id >= MAX_CLIENTS) {
        return (void*)0;
    }

    // Check if already mapped
    if (client_shm[client_id].valid && client_shm[client_id].shm_id == shm_id) {
        return client_shm[client_id].mapped_addr;
    }

    // Unmap old one if different
    if (client_shm[client_id].valid) {
        sys_shmunmap(client_shm[client_id].shm_id);
        client_shm[client_id].valid = 0;
    }

    // Map the new one
    void *addr = sys_shmmap(shm_id, (void*)0);
    if ((long)addr < 0) {
        return (void*)0;
    }

    client_shm[client_id].shm_id = shm_id;
    client_shm[client_id].mapped_addr = addr;
    client_shm[client_id].valid = 1;

    return addr;
}

// Console server main loop
void console_main(void) {
    // Initialize client SHM tracking
    for (int i = 0; i < MAX_CLIENTS; i++) {
        client_shm[i].valid = 0;
    }

    // Print startup message
    const char *startup = "[console] Server started\n";
    for (const char *p = startup; *p; p++) {
        uart_putc(*p);
    }

    // Main message processing loop
    while (1) {
        // Wait for a message from any task
        RecvResult recv = sys_recv(TASK_ANY);

        if (recv.msg.tag == MSG_WRITE) {
            // MSG_WRITE: data[0] = length, data[1-3] = inline string data (up to 24 bytes)
            unsigned long len = recv.msg.data[0];
            const char *buf = (const char*)&recv.msg.data[1];

            // Limit to actual inline data capacity
            if (len > 24) {
                len = 24;
            }

            // Write to UART
            unsigned long written = uart_write(buf, len);

            // Reply with number of bytes written
            Message reply = {
                .tag = written,
                .data = {0, 0, 0, 0}
            };
            sys_reply(&reply);
        } else if (recv.msg.tag == MSG_SHM_WRITE) {
            // MSG_SHM_WRITE: data[0]=shm_id, data[1]=offset, data[2]=len
            ShmId shm_id = recv.msg.data[0];
            unsigned long offset = recv.msg.data[1];
            unsigned long len = recv.msg.data[2];

            // Get mapped address for this client's SHM
            void *shm_base = get_client_shm(recv.sender, shm_id);
            if (shm_base == (void*)0) {
                // Failed to map SHM
                Message reply = {
                    .tag = (unsigned long)SHM_ERR_INVALID,
                    .data = {0, 0, 0, 0}
                };
                sys_reply(&reply);
                continue;
            }

            // Write from SHM to UART
            const char *buf = (const char*)shm_base + offset;
            unsigned long written = uart_write(buf, len);

            // Reply with number of bytes written
            Message reply = {
                .tag = written,
                .data = {0, 0, 0, 0}
            };
            sys_reply(&reply);
        } else if (recv.msg.tag == MSG_EXIT) {
            // MSG_EXIT: client wants to terminate
            // Just reply with success
            Message reply = {
                .tag = IPC_OK,
                .data = {0, 0, 0, 0}
            };
            sys_reply(&reply);
        } else {
            // Unknown message - reply with error
            Message reply = {
                .tag = (unsigned long)IPC_ERR_INVALID,
                .data = {0, 0, 0, 0}
            };
            sys_reply(&reply);
        }
    }
}
