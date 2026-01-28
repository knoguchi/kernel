// Console server for Kenix
// User-space server that handles console I/O via IPC
//
// This server receives MSG_WRITE messages and writes to the UART.
// The UART MMIO region is mapped into this task's address space.

#include "ipc.h"

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

// Console server main loop
void console_main(void) {
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
