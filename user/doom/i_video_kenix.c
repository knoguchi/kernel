// Kenix framebuffer video implementation for DOOM
// Uses IPC to fbdev server for display

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <time.h>

#include "doomstat.h"
#include "i_system.h"
#include "v_video.h"
#include "m_argv.h"
#include "d_main.h"
#include "doomdef.h"

// Kenix syscall numbers
#define SYS_CALL        3
#define SYS_SHMCREATE   10
#define SYS_SHMMAP      11
#define SYS_SHMGRANT    13

// Fbdev task ID
#define TASK_FBDEV      7

// IPC message tags
#define FB_INIT         400
#define FB_BLIT         410
#define ERR_OK          0

// Console server
#define TASK_CONSOLE    1
#define MSG_READ_NONBLOCK 302   // Non-blocking read from console

// IPC message structure (must match kernel's 40-byte layout)
typedef struct {
    uint64_t tag;
    uint64_t data[4];
} ipc_msg_t;

// Framebuffer configuration
#define FB_WIDTH  800
#define FB_HEIGHT 600
#define FB_BPP    4

// Scale factor (2x for 320x200 -> 640x400)
static int multiply = 2;

// Local framebuffer for conversion
static uint32_t *local_fb = NULL;
static int fb_width = FB_WIDTH;
static int fb_height = FB_HEIGHT;

// Shared memory for blitting
static int64_t shm_id = -1;
static uint32_t *shm_ptr = NULL;
static size_t shm_size = 0;

// Palette lookup table (8bpp -> 32bpp XRGB)
static uint32_t palette_rgb[256];

// Raw syscall wrappers
static inline long syscall3(long n, long a, long b, long c) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
    return x0;
}

// IPC call syscall - kernel expects: x0=dest, x1=tag, x2-x5=data[0-3]
// Returns: x0=reply_tag, x1-x4=reply_data[0-3]
static int ipc_call(int task_id, ipc_msg_t *msg) {
    register long x8 __asm__("x8") = SYS_CALL;
    register long x0 __asm__("x0") = task_id;
    register long x1 __asm__("x1") = msg->tag;
    register long x2 __asm__("x2") = msg->data[0];
    register long x3 __asm__("x3") = msg->data[1];
    register long x4 __asm__("x4") = msg->data[2];
    register long x5 __asm__("x5") = msg->data[3];

    __asm__ volatile(
        "svc #0"
        : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3), "+r"(x4)
        : "r"(x5), "r"(x8)
        : "memory"
    );

    // Store reply back into msg
    msg->tag = x0;
    msg->data[0] = x1;
    msg->data[1] = x2;
    msg->data[2] = x3;
    msg->data[3] = x4;

    return 0;  // Success
}

// Shared memory syscalls
static int64_t shm_create(size_t size) {
    return syscall3(SYS_SHMCREATE, size, 0, 0);
}

static void *shm_map(int64_t id, uintptr_t hint) {
    long result = syscall3(SYS_SHMMAP, id, hint, 0);
    if (result < 0) return NULL;
    return (void *)result;
}

static int shm_grant(int64_t id, int task_id) {
    return syscall3(SYS_SHMGRANT, id, task_id, 0);
}

// DOOM key translation from ASCII
static int translate_key(int key) {
    switch (key) {
        case 27:  return KEY_ESCAPE;
        case 13:  return KEY_ENTER;
        case '\t': return KEY_TAB;
        case 127:
        case 8:   return KEY_BACKSPACE;
        case ' ': return ' ';
        case 'w': case 'W': return KEY_UPARROW;
        case 's': case 'S': return KEY_DOWNARROW;
        case 'a': case 'A': return KEY_LEFTARROW;
        case 'd': case 'D': return KEY_RIGHTARROW;
        case 'f': case 'F': return KEY_RCTRL;
        case 'e': case 'E': return ' ';
        case 'q': case 'Q': return KEY_RALT;
        case '1': case '2': case '3': case '4':
        case '5': case '6': case '7':
            return key;
        case '-': return KEY_MINUS;
        case '=': return KEY_EQUALS;
        default:
            if (key >= 'a' && key <= 'z')
                return key;
            if (key >= 'A' && key <= 'Z')
                return key - 'A' + 'a';
            return key;
    }
}

// State machine for escape sequence parsing
// Arrow keys send: ESC [ A/B/C/D
static int escape_state = 0;  // 0=normal, 1=saw ESC, 2=saw ESC[

// Process escape sequences and return DOOM key code, or -1 to skip
static int process_escape_seq(unsigned char c) {
    switch (escape_state) {
        case 0:  // Normal state
            if (c == 0x1B) {  // ESC
                escape_state = 1;
                return -1;  // Don't emit key yet
            }
            return translate_key(c);

        case 1:  // Saw ESC
            escape_state = 0;  // Reset state regardless
            if (c == '[') {
                escape_state = 2;
                return -1;  // Don't emit key yet
            }
            // Not an escape sequence - ESC followed by regular char
            // Just ignore the ESC and return the regular key
            // (User pressing ESC then a letter quickly is rare in games)
            return translate_key(c);

        case 2:  // Saw ESC[
            escape_state = 0;  // Reset state
            switch (c) {
                case 'A': return KEY_UPARROW;
                case 'B': return KEY_DOWNARROW;
                case 'C': return KEY_RIGHTARROW;
                case 'D': return KEY_LEFTARROW;
                default:
                    // Unknown escape sequence, ignore entire sequence
                    return -1;
            }
    }
    return translate_key(c);
}

void I_ShutdownGraphics(void) {
    // Nothing to clean up
}

void I_StartFrame(void) {
    // Nothing needed
}

void I_GetEvent(void) {
    event_t event;
    ipc_msg_t msg;

    // Non-blocking keyboard poll using direct IPC
    msg.tag = MSG_READ_NONBLOCK;
    msg.data[0] = 8;  // max bytes to read
    msg.data[1] = msg.data[2] = msg.data[3] = 0;

    ipc_call(TASK_CONSOLE, &msg);

    // msg.tag = bytes read (0-8)
    // msg.data[0] = bytes read
    // msg.data[1-3] = data (up to 24 bytes inline)
    int bytes_read = (int)msg.tag;
    if (bytes_read <= 0) return;

    unsigned char *data = (unsigned char *)&msg.data[1];
    int i;
    for (i = 0; i < bytes_read; i++) {
        unsigned char c = data[i];

        // Process through escape sequence handler
        int key = process_escape_seq(c);
        if (key < 0) continue;  // Part of escape sequence, skip

        event.type = ev_keydown;
        event.data1 = key;
        event.data2 = event.data3 = 0;
        D_PostEvent(&event);

        event.type = ev_keyup;
        D_PostEvent(&event);
    }
}

void I_StartTic(void) {
    I_GetEvent();
}

void I_UpdateNoBlit(void) {
    // Nothing
}

// Convert 8bpp paletted framebuffer to 32bpp XRGB and blit via IPC
void I_FinishUpdate(void) {
    if (!shm_ptr) return;
    if (!screens[0]) return;

    // Convert and scale 320x200 8bpp to 640x400 32bpp (2x scale)
    uint8_t *src = screens[0];
    int x, y;
    int scaled_width = SCREENWIDTH * multiply;
    int scaled_height = SCREENHEIGHT * multiply;
    uint32_t *dst = shm_ptr;
    uint32_t color;

    if (multiply == 2) {
        for (y = 0; y < SCREENHEIGHT; y++) {
            uint32_t *row1 = dst + (y * 2) * scaled_width;
            uint32_t *row2 = row1 + scaled_width;
            for (x = 0; x < SCREENWIDTH; x++) {
                color = palette_rgb[src[y * SCREENWIDTH + x]];
                row1[x * 2] = color;
                row1[x * 2 + 1] = color;
                row2[x * 2] = color;
                row2[x * 2 + 1] = color;
            }
        }
    } else {
        for (y = 0; y < SCREENHEIGHT; y++) {
            for (x = 0; x < SCREENWIDTH; x++) {
                dst[y * scaled_width + x] = palette_rgb[src[y * SCREENWIDTH + x]];
            }
        }
    }

    int offset_x = (fb_width - scaled_width) / 2;
    int offset_y = (fb_height - scaled_height) / 2;

    // Call fbdev to blit
    ipc_msg_t msg;
    msg.tag = FB_BLIT;
    msg.data[0] = (uint64_t)shm_id;
    msg.data[1] = offset_x | ((uint64_t)offset_y << 16);
    msg.data[2] = scaled_width | ((uint64_t)scaled_height << 16);
    msg.data[3] = scaled_width * 4;  // stride in bytes

    ipc_call(TASK_FBDEV, &msg);
}

void I_ReadScreen(byte *scr) {
    memcpy(scr, screens[0], SCREENWIDTH * SCREENHEIGHT);
}

void I_SetPalette(byte *palette) {
    int i;
    int r, g, b;
    for (i = 0; i < 256; i++) {
        r = gammatable[usegamma][palette[i * 3 + 0]];
        g = gammatable[usegamma][palette[i * 3 + 1]];
        b = gammatable[usegamma][palette[i * 3 + 2]];
        palette_rgb[i] = (r << 16) | (g << 8) | b;
    }
}

void I_InitGraphics(void) {
    static int firsttime = 1;

    if (!firsttime) return;
    firsttime = 0;

    if (M_CheckParm("-1"))
        multiply = 1;
    if (M_CheckParm("-2"))
        multiply = 2;
    if (M_CheckParm("-3"))
        multiply = 3;

    // Query fbdev for screen dimensions
    ipc_msg_t msg;
    msg.tag = FB_INIT;
    msg.data[0] = msg.data[1] = msg.data[2] = msg.data[3] = 0;
    ipc_call(TASK_FBDEV, &msg);
    if (msg.tag == ERR_OK) {
        fb_width = msg.data[0];
        fb_height = msg.data[1];
    }

    // Allocate shared memory for blitting
    int scaled_width = SCREENWIDTH * multiply;
    int scaled_height = SCREENHEIGHT * multiply;
    shm_size = scaled_width * scaled_height * 4;

    shm_id = shm_create(shm_size);
    if (shm_id < 0) {
        I_Error("Could not create shared memory for framebuffer");
    }

    shm_ptr = (uint32_t *)shm_map(shm_id, 0);
    if (!shm_ptr) {
        I_Error("Could not map shared memory");
    }

    // Grant fbdev access to our shared memory
    if (shm_grant(shm_id, TASK_FBDEV) < 0) {
        I_Error("Could not grant fbdev access to shared memory");
    }

    // Clear to black
    memset(shm_ptr, 0, shm_size);

    // Initialize default palette (DOOM will override via I_SetPalette)
    {
        int i;
        for (i = 0; i < 256; i++) {
            palette_rgb[i] = (i << 16) | (i << 8) | i;  // grayscale fallback
        }
    }

    // Allocate DOOM's 320x200 8bpp screen buffer
    screens[0] = (unsigned char *)malloc(SCREENWIDTH * SCREENHEIGHT);
    if (!screens[0]) {
        I_Error("Could not allocate screen buffer");
    }
}
