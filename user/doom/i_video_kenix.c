// Kenix framebuffer video implementation for DOOM
// Uses direct framebuffer access instead of X11

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

// Framebuffer configuration
#define FB_WIDTH  800
#define FB_HEIGHT 600
#define FB_BPP    4  // 32bpp XRGB

// Fixed virtual address for framebuffer (shared with fbdev)
#define FRAMEBUFFER_VADDR 0x2000_0000UL

// Scale factor (2x for 320x200 -> 640x400)
static int multiply = 2;

// Framebuffer pointer
static uint32_t *framebuffer = NULL;
static int fb_width = FB_WIDTH;
static int fb_height = FB_HEIGHT;
static int fb_stride = FB_WIDTH * FB_BPP;

// Palette lookup table (8bpp -> 32bpp XRGB)
static uint32_t palette_rgb[256];

// Keyboard input state
static int keyboard_fd = -1;

// Keyboard buffer for non-blocking input
#define KB_BUFFER_SIZE 32
static unsigned char kb_buffer[KB_BUFFER_SIZE];
static int kb_head = 0;
static int kb_tail = 0;

// DOOM key translation from ASCII
static int translate_key(int key) {
    switch (key) {
        case 27:  return KEY_ESCAPE;
        case 13:  return KEY_ENTER;
        case '\t': return KEY_TAB;
        case 127: // DEL
        case 8:   return KEY_BACKSPACE;
        case ' ': return ' ';
        // Arrow keys (using ANSI escape sequences would be complex,
        // for now use WASD)
        case 'w': case 'W': return KEY_UPARROW;
        case 's': case 'S': return KEY_DOWNARROW;
        case 'a': case 'A': return KEY_LEFTARROW;
        case 'd': case 'D': return KEY_RIGHTARROW;
        // Fire/use
        case 'f': case 'F': return KEY_RCTRL;  // Fire
        case 'e': case 'E': return ' ';        // Use
        case 'q': case 'Q': return KEY_RALT;   // Strafe
        // Weapons
        case '1': case '2': case '3': case '4':
        case '5': case '6': case '7':
            return key;
        // Movement
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

void I_ShutdownGraphics(void) {
    // Nothing to clean up - framebuffer is kernel-managed
}

void I_StartFrame(void) {
    // Nothing needed
}

// Poll keyboard input from stdin
void I_GetEvent(void) {
    event_t event;
    unsigned char c;
    ssize_t n;

    // Non-blocking read from stdin
    while ((n = read(0, &c, 1)) > 0) {
        event.type = ev_keydown;
        event.data1 = translate_key(c);
        event.data2 = event.data3 = 0;
        D_PostEvent(&event);

        // Also post keyup immediately (simple polling)
        // This is a simplification - proper implementation would
        // track key state
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

// Convert 8bpp paletted framebuffer to 32bpp XRGB and display
void I_FinishUpdate(void) {
    static int lasttic;
    int tics;
    int i;

    if (!framebuffer) return;

    // Draw timing dots for dev mode
    if (devparm) {
        i = I_GetTime();
        tics = i - lasttic;
        lasttic = i;
        if (tics > 20) tics = 20;

        for (i = 0; i < tics * 2; i += 2)
            screens[0][(SCREENHEIGHT - 1) * SCREENWIDTH + i] = 0xff;
        for (; i < 20 * 2; i += 2)
            screens[0][(SCREENHEIGHT - 1) * SCREENWIDTH + i] = 0x0;
    }

    // Convert and scale 320x200 8bpp to 640x400 32bpp (2x scale)
    uint8_t *src = screens[0];
    int x, y;
    int offset_x, offset_y;
    uint32_t *dst_row;
    uint32_t *dst_row1;
    uint32_t *dst_row2;
    uint32_t color;

    // Center on screen
    offset_x = (fb_width - SCREENWIDTH * multiply) / 2;
    offset_y = (fb_height - SCREENHEIGHT * multiply) / 2;

    if (multiply == 2) {
        for (y = 0; y < SCREENHEIGHT; y++) {
            dst_row1 = framebuffer + (offset_y + y * 2) * (fb_stride / 4) + offset_x;
            dst_row2 = dst_row1 + (fb_stride / 4);

            for (x = 0; x < SCREENWIDTH; x++) {
                color = palette_rgb[src[y * SCREENWIDTH + x]];
                // 2x2 pixel block
                dst_row1[x * 2] = color;
                dst_row1[x * 2 + 1] = color;
                dst_row2[x * 2] = color;
                dst_row2[x * 2 + 1] = color;
            }
        }
    } else {
        // 1x scale
        for (y = 0; y < SCREENHEIGHT; y++) {
            dst_row = framebuffer + (offset_y + y) * (fb_stride / 4) + offset_x;
            for (x = 0; x < SCREENWIDTH; x++) {
                dst_row[x] = palette_rgb[src[y * SCREENWIDTH + x]];
            }
        }
    }

    // Note: In a full implementation, we'd signal fbdev to flush
    // For virtio-gpu this happens automatically on the next vsync
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
        // XRGB format (used by Kenix fbdev)
        palette_rgb[i] = (r << 16) | (g << 8) | b;
    }
}

void I_InitGraphics(void) {
    static int firsttime = 1;

    if (!firsttime) return;
    firsttime = 0;

    // Check for scale arguments
    if (M_CheckParm("-1"))
        multiply = 1;
    if (M_CheckParm("-2"))
        multiply = 2;
    if (M_CheckParm("-3"))
        multiply = 3;

    printf("[doom] Initializing graphics %dx%d scaled %dx\n",
           SCREENWIDTH, SCREENHEIGHT, multiply);

    // Map framebuffer
    // In Kenix, this is done via mmap with MAP_FIXED to a known address
    // The kernel pre-maps the framebuffer for fbdev
    // For now, we use anonymous memory and will integrate with fbdev later
    framebuffer = (uint32_t *)mmap(
        (void *)0x30000000,  // Hint address for doom framebuffer
        FB_WIDTH * FB_HEIGHT * FB_BPP,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0
    );

    if (framebuffer == MAP_FAILED) {
        I_Error("Could not allocate framebuffer memory");
    }

    // Clear to black
    memset(framebuffer, 0, FB_WIDTH * FB_HEIGHT * FB_BPP);

    // Allocate DOOM's 320x200 8bpp screen buffer
    screens[0] = (unsigned char *)malloc(SCREENWIDTH * SCREENHEIGHT);
    if (!screens[0]) {
        I_Error("Could not allocate screen buffer");
    }

    printf("[doom] Graphics initialized: %dx%d @ 32bpp, scale=%d\n",
           fb_width, fb_height, multiply);
}
