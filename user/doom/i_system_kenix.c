// Kenix system implementation for DOOM
// Provides timing, memory, and system services

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>

#include "doomdef.h"
#include "m_misc.h"
#include "i_video.h"
#include "i_sound.h"
#include "d_net.h"
#include "g_game.h"
#include "i_system.h"

// Memory pool size in MB
int mb_used = 8;

void I_Tactile(int on, int off, int total) {
    // Unused
    (void)on;
    (void)off;
    (void)total;
}

ticcmd_t emptycmd;

ticcmd_t *I_BaseTiccmd(void) {
    return &emptycmd;
}

int I_GetHeapSize(void) {
    return mb_used * 1024 * 1024;
}

byte *I_ZoneBase(int *size) {
    *size = mb_used * 1024 * 1024;
    byte *zone = (byte *)malloc(*size);
    if (!zone) {
        fprintf(stderr, "Error: Could not allocate %d MB for zone\n", mb_used);
        exit(1);
    }
    return zone;
}

// Returns time in 1/35th second tics (TICRATE = 35)
int I_GetTime(void) {
    struct timespec ts;
    static long basetime_sec = 0;
    static long basetime_nsec = 0;

    clock_gettime(CLOCK_MONOTONIC, &ts);

    if (basetime_sec == 0 && basetime_nsec == 0) {
        basetime_sec = ts.tv_sec;
        basetime_nsec = ts.tv_nsec;
    }

    long elapsed_sec = ts.tv_sec - basetime_sec;
    long elapsed_nsec = ts.tv_nsec - basetime_nsec;

    // Convert to tics (1/35 second each)
    // tics = elapsed_seconds * 35 + elapsed_nsec * 35 / 1000000000
    int tics = (int)(elapsed_sec * TICRATE +
                     (elapsed_nsec * TICRATE) / 1000000000L);

    return tics;
}

void I_Init(void) {
    I_InitSound();
}

void I_Quit(void) {
    D_QuitNetGame();
    I_ShutdownSound();
    I_ShutdownMusic();
    M_SaveDefaults();
    I_ShutdownGraphics();
    exit(0);
}

void I_WaitVBL(int count) {
    // Wait for count * (1/70) seconds
    // Using usleep for microseconds
    usleep(count * (1000000 / 70));
}

void I_BeginRead(void) {
    // Disk access indicator - nothing to do
}

void I_EndRead(void) {
    // Disk access indicator - nothing to do
}

byte *I_AllocLow(int length) {
    byte *mem = (byte *)malloc(length);
    if (mem) {
        memset(mem, 0, length);
    }
    return mem;
}

extern boolean demorecording;

void I_Error(char *error, ...) {
    va_list argptr;

    // Print error message
    va_start(argptr, error);
    fprintf(stderr, "Error: ");
    vfprintf(stderr, error, argptr);
    fprintf(stderr, "\n");
    va_end(argptr);

    fflush(stderr);

    // Shutdown
    if (demorecording)
        G_CheckDemoStatus();

    D_QuitNetGame();
    I_ShutdownGraphics();

    exit(-1);
}
