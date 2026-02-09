// Kenix network stubs for DOOM
// Network/multiplayer is not yet implemented

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "i_system.h"
#include "d_event.h"
#include "d_net.h"
#include "m_argv.h"
#include "doomstat.h"
#include "i_net.h"

void I_InitNetwork(void) {
    // Initialize for single player only

    doomcom = malloc(sizeof(*doomcom));
    if (!doomcom) {
        I_Error("I_InitNetwork: Could not allocate doomcom");
    }
    memset(doomcom, 0, sizeof(*doomcom));

    // Single player configuration
    doomcom->id = DOOMCOM_ID;
    doomcom->numplayers = 1;
    doomcom->numnodes = 1;
    doomcom->deathmatch = false;
    doomcom->consoleplayer = 0;
    doomcom->ticdup = 1;
    doomcom->extratics = 0;

    // Disable network game
    netgame = false;

    printf("[doom] Network disabled (single player only)\n");
}

void I_NetCmd(void) {
    // Stub - networking not supported
    // This should never be called in single player
}
