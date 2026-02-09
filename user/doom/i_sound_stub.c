// Kenix sound stubs for DOOM
// Sound is not yet implemented in Kenix

#include <stdio.h>
#include <stdlib.h>

#include "z_zone.h"
#include "i_system.h"
#include "i_sound.h"
#include "m_argv.h"
#include "m_misc.h"
#include "w_wad.h"
#include "doomdef.h"
#include "doomstat.h"

// Sound volumes are defined in s_sound.c
extern int snd_SfxVolume;
extern int snd_MusicVolume;

// sndserver_filename needed by m_misc defaults
char* sndserver_filename = "sndserver";
// mb_used is defined in i_system_kenix.c
extern int mb_used;

void I_SetChannels(void) {
    // Stub
}

void I_SetSfxVolume(int volume) {
    snd_SfxVolume = volume;
}

void I_SetMusicVolume(int volume) {
    snd_MusicVolume = volume;
}

int I_GetSfxLumpNum(sfxinfo_t *sfx) {
    char namebuf[9];
    sprintf(namebuf, "ds%s", sfx->name);
    return W_GetNumForName(namebuf);
}

int I_StartSound(int id, int vol, int sep, int pitch, int priority) {
    // Stub - no sound
    (void)id;
    (void)vol;
    (void)sep;
    (void)pitch;
    (void)priority;
    return 0;
}

void I_StopSound(int handle) {
    (void)handle;
}

int I_SoundIsPlaying(int handle) {
    (void)handle;
    return 0;
}

void I_UpdateSound(void) {
    // Stub
}

void I_SubmitSound(void) {
    // Stub
}

void I_UpdateSoundParams(int handle, int vol, int sep, int pitch) {
    (void)handle;
    (void)vol;
    (void)sep;
    (void)pitch;
}

void I_ShutdownSound(void) {
    // Stub
}

void I_InitSound(void) {
    // No sound available on Kenix yet
    printf("[doom] Sound disabled (no audio device)\n");
}

// Music API stubs
void I_InitMusic(void) {
}

void I_ShutdownMusic(void) {
}

void I_PlaySong(int handle, int looping) {
    (void)handle;
    (void)looping;
}

void I_PauseSong(int handle) {
    (void)handle;
}

void I_ResumeSong(int handle) {
    (void)handle;
}

void I_StopSong(int handle) {
    (void)handle;
}

void I_UnRegisterSong(int handle) {
    (void)handle;
}

int I_RegisterSong(void *data) {
    (void)data;
    return 1;
}

int I_QrySongPlaying(int handle) {
    (void)handle;
    return 0;
}
