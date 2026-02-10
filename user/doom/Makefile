# Makefile for DOOM on Kenix
#
# Builds DOOM against musl libc for the aarch64 Kenix target.

# Cross compiler
CC = aarch64-elf-gcc
LD = aarch64-elf-ld
OBJCOPY = aarch64-elf-objcopy

# musl paths
MUSL = ../../musl-kenix

# DOOM source (use arm64-macOS port which has 64-bit fixes already)
DOOM_SRC = ../../DOOM-arm64-macOS/linuxdoom-1.10

# Compiler flags
# Use gnu89 mode because DOOM source uses old-style declarations
# Include stdint.h for int32_t types used in DOOM-arm64-macOS port
CFLAGS = -std=gnu89 -O2 -g \
         -nostdlib -nostdinc \
         -isystem $(MUSL)/include \
         -include stdint.h \
         -I$(DOOM_SRC) \
         -DNORMALUNIX -DKENIX -DLINUX \
         -fno-stack-protector \
         -fno-builtin \
         -ffreestanding \
         -fno-tree-vectorize \
         -Wall -Wno-unused-variable -Wno-unused-but-set-variable \
         -Wno-pointer-sign -Wno-unused-function \
         -Wno-implicit-int -Wno-return-type

# Linker flags
LDFLAGS = -nostdlib \
          -L$(MUSL)/lib \
          -T../user.ld

# Libraries
CRT_START = $(MUSL)/lib/crt1.o $(MUSL)/lib/crti.o
CRT_END = $(MUSL)/lib/crtn.o
LIBS = -lc -lgcc

# DOOM source files
DOOM_SRCS = \
    $(DOOM_SRC)/am_map.c \
    $(DOOM_SRC)/d_items.c \
    $(DOOM_SRC)/d_main.c \
    $(DOOM_SRC)/d_net.c \
    $(DOOM_SRC)/doomdef.c \
    $(DOOM_SRC)/doomstat.c \
    $(DOOM_SRC)/dstrings.c \
    $(DOOM_SRC)/f_finale.c \
    $(DOOM_SRC)/f_wipe.c \
    $(DOOM_SRC)/g_game.c \
    $(DOOM_SRC)/hu_lib.c \
    $(DOOM_SRC)/hu_stuff.c \
    $(DOOM_SRC)/i_main.c \
    $(DOOM_SRC)/info.c \
    $(DOOM_SRC)/m_argv.c \
    $(DOOM_SRC)/m_bbox.c \
    $(DOOM_SRC)/m_cheat.c \
    $(DOOM_SRC)/m_fixed.c \
    $(DOOM_SRC)/m_menu.c \
    $(DOOM_SRC)/m_random.c \
    $(DOOM_SRC)/m_swap.c \
    $(DOOM_SRC)/p_ceilng.c \
    $(DOOM_SRC)/p_doors.c \
    $(DOOM_SRC)/p_enemy.c \
    $(DOOM_SRC)/p_floor.c \
    $(DOOM_SRC)/p_inter.c \
    $(DOOM_SRC)/p_lights.c \
    $(DOOM_SRC)/p_map.c \
    $(DOOM_SRC)/p_maputl.c \
    $(DOOM_SRC)/p_mobj.c \
    $(DOOM_SRC)/p_plats.c \
    $(DOOM_SRC)/p_pspr.c \
    $(DOOM_SRC)/p_saveg.c \
    $(DOOM_SRC)/p_setup.c \
    $(DOOM_SRC)/p_sight.c \
    $(DOOM_SRC)/p_spec.c \
    $(DOOM_SRC)/p_switch.c \
    $(DOOM_SRC)/p_telept.c \
    $(DOOM_SRC)/p_tick.c \
    $(DOOM_SRC)/p_user.c \
    $(DOOM_SRC)/r_bsp.c \
    $(DOOM_SRC)/r_data.c \
    $(DOOM_SRC)/r_draw.c \
    $(DOOM_SRC)/r_main.c \
    $(DOOM_SRC)/r_plane.c \
    $(DOOM_SRC)/r_segs.c \
    $(DOOM_SRC)/r_sky.c \
    $(DOOM_SRC)/r_things.c \
    $(DOOM_SRC)/s_sound.c \
    $(DOOM_SRC)/sounds.c \
    $(DOOM_SRC)/st_lib.c \
    $(DOOM_SRC)/st_stuff.c \
    $(DOOM_SRC)/tables.c \
    $(DOOM_SRC)/v_video.c \
    $(DOOM_SRC)/w_wad.c \
    $(DOOM_SRC)/wi_stuff.c \
    $(DOOM_SRC)/z_zone.c

# Kenix platform files (replace DOOM's X11/Linux-specific files)
# Also includes m_misc_kenix.c for 64-bit compatibility
KENIX_SRCS = \
    i_video_kenix.c \
    i_system_kenix.c \
    i_sound_stub.c \
    i_net_stub.c \
    m_misc_kenix.c

# Object files
DOOM_OBJS = $(patsubst $(DOOM_SRC)/%.c,obj/%.o,$(DOOM_SRCS))
KENIX_OBJS = $(patsubst %.c,obj/%.o,$(KENIX_SRCS))

ALL_OBJS = $(DOOM_OBJS) $(KENIX_OBJS)

# Target
TARGET = doom.elf
MINIMAL_TARGET = doom_minimal.elf

.PHONY: all clean minimal

all: $(TARGET)

# Minimal test build
minimal: obj $(MINIMAL_TARGET)

$(MINIMAL_TARGET): obj/minimal_main.o
	$(CC) $(LDFLAGS) -o $@ $(CRT_START) obj/minimal_main.o $(LIBS) $(CRT_END)
	@echo "Built $@"
	@ls -la $@

$(TARGET): obj $(ALL_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(CRT_START) $(ALL_OBJS) $(LIBS) $(CRT_END)
	@echo "Built $@"
	@ls -la $@

obj:
	mkdir -p obj

# Compile DOOM source files
obj/%.o: $(DOOM_SRC)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Compile Kenix platform files
obj/%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf obj $(TARGET)

# Install to disk image
install: $(TARGET)
	cp $(TARGET) ../../disk/bin/doom
	@echo "Installed to disk/bin/doom"

# Debug info
info:
	@echo "DOOM sources: $(words $(DOOM_SRCS)) files"
	@echo "Kenix sources: $(words $(KENIX_SRCS)) files"
	@echo "musl: $(MUSL)"
	@echo "CC: $(CC)"
