#!/bin/bash
# Create FAT32 disk image for Kenix
# Requires: mtools (brew install mtools on macOS)

set -e

DISK_IMG=${1:-disk.img}
SIZE_MB=${2:-32}

echo "Creating ${SIZE_MB}MB FAT32 disk image: ${DISK_IMG}"

# Create empty disk image
dd if=/dev/zero of="${DISK_IMG}" bs=1M count="${SIZE_MB}" 2>/dev/null

# Format as FAT32
# -F: use FAT32
# -i: specify disk image
mformat -F -i "${DISK_IMG}" ::

# Add test files
echo "Hello from FAT32!" | mcopy -i "${DISK_IMG}" - ::/hello.txt
echo "This is a test file on the Kenix FAT32 disk." | mcopy -i "${DISK_IMG}" - ::/test.txt

# Create a subdirectory with a file
mmd -i "${DISK_IMG}" ::/data
echo "File in subdirectory" | mcopy -i "${DISK_IMG}" - ::/data/subfile.txt

# List contents
echo ""
echo "Disk contents:"
mdir -i "${DISK_IMG}" ::
echo ""
mdir -i "${DISK_IMG}" ::/data

echo ""
echo "Disk image created successfully: ${DISK_IMG}"
