#!/bin/bash
# Create FAT32 disk image for Kenix
# Requires: mtools (brew install mtools on macOS)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${SCRIPT_DIR}/.."
DISK_IMG=${1:-disk.img}
SIZE_MB=${2:-32}
BUSYBOX_PATH="${PROJECT_DIR}/busybox"

# Download busybox if not present
download_busybox() {
    echo "Downloading BusyBox for aarch64..."
    # Use Ubuntu's static busybox (works with our alignment emulation)
    local URL="http://ports.ubuntu.com/ubuntu-ports/pool/main/b/busybox/busybox-static_1.36.1-6ubuntu3_arm64.deb"
    local DEB_FILE="/tmp/busybox-static.deb"

    curl -L -o "$DEB_FILE" "$URL"

    # Extract busybox binary from .deb
    cd /tmp
    ar x "$DEB_FILE"
    tar xf data.tar.* ./bin/busybox
    mv ./bin/busybox "$BUSYBOX_PATH"
    rm -f "$DEB_FILE" data.tar.* control.tar.* debian-binary
    rmdir ./bin 2>/dev/null || true
    cd - >/dev/null

    chmod +x "$BUSYBOX_PATH"
    echo "BusyBox downloaded to $BUSYBOX_PATH"
}

# Check for busybox, download if missing
if [ ! -f "$BUSYBOX_PATH" ]; then
    download_busybox
fi

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

# Create bin directory and add busybox
if [ -f "$BUSYBOX_PATH" ]; then
    echo "Adding busybox to disk..."
    mmd -i "${DISK_IMG}" ::/bin
    mcopy -i "${DISK_IMG}" "$BUSYBOX_PATH" ::/bin/busybox
    # Also create a simple test script
    echo '#!/bin/busybox sh' > /tmp/test_script
    echo 'echo "Test passed!"' >> /tmp/test_script
    mcopy -i "${DISK_IMG}" /tmp/test_script ::/bin/test
    rm /tmp/test_script
else
    echo "Warning: busybox not found at $BUSYBOX_PATH"
fi

# List contents
echo ""
echo "Disk contents:"
mdir -i "${DISK_IMG}" ::
echo ""
mdir -i "${DISK_IMG}" ::/data
if mdir -i "${DISK_IMG}" ::/bin 2>/dev/null; then
    echo ""
fi

echo ""
echo "Disk image created successfully: ${DISK_IMG}"
