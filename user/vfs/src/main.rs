//! VFS Server for Kenix
//!
//! User-space filesystem server implementing ramfs (in-memory filesystem)
//! and FAT32 (mounted at /disk/).
//! Receives file operation requests via IPC and manages file state.

#![no_std]
#![no_main]

mod fat32;
mod blk_client;

use libkenix::ipc::{self, Message, TASK_ANY};
use libkenix::shm::{self, ShmId};
use libkenix::msg::*;
use libkenix::console;

use fat32::{Fat32, FatTable, DirEntry, DirIterator, Fat32File, SECTOR_SIZE};
use blk_client::BlkClient;

// ============================================================================
// RAM Filesystem
// ============================================================================

const MAX_INODES: usize = 8;
const MAX_FILE_SIZE: usize = 1024;  // 1KB max file size for owned files
const MAX_DIR_ENTRIES: usize = 16;
const MAX_NAME_LEN: usize = 32;

#[derive(Clone, Copy, PartialEq)]
enum InodeType {
    Free,
    File,
    Directory,
}

struct FileData {
    data: [u8; MAX_FILE_SIZE],
    size: usize,
}

struct DirEntryRam {
    name: [u8; MAX_NAME_LEN],
    name_len: usize,
    inode: usize,
}

struct DirData {
    entries: [DirEntryRam; MAX_DIR_ENTRIES],
    count: usize,
}

enum InodeData {
    None,
    File(FileData),
    Dir(DirData),
}

struct Inode {
    itype: InodeType,
    data: InodeData,
}

impl Inode {
    const fn empty() -> Self {
        Self {
            itype: InodeType::Free,
            data: InodeData::None,
        }
    }
}

impl DirEntryRam {
    const fn empty() -> Self {
        Self {
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            inode: 0,
        }
    }
}

struct RamFs {
    inodes: [Inode; MAX_INODES],
}

impl RamFs {
    fn init(&mut self) {
        // Initialize all inodes as empty
        for inode in self.inodes.iter_mut() {
            *inode = Inode::empty();
        }

        // Create root directory at inode 0
        const EMPTY_ENTRY: DirEntryRam = DirEntryRam::empty();
        self.inodes[0] = Inode {
            itype: InodeType::Directory,
            data: InodeData::Dir(DirData {
                entries: [EMPTY_ENTRY; MAX_DIR_ENTRIES],
                count: 0,
            }),
        };

        // Create /hello.txt
        self.create_file(0, "hello.txt", b"Hello!\n");

        // Create /test.txt
        self.create_file(0, "test.txt", b"Test file from VFS.\n");
    }

    fn alloc_inode(&mut self) -> Option<usize> {
        for i in 1..MAX_INODES {
            if self.inodes[i].itype == InodeType::Free {
                return Some(i);
            }
        }
        None
    }

    fn create_file(&mut self, dir_ino: usize, name: &str, content: &[u8]) -> Option<usize> {
        let ino = self.alloc_inode()?;

        let mut file_data = FileData {
            data: [0; MAX_FILE_SIZE],
            size: content.len().min(MAX_FILE_SIZE),
        };
        file_data.data[..file_data.size].copy_from_slice(&content[..file_data.size]);

        self.inodes[ino] = Inode {
            itype: InodeType::File,
            data: InodeData::File(file_data),
        };

        // Add to directory
        if let InodeData::Dir(ref mut dir) = self.inodes[dir_ino].data {
            if dir.count < MAX_DIR_ENTRIES {
                let entry = &mut dir.entries[dir.count];
                let name_bytes = name.as_bytes();
                let len = name_bytes.len().min(MAX_NAME_LEN - 1);
                entry.name[..len].copy_from_slice(&name_bytes[..len]);
                entry.name_len = len;
                entry.inode = ino;
                dir.count += 1;
            }
        }

        Some(ino)
    }

    fn lookup(&self, path: &[u8], path_len: usize) -> Result<usize, i64> {
        let mut start = 0;
        if path_len > 0 && path[0] == b'/' {
            start = 1;
        }

        if start >= path_len {
            return Ok(0); // Root
        }

        let mut current = 0usize;
        let mut pos = start;

        while pos < path_len {
            let mut end = pos;
            while end < path_len && path[end] != b'/' {
                end += 1;
            }

            if end == pos {
                pos = end + 1;
                continue;
            }

            let comp = &path[pos..end];
            let comp_len = end - pos;

            match &self.inodes[current].data {
                InodeData::Dir(dir) => {
                    let mut found = false;
                    for i in 0..dir.count {
                        let entry = &dir.entries[i];
                        if entry.name_len == comp_len {
                            let mut matches = true;
                            for j in 0..comp_len {
                                if entry.name[j] != comp[j] {
                                    matches = false;
                                    break;
                                }
                            }
                            if matches {
                                current = entry.inode;
                                found = true;
                                break;
                            }
                        }
                    }
                    if !found {
                        return Err(ERR_NOENT);
                    }
                }
                _ => return Err(ERR_NOTDIR),
            }

            pos = end + 1;
        }

        Ok(current)
    }

    fn get_file_size(&self, ino: usize) -> Option<usize> {
        match &self.inodes[ino].data {
            InodeData::File(file) => Some(file.size),
            InodeData::Dir(dir) => Some(dir.count),
            _ => None,
        }
    }

    fn read(&self, ino: usize, offset: usize, buf: &mut [u8]) -> Result<usize, i64> {
        if ino >= MAX_INODES {
            return Err(ERR_INVAL);
        }

        match &self.inodes[ino].data {
            InodeData::File(file) => {
                if offset >= file.size {
                    return Ok(0);
                }
                let avail = file.size - offset;
                let to_read = buf.len().min(avail);
                buf[..to_read].copy_from_slice(&file.data[offset..offset + to_read]);
                Ok(to_read)
            }
            InodeData::Dir(_) => Err(ERR_ISDIR),
            InodeData::None => Err(ERR_NOENT),
        }
    }

    fn write(&mut self, ino: usize, offset: usize, buf: &[u8]) -> Result<usize, i64> {
        if ino >= MAX_INODES {
            return Err(ERR_INVAL);
        }

        match &mut self.inodes[ino].data {
            InodeData::File(file) => {
                if offset >= MAX_FILE_SIZE {
                    return Err(ERR_NOSPC);
                }
                let avail = MAX_FILE_SIZE - offset;
                let to_write = buf.len().min(avail);
                file.data[offset..offset + to_write].copy_from_slice(&buf[..to_write]);
                if offset + to_write > file.size {
                    file.size = offset + to_write;
                }
                Ok(to_write)
            }
            InodeData::Dir(_) => Err(ERR_ISDIR),
            InodeData::None => Err(ERR_NOENT),
        }
    }
}

// ============================================================================
// FAT32 Integration
// ============================================================================

/// FAT32 open file handle
#[derive(Clone, Copy)]
struct Fat32OpenFile {
    file: Fat32File,
    in_use: bool,
}

impl Fat32OpenFile {
    const fn empty() -> Self {
        Fat32OpenFile {
            file: Fat32File {
                first_cluster: 0,
                size: 0,
                position: 0,
                current_cluster: 0,
                cluster_offset: 0,
            },
            in_use: false,
        }
    }
}

// ============================================================================
// Open File Tracking
// ============================================================================

const MAX_CLIENTS: usize = 8;
const MAX_OPEN_FILES: usize = 8;

/// File source type
#[derive(Clone, Copy, PartialEq)]
enum FileSource {
    None,
    RamFs,
    Fat32,
}

#[derive(Clone, Copy)]
struct OpenFile {
    source: FileSource,
    /// For RamFs: inode number; For FAT32: index into fat32_files
    handle: usize,
    offset: usize,
    in_use: bool,
}

impl OpenFile {
    const fn empty() -> Self {
        Self {
            source: FileSource::None,
            handle: 0,
            offset: 0,
            in_use: false,
        }
    }
}

struct ClientState {
    files: [OpenFile; MAX_OPEN_FILES],
    shm_id: Option<ShmId>,
    shm_addr: Option<usize>,
}

impl ClientState {
    const fn new() -> Self {
        const EMPTY: OpenFile = OpenFile::empty();
        Self {
            files: [EMPTY; MAX_OPEN_FILES],
            shm_id: None,
            shm_addr: None,
        }
    }
}

// ============================================================================
// VFS Server Main
// ============================================================================

static mut RAMFS: RamFs = RamFs {
    inodes: [const { Inode::empty() }; MAX_INODES],
};

static mut CLIENTS: [ClientState; MAX_CLIENTS] = {
    const EMPTY: ClientState = ClientState::new();
    [EMPTY; MAX_CLIENTS]
};

static mut BLK_CLIENT: BlkClient = BlkClient::new();
static mut FAT32_FS: Option<Fat32> = None;
static mut FAT32_FILES: [Fat32OpenFile; MAX_OPEN_FILES] = [const { Fat32OpenFile::empty() }; MAX_OPEN_FILES];

/// Sector buffer for disk reads
static mut SECTOR_BUF: [u8; SECTOR_SIZE] = [0; SECTOR_SIZE];
/// Cluster buffer for FAT32 reads (up to 8 sectors)
static mut CLUSTER_BUF: [u8; 4096] = [0; 4096];

/// Check if a path starts with /disk/
fn is_disk_path(path: &[u8], path_len: usize) -> bool {
    if path_len >= 5 {
        path[0] == b'/' && path[1] == b'd' && path[2] == b'i' && path[3] == b's' && path[4] == b'k'
            && (path_len == 5 || path[5] == b'/')
    } else {
        false
    }
}

/// Get the path relative to /disk/
fn disk_relative_path(path: &[u8], path_len: usize) -> (&[u8], usize) {
    if path_len <= 6 {
        // Just "/disk" or "/disk/"
        (&[], 0)
    } else {
        (&path[6..path_len], path_len - 6)
    }
}

/// Look up a file in FAT32 by path
fn fat32_lookup(path: &[u8], path_len: usize) -> Result<DirEntry, i64> {
    let fs = unsafe {
        match &FAT32_FS {
            Some(fs) => fs,
            None => return Err(ERR_IO),
        }
    };

    // Start from root directory
    let mut current_cluster = fs.root_cluster;
    let cluster_size = (fs.sectors_per_cluster as usize) * SECTOR_SIZE;

    // If path is empty or just "/", return root as a directory entry
    if path_len == 0 {
        return Ok(DirEntry {
            name: *b"           ",
            attributes: fat32::dir::attr::DIRECTORY,
            first_cluster_hi: (fs.root_cluster >> 16) as u16,
            first_cluster_lo: fs.root_cluster as u16,
            file_size: 0,
        });
    }

    let mut pos = 0;
    if path[0] == b'/' {
        pos = 1;
    }

    let mut last_entry: Option<DirEntry> = None;

    while pos < path_len {
        // Find end of component
        let mut end = pos;
        while end < path_len && path[end] != b'/' {
            end += 1;
        }

        if end == pos {
            pos = end + 1;
            continue;
        }

        let component = &path[pos..end];

        // Read the directory cluster
        let sector = fs.cluster_to_sector(current_cluster);
        let bytes_read = unsafe {
            BLK_CLIENT.read(sector as u64, &mut CLUSTER_BUF[..cluster_size])
        };
        if bytes_read < cluster_size as isize {
            return Err(ERR_IO);
        }

        // Search for the component
        let mut found = false;
        for entry in DirIterator::new(unsafe { &CLUSTER_BUF[..cluster_size] }) {
            if entry.matches_name(component) {
                if entry.is_directory() {
                    current_cluster = entry.first_cluster();
                    last_entry = Some(entry);
                    found = true;
                    break;
                } else if end >= path_len || pos + component.len() >= path_len {
                    // This is the final component
                    return Ok(entry);
                } else {
                    // Trying to traverse through a file
                    return Err(ERR_NOTDIR);
                }
            }
        }

        if !found {
            return Err(ERR_NOENT);
        }

        pos = end + 1;
    }

    // Return the last directory entry found
    match last_entry {
        Some(entry) => Ok(entry),
        None => Err(ERR_NOENT),
    }
}

/// Read data from a FAT32 file
fn fat32_read(file_idx: usize, buf: &mut [u8]) -> Result<usize, i64> {
    let fs = unsafe {
        match &FAT32_FS {
            Some(fs) => fs,
            None => return Err(ERR_IO),
        }
    };

    let file = unsafe { &mut FAT32_FILES[file_idx].file };
    if file.is_eof() {
        return Ok(0);
    }

    let cluster_size = (fs.sectors_per_cluster as usize) * SECTOR_SIZE;
    let mut total_read = 0usize;

    while total_read < buf.len() && !file.is_eof() {
        // Read current cluster
        let sector = fs.cluster_to_sector(file.current_cluster);
        let bytes_read = unsafe {
            BLK_CLIENT.read(sector as u64, &mut CLUSTER_BUF[..cluster_size])
        };
        if bytes_read < cluster_size as isize {
            return Err(ERR_IO);
        }

        // Calculate how much we can read from this cluster
        let offset_in_cluster = file.cluster_offset as usize;
        let remaining_in_cluster = cluster_size - offset_in_cluster;
        let remaining_in_file = file.remaining() as usize;
        let remaining_in_buf = buf.len() - total_read;
        let to_read = remaining_in_cluster.min(remaining_in_file).min(remaining_in_buf);

        // Copy data
        buf[total_read..total_read + to_read]
            .copy_from_slice(unsafe { &CLUSTER_BUF[offset_in_cluster..offset_in_cluster + to_read] });

        total_read += to_read;
        file.advance(to_read as u32, cluster_size as u32);

        // If we need more data and haven't reached EOF, get next cluster
        if file.cluster_offset == 0 && !file.is_eof() {
            // Read FAT to get next cluster
            let fat_sector = fs.fat_sector_for_cluster(file.current_cluster);
            let fat_offset = fs.fat_offset_for_cluster(file.current_cluster);

            let bytes_read = unsafe {
                BLK_CLIENT.read(fat_sector as u64, &mut SECTOR_BUF)
            };
            if bytes_read < SECTOR_SIZE as isize {
                return Err(ERR_IO);
            }

            let next_cluster = FatTable::read_entry(unsafe { &SECTOR_BUF }, fat_offset);
            if FatTable::is_end_of_chain(next_cluster) {
                break;
            }
            file.set_current_cluster(next_cluster);
        }
    }

    Ok(total_read)
}

fn handle_open(client: usize, msg_data: &[u64; 4]) -> i64 {
    if client >= MAX_CLIENTS {
        return ERR_INVAL;
    }

    // New SHM-based format: data[0] = shm_id, data[1] = path_len, data[2] = flags
    let shm_id = msg_data[0];
    let path_len = msg_data[1] as usize;
    let _flags = msg_data[2] as u32;

    if path_len == 0 || path_len > 255 {
        return ERR_INVAL;
    }

    // Read path from SHM (scope the borrow to avoid conflicts later)
    let mut path_buf = [0u8; 256];
    {
        let client_state = unsafe { &mut CLIENTS[client] };

        // Map SHM if not already mapped or different SHM
        if client_state.shm_id != Some(shm_id) {
            if let Some(old_id) = client_state.shm_id {
                shm::unmap(old_id);
                client_state.shm_id = None;
                client_state.shm_addr = None;
            }

            let addr = shm::map(shm_id, 0);
            if addr < 0 {
                return ERR_INVAL;
            }
            client_state.shm_id = Some(shm_id);
            client_state.shm_addr = Some(addr as usize);
        }

        let shm_base = match client_state.shm_addr {
            Some(a) => a,
            None => return ERR_INVAL,
        };

        // Read path from SHM
        let src_ptr = shm_base as *const u8;
        unsafe {
            core::ptr::copy_nonoverlapping(src_ptr, path_buf.as_mut_ptr(), path_len);
        }
    } // client_state borrow ends here

    // Check if this is a /disk/ path
    if is_disk_path(&path_buf, path_len) {
        let (rel_path, rel_len) = disk_relative_path(&path_buf, path_len);

        // Look up in FAT32
        let entry = match fat32_lookup(rel_path, rel_len) {
            Ok(e) => e,
            Err(e) => return e,
        };

        if entry.is_directory() {
            return ERR_ISDIR;
        }

        // Find a free FAT32 file slot
        let fat32_idx = unsafe {
            let mut idx = None;
            for i in 0..MAX_OPEN_FILES {
                if !FAT32_FILES[i].in_use {
                    idx = Some(i);
                    break;
                }
            }
            match idx {
                Some(i) => {
                    FAT32_FILES[i] = Fat32OpenFile {
                        file: Fat32File::from_dir_entry(&entry),
                        in_use: true,
                    };
                    i
                }
                None => return ERR_NFILE,
            }
        };

        // Find a free client file slot
        let client_state = unsafe { &mut CLIENTS[client] };
        for i in 0..MAX_OPEN_FILES {
            if !client_state.files[i].in_use {
                client_state.files[i] = OpenFile {
                    source: FileSource::Fat32,
                    handle: fat32_idx,
                    offset: 0,
                    in_use: true,
                };
                return i as i64;
            }
        }

        // No client slot, clean up FAT32 slot
        unsafe { FAT32_FILES[fat32_idx].in_use = false; }
        return ERR_NFILE;
    }

    // RamFS path
    let ino = match unsafe { RAMFS.lookup(&path_buf, path_len) } {
        Ok(i) => i,
        Err(e) => return e,
    };

    let client_state = unsafe { &mut CLIENTS[client] };
    for i in 0..MAX_OPEN_FILES {
        if !client_state.files[i].in_use {
            client_state.files[i] = OpenFile {
                source: FileSource::RamFs,
                handle: ino,
                offset: 0,
                in_use: true,
            };
            return i as i64;
        }
    }

    ERR_NFILE
}

fn handle_close(client: usize, handle: u64) -> i64 {
    if client >= MAX_CLIENTS || handle as usize >= MAX_OPEN_FILES {
        return ERR_BADF;
    }

    let client_state = unsafe { &mut CLIENTS[client] };
    let file = &mut client_state.files[handle as usize];
    if !file.in_use {
        return ERR_BADF;
    }

    // If FAT32, free the FAT32 file slot
    if file.source == FileSource::Fat32 {
        unsafe { FAT32_FILES[file.handle].in_use = false; }
    }

    file.in_use = false;
    file.source = FileSource::None;
    ERR_OK
}

fn handle_read(client: usize, handle: u64, len: u64, reply_data: &mut [u64; 4]) -> i64 {
    if client >= MAX_CLIENTS || handle as usize >= MAX_OPEN_FILES {
        return ERR_BADF;
    }

    let client_state = unsafe { &mut CLIENTS[client] };
    let file = &mut client_state.files[handle as usize];
    if !file.in_use {
        return ERR_BADF;
    }

    let read_len = (len as usize).min(32);
    let mut buf = [0u8; 32];

    let result = match file.source {
        FileSource::RamFs => {
            match unsafe { RAMFS.read(file.handle, file.offset, &mut buf[..read_len]) } {
                Ok(n) => {
                    file.offset += n;
                    Ok(n)
                }
                Err(e) => Err(e),
            }
        }
        FileSource::Fat32 => {
            match fat32_read(file.handle, &mut buf[..read_len]) {
                Ok(n) => Ok(n),
                Err(e) => Err(e),
            }
        }
        FileSource::None => Err(ERR_BADF),
    };

    match result {
        Ok(n) => {
            unsafe {
                let reply_bytes = core::slice::from_raw_parts_mut(
                    reply_data.as_mut_ptr() as *mut u8,
                    32
                );
                reply_bytes[..n].copy_from_slice(&buf[..n]);
            }
            n as i64
        }
        Err(e) => e,
    }
}

/// File type and mode constants
const S_IFMT: u32 = 0o170000;   // File type mask
const S_IFDIR: u32 = 0o040000;  // Directory
const S_IFREG: u32 = 0o100000;  // Regular file

/// Device IDs
const DEV_RAMFS: u64 = 1;
const DEV_FAT32: u64 = 2;

fn handle_stat(client: usize, msg_data: &[u64; 4], reply_data: &mut [u64; 4]) -> i64 {
    if client >= MAX_CLIENTS {
        return ERR_INVAL;
    }

    let path_len = (msg_data[0] & 0xFF) as usize;
    if path_len > 31 {
        return ERR_INVAL;
    }

    let mut path_buf = [0u8; 32];
    let msg_bytes = unsafe {
        core::slice::from_raw_parts(msg_data.as_ptr() as *const u8, 32)
    };
    path_buf[..path_len].copy_from_slice(&msg_bytes[1..1 + path_len]);

    // Check if this is a /disk/ path
    if is_disk_path(&path_buf, path_len) {
        let (rel_path, rel_len) = disk_relative_path(&path_buf, path_len);

        let entry = match fat32_lookup(rel_path, rel_len) {
            Ok(e) => e,
            Err(e) => return e,
        };

        // reply_data[0] = size
        // reply_data[1] = mode (S_IFDIR/S_IFREG | permissions)
        // reply_data[2] = device (2 for FAT32)
        // reply_data[3] = inode (cluster number)
        reply_data[0] = entry.file_size as u64;
        let mode = if entry.is_directory() {
            S_IFDIR | 0o755
        } else {
            S_IFREG | 0o644
        };
        reply_data[1] = mode as u64;
        reply_data[2] = DEV_FAT32;
        reply_data[3] = entry.first_cluster() as u64;
        return ERR_OK;
    }

    // RamFS path
    let ino = match unsafe { RAMFS.lookup(&path_buf, path_len) } {
        Ok(i) => i,
        Err(e) => return e,
    };

    let size = match unsafe { RAMFS.get_file_size(ino) } {
        Some(s) => s,
        None => return ERR_NOENT,
    };

    let (mode, is_dir) = match unsafe { &RAMFS.inodes[ino].data } {
        InodeData::Dir(_) => (S_IFDIR | 0o755, true),
        _ => (S_IFREG | 0o644, false),
    };

    // reply_data[0] = size
    // reply_data[1] = mode (S_IFDIR/S_IFREG | permissions)
    // reply_data[2] = device (1 for ramfs)
    // reply_data[3] = inode
    reply_data[0] = size as u64;
    reply_data[1] = mode as u64;
    reply_data[2] = DEV_RAMFS;
    reply_data[3] = ino as u64;

    let _ = is_dir; // Used implicitly in mode
    ERR_OK
}

/// Handle VFS_READDIR: read directory entries
/// msg_data[0] = handle (VFS file handle)
/// msg_data[1] = shm_id
/// msg_data[2] = count (max bytes)
/// Returns: bytes written to SHM, or negative error
fn handle_readdir(client: usize, msg_data: &[u64; 4]) -> i64 {
    if client >= MAX_CLIENTS {
        return ERR_INVAL;
    }

    let handle = msg_data[0] as usize;
    let shm_id = msg_data[1];
    let count = msg_data[2] as usize;

    if handle >= MAX_OPEN_FILES {
        return ERR_BADF;
    }

    let client_state = unsafe { &mut CLIENTS[client] };

    // Map SHM if not already mapped
    if client_state.shm_id != Some(shm_id) {
        if let Some(old_id) = client_state.shm_id {
            shm::unmap(old_id);
            client_state.shm_id = None;
            client_state.shm_addr = None;
        }

        let addr = shm::map(shm_id, 0);
        if addr < 0 {
            return ERR_INVAL;
        }
        client_state.shm_id = Some(shm_id);
        client_state.shm_addr = Some(addr as usize);
    }

    let shm_base = match client_state.shm_addr {
        Some(a) => a,
        None => return ERR_INVAL,
    };

    let file = &client_state.files[handle];
    if !file.in_use {
        return ERR_BADF;
    }

    // Directory entry constants
    const DT_REG: u8 = 8;
    const DT_DIR: u8 = 4;

    let mut bytes_written: usize = 0;
    let mut entry_offset: i64 = 0;

    match file.source {
        FileSource::RamFs => {
            // Check if it's a directory
            let dir_data = match unsafe { &RAMFS.inodes[file.handle].data } {
                InodeData::Dir(d) => d,
                _ => return ERR_NOTDIR,
            };

            // Write dirent64 entries for each directory entry
            for i in 0..dir_data.count {
                let entry = &dir_data.entries[i];
                let name_len = entry.name_len;

                // Calculate record length: header (19 bytes) + name + null + padding to 8-byte alignment
                // dirent64: d_ino(8) + d_off(8) + d_reclen(2) + d_type(1) + d_name[...]
                let header_size = 8 + 8 + 2 + 1; // 19 bytes
                let reclen_unaligned = header_size + name_len + 1; // +1 for null terminator
                let reclen = (reclen_unaligned + 7) & !7; // Align to 8 bytes

                if bytes_written + reclen > count {
                    break; // No more space
                }

                entry_offset += reclen as i64;

                // Get the inode type
                let d_type = match unsafe { RAMFS.inodes[entry.inode].itype } {
                    InodeType::File => DT_REG,
                    InodeType::Directory => DT_DIR,
                    _ => 0,
                };

                // Write dirent64 structure to SHM
                let dest = shm_base + bytes_written;
                unsafe {
                    // d_ino at offset 0
                    core::ptr::write_unaligned(dest as *mut u64, entry.inode as u64);
                    // d_off at offset 8
                    core::ptr::write_unaligned((dest + 8) as *mut i64, entry_offset);
                    // d_reclen at offset 16
                    core::ptr::write_unaligned((dest + 16) as *mut u16, reclen as u16);
                    // d_type at offset 18
                    core::ptr::write_unaligned((dest + 18) as *mut u8, d_type);
                    // d_name at offset 19
                    let name_dest = (dest + 19) as *mut u8;
                    core::ptr::copy_nonoverlapping(entry.name.as_ptr(), name_dest, name_len);
                    // Null terminator
                    core::ptr::write_unaligned(name_dest.add(name_len), 0u8);
                }

                bytes_written += reclen;
            }
        }
        FileSource::Fat32 => {
            // For FAT32 directories, we need to iterate through the directory
            // The handle points to an open FAT32 file/directory
            let fat32_file = unsafe { &FAT32_FILES[file.handle] };
            if !fat32_file.in_use {
                return ERR_BADF;
            }

            let fs = unsafe {
                match &FAT32_FS {
                    Some(fs) => fs,
                    None => return ERR_IO,
                }
            };

            // Read directory entries from FAT32
            let mut current_cluster = fat32_file.file.first_cluster;
            let blk = unsafe { &BLK_CLIENT };
            let mut sector_buf = [0u8; SECTOR_SIZE];

            'outer: loop {
                if current_cluster < 2 || current_cluster >= 0x0FFFFFF8 {
                    break;
                }

                let first_sector = fs.cluster_to_sector(current_cluster);

                // Read the cluster
                for sec_offset in 0..fs.sectors_per_cluster as u32 {
                    if !blk.read_sector((first_sector + sec_offset) as u64, &mut sector_buf) {
                        return ERR_IO;
                    }

                    // Parse directory entries (32 bytes each)
                    for entry_idx in 0..(SECTOR_SIZE / 32) {
                        let entry_offset_in_sector = entry_idx * 32;
                        let first_byte = sector_buf[entry_offset_in_sector];

                        // End of directory
                        if first_byte == 0x00 {
                            break 'outer;
                        }
                        // Deleted entry
                        if first_byte == 0xE5 {
                            continue;
                        }
                        // Long filename entry (skip for now)
                        if sector_buf[entry_offset_in_sector + 11] == 0x0F {
                            continue;
                        }

                        // Parse the 8.3 filename
                        let mut name_buf = [0u8; 13]; // "filename.ext" + null
                        let mut name_pos = 0;

                        // Base name (8 chars, space-padded)
                        for j in 0..8 {
                            let c = sector_buf[entry_offset_in_sector + j];
                            if c != b' ' {
                                name_buf[name_pos] = c;
                                name_pos += 1;
                            }
                        }

                        // Extension (3 chars)
                        let ext_start = entry_offset_in_sector + 8;
                        let has_ext = sector_buf[ext_start] != b' ';
                        if has_ext {
                            name_buf[name_pos] = b'.';
                            name_pos += 1;
                            for j in 0..3 {
                                let c = sector_buf[ext_start + j];
                                if c != b' ' {
                                    name_buf[name_pos] = c;
                                    name_pos += 1;
                                }
                            }
                        }

                        let name_len = name_pos;

                        // Calculate record length
                        let header_size = 8 + 8 + 2 + 1; // 19 bytes
                        let reclen_unaligned = header_size + name_len + 1;
                        let reclen = (reclen_unaligned + 7) & !7;

                        if bytes_written + reclen > count {
                            break 'outer;
                        }

                        entry_offset += reclen as i64;

                        // Get attributes
                        let attr = sector_buf[entry_offset_in_sector + 11];
                        let d_type = if attr & 0x10 != 0 { DT_DIR } else { DT_REG };

                        // Get cluster number (for inode)
                        let cluster_hi = u16::from_le_bytes([
                            sector_buf[entry_offset_in_sector + 20],
                            sector_buf[entry_offset_in_sector + 21],
                        ]) as u32;
                        let cluster_lo = u16::from_le_bytes([
                            sector_buf[entry_offset_in_sector + 26],
                            sector_buf[entry_offset_in_sector + 27],
                        ]) as u32;
                        let d_ino = (cluster_hi << 16) | cluster_lo;

                        // Write dirent64 structure to SHM
                        let dest = shm_base + bytes_written;
                        unsafe {
                            core::ptr::write_unaligned(dest as *mut u64, d_ino as u64);
                            core::ptr::write_unaligned((dest + 8) as *mut i64, entry_offset);
                            core::ptr::write_unaligned((dest + 16) as *mut u16, reclen as u16);
                            core::ptr::write_unaligned((dest + 18) as *mut u8, d_type);
                            let name_dest = (dest + 19) as *mut u8;
                            core::ptr::copy_nonoverlapping(name_buf.as_ptr(), name_dest, name_len);
                            core::ptr::write_unaligned(name_dest.add(name_len), 0u8);
                        }

                        bytes_written += reclen;
                    }
                }

                // Follow FAT chain to next cluster
                current_cluster = fat32_next_cluster(fs, blk, current_cluster);
            }
        }
        FileSource::None => return ERR_BADF,
    }

    bytes_written as i64
}

/// Get next cluster from FAT
fn fat32_next_cluster(fs: &Fat32, blk: &BlkClient, cluster: u32) -> u32 {
    let fat_sector = fs.fat_sector_for_cluster(cluster);
    let entry_offset = fs.fat_offset_for_cluster(cluster);
    let mut sector_buf = [0u8; SECTOR_SIZE];
    if !blk.read_sector(fat_sector as u64, &mut sector_buf) {
        return 0x0FFFFFFF; // End of chain on error
    }
    u32::from_le_bytes([
        sector_buf[entry_offset],
        sector_buf[entry_offset + 1],
        sector_buf[entry_offset + 2],
        sector_buf[entry_offset + 3],
    ]) & 0x0FFFFFFF
}

fn handle_read_shm(client: usize, msg_data: &[u64; 4]) -> i64 {
    if client >= MAX_CLIENTS {
        return ERR_INVAL;
    }

    let handle = msg_data[0] as usize;
    let shm_id = msg_data[1];
    let shm_offset = msg_data[2] as usize;
    let max_len = msg_data[3] as usize;

    if handle >= MAX_OPEN_FILES {
        return ERR_BADF;
    }

    let client_state = unsafe { &mut CLIENTS[client] };

    if client_state.shm_id != Some(shm_id) {
        if let Some(old_id) = client_state.shm_id {
            shm::unmap(old_id);
            client_state.shm_id = None;
            client_state.shm_addr = None;
        }

        let addr = shm::map(shm_id, 0);
        if addr < 0 {
            return ERR_INVAL;
        }
        client_state.shm_id = Some(shm_id);
        client_state.shm_addr = Some(addr as usize);
    }

    let shm_base = match client_state.shm_addr {
        Some(a) => a,
        None => return ERR_INVAL,
    };

    let file = &mut client_state.files[handle];
    if !file.in_use {
        return ERR_BADF;
    }

    match file.source {
        FileSource::RamFs => {
            // Read file data
            let file_data = match unsafe { &RAMFS.inodes[file.handle].data } {
                InodeData::File(f) => &f.data[..f.size],
                _ => return ERR_ISDIR,
            };

            if file.offset >= file_data.len() {
                return 0;
            }
            let avail = file_data.len() - file.offset;
            let to_read = max_len.min(avail);

            let dest_ptr = (shm_base + shm_offset) as *mut u8;
            unsafe {
                core::ptr::copy_nonoverlapping(
                    file_data[file.offset..].as_ptr(),
                    dest_ptr,
                    to_read
                );
            }

            file.offset += to_read;
            to_read as i64
        }
        FileSource::Fat32 => {
            // Read from FAT32 into SHM
            let dest_ptr = (shm_base + shm_offset) as *mut u8;
            let buf = unsafe {
                core::slice::from_raw_parts_mut(dest_ptr, max_len)
            };

            match fat32_read(file.handle, buf) {
                Ok(n) => n as i64,
                Err(e) => e,
            }
        }
        FileSource::None => ERR_BADF,
    }
}

fn handle_write_shm(client: usize, msg_data: &[u64; 4]) -> i64 {
    if client >= MAX_CLIENTS {
        return ERR_INVAL;
    }

    let handle = msg_data[0] as usize;
    let shm_id = msg_data[1];
    let shm_offset = msg_data[2] as usize;
    let len = msg_data[3] as usize;

    if handle >= MAX_OPEN_FILES {
        return ERR_BADF;
    }

    let client_state = unsafe { &mut CLIENTS[client] };

    // Map SHM if not already mapped
    if client_state.shm_id != Some(shm_id) {
        if let Some(old_id) = client_state.shm_id {
            shm::unmap(old_id);
            client_state.shm_id = None;
            client_state.shm_addr = None;
        }

        let addr = shm::map(shm_id, 0);
        if addr < 0 {
            return ERR_INVAL;
        }
        client_state.shm_id = Some(shm_id);
        client_state.shm_addr = Some(addr as usize);
    }

    let shm_base = match client_state.shm_addr {
        Some(a) => a,
        None => return ERR_INVAL,
    };

    let file = &mut client_state.files[handle];
    if !file.in_use {
        return ERR_BADF;
    }

    match file.source {
        FileSource::RamFs => {
            // Get data from SHM
            let src_ptr = (shm_base + shm_offset) as *const u8;
            let buf = unsafe {
                core::slice::from_raw_parts(src_ptr, len)
            };

            // Write to RAM filesystem
            match unsafe { RAMFS.write(file.handle, file.offset, buf) } {
                Ok(n) => {
                    file.offset += n;
                    n as i64
                }
                Err(e) => e,
            }
        }
        FileSource::Fat32 => {
            // FAT32 write not yet supported
            ERR_IO
        }
        FileSource::None => ERR_BADF,
    }
}

fn handle_write(client: usize, handle: u64, buf_ptr: u64, len: u64) -> i64 {
    if client >= MAX_CLIENTS || handle as usize >= MAX_OPEN_FILES {
        return ERR_BADF;
    }

    let client_state = unsafe { &mut CLIENTS[client] };
    let file = &mut client_state.files[handle as usize];
    if !file.in_use {
        return ERR_BADF;
    }

    // Only RamFS supports writes
    if file.source != FileSource::RamFs {
        return ERR_IO;
    }

    let buf = unsafe {
        core::slice::from_raw_parts(buf_ptr as *const u8, len as usize)
    };

    match unsafe { RAMFS.write(file.handle, file.offset, buf) } {
        Ok(n) => {
            file.offset += n;
            n as i64
        }
        Err(e) => e,
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    main()
}

fn main() -> ! {
    unsafe {
        RAMFS.init();
    }

    console::println("[vfs] Server started");

    // Initialize block device client
    let blk_ok = unsafe { BLK_CLIENT.init() };
    if blk_ok {
        console::println("[vfs] Block device connected");

        // Read boot sector
        let boot_ok = unsafe {
            BLK_CLIENT.read_sector(0, &mut SECTOR_BUF)
        };

        if boot_ok {
            // Try to parse as FAT32
            if let Some(fs) = Fat32::new(unsafe { &SECTOR_BUF }) {
                console::println("[vfs] FAT32 filesystem mounted at /disk/");
                unsafe { FAT32_FS = Some(fs); }
            } else {
                console::println("[vfs] No FAT32 found on disk");
            }
        } else {
            console::println("[vfs] Failed to read boot sector");
        }
    } else {
        console::println("[vfs] No block device available");
    }

    loop {
        let recv = ipc::recv(TASK_ANY);
        let client = recv.sender;

        let mut reply_data = [0u64; 4];

        let result = match recv.msg.tag {
            VFS_OPEN => handle_open(client, &recv.msg.data),
            VFS_CLOSE => handle_close(client, recv.msg.data[0]),
            VFS_READ => handle_read(client, recv.msg.data[0], recv.msg.data[1], &mut reply_data),
            VFS_STAT => handle_stat(client, &recv.msg.data, &mut reply_data),
            VFS_READ_SHM => handle_read_shm(client, &recv.msg.data),
            VFS_WRITE_SHM => handle_write_shm(client, &recv.msg.data),
            VFS_WRITE => handle_write(client, recv.msg.data[0], recv.msg.data[1], recv.msg.data[2]),
            VFS_READDIR => handle_readdir(client, &recv.msg.data),
            _ => ERR_INVAL,
        };

        let reply = Message::new(result as u64, reply_data);
        ipc::reply(&reply);
    }
}
