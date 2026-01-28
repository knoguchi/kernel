//! VFS Server for Kenix
//!
//! User-space filesystem server implementing ramfs (in-memory filesystem).
//! Receives file operation requests via IPC and manages file state.

#![no_std]
#![no_main]

use libkenix::ipc::{self, Message, TASK_ANY};
use libkenix::msg::*;
use libkenix::console;

// ============================================================================
// RAM Filesystem
// ============================================================================

// Note: Keep sizes small to fit in 4KB frame (kernel limitation)
const MAX_INODES: usize = 4;
const MAX_FILE_SIZE: usize = 256;
const MAX_DIR_ENTRIES: usize = 8;
const MAX_NAME_LEN: usize = 16;

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

struct DirEntry {
    name: [u8; MAX_NAME_LEN],
    name_len: usize,
    inode: usize,
}

struct DirData {
    entries: [DirEntry; MAX_DIR_ENTRIES],
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

impl DirEntry {
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
    fn new() -> Self {
        const EMPTY: Inode = Inode::empty();
        Self {
            inodes: [EMPTY; MAX_INODES],
        }
    }

    fn init(&mut self) {
        // Create root directory at inode 0
        const EMPTY_ENTRY: DirEntry = DirEntry::empty();
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
        self.create_file(0, "test.txt", b"Test file.\n");
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

        // Initialize file inode
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
        // Skip leading slash
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
            // Find end of component (next / or end)
            let mut end = pos;
            while end < path_len && path[end] != b'/' {
                end += 1;
            }

            if end == pos {
                pos = end + 1;
                continue;
            }

            // Look up component
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

    fn get_size(&self, ino: usize) -> Result<usize, i64> {
        if ino >= MAX_INODES {
            return Err(ERR_INVAL);
        }
        match &self.inodes[ino].data {
            InodeData::File(file) => Ok(file.size),
            InodeData::Dir(dir) => Ok(dir.count),
            InodeData::None => Err(ERR_NOENT),
        }
    }
}

// ============================================================================
// Open File Tracking
// ============================================================================

// Keep client tracking small (kernel limitation)
const MAX_CLIENTS: usize = 8;
const MAX_OPEN_FILES: usize = 4;

#[derive(Clone, Copy)]
struct OpenFile {
    inode: usize,
    offset: usize,
    in_use: bool,
}

impl OpenFile {
    const fn empty() -> Self {
        Self {
            inode: 0,
            offset: 0,
            in_use: false,
        }
    }
}

struct ClientState {
    files: [OpenFile; MAX_OPEN_FILES],
}

impl ClientState {
    const fn new() -> Self {
        const EMPTY: OpenFile = OpenFile::empty();
        Self {
            files: [EMPTY; MAX_OPEN_FILES],
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

fn handle_open(client: usize, msg_data: &[u64; 4]) -> i64 {
    if client >= MAX_CLIENTS {
        return ERR_INVAL;
    }

    // Path is embedded in message data[0..3] (up to 32 bytes)
    // data[0] bits 0-7: path length
    // data[0] bits 8+, data[1-3]: path bytes
    let path_len = (msg_data[0] & 0xFF) as usize;
    if path_len > 31 {
        return ERR_INVAL;
    }

    // Extract path bytes from message
    let mut path_buf = [0u8; 32];
    let msg_bytes = unsafe {
        core::slice::from_raw_parts(msg_data.as_ptr() as *const u8, 32)
    };
    // Skip first byte (length), copy path
    path_buf[..path_len].copy_from_slice(&msg_bytes[1..1 + path_len]);

    // Lookup the file
    let ino = match unsafe { RAMFS.lookup(&path_buf, path_len) } {
        Ok(i) => i,
        Err(e) => return e,
    };

    // Find free file slot
    let client_state = unsafe { &mut CLIENTS[client] };
    for i in 0..MAX_OPEN_FILES {
        if !client_state.files[i].in_use {
            client_state.files[i] = OpenFile {
                inode: ino,
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
    if !client_state.files[handle as usize].in_use {
        return ERR_BADF;
    }

    client_state.files[handle as usize].in_use = false;
    ERR_OK
}

/// Handle read - returns data in reply message
/// Reply: tag = bytes_read (or error), data[0-3] = file data (up to 32 bytes)
fn handle_read(client: usize, handle: u64, len: u64, reply_data: &mut [u64; 4]) -> i64 {
    if client >= MAX_CLIENTS || handle as usize >= MAX_OPEN_FILES {
        return ERR_BADF;
    }

    let client_state = unsafe { &mut CLIENTS[client] };
    let file = &mut client_state.files[handle as usize];
    if !file.in_use {
        return ERR_BADF;
    }

    // Read into a local buffer (max 32 bytes for message-based transfer)
    let read_len = (len as usize).min(32);
    let mut buf = [0u8; 32];

    match unsafe { RAMFS.read(file.inode, file.offset, &mut buf[..read_len]) } {
        Ok(n) => {
            file.offset += n;
            // Copy data to reply message
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

fn handle_write(client: usize, handle: u64, buf_ptr: u64, len: u64) -> i64 {
    if client >= MAX_CLIENTS || handle as usize >= MAX_OPEN_FILES {
        return ERR_BADF;
    }

    let client_state = unsafe { &mut CLIENTS[client] };
    let file = &mut client_state.files[handle as usize];
    if !file.in_use {
        return ERR_BADF;
    }

    let buf = unsafe {
        core::slice::from_raw_parts(buf_ptr as *const u8, len as usize)
    };

    match unsafe { RAMFS.write(file.inode, file.offset, buf) } {
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
    // Initialize ramfs
    unsafe {
        RAMFS.init();
    }

    console::println("[vfs] Server started");

    // Main message loop
    loop {
        let recv = ipc::recv(TASK_ANY);
        let client = recv.sender;

        // Debug: show what we received
        console::print("[vfs] recv tag=");
        console::print_hex("", recv.msg.tag);

        // Prepare reply data (may be filled by handle_read)
        let mut reply_data = [0u64; 4];

        let result = match recv.msg.tag {
            VFS_OPEN => {
                console::print("[vfs] OPEN\n");
                // Path embedded in msg.data
                handle_open(client, &recv.msg.data)
            }
            VFS_CLOSE => {
                console::print("[vfs] CLOSE\n");
                handle_close(client, recv.msg.data[0])
            }
            VFS_READ => {
                console::print("[vfs] READ\n");
                // data[0] = handle, data[1] = max_len
                handle_read(
                    client,
                    recv.msg.data[0],
                    recv.msg.data[1],
                    &mut reply_data,
                )
            }
            VFS_WRITE => {
                console::print("[vfs] WRITE\n");
                handle_write(
                    client,
                    recv.msg.data[0],  // handle
                    recv.msg.data[1],  // buf_ptr (unused for now)
                    recv.msg.data[2],  // len
                )
            }
            _ => {
                console::print("[vfs] UNKNOWN\n");
                ERR_INVAL
            }
        };

        // Debug: show result
        console::print("[vfs] reply result=");
        console::print_hex("", result as u64);

        let reply = Message::new(result as u64, reply_data);
        ipc::reply(&reply);
    }
}
