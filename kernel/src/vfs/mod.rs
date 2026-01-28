//! Virtual Filesystem (VFS) for Kenix
//!
//! Provides a unified interface for file operations across different
//! filesystem implementations. Currently supports:
//! - ramfs: In-memory filesystem

pub mod ramfs;

use alloc::string::String;
use alloc::vec::Vec;

/// Maximum path length
pub const MAX_PATH: usize = 256;

/// Maximum number of open files system-wide
pub const MAX_OPEN_FILES: usize = 256;

/// File types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Regular,
    Directory,
}

/// File open flags
#[derive(Debug, Clone, Copy)]
pub struct OpenFlags {
    pub read: bool,
    pub write: bool,
    pub create: bool,
    pub truncate: bool,
    pub append: bool,
}

impl OpenFlags {
    pub const fn read_only() -> Self {
        Self { read: true, write: false, create: false, truncate: false, append: false }
    }

    pub const fn write_only() -> Self {
        Self { read: false, write: true, create: false, truncate: false, append: false }
    }

    pub const fn read_write() -> Self {
        Self { read: true, write: true, create: false, truncate: false, append: false }
    }

    /// Parse from POSIX O_* flags
    pub fn from_posix(flags: u32) -> Self {
        const O_RDONLY: u32 = 0x0000;
        const O_WRONLY: u32 = 0x0001;
        const O_RDWR: u32 = 0x0002;
        const O_CREAT: u32 = 0x0040;
        const O_TRUNC: u32 = 0x0200;
        const O_APPEND: u32 = 0x0400;

        let access = flags & 0x03;
        Self {
            read: access == O_RDONLY || access == O_RDWR,
            write: access == O_WRONLY || access == O_RDWR,
            create: (flags & O_CREAT) != 0,
            truncate: (flags & O_TRUNC) != 0,
            append: (flags & O_APPEND) != 0,
        }
    }
}

/// File stat information
#[derive(Debug, Clone)]
pub struct Stat {
    pub file_type: FileType,
    pub size: usize,
    pub inode: u64,
}

/// VFS error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VfsError {
    NotFound,       // -2 ENOENT
    IoError,        // -5 EIO
    BadFd,          // -9 EBADF
    NoMemory,       // -12 ENOMEM
    Exists,         // -17 EEXIST
    NotDir,         // -20 ENOTDIR
    IsDir,          // -21 EISDIR
    Invalid,        // -22 EINVAL
    TooManyFiles,   // -23 ENFILE
    NoSpace,        // -28 ENOSPC
}

impl VfsError {
    pub fn to_errno(self) -> i64 {
        match self {
            VfsError::NotFound => -2,
            VfsError::IoError => -5,
            VfsError::BadFd => -9,
            VfsError::NoMemory => -12,
            VfsError::Exists => -17,
            VfsError::NotDir => -20,
            VfsError::IsDir => -21,
            VfsError::Invalid => -22,
            VfsError::TooManyFiles => -23,
            VfsError::NoSpace => -28,
        }
    }
}

pub type VfsResult<T> = Result<T, VfsError>;

/// Vnode - virtual inode representing an open file
#[derive(Debug)]
pub struct Vnode {
    /// Filesystem-specific inode number
    pub inode: u64,
    /// File type
    pub file_type: FileType,
    /// Current read/write offset
    pub offset: usize,
    /// Open flags
    pub flags: OpenFlags,
    /// Reference count
    pub refcount: u32,
}

/// Global VFS state
pub struct Vfs {
    /// Open vnodes
    vnodes: [Option<Vnode>; MAX_OPEN_FILES],
    /// The ramfs instance
    ramfs: ramfs::RamFs,
}

impl Vfs {
    /// Create a new VFS
    pub const fn new() -> Self {
        const NONE: Option<Vnode> = None;
        Self {
            vnodes: [NONE; MAX_OPEN_FILES],
            ramfs: ramfs::RamFs::new(),
        }
    }

    /// Initialize the VFS with default files
    pub fn init(&mut self) {
        self.ramfs.init();
    }

    /// Allocate a vnode slot
    fn alloc_vnode(&mut self) -> VfsResult<usize> {
        for (i, slot) in self.vnodes.iter().enumerate() {
            if slot.is_none() {
                return Ok(i);
            }
        }
        Err(VfsError::TooManyFiles)
    }

    /// Open a file
    pub fn open(&mut self, path: &str, flags: OpenFlags) -> VfsResult<usize> {
        // Look up the path in ramfs
        let inode = self.ramfs.lookup(path)?;
        let stat = self.ramfs.stat(inode)?;

        // Can't open directories for read/write (yet)
        if stat.file_type == FileType::Directory && (flags.read || flags.write) {
            return Err(VfsError::IsDir);
        }

        // Allocate a vnode
        let vnode_id = self.alloc_vnode()?;

        // Handle truncate
        if flags.truncate && flags.write {
            self.ramfs.truncate(inode)?;
        }

        self.vnodes[vnode_id] = Some(Vnode {
            inode,
            file_type: stat.file_type,
            offset: if flags.append { stat.size } else { 0 },
            flags,
            refcount: 1,
        });

        Ok(vnode_id)
    }

    /// Close a file
    pub fn close(&mut self, vnode_id: usize) -> VfsResult<()> {
        if vnode_id >= MAX_OPEN_FILES {
            return Err(VfsError::BadFd);
        }

        match &mut self.vnodes[vnode_id] {
            Some(vnode) => {
                vnode.refcount -= 1;
                if vnode.refcount == 0 {
                    self.vnodes[vnode_id] = None;
                }
                Ok(())
            }
            None => Err(VfsError::BadFd),
        }
    }

    /// Read from a file
    pub fn read(&mut self, vnode_id: usize, buf: &mut [u8]) -> VfsResult<usize> {
        if vnode_id >= MAX_OPEN_FILES {
            return Err(VfsError::BadFd);
        }

        let vnode = self.vnodes[vnode_id].as_mut().ok_or(VfsError::BadFd)?;

        if !vnode.flags.read {
            return Err(VfsError::BadFd);
        }

        if vnode.file_type == FileType::Directory {
            return Err(VfsError::IsDir);
        }

        let bytes_read = self.ramfs.read(vnode.inode, vnode.offset, buf)?;
        vnode.offset += bytes_read;

        Ok(bytes_read)
    }

    /// Write to a file
    pub fn write(&mut self, vnode_id: usize, buf: &[u8]) -> VfsResult<usize> {
        if vnode_id >= MAX_OPEN_FILES {
            return Err(VfsError::BadFd);
        }

        let vnode = self.vnodes[vnode_id].as_mut().ok_or(VfsError::BadFd)?;

        if !vnode.flags.write {
            return Err(VfsError::BadFd);
        }

        if vnode.file_type == FileType::Directory {
            return Err(VfsError::IsDir);
        }

        let bytes_written = self.ramfs.write(vnode.inode, vnode.offset, buf)?;
        vnode.offset += bytes_written;

        Ok(bytes_written)
    }

    /// Stat a file by path
    pub fn stat(&self, path: &str) -> VfsResult<Stat> {
        let inode = self.ramfs.lookup(path)?;
        self.ramfs.stat(inode)
    }

    /// Get file size for an open file
    pub fn fstat(&self, vnode_id: usize) -> VfsResult<Stat> {
        if vnode_id >= MAX_OPEN_FILES {
            return Err(VfsError::BadFd);
        }

        let vnode = self.vnodes[vnode_id].as_ref().ok_or(VfsError::BadFd)?;
        self.ramfs.stat(vnode.inode)
    }
}

/// Global VFS instance
static mut VFS: Vfs = Vfs::new();

/// Initialize the VFS
pub fn init() {
    unsafe {
        VFS.init();
    }
}

/// Open a file (syscall interface)
pub fn sys_open(path: &str, flags: u32) -> i64 {
    let open_flags = OpenFlags::from_posix(flags);
    unsafe {
        match VFS.open(path, open_flags) {
            Ok(vnode_id) => vnode_id as i64,
            Err(e) => e.to_errno(),
        }
    }
}

/// Close a file (syscall interface)
pub fn sys_close(vnode_id: usize) -> i64 {
    unsafe {
        match VFS.close(vnode_id) {
            Ok(()) => 0,
            Err(e) => e.to_errno(),
        }
    }
}

/// Read from a file (syscall interface)
pub fn sys_read(vnode_id: usize, buf: &mut [u8]) -> i64 {
    unsafe {
        match VFS.read(vnode_id, buf) {
            Ok(n) => n as i64,
            Err(e) => e.to_errno(),
        }
    }
}

/// Write to a file (syscall interface)
pub fn sys_write(vnode_id: usize, buf: &[u8]) -> i64 {
    unsafe {
        match VFS.write(vnode_id, buf) {
            Ok(n) => n as i64,
            Err(e) => e.to_errno(),
        }
    }
}

/// Stat a file (syscall interface)
pub fn sys_stat(path: &str) -> VfsResult<Stat> {
    unsafe { VFS.stat(path) }
}
