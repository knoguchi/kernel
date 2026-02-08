//! Minimal ELF64 parser for loading userspace programs
//!
//! This module provides a minimal ELF64 parser that handles:
//! - ELF header validation (magic, class, endianness, machine type)
//! - Program headers (PT_LOAD segments only)
//!
//! No section headers, symbols, or relocations are supported (not needed for static executables).

use core::mem;

/// ELF magic number
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// ELF class identifiers
const ELFCLASS64: u8 = 2;

/// ELF data encoding (endianness)
const ELFDATA2LSB: u8 = 1; // Little endian

/// ELF machine types
const EM_AARCH64: u16 = 183;

/// ELF executable type
const ET_EXEC: u16 = 2;
/// ELF shared object type (also used for PIE executables)
const ET_DYN: u16 = 3;

/// Program header types
const PT_LOAD: u32 = 1;

/// Program header flags
pub const PF_X: u32 = 1 << 0; // Executable
pub const PF_W: u32 = 1 << 1; // Writable
pub const PF_R: u32 = 1 << 2; // Readable

/// ELF64 Header (64 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Header {
    /// ELF identification bytes
    pub e_ident: [u8; 16],
    /// Object file type (ET_EXEC = 2)
    pub e_type: u16,
    /// Machine architecture (EM_AARCH64 = 183)
    pub e_machine: u16,
    /// ELF version (always 1)
    pub e_version: u32,
    /// Entry point virtual address
    pub e_entry: u64,
    /// Program header table file offset
    pub e_phoff: u64,
    /// Section header table file offset
    pub e_shoff: u64,
    /// Processor-specific flags
    pub e_flags: u32,
    /// ELF header size (should be 64)
    pub e_ehsize: u16,
    /// Program header entry size (should be 56)
    pub e_phentsize: u16,
    /// Number of program headers
    pub e_phnum: u16,
    /// Section header entry size
    pub e_shentsize: u16,
    /// Number of section headers
    pub e_shnum: u16,
    /// Section name string table index
    pub e_shstrndx: u16,
}

/// ELF64 Program Header (56 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Phdr {
    /// Segment type (PT_LOAD = 1)
    pub p_type: u32,
    /// Segment flags (PF_X, PF_W, PF_R)
    pub p_flags: u32,
    /// File offset of segment data
    pub p_offset: u64,
    /// Virtual address of segment
    pub p_vaddr: u64,
    /// Physical address (unused)
    pub p_paddr: u64,
    /// Size in file
    pub p_filesz: u64,
    /// Size in memory (>= filesz for BSS)
    pub p_memsz: u64,
    /// Alignment
    pub p_align: u64,
}

/// Errors that can occur during ELF parsing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfError {
    /// Data too small to contain ELF header
    TooSmall,
    /// Invalid ELF magic number
    InvalidMagic,
    /// Not a 64-bit ELF file
    Not64Bit,
    /// Not little endian
    NotLittleEndian,
    /// Not an AArch64 executable
    NotAarch64,
    /// Not an executable file
    NotExecutable,
    /// Invalid program header offset
    InvalidPhdrOffset,
    /// Invalid segment offset or size
    InvalidSegment,
}

/// Parsed ELF file
pub struct ElfFile<'a> {
    /// Reference to the ELF header
    header: &'a Elf64Header,
    /// Raw ELF data
    data: &'a [u8],
}

impl<'a> ElfFile<'a> {
    /// Parse an ELF file from raw bytes
    pub fn parse(data: &'a [u8]) -> Result<Self, ElfError> {
        // Check minimum size for ELF header
        if data.len() < mem::size_of::<Elf64Header>() {
            return Err(ElfError::TooSmall);
        }

        // Safety: We've verified the data is large enough
        let header = unsafe { &*(data.as_ptr() as *const Elf64Header) };

        // Validate ELF magic
        if header.e_ident[0..4] != ELF_MAGIC {
            return Err(ElfError::InvalidMagic);
        }

        // Check 64-bit class
        if header.e_ident[4] != ELFCLASS64 {
            return Err(ElfError::Not64Bit);
        }

        // Check little endian
        if header.e_ident[5] != ELFDATA2LSB {
            return Err(ElfError::NotLittleEndian);
        }

        // Check machine type
        if header.e_machine != EM_AARCH64 {
            return Err(ElfError::NotAarch64);
        }

        // Check executable type (ET_EXEC or ET_DYN for PIE)
        if header.e_type != ET_EXEC && header.e_type != ET_DYN {
            return Err(ElfError::NotExecutable);
        }

        // Validate program header table fits in data
        let phdr_end = header.e_phoff as usize
            + (header.e_phnum as usize * header.e_phentsize as usize);
        if phdr_end > data.len() {
            return Err(ElfError::InvalidPhdrOffset);
        }

        Ok(Self { header, data })
    }

    /// Get the entry point virtual address
    pub fn entry_point(&self) -> u64 {
        self.header.e_entry
    }

    /// Get the ELF header
    pub fn header(&self) -> &Elf64Header {
        self.header
    }

    /// Get an iterator over PT_LOAD program headers
    pub fn load_segments(&self) -> LoadSegmentIter<'a> {
        LoadSegmentIter {
            data: self.data,
            phoff: self.header.e_phoff as usize,
            phentsize: self.header.e_phentsize as usize,
            phnum: self.header.e_phnum as usize,
            current: 0,
        }
    }

    /// Get the number of PT_LOAD segments
    pub fn load_segment_count(&self) -> usize {
        self.load_segments().count()
    }

    /// Get segment data for a given program header
    pub fn segment_data(&self, phdr: &Elf64Phdr) -> Result<&'a [u8], ElfError> {
        let offset = phdr.p_offset as usize;
        let filesz = phdr.p_filesz as usize;

        if offset.saturating_add(filesz) > self.data.len() {
            return Err(ElfError::InvalidSegment);
        }

        Ok(&self.data[offset..offset + filesz])
    }
}

/// Iterator over PT_LOAD segments
pub struct LoadSegmentIter<'a> {
    data: &'a [u8],
    phoff: usize,
    phentsize: usize,
    phnum: usize,
    current: usize,
}

impl<'a> Iterator for LoadSegmentIter<'a> {
    type Item = &'a Elf64Phdr;

    fn next(&mut self) -> Option<Self::Item> {
        while self.current < self.phnum {
            let offset = self.phoff + self.current * self.phentsize;
            self.current += 1;

            if offset + mem::size_of::<Elf64Phdr>() <= self.data.len() {
                // Safety: We've verified the offset is within bounds
                let phdr = unsafe { &*(self.data.as_ptr().add(offset) as *const Elf64Phdr) };

                if phdr.p_type == PT_LOAD {
                    return Some(phdr);
                }
            }
        }
        None
    }
}

/// Helper to convert ELF flags to human-readable string
pub fn flags_to_str(flags: u32) -> &'static str {
    match (flags & PF_R != 0, flags & PF_W != 0, flags & PF_X != 0) {
        (true, false, true) => "R-X",
        (true, true, false) => "RW-",
        (true, false, false) => "R--",
        (true, true, true) => "RWX",
        (false, true, false) => "-W-",
        (false, false, true) => "--X",
        (false, true, true) => "-WX",
        (false, false, false) => "---",
    }
}
