//! Pipe server for Kenix
//!
//! Provides userspace pipes for inter-process data streams via IPC.
//! Supports blocking reads/writes using deferred IPC replies.

#![no_std]
#![no_main]

use libkenix::ipc::{self, Message, TASK_ANY};
use libkenix::msg::{PIPE_CREATE, PIPE_READ, PIPE_WRITE, PIPE_CLOSE, ERR_OK, ERR_NOMEM, ERR_INVAL, ERR_BADF};
use libkenix::shm;
use libkenix::uart;

/// Maximum number of pipes
const MAX_PIPES: usize = 64;

/// Pipe buffer size (4KB)
const PIPE_BUF_SIZE: usize = 4096;

/// Maximum pending readers/writers per pipe
const MAX_PENDING: usize = 8;

/// A pending reader waiting for data
#[derive(Clone, Copy)]
struct PendingReader {
    task_id: usize,
    shm_id: u64,
    max_len: usize,
}

/// A pending writer waiting for space
#[derive(Clone, Copy)]
struct PendingWriter {
    task_id: usize,
    shm_id: u64,
    len: usize,
}

/// A single pipe instance
struct Pipe {
    /// Circular buffer
    buffer: [u8; PIPE_BUF_SIZE],
    /// Read position in buffer
    read_pos: usize,
    /// Write position in buffer
    write_pos: usize,
    /// Current data length in buffer
    len: usize,
    /// Number of open readers
    readers: usize,
    /// Number of open writers
    writers: usize,
    /// Whether this pipe slot is in use
    in_use: bool,
    /// Pending readers waiting for data
    pending_readers: [Option<PendingReader>; MAX_PENDING],
    /// Pending writers waiting for space
    pending_writers: [Option<PendingWriter>; MAX_PENDING],
}

impl Pipe {
    const fn new() -> Self {
        Self {
            buffer: [0; PIPE_BUF_SIZE],
            read_pos: 0,
            write_pos: 0,
            len: 0,
            readers: 0,
            writers: 0,
            in_use: false,
            pending_readers: [None; MAX_PENDING],
            pending_writers: [None; MAX_PENDING],
        }
    }

    /// Initialize a new pipe
    fn init(&mut self) {
        self.buffer = [0; PIPE_BUF_SIZE];
        self.read_pos = 0;
        self.write_pos = 0;
        self.len = 0;
        self.readers = 1;
        self.writers = 1;
        self.in_use = true;
        self.pending_readers = [None; MAX_PENDING];
        self.pending_writers = [None; MAX_PENDING];
    }

    /// Check if pipe has data to read
    fn has_data(&self) -> bool {
        self.len > 0
    }

    /// Check if pipe has space to write
    fn has_space(&self) -> bool {
        self.len < PIPE_BUF_SIZE
    }

    /// Read data from pipe
    fn read(&mut self, dst: &mut [u8]) -> usize {
        let to_read = dst.len().min(self.len);
        if to_read == 0 {
            return 0;
        }

        for i in 0..to_read {
            dst[i] = self.buffer[self.read_pos];
            self.read_pos = (self.read_pos + 1) % PIPE_BUF_SIZE;
        }
        self.len -= to_read;
        to_read
    }

    /// Write data to pipe
    fn write(&mut self, src: &[u8]) -> usize {
        let space = PIPE_BUF_SIZE - self.len;
        let to_write = src.len().min(space);
        if to_write == 0 {
            return 0;
        }

        for i in 0..to_write {
            self.buffer[self.write_pos] = src[i];
            self.write_pos = (self.write_pos + 1) % PIPE_BUF_SIZE;
        }
        self.len += to_write;
        to_write
    }

    /// Add a pending reader
    fn add_pending_reader(&mut self, reader: PendingReader) -> bool {
        for slot in &mut self.pending_readers {
            if slot.is_none() {
                *slot = Some(reader);
                return true;
            }
        }
        false
    }

    /// Take the first pending reader
    fn take_pending_reader(&mut self) -> Option<PendingReader> {
        for slot in &mut self.pending_readers {
            if slot.is_some() {
                return slot.take();
            }
        }
        None
    }

    /// Add a pending writer
    fn add_pending_writer(&mut self, writer: PendingWriter) -> bool {
        for slot in &mut self.pending_writers {
            if slot.is_none() {
                *slot = Some(writer);
                return true;
            }
        }
        false
    }

    /// Take the first pending writer
    fn take_pending_writer(&mut self) -> Option<PendingWriter> {
        for slot in &mut self.pending_writers {
            if slot.is_some() {
                return slot.take();
            }
        }
        None
    }

    /// Check if pipe should be deallocated
    fn should_free(&self) -> bool {
        self.readers == 0 && self.writers == 0
    }
}

/// Global pipe table
static mut PIPES: [Pipe; MAX_PIPES] = [const { Pipe::new() }; MAX_PIPES];

/// Allocate a new pipe
fn alloc_pipe() -> Option<usize> {
    unsafe {
        for i in 0..MAX_PIPES {
            if !PIPES[i].in_use {
                PIPES[i].init();
                return Some(i);
            }
        }
        None
    }
}

/// Free a pipe slot
fn free_pipe(id: usize) {
    unsafe {
        if id < MAX_PIPES && PIPES[id].in_use {
            PIPES[id].in_use = false;
        }
    }
}

/// Complete a read operation: copy data from pipe to SHM and reply
fn complete_read(task_id: usize, pipe: &mut Pipe, shm_id: u64, max_len: usize) {
    // Map the shared memory
    let shm_addr = shm::map(shm_id, 0);
    if shm_addr < 0 {
        let reply = Message::new(ERR_INVAL as u64, [0; 4]);
        ipc::reply_to(task_id, &reply);
        return;
    }

    // Read from pipe into SHM buffer
    let buf = unsafe {
        core::slice::from_raw_parts_mut(shm_addr as *mut u8, max_len)
    };
    let bytes_read = pipe.read(buf);

    // Unmap SHM
    shm::unmap(shm_id);

    let reply = Message::new(bytes_read as u64, [0; 4]);
    ipc::reply_to(task_id, &reply);
}

/// Complete a write operation: copy data from SHM to pipe and reply
fn complete_write(task_id: usize, pipe: &mut Pipe, shm_id: u64, len: usize) {
    // Map the shared memory
    let shm_addr = shm::map(shm_id, 0);
    if shm_addr < 0 {
        let reply = Message::new(ERR_INVAL as u64, [0; 4]);
        ipc::reply_to(task_id, &reply);
        return;
    }

    // Read from SHM buffer and write to pipe
    let buf = unsafe {
        core::slice::from_raw_parts(shm_addr as *const u8, len)
    };
    let bytes_written = pipe.write(buf);

    // Unmap SHM
    shm::unmap(shm_id);

    let reply = Message::new(bytes_written as u64, [0; 4]);
    ipc::reply_to(task_id, &reply);
}

/// Wake all pending readers with EOF (0 bytes)
fn wake_readers_eof(pipe: &mut Pipe) {
    while let Some(reader) = pipe.take_pending_reader() {
        // Reply with 0 bytes (EOF)
        let reply = Message::new(0, [0; 4]);
        ipc::reply_to(reader.task_id, &reply);
    }
}

/// Wake all pending writers with error (broken pipe)
fn wake_writers_error(pipe: &mut Pipe) {
    while let Some(writer) = pipe.take_pending_writer() {
        // Reply with error (EPIPE-like)
        let reply = Message::new(ERR_BADF as u64, [0; 4]);
        ipc::reply_to(writer.task_id, &reply);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    uart::println("[pipeserv] ok, ready!\n");

    // Main server loop
    loop {
        // Wait for message
        let recv = ipc::recv(TASK_ANY);
        let sender = recv.sender;
        let msg = recv.msg;

        match msg.tag {
            PIPE_CREATE => {
                // Create a new pipe
                let reply = match alloc_pipe() {
                    Some(id) => Message::new(id as u64, [0; 4]),
                    None => Message::new(ERR_NOMEM as u64, [0; 4]),
                };
                ipc::reply(&reply);
            }

            PIPE_READ => {
                // PIPE_READ: data[0] = pipe_id, data[1] = shm_id, data[2] = max_len
                let pipe_id = msg.data[0] as usize;
                let shm_id = msg.data[1];
                let max_len = msg.data[2] as usize;

                // Validate pipe_id
                if pipe_id >= MAX_PIPES {
                    let reply = Message::new(ERR_BADF as u64, [0; 4]);
                    ipc::reply(&reply);
                    continue;
                }

                let pipe = unsafe { &mut PIPES[pipe_id] };
                if !pipe.in_use {
                    let reply = Message::new(ERR_BADF as u64, [0; 4]);
                    ipc::reply(&reply);
                    continue;
                }

                if pipe.has_data() {
                    // Data available - read immediately
                    let shm_addr = shm::map(shm_id, 0);
                    if shm_addr < 0 {
                        let reply = Message::new(ERR_INVAL as u64, [0; 4]);
                        ipc::reply(&reply);
                        continue;
                    }

                    let buf = unsafe {
                        core::slice::from_raw_parts_mut(shm_addr as *mut u8, max_len)
                    };
                    let bytes_read = pipe.read(buf);
                    shm::unmap(shm_id);

                    let reply = Message::new(bytes_read as u64, [0; 4]);
                    ipc::reply(&reply);

                    // Wake any pending writers now that there's space
                    while pipe.has_space() {
                        if let Some(writer) = pipe.take_pending_writer() {
                            complete_write(writer.task_id, pipe, writer.shm_id, writer.len);
                        } else {
                            break;
                        }
                    }
                } else if pipe.writers == 0 {
                    // No writers left - return EOF
                    let reply = Message::new(0, [0; 4]);
                    ipc::reply(&reply);
                } else {
                    // No data but writers exist - block (defer reply)
                    let reader = PendingReader {
                        task_id: sender,
                        shm_id,
                        max_len,
                    };
                    if !pipe.add_pending_reader(reader) {
                        // Too many pending readers - return 0 (caller should retry)
                        let reply = Message::new(0, [0; 4]);
                        ipc::reply(&reply);
                    }
                    // Don't reply - caller stays blocked
                }
            }

            PIPE_WRITE => {
                // PIPE_WRITE: data[0] = pipe_id, data[1] = shm_id, data[2] = len
                let pipe_id = msg.data[0] as usize;
                let shm_id = msg.data[1];
                let len = msg.data[2] as usize;

                // Validate pipe_id
                if pipe_id >= MAX_PIPES {
                    let reply = Message::new(ERR_BADF as u64, [0; 4]);
                    ipc::reply(&reply);
                    continue;
                }

                let pipe = unsafe { &mut PIPES[pipe_id] };
                if !pipe.in_use {
                    let reply = Message::new(ERR_BADF as u64, [0; 4]);
                    ipc::reply(&reply);
                    continue;
                }

                // If no readers, return error (EPIPE-like)
                if pipe.readers == 0 {
                    let reply = Message::new(ERR_BADF as u64, [0; 4]);
                    ipc::reply(&reply);
                    continue;
                }

                if pipe.has_space() {
                    // Space available - write immediately
                    let shm_addr = shm::map(shm_id, 0);
                    if shm_addr < 0 {
                        let reply = Message::new(ERR_INVAL as u64, [0; 4]);
                        ipc::reply(&reply);
                        continue;
                    }

                    let buf = unsafe {
                        core::slice::from_raw_parts(shm_addr as *const u8, len)
                    };
                    let bytes_written = pipe.write(buf);
                    shm::unmap(shm_id);

                    let reply = Message::new(bytes_written as u64, [0; 4]);
                    ipc::reply(&reply);

                    // Wake any pending readers now that there's data
                    while pipe.has_data() {
                        if let Some(reader) = pipe.take_pending_reader() {
                            complete_read(reader.task_id, pipe, reader.shm_id, reader.max_len);
                        } else {
                            break;
                        }
                    }
                } else {
                    // No space - block (defer reply)
                    let writer = PendingWriter {
                        task_id: sender,
                        shm_id,
                        len,
                    };
                    if !pipe.add_pending_writer(writer) {
                        // Too many pending writers - return 0 (caller should retry)
                        let reply = Message::new(0, [0; 4]);
                        ipc::reply(&reply);
                    }
                    // Don't reply - caller stays blocked
                }
            }

            PIPE_CLOSE => {
                // PIPE_CLOSE: data[0] = pipe_id, data[1] = is_read_end (1=read, 0=write)
                let pipe_id = msg.data[0] as usize;
                let is_read = msg.data[1] != 0;

                // Validate pipe_id
                if pipe_id >= MAX_PIPES {
                    let reply = Message::new(ERR_BADF as u64, [0; 4]);
                    ipc::reply(&reply);
                    continue;
                }

                let pipe = unsafe { &mut PIPES[pipe_id] };
                if !pipe.in_use {
                    let reply = Message::new(ERR_BADF as u64, [0; 4]);
                    ipc::reply(&reply);
                    continue;
                }

                // Decrement appropriate reference count
                if is_read {
                    if pipe.readers > 0 {
                        pipe.readers -= 1;
                    }
                    // If no more readers, wake pending writers with error
                    if pipe.readers == 0 {
                        wake_writers_error(pipe);
                    }
                } else {
                    if pipe.writers > 0 {
                        pipe.writers -= 1;
                    }
                    // If no more writers, wake pending readers with EOF
                    if pipe.writers == 0 {
                        wake_readers_eof(pipe);
                    }
                }

                // Free pipe if no more references
                if pipe.should_free() {
                    free_pipe(pipe_id);
                }

                let reply = Message::new(ERR_OK as u64, [0; 4]);
                ipc::reply(&reply);
            }

            _ => {
                // Unknown message
                let reply = Message::new(ERR_INVAL as u64, [0; 4]);
                ipc::reply(&reply);
            }
        }
    }
}
