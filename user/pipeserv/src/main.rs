//! Pipe server for Kenix
//!
//! Provides userspace pipes for inter-process data streams via IPC.

#![no_std]
#![no_main]

use libkenix::ipc::{self, Message, TASK_ANY};
use libkenix::msg::{PIPE_CREATE, PIPE_READ, PIPE_WRITE, PIPE_CLOSE, ERR_OK, ERR_NOMEM, ERR_INVAL, ERR_BADF};
use libkenix::shm;
use libkenix::console;

/// Maximum number of pipes
const MAX_PIPES: usize = 64;

/// Pipe buffer size (4KB)
const PIPE_BUF_SIZE: usize = 4096;

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
    /// Returns number of bytes read
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
    /// Returns number of bytes written
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

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // Use stack buffer to avoid potential rodata mapping issues
    let msg: [u8; 24] = *b"[pipeserv] ok, ready!\n\n\n";
    libkenix::syscall::write(1, &msg);

    // Main server loop
    loop {
        // Wait for message
        let recv = ipc::recv(TASK_ANY);
        let _sender = recv.sender;
        let msg = recv.msg;

        match msg.tag {
            PIPE_CREATE => {
                console::println("[pipeserv] PIPE_CREATE");
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

                // Map the shared memory
                let shm_addr = shm::map(shm_id, 0);
                if shm_addr < 0 {
                    let reply = Message::new(ERR_INVAL as u64, [0; 4]);
                    ipc::reply(&reply);
                    continue;
                }

                // Read from pipe into SHM buffer
                let buf = unsafe {
                    core::slice::from_raw_parts_mut(shm_addr as *mut u8, max_len)
                };

                // If pipe is empty and no writers, return EOF (0)
                // If pipe is empty but has writers, block (for now return 0 - TODO: proper blocking)
                let bytes_read = if pipe.has_data() {
                    pipe.read(buf)
                } else if pipe.writers == 0 {
                    0 // EOF
                } else {
                    0 // Would block - for now return 0
                };

                // Unmap SHM
                shm::unmap(shm_id);

                let reply = Message::new(bytes_read as u64, [0; 4]);
                ipc::reply(&reply);
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
                    // Unmap and return error
                    let reply = Message::new(ERR_BADF as u64, [0; 4]);
                    ipc::reply(&reply);
                    continue;
                }

                // Map the shared memory
                let shm_addr = shm::map(shm_id, 0);
                if shm_addr < 0 {
                    let reply = Message::new(ERR_INVAL as u64, [0; 4]);
                    ipc::reply(&reply);
                    continue;
                }

                // Read from SHM buffer and write to pipe
                let buf = unsafe {
                    core::slice::from_raw_parts(shm_addr as *const u8, len)
                };

                // Write as much as possible (non-blocking for now)
                let bytes_written = pipe.write(buf);

                // Unmap SHM
                shm::unmap(shm_id);

                let reply = Message::new(bytes_written as u64, [0; 4]);
                ipc::reply(&reply);
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
                } else {
                    if pipe.writers > 0 {
                        pipe.writers -= 1;
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
