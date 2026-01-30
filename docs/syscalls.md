# Kenix System Calls

## Overview

Kenix uses the AArch64 SVC instruction for system calls. The syscall number is passed in `x8`, arguments in `x0-x5`, and return values in `x0-x5`.

```
SVC #0
  x8 = syscall number
  x0-x5 = arguments
  x0-x5 = return values
```

## Status Legend

| Symbol | Meaning |
|--------|---------|
| :white_check_mark: | Implemented |
| :construction: | Planned |
| :grey_question: | Under consideration |

---

## 1. Process Management

| # | Name | Status | Description |
|---|------|--------|-------------|
| 0 | `SYS_YIELD` | :white_check_mark: | Voluntarily yield CPU |
| 93 | `SYS_EXIT` | :white_check_mark: | Terminate current task |
| 20 | `SYS_GETPID` | :white_check_mark: | Get current task ID |
| 21 | `SYS_SPAWN` | :white_check_mark: | Create new task from ELF |
| 22 | `SYS_WAIT` | :construction: | Wait for child task to exit |
| 23 | `SYS_KILL` | :construction: | Send signal to task |

### SYS_YIELD (0)
```
Args:   (none)
Return: x0 = 0 (always succeeds)
```
Voluntarily give up the CPU to allow other tasks to run.

### SYS_EXIT (93)
```
Args:   x0 = exit_code
Return: (does not return)
```
Terminate the current task. Exit code is reported to parent if waiting.

### SYS_GETPID (20)
```
Args:   (none)
Return: x0 = task_id
```
Get the current task's ID.

### SYS_SPAWN (21)
```
Args:   x0 = elf_ptr (pointer to ELF data)
        x1 = elf_len (length of ELF data)
Return: x0 = child_task_id (>= 0) or error (< 0)
```
Create a new task from an ELF image in memory. The ELF data must be
accessible in the calling task's address space. The new task starts
running immediately and is added to the scheduler's ready queue.

### SYS_WAIT (22) :construction:
```
Args:   x0 = task_id (-1 for any child)
Return: x0 = exited_task_id, x1 = exit_code
```
Wait for a child task to exit.

### SYS_KILL (23) :construction:
```
Args:   x0 = task_id, x1 = signal
Return: x0 = 0 or error
```
Send a signal to another task.

---

## 2. IPC (Inter-Process Communication)

| # | Name | Status | Description |
|---|------|--------|-------------|
| 1 | `SYS_SEND` | :white_check_mark: | Send message (blocking) |
| 2 | `SYS_RECV` | :white_check_mark: | Receive message (blocking) |
| 3 | `SYS_CALL` | :white_check_mark: | Send + receive reply (RPC) |
| 4 | `SYS_REPLY` | :white_check_mark: | Reply to caller |
| 5 | `SYS_NBSEND` | :construction: | Non-blocking send |
| 6 | `SYS_NBRECV` | :construction: | Non-blocking receive |
| 7 | `SYS_NOTIFY` | :construction: | Send async notification |
| 8 | `SYS_WAIT_NOTIFY` | :construction: | Wait for notification |

### Message Format
```
tag:     u64     Message type/opcode
data[4]: u64[4]  32 bytes of inline data
```

### SYS_SEND (1)
```
Args:   x0 = dest_task_id
        x1 = tag
        x2-x5 = data[0..3]
Return: x0 = 0 or error
```
Send a message to another task. Blocks until the receiver calls `recv()`.

### SYS_RECV (2)
```
Args:   x0 = from_task_id (-1 = any sender)
Return: x0 = sender_task_id
        x1 = tag
        x2-x5 = data[0..3]
```
Receive a message. Blocks until a message is available.

### SYS_CALL (3)
```
Args:   x0 = dest_task_id
        x1 = tag
        x2-x5 = data[0..3]
Return: x0 = reply_tag
        x1-x4 = reply_data[0..3]
```
Send a message and wait for reply (synchronous RPC).

### SYS_REPLY (4)
```
Args:   x0 = tag
        x1-x4 = data[0..3]
Return: x0 = 0 or error
```
Reply to the task that called us via `SYS_CALL`.

### SYS_NBSEND (5) :construction:
```
Args:   x0 = dest_task_id, x1 = tag, x2-x5 = data
Return: x0 = 0 or -EWOULDBLOCK
```
Non-blocking send. Returns immediately if receiver not ready.

### SYS_NBRECV (6) :construction:
```
Args:   x0 = from_task_id
Return: x0 = sender or -EWOULDBLOCK, x1-x5 = message
```
Non-blocking receive. Returns immediately if no message.

### SYS_NOTIFY (7) :construction:
```
Args:   x0 = dest_task_id, x1 = notification_bits
Return: x0 = 0 or error
```
Send asynchronous notification (bitmap). Never blocks.

### SYS_WAIT_NOTIFY (8) :construction:
```
Args:   x0 = expected_bits (0 = any)
Return: x0 = notification_bits received
```
Wait for notification bits to be set.

---

## 3. Shared Memory

| # | Name | Status | Description |
|---|------|--------|-------------|
| 10 | `SYS_SHMCREATE` | :white_check_mark: | Create shared memory region |
| 11 | `SYS_SHMMAP` | :white_check_mark: | Map SHM into address space |
| 12 | `SYS_SHMUNMAP` | :white_check_mark: | Unmap SHM from address space |
| 13 | `SYS_SHMGRANT` | :white_check_mark: | Grant task access to SHM |
| 14 | `SYS_SHMREVOKE` | :construction: | Revoke task's SHM access |
| 15 | `SYS_SHMDESTROY` | :construction: | Destroy SHM region |

### SYS_SHMCREATE (10)
```
Args:   x0 = size (bytes, rounded up to 4KB)
Return: x0 = shm_id or error
```
Create a new shared memory region. Caller is automatically granted access.

### SYS_SHMMAP (11)
```
Args:   x0 = shm_id
        x1 = vaddr_hint (0 = auto)
Return: x0 = mapped_vaddr or error
```
Map a shared memory region into the current task's address space.

### SYS_SHMUNMAP (12)
```
Args:   x0 = shm_id
Return: x0 = 0 or error
```
Unmap a shared memory region from the current task's address space.

### SYS_SHMGRANT (13)
```
Args:   x0 = shm_id
        x1 = task_id
Return: x0 = 0 or error
```
Grant another task permission to map the shared memory region.

### SYS_SHMREVOKE (14) :construction:
```
Args:   x0 = shm_id, x1 = task_id
Return: x0 = 0 or error
```
Revoke a task's access to shared memory (unmaps if mapped).

### SYS_SHMDESTROY (15) :construction:
```
Args:   x0 = shm_id
Return: x0 = 0 or error
```
Destroy a shared memory region (must be owner, unmaps from all tasks).

---

## 4. File Descriptors

| # | Name | Status | Description |
|---|------|--------|-------------|
| 57 | `SYS_CLOSE` | :white_check_mark: | Close file descriptor |
| 63 | `SYS_READ` | :white_check_mark: | Read from fd |
| 64 | `SYS_WRITE` | :white_check_mark: | Write to fd |
| 56 | `SYS_OPENAT` | :construction: | Open file (via VFS) |
| 23 | `SYS_DUP` | :construction: | Duplicate fd |
| 24 | `SYS_DUP2` | :construction: | Duplicate fd to specific number |
| 59 | `SYS_PIPE` | :construction: | Create pipe pair |
| 62 | `SYS_LSEEK` | :construction: | Seek in file |
| 79 | `SYS_FSTAT` | :construction: | Get file status |
| 80 | `SYS_FSTATAT` | :construction: | Get file status (path) |

### SYS_READ (63)
```
Args:   x0 = fd
        x1 = buf_ptr
        x2 = count
Return: x0 = bytes_read or error
```
Read up to `count` bytes from file descriptor into buffer.

### SYS_WRITE (64)
```
Args:   x0 = fd
        x1 = buf_ptr
        x2 = count
Return: x0 = bytes_written or error
```
Write up to `count` bytes from buffer to file descriptor.

### SYS_CLOSE (57)
```
Args:   x0 = fd
Return: x0 = 0 or error
```
Close a file descriptor.

### SYS_OPENAT (56) :construction:
```
Args:   x0 = dirfd (-1 = cwd)
        x1 = path_ptr
        x2 = flags
        x3 = mode
Return: x0 = fd or error
```
Open a file. Routes to VFS server via IPC internally.

### SYS_DUP (23) :construction:
```
Args:   x0 = oldfd
Return: x0 = newfd or error
```
Duplicate file descriptor to lowest available number.

### SYS_DUP2 (24) :construction:
```
Args:   x0 = oldfd, x1 = newfd
Return: x0 = newfd or error
```
Duplicate file descriptor to specific number.

### SYS_PIPE (59) :construction:
```
Args:   x0 = pipefd_ptr (array of 2 ints)
Return: x0 = 0 or error
        [pipefd[0]] = read end
        [pipefd[1]] = write end
```
Create a unidirectional pipe.

### SYS_LSEEK (62) :construction:
```
Args:   x0 = fd, x1 = offset, x2 = whence
Return: x0 = new_offset or error
```
Reposition read/write file offset.

---

## 5. Memory Management

| # | Name | Status | Description |
|---|------|--------|-------------|
| 222 | `SYS_MMAP` | :construction: | Map memory |
| 215 | `SYS_MUNMAP` | :construction: | Unmap memory |
| 226 | `SYS_MPROTECT` | :construction: | Change memory protection |
| 214 | `SYS_BRK` | :grey_question: | Change data segment size |

### SYS_MMAP (222) :construction:
```
Args:   x0 = addr_hint
        x1 = length
        x2 = prot (PROT_READ|PROT_WRITE|PROT_EXEC)
        x3 = flags (MAP_PRIVATE|MAP_ANONYMOUS|...)
        x4 = fd (-1 for anonymous)
        x5 = offset
Return: x0 = mapped_addr or error
```
Map memory into the address space.

### SYS_MUNMAP (215) :construction:
```
Args:   x0 = addr, x1 = length
Return: x0 = 0 or error
```
Unmap memory from the address space.

### SYS_MPROTECT (226) :construction:
```
Args:   x0 = addr, x1 = length, x2 = prot
Return: x0 = 0 or error
```
Change protection on a memory region.

---

## 6. Time

| # | Name | Status | Description |
|---|------|--------|-------------|
| 113 | `SYS_CLOCK_GETTIME` | :construction: | Get current time |
| 115 | `SYS_NANOSLEEP` | :construction: | Sleep for duration |
| 116 | `SYS_TIMER_CREATE` | :grey_question: | Create timer |

### SYS_CLOCK_GETTIME (113) :construction:
```
Args:   x0 = clock_id (0 = CLOCK_REALTIME, 1 = CLOCK_MONOTONIC)
        x1 = timespec_ptr
Return: x0 = 0 or error
```
Get current time from specified clock.

### SYS_NANOSLEEP (115) :construction:
```
Args:   x0 = req_timespec_ptr, x1 = rem_timespec_ptr
Return: x0 = 0 or -EINTR (remaining time in rem)
```
Sleep for specified duration.

---

## 7. System Information

| # | Name | Status | Description |
|---|------|--------|-------------|
| 100 | `SYS_SYSINFO` | :construction: | Get system information |
| 101 | `SYS_TASKINFO` | :construction: | Get task information |

### SYS_SYSINFO (100) :construction:
```
Args:   x0 = info_ptr
Return: x0 = 0 or error
```
Get system information (memory, CPU count, uptime).

### SYS_TASKINFO (101) :construction:
```
Args:   x0 = task_id (-1 = self), x1 = info_ptr
Return: x0 = 0 or error
```
Get information about a task (state, CPU time, memory usage).

---

## 8. IRQ Handling

| # | Name | Status | Description |
|---|------|--------|-------------|
| 30 | `SYS_IRQ_REGISTER` | :white_check_mark: | Register task as IRQ handler |
| 31 | `SYS_IRQ_WAIT` | :white_check_mark: | Wait for IRQ to fire |
| 32 | `SYS_IRQ_ACK` | :white_check_mark: | Acknowledge IRQ |

### SYS_IRQ_REGISTER (30)
```
Args:   x0 = irq_number
Return: x0 = 0 or error
```
Register the current task as the handler for the specified IRQ. Only one task
can be registered per IRQ. Used by device driver servers (e.g., blkdev for
VirtIO-blk interrupt).

### SYS_IRQ_WAIT (31)
```
Args:   x0 = irq_number
Return: x0 = 0 (IRQ fired) or error
```
Block until the specified IRQ fires. The task must have previously registered
for this IRQ with `SYS_IRQ_REGISTER`. Returns immediately if the IRQ is already
pending.

### SYS_IRQ_ACK (32)
```
Args:   x0 = irq_number
Return: x0 = 0 or error
```
Acknowledge an IRQ after handling it. This clears the pending flag and sends
End-Of-Interrupt (EOI) to the interrupt controller, allowing the IRQ to fire
again.

---

## 9. Capability / Security :grey_question:

| # | Name | Status | Description |
|---|------|--------|-------------|
| 200 | `SYS_CAP_GRANT` | :grey_question: | Grant capability to task |
| 201 | `SYS_CAP_REVOKE` | :grey_question: | Revoke capability |
| 202 | `SYS_CAP_CHECK` | :grey_question: | Check if task has capability |

Reserved for future capability-based security model.

---

## Error Codes

| Code | Name | Description |
|------|------|-------------|
| 0 | `ESUCCESS` | Success |
| -1 | `EPERM` | Operation not permitted |
| -2 | `ENOENT` | No such file or directory |
| -5 | `EIO` | I/O error |
| -9 | `EBADF` | Bad file descriptor |
| -11 | `EAGAIN` | Resource temporarily unavailable |
| -12 | `ENOMEM` | Out of memory |
| -14 | `EFAULT` | Bad address |
| -17 | `EEXIST` | File exists |
| -20 | `ENOTDIR` | Not a directory |
| -21 | `EISDIR` | Is a directory |
| -22 | `EINVAL` | Invalid argument |
| -23 | `ENFILE` | Too many open files in system |
| -24 | `EMFILE` | Too many open files |
| -28 | `ENOSPC` | No space left on device |
| -38 | `ENOSYS` | Function not implemented |

---

## Syscall Number Ranges

| Range | Category |
|-------|----------|
| 0-9 | Process / Scheduling |
| 1-8 | IPC |
| 10-19 | Shared Memory |
| 20-29 | Process Management |
| 30-39 | IRQ Handling |
| 56-99 | File I/O (Linux-compatible) |
| 100-119 | System Info / Time |
| 200-219 | Capabilities (reserved) |
| 220-239 | Memory Management |
