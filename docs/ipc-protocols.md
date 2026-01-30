# Kenix IPC Message Protocols

This document defines the message formats used for communication between user-space servers and clients.

## Message Structure

All IPC messages use this format:
```
tag:     u64     - Message type/opcode
data[4]: u64[4]  - 32 bytes of inline data
```

Total inline payload: 32 bytes. Use shared memory for larger transfers.

---

## Console Server (Task 1)

### MSG_WRITE (1) - Write inline text
```
Request:
  tag = 1
  data[0] = length (max 24)
  data[1..3] = string bytes (up to 24 bytes)

Reply:
  tag = bytes_written
```

### MSG_SHM_WRITE (10) - Write via shared memory
```
Request:
  tag = 10
  data[0] = shm_id
  data[1] = offset in SHM
  data[2] = length

Reply:
  tag = bytes_written or error
```
Note: Caller must grant console server access via `SYS_SHMGRANT` first.

### MSG_EXIT (2) - Notify exit (optional)
```
Request:
  tag = 2

Reply:
  tag = 0
```

---

## VFS Server (Task 3)

### VFS_OPEN (100) - Open file
```
Request:
  tag = 100
  data[0..3] as bytes:
    byte 0 = path_length (max 31)
    bytes 1-31 = path string

Reply:
  tag = file_handle (>= 0) or error (< 0)
```

### VFS_CLOSE (101) - Close file
```
Request:
  tag = 101
  data[0] = file_handle

Reply:
  tag = 0 or error
```

### VFS_READ (102) - Read from file
```
Request:
  tag = 102
  data[0] = file_handle
  data[1] = max_bytes (max 32)

Reply:
  tag = bytes_read or error
  data[0..3] = file data (up to 32 bytes)
```

### VFS_WRITE (103) - Write to file :construction:
```
Request:
  tag = 103
  data[0] = file_handle
  data[1] = length (max 24)
  data[2..3] = data bytes

Reply:
  tag = bytes_written or error
```

### VFS_STAT (104) - Get file info :construction:
```
Request:
  tag = 104
  data[0..3] as bytes:
    byte 0 = path_length
    bytes 1-31 = path string

Reply:
  tag = 0 or error
  data[0] = file_size
  data[1] = file_type (0=file, 1=dir)
  data[2] = permissions
```

### VFS_MKDIR (105) - Create directory :construction:
```
Request:
  tag = 105
  data[0..3] as bytes:
    byte 0 = path_length
    bytes 1-31 = path string

Reply:
  tag = 0 or error
```

### VFS_READDIR (106) - Read directory :construction:
```
Request:
  tag = 106
  data[0] = dir_handle
  data[1] = entry_index

Reply:
  tag = 0 (more entries) or 1 (end) or error
  data[0..3] as bytes:
    byte 0 = name_length
    bytes 1-31 = entry name
```

### VFS_UNLINK (107) - Delete file :construction:
```
Request:
  tag = 107
  data[0..3] as bytes:
    byte 0 = path_length
    bytes 1-31 = path string

Reply:
  tag = 0 or error
```

### VFS_RENAME (108) - Rename file :construction:
```
Request:
  tag = 108
  data[0] = shm_id (containing old_path + new_path)
  data[1] = old_path_offset
  data[2] = old_path_len
  data[3] = new_path_len (new_path follows old_path)

Reply:
  tag = 0 or error
```

---

## Block Device Server (Task 4)

The block device server provides block-level access to storage devices via VirtIO-blk.
Block size is 512 bytes (standard sector size).

### BLK_READ (200) - Read sectors
```
Request:
  tag = 200
  data[0] = sector_number (starting sector)
  data[1] = sector_count (number of sectors to read)
  data[2] = shm_id (destination buffer, must be granted access)

Reply:
  tag = bytes_read (>= 0) or error (< 0)
```
Note: Maximum read size is 4KB (8 sectors) per request due to bounce buffer.

### BLK_WRITE (201) - Write sectors
```
Request:
  tag = 201
  data[0] = sector_number (starting sector)
  data[1] = sector_count (number of sectors to write)
  data[2] = shm_id (source buffer, must be granted access)

Reply:
  tag = bytes_written (>= 0) or error (< 0)
```
Note: Maximum write size is 4KB (8 sectors) per request due to bounce buffer.

### BLK_INFO (202) - Get device info
```
Request:
  tag = 202

Reply:
  tag = ERR_OK (0) or error
  data[0] = capacity (total sectors)
  data[1] = sector_size (512)
```

---

## Network Device Server (Task 5)

The network device server provides raw packet send/receive via VirtIO-net.

### NET_SEND (300) - Send packet
```
Request:
  tag = 300
  data[0] = shm_id (source buffer)
  data[1] = offset in SHM
  data[2] = length (max 1514 bytes)

Reply:
  tag = bytes_sent (>= 0) or error (< 0)
```
Note: Caller must grant netdev server access via `SYS_SHMGRANT` first.

### NET_RECV (301) - Receive packet
```
Request:
  tag = 301
  data[0] = shm_id (destination buffer)
  data[1] = offset in SHM
  data[2] = max_length

Reply:
  tag = bytes_received (>= 0) or error (< 0)
```
Returns 0 if no packet is available.

### NET_INFO (302) - Get device info
```
Request:
  tag = 302

Reply:
  tag = ERR_OK (0)
  data[0] = MAC address (6 bytes packed in low 48 bits)
  data[1] = link status (1 = up, 0 = down)
```

---

## Network Socket Server (Future) :construction:

The socket server will provide TCP/IP networking, built on top of the netdev raw packet interface.

### SOCK_SOCKET (400) - Create socket
```
Request:
  tag = 400
  data[0] = domain (AF_INET=2)
  data[1] = type (SOCK_STREAM=1, SOCK_DGRAM=2)

Reply:
  tag = socket_handle or error
```

### SOCK_BIND (401) - Bind socket
```
Request:
  tag = 401
  data[0] = socket_handle
  data[1] = ip_address (big-endian)
  data[2] = port

Reply:
  tag = 0 or error
```

### SOCK_LISTEN (402) - Listen for connections
```
Request:
  tag = 402
  data[0] = socket_handle
  data[1] = backlog

Reply:
  tag = 0 or error
```

### SOCK_ACCEPT (403) - Accept connection
```
Request:
  tag = 403
  data[0] = socket_handle

Reply:
  tag = new_socket_handle or error
  data[0] = client_ip
  data[1] = client_port
```

### SOCK_CONNECT (404) - Connect to server
```
Request:
  tag = 404
  data[0] = socket_handle
  data[1] = ip_address
  data[2] = port

Reply:
  tag = 0 or error
```

### SOCK_SEND (405) - Send data
```
Request:
  tag = 405
  data[0] = socket_handle
  data[1] = shm_id
  data[2] = offset
  data[3] = length

Reply:
  tag = bytes_sent or error
```

### SOCK_RECV (406) - Receive data
```
Request:
  tag = 406
  data[0] = socket_handle
  data[1] = shm_id
  data[2] = offset
  data[3] = max_length

Reply:
  tag = bytes_received or error
```

### SOCK_CLOSE (407) - Close socket
```
Request:
  tag = 407
  data[0] = socket_handle

Reply:
  tag = 0 or error
```

---

## Well-Known Task IDs

| ID | Name | Description |
|----|------|-------------|
| 0 | Idle | Kernel idle task |
| 1 | Console | Console I/O server (UART) |
| 2 | Init | Init process |
| 3 | VFS | Virtual filesystem server (ramfs + FAT32) |
| 4 | Blkdev | Block device server (VirtIO-blk) |
| 5 | Netdev | Network device server (VirtIO-net) |
| 6+ | (dynamic) | User applications |

---

## Error Codes (IPC-level)

| Code | Name | Description |
|------|------|-------------|
| 0 | `IPC_OK` | Success |
| -1 | `IPC_ERR_INVALID` | Invalid message or parameter |
| -2 | `IPC_ERR_DEAD` | Target task is dead |
| -3 | `IPC_ERR_BLOCKED` | Would block (non-blocking mode) |
| -4 | `IPC_ERR_NOT_WAITING` | Target not waiting for reply |

## Error Codes (Server-level)

Use standard errno values for consistency:
| Code | Name | Description |
|------|------|-------------|
| -2 | `ENOENT` | File not found |
| -5 | `EIO` | I/O error (device failure) |
| -9 | `EBADF` | Bad file handle |
| -12 | `ENOMEM` | Out of memory |
| -17 | `EEXIST` | Already exists |
| -20 | `ENOTDIR` | Not a directory |
| -21 | `EISDIR` | Is a directory |
| -22 | `EINVAL` | Invalid argument |
| -23 | `ENFILE` | Too many open files |
| -28 | `ENOSPC` | No space left |
