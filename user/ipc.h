// IPC types and syscall wrappers for Kenix userspace
#ifndef _KENIX_IPC_H
#define _KENIX_IPC_H

// Task ID type
typedef unsigned long TaskId;

// Special task ID meaning "any sender"
#define TASK_ANY ((TaskId)-1)

// Syscall numbers
#define SYS_SEND  1
#define SYS_RECV  2
#define SYS_CALL  3
#define SYS_REPLY 4

// Message tags for built-in services
#define MSG_WRITE     1   // Inline write (up to 24 bytes in data[1-3])
#define MSG_EXIT      2   // Exit notification
#define MSG_YIELD     3   // Yield hint
#define MSG_SHM_WRITE 4   // Write via shared memory: data[0]=shm_id, data[1]=offset, data[2]=len

// IPC result codes
#define IPC_OK             0
#define IPC_ERR_INVALID   -1
#define IPC_ERR_DEAD      -2
#define IPC_ERR_BLOCKED   -3
#define IPC_ERR_NOT_WAIT  -4

// IPC Message structure
// Matches kernel Message struct layout
typedef struct {
    unsigned long tag;      // Message type/opcode
    unsigned long data[4];  // 4 words of inline data
} Message;

// Received message with sender information
typedef struct {
    TaskId sender;
    Message msg;
} RecvResult;

// Send a message to destination task (blocking)
// Returns 0 on success, negative error code on failure
static inline long sys_send(TaskId dest, const Message *msg) {
    register unsigned long x0 __asm__("x0") = dest;
    register unsigned long x1 __asm__("x1") = msg->tag;
    register unsigned long x2 __asm__("x2") = msg->data[0];
    register unsigned long x3 __asm__("x3") = msg->data[1];
    register unsigned long x4 __asm__("x4") = msg->data[2];
    register unsigned long x5 __asm__("x5") = msg->data[3];
    register unsigned long x8 __asm__("x8") = SYS_SEND;

    __asm__ volatile(
        "svc #0"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
        : "memory"
    );

    return (long)x0;
}

// Receive a message (blocking)
// from: TASK_ANY to accept from any sender, or specific task ID
// Returns received message with sender ID
static inline RecvResult sys_recv(TaskId from) {
    RecvResult result;
    register unsigned long x0 __asm__("x0") = from;
    register unsigned long x1 __asm__("x1");
    register unsigned long x2 __asm__("x2");
    register unsigned long x3 __asm__("x3");
    register unsigned long x4 __asm__("x4");
    register unsigned long x5 __asm__("x5");
    register unsigned long x8 __asm__("x8") = SYS_RECV;

    __asm__ volatile(
        "svc #0"
        : "+r"(x0), "=r"(x1), "=r"(x2), "=r"(x3), "=r"(x4), "=r"(x5)
        : "r"(x8)
        : "memory"
    );

    result.sender = x0;
    result.msg.tag = x1;
    result.msg.data[0] = x2;
    result.msg.data[1] = x3;
    result.msg.data[2] = x4;
    result.msg.data[3] = x5;

    return result;
}

// Send message and wait for reply (RPC pattern)
// Returns reply message
static inline Message sys_call(TaskId dest, const Message *msg) {
    Message reply;
    register unsigned long x0 __asm__("x0") = dest;
    register unsigned long x1 __asm__("x1") = msg->tag;
    register unsigned long x2 __asm__("x2") = msg->data[0];
    register unsigned long x3 __asm__("x3") = msg->data[1];
    register unsigned long x4 __asm__("x4") = msg->data[2];
    register unsigned long x5 __asm__("x5") = msg->data[3];
    register unsigned long x8 __asm__("x8") = SYS_CALL;

    __asm__ volatile(
        "svc #0"
        : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3), "+r"(x4)
        : "r"(x5), "r"(x8)
        : "memory"
    );

    reply.tag = x0;
    reply.data[0] = x1;
    reply.data[1] = x2;
    reply.data[2] = x3;
    reply.data[3] = x4;

    return reply;
}

// Reply to a caller (non-blocking)
// Returns 0 on success, negative error code on failure
static inline long sys_reply(const Message *msg) {
    register unsigned long x0 __asm__("x0") = msg->tag;
    register unsigned long x1 __asm__("x1") = msg->data[0];
    register unsigned long x2 __asm__("x2") = msg->data[1];
    register unsigned long x3 __asm__("x3") = msg->data[2];
    register unsigned long x4 __asm__("x4") = msg->data[3];
    register unsigned long x8 __asm__("x8") = SYS_REPLY;

    __asm__ volatile(
        "svc #0"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x8)
        : "memory"
    );

    return (long)x0;
}

#endif // _KENIX_IPC_H
