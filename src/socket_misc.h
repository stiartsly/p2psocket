#pragma once

#if defined(__WIN32__)
#include <winsock2.h>

#ifndef EWOULDBLOCK
#define EWOULDBLOCK WSAEWOULDBLOCK
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#define _socket_errno WSAGetLastError()
#else
#include <netinet/in.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>
#define _socket_errno errno
#endif
#include <stdint.h>
#include "p2psocket.h"
#include "tunnel.h"
#include "vlist.h"

#define retE(exp, value) if (exp) return (value)

struct p2psocket;
struct p2psocket_ops {
    int  (*do_TCP_connection)(struct p2psocket*);
    int  (*do_TCP_packet)    (struct p2psocket*);
    int  (*do_UDP_packet)    (struct p2psocket*);
};

struct p2psocket_cb_ops {
    void (*do_recv_event)    (struct p2psocket*);
    void (*do_send_event)    (struct p2psocket*);
    void (*do_error_event)   (struct p2psocket*);
};

struct p2psocket_helper_ops {
    int (*create_passive_socket) (int, int, uint16_t, int, void*);
    int (*destroy_passive_socket)(int);
    int (*postbind_socket)   (int, int);
    int (*send_TCP_packet)   (int, const uint8_t*, int);
    int (*send_UDP_packet)   (int, const uint8_t*, int);
};

struct socket_stat {
    int32_t recv_error;
    int32_t sent_error;
    int64_t recv_bytes;
    int64_t sent_bytes;
};

#define SOCK_RECV_ERROR(sck)        do { sck->stat.recv_error += 1;     } while(0)
#define SOCK_RECV_BYTES(sck, bytes) do { sck->stat.sent_error += bytes; } while(0)
#define SOCK_SENT_ERROR(sck)        do { sck->stat.sent_error += 1;     } while(0)
#define SOCK_SENT_BYTES(sck, bytes) do { sck->stat.sent_bytes += bytes; } while(0)

#define SOCK_RECV_BUFSZ (0xFFFF)

struct p2psocket {
    int32_t domain;
    int32_t type;
    int32_t proto;

    volatile int32_t count;
    struct vlist list;
    struct socket_stat stat;

    int32_t lfd;    // local sockfd;
    int32_t rfd;    // sockfd on remote agent.
    int32_t tmp_fd; // used for connection from TCP client.

#define laddr_family laddr.in.laddr.sin_family
#define laddr_port   laddr.in.laddr.sin_port
#define laddr_saddr  laddr.in.laddr.sin_addr.s_addr
#define laddr_addr   laddr.in.laddr
#define laddr_rport  laddr.in.rport
#define laddr_key    laddr.in.key
    union {
        struct sockaddr_p2pin in;
    }laddr;

#define raddr_family raddr.in.sin_family
#define raddr_port   raddr.in.sin_port
#define raddr_addr   raddr.in.sin_addr
    union {
        struct sockaddr_in in;
    }raddr; // address of client peer.

    uint8_t* rcvbuf;

    uint8_t* unfinished_tcp_packet;
    int32_t  unfinished_tcp_packet_sz;

    struct p2psocket_ops* ops;
    struct p2psocket_cb_ops* cb_ops;

    struct p2ptunnel* tun;

    void (*shutdown_cb)(struct p2psocket*);
};

struct p2psocket* get_socket(int);
struct p2psocket* pop_socket(int);
void put_socket (struct p2psocket*);
void push_socket(struct p2psocket*);
void do_each_socket(void (*)(struct p2psocket*, void*), void*);

int  laundry_start(void);
void laundry_stop (void);

