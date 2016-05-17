#pragma once

#include <stdint.h>
#include "p2psocket.h"
#include "socket_misc.h"
#include "vlist.h"
#include "vsys.h"

#define UINT8_T(data)  (*(uint8_t*)(data))
#define UINT16_T(data) (*(uint16_t*)(data))
#define UINT32_T(data) (*(uint32_t*)(data))
#define INT32_T(data)  (*(int32_t*)(data))

enum {
    P2PTUNNEL_BIND_REQ,
    P2PTUNNEL_BIND_RSP,
    P2PTUNNEL_POSTBIND,
    P2PTUNNEL_UNBIND,
};

enum {
    P2PTUNNEL_BIND_RSP_OK,
    P2PTUNNEL_BIND_RSP_ERR,
};

struct p2ptunnel_msg_ops {
    int  (*enc_bind_req_msg)   (int, int, uint16_t, int, uint16_t, uint8_t*, int);
    int  (*enc_bind_rsp_msg)   (uint16_t, int, uint16_t,uint8_t*, int);
    int  (*enc_postbind_msg)   (int, int, uint8_t*, int);
    int  (*enc_unbind_msg)     (int, uint8_t*, int);
    int  (*enc_TCP_packet)     (const uint8_t*, uint16_t, int, uint8_t*, int);
    int  (*enc_UDP_packet)     (const uint8_t*, uint16_t, uint16_t, uint8_t, uint16_t, int, uint8_t*, int);

    int  (*dec_bind_req_msg)   (const uint8_t*, int, int*, int*, uint16_t*, int*, uint16_t*);
    int  (*dec_bind_rsp_msg)   (const uint8_t*, int, uint16_t*, int*, uint16_t*);
    int  (*dec_postbind_msg)   (const uint8_t*, int, int*, int*);
    int  (*dec_unbind_msg)     (const uint8_t*, int, int*);
    int  (*dec_TCP_packet)     (const uint8_t*, int, uint8_t*, int, uint16_t*, int*);
    int  (*dec_UDP_packet_info)(const uint8_t*, int, uint16_t*, uint16_t*, uint8_t*, uint16_t*, int*);
    int  (*dec_UDP_packet)     (const uint8_t*, int, uint8_t*, int);
};

struct p2ptunnel_cb_ops {
    void (*handle_bind_req_msg)(struct p2ptunnel*, const uint8_t*, int);
    void (*handle_bind_rsp_msg)(struct p2ptunnel*, const uint8_t*, int);
    void (*handle_postbind_msg)(struct p2ptunnel*, const uint8_t*, int);
    void (*handle_unbind_msg)  (struct p2ptunnel*, const uint8_t*, int);
    void (*handle_UDP_packet)  (struct p2ptunnel*, const uint8_t*, int);
    void (*handle_TCP_packet)  (struct p2ptunnel*, const uint8_t*, int);
};

struct p2ptunnel_ops {
    int  (*bind)               (struct p2ptunnel*, int, int, uint16_t, int);
    int  (*postbind)           (struct p2ptunnel*, int, int);
    void (*unbind)             (struct p2ptunnel*, int);
    int  (*send_UDP_packet)    (struct p2ptunnel*, const uint8_t*, int, int);
    int  (*send_unfinished_TCP_packet)(struct p2ptunnel*);
    int  (*send_TCP_packet)    (struct p2ptunnel*, const uint8_t*, int, int);
};

struct unfinished_TCP_packet {
    uint8_t* packet;
    uint8_t  pad[2];
    uint16_t leftsz;
    int32_t  sockfd;
};

struct recv_UDP_packet{
    uint8_t* packet;
    uint16_t expect_sz;
    uint16_t cur_sz;
};

struct binding_waiter {
    struct vlist list;
    struct vlock lock;
    struct vcond cond;
    uint16_t nonce;
    uint8_t pad[2];
    int32_t tmpfd;
};

struct tunnel_stat
{
    int32_t sent_error;
    int64_t sent_bytes;
    int64_t recv_bytes;
};

#define TUN_SENT_ERROR(tun)         do {tun->stat.sent_error += 1;     } while(0)
#define TUN_SENT_BYTES(tun, bytes)  do {tun->stat.sent_bytes += bytes; } while(0)
#define TUN_RECV_BYTES(tun, bytes)  do {tun->stat.recv_bytes += bytes; } while(0)

#define TUNNEL_MAX_PACKETID (0xFF)

struct p2ptunnel {
    struct vlist list;
    struct tunnel_stat stat;
    uint8_t key[P2PSOCK_KEY_LEN];
    int32_t friendid;
    volatile int32_t count;

    uint8_t pad1[2];
    uint16_t nonce;
    struct vlist binding_list;
    struct vlock binding_lock;

    struct unfinished_TCP_packet unfinished_tcp_packet;

    uint8_t pad2[3];
    uint8_t udp_send_pktid;
    struct recv_UDP_packet* udp_pkts[TUNNEL_MAX_PACKETID + 1];

    struct p2ptunnel_ops* ops;
    struct p2ptunnel_cb_ops* cb_ops;
    struct p2ptunnel_msg_ops* msg_ops;
    struct p2psocket_helper_ops* sock_ops;
};

struct p2ptunnel* create_tunnel(const uint8_t*, int);

