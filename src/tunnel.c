#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#if defined(__WIN32__)
#include <winsock2.h>
#else
#include <<arpa/inet.h>
#endif
#include "ectox.h"
#include "socket_misc.h"
#include "tunnel.h"
#include "tunnel_misc.h"
#include "vlist.h"
#include "vsys.h"
#include "vlog.h"

#define TUNNEL_MTU (1024)

static
int _encode_bind_req_msg(int domain, int type, uint16_t rport, int lsockfd, uint16_t nonce, uint8_t* buf, int bufsz)
{
    assert(domain == P2P_AF_INET);
    assert(type == P2P_SOCK_DGRAM || type == P2P_SOCK_STREAM);
    assert(lsockfd >= 0 || lsockfd == -1);
    assert(rport >= 0);
    assert(buf);
    assert(bufsz >= 8);

    int sz = 0;
    UINT8_T(buf + sz) = P2PTUNNEL_BIND_REQ;
    sz += 1;
    UINT8_T(buf + sz) = (uint8_t)domain;
    sz += 1;
    UINT8_T(buf + sz) = (uint8_t)type;
    sz += 1;
    UINT8_T(buf + sz) = 0;
    sz += 1;
    UINT16_T(buf + sz)= htons(rport);
    sz += 2;
    INT32_T(buf + sz) = htonl(lsockfd);
    sz += 4;
    UINT16_T(buf + sz)= htons(nonce);
    sz += 2;
    return sz;
}

static
int _encode_bind_rsp_msg(uint16_t status, int sockfd, uint16_t nonce, uint8_t* buf, int bufsz)
{
    assert(sockfd >= 0 || sockfd < 0);
    assert(buf);
    assert(bufsz >= 12);

    int sz = 0;
    UINT8_T(buf + sz) = P2PTUNNEL_BIND_RSP;
    sz += 1;
    UINT8_T(buf + sz) = 0; //reserved;
    sz += 1;
    UINT16_T(buf + sz)= htons(status);
    sz += 2;
    INT32_T(buf + sz) = (int32_t)htonl(sockfd);
    sz += 4;
    UINT16_T(buf + sz)= 0; // servered word.
    sz += 2;
    UINT16_T(buf + sz)= htons(nonce);
    sz += 2;
    return sz;
}

static
int _encode_postbind_msg(int lsockfd, int rsockfd, uint8_t* buf, int bufsz)
{
    assert(lsockfd >= 0);
    assert(rsockfd >= 0);
    assert(buf);
    assert(bufsz > 0);

    int sz = 0;
    UINT8_T(buf + sz) = P2PTUNNEL_POSTBIND;
    sz += 1;
    UINT8_T(buf + sz) = 0;
    sz += 1;
    UINT16_T(buf + sz)= 0;
    sz += 2;
    INT32_T(buf + sz) = htonl(lsockfd);
    sz += 4;
    INT32_T(buf + sz) = htonl(rsockfd);
    sz += 4;
    return sz;
}

static
int _encode_unbind_msg(int rsockfd, uint8_t* buf, int bufsz)
{
    assert(rsockfd >= 0);
    assert(buf);
    assert(bufsz >= 8);

    int sz = 0;
    UINT8_T(buf + sz) = P2PTUNNEL_UNBIND;
    sz += 1;
    UINT8_T(buf + sz) = 0; //reserved;
    sz += 1;
    UINT16_T(buf + sz)= 0; //reserved;
    sz += 2;
    INT32_T(buf + sz) = htonl(rsockfd);
    sz += 4;
    return sz;
}

static
int _encode_TCP_packet(const uint8_t* seg_data, uint16_t seg_sz, int rsockfd, uint8_t* buf, int bufsz)
{
    assert(seg_data);
    assert(rsockfd >= 0);
    assert(buf);
    assert(bufsz > 8);

    int sz = 0;
    UINT8_T(buf + sz) = 160;
    sz += 1;
    UINT8_T(buf + sz) = 0; //reserved;
    sz += 1;
    UINT16_T(buf + sz)= htons(seg_sz);
    sz += 2;
    INT32_T(buf + sz) = htonl(rsockfd);
    sz += 4;
    memcpy(buf + sz, seg_data, seg_sz);
    sz += seg_sz;

    assert(buf[0] == 160);
    return sz;
}

static
int _encode_UDP_packet(const uint8_t* seg_data, uint16_t seg_sz, uint16_t seg_off, uint8_t pktid, uint16_t pktsz, int rsockfd, uint8_t* buf, int bufsz)
{
    assert(seg_data);
    assert(rsockfd >= 0);
    assert(buf);
    assert(bufsz > 8);

    int sz = 0;
    UINT8_T(buf + sz) = 200;
    sz += 1;
    UINT8_T(buf + sz) = pktid;
    sz += 1;
    UINT16_T(buf + sz)= htons(pktsz);
    sz += 2;
    UINT16_T(buf + sz)= htons(seg_sz);
    sz += 2;
    UINT16_T(buf + sz)= htons(seg_off);
    sz += 2;
    INT32_T(buf + sz) = htonl(rsockfd);
    sz += 4;
    memcpy(buf + sz, seg_data, seg_sz);
    sz += seg_sz;
    return sz;
}

static
int _decode_bind_req_msg(const uint8_t* data, int datasz, int* domain, int* type, uint16_t* port, int* rsockfd, uint16_t* nonce)
{
    assert(data);
    assert(data[0] == P2PTUNNEL_BIND_REQ);
    assert(datasz >= 12);
    assert(domain);
    assert(type);
    assert(port);
    assert(rsockfd);
    assert(nonce);

    int sz = 0; sz += 1;
    *domain = UINT8_T(data + sz);
    sz += 1;
    *type = UINT8_T(data + sz);
    sz += 1;
    sz += 1; //reserved byte.
    *port = ntohs(UINT16_T(data + sz));
    sz += 2;
    *rsockfd = ntohl(INT32_T(data + sz));
    sz += 4;
    *nonce = ntohs(UINT16_T(data + sz));
    sz += 2;
    return sz;
}

static
int _decode_bind_rsp_msg(const uint8_t* data, int datasz, uint16_t* status, int* sockfd, uint16_t* nonce)
{
    assert(data);
    assert(data[0] == P2PTUNNEL_BIND_RSP);
    assert(datasz >= 8);
    assert(status);
    assert(sockfd);
    assert(nonce);

    int sz = 0; sz += 2;
    *status = ntohs(UINT16_T(data + sz));
    sz += 2;
    *sockfd = ntohl(INT32_T(data + sz));
    sz += 4;
    sz += 2; //skip reserved word.
    *nonce  = ntohs(UINT16_T(data + sz));
    sz += 2;
    return sz;
}

static
int _decode_postbind_msg(const uint8_t* data, int datasz, int* rsockfd, int* lsockfd)
{
    assert(data);
    assert(data[0] == P2PTUNNEL_POSTBIND);
    assert(datasz > 0);
    assert(rsockfd);
    assert(lsockfd);

    int sz = 0; sz += 4;
    *rsockfd = ntohl(INT32_T(data + sz));
    sz += 4;
    *lsockfd = ntohl(INT32_T(data + sz));
    sz += 4;
    return sz;
}

static
int _decode_unbind_msg(const uint8_t* data, int datasz, int* sockfd)
{
    assert(data);
    assert(datasz >= 8);
    assert(sockfd);
    assert(data[0] == P2PTUNNEL_UNBIND);

    int sz = 0; sz += 4;
    *sockfd = ntohl(INT32_T(data + sz));
    sz += sizeof(int32_t);
    return sz;
}

static
int _decode_TCP_packet(const uint8_t* data, int datasz, uint8_t* buf, int bufsz, uint16_t* seg_sz, int* sockfd)
{
    assert(data);
    assert(data[0] == 160);
    assert(datasz > 8);
    assert(buf);
    assert(bufsz > 0);
    assert(seg_sz);
    assert(sockfd);

    int sz = 0; sz += 2;
    *seg_sz = ntohs(UINT16_T(data + sz));
    if (*seg_sz > bufsz) {
        return -1;
    }
    sz += 2;
    *sockfd = ntohl(INT32_T(data + sz));
    sz += 4;
    memcpy(buf, data + sz, *seg_sz);
    sz += *seg_sz;
    return sz;
}

static
int _decode_UDP_packet_info(const uint8_t* data, int datasz, uint16_t* seg_sz, uint16_t* seg_off, uint8_t* pkt_id, uint16_t* pkt_sz, int* sockfd)
{
    assert(data);
    assert(data[0] == 200);
    assert(datasz >= 12);
    assert(seg_sz);
    assert(seg_off);
    assert(pkt_id);
    assert(pkt_sz);
    assert(sockfd);

    int sz = 0; sz += 1;
    *pkt_id = UINT8_T(data + sz);
    sz += 1;
    *pkt_sz = ntohs(UINT16_T(data + sz));
    sz += 2;
    *seg_sz = ntohs(UINT16_T(data + sz));
    sz += 2;
    *seg_off= ntohs(UINT16_T(data + sz));
    sz += 2;
    *sockfd = ntohl(INT32_T(data + sz));
    sz += 4;
    return sz;
}

static
int _decode_UDP_packet(const uint8_t* data, int datasz, uint8_t* buf, int bufsz)
{
    assert(data);
    assert(datasz > 0);
    assert(buf);
    assert(bufsz > 0);

    int sz = 0;
    memcpy(buf, data, datasz);
    sz += datasz;
    return sz;
}

static
struct p2ptunnel_msg_ops tunnel_msg_ops = {
    .enc_bind_req_msg    = _encode_bind_req_msg,
    .enc_bind_rsp_msg    = _encode_bind_rsp_msg,
    .enc_postbind_msg    = _encode_postbind_msg,
    .enc_unbind_msg      = _encode_unbind_msg,
    .enc_TCP_packet      = _encode_TCP_packet,
    .enc_UDP_packet      = _encode_UDP_packet,

    .dec_bind_req_msg    = _decode_bind_req_msg,
    .dec_bind_rsp_msg    = _decode_bind_rsp_msg,
    .dec_postbind_msg    = _decode_postbind_msg,
    .dec_unbind_msg      = _decode_unbind_msg,
    .dec_TCP_packet      = _decode_TCP_packet,
    .dec_UDP_packet_info = _decode_UDP_packet_info,
    .dec_UDP_packet      = _decode_UDP_packet,
};

static
void _handle_bind_req_msg(struct p2ptunnel* tun, const uint8_t* data, int sz)
{
    assert(tun);
    assert(tun->friendid >= 0);
    assert(data);
    assert(sz > 0);
    assert(data[0] == P2PTUNNEL_BIND_REQ);

    uint16_t port  = 0;
    uint16_t nonce = 0;
    int domain = 0;
    int type   = 0;
    int rfd    = 0;

    tun->msg_ops->dec_bind_req_msg(data, sz, &domain, &type, &port, &rfd, &nonce);

    uint16_t status = 0;
    int fd = tun->sock_ops->create_passive_socket(domain, type, port, rfd, tun);
    if (fd < 0) {
        vlogE("create passive socket error");
        status = (uint16_t)-fd;
    } else {
        status = P2PTUNNEL_BIND_RSP_OK;
    }

    uint8_t msg[12] = {0};
    int ret = tun->msg_ops->enc_bind_rsp_msg(status, fd, nonce, msg, sizeof(msg));
    ret = ecMessageFriend(tun->friendid, msg, ret);
    if (ret < 0) {
        vlogE("ecMessageFriend error");
        put_socket(pop_socket(fd));
    }
    vlogI("binding tunnel succeeded");
    return;
}

static
void _handle_bind_rsp_msg(struct p2ptunnel* tun, const uint8_t* data, int sz)
{
    assert(tun);
    assert(tun->friendid >= 0);
    assert(data);
    assert(sz > 0);
    assert(data[0] == P2PTUNNEL_BIND_RSP);

    uint16_t status = 0;
    uint16_t nonce  = 0;
    int rfd = 0;
    tun->msg_ops->dec_bind_rsp_msg(data, sz, &status, &rfd, &nonce);

    struct binding_waiter* wt = NULL;
    struct vlist* node = NULL;
    int found =0;

    vlock_enter(&tun->binding_lock);
    __vlist_for_each(node, &tun->binding_list) {
        wt = vlist_entry(node, struct binding_waiter, list);
        if (wt->nonce == nonce) {
            found = 1;
            break;
        }
    }
    vlock_leave(&tun->binding_lock);

    if (!wt) {
        vlogE("unrecognized nonce");
        return;
    }
    vlock_enter(&wt->lock);
    wt->tmpfd = rfd;
    vcond_signal(&wt->cond);
    vlock_leave(&wt->lock);
    return;
}

static
void _handle_postbind_msg(struct p2ptunnel* tun, const uint8_t* data, int sz)
{
    assert(tun);
    assert(data);
    assert(data[0] == P2PTUNNEL_POSTBIND);
    assert(sz > 0);

    int lsockfd = 0;
    int rsockfd = 0;
    tun->msg_ops->dec_postbind_msg(data, sz, &rsockfd, &lsockfd);
    tun->sock_ops->postbind_socket(lsockfd, rsockfd);
    return;
}

static
void _handle_unbind_msg(struct p2ptunnel* tun, const uint8_t* data, int sz)
{
    assert(tun);
    assert(tun->friendid >= 0);
    assert(data);
    assert(data[0] == P2PTUNNEL_UNBIND);
    assert(sz > 0);

    int sockfd = 0;
    tun->msg_ops->dec_unbind_msg(data, sz, &sockfd);
    tun->sock_ops->destroy_passive_socket(sockfd);
    return;
}

static
void _handle_UDP_packet(struct p2ptunnel* tun, const uint8_t* data, int sz)
{
    assert(tun);
    assert(tun->friendid >= 0);
    assert(data);
    assert(sz > 0);
    assert(data[0] == 200);

    uint8_t  seg_data[TUNNEL_MTU] = {0};
    uint16_t seg_sz  = 0;
    uint16_t seg_off = 0;
    uint8_t  pktid   = 0;
    uint16_t pktsz   = 0;
    int32_t  sockfd  = 0;
    int off = 0;
    int ret = 0;

    off = tun->msg_ops->dec_UDP_packet_info(data, sz, &seg_sz, &seg_off, &pktid, &pktsz, &sockfd);
    TUN_RECV_BYTES(tun, seg_sz);
    vlogI("<<- tunnel <<-|: received %d bytes(UDP)", seg_sz);

    if (pktsz == seg_sz) {
        tun->msg_ops->dec_UDP_packet(data + off, sz - off, seg_data, sizeof(seg_data));
        ret = tun->sock_ops->send_UDP_packet(sockfd, seg_data, pktsz);
        if (ret < 0) {
            vlogE("socket send packet error");
            return;
        }
        return;
    }

    struct recv_UDP_packet* up = tun->udp_pkts[pktid];
    if (up) {
        if (seg_off == 0) { // the first segment of packet.
            vlogE("recombination failure£¬discard it");
            free(up);
            up = calloc(1, pktsz + sizeof(*up));
            if (!up) {
                vlogE("calloc error");
                return;
            }
            up->packet = (uint8_t*)(up + 1);
            up->expect_sz = pktsz;
            up->cur_sz = 0;
        }
    } else {
        if (seg_off > 0) {
            vlogE("the first segment lost");
            return;
        }
        up = calloc(1, pktsz + sizeof(*up));
        if (!up) {
            vlogE("calloc error");
            return;
        }
        up->packet = (uint8_t*)(up + 1);
        up->expect_sz = pktsz;
        up->cur_sz = 0;
    }
    tun->msg_ops->dec_UDP_packet(data + off, sz - off, up->packet + seg_off, seg_sz);
    up->cur_sz += seg_sz;
    if (up->expect_sz == up->cur_sz) {
        ret = tun->sock_ops->send_UDP_packet(sockfd, up->packet, up->expect_sz);
        if (ret < 0) {
            vlogE("socket send packet error");
            return;
        }
    }
    return;
}

static
void _handle_TCP_packet(struct p2ptunnel* tun, const uint8_t* data, int sz)
{
    assert(tun);
    assert(tun->friendid >= 0);
    assert(data);
    assert(sz > 0);
    assert(data[0] == 160);

    uint8_t  seg_data[TUNNEL_MTU] = {0};
    uint16_t seg_sz  = 0;
    uint16_t seg_off = 0;
    int sockfd = 0;
    int leftsz = sz;

    while(leftsz > 0) {
        int ret = tun->msg_ops->dec_TCP_packet(data + seg_off, leftsz, seg_data, sizeof(seg_data), &seg_sz, &sockfd);
        leftsz  -= ret;
        seg_off += ret;
        vlogI("<<- tunnel <<-|: received %d bytes(TCP)", seg_sz);
        TUN_RECV_BYTES(tun, seg_sz);

        ret = tun->sock_ops->send_TCP_packet(sockfd, seg_data, seg_sz);
        if (ret < 0) {
            vlogE("socket send pacekt error");
            continue;
        }
    }
    return;
}

struct p2ptunnel_cb_ops tunnel_cb_ops = {
    .handle_bind_req_msg = _handle_bind_req_msg,
    .handle_bind_rsp_msg = _handle_bind_rsp_msg,
    .handle_postbind_msg = _handle_postbind_msg,
    .handle_unbind_msg   = _handle_unbind_msg,
    .handle_UDP_packet   = _handle_UDP_packet,
    .handle_TCP_packet   = _handle_TCP_packet,
};

static
int _tunnel_bind(struct p2ptunnel* tun, int domain, int type, uint16_t rport, int lsockfd)
{
    assert(tun);
    assert(domain == P2P_AF_INET);
    assert(type == P2P_SOCK_STREAM || type == P2P_SOCK_DGRAM);
    assert(lsockfd >= 0);
    assert(rport > 0);

    struct binding_waiter* wt = calloc(1, sizeof(*wt));
    if (!wt) {
        vlogE("calloc error");
        return -1;
    }
    wt->tmpfd = -1;
    wt->nonce = ++tun->nonce;
    vlist_init(&wt->list);
    vlock_init(&wt->lock);
    vcond_init(&wt->cond);

    vlock_enter(&tun->binding_lock);
    vlist_add_tail(&tun->binding_list, &wt->list);
    vlock_leave(&tun->binding_lock);

    uint8_t msg[12] = {0};
    int ret = tun->msg_ops->enc_bind_req_msg(domain, type, rport, lsockfd, wt->nonce, msg, sizeof(msg));
    int err = 0;
    do {
         err = ecMessageFriend(tun->friendid, msg, ret);
         if (err < 0) {
             if (err != -3) {
                 vlogE("ecMessageFriend error");
                 break;
             }
             vthread_sleep(1000);
         }
    } while(err == -3);

    if (err == 0) {
        vlock_enter(&wt->lock);
        vcond_wait(&wt->cond, &wt->lock);
        vlock_leave(&wt->lock);
    }
    vlock_enter(&tun->binding_lock);
    vlist_del(&wt->list);
    vlock_leave(&tun->binding_lock);

    int tmpfd = wt->tmpfd;
    free(wt);

    return tmpfd;
}

int _tunnel_postbind(struct p2ptunnel* tun, int lsockfd, int rsockfd)
{
    assert(tun);
    assert(lsockfd >= 0);
    assert(rsockfd >= 0);

    uint8_t msg[12] = {0};
    int ret = tun->msg_ops->enc_postbind_msg(lsockfd, rsockfd, msg, sizeof(msg));
    ret = ecMessageFriend(tun->friendid, msg, ret);
    if (ret < 0) {
       vlogE("ecMessageFriend error");
       return -1;
    }
    return 0;
}

void _tunnel_unbind(struct p2ptunnel* tun, int rsockfd)
{
    assert(tun);
    assert(rsockfd >= 0);

    uint8_t msg[8] = {0};
    int ret = tun->msg_ops->enc_unbind_msg(rsockfd, msg, sizeof(msg));
    ret = ecMessageFriend(tun->friendid, msg, ret);
    if (ret < 0) {
        vlogE("ecMessageFriend error");
        return;
    }
    return;
}

int _tunnel_send_unfinished_TCP_packet(struct p2ptunnel* tun)
{
    assert(tun);
    struct unfinished_TCP_packet* tp = &tun->unfinished_tcp_packet;
    if (!tp->packet) {
        return 0;
    }

    uint8_t packet[TUNNEL_MTU + 8] = {0};
    int leftsz = tp->leftsz;
    int sentsz = 0;
    int ret = 0;

    while(leftsz > 0) {
        int sendsz = (leftsz >= TUNNEL_MTU) ? TUNNEL_MTU : leftsz;
        ret = tun->msg_ops->enc_TCP_packet(tp->packet + sentsz, sendsz, tp->sockfd, packet, sizeof(packet));
        ret = ecSendLosslessPacket(tun->friendid, packet, ret);
        if (ret < 0) {
            vlogE("ecSendLosslessPacket error");
            TUN_SENT_ERROR(tun);
            break;
        }
        vlogI("->> tunnel ->>|: send %d bytes(unfinished TCP)", sendsz);
        TUN_SENT_BYTES(tun, sendsz);

        sentsz += sendsz;
        leftsz -= sendsz;
    }
    free(tp->packet);
    tp->packet = NULL;
    tp->leftsz = 0;
    tp->sockfd = -1;
    retE((leftsz > 0), -1);
    return 0;
}

int _tunnel_send_TCP_packet(struct p2ptunnel* tun, const uint8_t* data, int sz, int rsockfd)
{
    assert(tun);
    assert(data);
    assert(sz > 0);
    assert(rsockfd >= 0);

    uint8_t packet[TUNNEL_MTU + 8] = {0};
    int leftsz = sz;
    int sentsz = 0;
    int ret = 0;

    while(leftsz > 0) {
        int sendsz = (leftsz >= TUNNEL_MTU ? TUNNEL_MTU : leftsz);
        ret = tun->msg_ops->enc_TCP_packet(data + sentsz, sendsz, rsockfd, packet, sizeof(packet));
        ret = ecSendLosslessPacket(tun->friendid, packet, ret);
        if (ret < 0) {
            vlogE("ecSendLosslessPacket error");
            TUN_SENT_ERROR(tun);
            break;
        }
        vlogI("->> tunnel ->>|: send %d bytes(TCP)", sendsz);
        TUN_SENT_BYTES(tun, sendsz);

        sentsz += sendsz;
        leftsz -= sendsz;
    }

    if (leftsz > 0) {
        struct unfinished_TCP_packet* tp = &tun->unfinished_tcp_packet;
        tp->packet = calloc(1, leftsz);
        if (!tp->packet) {
            vlogE("calloc error");
            return -1;
        }
        tp->leftsz = leftsz;
        tp->sockfd = rsockfd;
        memcpy(tp->packet, data + sentsz, leftsz);
    }
    return sz;
}

int _tunnel_send_UDP_packet(struct p2ptunnel* tun, const uint8_t* data, int sz, int rsockfd)
{
    assert(tun);
    assert(data);
    assert(sz > 0);
    assert(rsockfd >= 0);

    uint8_t packet[TUNNEL_MTU + 12] = {0};
    int seg_num = 0;
    int seg_off = 0;
    int seg_sz  = 0;
    int ret = 0;

    if (sz % TUNNEL_MTU) {
        seg_num = sz / TUNNEL_MTU + 1;
    } else {
        seg_num = sz / TUNNEL_MTU;
    }

    while(seg_off < sz) {
        if (seg_off + TUNNEL_MTU < sz) {
            seg_sz = TUNNEL_MTU;
        } else {
            seg_sz = sz - seg_off;
        }
        ret = tun->msg_ops->enc_UDP_packet(data + seg_off, seg_sz, seg_off, tun->udp_send_pktid, sz, rsockfd, packet, sizeof(packet));
        ret = ecSendLossyPacket(tun->friendid, packet, ret);
        if (ret < 0) {
            vlogE("ecSendLossyPacket error");
            TUN_SENT_ERROR(tun);
            break;
        }
        TUN_SENT_BYTES(tun, seg_sz);
        vlogI("->> tunnel ->>|: send %d bytes(UDP)", seg_sz);
        seg_off += seg_sz;
    }
    ++tun->udp_send_pktid;
    return seg_off;
}

static
struct p2ptunnel_ops tunnel_ops = {
    .bind            = _tunnel_bind,
    .postbind        = _tunnel_postbind,
    .unbind          = _tunnel_unbind,
    .send_unfinished_TCP_packet
                     = _tunnel_send_unfinished_TCP_packet,
    .send_TCP_packet = _tunnel_send_TCP_packet,
    .send_UDP_packet = _tunnel_send_UDP_packet,
};

struct p2ptunnel* create_tunnel(const uint8_t* key, int active_flag)
{
    assert(key);
    struct p2ptunnel* tun = calloc(1, sizeof(*tun));
    if (!tun) {
        vlogE("calloc error");
        return NULL;
    }
    int fid = 0;
    if (!!active_flag) {
        fid = ecAddFriend(key, "123456", strlen("123456"));
        if (fid < 0) {
            free(tun);
            vlogE("ecAddFriend error");
            return NULL;
        }
    } else {
        fid = ecAcceptFriend(key);
        if (fid < 0) {
            free(tun);
            vlogE("ecAcceptFriend error");
            return NULL;
        }
    }
    vlogI("added a new friend");

    vlist_init(&tun->list);
    memcpy(tun->key, key, 32);
    tun->friendid = fid;
    tun->count    = 1;
    tun->nonce    = 0;
    tun->ops      = &tunnel_ops;
    tun->cb_ops   = &tunnel_cb_ops;
    tun->msg_ops  = &tunnel_msg_ops;

    extern struct p2psocket_helper_ops socket_helper_ops;
    tun->sock_ops = &socket_helper_ops;

    vlist_init(&tun->binding_list);
    vlock_init(&tun->binding_lock);
    return tun;
}

