#include <stdlib.h>
#include <assert.h>
#if defined(__WIN32__)
#include <winsock2.h>
#define close(fd) closesocket(fd)
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#endif
#include "p2psocket.h"
#include "socket_misc.h"
#include "tunnel.h"
#include "tunnel_misc.h"
#include "vlist.h"
#include "vsys.h"
#include "vlog.h"

struct p2psocket_ops    socket_ops;
struct p2psocket_cb_ops socket_cb_ops;
static uint8_t socket_rcvbuf[SOCK_RECV_BUFSZ] = {0};
void _socket_shutdown(struct p2psocket*);

int _socket_set_nonblock(int sockfd)
{
    int ret = 0;
#if defined(__WIN32__)
    u_long mode = 1;
    ret = ioctlsocket(sockfd, FIONBIO, &mode);
#else
    ret = fcntl(sockfd, F_SETFL, O_NONBLOCK, 1);
#endif
    retE((ret != 0), -1);

    ret = 1;
    ret = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void*)&ret, sizeof(ret));
    retE((ret != 0), -1);
    return 0;
}

static
int _create_passive_socket(int domain, int type, uint16_t port, int rsockfd, void* tun)
{
    assert(domain == P2P_AF_INET);
    assert(type == P2P_SOCK_STREAM || type == P2P_SOCK_DGRAM);
    assert(port > 0);
    assert(rsockfd >= 0);
    assert(tun);

    struct p2psocket* tmp = calloc(1, sizeof(*tmp));
    if (!tmp) {
        vlogE("calloc error");
        return -1;
    }
    int fd = socket(domain, (int)type, 0);
    if (fd < 0) {
        vlogE("socket error(%d)", _socket_errno);
        free(tmp);
        return -1;
    }

    tmp->raddr_family = domain;
    tmp->raddr_port   = htons(port);
    tmp->raddr_addr.s_addr = inet_addr("127.0.0.1");
    if (type == P2P_SOCK_STREAM) {
        int ret = connect(fd, (struct sockaddr*)&tmp->raddr.in, sizeof(tmp->raddr.in));
        if (ret < 0) {
            vlogE("connect error(%d)", _socket_errno);
            close(fd);
            free(tmp);
            return -1;
        }
        _socket_set_nonblock(fd);
    }
    tmp->domain = domain;
    tmp->type   = (int)type;
    tmp->proto  = 0;
    tmp->count  = 1;
    tmp->lfd    = fd;
    tmp->rfd    = rsockfd;
    tmp->tmp_fd = -1;
    tmp->rcvbuf = socket_rcvbuf;
    tmp->ops    = &socket_ops;
    tmp->cb_ops = &socket_cb_ops;
    tmp->tun    = tun;
    ++tmp->tun->count;
    vlist_init(&tmp->list);
    tmp->shutdown_cb = _socket_shutdown;

    vlogI("new p2psocket created:\n"\
          "    local  port:%d\n"\
          "    remote port:%d\n"\
          "    local  socket:%d\n"
          "    remote socket:%d\n",
          ntohs(tmp->laddr_port), \
          tmp->laddr_rport, \
          tmp->lfd, \
          tmp->rfd);

    push_socket(tmp);
    return tmp->lfd;
}

static
int _destroy_passive_socket(int sockfd)
{
    assert(sockfd >= 0);

    struct p2psocket* socket = pop_socket(sockfd);
    if (!socket) {
        vlogE("p2psocket not found");
        return -1;
    }
    socket->rfd = -1; // the remote peer socket was closed.
    put_socket(socket);
    free(socket);
    return 0;
}

static
int _postbind_socket(int sockfd, int rsockfd)
{
    assert(sockfd  >= 0);
    assert(rsockfd >= 0);

    struct p2psocket* socket = get_socket(sockfd);
    if (!socket) {
        vlogE("p2psocket not found");
    }
    assert(socket->type == P2P_SOCK_STREAM);
    socket->rfd = rsockfd;
    put_socket(socket);
    return 0;
}

static
int _send_TCP_packet(int sockfd, const uint8_t* data, int sz)
{
    assert(sockfd >= 0);
    assert(data);
    assert(sz > 0);

    struct p2psocket* socket = get_socket(sockfd);
    if (!socket) {
        vlogE("[TCP] p2psocket not found");
        return -1;
    }
    assert(socket->type == P2P_SOCK_STREAM);
    int ret = 0;
    if (socket->unfinished_tcp_packet) {
        ret = send(socket->lfd, socket->unfinished_tcp_packet, socket->unfinished_tcp_packet_sz, MSG_NOSIGNAL);
        free(socket->unfinished_tcp_packet);
        socket->unfinished_tcp_packet    = NULL;
        if (ret < 0) {
            vlogE("send error(%d)", _socket_errno);
            SOCK_SENT_ERROR(socket);
            put_socket(socket);
            return -1;
        }
        SOCK_SENT_BYTES(socket, ret);
        vlogI("<<- socket <<-|: sended %d bytes (unfinished TCP)", ret);
    }
    int leftsz = 0;
    ret = send(socket->lfd, data, sz, MSG_NOSIGNAL);
    if (ret < 0) {
        if (_socket_errno == EAGAIN || _socket_errno == EWOULDBLOCK) {
            leftsz = sz;
        } else {
            vlogE("send error(%d)", _socket_errno);
            SOCK_SENT_ERROR(socket);
            put_socket(socket);
            return -1;
        }
    }
    SOCK_SENT_BYTES(socket, ret);
    vlogI("<<- socket <<-|: sended %d bytes(TCP)", ret);

    if (ret < sz) {
        uint8_t* packet = calloc(1, sz - ret);
        if (!packet) {
            vlogE("calloc error");
            put_socket(socket);
            return -1;
        }
        memcpy(packet, data + ret, sz -ret);
        socket->unfinished_tcp_packet = packet;
        socket->unfinished_tcp_packet_sz = sz - ret;
    }
    put_socket(socket);
    return 0;
}

static
int _send_UDP_packet(int sockfd, const uint8_t* data, int sz)
{
    assert(sockfd >= 0);
    assert(data);
    assert(sz > 0);

    struct p2psocket* socket = get_socket(sockfd);
    if (!socket) {
        vlogE("p2psocket not found");
        return -1;
    }
    assert(socket->type == P2P_SOCK_DGRAM);

    int ret = sendto(socket->lfd, data, sz, MSG_NOSIGNAL, (struct sockaddr*)&socket->raddr.in, sizeof(struct sockaddr_in));
    if (ret < 0) {
        vlogE("sendto error(%d)", _socket_errno);
        SOCK_SENT_ERROR(socket);
        put_socket(socket);
        return -1;
    }
    SOCK_SENT_BYTES(socket, ret);
    vlogI("<<- socket <<-|: sended %d bytes(UDP)", ret);
    put_socket(socket);
    return ret;
}

struct p2psocket_helper_ops socket_helper_ops = {
    .create_passive_socket = _create_passive_socket,
    .destroy_passive_socket= _destroy_passive_socket,
    .postbind_socket       = _postbind_socket,
    .send_TCP_packet       = _send_TCP_packet,
    .send_UDP_packet       = _send_UDP_packet,
};

static
int _handle_TCP_connection(struct p2psocket* socket)
{
    assert(socket);
    assert(socket->rfd < 0);
    assert(socket->type == P2P_SOCK_STREAM);

    if (socket->tmp_fd < 0) {
        int ret = socket->tun->ops->bind(socket->tun, socket->domain, socket->type, socket->laddr_rport, socket->lfd);
        retE((ret < 0), -1);
        socket->tmp_fd = ret;
    }
    struct p2psocket* tmp = calloc(1, sizeof(*tmp));
    if (!tmp) {
        vlogE("calloc error");
        return -1;
    }

    int addrlen = sizeof(struct sockaddr_in);
    int fd = accept(socket->lfd, (struct sockaddr*)&tmp->raddr, &addrlen);
    if (fd < 0) {
        free(tmp);
        vlogE("accept error: %d", _socket_errno);
        return -1;
    }
    listen(socket->lfd, 1);
    _socket_set_nonblock(fd);

    tmp->domain = socket->domain;
    tmp->type   = socket->type;
    tmp->proto  = socket->proto;
    tmp->lfd    = fd;
    tmp->rfd    = socket->tmp_fd;
    tmp->tmp_fd = -1;
    tmp->count  = 1;
    tmp->rcvbuf = socket_rcvbuf;
    tmp->ops    = &socket_ops;
    tmp->cb_ops = &socket_cb_ops;
    tmp->tun    = socket->tun;
    ++tmp->tun->count;
    vlist_init(&tmp->list);
    tmp->shutdown_cb = _socket_shutdown;
    tmp->tun->ops->postbind(tmp->tun, tmp->lfd, tmp->rfd);

    vlogI("new p2psocket created: -->\n"\
          "    local  port:%d\n"\
          "    remote port:%d\n"\
          "    local  socket:%d\n"
          "    remote socket:%d\n",
          ntohs(tmp->laddr_port), \
          tmp->laddr_rport, \
          tmp->lfd, \
          tmp->rfd);

    push_socket(tmp);
    socket->tmp_fd = socket->tun->ops->bind(socket->tun, socket->domain, socket->type, socket->laddr_rport, socket->lfd);
    return tmp->lfd;
}

static
int _handle_TCP_packet(struct p2psocket* socket)
{
    assert(socket);
    assert(socket->rfd >= 0);
    assert(socket->tmp_fd < 0);
    assert(socket->type == P2P_SOCK_STREAM);

    int ret = socket->tun->ops->send_unfinished_TCP_packet(socket->tun);
    retE((ret < 0), -1);

    ret = recv(socket->lfd, socket->rcvbuf, SOCK_RECV_BUFSZ, MSG_NOSIGNAL);
    if (ret < 0) {
        vlogE("recv error(%d)", _socket_errno);
        SOCK_RECV_ERROR(socket);
        return -1;
    }

    SOCK_RECV_BYTES(socket, ret);
    vlogI("|->> socket ->>: received %d bytes(TCP)", ret);

    ret = socket->tun->ops->send_TCP_packet(socket->tun, socket->rcvbuf, ret, socket->rfd);
    retE((ret < 0), -1);
    return 0;
}

static
int _handle_UDP_packet(struct p2psocket* socket)
{
    assert(socket);
    assert(socket->rfd >= 0);
    assert(socket->tmp_fd < 0);
    assert(socket->type == P2P_SOCK_DGRAM);

    int addrlen = sizeof(struct sockaddr_in);
    int ret = recvfrom(socket->lfd, socket->rcvbuf, SOCK_RECV_BUFSZ, MSG_NOSIGNAL, (struct sockaddr*)&socket->raddr, &addrlen);
    if (ret < 0) {
        vlogE("recvfrom error(%d)", _socket_errno);
        SOCK_RECV_ERROR(socket);
        return -1;
    }
    SOCK_RECV_BYTES(socket, ret);
    vlogI("|->> socket ->>: received %d bytes(UDP)", ret);

    ret = socket->tun->ops->send_UDP_packet(socket->tun, socket->rcvbuf, ret, socket->rfd);
    retE((ret < 0), -1);
    return 0;
}

struct p2psocket_ops socket_ops = {
    .do_TCP_connection = _handle_TCP_connection,
    .do_TCP_packet     = _handle_TCP_packet,
    .do_UDP_packet     = _handle_UDP_packet,
};

static
void _handle_recv_event(struct p2psocket* socket)
{
    assert(socket);
    switch(socket->type) {
    case P2P_SOCK_STREAM:
        if (socket->rfd < 0) {
            socket->ops->do_TCP_connection(socket);
        } else {
            socket->ops->do_TCP_packet(socket);
        }
        break;
    case P2P_SOCK_DGRAM:
        if (socket->rfd >= 0) {
            socket->ops->do_UDP_packet(socket);
        }
        break;
    default:
        break;
    }
    return;
}

static
void _handle_errno_event(struct p2psocket* socket)
{
    assert(socket);
    //todo;
    return;
}

struct p2psocket_cb_ops socket_cb_ops = {
    .do_recv_event  = _handle_recv_event,
    .do_send_event  = NULL,
    .do_error_event = _handle_errno_event,
};

int make_sockaddr_p2pin(int domain, uint16_t lport, uint16_t rport, const uint8_t* key, struct sockaddr_p2pin* addr)
{
    retE((domain != P2P_AF_INET), -1);
    retE((!key), -1);
    retE((lport <= 0), -1);
    retE((rport <= 0), -1);
    retE((!addr), -1);

    memset(addr, 0, sizeof(*addr));
    addr->laddr.sin_family = domain;
    addr->laddr.sin_port   = htons(lport);
    addr->laddr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr->rport = rport;
    memcpy(addr->key, key, P2PSOCK_KEY_LEN);
    return 0;
}

void _socket_shutdown(struct p2psocket* socket)
{
    assert(socket);
    assert(vlist_is_empty(&socket->list)); //must be called pop_socket() before.

    if (socket->tun) {
        if (socket->rfd >= 0) {
            socket->tun->ops->unbind(socket->tun, socket->rfd);
            socket->rfd = -1;
        }
        if (socket->tmp_fd >= 0) {
            socket->tun->ops->unbind(socket->tun, socket->tmp_fd);
            socket->tmp_fd = -1;
        }
        put_tunnel(socket->tun);
        socket->tun = NULL;
    }
    close(socket->lfd);
    return;
}

int p2psocket_open(int domain, int type, struct sockaddr* addr, int addrlen)
{
    retE((domain != P2P_AF_INET), -1);
    retE((type != P2P_SOCK_DGRAM && type != P2P_SOCK_STREAM), -1);
    retE((!addr), -1);
    retE((sizeof(struct sockaddr_p2pin) != addrlen), -1);

    struct p2psocket* tmp = calloc(1, sizeof(*tmp));
    if (!tmp) {
        vlogE("calloc error");
        return -1;
    }
    int fd = socket(domain, type, 0);
    if (fd < 0) {
        vlogE("socket error(%d)", _socket_errno);
        free(tmp);
        return -1;
    }
    _socket_set_nonblock(fd);
    memcpy(&tmp->laddr.in, addr, sizeof(tmp->laddr.in));
    int ret = bind(fd, (struct sockaddr*)&tmp->laddr_addr, sizeof(tmp->laddr_addr));
    if (ret < 0) {
        vlogE("bind error(%d)", _socket_errno);
        close(fd);
        free(tmp);
        return -1;
    }
    tmp->tun = get_tunnel_by_key(tmp->laddr_key, create_tunnel, 1);
    if (!tmp->tun) {
        vlogE("tunnel not found");
        close(fd);
        free(tmp);
        return -1;
    }
    ret = tmp->tun->ops->bind(tmp->tun, domain, type, tmp->laddr_rport, fd);
    if (ret < 0) {
       vlogE("tunnel bind error");
       put_tunnel(tmp->tun);
       close(fd);
       free(tmp);
    }

    if(type == P2P_SOCK_STREAM) {
       listen(fd, 1);
    }

    tmp->domain = domain;
    tmp->type   = type;
    tmp->proto  = 0;
    tmp->count  = 1;
    tmp->lfd    = fd;
    tmp->rfd    = (type == P2P_SOCK_STREAM) ? -1 : ret;
    tmp->tmp_fd = (type == P2P_SOCK_STREAM) ? ret: -1 ;
    tmp->rcvbuf = socket_rcvbuf;
    tmp->ops    = &socket_ops;
    tmp->cb_ops = &socket_cb_ops;
    vlist_init(&tmp->list);
    tmp->shutdown_cb = _socket_shutdown;

    vlogI("p2psocket newly created:----\n"
          "    local  port:%d\n"\
          "    remote port:%d\n"\
          "    local  socket:%d\n"
          "    remote socket:%d\n",
          ntohs(tmp->laddr_port), \
          tmp->laddr_rport, \
          tmp->lfd, \
          tmp->rfd >= 0 ? tmp->rfd : tmp->tmp_fd);

    push_socket(tmp);
    return tmp->lfd;

error_exit:
    if (tmp->tun) put_tunnel(tmp->tun);
    if (fd)  close(fd);
    if (tmp) free(tmp);
    return -1;
}

int p2psocket_status(int sockfd, struct p2psocket_status* stat)
{
    retE((sockfd < 0), -1);
    retE((!stat), -1);

    struct p2psocket* socket = pop_socket(sockfd);
    if (!socket) {
        vlogE("p2psocket not found");
        return -1;
    }

    stat->recv_error = socket->stat.recv_error;
    stat->sent_error = socket->stat.sent_error;
    stat->recv_bytes = socket->stat.recv_bytes;
    stat->sent_bytes = socket->stat.sent_bytes;

    stat->type = socket->type;
    stat->lfd  = socket->lfd;
    stat->rfd  = socket->rfd;

    memcpy(&stat->laddr, &socket->laddr, sizeof(stat->laddr));
    memcpy(&stat->raddr, &socket->raddr, sizeof(stat->raddr));

    put_socket(socket);
    return 0;
}

int p2psocket_close(int sockfd)
{
    retE((sockfd < 0), -1);

    struct p2psocket* socket = pop_socket(sockfd);
    if (!socket) {
        vlogE("p2psocket not found");
        return -1;
    }
    put_socket(socket);
    return 0;
}

static int p2psocket_init_flag = 0;
int p2psocket_init(const char* data_path)
{
    if (!p2psocket_init_flag) {
#if defined(__WIN32__)
        WSADATA wsa_data = {0};
        int res = WSAStartup(MAKEWORD(2,2), &wsa_data);
        if (res != 0) {
            vlogE("WSAStartup error");
            return -1;
        }
#endif
        tuntox_start(data_path);
        laundry_start();
        p2psocket_init_flag = 1;
    }
    return 0;
}

void p2psocket_deinit(void)
{
    if (p2psocket_init_flag) {
        laundry_stop();
        tuntox_stop();
#if defined(__WIN32__)
        WSACleanup();
#endif
        p2psocket_init_flag = 0;
    }
    return;
}

