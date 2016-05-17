#pragma once

#include <stdint.h>
#if defined(__WIN32__)
#include <winsock2.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#define P2PSOCK_KEY_LEN (32 + sizeof(uint32_t) + sizeof(uint16_t))

struct sockaddr_p2pin {
    struct sockaddr_in laddr;
    uint8_t key[P2PSOCK_KEY_LEN];
    uint16_t rport;
    uint8_t pad[2];
} __attribute__(packed);

struct p2psocket_status {
    int32_t recv_error;
    int32_t sent_error;
    int64_t recv_bytes;
    int64_t sent_bytes;

    int domain;
    int type;
    int lfd;
    int rfd;

    union {
        struct sockaddr_p2pin in;
    } laddr;
    union {
        struct sockaddr_in in;
    } raddr;
};

enum {
    P2P_AF_INET  = 2,
};

enum {
    P2P_SOCK_STREAM = 1,
    P2P_SOCK_DGRAM  = 2,
    P2P_SOCK_BUTT,
};

/**
 * @brief Make an sockaddr_p2pin
 *
 * @brief A device may use this function to make an p2psocket address.
 *
 * @param
 *     key              [in] The key of dest DHT mode.
 * @param
 *     lport            [in] local port to bind;
 * @param
 *     rport            [in] remote port to forward;
 * @param
 *     addr             [out] local p2pin sort address.
 *
 * @return
 *
 */
int make_sockaddr_p2pin(int domain, uint16_t lport, uint16_t rport, const uint8_t* key, struct sockaddr_p2pin* addr);

/*
 *  open an endpoint of forwarding on p2p communication;
 *
 */
int p2psocket_open(int domain, int type, struct sockaddr* addr, int addrlen);

/*
 * get status of p2psocket
 */
int p2psocket_status(int sockfd, struct p2psocket_status* stat);

/*
 *  close the forwarding socket.
 */
int p2psocket_close(int sockfd);


/*
 *  initialize the p2p forwarding.
 *
 */
int p2psocket_init(const char* data_path);

/*
 *  deintialize p2p forwarding
 *
 */
void p2psocket_deinit(void);


