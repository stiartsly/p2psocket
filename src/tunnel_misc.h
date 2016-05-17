#pragma once

#include "tunnel.h"

struct bootstrap_node {
    char* address;
    uint16_t port;
    uint8_t key[32];
};

struct p2ptunnel* get_tunnel(int);
struct p2ptunnel* pop_tunnel(int);
void put_tunnel (struct p2ptunnel*);
void push_tunnel(struct p2ptunnel*);

typedef struct p2ptunnel* (*create_tunnel_cb_t)(const uint8_t*, int);
struct p2ptunnel* get_tunnel_by_key(const uint8_t* key, create_tunnel_cb_t cb, int active_flag);

int  tuntox_start(const char* path);
void tuntox_stop (void);

