#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "ectox.h"
#include "tunnel.h"
#include "tunnel_misc.h"
#include "tunnel_bootstrap.h"
#include "vlog.h"

struct tunnel_ctxt {
    char path[256];

    struct bootstrap_node* bootstrap_nodes;
    int bootstrap_node_num;
};

static
int32_t _tox_get_data_size(void* ctxt)
{
    assert(ctxt);

    struct tunnel_ctxt* tc = (struct tunnel_ctxt*)ctxt;
    FILE* fp = fopen(tc->path, "rb");
    if(!fp) {
        vlogE("data file (%s) not found", tc->path);
        return -1;
    }
    fseek(fp, 0, SEEK_END);
    int sz = ftell(fp);
    fclose(fp);

    return sz;
}

static
void _tox_load_data(uint8_t* data, int32_t length, void* ctxt)
{
    assert(data);
    assert(length > 0);
    assert(ctxt);

    struct tunnel_ctxt* tc = (struct tunnel_ctxt*)ctxt;
    FILE* fp = fopen(tc->path, "rb");
    if (!fp) {
        vlogE("data file (%s) not found", tc->path);
        return;
    }
    fseek(fp, 0, SEEK_END);
    int sz = ftell(fp);
    if (sz > length) {
        sz = length;
    }
    fseek(fp, 0, SEEK_SET);
    int ret = fread(data, sz, 1, fp);
    fclose(fp);
    if (ret != 1) {
        vlogE("read data file error");
        return;
    }
    return;
}

static
void _tox_save_data(const uint8_t* data, int32_t length, void* ctxt)
{
    assert(data);
    assert(length > 0);
    assert(ctxt);

    struct tunnel_ctxt* tc = (struct tunnel_ctxt*)ctxt;
    FILE* fp = NULL;
    fp = fopen(tc->path, "wb");
    if (!fp) {
        vlogE("File open failed (%s)", tc->path);
        return;
    }

    int sz = fwrite(data, length, 1, fp);
    if (sz != 1) {
        vlogE("File write failed");
        fclose(fp);
        return;
    }
    fflush(fp);
    fclose(fp);
    return;
}

static
void _tox_bootstrap(bootstrap_t cb, void* ctxt)
{
    assert(cb);
    assert(ctxt);

    struct tunnel_ctxt* tc = (struct tunnel_ctxt*)ctxt;
    static int j = 0;
    if (j == 0) {
        j = rand();
    }

    int tries = 0;
    while(tries < 4) {
        struct bootstrap_node* node = &tc->bootstrap_nodes[j % tc->bootstrap_node_num];
        cb(node->address, node->port, node->key);
        j++;
        tries++;
    }
    return;
}

static
void _tox_on_connected(int status, void* ctxt)
{
    assert(ctxt);
    vlogI("DHT went online");
    return;
}

static
void _tox_on_disconnected(void* ctxt)
{
    assert(ctxt);
    vlogI("DHT went offline");
    return;
}

static
void _tox_on_friend_add_request(const uint8_t* nodeid, const uint8_t* code, int32_t len, void* ctxt)
{
    assert(nodeid);
    assert(code);
    assert(len > 0);

    char verifycode[] = "123456";
    if (len != strlen(verifycode) || memcmp(verifycode, code, len)) {
        vlogE("unauthorized friend add request");
        return;
    }

    vlogI("the friend add request is verified");
    struct p2ptunnel* tun = get_tunnel_by_key(nodeid, create_tunnel, 0);
    if (!tun) {
        vlogE("create new tunnel error");
        return;
    }
    vlogI("the newly friend tunnel established");
    put_tunnel(tun);
    return;
}

static
void _tox_on_friend_connected(int fid, void* ctxt)
{
    assert(fid >= 0);

    vlogI("DHT friendid (%d) connected", fid);
    return;
}

static
void _tox_on_friend_disconnected(int fid, void* ctxt)
{
    assert(fid >= 0);

    vlogI("DHT friendid (%d) disconnected", fid);
    return;
}

static
void _tox_on_friend_deleted(int fid, void* ctxt)
{
    vlogI("friend (fid:%d) deleted", fid);
    //todo;
    return;
}

static
void _tox_on_friend_message(int fid, const uint8_t* data, int sz, void* ctxt)
{
    assert(fid >= 0);
    assert(data);
    assert(sz > 0);

    struct p2ptunnel* tun = get_tunnel(fid);
    if (!tun) {
        vlogE("tunnel not found");
        return;
    }

    switch(data[0]) {
    case P2PTUNNEL_BIND_REQ:
        tun->cb_ops->handle_bind_req_msg(tun, data, sz);
        break;
    case P2PTUNNEL_BIND_RSP:
        tun->cb_ops->handle_bind_rsp_msg(tun, data, sz);
        break;
    case P2PTUNNEL_POSTBIND:
        tun->cb_ops->handle_postbind_msg(tun, data, sz);
        break;
    case P2PTUNNEL_UNBIND:
        tun->cb_ops->handle_unbind_msg(tun, data, sz);
        break;
    default:
        vlogE("unsupported message");
        break;
    }
    put_tunnel(tun);
    return;
}

static
void _tox_on_lossypacket_received(int fid, const uint8_t* data, int sz, void* ctxt)
{
    assert(fid >= 0);
    assert(data);
    assert(sz > 0);

    if (data[0] != 200) {
        vlogE("vicious packet!! discarded");
        return;
    }

    struct p2ptunnel* tun = get_tunnel(fid);
    if (!tun) {
        vlogE("tunnel not found");
        return;
    }
    tun->cb_ops->handle_UDP_packet(tun, data, sz);
    put_tunnel(tun);
    return;
}

static
void _tox_on_lossesspacket_received(int fid, const uint8_t* data, int sz, void* ctxt)
{
    assert(fid >= 0);
    assert(data);
    assert(sz > 0);

    if (data[0] != 160) {
        vlogE("vicious packet!! discarded");
        return;
    }

    struct p2ptunnel* tun = get_tunnel(fid);
    if (!tun) {
        vlogE("tunnel not found");
        return;
    }
    if (data[0] == 160) {
        tun->cb_ops->handle_TCP_packet(tun, data, sz);
    }
    put_tunnel(tun);
    return;
}

static
ecNodeHandler tunnel_handler = {
    .getRoamingDataSize       = _tox_get_data_size,
    .loadRoamingData          = _tox_load_data,
    .saveRoamingData          = _tox_save_data,
    .onBootstrap              = _tox_bootstrap,
    .onConnected              = _tox_on_connected,
    .onDisconnected           = _tox_on_disconnected,
    .onFriendAddRequest       = _tox_on_friend_add_request,
    .onFriendConnected        = _tox_on_friend_connected,
    .onFriendDisconnected     = _tox_on_friend_disconnected,
    .onFriendDeleted          = _tox_on_friend_deleted,
    .onFriendMessage          = _tox_on_friend_message,
    .onLossyPacketReceived    = _tox_on_lossypacket_received,
    .onLosslessPacketReceived = _tox_on_lossesspacket_received,
};

int tuntox_start(const char* data_path)
{
    if (!data_path) {
        return -1;
    }

    static struct tunnel_ctxt ctxt = {0};
    strcpy(ctxt.path, data_path);
    ctxt.bootstrap_nodes = bootstrap_nodes;
    ctxt.bootstrap_node_num = sizeof(bootstrap_nodes) / sizeof(struct bootstrap_node);

    int ret = ecNodeStart(&tunnel_handler, &ctxt);
    if (ret < 0) {
        vlogE("ecNodeStart error");
        return -1;
    }
    vlogI("tox started");
    ecDumpNodeId();
    return 0;
}

void tuntox_stop(void)
{
    ecNodeStop();
    return;
}

