#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <time.h>
#include "vsys.h"
#include "ectox.h"
#include "ectoxInt.h"

#define retE(exp, err) if ((exp)) return err

ToxNode*   gNode   = NULL;
#if defined(__TOXAV__)
ToxAvNode* gAvNode = NULL;
#endif

void setToxCallbacks(Tox*, void*);

#if defined(__TOXAV__)
void setToxAvCallbacks(ToxAV*, void*);
#endif

static
void _auxBootstrapCb(const char* ip, uint16_t port, const uint8_t* key)
{
    if (!ip)  return;
    if (!key) return;

    Tox* tox = gNode ? gNode->tox : NULL;
    if (tox) {
        tox_bootstrap(tox, ip, port, key, NULL);
        tox_add_tcp_relay(tox, ip, port, key, NULL);
    }
    return;
}

static
int _auxThreadEntry(void* params)
{
    time_t  lastTimestamp = time(NULL);
    int32_t lastConnected = 0;
    int32_t status = 0;
    ToxNode* node = gNode;

    assert(node);
    assert(node->handler);
    assert(node->tox);

    while(!node->threadQuit) {
        status = tox_self_get_connection_status(node->tox);
        if (!lastConnected) {
            if (status) {
                printf("[DHT] Connected\n");
                lastConnected = 1;
                if (node->handler->onConnected) {
                    node->handler->onConnected(status, node->userData);
                }
            } else {
                time_t now = time(NULL);
                if (lastTimestamp + 10 < now) {
                    if (node->handler->onBootstrap) {
                        node->handler->onBootstrap(_auxBootstrapCb, node->userData);
                    }
                    lastTimestamp = now;
                }
            }
        } else {
            if (!status) {
                lastConnected = 0;
                printf("[DHT] Disconnected\n");
                if (node->handler->onDisconnected) {
                    node->handler->onDisconnected(node->userData);
                }
            }
        }
        tox_iterate(node->tox);
        vthread_sleep(200);
    }
    return 0;
}

int32_t ecNodeStart(ecNodeHandler* handler, void* userData)
{
    retE((!handler), -1);
    retE((gNode), -1);

    ToxNode* node = calloc(1, sizeof(*node));
    if (!node) {
        printf("[DHT] calloc failed\n");
        return -1;
    }

    uint8_t* data = NULL;
    int32_t  sz = 0;
    if (handler->getRoamingDataSize) {
        sz = handler->getRoamingDataSize(userData);
    }
    if (sz > 0 && handler->loadRoamingData) {
        data = calloc(1, sz);
        if (data) {
            handler->loadRoamingData(data, sz, userData);
        }
    }

    TOX_ERR_NEW err = 0;
    Tox* tox = NULL;
    if (data) {
        struct Tox_Options opt = {
            .proxy_type    = TOX_PROXY_TYPE_NONE,
            .ipv6_enabled  = 0,
            .udp_enabled   = 1,
            .savedata_type = TOX_SAVEDATA_TYPE_TOX_SAVE,
            .savedata_data = data,
            .savedata_length = sz
        };
        tox = tox_new(&opt, &err);
        free(data);
    } else {
        tox = tox_new(NULL, &err);
    }
    if (!tox) {
        printf("[DHT] Tox new error\n");
        free(node);
        return -1;
    }
    node->tox = tox;
    node->handler = handler;
    node->userData = userData;

    setToxCallbacks(tox, node);
    sz = tox_get_savedata_size(tox);
    if (sz > 0 && handler->saveRoamingData) {
        data = calloc(1, sz);
        if (data) {
            tox_get_savedata(tox, data);
            handler->saveRoamingData(data, sz, userData);
            free(data);
        }
    }
    if (handler->onBootstrap) {
        handler->onBootstrap(_auxBootstrapCb, userData);
    }

    node->threadQuit = 0;
    if (vthread_init(&node->thread, _auxThreadEntry, node) < 0) {
        tox_kill(tox);
        free(node);
        printf("[DHT] New thread failed\n");
        return -1;
    }
    vthread_start(&node->thread);

    gNode = node;
    return 0;
}

void ecNodeStop(void)
{
    ToxNode* node = gNode;
    if (!node) return;

    int sz = tox_get_savedata_size(node->tox);
    if (sz > 0 && node->handler->saveRoamingData) {
        void* data = calloc(1, sz);
        if (data) {
            node->handler->saveRoamingData(data, sz, node->userData);
            free(data);
        }
    }

    node->threadQuit = 1;
    vthread_join(&node->thread, NULL);
    tox_kill(node->tox);
    free(node);
    gNode = NULL;
    return;
}

int32_t ecGetSelfNodeId(uint8_t* nodeId, int length)
{
    retE((!nodeId), -1);
    retE((length < 38), -1);
    retE((!gNode), -1);

    tox_self_get_address(gNode->tox, nodeId);
    return 0;
}

static
void fraddr_to_str(uint8_t *id_bin, char *id_str)
{
#define FRADDR_TOSTR_CHUNK_LEN 8
    uint32_t i, delta = 0, pos_extra, sum_extra = 0;

    for (i = 0; i < TOX_ADDRESS_SIZE; i++) {
        sprintf(&id_str[2 * i + delta], "%02hhX", id_bin[i]);

        if ((i + 1) == TOX_PUBLIC_KEY_SIZE)
            pos_extra = 2 * (i + 1) + delta;

        if (i >= TOX_PUBLIC_KEY_SIZE)
            sum_extra |= id_bin[i];

        if (!((i + 1) % FRADDR_TOSTR_CHUNK_LEN)) {
            id_str[2 * (i + 1) + delta] = ' ';
            delta++;
        }
    }

    id_str[2 * i + delta] = 0;

    if (!sum_extra)
        id_str[pos_extra] = 0;
}

void ecDumpNodeId(void)
{
    char buf[200] = {0};
    int off = 0;

    uint8_t addr[ECNODE_ID_LEN];
    tox_self_get_address(gNode->tox, addr);
    off = sprintf(buf, "[ID]: ");
    fraddr_to_str(addr, buf + off);

    printf("%s", buf);
    printf("\n");
    return;
}

int32_t ecGetSelfConnectionStatus(void)
{
    //todo;
    return 0;
}

int32_t ecAddFriend(const uint8_t* nodeId, const uint8_t* verifyCode, int32_t length)
{
    retE((!nodeId), -1);
    retE((!verifyCode), -1);
    retE((length <= 0), -1);
    retE((!gNode), -1);

    TOX_ERR_FRIEND_ADD err;
    uint32_t fid = tox_friend_add(gNode->tox, nodeId, verifyCode, length, &err);
    if (fid == UINT32_MAX) {
        printf("[DHT] add friend error (err:%d)\n", err);
        return -1;
    }
    return (int32_t)fid;
}

int32_t ecDeleteFriend(int32_t friendId)
{
    retE((friendId <= 0), -1);
    retE((!gNode), -1);

    TOX_ERR_FRIEND_DELETE err;
    int32_t ret = tox_friend_delete(gNode->tox, (uint32_t)friendId, &err);
    if (!ret) {
        printf("[DHT] delete friend error (err:%d)\n", err);
        return -1;
    }
    return 0;
}

int32_t ecAcceptFriend(const uint8_t* nodeId)
{
    retE((!nodeId), -1);
    retE((!gNode), -1);

    TOX_ERR_FRIEND_ADD e1 = 0;
    uint32_t fid = tox_friend_add_norequest(gNode->tox, nodeId, &e1);
    if (fid == UINT32_MAX) {
        printf("[DHT] accept friend error (err:%d)\n",e1);
        return -1;
    }
    printf("[DHT] accept friend Id:%u\n", fid);

#if 0
    Sleep(5*1000);
    TOX_ERR_FRIEND_SEND_MESSAGE e2 = 0;
    uint32_t ret = tox_friend_send_message(gNode->tox, fid, TOX_MESSAGE_TYPE_NORMAL,
                                          "accept", sizeof("accept"),
                                          &e2);
    if (!ret) {
        printf("[DHT] send accept message error (err:%d)\n", e2);
        tox_friend_delete(gNode->tox, fid, NULL);
        return -1;
    }
#endif
    return (int32_t)fid;
}

int32_t ecMessageFriend(int32_t friendId, const uint8_t* message, int32_t length)
{
    retE((friendId < 0), -1);
    retE((!message), -1);
    retE((length <= 0), -1);
    retE((!gNode), -1);

    TOX_ERR_FRIEND_SEND_MESSAGE err = 0;
    uint32_t ret = tox_friend_send_message(gNode->tox, friendId, TOX_MESSAGE_TYPE_NORMAL, message, length, &err);
    if (ret == 0) {
        printf("[DHT] send message error (err:%d)\n", err);
        return -err;
    }
    return 0;
}

int32_t ecSendLossyPacket(int32_t friendId, const uint8_t* packet, int32_t length)
{
    retE((friendId < 0), -1);
    retE((!packet), -1);
    retE((length <= 0), -1);
    retE((!gNode), -1);

    TOX_ERR_FRIEND_CUSTOM_PACKET err = 0;
    bool ret = tox_friend_send_lossy_packet(gNode->tox, friendId, packet, length, &err);
    if (!ret) {
        printf("[DHT] send lossy packet error (err:%d)\n", err);
        return -1;
    }
    return 0;
}

int32_t ecSendLosslessPacket(int32_t friendId, const uint8_t* packet, int32_t length)
{
    retE((friendId < 0), -1);
    retE((!packet), -1);
    retE((length <= 0), -1);
    retE((!gNode), -1);

    TOX_ERR_FRIEND_CUSTOM_PACKET err = 0;
    bool ret = tox_friend_send_lossless_packet(gNode->tox, friendId, packet, length, &err);
    if (!ret) {
        printf("[DHT] send lossy packet error (err:%d)\n", err);
        return -1;
    }
    return 0;
}

#if defined(__TOXAV__)
static
int32_t _auxAvThreadEntry(void* params)
{
    ToxAvNode* avNode = (ToxAvNode*)params;
    assert(avNode);
    assert(avNode->handler);
    assert(avNode->av);

    while(!avNode->threadQuit) {
        toxav_iterate(avNode->av);

        ToxAvMsg* msg = &avNode->msg;
        switch(msg->msgId) {
        case msgFriendRequestCall:
            printf("Avcb::friendCallRequest\n");
            if (avNode->handler && avNode->handler->onCallRequest) {
                avNode->handler->onCallRequest(msg->friendId, msg->audio, msg->video, msg->cookie);
            }
            msg->msgId = 0;
            break;
        case msgFriendCallStateChanged:
            printf("Avcb::freindCallStateChanged\n");
            if (avNode->handler && avNode->handler->onCallStateChanged) {
                avNode->handler->onCallStateChanged(msg->friendId, msg->status, msg->cookie);
            }
            msg->msgId = 0;
            break;
        default:
            //printf("Avcb::default\n");
            break;
        }
        vthread_sleep(toxav_iteration_interval(avNode->av));
    }
    return 0;
}

int32_t ecNodeStartAv(ecNodeAvHandler* handler, void* userData)
{
    ToxNode* node = gNode;

    retE((!handler), -1);
    retE((!node), -1);
    retE((gAvNode), -1);

    ToxAvNode* avNode = calloc(1, sizeof(*avNode));
    if (!avNode) {
        printf("[DHT] ToxAvNode calloc failed\n");
        return -1;
    }

    TOXAV_ERR_NEW err = 0;
    ToxAV* av = toxav_new(node->tox, &err);
    if (!av) {
        printf("[DHT] New toxav error\n");
        return -1;
    }

    avNode->av = av;
    avNode->handler = handler;
    avNode->userData = userData;
    setToxAvCallbacks(av, avNode);

    int32_t ret = vthread_init(&avNode->thread, _auxAvThreadEntry, avNode);
    if (ret < 0) {
        printf("[DHT] New Av thread error");
        toxav_kill(av);
        free(avNode);
        return -1;
    }
    vthread_start(&avNode->thread);

    gAvNode = avNode;
    return 0;
}

void ecNodeStopAv(void)
{
    ToxAvNode* avNode = gAvNode;

    if (!avNode) return;

    avNode->threadQuit = 1;
    vthread_join(&avNode->thread, NULL);
    toxav_kill(avNode->av);
    free(avNode);
    gAvNode = NULL;

    return;
}

int32_t ecCallFriend(int32_t friendId, int32_t audioBitRate,int32_t videoBitRate)
{
    retE((friendId < 0), -1);
    retE((!gNode), -1);
    retE((!gAvNode), -1);

    TOXAV_ERR_CALL err = 0;
    int32_t ret = toxav_call(gAvNode->av, friendId, audioBitRate, videoBitRate, &err);
    if (ret < 0) {
        printf("[DHT] tox call friend error (err:%d)\n", err);
        return -1;
    }
    return 0;
}

int32_t ecCallAnswer(int32_t friendId, int32_t audioRate, int32_t videoRate)
{
    retE((friendId < 0), -1);
    retE((!gNode), -1);
    retE((!gAvNode), -1);

    TOXAV_ERR_ANSWER err = 0;
    int32_t ret = toxav_answer(gAvNode->av, friendId, audioRate, videoRate, &err);
    if (ret < 0) {
        printf("[DHT] tox call answer error (err:%d)\n", err);
        return -1;
    }
    return 0;
}

int32_t ecSendVideoFrame(int32_t friendId, const uint8_t* y, const uint8_t* u, const uint8_t* v, int32_t width, int32_t height)
{
    retE((friendId < 0), -1);
    retE((!y), -1);
    retE((!u), -1);
    retE((!v), -1);
    retE((width <= 0), -1);
    retE((height <= 0), -1);
    retE((!gNode), -1);
    retE((!gAvNode), -1);

    TOXAV_ERR_SEND_FRAME err = 0;
    bool ret = toxav_video_send_frame(gAvNode->av, friendId, width, height, y, u, v, &err);
    if (!ret) {
        printf("[DHT] send video Frame error (err:%d)\n", err);
        return -1;
    }
    return 0;
}
#endif

