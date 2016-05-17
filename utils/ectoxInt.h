#pragma once

#include <stdint.h>
#include "tox/tox.h"
#if defined(__TOXAV__)
#include "tox/toxav.h"
#endif
#include "ectox.h"
#include "vsys.h"

#if defined(__TOXAV__)
enum {
    msgFriendRequestCall = (int32_t)0x01,
    msgFriendCallStateChanged,
    msgFriendAudioFrame,
    msgFriendVideoFrame,

};

struct ToxAvMsg {
    uint32_t friendId;
    int32_t msgId;
    int32_t audio;
    int32_t video;
    void* data;
    int32_t length;
    uint32_t status;
    void* cookie;
};
typedef struct ToxAvMsg ToxAvMsg;
#endif

struct ToxNode {
    Tox* tox;

    ecNodeHandler* handler;
    void* userData;

    struct vthread thread;
    int32_t threadQuit;    
};

#if defined(__TOXAV__)
struct ToxAvNode {
    ToxAV* av;

    ecNodeAvHandler* handler;
    void* userData;

    struct vthread thread;
    int32_t threadQuit;

    ToxAvMsg msg;
};
#endif

typedef struct ToxNode   ToxNode;

#if defined(__TOXAV__)
typedef struct ToxAvNode ToxAvNode;
#endif

