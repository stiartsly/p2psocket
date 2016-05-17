#pragma once

#include <stdint.h>

enum {
    ecNodeConnectionNone = ((int32_t)0x0),
    ecNodeConnectionTcp  = ((int32_t)0x01),
    ecNodeConnectionUdp  = ((int32_t)0x02)
};

#define ECNODE_ID_LEN  (32 + sizeof(uint32_t) + sizeof(uint16_t))

typedef void (*bootstrap_t)(const char*, uint16_t, const uint8_t*);
struct ecNodeHandler {
    int32_t (*getRoamingDataSize)   (void*);
    void (*loadRoamingData)         (uint8_t* data, int32_t size, void*);
    void (*saveRoamingData)         (const uint8_t* data, int32_t size, void*);

    void (*onBootstrap)             (bootstrap_t cb, void*);
    void (*onConnected)             (int32_t status, void*);
    void (*onDisconnected)          (void*);

    void (*onFriendAddRequest)      (const uint8_t* peerNodeId, const uint8_t* verifyCode, int32_t length, void*);
    void (*onFriendConnected)       (int32_t friendId, void*);
    void (*onFriendDisconnected)    (int32_t friendId, void*);
    void (*onFriendDeleted)         (int32_t friendId, void*);
    void (*onFriendMessage)         (int32_t friendId, const uint8_t*, int32_t, void*);

    void (*onLossyPacketReceived)   (int32_t friendId, const uint8_t* data, int32_t length, void*);
    void (*onLosslessPacketReceived)(int32_t friendId, const uint8_t* data, int32_t length, void*);
};
typedef struct ecNodeHandler ecNodeHandler;

int32_t ecNodeStart(ecNodeHandler* handler, void*);
void    ecNodeStop(void);

int32_t ecGetSelfConnectionStatus(void);
int32_t ecGetSelfNodeId(uint8_t* nodeId, int length);
void    ecDumpNodeId(void);

int32_t ecAddFriend(const uint8_t* peerId, const uint8_t* credential, int32_t length);
int32_t ecDeleteFriend(int32_t friendId);
int32_t ecAcceptFriend(const uint8_t* peerId);

int32_t ecMessageFriend(int32_t friendId, const uint8_t*, int32_t);

int32_t ecSendLossyPacket   (int32_t friendId, const uint8_t* packet, int32_t length);
int32_t ecSendLosslessPacket(int32_t friendId, const uint8_t* packet, int32_t length);

#if defined(__TOXAV__)

struct ecNodeAvHandler {
    void (*onCallRequest)       (int32_t, int32_t, int32_t, void*);
    void (*onCallStateChanged)  (int32_t, uint32_t, void*);
    void (*onAudioFrameReceived)(int32_t, const int16_t*, int32_t, int32_t, int32_t, void*);
    void (*onVideoFrameReceived)(int32_t, int32_t, int32_t, const uint8_t*, const uint8_t*, const uint8_t*, int32_t, int32_t, int32_t, void*);
};
typedef struct ecNodeAvHandler ecNodeAvHandler;

int32_t ecNodeStartAv(ecNodeAvHandler* handler, void*);
void    ecNodeStopAv(void);
int32_t ecSendVideoFrame(int32_t, const uint8_t*, const uint8_t*, const uint8_t*, int32_t, int32_t);
int32_t ecCallFriend(int32_t, int32_t,int32_t);
int32_t ecCallAnswer(int32_t, int32_t,int32_t);
#endif

