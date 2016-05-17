#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include "ectox.h"
#include "ectoxInt.h"

static
void _friendReqCb(Tox* tox, const uint8_t* id, const uint8_t* msg, size_t length, void* userData)
{
    assert(tox);
    assert(id);
    assert(msg);
    assert(length >= 0);
    assert(userData);

    ToxNode* node = (ToxNode*)userData;
    if (node->handler && node->handler->onFriendAddRequest) {
        node->handler->onFriendAddRequest(id, msg, length, node->userData);
    }
    return;
}

static
void _friendMsgCb(Tox* tox, uint32_t fid, TOX_MESSAGE_TYPE type, const uint8_t* msg, size_t length, void* userData)
{
    assert(tox);
    assert(fid != UINT32_MAX);
    assert(msg);
    assert(length > 0);
    assert(userData);

    ToxNode* node = (ToxNode*)userData;
    if (node->handler && node->handler->onFriendMessage) {
        node->handler->onFriendMessage(fid, msg, length, node->userData);
    }
    return;
}

static
void _friendNameCb(Tox* tox, uint32_t fid, const uint8_t* newName, size_t length, void* userData)
{
    printf("[DHT] received a name message.\n");
    //todo;
    return ;
}

static
void _friendStatusCb(Tox* tox, uint32_t fid, const uint8_t* newStatus, size_t length, void* userData)
{
    printf("[DHT] received a status message.\n");
    //todo;
    return;
}

static
void _friendUserStatusCb(Tox* tox, uint32_t fid, TOX_USER_STATUS status, void* userData)
{
    printf("[DHT] received a user status message.\n");
    //todo;
    return;
}

static
void _friendTypingCb(Tox* tox, uint32_t fid, _Bool is_typing, void* userData)
{
    //printf("[DHT] received a typing message.\n");
    //todo;
    return ;
}

static
void _friendReadReceiptCb(Tox* tox, uint32_t fid, uint32_t receipt, void* userData)
{
    //printf("[DHT] received a read recept message.\n");
    //todo;
    return;
}

static
void _friendConnectionCb(Tox* tox, uint32_t fid, TOX_CONNECTION status, void* userData)
{
     printf("[DHT] received a connection message.\n");

     ToxNode* node = (ToxNode*)userData;

     if (node->handler && node->handler->onFriendConnected) {
         node->handler->onFriendConnected(fid, node->userData);
     }
     return;
}

static
void _friendLossyPacketCb(Tox* tox, uint32_t fid, const uint8_t* data, size_t length, void* userData)
{
    assert(tox);
    assert(fid != UINT32_MAX);
    assert(data);
    assert(length > 0);
    assert(userData);

    ToxNode* node = (ToxNode*)userData;
    if (node->handler && node->handler->onLossyPacketReceived) {
        node->handler->onLossyPacketReceived(fid, data, length, node->userData);
    }
    return;
}

static
void _friendLosslessPacketCb(Tox* tox, uint32_t fid, const uint8_t* data, size_t length, void* userData)
{
    assert(tox);
    assert(fid != UINT32_MAX);
    assert(data);
    assert(length > 0);
    assert(userData);

    ToxNode* node = (ToxNode*)userData;
    if (node->handler && node->handler->onLosslessPacketReceived) {
        node->handler->onLosslessPacketReceived(fid, data, length, node->userData);
    }
    return;
}

void setToxCallbacks(Tox* tox, void* userData)
{
    tox_callback_friend_request(tox, _friendReqCb,  userData);
    tox_callback_friend_message(tox, _friendMsgCb,  userData);
    tox_callback_friend_name   (tox, _friendNameCb, userData);
    tox_callback_friend_status_message(tox, _friendStatusCb, userData);
    tox_callback_friend_status (tox, _friendUserStatusCb, userData);
    tox_callback_friend_typing (tox, _friendTypingCb,     userData);
    tox_callback_friend_read_receipt(tox, _friendReadReceiptCb, userData);
    tox_callback_friend_connection_status(tox, _friendConnectionCb, userData);
    tox_callback_friend_lossy_packet(tox, _friendLossyPacketCb, userData);
    tox_callback_friend_lossless_packet(tox, _friendLosslessPacketCb, userData);

    return;
}

#if defined(__TOXAV__)
static
void _friendCallStateChangeCb(ToxAV *av, uint32_t fid, uint32_t state, void *userData)
{
    printf("[DHT] received a call state change (state:%d)\n", state);

    ToxAvNode* avNode = (ToxAvNode*)userData;
    ToxAvMsg*  msg    = &avNode->msg;

    msg->msgId = msgFriendCallStateChanged;
    msg->friendId = fid;
    msg->status = state;
    msg->cookie = avNode->userData;
    return;
}

static
void _friendCallRequestCb(ToxAV* av, uint32_t fid, bool audio, bool video, void* userData)
{
    printf("[DHT] received a call request\n");

    ToxAvNode* avNode = (ToxAvNode*)userData;
    ToxAvMsg* msg = &avNode->msg;

    msg->msgId = msgFriendRequestCall;
    msg->friendId = fid;
    msg->audio = audio;
    msg->video = video;
    msg->cookie = avNode->userData;
    return;
}

static
void _friendAudioFrameReceivedCb(ToxAV *av, uint32_t friend_number, const int16_t *pcm, size_t sample_count,
                                    uint8_t channels, uint32_t sample_rate, void *userdata)
{
    printf("[DHT] received a audio frame\n");

    //todo;
    return;
}

static
void _friendVideoFrameReceivedCb(ToxAV *toxAV, uint32_t fid, uint16_t width, uint16_t height,
                                        const uint8_t *y, const uint8_t *u, const uint8_t *v,
                                        int32_t ystride, int32_t ustride, int32_t vstride, void *user_data)
{
    printf("[DHT] received a video frame\n");

    ToxAvNode* avNode = (ToxAvNode*)user_data;
    if (avNode->handler && avNode->handler->onVideoFrameReceived) {
        avNode->handler->onVideoFrameReceived(fid,width, height, y, u, v, ystride, ustride, vstride, avNode->userData);
    }
    return;
}

static
void _friendAvRateChangeCb(ToxAV *AV, uint32_t f_num, uint32_t a_bitrate, uint32_t v_bitrate, void *ud)
{
    printf("[DHT] Av rate change\n");
    //todo;

    return;
}

void setToxAvCallbacks(ToxAV* av, void* userData)
{
    toxav_callback_call(av, _friendCallRequestCb, userData);
    toxav_callback_call_state(av, _friendCallStateChangeCb, userData);
    toxav_callback_audio_receive_frame(av, _friendAudioFrameReceivedCb, userData);
    toxav_callback_video_receive_frame(av, _friendVideoFrameReceivedCb, userData);
    toxav_callback_bit_rate_status(av, _friendAvRateChangeCb, userData);

    return;
}
#endif

