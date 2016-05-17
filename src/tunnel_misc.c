#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "tunnel.h"
#include "tunnel_misc.h"
#include "vlist.h"
#include "vsys.h"
#include "vlog.h"

static struct vlist VLIST_HEAD(tunnel_list);
static struct vlock lock = VLOCK_INITIALIZER;
static int tunnel_num = 0;

struct p2ptunnel* get_tunnel(int friendid)
{
    assert(friendid >= 0);

    struct p2ptunnel* tun = NULL;
    struct vlist* node = NULL;
    int found = 0;

    vlock_enter(&lock);
    __vlist_for_each(node, &tunnel_list) {
        tun = vlist_entry(node, struct p2ptunnel, list);
        if (tun->friendid == friendid) {
            tun->count++;
            found = 1;
            break;
        }
    }
    vlock_leave(&lock);
    return (found ? tun : NULL);
}

void put_tunnel(struct p2ptunnel* tun)
{
    assert(tun);

    vlock_enter(&lock);
    if (!--tun->count) {
       assert(0);
       vlogE("orphan tunnel !!!!");
       //todo;
    }
    vlock_leave(&lock);
    return ;
}

struct p2ptunnel* pop_tunnel(int friendid)
{
    assert(friendid >= 0);

    struct p2ptunnel* tun = NULL;
    struct vlist* node = NULL;
    int found = 0;

    vlock_enter(&lock);
    __vlist_for_each(node, &tunnel_list) {
        tun = vlist_entry(node, struct p2ptunnel, list);
        if (tun->friendid == friendid) {
            vlist_del(&tun->list);
            --tunnel_num;
            found = 1;
            break;
        }
    }
    vlock_leave(&lock);
    return (found ? tun : NULL);
}

void push_tunnel(struct p2ptunnel* tun)
{
    assert(tun);

    vlock_enter(&lock);
    vlist_add_tail(&tunnel_list, &tun->list);
    ++tunnel_num;
    vlock_leave(&lock);
    return;
}

struct p2ptunnel* get_tunnel_by_key(const uint8_t* key, create_tunnel_cb_t create_cb, int active_flag)
{
    struct p2ptunnel* tun = NULL;
    struct vlist* node = NULL;
    int found = 0;

    vlock_enter(&lock);
    __vlist_for_each(node, &tunnel_list) {
        tun = vlist_entry(node, struct p2ptunnel, list);
        if (!memcmp(tun->key, key, P2PSOCK_KEY_LEN)) {
           tun->count++;
           found = 1;
           break;
        }
    }
    if (!found) {
        tun = create_cb(key, active_flag);
        if (!tun) {
            vlock_leave(&lock);
            return NULL;
        }
        tun->count++;
        vlist_add_tail(&tunnel_list, &tun->list);
        ++tunnel_num;
    }
    vlock_leave(&lock);
    return tun;
}

