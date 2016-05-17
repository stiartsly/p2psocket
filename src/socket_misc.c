#include <assert.h>
#include "socket_misc.h"
#include "vlist.h"
#include "vsys.h"

static struct vlist VLIST_HEAD(socket_list);
static struct vlock lock = VLOCK_INITIALIZER;
static int socket_num = 0;

struct p2psocket* get_socket(int sockfd)
{
    struct p2psocket* socket = NULL;
    struct vlist* node = NULL;
    int found = 0;

    assert(sockfd >= 0);

    vlock_enter(&lock);
    __vlist_for_each(node, &socket_list) {
        socket = vlist_entry(node, struct p2psocket, list);
        if (socket->lfd == sockfd) {
            socket->count++;
            found = 1;
            break;
        }
    }
    vlock_leave(&lock);
    return (found ? socket: NULL);
}

struct p2psocket* pop_socket(int sockfd)
{
    struct p2psocket* socket = NULL;
    struct vlist* node = NULL;
    int found = 0;

    assert(sockfd >= 0);

    vlock_enter(&lock);
    __vlist_for_each(node, &socket_list) {
        socket = vlist_entry(node, struct p2psocket, list);
        if (socket->lfd == sockfd) {
            vlist_del(&socket->list);
            --socket_num;
            found = 1;
            break;
        }
    }
    vlock_leave(&lock);
    return (found ? socket: NULL);
}

void push_socket(struct p2psocket* socket)
{
    assert(socket);

    vlock_enter(&lock);
    vlist_add_tail(&socket_list, &socket->list);
    ++socket_num;
    vlock_leave(&lock);
}

void do_each_socket(void (*cb)(struct p2psocket*, void*), void* args)
{
    struct p2psocket* socket = NULL;
    struct vlist* node = NULL;
    assert(cb);

    vlock_enter(&lock);
    __vlist_for_each(node, &socket_list) {
        socket = vlist_entry(node, struct p2psocket, list);
        cb(socket, args);
    }
    vlock_leave(&lock);
    return;
}

void put_socket(struct p2psocket* socket)
{
    assert(socket);

    if (!--socket->count) {
        assert(vlist_is_empty(&socket->list));
        socket->shutdown_cb(socket);
        free(socket);
    }
    return;
}

