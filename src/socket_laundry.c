#include <assert.h>
#if defined(__WIN32__)
#else
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#endif
#include "socket_misc.h"
#include "vsys.h"
#include "vlog.h"

static struct vthread laundry_thread = {0};
static int stop_flag = 0;

static
void _laundry_prepare_cb(struct p2psocket* socket, void* args)
{
    fd_set* rfds = (fd_set*)((void**)args)[0];
    fd_set* efds = (fd_set*)((void**)args)[1];
    int* maxfd   = (int*)   ((void**)args)[2];

    FD_SET(socket->lfd, efds);
    FD_SET(socket->lfd, rfds);

    if (*maxfd < socket->lfd) {
        *maxfd = socket->lfd;
    }
    return;
}

static
void _laundry_work_cb(struct p2psocket* socket, void* args)
{
    fd_set* rfds = (fd_set*)((void**)args)[0];
    fd_set* efds = (fd_set*)((void**)args)[1];

    if (FD_ISSET(socket->lfd, rfds) && socket->cb_ops->do_recv_event) {
        socket->cb_ops->do_recv_event(socket);
    }
    if (FD_ISSET(socket->lfd, efds) && socket->cb_ops->do_error_event) {
        socket->cb_ops->do_error_event(socket);
    }
    return ;
}

static
int _laundry_routine(void* params)
{
    while(!stop_flag) {
        fd_set rfds;
        fd_set wfds;
        fd_set efds;
        int maxfd = -1;

        FD_ZERO(&rfds);
        FD_ZERO(&efds);
        FD_ZERO(&wfds);

        void* args[] = {
            &rfds,
            &efds,
            &maxfd
        };

        do_each_socket(_laundry_prepare_cb, args);

        if (maxfd < 0) {
            vthread_sleep(500);
            continue;
        } else {
            struct timeval tv = {0, 500*1000};
            int ret = select(maxfd + 1, &rfds, &wfds, &efds, &tv);
            if (ret < 0) {
                vlogE("select error(%d)", _socket_errno);
                break;
            } else if (ret == 0) { //timeout;
                continue;
            } else {
                //DO NOTHING.
            }
        }
        do_each_socket(_laundry_work_cb, args);
    }
    return 0;
}

int laundry_start(void)
{
    stop_flag = 0;
    int ret = vthread_init(&laundry_thread, _laundry_routine, NULL);
    if (ret < 0) {
        vlogE("vthread init error");
        return -1;
    }
    vthread_detach(&laundry_thread);
    vthread_start(&laundry_thread);
    return 0;
}

void laundry_stop(void)
{
    stop_flag = 1;
    vthread_join(&laundry_thread, NULL);
    stop_flag = 0;

    return;
}

