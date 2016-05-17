#include <string.h>
#include <assert.h>
#include "vsys.h"
#if defined(__WIN32__)
#include <pthread.h>
#include <Windows.h>
#else
#include <pthread.h>
#include <sys/time.h>
#include <unistd.h>
#endif

/*
 * for pthread mutex
 */
int vlock_init(struct vlock* lock)
{
    assert(lock);
    pthread_mutexattr_init(&lock->attr);
    pthread_mutexattr_settype(&lock->attr, PTHREAD_MUTEX_RECURSIVE_NP);
    return pthread_mutex_init(&lock->mutex, &lock->attr);
}

int vlock_enter(struct vlock* lock)
{
    assert(lock);
    return pthread_mutex_lock(&lock->mutex);
}

int vlock_leave(struct vlock* lock)
{
    assert(lock);
    return pthread_mutex_unlock(&lock->mutex);
}

void vlock_deinit(struct vlock* lock)
{
    assert(lock);
    pthread_mutex_destroy(&lock->mutex);
    pthread_mutexattr_destroy(&lock->attr);
    return ;
}

/*
 * for pthread condition
 */
int vcond_init(struct vcond* cond)
{
    assert(cond);
    int res = pthread_cond_init(&cond->cond, 0);
    return ((res < 0) ? -1 : 0);
}

int vcond_wait(struct vcond* cond, struct vlock* lock)
{
    assert(cond);
    assert(lock);

    --cond->signal_times;
    while (cond->signal_times < 0) {
        pthread_cond_wait(&cond->cond, &lock->mutex);
    }
    return 0;
}

int vcond_timedwait(struct vcond* cond, struct vlock* lock, int secs)
{
    assert(cond);
    assert(lock);
    assert(secs >= 0);

    struct timespec timeout;
    timeout.tv_sec  = time( NULL ) + secs;
    timeout.tv_nsec = 0;

    return pthread_cond_timedwait(&cond->cond, &lock->mutex, &timeout);;
}

int vcond_signal(struct vcond* cond)
{
    assert(cond);

    cond->signal_times++;
    pthread_cond_signal(&cond->cond);
    return 0;
}

void vcond_deinit(struct vcond* cond)
{
    assert(cond);
    pthread_cond_destroy(&cond->cond);
    return ;
}

static
void* _aux_thread_entry(void* argv)
{
    struct vthread* thread = (struct vthread*)argv;
    assert(thread);

    pthread_mutex_lock(&thread->mutex);
    pthread_mutex_unlock(&thread->mutex);
    thread->quit_code = thread->entry_cb(thread->cookie);
    return thread;
}

/*
 * for thread
 */
int vthread_init(struct vthread* thread, vthread_entry_t entry, void* argv)
{
    assert(thread);
    assert(entry);

    thread->entry_cb = entry;
    thread->cookie = argv;
    thread->quit_code = 0;
    thread->started = 0;

    pthread_mutex_init(&thread->mutex, 0);
    pthread_mutex_lock(&thread->mutex);
    int res = pthread_create(&thread->thread, 0, _aux_thread_entry, thread);
    if (res) {
        pthread_mutex_unlock(&thread->mutex);
        pthread_mutex_destroy(&thread->mutex);
        return -1;
    }
    return 0;
}

int vthread_start(struct vthread* thread)
{
    assert(thread);

    if (thread->started) return -1;
    thread->started = 1;
    pthread_mutex_unlock(&thread->mutex);
    return 0;
}

int vthread_detach(struct vthread* thread)
{
    assert(thread);
    pthread_detach(thread->thread);
    return 0;
}

int vthread_join(struct vthread* thread, int* quit_code)
{
    assert(thread);
    assert(quit_code || !quit_code);

    int ret = pthread_join(thread->thread, NULL);
    if (ret < 0) return -1;
    if (quit_code) {
        *quit_code = thread->quit_code;
    }
    return 0;
}

void vthread_deinit(struct vthread* thread)
{
    assert(thread);
    pthread_mutex_destroy(&thread->mutex);
    return ;
}

int vthread_sleep(int milliseconds)
{
    assert(milliseconds >= 0);
#if defined(__WIN32__)
    Sleep(milliseconds);
#else
    usleep(1000 * milliseconds);
#endif
    return 0;
}

/*
 * for vtimer
 */
#if defined(__WIN32__)

static
VOID CALLBACK _aux_timer_routine(HWND hwnd, UINT umsg, UINT_PTR idevent, DWORD dwTime)
{
    //todo;
    return ;
}
#elif defined(__APPLE__)
static
dispatch_queue_t timer_manager_queue() {
    static dispatch_queue_t timer_manager_queue;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        timer_manager_queue = dispatch_queue_create("com.elastos.cloud.ecdev", DISPATCH_QUEUE_SERIAL);
    });

    return timer_manager_queue;
}
#else
static
void _aux_timer_routine(union sigval sv)
{
    struct vtimer* timer = (struct vtimer*)(sv.sival_ptr);
    assert(timer);

    (void)timer->cb(timer->cookie);
    return ;
}
#endif

int vtimer_init(struct vtimer* timer, vtimer_cb_t cb, void* cookie, int start_once)
{
#if defined(__WIN32__)
    assert(timer);
    assert(cb);

    timer->cb = cb;
    timer->cookie = cookie;
    timer->once_flag = (!!start_once);

    return 0;

#elif defined(__APPLE__)
    dispatch_source_t source = 0;

    assert(timer);
    assert(cb);

    timer->cb = cb;
    timer->cookie = cookie;
    timer->once_flag = (!!start_once);

    source = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, timer_manager_queue());
    dispatch_source_set_event_handler(source, ^{
        cb(timer->cookie);
    });
    timer->source = source;
    return 0;

#else
    struct sigevent evp;
    int ret = 0;

    assert(timer);
    assert(cb);

    timer->id = (timer_t)-1;
    timer->cb = cb;
    timer->cookie = cookie;
    timer->once_flag = (!!start_once);

    memset(&evp, 0, sizeof(evp));
    evp.sigev_value.sival_ptr = timer;
    evp.sigev_notify = SIGEV_THREAD;
    evp.sigev_notify_function = _aux_timer_routine;

    ret = timer_create(CLOCK_REALTIME, &evp, &timer->id);
    if (ret < 0) {
        printf("timer create error");
        return -1;
    }
    return 0;
#endif
}

int vtimer_start(struct vtimer* timer, int secs, int usecs)
{
#if defined(__WIN32__)
    assert(timer);
    assert(secs > 0 || usecs > 0);

    timer->id = SetTimer(NULL,(UINT)0, secs * 1000* 1000 + usecs, _aux_timer_routine);
    if (!timer->id) return -1;
    return 0;

#elif defined(__APPLE__)
    dispatch_source_t source  = timer->source;
    dispatch_time_t startTime = 0;
    uint64_t total_timeout = (uint64_t)(secs * NSEC_PER_SEC + usecs * NSEC_PER_USEC);

    assert(timer);
    assert(secs > 0 || usecs > 0);

    startTime = dispatch_time(DISPATCH_TIME_NOW, total_timeout);
    if (timer->once_flag) {
        dispatch_after(startTime, timer_manager_queue(), ^(void){
            timer->cb(timer->cookie);
            dispatch_cancel(timer->source);
        });
    } else {
        dispatch_source_set_timer(source, startTime, total_timeout, 0.0);
        dispatch_resume(source);
    }

    return 0;
#else
    struct itimerspec tmo;
    int ret = 0;

    assert(timer);
    assert(secs > 0 || usecs > 0);
    assert(timer->id != (timer_t)-1);

    if (timer->once_flag) {
        tmo.it_interval.tv_sec  = 0;
        tmo.it_interval.tv_nsec = 0;
    } else {
        tmo.it_interval.tv_sec  = secs;
        tmo.it_interval.tv_nsec = usecs * 1000;
    }

    tmo.it_value.tv_sec  = secs;
    tmo.it_value.tv_nsec = usecs * 1000;

    ret = timer_settime(timer->id, 0, &tmo, NULL);
    if (ret < 0) {
        printf("timer settime error");
        return -1;
    }
    return 0;
#endif
}

int vtimer_restart(struct vtimer* timer, int secs, int usecs)
{
#if defined(__WIN32__)
    //todo;
	return -1;
#elif defined(__APPLE__)
    dispatch_source_t source  = timer->source;
    dispatch_time_t startTime = 0;
    uint64_t total_timeout = (uint64_t)(secs * NSEC_PER_SEC + usecs * NSEC_PER_USEC);
    assert(timer);
    assert(secs > 0 || usecs > 0);

    dispatch_source_cancel(source);

    source = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, timer_manager_queue());
    dispatch_source_set_event_handler(source, ^{
        timer->cb(timer->cookie);
        if (timer->once_flag) {
            dispatch_source_cancel(source);
        }
    });

    startTime = dispatch_time(DISPATCH_TIME_NOW, total_timeout);
    dispatch_source_set_timer(source, startTime, total_timeout, 0.0);
    dispatch_resume(source);
    timer->source = source;

    return 0;
#else
    struct itimerspec tmo;
    int ret = 0;

    assert(timer);
    assert(secs > 0 || usecs > 0);
    assert(timer->id != (timer_t)-1);

    if (timer->once_flag) {
        tmo.it_interval.tv_sec  = 0;
        tmo.it_interval.tv_nsec = 0;
    } else {
        tmo.it_interval.tv_sec  = secs;
        tmo.it_interval.tv_nsec = usecs * 1000;
    }
    tmo.it_value.tv_sec = secs;
    tmo.it_value.tv_nsec = usecs * 1000;

    ret = timer_settime(timer->id, 0, &tmo, NULL);
    if (ret < 0) {
        printf("timer setttime error");
        return -1;
    }
    return 0;
#endif
}

int vtimer_stop(struct vtimer* timer)
{
#if defined(__WIN32__)
    //todo;
	return -1;
#elif defined(__APPLE__)
    assert(timer);

    dispatch_source_t source = timer->source;
    dispatch_source_cancel(source);

    return 0;
#else
    int ret = 0;
    assert(timer);
    assert(timer->id != (timer_t)-1);

    ret = timer_delete(timer->id);
    if (ret < 0) {
        printf("timer delete error");
        return -1;
    }
    timer->id = (timer_t)-1;
    return 0;
#endif
}

void vtimer_deinit(struct vtimer* timer)
{
#if defined(__WIN32__)
    //todo;
#elif defined(__APPLE__)
    assert(timer);

    dispatch_source_t source = timer->source;
    dispatch_source_cancel(source);
    source = NULL;
#else
    assert(timer);

    if (timer->id != (timer_t)-1) {
        timer_delete(timer->id);
        timer->id = (timer_t)-1;
    }
    return ;
#endif
}

