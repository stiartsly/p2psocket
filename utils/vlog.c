#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdarg.h>
#include "vlog.h"

static int g_stdout_level = VLOG_DEBUG;
/*
 * the routine to log debug message.
 */
void vlogD(const char* fmt, ...)
{
    va_list args;
    assert(fmt);

    if (g_stdout_level < VLOG_DEBUG) {
        return;
    }

    if (1) {
        va_start(args, fmt);
        printf("[D]");
        vprintf(fmt, args);
        printf("\n");
        va_end(args);
    }
    return;
}

/*
 * the routine to log debug message on given condition.
 * @cond: condition.
 */
void vlogDv(int cond, const char* fmt, ...)
{
    va_list(args);
    assert(fmt);

    if ((!cond) || (g_stdout_level < VLOG_DEBUG)){
        return;
    }

    if (1) {
        va_start(args, fmt);
        printf("[D]");
        vprintf(fmt, args);
        printf("\n");
        va_end(args);
    }
    return;
}

/*
 * the routine to log inform message;
 */
void vlogI(const char* fmt, ...)
{
    va_list args;
    assert(fmt);

    if (g_stdout_level < VLOG_INFO) {
        return ;
    }

    if (1) {
        va_start(args, fmt);
        printf("[I]");
        vprintf(fmt, args);
        printf("\n");
        va_end(args);
    }
    return ;
}

/*
 * the routine to log inform message on given condition.
 * @cond: condition.
 */
void vlogIv(int cond, const char* fmt, ...)
{
    va_list args;
    assert(fmt);

    if (!cond || (g_stdout_level < VLOG_INFO)) {
        return ;
    }

    if (1) {
        va_start(args, fmt);
        printf("[I]");
        vprintf(fmt, args);
        printf("\n");
        va_end(args);
    }
    return;
}

/*
 * the routine to log error message
 */
void vlogE(const char* fmt, ...)
{
    va_list(args);
    assert(fmt);

    if (1) {
        va_start(args, fmt);
        printf("[E]");
        vprintf(fmt, args);
        printf("\n");
        va_end(args);
    }
    return;
}

/*
 * the routine to log error message on given condition.
 * @cond: condition.
 */
void vlogEv(int cond, const char* fmt, ...)
{
    va_list(args);
    assert(fmt);

    if (!cond) {
        return;
    }

    if (1) {
        va_start(args, fmt);
        printf("[E]");
        vprintf(fmt, args);
        printf("\n");
        va_end(args);
    }
    return;
}

