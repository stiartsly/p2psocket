#pragma once

enum {
    VLOG_ERR,
    VLOG_INFO,
    VLOG_DEBUG,
    VLOG_BUTT
};

void vlogD (const char*, ...);
void vlogI (const char*, ...);
void vlogE (const char*, ...);
void vlogDv(int, const char*, ...);
void vlogIv(int, const char*, ...);
void vlogEv(int, const char*, ...);

