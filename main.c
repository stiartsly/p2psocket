#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#if defined(__WIN32__)
#else
#include <unistd.h>
#endif
#include "p2psocket.h"

static int daemonize = 0;

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
#define c_sleep(x) Sleep(1*x)
#else
#include <unistd.h>
#define c_sleep(x) usleep(1000*x)
#endif

char datapath[256] = {0};
int  datapath_set = 0;
uint8_t pubkey[P2PSOCK_KEY_LEN] = {0};
int  pubkey_set = 0;
uint16_t lport = 0;
uint16_t rport = 0;
int type = 0;
int show_help = 0;
int show_ver  = 0;
int client_mode = 0;
int server_mode = 1;

static
struct option long_options[] = {
    {"daemon",           no_argument,        &daemonize,   1  },
    {"client",           no_argument,        &client_mode, 1  },
    {"server",           no_argument,        &server_mode, 1  },
    {"data-file",        required_argument,  0,            'f'},
    {"key",              required_argument,  0,            'k'},
    {"lport",            required_argument,  0,            'l'},
    {"rport",            required_argument,  0,            'r'},
    {"proto",            required_argument,  0,            'p'},
    {0, 0, 0, 0}
};

static
void show_usage(void)
{
    printf("Usage: p2pd [OPTION...]\n");
    printf("  -D, --daemon                  Become a daemon\n");
    printf("  -f, --data-file=DATAFILE      saved data filename\n");
    printf(" Client options:\n");
    printf("  -c, --client                  client mode\n");
    printf("  -k, --key=PUBLIC_KEY          public key of remote peer\n");
    printf("  -l, --lport=PORT              local port to bind\n");
    printf("  -r, --rport=PORT              rmote port to forward\n");
    printf("  -p, --proto=TCP|UDP           protocol to forward\n");
    printf(" Server options:\n");
    printf("  -s, --server                  server mode\n");
    printf(" Help options:\n");
    printf("  -h                            show this message\n");
    printf("  -v                            show current version\n");
    printf("\n");
}

static
void show_version(void)
{
    printf("Version 0.0.1\n");
    return ;
}

static
int32_t convert2key(const char* hexStr, uint8_t* key)
{
    assert(hexStr);
    assert(key);

    if (strlen(hexStr) % 2 != 0) {
        return -1;
    }
    int   len = strlen(hexStr)/2;
    char* pos = (char*)hexStr;

    for (int i = 0; i < len; i++, pos += 2) {
        sscanf(pos, "%2hhx", &key[i]);
    }
    return 0;
}

int main(int argc, char** argv)
{
    char* cfg_file = NULL;
    int opt_idx = 0;
    int ret = 0;
    int c = 0;

    while(c >= 0) {
        c = getopt_long(argc, argv, "Df:k:l:r:p:cshv", long_options, &opt_idx);
        if (c < 0) {
            break;
        }
        switch(c) {
        case 0: {
            if (long_options[opt_idx].flag != 0)
                break;
            printf ("option %s", long_options[opt_idx].name);
            if (optarg)
                printf (" with arg %s", optarg);
            printf ("\n");
            break;
        }
        case 'D':
            daemonize = 1;
            break;
        case 'f':
            strcpy(datapath, optarg);
            datapath_set = 1;
            break;
        case 'k':
            convert2key(optarg,pubkey);
            pubkey_set = 1;
            break;
        case 'l':
            lport = atoi(optarg);
            break;
        case 'r':
            rport = atoi(optarg);
            break;
        case 'p':
            if (!strcmp(optarg, "tcp") || !strcmp(optarg, "TCP")) {
                type = P2P_SOCK_STREAM;
            }
            if (!strcmp(optarg, "udp") || !strcmp(optarg, "UDP")) {
                type = P2P_SOCK_DGRAM;
            }
            break;
        case 'c':
            client_mode = 1;
            break;
        case 's':
            server_mode = 1;
            break;
        case 'h':
            show_help = 1;
            break;
        case 'v':
            show_ver = 1;
            break;
        default:
            printf("Invalid option -%c: Unknown option.\n", (char)c);
            show_usage();
            exit(-1);
        }
    }
    if (optind < argc) {
        printf("Too many arguments.\n");
        show_usage();
        exit(-1);
    }

    if (show_help) {
        show_usage();
        exit(0);
    }
    if (show_ver) {
        show_version();
        exit(0);
    }

#if !defined(__WIN32__)
    if (daemonize) {
        int pid = fork();
        if (pid < 0) {
            perror("fork: ");
            exit(-1);
        }else if (pid > 0) {
            exit(0);
        }else {
            setsid();
        }
    }
#endif
    {
        int fd = 0;
        p2psocket_init(datapath);

        if (client_mode) {
            struct sockaddr_p2pin addr;
            make_sockaddr_p2pin(P2P_AF_INET, lport, rport, pubkey, &addr);
            fd = p2psocket_open(P2P_AF_INET, type, (struct sockaddr*)&addr, sizeof(addr));
            if (fd < 0) {
                printf("p2psocket open error");
                p2psocket_deinit();
                exit(-1);
            }
            printf("Run as client mode\n");
        } else {
            printf("Run as server mode\n");
        }

        while(1) {
            c_sleep(500);
        }

        if (client_mode) {
            if (fd > 0) {
                p2psocket_close(fd);
            }
        }
        p2psocket_deinit();
    }
    return 0;
}
