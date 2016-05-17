#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(__WIN32__)
#include <winsock2.h>
#define close(fd) closesocket(fd)
#else
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
#define c_sleep(x) Sleep(1*x)
#define _errno WSAGetLastError()
#else
#include <unistd.h>
#define c_sleep(x) usleep(1000*x)
#define _errno errno
#endif

int main(int argc, char **argv)
{
    struct sockaddr_in saddr;
    struct sockaddr_in caddr;
    int caddr_len = sizeof(caddr);
    int sfd = 0;
    int cfd = 0;
    int ret = 0;
    int opt_val = 1;

    if (argc != 2) {
        printf("Usage: %s port\n", argv[0]);
        return -1;
    }

#if defined(__WIN32__)
    WSADATA wsa_data = {0};
    int res = WSAStartup(MAKEWORD(2,2), &wsa_data);
    if (res != 0) {
        printf("WSAStartup error\n");
        return -1;
    }
#endif

    sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) {
        printf("socket error:%d\n", _errno);
        return -1;
    }
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (void*)&opt_val, sizeof(opt_val));

    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = htonl(INADDR_ANY);
    saddr.sin_port = htons(atoi(argv[1]));
    ret = bind(sfd, (struct sockaddr *)&saddr, sizeof(saddr));
    if (ret < 0) {
        printf("bind error(err:%d)\n", _errno);
        close(sfd);
        return -1;
    }
    ret = listen(sfd, 5);
    if (ret < 0) {
        printf("listen error(err:%d)\n", _errno);
        close(sfd);
        return -1;
    }
    cfd = accept(sfd, (struct sockaddr *)&caddr, &caddr_len);
    if (cfd < 0) {
        printf("accept error(err:%d)\n", _errno);
        close(sfd);
        return -1;
    }
    while (1) {
        static int times = 0;
        char buf[32] = {0};
        char msg[] = "server message";

        printf("wating to read.\n");
        ret = recv(cfd, buf, sizeof(buf), 0);
        if (ret < 0) {
            printf("recv error (err:%d)\n", _errno);
            break;
        }
        printf("received a message [%d]:%s (len:%d)\n", times++, buf, ret);

        ret = send(cfd, msg, strlen(msg), 0);
        if (ret < 0) {
            printf("send error (err:%d)\n", _errno);
            break;
        }
        printf("sent (%d)bytes message.\n", ret);
        c_sleep(1);
    }
    printf("exit.\n");
    close(cfd);
    close(sfd);

#if defined(__WIN32__)
    WSACleanup();
#endif
    return 0;
}

