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
    struct sockaddr_in laddr;
    int sockfd  = 0;
    int opt_val = 1;
    int ret = 0;

    if (argc != 3) {
        printf("Usage: %s IP port\n", argv[0]);
        return -1;
    }
#if defined(__WIN32__)
    WSADATA wsa_data = {0};
    int res = WSAStartup(MAKEWORD(2,2), &wsa_data);
    if (res != 0) {
        printf("WSAStartup error");
        return -1;
    }
#endif

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket < 0) {
        printf("socket error:(err:%d)\n", _errno);
        return -1;
    }
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void*)&opt_val, sizeof(opt_val));

    laddr.sin_family = AF_INET;
    laddr.sin_addr.s_addr = inet_addr(argv[1]);
    laddr.sin_port = htons(atoi(argv[2]));
    ret = connect(sockfd, (struct sockaddr *)&laddr, sizeof(laddr));
    if(ret < 0) {
        printf("connect error (err:%d)\n", _errno);
        close(sockfd);
        return -1;
    }
    printf("connect OK\n");

    while (1) {
        static int times = 0;
        char msg[] = "client message";
        char buf[32] = {0};
        ret = send(sockfd, msg, strlen(msg), 0);
        if (ret < 0) {
            printf("write error(err:%d)\n", _errno);
            break;
        }
        printf("sent %d bytes, then waiting to read.\n", strlen(msg));
        ret = recv(sockfd, buf, sizeof(buf), 0);
        if (ret < 0) {
            printf("recv error (err:%d)\n", _errno);
            break;
        }
        printf("received a message [%d]:%s (len:%d)\n", times++, buf, ret);
        c_sleep(500);
    }
    close(sockfd);
#if defined(__WIN32__)
    WSACleanup();
#endif
    return 0;
}

