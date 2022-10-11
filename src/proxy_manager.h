#ifndef PROXY_MANAGER_H_INCLUDE_
#define PROXY_MANAGER_H_INCLUDE_
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <openssl/crypto.h> 
#include <openssl/x509.h> 
#include <openssl/pem.h> 
#include <openssl/ssl.h> 
#include <openssl/err.h>
#include <signal.h>
#include "misc.h"

struct thread_info
{
    int clientfd, serverfd, n, port, *complete, bytes, ret;
    char buf[MAX_HEADER+1], ip[INET_ADDRSTRLEN], *hostname, *path, Agent, *request, *code, *line;
    struct timeval *tv;
    SSL *ssl;
};

int Resolve_Connect(char **hostname, int port);

void Send_Error(int clientfd, char *error);

int website_check(struct addrinfo *res, char *hostname);

void sigintHandler(int sig_num);

void free_Thread_Memory(struct thread_info **thread_list);

#endif