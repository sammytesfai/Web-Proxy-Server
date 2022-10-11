#ifndef SYSCALLS_H_INCLUDE_
#define SYSCALLS_H_INCLUDE_
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <openssl/crypto.h> 
#include <openssl/x509.h> 
#include <openssl/pem.h> 
#include <openssl/ssl.h> 
#include <openssl/err.h> 

void *Calloc(size_t nmemb, size_t size);

int Socket(int family, int type, int protocol);

int Bind(int socket, const struct sockaddr *addr, socklen_t addr_len);

int Connect(int socket, const struct sockaddr *addr, socklen_t addr_len);

int Listen(int socket, int backlog);

int Accept(int socket, struct sockaddr *addr, socklen_t *addr_len);

ssize_t Read(int fd, void *buf, size_t count);

ssize_t Write(int fd, const void *buf, size_t count);

ssize_t Recvfrom(int sockfd, void *restrict buf, size_t len, int flags, 
                struct sockaddr *restrict src_addr, socklen_t *restrict addrlen);

ssize_t Sendto(int socket, const void *message, size_t length, int flags, 
                const struct sockaddr *dest_addr, socklen_t dest_len);

int Inet_pton(int af, const char *restrict src, void *restrict dst);

const char *Inet_ntop(int af, const void *restrict src, char *restrict dst, socklen_t size);

int Setsockopt(int socket, int level, int option_name, const void *option_value, 
                socklen_t option_len);

FILE *Fopen(const char *restrict pathname, const char *restrict mode);

int Fclose(FILE *stream);

size_t Fread(void *restrict ptr, size_t size, size_t nmemb, FILE *restrict stream);

size_t Fwrite(const void *restrict ptr, size_t size, size_t nitems, FILE *restrict stream);

void Mkdir(char *s);

int Getsockname(int sockfd, struct sockaddr *restrict addr,
                       socklen_t *restrict addrlen);

int Getaddrinfo(const char *node, const char *service, const struct addrinfo *hints,
                struct addrinfo **res);

int Getnameinfo(const struct sockaddr *restrict addr, socklen_t addrlen,
                       char *restrict host, socklen_t hostlen,
                       char *restrict serv, socklen_t servlen, int flags);

SSL_CTX *SSL_CTX_NEW(const SSL_METHOD *method);

int SSL_CTX_SET_CIPHER_LIST(SSL_CTX *ctx, const char *str);

SSL *SSL_NEW(SSL_CTX *ctx);

int SSL_SET_FD(SSL *ssl, int fd);

int SSL_SET_TLSEXT_HOST_NAME(SSL *s, const char *name);

int SSL_WRITE(SSL *ssl, const void *buf, int num);

int SSL_READ(SSL *ssl, void *buf, int num);

#endif