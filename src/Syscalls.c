#include <pthread.h>
#include "Syscalls.h"

int active_threads;

void *Calloc(size_t nmemb, size_t size)
{
    void *ret = calloc(nmemb, size);
    if(ret == NULL)
    {
        fprintf(stderr, "Error: calloc failed\n");
        exit(1);
    }
    return ret;
}

int Socket(int family, int type, int protocol)
{
    int ret = 0;
    if( (ret = socket(family, type, protocol)) < 0) 
    {
        perror("Error");
        exit(1);
    }
    return ret;
}

int Bind(int socket, const struct sockaddr *addr, socklen_t addr_len)
{
    int ret = 0;
    if( (ret = bind(socket, addr, addr_len)) != 0) 
    {
        perror("Error");
        exit(1);
    }
    return ret;
}

int Connect(int socket, const struct sockaddr *addr, socklen_t addr_len)
{
    int ret = connect(socket, addr, addr_len);
    return ret;
}

int Listen(int socket, int backlog)
{
    int ret = 0;
    if( (ret = listen(socket, backlog)) != 0) 
    {
        perror("Error");
        exit(1);
    }
    return ret;
}

int Accept(int socket, struct sockaddr *addr, socklen_t *addr_len)
{
    int ret = 0;
    if( (ret = accept(socket, addr, addr_len)) == -1) 
    {
        perror("Error");
        exit(1);
    }
    return ret;
}

ssize_t Read(int fd, void *buf, size_t count)
{
    ssize_t ret = 0;
    if( (ret = read(fd, buf, count)) < 0 )
    {
        if(errno == EWOULDBLOCK || errno == EAGAIN) return ret;
        perror("Error");
        pthread_exit(0);
    }
    return ret;
}

ssize_t Write(int fd, const void *buf, size_t count)
{
    ssize_t ret = 0;
    if( (ret = write(fd, buf, count)) < 0 )
    {
        perror("Error");
        pthread_exit(0);
    }
    return ret;
}

ssize_t Recvfrom(int sockfd, void *restrict buf, size_t len, int flags, 
                struct sockaddr *restrict src_addr, socklen_t *restrict addrlen)
{
    ssize_t ret = 0;
    if( (ret = recvfrom(sockfd, buf, len, flags, src_addr, addrlen)) == -1)
    {
        perror("Error");
        exit(1);
    }
    return ret;
}

ssize_t Sendto(int socket, const void *message, size_t length, int flags, 
                const struct sockaddr *dest_addr, socklen_t dest_len)
{
    ssize_t ret = 0;
    if( (ret = sendto(socket, message, length, flags, dest_addr, dest_len)) == -1)
    {
        perror("Error");
        exit(1);
    }
    return ret;
}

int Inet_pton(int af, const char *restrict src, void *restrict dst)
{
    int ret = ret = inet_pton(AF_INET, src, dst);
    return ret;
}

const char *Inet_ntop(int af, const void *restrict src, char *restrict dst, socklen_t size)
{
    const char *ret = inet_ntop(af, src, dst, size);
    return ret;
}

int Setsockopt(int socket, int level, int option_name, const void *option_value, socklen_t option_len)
{
    int ret = 0;
    if( (ret = setsockopt(socket, level, option_name, option_value, option_len)) != 0)
    {
        perror("Error");
        exit(1);
    }
    return ret;
}

FILE *Fopen(const char *restrict pathname, const char *restrict mode)
{
    FILE *f;
    if( (f = fopen(pathname, mode)) == NULL)
    {
        perror("Error");
        exit(1);
    }
    return f;
}

int Fclose(FILE *stream)
{
    int ret = 0;
    if( (ret = fclose(stream)) != 0)
    {
        perror("Error");
        exit(1);
    }
    return ret;
}

size_t Fread(void *restrict ptr, size_t size, size_t nmemb, FILE *restrict stream)
{
    size_t ret = 0;
    if( (ret = fread(ptr, size, nmemb, stream)) < 0)
    {
        perror("Error");
        exit(1);
    }
    return ret;
}

size_t Fwrite(const void *restrict ptr, size_t size, size_t nitems, FILE *restrict stream)
{
    size_t ret = 0;
    if( (ret = fwrite(ptr, size, nitems, stream)) < 0)
    {
        perror("Error");
        exit(1);
    }
    return ret;
}

void Mkdir(char *s)
{
    if(strpbrk(s, "/") == NULL) return;
    char *token, *copy;
    copy = calloc(strlen(s)+1, sizeof(char));
    strncpy(copy, s, strlen(s));
    token = strtok(copy, "/");
    if (mkdir(token, 0777) == -1)
    {
        if(errno != EEXIST)
        {
            perror("Error");
            exit(1);
        }
    }
    chdir(token);
    token = strtok(NULL, "");
    Mkdir(token);
    chdir("..");
    free(copy);
}

int Getsockname(int sockfd, struct sockaddr *restrict addr,
                       socklen_t *restrict addrlen)
{
    int ret = 0;
    if( (ret = getsockname(sockfd, addr, addrlen)) != 0)
    {
        perror("Error");
        exit(1);
    }
    return ret;
}

int Getaddrinfo(const char *node, const char *service, const struct addrinfo *hints,
                struct addrinfo **res)
{
    int ret = getaddrinfo(node, service, hints, res);
    return ret;
}

int Getnameinfo(const struct sockaddr *restrict addr, socklen_t addrlen,
                       char *restrict host, socklen_t hostlen,
                       char *restrict serv, socklen_t servlen, int flags)
{
    int ret = getnameinfo(addr, addrlen, host, hostlen, serv, servlen, flags);
    return ret;
}

SSL_CTX *SSL_CTX_NEW(const SSL_METHOD *method)
{
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (ctx == NULL) 
    {
        fprintf(stderr, "Error: SSL_CTX_NEW() failed\n");
        exit(1);
    }
    return ctx;
}

int SSL_CTX_SET_CIPHER_LIST(SSL_CTX *ctx, const char *str)
{
    if(SSL_CTX_set_cipher_list(ctx, "HIGH:MEDIUM") != 1)
    {
        fprintf(stderr, "Error: CTX set cipher failed\n");
        exit(1);
    }
    return 1;
}

SSL *SSL_NEW(SSL_CTX *ctx)
{
    SSL *ssl = SSL_new(ctx);
    return ssl;
}

int SSL_SET_FD(SSL *ssl, int fd)
{
    int ret = 0;
    if( (ret = SSL_set_fd(ssl, fd)) == 0)
    {
        fprintf(stderr, "Error: SSL_set_fd() failed\n");
        pthread_exit(0);
    }
    return ret;
}

int SSL_SET_TLSEXT_HOST_NAME(SSL *s, const char *name)
{
    if (!SSL_set_tlsext_host_name(s, name)) 
    {
        fprintf(stderr, "Server Name Identification Failed\n");
        pthread_exit(0);
    }
    return 1;
}

int SSL_WRITE(SSL *ssl, const void *buf, int num)
{
    int ret = 0;
    if ( (ret = SSL_write(ssl, buf, num)) < 0)
    {
        fprintf(stderr, "Error: SSL write failed\n");
        pthread_exit(0);
    }
    return ret;
}

int SSL_READ(SSL *ssl, void *buf, int num)
{
    int ret = 0;
    if ( (ret = SSL_read(ssl, buf, num)) < 0)
    {
        if(errno == EWOULDBLOCK || errno == EAGAIN) return ret;
        fprintf(stderr, "Error: SSL read failed\n");
        pthread_exit(0);
    }
    return ret;
}