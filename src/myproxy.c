#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <netinet/in.h>
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
#include "Syscalls.h"
#include "misc.h"
#include "proxy_manager.h"
#define MAX_CLIENTS 1000

// ---------------------------------------------------------------------------------
// Obtained from https://curl.se/libcurl/c/opensslthreadlock.html 
/* This array will store all of the mutexes available to OpenSSL. */
static pthread_mutex_t *mutex_buf = NULL;
 
static void locking_function(int mode, int n, const char *file, int line)
{
  if(mode & CRYPTO_LOCK)
    pthread_mutex_lock(&mutex_buf[n]);
  else
    pthread_mutex_unlock(&mutex_buf[n]);
}
 
static unsigned long id_function(void)
{
  return ((unsigned long)pthread_self());
}
 
int thread_setup(void)
{
  int i;
 
  mutex_buf = malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
  if(!mutex_buf)
    return 0;

  for(i = 0;  i < CRYPTO_num_locks();  i++)
    pthread_mutex_init(&mutex_buf[i], NULL);

  CRYPTO_set_id_callback(id_function);
  CRYPTO_set_locking_callback(locking_function);
  return 1;
}

// -------------------------------------------------------------------------------------

// list of forbidden urls and filename to the forbidden urls
extern char **forbidden_URLs, *filename, *log_filename;

// Mutex for locking log output
extern pthread_mutex_t log_output;
extern pthread_mutex_t lock;

// SSL context strucuture
static const SSL_METHOD *req_method;
static SSL_CTX *ctx;

// Function for which threads will execute
static void *thread_func(void *arg);

void sigpipe_handler(int unused)
{
}

int main(int argc, char **argv)
{
    if(argc != 4)
    {
        fprintf(stderr, "Error: Incorrect number of arguments\n");
        exit(1);
    }
    int listenfd, port, tr = 1;
    struct sockaddr_in servaddr, client;
    struct thread_info *thread_data;
    struct timeval tv;
    pthread_t *thread;
    socklen_t clilen;
    memset(&servaddr, 0, sizeof(servaddr));
    memset(&client, 0, sizeof(client));

    // Check the arguent passed is a valid port number
    port = checknum(argv[1]);
    if(port == -1)
    {
        fprintf(stderr, "Error: Invalid port\n");
        exit(1);
    }
    else if(port < 1024)
    {
        fprintf(stderr, "Error: Can not use reseverved port: %d", port);
        exit(1);
    }
    else if(port > 65535)
    {
        fprintf(stderr, "Error: Port number is out of range: %d", port);
        exit(1);
    }

    // Make directory of log file
    Mkdir(argv[3]);

    // Assign Log file name
    log_filename = argv[3];

    // Lock for printing log output
    pthread_mutex_init(&log_output, NULL);
    pthread_mutex_init(&lock, NULL);

    // Set signal for CTRL+C
    signal(SIGINT, sigintHandler);
    signal(SIGPIPE, sigintHandler);

    // Get current list of Forbidden addresses
    forbidden_URLs = get_forbidden_sites(argv[2]);
    filename = argv[2];

    // Initialize SSL context and set options
    SSL_library_init();
    SSL_load_error_strings();
    req_method = SSLv23_client_method();
    ctx = SSL_CTX_NEW(req_method);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_COMPRESSION | SSL_OP_SINGLE_DH_USE);
    SSL_CTX_SET_CIPHER_LIST(ctx, "HIGH:MEDIUM");

    // Setting Timeout parameters
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    
    // Set and initialize proxy server settings
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);

    // Open Socket for server, set socket option for reuse of port number when improper
    // termination of server has occurred. Bind Server struct to socket and set to listening state
    // for up to 50 clients queued
    listenfd = Socket(AF_INET, SOCK_STREAM, 0);
    Setsockopt(listenfd,SOL_SOCKET,SO_REUSEADDR,&tr,sizeof(int));
    Bind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr));
    Listen(listenfd, MAX_CLIENTS);

    thread_setup();

    // Loop to accept incoming TCP connections, allocate memory space for each client and 
    // create thread to execute their request
    while(1)
    {
        clilen = sizeof(client);
        thread_data = Calloc(1, sizeof(struct thread_info));
        thread_data->clientfd = Accept(listenfd, (struct sockaddr*)&client, &clilen);
        Inet_ntop (AF_INET, &client.sin_addr, thread_data->ip, INET_ADDRSTRLEN);
        thread = Calloc(1, sizeof(pthread_t));

        thread_data->tv = &tv;
        thread_data->n = 0;

        if( (pthread_create(thread, NULL, thread_func, thread_data)) != 0)
        {
            fprintf(stderr, "Failed to create thread!\n");
            exit(EXIT_FAILURE);
        }
        memset(&client, 0, sizeof(client));
    }
    exit(0);
}

static void *thread_func(void *arg)
{
    // Detach thread from main thread and set socket option for a 2s timeout of inactivity
    pthread_detach(pthread_self());
    struct thread_info *thread_list = (struct thread_info*)(arg);
    Setsockopt(thread_list->clientfd, SOL_SOCKET, SO_RCVTIMEO, thread_list->tv, sizeof(*(thread_list->tv)));

    // Read in client request from I/O
    while(Read(thread_list->clientfd, thread_list->buf, MAX_HEADER) > 0);

    // Parse client header request to get necessary information to establish connection with webserver
    get_line_request(&thread_list->line, thread_list->buf);
    getrequest(&thread_list->request, thread_list->buf);
    getagent(&thread_list->Agent, thread_list->buf);
    getpath(thread_list->Agent, &thread_list->path, thread_list->buf);

    if(gethost(&thread_list->hostname, thread_list->buf) == -1 || thread_list->hostname == NULL)
    {
        print_log(thread_list->ip, thread_list->line, "400", 339);
        Send_Error(thread_list->clientfd, "400");
        free_Thread_Memory(&thread_list);
        pthread_exit(0);
    }
    getport(&thread_list->port, thread_list->buf, strlen(thread_list->hostname));

    // Formulate GET or HEAD request to webserver and store in buffer
    // If request is anythin other that GET or HEAD return 501 error
    memset(thread_list->buf, 0 , MAX_HEADER);
    if(thread_list->request != NULL && strncmp(thread_list->request, "GET", strlen(thread_list->request)) == 0)
    {
        snprintf(thread_list->buf, MAX_HEADER, "GET %s HTTP/1.1\r\nUser-Agent: Wget/1.14 (linux-gnu)\r\nAccept: */*\r\nHost: %s:%d\r\nConnection: close\r\n\r\n",
                thread_list->path!=NULL?thread_list->path:"/", thread_list->hostname, thread_list->port);
    }
    else if(thread_list->request != NULL && strncmp(thread_list->request, "HEAD", strlen(thread_list->request)) == 0)
    {
        snprintf(thread_list->buf, MAX_HEADER, "HEAD %s HTTP/1.1\r\nHost: %s:%d\r\n\r\n",thread_list->path!=NULL?thread_list->path:"/", 
                thread_list->hostname, thread_list->port);
    }
    else
    {
        print_log(thread_list->ip, thread_list->line, "501", 347);
        Send_Error(thread_list->clientfd, "501");
        free_Thread_Memory(&thread_list);
        pthread_exit(0);
    }

    // Try to resolve url of webserver and try to establish TCP connection.
    // If error in verifying url in forbidden list, return 403 error
    thread_list->serverfd = Resolve_Connect(&thread_list->hostname, thread_list->port);
    if(thread_list->serverfd < 0)
    {
        if (thread_list->serverfd == -1) 
        {
            print_log(thread_list->ip, thread_list->line, "400", 339);
            Send_Error(thread_list->clientfd, "400");
        }
        else if (thread_list->serverfd == -2) 
        {
            print_log(thread_list->ip, thread_list->line, "403", 343);
            Send_Error(thread_list->clientfd, "403");
        }
        free_Thread_Memory(&thread_list);
        pthread_exit(0);
    }

    // Set SSL struct and establish ssl connection with a HTTPS webserver
    // If failed to connect return 400 error to client.
    thread_list->ssl = SSL_NEW(ctx);
    if(thread_list->ssl == NULL)
    {
        print_log(thread_list->ip, thread_list->line, "400", 339);
        Send_Error(thread_list->clientfd, "400");
        free_Thread_Memory(&thread_list);
        pthread_exit(0);
    }
    SSL_SET_FD(thread_list->ssl, thread_list->serverfd);
    if(checkipv4(thread_list->hostname) == -1) SSL_SET_TLSEXT_HOST_NAME(thread_list->ssl, thread_list->hostname);
    thread_list->ret = SSL_connect(thread_list->ssl);
    if (thread_list->ret != 1)
    {
        print_log(thread_list->ip, thread_list->line, "400", 339);
        Send_Error(thread_list->clientfd, "400");
        free_Thread_Memory(&thread_list);
        pthread_exit(0);
    }

    // Write request to HTTPS webserver
    SSL_WRITE(thread_list->ssl, thread_list->buf, strlen(thread_list->buf));
    memset(thread_list->buf, 0 , MAX_HEADER);

    // Loop through receiving the response and obtain the status code of the response
    // If other other 200 code then return 400 error, else return the response requested
    while( (thread_list->n = SSL_READ(thread_list->ssl, thread_list->buf, MAX_HEADER)) > 0)
    {
        thread_list->bytes += thread_list->n;
        
        if(thread_list->code == NULL)
        {
            getcode(&thread_list->code, thread_list->buf);
        }
        if(strncmp(thread_list->code, "200", strlen(thread_list->code)) == 0)
        {
            Write(thread_list->clientfd, thread_list->buf, thread_list->n);
        }
        else
        {
            SSL_shutdown(thread_list->ssl);
            print_log(thread_list->ip, thread_list->line, "404", 343);
            Send_Error(thread_list->clientfd, "404");
            free_Thread_Memory(&thread_list);
            pthread_exit(0);
        }
    }
    if(thread_list->n < 0)
    {
        free_Thread_Memory(&thread_list);
        pthread_exit(0);
    }

    print_log(thread_list->ip, thread_list->line, "200", thread_list->bytes);
    SSL_shutdown(thread_list->ssl);
    free_Thread_Memory(&thread_list);
    pthread_exit(0);
    return NULL;
}