#include "proxy_manager.h"
#include "Syscalls.h"

static const char *Error_501 = {"HTTP/1.0 501 Not Implemented\r\nContent-Type: text/html\r\nContent-Length: 347\r\nConnection: close\r\n\r\n"
                                "<?xml version='1.0' encoding='so-8859-1'?>\n<!DOCTYPE html PUBLIC '-/W3C//DTD XHTML 1.0 Transitional//EN'\n\t"
                                "'http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd'>\n<html xmlns='http://www.w3.org/1999/xhtml' xml:lang='en' lang='en'>\n\t"
                                "<head>\n\t\t<title>501 - Not Implemented</title>\n\t</head>\n\t<body>\n\t\t<h1>501 - Not Implemented</h1>\n\t</body>\n</html>\n"};

static const char *Error_404 = {"HTTP/1.0 404 Not Found\r\nContent-Type: text/html\r\nContent-Length: 335\r\nConnection: close\r\n\r\n"
                                "<?xml version='1.0' encoding='so-8859-1'?>\n<!DOCTYPE html PUBLIC '-/W3C//DTD XHTML 1.0 Transitional//EN'\n\t"
                                "'http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd'>\n<html xmlns='http://www.w3.org/1999/xhtml' xml:lang='en' lang='en'>\n\t"
                                "<head>\n\t\t<title>404 - Not Found</title>\n\t</head>\n\t<body>\n\t\t<h1>404 - Not Found</h1>\n\t</body>\n</html>\n"};

static const char *Error_403 = {"HTTP/1.0 403 Forbidden URL\r\nContent-Type: text/html\r\nContent-Length: 343\r\nConnection: close\r\n\r\n"
                                "<?xml version='1.0' encoding='so-8859-1'?>\n<!DOCTYPE html PUBLIC '-/W3C//DTD XHTML 1.0 Transitional//EN'\n\t"
                                "'http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd'>\n<html xmlns='http://www.w3.org/1999/xhtml' xml:lang='en' lang='en'>\n\t"
                                "<head>\n\t\t<title>403 - Forbidden URL</title>\n\t</head>\n\t<body>\n\t\t<h1>403 - Forbidden URL</h1>\n\t</body>\n</html>\n"};

static const char *Error_400 = {"HTTP/1.0 400 Bad Request\r\nContent-Type: text/html\r\nContent-Length: 339\r\nConnection: close\r\n\r\n"
                                "<?xml version='1.0' encoding='so-8859-1'?>\n<!DOCTYPE html PUBLIC '-/W3C//DTD XHTML 1.0 Transitional//EN'\n\t"
                                "'http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd'>\n<html xmlns='http://www.w3.org/1999/xhtml' xml:lang='en' lang='en'>\n\t"
                                "<head>\n\t\t<title>400 - Bad Request</title>\n\t</head>\n\t<body>\n\t\t<h1>400 - Bad Request</h1>\n\t</body>\n</html>\n"};

static int updating = 0;

pthread_mutex_t lock;

static pthread_cond_t cond;

char **forbidden_URLs, *filename;

int Resolve_Connect(char **hostname, int port)
{
    int sockfd = 0;
    struct sockaddr_in webserver;
    struct addrinfo hints, *res = NULL, *ressave = NULL;
    struct timeval tv;
    memset(&webserver, 0, sizeof(webserver));
    memset(&hints, 0, sizeof(struct addrinfo));

    tv.tv_sec = 15;
    tv.tv_usec = 0;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if(Getaddrinfo(*hostname, "http", &hints, &res) != 0 && errno != 0) return -1;
    ressave = res;
    if(website_check(res, *hostname) == -1) return -2;
    res = ressave;
    ((struct sockaddr_in*)res->ai_addr)->sin_port = htons(port);
    if( (sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) return -1;
    if(setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) return -1;
    if(Connect(sockfd, res->ai_addr, res->ai_addrlen) != 0) return -1;

    if (ressave != NULL) freeaddrinfo(ressave);
    return sockfd;
}

void Send_Error(int clientfd, char *error)
{
    if(strncmp(error, "501", strlen(error)) == 0)
    {
        Write(clientfd, Error_501, strlen(Error_501));
    }
    else if(strncmp(error, "404", strlen(error)) == 0)
    {
        Write(clientfd, Error_404, strlen(Error_404));
    }
    else if(strncmp(error, "403", strlen(error)) == 0)
    {
        Write(clientfd, Error_403, strlen(Error_403));
    }
    else if(strncmp(error, "400", strlen(error)) == 0)
    {
        Write(clientfd, Error_400, strlen(Error_400));
    }
}

int website_check(struct addrinfo *res, char *hostname)
{
    char ip1[INET_ADDRSTRLEN];
    int i = 0;
    while(updating == 1)
    {
        pthread_cond_wait(&cond, &lock);
    }
    pthread_mutex_lock(&lock);
    while(forbidden_URLs[i] != NULL)
    {
        if(checkipv4(forbidden_URLs[i]) == 1)
        {
            do
            {
                if(Inet_ntop (AF_INET, &((struct sockaddr_in*)res->ai_addr)->sin_addr, ip1, INET_ADDRSTRLEN) == NULL) 
                {
                    pthread_mutex_unlock(&lock);
                    return -1;
                }
                if(strncmp(ip1, "0.0.0.0", INET_ADDRSTRLEN) != 0)
                {
                    if(strncmp(ip1, forbidden_URLs[i], strlen(ip1) > strlen(forbidden_URLs[i])?strlen(forbidden_URLs[i]):strlen(ip1)) == 0)
                    {
                        pthread_mutex_unlock(&lock);
                        return -1;
                    }
                }
                memset(ip1, 0, INET_ADDRSTRLEN);
            }while((res = res->ai_next) != NULL);
        }
        else
        {
            if(strncmp(hostname, forbidden_URLs[i], strlen(hostname) > strlen(forbidden_URLs[i])?strlen(forbidden_URLs[i]):strlen(hostname)) == 0)
            {
                pthread_mutex_unlock(&lock);
                return -1;
            }
        }
        i++;
    }
    pthread_mutex_unlock(&lock);
    return 0;
}

void sigintHandler(int sig_num)
{
    int i = 0;
    updating = 1;
    pthread_mutex_lock(&lock);
    while(forbidden_URLs[i] != NULL)
    {
        free(forbidden_URLs[i++]);
    }
    free(forbidden_URLs);
    forbidden_URLs = NULL;
    forbidden_URLs = get_forbidden_sites(filename);
    updating = 0;
    pthread_mutex_unlock(&lock);
    pthread_cond_broadcast(&cond);
}

void free_Thread_Memory(struct thread_info **thread_list)
{
    // Free Thread memory space
    if((*thread_list)->hostname != NULL) free((*thread_list)->hostname);
    if((*thread_list)->path != NULL) free((*thread_list)->path);
    if((*thread_list)->request != NULL) free((*thread_list)->request);
    if((*thread_list)->code != NULL) free((*thread_list)->code);
    if((*thread_list)->line != NULL) free((*thread_list)->line);
    if((*thread_list)->ssl != NULL) SSL_free((*thread_list)->ssl);
    if((*thread_list)->serverfd > 0) close((*thread_list)->serverfd);
    if((*thread_list)->clientfd > 0) close((*thread_list)->clientfd);
    free(*thread_list);
}