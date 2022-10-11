#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>
#include "misc.h"
#include "Syscalls.h"

pthread_mutex_t log_output;

char *log_filename;

int checkipv4(char* s)
{
    char *token, *copy;
    int octets = 0, val;
    copy = Calloc(strlen(s) + 1, sizeof(char));
    strncpy(copy, s, strlen(s));
    token = strtok(copy, ".");

    while(token != NULL)
    {
        octets++;
        for(int i = 0; i < strlen(token); i++)
        {
            if(!isdigit(token[i]))
            {
                free(copy);
                return -1;
            }
        }
        val = atoi(token);
        if(val < 0 || val > 255) 
        {
            free(copy);
            return -1;
        }
        
        if(octets < 3) token = strtok(NULL, ".");
        else token = strtok(NULL, "");
    }

    if(octets != 4) 
    {
        free(copy);
        return -1;
    }
    free(copy);
    return 1;
}

int checknum(char* s)
{
    for(int i = 0; i < strlen(s); i++)
    {
        if(!isdigit(s[i]))
        {
            return -1;
        }
    }
    return atoi(s);
}

void print_log(char *client_ip, char *request_line,  char *code, int bytes)
{
    pthread_mutex_lock(&log_output);
    FILE *fp = Fopen(log_filename, "a+");
    char buf[1000];
    struct timeval tv;
    struct tm *t;
    int len = 0;
    memset(buf, 0 , 1000);

    gettimeofday(&tv,NULL);

    t = gmtime(&tv.tv_sec);
    len += strftime(buf,1000,"%Y-%m-%dT%H:%M:%S", t);
    snprintf(buf+len, 1000-len, ".%03ldZ", tv.tv_usec/1000);
    strcat(buf, " ");
    strncat(buf, client_ip, strlen(client_ip));
    strcat(buf, " ");
    strcat(buf, "\"");
    strncat(buf, request_line, strlen(request_line));
    strcat(buf, "\"");
    strcat(buf, " ");
    strncat(buf, code, strlen(code));
    strcat(buf, " ");
    sprintf(buf+strlen(buf), "%d", bytes);
    strcat(buf, "\n");
    fprintf(fp, buf);
    Fclose(fp);
    pthread_mutex_unlock(&log_output);
}

int gethost(char **host, char *header)
{
    int j = 0;
    char hostname[MAX_ADDRESS];
    for(int i = 0; i < strlen(header); i++)
    {
        if(header[i] == 'H' && header[i+1] == 'o' && header[i+2] == 's' &&
           header[i+3] == 't' && header[i+4] == ':' && header[i+5] == ' ')
        {
            i+=6;
            while(i < strlen(header) && header[i] != '\r' && header[i] != '\n')
            {
                hostname[j++] = header[i++];
            }
            hostname[j] = 0;
            if(strlen(hostname) > 0)
            {
                for(int k = 0; k < strlen(hostname); k++)
                {
                    if(hostname[k] == ':') hostname[k]=0;
                }
                *host = Calloc(strlen(hostname)+1, sizeof(char));
                strncpy(*host, hostname, strlen(hostname));
            }
            return 1;
        }
    }
    return -1;
}

void getagent(char *agent, char *header)
{
    for(int i = 0; i < strlen(header); i++)
    {
        if(header[i] == 'c' && header[i+1] == 'u' && header[i+2] == 'r' &&
           header[i+3] == 'l')
        {
               *agent = 'C';
               return;
        }
        else if(header[i] == 'W' && header[i+1] == 'g' && header[i+2] == 'e' &&
                header[i+3] == 't')
        {
            *agent = 'W';
            return;
        }
    }
}

void getpath(char agent, char **path, char *header)
{
    char *copy, *token;
    copy = Calloc(strlen(header), sizeof(char));
    strncpy(copy, header, strlen(header));
    token = strtok(copy+13, "/");
    token = strtok(NULL, "");
    if(token[0] == ' ')
    {
        *path = Calloc(2, sizeof(char));
        (*path)[0] = '/';
        free(copy);
        return;
    }

    token = strtok(token, " ");
    *path = Calloc(strlen(token)+2, sizeof(char));
    (*path)[0] = '/';
    strncpy(*path + 1, token, strlen(token));
    free(copy);
}

void getrequest(char **request, char *header)
{
    char req[10];
    int i = 0;
    while(i < strlen(header) && header[i] != ' ') 
    {
        req[i] = header[i];
        i++;
    }
    req[i] = 0;
    if(strlen(req) > 0)
    {
        *request = Calloc(strlen(req)+1, sizeof(char));
        strncpy(*request, req, strlen(req));
    }
}

void getport(int *port, char *header, int host_len)
{
    int j = 0;
    char port_ch[6];
    for(int i = 0; i < strlen(header); i++)
    {
        if(header[i] == 'H' && header[i+1] == 'o' && header[i+2] == 's'
           && header[i+3] == 't' && header[i+4] == ':' && header[i+5] == ' ')
        {
            i+=6;
            i+=host_len+1;
            while(isdigit(header[i]))
            {
                port_ch[j++] = header[i++];
            }
            port_ch[j] = 0;
            if(strlen(port_ch) > 0)
            {
                (*port) = atoi(port_ch);
                return;
            }
        }
    }
    *port = 443;
}

void getcode(char **code, char *header)
{
    char ch[4];
    int i = 0, j= 0;
    while(header[i] != ' ') i++;
    i++;
    while(header[i] != ' ') ch[j++] = header[i++];
    ch[j] = 0;
    (*code) = Calloc(strlen(ch)+1, sizeof(char));
    strncpy(*code, ch, strlen(ch));
}

void get_line_request(char **line, char *header)
{
    char *copy, *token;
    copy = calloc(strlen(header)+1, sizeof(char));
    strncpy(copy, header, strlen(header));
    token = strtok(copy, "\n");
    token = strtok(token, "\r");
    *line = calloc(strlen(token)+1, sizeof(char));
    strncpy(*line, token, strlen(token));
}

char **get_forbidden_sites(char *filename)
{
    char **sites, line[MAX_ADDRESS+1], *token;
    int lines = 0, i = 0;
    memset(line, 0, MAX_ADDRESS+1);

    FILE *fp = Fopen(filename, "r+");
    while(!feof(fp))
    {
        if (fgetc(fp) == '\n') lines++;
    }
    lines += 2;
    
    sites = Calloc(lines, sizeof(char*));
    fseek(fp, 0, SEEK_SET);

    while( fgets(line, MAX_ADDRESS, fp) != NULL)
    {
        if(line[0] != '\n' && line[0] != '\r')
        {
            token = strtok(line, "\n");
            token = strtok(token, "\r");
            sites[i] = Calloc(strlen(token)+1, sizeof(char));
            strncpy(sites[i], token, strlen(token));
            memset(line, 0, MAX_ADDRESS+1);
            i++;
        }
    }
    Fclose(fp);
    return sites;
}