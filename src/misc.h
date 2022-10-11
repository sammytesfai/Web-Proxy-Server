#ifndef MISC_H_INCLUDE_
#define MISC_H_INCLUDE_
#include <stdint.h>
#define MAX_ADDRESS 100
#define MAX_HEADER 4096

int checkipv4(char* s);

int checknum(char* s);

void print_log(char *client_ip, char *request_line,  char *code, int bytes);

int gethost(char **host, char *header);

void getagent(char *agent, char *header);

void getpath(char agent, char **path, char *header);

void getrequest(char **request, char *header);

void getport(int *port, char *header, int host_len);

void getcode(char **code, char *header);

void get_line_request(char **line, char *header);

char **get_forbidden_sites(char *filename);

#endif