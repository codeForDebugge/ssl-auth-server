#ifndef AUTH_H
#define AUTH_H

/* Open SSL includes */
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
/**************/

#include <fcntl.h>
#include <stdbool.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <signal.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "jwt.h"
#include "logger.h"
#define MAX_USERS       1000
#define MAX_SESSION     100
#define PORT            2020
#define MAX_EVENTS      128

int epfd;
typedef struct
{
    char uname[64];
    char pwd[65];
} Users;
Users users[MAX_USERS];
int userCount = 0;


bool valid_username(char user[64]);
bool validate_password(char pwd[16]);
typedef struct 
{
    int fd;
    bool is_listener;
    bool closed;
    SSL *ssl;
    bool authenticated;
    char username[64];

} Connection;

/* OpenSSL */
SSL_CTX *ctx;
//SSL *ssl;
/**************************/
#endif