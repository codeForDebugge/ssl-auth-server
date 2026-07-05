#ifndef JWT_H
#define JWT_H

#include <stdbool.h>

#define JWT_SECRET "MySuperSecretKey"
#define JWT_EXPIRATION_SECONDS 600

void create_jwt(const char *username,
                char *jwt,
                int jwt_size);

bool verify_jwt(
        const char *jwt,
        char *username,
        time_t *expiry);

#endif