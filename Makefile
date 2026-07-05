CC = gcc

CFLAGS = -Wall -Wextra -I./include

all: auth_server
all_debug: debug_auth_server

auth_server:
	$(CC) $(CFLAGS) \
		src/auth.c \
		src/jwt.c \
		src/logger.c \
		-o auth_server \
		-lssl   \
		-lcrypto
debug_auth_server:
	$(CC) -g $(CFLAGS) \
		src/auth.c \
		src/jwt.c \
		src/logger.h \
		-o auth_server \
		-lssl   \
		-lcrypto

clean:
	rm -f auth_server