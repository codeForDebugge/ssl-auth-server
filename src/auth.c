#include "auth.h"

bool SSL_initiallization()
{
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }

    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        return false;
    }
    return true;
}
int make_socket_nonblocking(int fd)
{
    int flags =
        fcntl(fd,
              F_GETFL,
              0);

    if (flags == -1)
        return -1;

    return fcntl(fd,
                 F_SETFL,
                 flags | O_NONBLOCK);
}
void sha256_string(const char *str,
                   char output[65])
{
    unsigned char hash[SHA256_DIGEST_LENGTH];

    SHA256(
        (const unsigned char *)str,
        strlen(str),
        hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(
            output + (i * 2),
            "%02x",
            hash[i]);
    }

    output[64] = '\0';
}
bool login_user(char user[64], char pwd[16])
{
    char hash[65];
    sha256_string(pwd, hash);
    for (int i = 0; i < userCount; i++)
    {
        if (strcmp(users[i].uname, user) != 0)
            continue;

        return strcmp(users[i].pwd, hash) == 0;
    }
    return false;
}
bool register_user(char user[64], char pwd[16])
{
    printf("Register request recieved \n");
    for (int i = 0; i < userCount; i++)
    {
        if (strcmp(users[i].uname, user) == 0)
        {
            printf("User Already Register \n");
            return false;
        }
    }
    snprintf(users[userCount].uname,
             sizeof(users[userCount].uname),
             "%s",
             user);
    sha256_string(
        pwd,
        users[userCount].pwd);
    userCount += 1;

    return true;
}
void handleSend(Connection *conn, char *msg, size_t msg_len)
{
    int written = SSL_write(conn->ssl, msg, msg_len);
    if (written <= 0)
    {
        // Get the specific OpenSSL error code
        int ssl_err = SSL_get_error(conn->ssl, written);

        switch (ssl_err)
        {
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_READ:
            // Non-blocking socket needs to try again.
            // Do NOT consider this a fatal error.
            // Re-try SSL_write() with the EXACT same arguments when ready.
            break;

        case SSL_ERROR_ZERO_RETURN:
            // The TLS/SSL peer closed the connection gracefully (sent a close_notify alert)
            printf("Connection closed gracefully by peer.\n");
            // Clean up your socket/connection here
            connection_destroy(conn);
            break;

        case SSL_ERROR_SYSCALL:
            // An underlying I/O error occurred (check errno)
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                // Socket buffer full (non-blocking mode)
            }
            else
            {
                perror("Fatal system/socket error during SSL_write");
                connection_destroy(conn);
                // Clean up and close connection
            }
            break;

        case SSL_ERROR_SSL:
            // A fatal OpenSSL protocol error occurred (e.g., handshake failure, bad certificate)
            fprintf(stderr, "Fatal OpenSSL protocol error.\n");
            // Optional: Print details using ERR_print_errors_fp(stderr);
            // Clean up and close connection
            connection_destroy(conn);
            break;

        default:
            // Other fatal errors
            fprintf(stderr, "Unknown fatal SSL error: %d\n", ssl_err);
            // Clean up and close connection
            connection_destroy(conn);
            break;
        }
    }
    else
    {
        // Success: 'written' contains the number of bytes successfully sent
        LOG_INFO("Successfully wrote %d bytes.\n", written);
    }
}
bool checkUser(Connection *conn,
               char buffer[])
{
    char cmd[32] = {};
    char jwt[1024];
    int ret = sscanf(buffer, "%31s ", cmd);

    if (ret != 1)
        return false;
    if ((strcasecmp(cmd, "Login") == 0) || (strcasecmp(cmd, "Register") == 0))
    {
        char user[64];
        char pwd[16];
        char msg[64];
        if (sscanf(buffer, "%31s %15s %15s", cmd, user, pwd) != 3)
        {
            snprintf(msg, sizeof(msg), "Invalid Arguments \n");
            handleSend(conn, msg, strlen(msg));
            return false;
        }
        if (strcasecmp(cmd, "Login") == 0)
        {
            LOG_INFO("Login request recieved");
            if (login_user(user, pwd))
            {
                LOG_INFO("User = %s Logged in ",user);
                create_jwt(user, jwt, sizeof(jwt));
                handleSend(conn, jwt, strlen(jwt));
                return true;
            }
            snprintf(msg, sizeof(msg), "Logged-in Failed");
            handleSend(conn, msg, strlen(msg));
            LOG_WARN("Login request failed");
            return false;
        }
        else if (strcasecmp(cmd, "register") == 0)
        {
            LOG_INFO("Register request recieved");
            if (!valid_username(user))
            {
                LOG_WARN("User = %s is not valid", user);
                snprintf(msg, sizeof(msg), "user = %s not valid ", user);
                handleSend(conn, msg, strlen(msg));
                return false;
            }
            if (!validate_password(pwd))
            {
                LOG_WARN("User = %s has invalid paasword", user);
                snprintf(msg, sizeof(msg), "password = %s not valid ", user);
                handleSend(conn, msg, strlen(msg));
                return false;
            }
            if (register_user(user, pwd))
            {
                LOG_INFO("User = %s has registered", user);
                snprintf(msg, sizeof(msg), "Registered user = %s ", user);
                handleSend(conn, msg, strlen(msg));
                return true;
            }
            LOG_WARN("Register failed", user);
            return false;
        }
    }
    else if (strcasecmp(cmd, "Token") == 0)
    {
        char jwt_token[1024];
        char username[64];
        sscanf(buffer, "%31s %1063s", cmd, jwt_token);
        time_t expiry;
        if (!verify_jwt(jwt_token, username, &expiry))
        {
            handleSend(conn, "Invalid Token", 13);
            return false;
        }
        LOG_INFO("Authenticated user = %s\n", username);
        return true;
    }
    return false;
}
void handleRecv(Connection *conn)
{
    char response[1500];
    memset(response, 0, sizeof(response));

    int client_fd = conn->fd;
    conn->is_listener = false;
    int n = SSL_read(conn->ssl, response, sizeof(response) - 1);

    if (n > 0)
    {
        response[n] = '\0';
        checkUser(conn, response);
        return;
    }
    else
    {
        int err = SSL_get_error(conn->ssl, n);

        if (err == SSL_ERROR_WANT_READ ||
            err == SSL_ERROR_WANT_WRITE)
        {
            return;
        }
        LOG_INFO("Connection closed");
        connection_destroy(conn);
    }
}
volatile sig_atomic_t running = 1;
void signal_handler(int sig)
{
    running = 0;
}
void connection_destroy(Connection *conn)
{
    if (conn == NULL)
        return;

    if (conn->closed)
        return;

    conn->closed = true;

    epoll_ctl(epfd, EPOLL_CTL_DEL, conn->fd, NULL);

    if (conn->ssl)
    {
        SSL_shutdown(conn->ssl);
        SSL_free(conn->ssl);
    }

    if (conn->fd >= 0)
        close(conn->fd);
    free(conn);
}
bool valid_username(char user[64])
{
    size_t len = strlen(user);

    if (len < 3 || len > 32)
        return false;

    for (size_t i = 0; i < len; i++)
    {
        if (!isalnum(user[i]) &&
            user[i] != '_' &&
            user[i] != '-')
        {
            return false;
        }
    }

    return true;
}
bool validate_password(char pwd[16])
{
    if (pwd == NULL)
    {
        return false;
    }
    int len = strlen(pwd);

    if (len <= 3)
    {
        return false;
    }

    bool has_upper = false;
    bool has_lower = false;
    bool has_digit = false;
    bool has_special = false;

    for (size_t i = 0; i < len; i++)
    {
        unsigned char ch = pwd[i]; // Cast to avoid undefined behavior in ctype functions

        if (isupper(ch))
        {
            has_upper = true;
        }
        else if (islower(ch))
        {
            has_lower = true;
        }
        else if (isdigit(ch))
        {
            has_digit = true;
        }
        else if (ispunct(ch))
        {
            // ispunct checks for printable punctuation characters like !, @, #, $, etc.
            has_special = true;
        }
    }

    // Return true only if all security conditions are satisfied
    return (has_upper && has_lower && has_digit && has_special);
}
int main()
{
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    if (log_init("app.log", LOG_INFO) != 0)
    {
        fprintf(stderr, "Failed to initialize logging system\n");
        return 1;
    }

    if (!SSL_initiallization())
    {
        LOG_ERROR("SSL_initiallization Failed");
        return 1;
    }
    Connection *conn = malloc(sizeof(Connection));
    memset(conn, 0, sizeof(Connection));
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0)
    {
        free(conn);
        LOG_ERROR("Socket creation failed ");
        perror(fd);
        return 0;
    }

    conn->fd = fd;
    conn->is_listener = true;
    conn->closed = false;
    struct sockaddr_in authserver_addr;
    memset(&authserver_addr, 0, sizeof(authserver_addr));
    make_socket_nonblocking(fd);
    authserver_addr.sin_family = AF_INET;
    authserver_addr.sin_addr.s_addr = INADDR_ANY;
    authserver_addr.sin_port = htons(PORT);

    int opt = 1;

    setsockopt(fd,
               SOL_SOCKET,
               SO_REUSEADDR,
               &opt,
               sizeof(opt));

    if (bind(fd, (struct sockaddr *)(&authserver_addr), sizeof(authserver_addr)) < 0)
    {
        LOG_ERROR("Bind creation failed ");
        perror("Bind");
        return 0;
    }

    if (listen(fd, 5) < 0)
    {
        LOG_ERROR("Listen failed ");
        return 0;
    }
    epfd = epoll_create1(0);
    if (epfd < 0)
    {
        perror("epoll_create1");
        return 1;
    }

    struct epoll_event ev;
    struct epoll_event events[MAX_EVENTS];

    ev.events = EPOLLIN;
    ev.data.ptr = conn;

    epoll_ctl(epfd,
              EPOLL_CTL_ADD,
              conn->fd,
              &ev);
    LOG_INFO("Server starting up on port %d...", 2020);
    while (running)
    {
        int ready = epoll_wait(epfd, events, MAX_EVENTS, -1);
        LOG_DEBUG("Eopll wait ready = %d",ready);
        for (int i = 0; i < ready; i++)
        {
            // int client_fd = events[i].data.fd;
            Connection *conn = events[i].data.ptr;

            if (conn->is_listener)
            {
                int client_fd = accept(conn->fd, NULL, NULL);
                if (client_fd < 0)
                {
                    perror("accept");
                    continue;
                }
                /* beginning SSL Handshake */
                SSL *ssl = SSL_new(ctx);

                if (ssl == NULL)
                {
                    ERR_print_errors_fp(stderr);
                    close(client_fd);
                    continue;
                }
                if (!SSL_set_fd(ssl, client_fd))
                {
                    ERR_print_errors_fp(stderr);
                    SSL_free(ssl);
                    close(client_fd);
                    continue;
                }
                if (SSL_accept(ssl) <= 0)
                {
                    ERR_print_errors_fp(stderr);
                    SSL_free(ssl);
                    close(client_fd);
                    continue;
                }
                LOG_INFO("TLS Handshake successful");
                /* End SSL Handshake */

                Connection *client = malloc(sizeof(Connection));
                memset(client, 0, sizeof(Connection));
                client->fd = client_fd;
                client->ssl = ssl;
                client->closed = false;
                make_socket_nonblocking(client_fd);
                ev.events = EPOLLIN;
                ev.data.ptr = client;

                epoll_ctl(epfd,
                          EPOLL_CTL_ADD,
                          client->fd,
                          &ev);
            }
            else
            {
                handleRecv(conn);
            }
        }
    }
    connection_destroy(conn);
    SSL_CTX_free(ctx);
    close(epfd);
    return 1;
}