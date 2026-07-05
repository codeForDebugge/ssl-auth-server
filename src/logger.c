#include "logger.h"
#include <time.h>
#include <stdarg.h>
#include <pthread.h>

// Global Internal State
static struct {
    FILE *file;
    LogLevel min_level;
    pthread_mutex_t mutex;
} L;

// Text representations for log levels
static const char *level_strings[] = {
    "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"
};

// ANSI Color codes for beautiful console formatting
static const char *level_colors[] = {
    "\x1b[94m", "\x1b[36m", "\x1b[32m", "\x1b[33m", "\x1b[31m", "\x1b[35m"
};

int log_init(const char *filepath, LogLevel level) {
    L.min_level = level;
    L.file = NULL;

    // Initialize the mutex to prevent log overlap in multi-threaded/epoll code
    if (pthread_mutex_init(&L.mutex, NULL) != 0) {
        return -1;
    }

    if (filepath) {
        L.file = fopen(filepath, "a"); // Append mode
        if (!L.file) {
            pthread_mutex_destroy(&L.mutex);
            return -1;
        }
    }
    return 0;
}

void log_destroy(void) {
    pthread_mutex_lock(&L.mutex);
    if (L.file) {
        fclose(L.file);
        L.file = NULL;
    }
    pthread_mutex_unlock(&L.mutex);
    pthread_mutex_destroy(&L.mutex);
}

void log_msg(LogLevel level, const char *file, int line, const char *fmt, ...) {
    // Drop logs lower than our minimum configured level
    if (level < L.min_level) return;

    pthread_mutex_lock(&L.mutex);

    // 1. Get current ISO timestamp
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_buf[26];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);

    // 2. Format and print to Console (with ANSI colors)
    fprintf(stdout, "%s %s%-5s\x1b[0m \x1b[90m[%s:%d]\x1b[0m ", 
            time_buf, level_colors[level], level_strings[level], file, line);
    
    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
    fprintf(stdout, "\n");
    fflush(stdout);

    // 3. Format and print to File (if file is configured, no colors)
    if (L.file) {
        fprintf(L.file, "%s %-5s [%s:%d] ", time_buf, level_strings[level], file, line);
        va_start(args, fmt);
        vfprintf(L.file, fmt, args);
        va_end(args);
        fprintf(L.file, "\n");
        fflush(L.file);
    }

    pthread_mutex_unlock(&L.mutex);
}
