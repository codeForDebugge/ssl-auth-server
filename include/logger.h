#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>

// Log Levels
typedef enum {
    LOG_TRACE,
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR,
    LOG_FATAL
} LogLevel;

// Core Functions
int log_init(const char *filepath, LogLevel level);
void log_destroy(void);
void log_msg(LogLevel level, const char *file, int line, const char *fmt, ...);

// Public API Macros (Simplifies usage across your app)
#define LOG_TRACE(fmt, ...) log_msg(LOG_TRACE, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) log_msg(LOG_DEBUG, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)  log_msg(LOG_INFO,  __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  log_msg(LOG_WARN,  __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) log_msg(LOG_ERROR, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_FATAL(fmt, ...) log_msg(LOG_FATAL, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#endif // LOGGER_H
