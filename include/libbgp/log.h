#ifndef LIBBGP_LOG_H
#define LIBBGP_LOG_H

#include <stdarg.h>

#include "libbgp/types.h"

typedef enum libbgp_log_level {
    LIBBGP_LOG_ERROR = 0,
    LIBBGP_LOG_WARN  = 1,
    LIBBGP_LOG_INFO  = 2,
    LIBBGP_LOG_DEBUG = 3
} libbgp_log_level_t;

typedef void (*libbgp_log_fn)(
    libbgp_log_level_t level,
    const char *fmt,
    va_list args,
    void *ctx
);

typedef struct libbgp_logger {
    libbgp_log_fn log_fn;
    void *ctx;
    libbgp_log_level_t level;
} libbgp_logger_t;

LIBBGP_API void libbgp_logger_init(libbgp_logger_t *logger);
LIBBGP_API void libbgp_set_default_logger(const libbgp_logger_t *logger);
LIBBGP_API libbgp_logger_t *libbgp_get_default_logger(void);
LIBBGP_API void libbgp_log(libbgp_logger_t *logger, libbgp_log_level_t level, const char *fmt, ...);

#endif
