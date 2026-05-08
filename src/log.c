#include <stdarg.h>

#include "libbgp/log.h"

static libbgp_logger_t g_default_logger = {
    NULL,
    NULL,
    LIBBGP_LOG_INFO
};

void libbgp_logger_init(libbgp_logger_t *logger)
{
    if (!logger) {
        return;
    }

    logger->log_fn = NULL;
    logger->ctx = NULL;
    logger->level = LIBBGP_LOG_INFO;
}

void libbgp_set_default_logger(const libbgp_logger_t *logger)
{
    if (logger) {
        g_default_logger = *logger;
        return;
    }

    libbgp_logger_init(&g_default_logger);
}

libbgp_logger_t *libbgp_get_default_logger(void)
{
    return &g_default_logger;
}

void libbgp_log(libbgp_logger_t *logger, libbgp_log_level_t level, const char *fmt, ...)
{
    va_list args;
    libbgp_logger_t *target = logger ? logger : libbgp_get_default_logger();

    if (!target->log_fn || level > target->level || !fmt) {
        return;
    }

    va_start(args, fmt);
    target->log_fn(level, fmt, args, target->ctx);
    va_end(args);
}
