#ifndef LIBBGP_LOG_H
#define LIBBGP_LOG_H

/**
 * @file log.h
 * @brief Configurable logging callback API.
 * @ingroup libbgp_core
 */

#include <stdarg.h>

#include "libbgp/types.h"

typedef enum libbgp_log_level {
    LIBBGP_LOG_ERROR = 0, ///< Error messages indicating a failure condition.
    LIBBGP_LOG_WARN  = 1, ///< Warning messages indicating a potentially problematic condition.
    LIBBGP_LOG_INFO  = 2, ///< Informational messages about normal operation.
    LIBBGP_LOG_DEBUG = 3  ///< Detailed debug messages for troubleshooting.
} libbgp_log_level_t;

/** @brief Logging callback invoked by libbgp when a message is emitted. */
typedef void (*libbgp_log_fn)(
    libbgp_log_level_t level, ///< Severity level of the log message.
    const char *fmt,          ///< printf-style format string.
    va_list args,             ///< Arguments corresponding to `fmt`.
    void *ctx                 ///< Caller-owned context pointer.
);

/**
 * @brief Logger configuration bundling a callback, context, and minimum level.
 */
typedef struct libbgp_logger {
    libbgp_log_fn log_fn;      ///< Callback invoked for each log message.
    void *ctx;                 ///< Caller-owned context passed to `log_fn`.
    libbgp_log_level_t level;  ///< Minimum severity level for emitted messages.
} libbgp_logger_t;

/**
 * @brief Initialize a logger to the default no-op configuration.
 *
 * @param logger Logger object to initialize.
 */
LIBBGP_API void libbgp_logger_init(libbgp_logger_t *logger);

/**
 * @brief Install a logger as the process-wide default used when `NULL` is passed
 *        to `libbgp_log()`.
 *
 * @param logger Pointer to a caller-owned logger, or `NULL` to disable the default logger.
 */
LIBBGP_API void libbgp_set_default_logger(const libbgp_logger_t *logger);

/**
 * @brief Return the internal default logger object.
 *
 * In THREADSAFE=1 builds, `libbgp_set_default_logger()` and `libbgp_log(NULL, ...)`
 * synchronize their access to the default logger. Direct mutation through this
 * pointer is not synchronized; callers that need thread-safe reconfiguration
 * should install a complete logger with `libbgp_set_default_logger()`.
 *
 * @return Pointer to the default `libbgp_logger_t`; never `NULL`.
 */
LIBBGP_API libbgp_logger_t *libbgp_get_default_logger(void);

/**
 * @brief Emit a log message through the specified logger.
 *
 * @param logger Logger to use, or `NULL` to use the process-wide default logger.
 * @param level  Severity level of the message.
 * @param fmt    printf-style format string.
 * @param ...    Arguments corresponding to `fmt`.
 *
 * @note The callback is invoked synchronously from the caller's thread.
 */
LIBBGP_API void libbgp_log(libbgp_logger_t *logger, libbgp_log_level_t level, const char *fmt, ...);

#endif
