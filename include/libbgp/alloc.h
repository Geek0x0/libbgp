#ifndef LIBBGP_ALLOC_H
#define LIBBGP_ALLOC_H

/**
 * @file alloc.h
 * @brief Global allocator hooks used by libbgp allocations.
 * @ingroup libbgp_core
 */

#include <stddef.h>
#include "libbgp/types.h"

/**
 * @brief Allocator callback table used by libbgp.
 *
 * All callbacks must behave like their C standard library equivalents.
 * Passing `NULL` to `libbgp_set_alloc()` restores `libbgp_default_alloc`.
 */
typedef struct libbgp_alloc {
    void *(*malloc)(size_t size, void *ctx);               ///< Allocate `size` bytes.
    void *(*calloc)(size_t nmemb, size_t size, void *ctx); ///< Allocate and zero `nmemb * size` bytes.
    void *(*realloc)(void *ptr, size_t size, void *ctx);   ///< Resize or free an existing allocation.
    void (*free)(void *ptr, void *ctx);                    ///< Free an allocation returned by this allocator.
    void *ctx;                                             ///< Caller-owned context passed to every callback.
} libbgp_alloc_t;

/**
 * @brief Default allocator that wraps the C standard library allocation functions.
 */
/**
 * @brief Default allocator using standard C library.
 */
LIBBGP_API extern const libbgp_alloc_t libbgp_default_alloc;

/**
 * @brief Install a custom allocator for all subsequent libbgp allocations.
 *
 * @param alloc Pointer to a caller-owned allocator table, or `NULL` to restore
 *              `libbgp_default_alloc`.
 *
 * @note Set allocator hooks before creating libbgp objects. Changing hooks
 *       while libbgp-owned objects exist can make deallocation use a different
 *       allocator than allocation.
 */
/**
 * @brief Set the allocator for libbgp.
 * @param alloc Allocator table, or NULL to restore default.
 */
LIBBGP_API void libbgp_set_alloc(const libbgp_alloc_t *alloc);

/**
 * @brief Return the currently active allocator.
 *
 * @return Pointer to the active `libbgp_alloc_t`; never `NULL`.
 */
/**
 * @brief Get the current allocator.
 * @return Current allocator table.
 */
LIBBGP_API const libbgp_alloc_t *libbgp_get_alloc(void);

/**
 * @brief Allocate memory using the active libbgp allocator.
 *
 * @param size Number of bytes to allocate.
 * @return Pointer to allocated memory, or `NULL` on failure.
 */
LIBBGP_API void *libbgp_malloc(size_t size);

/**
 * @brief Allocate zeroed memory using the active libbgp allocator.
 *
 * @param nmemb Number of elements to allocate.
 * @param size  Size of each element in bytes.
 * @return Pointer to allocated zeroed memory, or `NULL` on failure.
 */
LIBBGP_API void *libbgp_calloc(size_t nmemb, size_t size);

/**
 * @brief Resize an allocation using the active libbgp allocator.
 *
 * @param ptr  Pointer to an existing allocation, or `NULL`.
 * @param size New size in bytes.
 * @return Pointer to resized memory, or `NULL` on failure.
 */
LIBBGP_API void *libbgp_realloc(void *ptr, size_t size);

/**
 * @brief Free memory using the active libbgp allocator.
 *
 * @param ptr Pointer to memory previously returned by a libbgp allocator, or `NULL`.
 */
LIBBGP_API void libbgp_free(void *ptr);

#endif
