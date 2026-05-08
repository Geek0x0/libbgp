#ifndef LIBBGP_ALLOC_H
#define LIBBGP_ALLOC_H

#include <stddef.h>
#include "libbgp/types.h"

typedef struct libbgp_alloc {
    void *(*malloc)(size_t size, void *ctx);
    void *(*calloc)(size_t nmemb, size_t size, void *ctx);
    void *(*realloc)(void *ptr, size_t size, void *ctx);
    void (*free)(void *ptr, void *ctx);
    void *ctx;
} libbgp_alloc_t;

LIBBGP_API extern const libbgp_alloc_t libbgp_default_alloc;

LIBBGP_API void libbgp_set_alloc(const libbgp_alloc_t *alloc);
LIBBGP_API const libbgp_alloc_t *libbgp_get_alloc(void);

LIBBGP_API void *libbgp_malloc(size_t size);
LIBBGP_API void *libbgp_calloc(size_t nmemb, size_t size);
LIBBGP_API void *libbgp_realloc(void *ptr, size_t size);
LIBBGP_API void libbgp_free(void *ptr);

#endif
