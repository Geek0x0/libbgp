#ifndef LIBBGP_ATTR_VIEW_H
#define LIBBGP_ATTR_VIEW_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "libbgp/pattr.h"

#define BGP_ATTR_TYPE_MAX 256u

typedef struct bgp_attr_view {
    const libbgp_pattr_t *by_type[BGP_ATTR_TYPE_MAX];
    bool present[BGP_ATTR_TYPE_MAX];
    bool duplicate_found;
} bgp_attr_view_t;

static inline void bgp_attr_view_init(bgp_attr_view_t *view)
{
    memset(view, 0, sizeof(*view));
}

static inline bool bgp_attr_view_add(bgp_attr_view_t *view, const libbgp_pattr_t *attr)
{
    uint8_t code;

    if (view == NULL || attr == NULL) {
        return false;
    }
    code = attr->type_code;
    if (view->present[code]) {
        view->duplicate_found = true;
        return false;
    }
    view->present[code] = true;
    view->by_type[code] = attr;
    return true;
}

static inline const libbgp_pattr_t *bgp_attr_view_get(
    const bgp_attr_view_t *view,
    uint8_t type_code)
{
    if (view == NULL || !view->present[type_code]) {
        return NULL;
    }
    return view->by_type[type_code];
}

static inline void bgp_attr_view_build(
    bgp_attr_view_t *view,
    libbgp_pattr_t *const *attrs,
    size_t attr_count)
{
    size_t i;

    bgp_attr_view_init(view);
    if (attrs == NULL) {
        return;
    }
    for (i = 0u; i < attr_count; i++) {
        if (attrs[i] != NULL) {
            (void)bgp_attr_view_add(view, attrs[i]);
        }
    }
}

#endif
