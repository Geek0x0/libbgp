#include "libbgp/filter.h"

#include <string.h>

#include "attr_view.h"
#include "internal.h"

#ifdef BGP_THREADSAFE
#include <pthread.h>

static pthread_mutex_t filter_acquire_lock = PTHREAD_MUTEX_INITIALIZER;

#define filter_acquire_global() pthread_mutex_lock(&filter_acquire_lock)
#define filter_release_global() pthread_mutex_unlock(&filter_acquire_lock)
#else
#define filter_acquire_global() ((void)0)
#define filter_release_global() ((void)0)
#endif

typedef struct filter_impl {
    libbgp_filter_rule_t *rules;
    size_t count;
    size_t cap;
    bgp_lock_t lock;
} filter_impl_t;

static filter_impl_t *filter_impl_get(const libbgp_filter_t *filter)
{
    return filter == NULL ? NULL : (filter_impl_t *)filter->impl;
}

static filter_impl_t *filter_impl_lock(libbgp_filter_t *filter)
{
    filter_impl_t *impl;

    filter_acquire_global();
    impl = filter_impl_get(filter);
    if (impl != NULL) {
        bgp_lock(&impl->lock);
    }
    filter_release_global();
    return impl;
}

static filter_impl_t *filter_impl_lock_const(const libbgp_filter_t *filter)
{
    return filter_impl_lock((libbgp_filter_t *)filter);
}

static bool filter_reserve(filter_impl_t *impl, size_t needed)
{
    libbgp_filter_rule_t *rules;
    size_t new_cap;

    if (needed <= impl->cap) {
        return true;
    }
    new_cap = impl->cap == 0u ? 4u : impl->cap * 2u;
    while (new_cap < needed) {
        if (new_cap > SIZE_MAX / 2u) {
            return false;
        }
        new_cap *= 2u;
    }
    if (new_cap > SIZE_MAX / sizeof(*impl->rules)) {
        return false;
    }
    rules = (libbgp_filter_rule_t *)bgp_realloc(impl->rules, new_cap * sizeof(*impl->rules));
    if (rules == NULL) {
        return false;
    }
    impl->rules = rules;
    impl->cap = new_cap;
    return true;
}

static bool as_path_contains(const libbgp_pattr_t *attr, uint32_t asn)
{
    size_t i;
    size_t j;

    if (attr == NULL ||
        (attr->type != LIBBGP_PATTR_AS_PATH && attr->type != LIBBGP_PATTR_AS4_PATH)) {
        return false;
    }
    if (attr->data.as_path.segment_count != 0u && attr->data.as_path.segments == NULL) {
        return false;
    }
    for (i = 0u; i < attr->data.as_path.segment_count; i++) {
        const libbgp_as_path_segment_t *segment = &attr->data.as_path.segments[i];
        if (segment->asn_count != 0u && segment->asns == NULL) {
            return false;
        }
        for (j = 0u; j < segment->asn_count; j++) {
            if (segment->asns[j] == asn) {
                return true;
            }
        }
    }
    return false;
}

static bool as_path_origin_asn(const libbgp_pattr_t *attr, uint32_t *origin_asn)
{
    bool found = false;
    size_t i;

    if (origin_asn != NULL) {
        *origin_asn = 0u;
    }
    if (attr == NULL ||
        (attr->type != LIBBGP_PATTR_AS_PATH && attr->type != LIBBGP_PATTR_AS4_PATH)) {
        return false;
    }
    if (attr->data.as_path.segment_count != 0u && attr->data.as_path.segments == NULL) {
        return false;
    }
    for (i = 0u; i < attr->data.as_path.segment_count; i++) {
        const libbgp_as_path_segment_t *segment = &attr->data.as_path.segments[i];

        if (segment->type != 2u || segment->asn_count == 0u) {
            continue;
        }
        if (segment->asns == NULL) {
            return false;
        }
        if (origin_asn != NULL) {
            *origin_asn = segment->asns[segment->asn_count - 1u];
        }
        found = true;
    }
    return found;
}

static bool community_contains(const libbgp_pattr_t *attr, uint32_t community)
{
    size_t i;

    if (attr == NULL || attr->type != LIBBGP_PATTR_COMMUNITY) {
        return false;
    }
    if (attr->data.community.count != 0u && attr->data.community.values == NULL) {
        return false;
    }
    for (i = 0u; i < attr->data.community.count; i++) {
        if (attr->data.community.values[i] == community) {
            return true;
        }
    }
    return false;
}

static bool attrs_have_asn(libbgp_pattr_t *const *attrs, size_t attr_count, uint32_t asn)
{
    size_t i;

    if (attr_count != 0u && attrs == NULL) {
        return false;
    }
    for (i = 0u; i < attr_count; i++) {
        if (as_path_contains(attrs[i], asn)) {
            return true;
        }
    }
    return false;
}

static bool attrs_have_community(
    libbgp_pattr_t *const *attrs,
    size_t attr_count,
    uint32_t community)
{
    size_t i;

    if (attr_count != 0u && attrs == NULL) {
        return false;
    }
    for (i = 0u; i < attr_count; i++) {
        if (community_contains(attrs[i], community)) {
            return true;
        }
    }
    return false;
}

static bool attrs_origin_asn(
    libbgp_pattr_t *const *attrs,
    size_t attr_count,
    uint32_t *origin_asn)
{
    size_t i;

    if (attr_count != 0u && attrs == NULL) {
        return false;
    }
    for (i = 0u; i < attr_count; i++) {
        if (as_path_origin_asn(attrs[i], origin_asn)) {
            return true;
        }
    }
    return false;
}

static bool attr_view_has_asn(
    const bgp_attr_view_t *attr_view,
    libbgp_pattr_t *const *attrs,
    size_t attr_count,
    uint32_t asn)
{
    const libbgp_pattr_t *as_path_attr = bgp_attr_view_get(attr_view, LIBBGP_PATTR_CODE_AS_PATH);
    const libbgp_pattr_t *as4_path_attr = bgp_attr_view_get(attr_view, LIBBGP_PATTR_CODE_AS4_PATH);

    if (attr_view->duplicate_found) {
        return attrs_have_asn(attrs, attr_count, asn);
    }
    return as_path_contains(as_path_attr, asn) || as_path_contains(as4_path_attr, asn);
}

static bool attr_view_has_community(
    const bgp_attr_view_t *attr_view,
    libbgp_pattr_t *const *attrs,
    size_t attr_count,
    uint32_t community)
{
    const libbgp_pattr_t *community_attr = bgp_attr_view_get(attr_view, LIBBGP_PATTR_CODE_COMMUNITY);

    if (attr_view->duplicate_found) {
        return attrs_have_community(attrs, attr_count, community);
    }
    return community_contains(community_attr, community);
}

static bool attr_view_origin_asn(
    const bgp_attr_view_t *attr_view,
    libbgp_pattr_t *const *attrs,
    size_t attr_count,
    uint32_t *origin_asn)
{
    const libbgp_pattr_t *as_path_attr = bgp_attr_view_get(attr_view, LIBBGP_PATTR_CODE_AS_PATH);
    const libbgp_pattr_t *as4_path_attr = bgp_attr_view_get(attr_view, LIBBGP_PATTR_CODE_AS4_PATH);

    if (attr_view->duplicate_found || (as_path_attr != NULL && as4_path_attr != NULL)) {
        return attrs_origin_asn(attrs, attr_count, origin_asn);
    }
    return as_path_origin_asn(as_path_attr, origin_asn) ||
        as_path_origin_asn(as4_path_attr, origin_asn);
}

static bool prefix4_more_specific(const libbgp_prefix4_t *rule, const libbgp_prefix4_t *route)
{
    return route->len > rule->len && libbgp_prefix4_includes(rule, route);
}

static bool prefix4_less_specific(const libbgp_prefix4_t *rule, const libbgp_prefix4_t *route)
{
    return route->len < rule->len && libbgp_prefix4_includes(route, rule);
}

static bool prefix6_more_specific(const libbgp_prefix6_t *rule, const libbgp_prefix6_t *route)
{
    return route->len > rule->len && libbgp_prefix6_includes(rule, route);
}

static bool prefix6_less_specific(const libbgp_prefix6_t *rule, const libbgp_prefix6_t *route)
{
    return route->len < rule->len && libbgp_prefix6_includes(route, rule);
}

static bool filter_rule_matches(
    const libbgp_filter_rule_t *rule,
    const libbgp_rib4_route_t *route,
    const bgp_attr_view_t *attr_view,
    libbgp_pattr_t *const *attrs,
    size_t attr_count)
{
    switch (rule->match_type) {
    case LIBBGP_FILTER_MATCH_PREFIX4:
    case LIBBGP_FILTER_MATCH_PREFIX4_MORE_OR_EQUAL:
        return libbgp_prefix4_includes(&rule->match.prefix4, &route->prefix);
    case LIBBGP_FILTER_MATCH_PREFIX4_EXACT:
        return libbgp_prefix4_eq(&rule->match.prefix4, &route->prefix);
    case LIBBGP_FILTER_MATCH_PREFIX4_MORE_SPECIFIC:
        return prefix4_more_specific(&rule->match.prefix4, &route->prefix);
    case LIBBGP_FILTER_MATCH_PREFIX4_LESS_SPECIFIC:
        return prefix4_less_specific(&rule->match.prefix4, &route->prefix);
    case LIBBGP_FILTER_MATCH_PREFIX4_LESS_OR_EQUAL:
        return libbgp_prefix4_includes(&route->prefix, &rule->match.prefix4);
    case LIBBGP_FILTER_MATCH_AS_PATH_CONTAINS:
        return attr_view_has_asn(attr_view, attrs, attr_count, rule->match.asn);
    case LIBBGP_FILTER_MATCH_AS_PATH_NOT_CONTAINS:
        return !attr_view_has_asn(attr_view, attrs, attr_count, rule->match.asn);
    case LIBBGP_FILTER_MATCH_AS_PATH_ORIGIN: {
        uint32_t origin_asn = 0u;

        return attr_view_origin_asn(attr_view, attrs, attr_count, &origin_asn) &&
            origin_asn == rule->match.asn;
    }
    case LIBBGP_FILTER_MATCH_AS_PATH_NOT_ORIGIN: {
        uint32_t origin_asn = 0u;

        return attr_view_origin_asn(attr_view, attrs, attr_count, &origin_asn) &&
            origin_asn != rule->match.asn;
    }
    case LIBBGP_FILTER_MATCH_COMMUNITY_CONTAINS:
        return attr_view_has_community(attr_view, attrs, attr_count, rule->match.community);
    case LIBBGP_FILTER_MATCH_COMMUNITY_NOT_CONTAINS:
        return !attr_view_has_community(attr_view, attrs, attr_count, rule->match.community);
    case LIBBGP_FILTER_MATCH_ANY:
        return true;
    default:
        return false;
    }
}

static bool filter_rule_matches6(
    const libbgp_filter_rule_t *rule,
    const libbgp_rib6_route_t *route,
    const bgp_attr_view_t *attr_view,
    libbgp_pattr_t *const *attrs,
    size_t attr_count)
{
    switch (rule->match_type) {
    case LIBBGP_FILTER_MATCH_PREFIX6:
    case LIBBGP_FILTER_MATCH_PREFIX6_MORE_OR_EQUAL:
        return libbgp_prefix6_includes(&rule->match.prefix6, &route->prefix);
    case LIBBGP_FILTER_MATCH_PREFIX6_EXACT:
        return libbgp_prefix6_eq(&rule->match.prefix6, &route->prefix);
    case LIBBGP_FILTER_MATCH_PREFIX6_MORE_SPECIFIC:
        return prefix6_more_specific(&rule->match.prefix6, &route->prefix);
    case LIBBGP_FILTER_MATCH_PREFIX6_LESS_SPECIFIC:
        return prefix6_less_specific(&rule->match.prefix6, &route->prefix);
    case LIBBGP_FILTER_MATCH_PREFIX6_LESS_OR_EQUAL:
        return libbgp_prefix6_includes(&route->prefix, &rule->match.prefix6);
    case LIBBGP_FILTER_MATCH_AS_PATH_CONTAINS:
        return attr_view_has_asn(attr_view, attrs, attr_count, rule->match.asn);
    case LIBBGP_FILTER_MATCH_AS_PATH_NOT_CONTAINS:
        return !attr_view_has_asn(attr_view, attrs, attr_count, rule->match.asn);
    case LIBBGP_FILTER_MATCH_AS_PATH_ORIGIN: {
        uint32_t origin_asn = 0u;

        return attr_view_origin_asn(attr_view, attrs, attr_count, &origin_asn) &&
            origin_asn == rule->match.asn;
    }
    case LIBBGP_FILTER_MATCH_AS_PATH_NOT_ORIGIN: {
        uint32_t origin_asn = 0u;

        return attr_view_origin_asn(attr_view, attrs, attr_count, &origin_asn) &&
            origin_asn != rule->match.asn;
    }
    case LIBBGP_FILTER_MATCH_COMMUNITY_CONTAINS:
        return attr_view_has_community(attr_view, attrs, attr_count, rule->match.community);
    case LIBBGP_FILTER_MATCH_COMMUNITY_NOT_CONTAINS:
        return !attr_view_has_community(attr_view, attrs, attr_count, rule->match.community);
    case LIBBGP_FILTER_MATCH_ANY:
        return true;
    default:
        return false;
    }
}

libbgp_err_t libbgp_filter_init(libbgp_filter_t *filter)
{
    filter_impl_t *impl;

    if (filter == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    filter->impl = NULL;
    impl = (filter_impl_t *)bgp_calloc(1u, sizeof(*impl));
    if (impl == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    bgp_lock_init(&impl->lock);
    filter_acquire_global();
    filter->impl = impl;
    filter_release_global();
    return LIBBGP_OK;
}

void libbgp_filter_destroy(libbgp_filter_t *filter)
{
    filter_impl_t *impl;
    libbgp_filter_rule_t *rules;

    filter_acquire_global();
    impl = filter_impl_get(filter);
    if (impl == NULL) {
        filter_release_global();
        return;
    }
    bgp_lock(&impl->lock);
    filter->impl = NULL;
    filter_release_global();

    rules = impl->rules;
    impl->rules = NULL;
    impl->count = 0u;
    impl->cap = 0u;
    bgp_unlock(&impl->lock);
    bgp_lock_destroy(&impl->lock);
    bgp_free(rules);
    bgp_free(impl);
}

libbgp_err_t libbgp_filter_add_rule(libbgp_filter_t *filter, const libbgp_filter_rule_t *rule)
{
    filter_impl_t *impl;

    if (rule == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    impl = filter_impl_lock(filter);
    if (impl == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    if (!filter_reserve(impl, impl->count + 1u)) {
        bgp_unlock(&impl->lock);
        return LIBBGP_ERR_NOMEM;
    }
    impl->rules[impl->count++] = *rule;
    bgp_unlock(&impl->lock);
    return LIBBGP_OK;
}

void libbgp_filter_clear(libbgp_filter_t *filter)
{
    filter_impl_t *impl = filter_impl_lock(filter);

    if (impl == NULL) {
        return;
    }
    impl->count = 0u;
    bgp_unlock(&impl->lock);
}

libbgp_filter_decision_t libbgp_filter_apply_route(
    const libbgp_filter_t *filter,
    const libbgp_rib4_route_t *route,
    libbgp_filter_decision_t default_decision)
{
    filter_impl_t *impl;
    libbgp_filter_decision_t decision = default_decision;
    bgp_attr_view_t attr_view;
    size_t i;

    if (route == NULL) {
        return default_decision;
    }
    bgp_attr_view_build(&attr_view, route->attrs, route->attr_count);
    impl = filter_impl_lock_const(filter);
    if (impl == NULL) {
        return default_decision;
    }
    for (i = impl->count; i > 0u; i--) {
        const libbgp_filter_rule_t *rule = &impl->rules[i - 1u];

        if (filter_rule_matches(rule, route, &attr_view, route->attrs, route->attr_count)) {
            decision = rule->decision;
            break;
        }
    }
    bgp_unlock(&impl->lock);
    return decision;
}

libbgp_filter_decision_t libbgp_filter_apply_route6(
    const libbgp_filter_t *filter,
    const libbgp_rib6_route_t *route,
    libbgp_filter_decision_t default_decision)
{
    filter_impl_t *impl;
    libbgp_filter_decision_t decision = default_decision;
    bgp_attr_view_t attr_view;
    size_t i;

    if (route == NULL) {
        return default_decision;
    }
    bgp_attr_view_build(&attr_view, route->attrs, route->attr_count);
    impl = filter_impl_lock_const(filter);
    if (impl == NULL) {
        return default_decision;
    }
    for (i = impl->count; i > 0u; i--) {
        const libbgp_filter_rule_t *rule = &impl->rules[i - 1u];

        if (filter_rule_matches6(rule, route, &attr_view, route->attrs, route->attr_count)) {
            decision = rule->decision;
            break;
        }
    }
    bgp_unlock(&impl->lock);
    return decision;
}

size_t libbgp_filter_rule_count(const libbgp_filter_t *filter)
{
    filter_impl_t *impl = filter_impl_lock_const(filter);
    size_t count;

    if (impl == NULL) {
        return 0u;
    }
    count = impl->count;
    bgp_unlock(&impl->lock);
    return count;
}
