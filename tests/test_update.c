#include "test_main.h"

#include "fixtures/bgp_packets.h"

#include "libbgp/update.h"
#include "libbgp/types.h"
#include "libbgp/alloc.h"

#include <stdlib.h>

static libbgp_pattr_t *make_as_path_attr(libbgp_pattr_type_t type, bool is_4b, const uint32_t *asns, size_t count)
{
    libbgp_pattr_t *attr = libbgp_pattr_new(type);

    LIBBGP_ASSERT(attr != NULL);
    attr->data.as_path.segment_count = 1u;
    attr->data.as_path.is_4b = is_4b;
    attr->data.as_path.segments = (libbgp_as_path_segment_t *)calloc(1u, sizeof(attr->data.as_path.segments[0]));
    LIBBGP_ASSERT(attr->data.as_path.segments != NULL);
    attr->data.as_path.segments[0].type = 2u;
    attr->data.as_path.segments[0].asn_count = count;
    if (count != 0u) {
        attr->data.as_path.segments[0].asns = (uint32_t *)calloc(count, sizeof(attr->data.as_path.segments[0].asns[0]));
        LIBBGP_ASSERT(attr->data.as_path.segments[0].asns != NULL);
        memcpy(attr->data.as_path.segments[0].asns, asns, count * sizeof(asns[0]));
    }
    return attr;
}

static uint32_t update_ip4(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    uint8_t bytes[4];
    uint32_t value;

    bytes[0] = a;
    bytes[1] = b;
    bytes[2] = c;
    bytes[3] = d;
    memcpy(&value, bytes, sizeof(value));
    return value;
}

static size_t test_as_path_asn_count(const libbgp_pattr_t *attr)
{
    size_t count = 0u;
    size_t i;

    LIBBGP_ASSERT(attr != NULL);
    for (i = 0u; i < attr->data.as_path.segment_count; i++) {
        count += attr->data.as_path.segments[i].asn_count;
    }
    return count;
}

static uint32_t test_as_path_asn_at(const libbgp_pattr_t *attr, size_t index)
{
    size_t base = 0u;
    size_t i;

    LIBBGP_ASSERT(attr != NULL);
    for (i = 0u; i < attr->data.as_path.segment_count; i++) {
        const libbgp_as_path_segment_t *segment = &attr->data.as_path.segments[i];

        if (index < base + segment->asn_count) {
            return segment->asns[index - base];
        }
        base += segment->asn_count;
    }
    LIBBGP_ASSERT(0);
    return 0u;
}

static libbgp_pattr_t *make_as_path_attr_segments(
    libbgp_pattr_type_t type,
    bool is_4b,
    const uint8_t *segment_types,
    const uint32_t *const *segment_asns,
    const size_t *segment_counts,
    size_t segment_count)
{
    libbgp_pattr_t *attr = libbgp_pattr_new(type);
    size_t i;

    LIBBGP_ASSERT(attr != NULL);
    attr->data.as_path.segment_count = segment_count;
    attr->data.as_path.is_4b = is_4b;
    if (segment_count == 0u) {
        return attr;
    }
    attr->data.as_path.segments = (libbgp_as_path_segment_t *)calloc(segment_count, sizeof(attr->data.as_path.segments[0]));
    LIBBGP_ASSERT(attr->data.as_path.segments != NULL);
    for (i = 0u; i < segment_count; i++) {
        attr->data.as_path.segments[i].type = segment_types[i];
        attr->data.as_path.segments[i].asn_count = segment_counts[i];
        if (segment_counts[i] != 0u) {
            LIBBGP_ASSERT(segment_asns[i] != NULL);
            attr->data.as_path.segments[i].asns = (uint32_t *)calloc(segment_counts[i], sizeof(attr->data.as_path.segments[i].asns[0]));
            LIBBGP_ASSERT(attr->data.as_path.segments[i].asns != NULL);
            memcpy(attr->data.as_path.segments[i].asns, segment_asns[i], segment_counts[i] * sizeof(segment_asns[i][0]));
        }
    }
    return attr;
}

typedef struct update_fail_realloc_ctx {
    size_t realloc_calls;
    size_t fail_on_realloc;
} update_fail_realloc_ctx_t;

typedef struct update_fail_alloc_ctx {
    size_t malloc_calls;
    size_t calloc_calls;
    size_t realloc_calls;
    size_t fail_on_malloc;
    size_t fail_on_calloc;
    size_t fail_on_realloc;
} update_fail_alloc_ctx_t;

static void *update_fail_realloc_malloc(size_t size, void *ctx)
{
    (void)ctx;
    return malloc(size);
}

static void *update_fail_realloc_calloc(size_t nmemb, size_t size, void *ctx)
{
    (void)ctx;
    return calloc(nmemb, size);
}

static void *update_fail_realloc_realloc(void *ptr, size_t size, void *ctx)
{
    update_fail_realloc_ctx_t *fail = (update_fail_realloc_ctx_t *)ctx;

    fail->realloc_calls++;
    if (fail->realloc_calls == fail->fail_on_realloc) {
        return NULL;
    }
    return realloc(ptr, size);
}

static void update_fail_realloc_free(void *ptr, void *ctx)
{
    (void)ctx;
    free(ptr);
}

static libbgp_alloc_t update_fail_realloc_make(update_fail_realloc_ctx_t *ctx)
{
    libbgp_alloc_t alloc;

    alloc.malloc = update_fail_realloc_malloc;
    alloc.calloc = update_fail_realloc_calloc;
    alloc.realloc = update_fail_realloc_realloc;
    alloc.free = update_fail_realloc_free;
    alloc.ctx = ctx;
    return alloc;
}

static void *update_fail_alloc_malloc(size_t size, void *ctx)
{
    update_fail_alloc_ctx_t *fail = (update_fail_alloc_ctx_t *)ctx;

    fail->malloc_calls++;
    if (fail->fail_on_malloc != 0u && fail->malloc_calls == fail->fail_on_malloc) {
        return NULL;
    }
    return malloc(size);
}

static void *update_fail_alloc_calloc(size_t nmemb, size_t size, void *ctx)
{
    update_fail_alloc_ctx_t *fail = (update_fail_alloc_ctx_t *)ctx;

    fail->calloc_calls++;
    if (fail->fail_on_calloc != 0u && fail->calloc_calls == fail->fail_on_calloc) {
        return NULL;
    }
    return calloc(nmemb, size);
}

static void *update_fail_alloc_realloc(void *ptr, size_t size, void *ctx)
{
    update_fail_alloc_ctx_t *fail = (update_fail_alloc_ctx_t *)ctx;

    fail->realloc_calls++;
    if (fail->fail_on_realloc != 0u && fail->realloc_calls == fail->fail_on_realloc) {
        return NULL;
    }
    return realloc(ptr, size);
}

static void update_fail_alloc_free(void *ptr, void *ctx)
{
    (void)ctx;
    free(ptr);
}

static libbgp_alloc_t update_fail_alloc_make(update_fail_alloc_ctx_t *ctx)
{
    libbgp_alloc_t alloc;

    alloc.malloc = update_fail_alloc_malloc;
    alloc.calloc = update_fail_alloc_calloc;
    alloc.realloc = update_fail_alloc_realloc;
    alloc.free = update_fail_alloc_free;
    alloc.ctx = ctx;
    return alloc;
}

static libbgp_pattr_t *make_aggregator_attr(libbgp_pattr_type_t type, uint32_t asn, uint32_t router_id, bool is_4b)
{
    libbgp_pattr_t *attr = libbgp_pattr_new(type);

    LIBBGP_ASSERT(attr != NULL);
    attr->data.aggregator.asn = asn;
    attr->data.aggregator.router_id = router_id;
    attr->data.aggregator.is_4b = is_4b;
    return attr;
}

LIBBGP_TEST(update_parse_write_empty_fixture_body)
{
    const uint8_t *body = LIBBGP_FIXTURE_UPDATE_EMPTY + LIBBGP_BGP_HEADER_LEN;
    const size_t body_len = LIBBGP_FIXTURE_UPDATE_EMPTY_LEN - LIBBGP_BGP_HEADER_LEN;
    uint8_t out[16];
    size_t used = 0u;
    size_t out_len = 0u;
    libbgp_update_msg_t msg;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_parse(&msg, body, body_len, &used));
    LIBBGP_ASSERT_EQ_U64(body_len, used);
    LIBBGP_ASSERT_EQ_U64(0u, msg.withdrawn_count);
    LIBBGP_ASSERT_EQ_U64(0u, msg.attr_count);
    LIBBGP_ASSERT_EQ_U64(0u, msg.nlri_count);
    LIBBGP_ASSERT(libbgp_update_find_attr(&msg, LIBBGP_PATTR_ORIGIN) == NULL);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_write(&msg, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(body_len, out_len);
    LIBBGP_ASSERT_BYTES_EQ(body, out, body_len);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_parse_write_with_withdrawn_attrs_and_nlri)
{
    const uint8_t body[] = {
        0u, 4u,
        24u, 198u, 51u, 100u,
        0u, 18u,
        0x40u, 1u, 1u, 0u,
        0x40u, 2u, 4u, 2u, 1u, 0xfdu, 0xe8u,
        0x40u, 3u, 4u, 192u, 0u, 2u, 254u,
        24u, 203u, 0u, 113u
    };
    uint8_t out[64];
    size_t used = 0u;
    size_t out_len = 0u;
    libbgp_update_msg_t msg;
    libbgp_pattr_t *origin;
    libbgp_pattr_t *as_path;
    libbgp_pattr_t *next_hop;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_parse(&msg, body, sizeof(body), &used));
    LIBBGP_ASSERT_EQ_U64(sizeof(body), used);
    LIBBGP_ASSERT_EQ_U64(1u, msg.withdrawn_count);
    LIBBGP_ASSERT_EQ_U64(3u, msg.attr_count);
    LIBBGP_ASSERT_EQ_U64(1u, msg.nlri_count);
    LIBBGP_ASSERT_EQ_U64(24u, msg.withdrawn[0].len);
    LIBBGP_ASSERT_EQ_U64(24u, msg.nlri[0].len);

    origin = libbgp_update_find_attr(&msg, LIBBGP_PATTR_ORIGIN);
    as_path = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    next_hop = libbgp_update_find_attr(&msg, LIBBGP_PATTR_NEXT_HOP);
    LIBBGP_ASSERT(origin != NULL);
    LIBBGP_ASSERT(as_path != NULL);
    LIBBGP_ASSERT(next_hop != NULL);
    LIBBGP_ASSERT_EQ_U64(0u, origin->data.origin.origin);
    {
        const uint8_t expected_next_hop[] = { 192u, 0u, 2u, 254u };
        uint8_t stored_next_hop[4];

        memcpy(stored_next_hop, &next_hop->data.next_hop.next_hop, sizeof(stored_next_hop));
        LIBBGP_ASSERT_EQ_U64(65000u, as_path->data.as_path.segments[0].asns[0]);
        LIBBGP_ASSERT_BYTES_EQ(expected_next_hop, stored_next_hop, sizeof(expected_next_hop));
    }

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_write(&msg, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(sizeof(body), out_len);
    LIBBGP_ASSERT_BYTES_EQ(body, out, sizeof(body));
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_parse_write_withdraw_only_without_mandatory_attrs)
{
    const uint8_t body[] = {
        0u, 4u,
        24u, 198u, 51u, 100u,
        0u, 0u
    };
    uint8_t out[16];
    size_t used = 0u;
    size_t out_len = 0u;
    libbgp_update_msg_t msg;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_parse(&msg, body, sizeof(body), &used));
    LIBBGP_ASSERT_EQ_U64(sizeof(body), used);
    LIBBGP_ASSERT_EQ_U64(1u, msg.withdrawn_count);
    LIBBGP_ASSERT_EQ_U64(0u, msg.attr_count);
    LIBBGP_ASSERT_EQ_U64(0u, msg.nlri_count);
    LIBBGP_ASSERT_EQ_U64(24u, msg.withdrawn[0].len);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_validate(&msg));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_write(&msg, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(sizeof(body), out_len);
    LIBBGP_ASSERT_BYTES_EQ(body, out, sizeof(body));
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_parse_rejects_ipv4_prefix_length_over_32)
{
    const uint8_t bad_withdrawn[] = {
        0u, 6u,
        33u, 198u, 51u, 100u, 0u,
        0u, 0u
    };
    const uint8_t bad_nlri[] = {
        0u, 0u,
        0u, 18u,
        0x40u, 1u, 1u, 0u,
        0x40u, 2u, 4u, 2u, 1u, 0xfdu, 0xe8u,
        0x40u, 3u, 4u, 192u, 0u, 2u, 254u,
        33u, 203u, 0u, 113u, 0u
    };
    size_t used = 0u;
    libbgp_update_msg_t msg;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_update_parse(&msg, bad_withdrawn, sizeof(bad_withdrawn), &used));
    LIBBGP_ASSERT_EQ_U64(0u, msg.withdrawn_count);
    libbgp_update_destroy(&msg);

    used = 0u;
    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_update_parse(&msg, bad_nlri, sizeof(bad_nlri), &used));
    LIBBGP_ASSERT_EQ_U64(0u, msg.nlri_count);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_rejects_duplicate_attrs_and_missing_mandatory_attrs)
{
    const uint8_t missing_as_path_body[] = {
        0u, 0u,
        0u, 11u,
        0x40u, 1u, 1u, 0u,
        0x40u, 3u, 4u, 192u, 0u, 2u, 254u,
        24u, 203u, 0u, 113u
    };
    uint8_t out[64];
    size_t marker = 99u;
    libbgp_prefix4_t nlri;
    libbgp_update_msg_t msg;
    libbgp_pattr_t *origin = libbgp_pattr_new(LIBBGP_PATTR_ORIGIN);
    libbgp_pattr_t *duplicate_origin = libbgp_pattr_new(LIBBGP_PATTR_ORIGIN);

    LIBBGP_ASSERT(origin != NULL);
    LIBBGP_ASSERT(duplicate_origin != NULL);
    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, origin));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_EXISTS, libbgp_update_add_attr(&msg, duplicate_origin));
    LIBBGP_ASSERT_EQ_U64(1u, msg.attr_count);
    libbgp_update_destroy(&msg);

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID,
        libbgp_update_parse(&msg, missing_as_path_body, sizeof(missing_as_path_body), &marker));
    LIBBGP_ASSERT_EQ_U64(99u, marker);
    nlri.addr = 0x7100cbu;
    nlri.len = 24u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_nlri(&msg, &nlri));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_update_validate(&msg));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_update_write(&msg, out, sizeof(out), &marker));

    libbgp_pattr_unref(duplicate_origin);
    libbgp_pattr_unref(origin);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_parse_as4_reads_four_octet_as_path_and_aggregator)
{
    const uint8_t body[] = {
        0u, 0u,
        0u, 24u,
        0x40u, 2u, 10u, 2u, 2u,
        0u, 0u, 0xfdu, 0xe8u,
        0u, 1u, 0u, 2u,
        0xc0u, 7u, 8u, 0u, 1u, 0u, 1u, 198u, 51u, 100u, 1u
    };
    uint8_t out[64];
    size_t used = 0u;
    size_t out_len = 0u;
    libbgp_update_msg_t msg;
    libbgp_pattr_t *as_path;
    libbgp_pattr_t *aggregator;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_parse_as4(&msg, body, sizeof(body), true, &used));
    LIBBGP_ASSERT_EQ_U64(sizeof(body), used);
    as_path = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    aggregator = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AGGREGATOR);
    LIBBGP_ASSERT(as_path != NULL);
    LIBBGP_ASSERT(aggregator != NULL);
    LIBBGP_ASSERT(as_path->data.as_path.is_4b);
    LIBBGP_ASSERT_EQ_U64(65538u, as_path->data.as_path.segments[0].asns[1]);
    LIBBGP_ASSERT(aggregator->data.aggregator.is_4b);
    LIBBGP_ASSERT_EQ_U64(65537u, aggregator->data.aggregator.asn);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_write(&msg, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(sizeof(body), out_len);
    LIBBGP_ASSERT_BYTES_EQ(body, out, sizeof(body));
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_as4_helpers_restore_downgrade_prepend_and_aggregator)
{
    uint32_t asns[] = { 65000u, 65537u };
    libbgp_update_msg_t msg;
    libbgp_pattr_t *as_path = make_as_path_attr(LIBBGP_PATTR_AS_PATH, true, asns, LIBBGP_ARRAY_LEN(asns));
    libbgp_pattr_t *aggregator = make_aggregator_attr(LIBBGP_PATTR_AGGREGATOR, 65537u, 0xc6336401u, true);
    libbgp_pattr_t *found;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, aggregator));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_downgrade_as_path(&msg));
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT(!found->data.as_path.is_4b);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_AS_TRANS, found->data.as_path.segments[0].asns[1]);
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS4_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT(found->data.as_path.is_4b);
    LIBBGP_ASSERT_EQ_U64(1u, found->data.as_path.segments[0].asn_count);
    LIBBGP_ASSERT_EQ_U64(65537u, found->data.as_path.segments[0].asns[0]);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_restore_as_path(&msg));
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT(found->data.as_path.is_4b);
    LIBBGP_ASSERT_EQ_U64(2u, found->data.as_path.segment_count);
    LIBBGP_ASSERT_EQ_U64(65000u, found->data.as_path.segments[0].asns[0]);
    LIBBGP_ASSERT_EQ_U64(65537u, found->data.as_path.segments[1].asns[0]);
    LIBBGP_ASSERT(libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS4_PATH) == NULL);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_prepend_asn(&msg, 65538u, true));
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(2u, found->data.as_path.segments[0].asn_count);
    LIBBGP_ASSERT_EQ_U64(65538u, found->data.as_path.segments[0].asns[0]);
    LIBBGP_ASSERT_EQ_U64(65000u, found->data.as_path.segments[0].asns[1]);
    LIBBGP_ASSERT_EQ_U64(65537u, found->data.as_path.segments[1].asns[0]);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_downgrade_aggregator(&msg));
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AGGREGATOR);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT(!found->data.aggregator.is_4b);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_AS_TRANS, found->data.aggregator.asn);
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS4_AGGREGATOR);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(65537u, found->data.aggregator.asn);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_restore_aggregator(&msg));
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AGGREGATOR);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT(found->data.aggregator.is_4b);
    LIBBGP_ASSERT_EQ_U64(65537u, found->data.aggregator.asn);

    libbgp_pattr_unref(aggregator);
    libbgp_pattr_unref(as_path);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_prepend_asn_creates_missing_two_octet_as_path)
{
    libbgp_update_msg_t msg;
    libbgp_pattr_t *found;

    libbgp_update_init(&msg);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_prepend_asn(&msg, 65538u, false));
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT(!found->data.as_path.is_4b);
    LIBBGP_ASSERT_EQ_U64(1u, found->data.as_path.segment_count);
    LIBBGP_ASSERT_EQ_U64(1u, found->data.as_path.segments[0].asn_count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_AS_TRANS, found->data.as_path.segments[0].asns[0]);

    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_prepend_asn_creates_missing_four_octet_as_path)
{
    libbgp_update_msg_t msg;
    libbgp_pattr_t *found;

    libbgp_update_init(&msg);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_prepend_asn(&msg, 65538u, true));
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT(found->data.as_path.is_4b);
    LIBBGP_ASSERT_EQ_U64(1u, found->data.as_path.segment_count);
    LIBBGP_ASSERT_EQ_U64(1u, found->data.as_path.segments[0].asn_count);
    LIBBGP_ASSERT_EQ_U64(65538u, found->data.as_path.segments[0].asns[0]);

    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_prepend_asn_rejects_four_octet_mode_when_as4_path_exists)
{
    uint32_t path_asns[] = { 64512u };
    uint32_t as4_asns[] = { 65538u };
    libbgp_update_msg_t msg;
    libbgp_pattr_t *as_path = make_as_path_attr(LIBBGP_PATTR_AS_PATH, false, path_asns, 1u);
    libbgp_pattr_t *as4_path = make_as_path_attr(LIBBGP_PATTR_AS4_PATH, true, as4_asns, 1u);
    libbgp_pattr_t *found;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as4_path));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_update_prepend_asn(&msg, 65539u, true));
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(1u, found->data.as_path.segment_count);
    LIBBGP_ASSERT_EQ_U64(64512u, found->data.as_path.segments[0].asns[0]);
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS4_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(1u, found->data.as_path.segment_count);
    LIBBGP_ASSERT_EQ_U64(65538u, found->data.as_path.segments[0].asns[0]);

    libbgp_pattr_unref(as4_path);
    libbgp_pattr_unref(as_path);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_prepend_asn_rejects_as_path_width_mismatch)
{
    uint32_t path_asns[] = { 65538u };
    libbgp_update_msg_t msg;
    libbgp_pattr_t *as_path = make_as_path_attr(LIBBGP_PATTR_AS_PATH, true, path_asns, 1u);
    libbgp_pattr_t *found;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_update_prepend_asn(&msg, 65539u, false));
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT(found->data.as_path.is_4b);
    LIBBGP_ASSERT_EQ_U64(1u, found->data.as_path.segment_count);
    LIBBGP_ASSERT_EQ_U64(65538u, found->data.as_path.segments[0].asns[0]);

    libbgp_pattr_unref(as_path);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_restore_as_path_replaces_as_trans_positionally_when_counts_match)
{
    uint32_t path_asns[] = { 65000u, LIBBGP_AS_TRANS, 64496u };
    uint32_t as4_asns[] = { 65000u, 65537u, 64496u };
    libbgp_update_msg_t msg;
    libbgp_pattr_t *as_path = make_as_path_attr(LIBBGP_PATTR_AS_PATH, false, path_asns, 3u);
    libbgp_pattr_t *as4_path = make_as_path_attr(LIBBGP_PATTR_AS4_PATH, true, as4_asns, 3u);
    libbgp_pattr_t *found;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as4_path));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_restore_as_path(&msg));
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT(found->data.as_path.is_4b);
    LIBBGP_ASSERT_EQ_U64(1u, found->data.as_path.segment_count);
    LIBBGP_ASSERT_EQ_U64(3u, found->data.as_path.segments[0].asn_count);
    LIBBGP_ASSERT_EQ_U64(65000u, found->data.as_path.segments[0].asns[0]);
    LIBBGP_ASSERT_EQ_U64(65537u, found->data.as_path.segments[0].asns[1]);
    LIBBGP_ASSERT_EQ_U64(64496u, found->data.as_path.segments[0].asns[2]);
    LIBBGP_ASSERT(libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS4_PATH) == NULL);

    libbgp_pattr_unref(as4_path);
    libbgp_pattr_unref(as_path);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_restore_as_path_consumes_as4_path_only_for_as_trans_when_counts_differ)
{
    uint32_t path_asns[] = { LIBBGP_AS_TRANS, 64496u, LIBBGP_AS_TRANS };
    uint32_t as4_asns[] = { 65537u, 65538u };
    libbgp_update_msg_t msg;
    libbgp_pattr_t *as_path = make_as_path_attr(LIBBGP_PATTR_AS_PATH, false, path_asns, 3u);
    libbgp_pattr_t *as4_path = make_as_path_attr(LIBBGP_PATTR_AS4_PATH, true, as4_asns, 2u);
    libbgp_pattr_t *found;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as4_path));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_restore_as_path(&msg));
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT(found->data.as_path.is_4b);
    LIBBGP_ASSERT_EQ_U64(3u, test_as_path_asn_count(found));
    LIBBGP_ASSERT_EQ_U64(65537u, test_as_path_asn_at(found, 0u));
    LIBBGP_ASSERT_EQ_U64(64496u, test_as_path_asn_at(found, 1u));
    LIBBGP_ASSERT_EQ_U64(65538u, test_as_path_asn_at(found, 2u));
    LIBBGP_ASSERT(libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS4_PATH) == NULL);

    libbgp_pattr_unref(as4_path);
    libbgp_pattr_unref(as_path);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_restore_as_path_falls_back_to_suffix_when_sparse_counts_differ)
{
    uint32_t path_asns[] = { LIBBGP_AS_TRANS, 64500u, LIBBGP_AS_TRANS, LIBBGP_AS_TRANS };
    uint32_t as4_asns[] = { 65537u, 65538u };
    libbgp_update_msg_t msg;
    libbgp_pattr_t *as_path = make_as_path_attr(LIBBGP_PATTR_AS_PATH, false, path_asns, 4u);
    libbgp_pattr_t *as4_path = make_as_path_attr(LIBBGP_PATTR_AS4_PATH, true, as4_asns, 2u);
    libbgp_pattr_t *found;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as4_path));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_restore_as_path(&msg));
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT(found->data.as_path.is_4b);
    LIBBGP_ASSERT_EQ_U64(4u, test_as_path_asn_count(found));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_AS_TRANS, test_as_path_asn_at(found, 0u));
    LIBBGP_ASSERT_EQ_U64(64500u, test_as_path_asn_at(found, 1u));
    LIBBGP_ASSERT_EQ_U64(65537u, test_as_path_asn_at(found, 2u));
    LIBBGP_ASSERT_EQ_U64(65538u, test_as_path_asn_at(found, 3u));
    LIBBGP_ASSERT(libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS4_PATH) == NULL);

    libbgp_pattr_unref(as4_path);
    libbgp_pattr_unref(as_path);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_restore_as_path_preserves_prefix_as_trans_for_mixed_suffix)
{
    uint32_t path_asns[] = { LIBBGP_AS_TRANS, 64500u, LIBBGP_AS_TRANS, 64501u };
    uint32_t as4_asns[] = { 65537u, 64501u };
    libbgp_update_msg_t msg;
    libbgp_pattr_t *as_path = make_as_path_attr(LIBBGP_PATTR_AS_PATH, false, path_asns, 4u);
    libbgp_pattr_t *as4_path = make_as_path_attr(LIBBGP_PATTR_AS4_PATH, true, as4_asns, 2u);
    libbgp_pattr_t *found;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as4_path));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_restore_as_path(&msg));
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT(found->data.as_path.is_4b);
    LIBBGP_ASSERT_EQ_U64(4u, test_as_path_asn_count(found));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_AS_TRANS, test_as_path_asn_at(found, 0u));
    LIBBGP_ASSERT_EQ_U64(64500u, test_as_path_asn_at(found, 1u));
    LIBBGP_ASSERT_EQ_U64(65537u, test_as_path_asn_at(found, 2u));
    LIBBGP_ASSERT_EQ_U64(64501u, test_as_path_asn_at(found, 3u));
    LIBBGP_ASSERT(libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS4_PATH) == NULL);

    libbgp_pattr_unref(as4_path);
    libbgp_pattr_unref(as_path);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_restore_aggregator_creates_aggregator_from_as4_aggregator_only)
{
    libbgp_update_msg_t msg;
    libbgp_pattr_t *as4_aggregator = make_aggregator_attr(LIBBGP_PATTR_AS4_AGGREGATOR, 65538u, 0xc6336401u, true);
    libbgp_pattr_t *found;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as4_aggregator));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_restore_aggregator(&msg));
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AGGREGATOR);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT(found->data.aggregator.is_4b);
    LIBBGP_ASSERT_EQ_U64(65538u, found->data.aggregator.asn);
    LIBBGP_ASSERT_EQ_U64(0xc6336401u, found->data.aggregator.router_id);
    LIBBGP_ASSERT(libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS4_AGGREGATOR) == NULL);

    libbgp_pattr_unref(as4_aggregator);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_prepend_2byte_peer_preserves_true_asn_in_as4_path)
{
    uint32_t asns[] = { LIBBGP_AS_TRANS };
    uint32_t as4_asns[] = { 65551u };
    libbgp_update_msg_t msg;
    libbgp_pattr_t *as_path = make_as_path_attr(LIBBGP_PATTR_AS_PATH, false, asns, 1u);
    libbgp_pattr_t *as4_path = make_as_path_attr(LIBBGP_PATTR_AS4_PATH, true, as4_asns, 1u);
    libbgp_pattr_t *found;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as4_path));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_prepend_asn(&msg, 65552u, false));

    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_AS_TRANS, found->data.as_path.segments[0].asns[0]);

    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS4_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(65552u, found->data.as_path.segments[0].asns[0]);

    libbgp_pattr_unref(as4_path);
    libbgp_pattr_unref(as_path);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_prepend_2byte_peer_creates_as4_path_when_needed)
{
    uint32_t asns[] = { 64512u };
    libbgp_update_msg_t msg;
    libbgp_pattr_t *as_path = make_as_path_attr(LIBBGP_PATTR_AS_PATH, false, asns, 1u);
    libbgp_pattr_t *found;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_prepend_asn(&msg, 65552u, false));
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_AS_TRANS, found->data.as_path.segments[0].asns[0]);
    LIBBGP_ASSERT_EQ_U64(64512u, found->data.as_path.segments[0].asns[1]);
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS4_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(1u, found->data.as_path.segment_count);
    LIBBGP_ASSERT_EQ_U64(2u, found->data.as_path.segments[0].asn_count);
    LIBBGP_ASSERT_EQ_U64(65552u, found->data.as_path.segments[0].asns[0]);
    LIBBGP_ASSERT_EQ_U64(64512u, found->data.as_path.segments[0].asns[1]);

    libbgp_pattr_unref(as_path);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_restore_as_path_uses_as4_path_as_structural_suffix)
{
    uint32_t path_seg0[] = { 64512u, LIBBGP_AS_TRANS };
    uint32_t path_seg1[] = { 64513u, LIBBGP_AS_TRANS };
    const uint32_t *path_asns[] = { path_seg0, path_seg1 };
    size_t path_counts[] = { 2u, 2u };
    uint8_t path_types[] = { 2u, 2u };
    uint32_t as4_seg0[] = { 65551u };
    uint32_t as4_seg1[] = { 65552u, 65553u };
    const uint32_t *as4_asns[] = { as4_seg0, as4_seg1 };
    size_t as4_counts[] = { 1u, 2u };
    uint8_t as4_types[] = { 1u, 2u };
    libbgp_update_msg_t msg;
    libbgp_pattr_t *as_path = make_as_path_attr_segments(
        LIBBGP_PATTR_AS_PATH, false, path_types, path_asns, path_counts, 2u);
    libbgp_pattr_t *as4_path = make_as_path_attr_segments(
        LIBBGP_PATTR_AS4_PATH, true, as4_types, as4_asns, as4_counts, 2u);
    libbgp_pattr_t *found;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as4_path));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_restore_as_path(&msg));
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT(found->data.as_path.is_4b);
    LIBBGP_ASSERT_EQ_U64(3u, found->data.as_path.segment_count);
    LIBBGP_ASSERT_EQ_U64(2u, found->data.as_path.segments[0].type);
    LIBBGP_ASSERT_EQ_U64(1u, found->data.as_path.segments[0].asn_count);
    LIBBGP_ASSERT_EQ_U64(64512u, found->data.as_path.segments[0].asns[0]);
    LIBBGP_ASSERT_EQ_U64(1u, found->data.as_path.segments[1].type);
    LIBBGP_ASSERT_EQ_U64(1u, found->data.as_path.segments[1].asn_count);
    LIBBGP_ASSERT_EQ_U64(65551u, found->data.as_path.segments[1].asns[0]);
    LIBBGP_ASSERT_EQ_U64(2u, found->data.as_path.segments[2].type);
    LIBBGP_ASSERT_EQ_U64(2u, found->data.as_path.segments[2].asn_count);
    LIBBGP_ASSERT_EQ_U64(65552u, found->data.as_path.segments[2].asns[0]);
    LIBBGP_ASSERT_EQ_U64(65553u, found->data.as_path.segments[2].asns[1]);
    LIBBGP_ASSERT(libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS4_PATH) == NULL);

    libbgp_pattr_unref(as4_path);
    libbgp_pattr_unref(as_path);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_restore_as_path_rejects_as4_path_longer_than_as_path)
{
    uint32_t asns[] = { LIBBGP_AS_TRANS };
    uint32_t as4_asns[] = { 65551u, 65552u };
    libbgp_update_msg_t msg;
    libbgp_pattr_t *as_path = make_as_path_attr(LIBBGP_PATTR_AS_PATH, false, asns, 1u);
    libbgp_pattr_t *as4_path = make_as_path_attr(LIBBGP_PATTR_AS4_PATH, true, as4_asns, 2u);

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as4_path));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_update_restore_as_path(&msg));
    LIBBGP_ASSERT(libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS4_PATH) != NULL);

    libbgp_pattr_unref(as4_path);
    libbgp_pattr_unref(as_path);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_prepend_partial_as4_path_restores_without_losing_prefix)
{
    uint32_t path_asns[] = { 64500u, LIBBGP_AS_TRANS };
    uint32_t as4_asns[] = { 65551u };
    libbgp_update_msg_t msg;
    libbgp_pattr_t *as_path = make_as_path_attr(LIBBGP_PATTR_AS_PATH, false, path_asns, 2u);
    libbgp_pattr_t *as4_path = make_as_path_attr(LIBBGP_PATTR_AS4_PATH, true, as4_asns, 1u);
    libbgp_pattr_t *found;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as4_path));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_prepend_asn(&msg, 65552u, false));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_restore_as_path(&msg));
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT(found->data.as_path.is_4b);
    LIBBGP_ASSERT_EQ_U64(2u, found->data.as_path.segment_count);
    LIBBGP_ASSERT_EQ_U64(2u, found->data.as_path.segments[0].type);
    LIBBGP_ASSERT_EQ_U64(2u, found->data.as_path.segments[0].asn_count);
    LIBBGP_ASSERT_EQ_U64(65552u, found->data.as_path.segments[0].asns[0]);
    LIBBGP_ASSERT_EQ_U64(64500u, found->data.as_path.segments[0].asns[1]);
    LIBBGP_ASSERT_EQ_U64(2u, found->data.as_path.segments[1].type);
    LIBBGP_ASSERT_EQ_U64(1u, found->data.as_path.segments[1].asn_count);
    LIBBGP_ASSERT_EQ_U64(65551u, found->data.as_path.segments[1].asns[0]);
    LIBBGP_ASSERT(libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS4_PATH) == NULL);

    libbgp_pattr_unref(as4_path);
    libbgp_pattr_unref(as_path);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_prepend_as4_failure_leaves_paths_unchanged)
{
    uint32_t path_asns[] = { 64500u, LIBBGP_AS_TRANS };
    uint32_t as4_asns[] = { 65551u, 65552u, 65553u };
    libbgp_update_msg_t msg;
    libbgp_pattr_t *as_path = make_as_path_attr(LIBBGP_PATTR_AS_PATH, false, path_asns, 2u);
    libbgp_pattr_t *as4_path = make_as_path_attr(LIBBGP_PATTR_AS4_PATH, true, as4_asns, 3u);
    libbgp_pattr_t *found;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as4_path));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_update_prepend_asn(&msg, 65554u, false));
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(1u, found->data.as_path.segment_count);
    LIBBGP_ASSERT_EQ_U64(2u, found->data.as_path.segments[0].asn_count);
    LIBBGP_ASSERT_EQ_U64(64500u, found->data.as_path.segments[0].asns[0]);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_AS_TRANS, found->data.as_path.segments[0].asns[1]);
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS4_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(3u, found->data.as_path.segments[0].asn_count);
    LIBBGP_ASSERT_EQ_U64(65551u, found->data.as_path.segments[0].asns[0]);
    LIBBGP_ASSERT_EQ_U64(65552u, found->data.as_path.segments[0].asns[1]);
    LIBBGP_ASSERT_EQ_U64(65553u, found->data.as_path.segments[0].asns[2]);

    libbgp_pattr_unref(as4_path);
    libbgp_pattr_unref(as_path);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_restore_rejects_as4_boundary_inside_as_set)
{
    uint32_t path_seg0[] = { 64512u, LIBBGP_AS_TRANS };
    uint32_t path_seg1[] = { 64513u };
    const uint32_t *path_asns[] = { path_seg0, path_seg1 };
    size_t path_counts[] = { 2u, 1u };
    uint8_t path_types[] = { 1u, 2u };
    uint32_t as4_asns[] = { 65551u, 65552u };
    libbgp_update_msg_t msg;
    libbgp_pattr_t *as_path = make_as_path_attr_segments(
        LIBBGP_PATTR_AS_PATH, false, path_types, path_asns, path_counts, 2u);
    libbgp_pattr_t *as4_path = make_as_path_attr(LIBBGP_PATTR_AS4_PATH, true, as4_asns, 2u);
    libbgp_pattr_t *found;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as4_path));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_update_restore_as_path(&msg));
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(2u, found->data.as_path.segment_count);
    LIBBGP_ASSERT_EQ_U64(1u, found->data.as_path.segments[0].type);
    LIBBGP_ASSERT_EQ_U64(2u, found->data.as_path.segments[0].asn_count);
    LIBBGP_ASSERT_EQ_U64(64512u, found->data.as_path.segments[0].asns[0]);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_AS_TRANS, found->data.as_path.segments[0].asns[1]);
    LIBBGP_ASSERT(libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS4_PATH) != NULL);

    libbgp_pattr_unref(as4_path);
    libbgp_pattr_unref(as_path);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_restore_preserves_as_set_prefix_at_suffix_boundary)
{
    uint32_t set_asns[] = { LIBBGP_AS_TRANS, 64513u };
    uint32_t seq_asns[] = { LIBBGP_AS_TRANS };
    const uint32_t *path_asns[] = { set_asns, seq_asns };
    size_t path_counts[] = { 2u, 1u };
    uint8_t path_types[] = { 1u, 2u };
    uint32_t as4_asns[] = { 65551u };
    libbgp_update_msg_t msg;
    libbgp_pattr_t *as_path = make_as_path_attr_segments(
        LIBBGP_PATTR_AS_PATH, false, path_types, path_asns, path_counts, 2u);
    libbgp_pattr_t *as4_path = make_as_path_attr(LIBBGP_PATTR_AS4_PATH, true, as4_asns, 1u);
    libbgp_pattr_t *found;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as4_path));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_restore_as_path(&msg));
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(2u, found->data.as_path.segment_count);
    LIBBGP_ASSERT_EQ_U64(1u, found->data.as_path.segments[0].type);
    LIBBGP_ASSERT_EQ_U64(2u, found->data.as_path.segments[0].asn_count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_AS_TRANS, found->data.as_path.segments[0].asns[0]);
    LIBBGP_ASSERT_EQ_U64(64513u, found->data.as_path.segments[0].asns[1]);
    LIBBGP_ASSERT_EQ_U64(2u, found->data.as_path.segments[1].type);
    LIBBGP_ASSERT_EQ_U64(1u, found->data.as_path.segments[1].asn_count);
    LIBBGP_ASSERT_EQ_U64(65551u, found->data.as_path.segments[1].asns[0]);
    LIBBGP_ASSERT(libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS4_PATH) == NULL);

    libbgp_pattr_unref(as4_path);
    libbgp_pattr_unref(as_path);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_restore_rejects_malformed_replaced_as_path_suffix)
{
    uint32_t asns[] = { LIBBGP_AS_TRANS };
    uint32_t as4_asns[] = { 65551u };
    libbgp_update_msg_t msg;
    libbgp_pattr_t *as_path = make_as_path_attr(LIBBGP_PATTR_AS_PATH, false, asns, 1u);
    libbgp_pattr_t *as4_path = make_as_path_attr(LIBBGP_PATTR_AS4_PATH, true, as4_asns, 1u);

    as_path->data.as_path.segments[0].type = 3u;
    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as4_path));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_restore_as_path(&msg));
    LIBBGP_ASSERT(libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS4_PATH) != NULL);

    libbgp_pattr_unref(as4_path);
    libbgp_pattr_unref(as_path);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_rejects_as_path_segment_count_over_255)
{
    uint32_t asns[256];
    libbgp_update_msg_t msg;
    libbgp_pattr_t *as_path;
    size_t i;

    for (i = 0u; i < LIBBGP_ARRAY_LEN(asns); i++) {
        asns[i] = 64512u;
    }
    as_path = make_as_path_attr(LIBBGP_PATTR_AS_PATH, true, asns, LIBBGP_ARRAY_LEN(asns));
    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_validate(&msg));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_downgrade_as_path(&msg));

    libbgp_pattr_unref(as_path);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_prepend_as4_attr_add_failure_leaves_paths_unchanged)
{
    uint32_t asns[] = { 64512u };
    libbgp_update_msg_t msg;
    libbgp_pattr_t *as_path = make_as_path_attr(LIBBGP_PATTR_AS_PATH, false, asns, 1u);
    libbgp_pattr_t *found;
    update_fail_realloc_ctx_t fail = { 0u, 1u };
    libbgp_alloc_t alloc;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));

    alloc = update_fail_realloc_make(&fail);
    libbgp_set_alloc(&alloc);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, libbgp_update_prepend_asn(&msg, 65552u, false));
    libbgp_set_alloc(NULL);

    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(1u, found->data.as_path.segment_count);
    LIBBGP_ASSERT_EQ_U64(1u, found->data.as_path.segments[0].asn_count);
    LIBBGP_ASSERT_EQ_U64(64512u, found->data.as_path.segments[0].asns[0]);
    LIBBGP_ASSERT(libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS4_PATH) == NULL);

    libbgp_pattr_unref(as_path);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_downgrade_2byte_as_path_omits_unneeded_as4_path)
{
    uint32_t asns[] = { 64512u, 64513u };
    libbgp_update_msg_t msg;
    libbgp_pattr_t *as_path = make_as_path_attr(LIBBGP_PATTR_AS_PATH, true, asns, 2u);
    libbgp_pattr_t *found;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_downgrade_as_path(&msg));
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT(!found->data.as_path.is_4b);
    LIBBGP_ASSERT_EQ_U64(64512u, found->data.as_path.segments[0].asns[0]);
    LIBBGP_ASSERT_EQ_U64(64513u, found->data.as_path.segments[0].asns[1]);
    LIBBGP_ASSERT(libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS4_PATH) == NULL);

    libbgp_pattr_unref(as_path);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_add_helpers_ref_attrs_and_write_fixture_body)
{
    const uint8_t *expected = LIBBGP_FIXTURE_UPDATE_IPV4 + LIBBGP_BGP_HEADER_LEN;
    const size_t expected_len = LIBBGP_FIXTURE_UPDATE_IPV4_LEN - LIBBGP_BGP_HEADER_LEN;
    uint8_t out[64];
    size_t out_len = 0u;
    libbgp_update_msg_t msg;
    libbgp_prefix4_t nlri;
    libbgp_pattr_t *origin = libbgp_pattr_new(LIBBGP_PATTR_ORIGIN);
    libbgp_pattr_t *as_path = libbgp_pattr_new(LIBBGP_PATTR_AS_PATH);
    libbgp_pattr_t *next_hop = libbgp_pattr_new(LIBBGP_PATTR_NEXT_HOP);
    uint32_t *asns;
    libbgp_as_path_segment_t *segment;

    LIBBGP_ASSERT(origin != NULL);
    LIBBGP_ASSERT(as_path != NULL);
    LIBBGP_ASSERT(next_hop != NULL);
    asns = (uint32_t *)malloc(sizeof(asns[0]));
    segment = (libbgp_as_path_segment_t *)calloc(1u, sizeof(segment[0]));
    LIBBGP_ASSERT(asns != NULL);
    LIBBGP_ASSERT(segment != NULL);
    asns[0] = 65000u;
    origin->data.origin.origin = 0u;
    segment->type = 2u;
    segment->asn_count = 1u;
    segment->asns = asns;
    as_path->data.as_path.segment_count = 1u;
    as_path->data.as_path.segments = segment;
    {
        const uint8_t next_hop_bytes[] = { 192u, 0u, 2u, 254u };
        memcpy(&next_hop->data.next_hop.next_hop, next_hop_bytes, sizeof(next_hop_bytes));
    }
    nlri.addr = 0x7100cbu;
    nlri.len = 24u;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, origin));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, next_hop));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_nlri(&msg, &nlri));
    LIBBGP_ASSERT_EQ_U64(2u, origin->refcount);
    LIBBGP_ASSERT(libbgp_update_find_attr(&msg, LIBBGP_PATTR_NEXT_HOP) == next_hop);
    libbgp_pattr_unref(origin);
    libbgp_pattr_unref(as_path);
    libbgp_pattr_unref(next_hop);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_write(&msg, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(expected_len, out_len);
    LIBBGP_ASSERT_BYTES_EQ(expected, out, expected_len);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_rejects_bad_lengths_and_small_output)
{
    const uint8_t short_len[] = { 0u };
    const uint8_t bad_withdrawn_len[] = { 0u, 4u, 24u, 192u, 0u };
    const uint8_t bad_attr_len[] = { 0u, 0u, 0u, 4u, 0x40u, 1u, 1u };
    uint8_t out[3];
    size_t marker = 99u;
    libbgp_update_msg_t msg;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_parse(NULL, short_len, sizeof(short_len), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_parse(&msg, NULL, sizeof(short_len), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_parse(&msg, short_len, sizeof(short_len), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_parse(&msg, bad_withdrawn_len, sizeof(bad_withdrawn_len), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_parse(&msg, bad_attr_len, sizeof(bad_attr_len), &marker));
    LIBBGP_ASSERT_EQ_U64(99u, marker);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_write(NULL, out, sizeof(out), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_write(&msg, NULL, sizeof(out), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BUFFER, libbgp_update_write(&msg, out, sizeof(out), &marker));
    LIBBGP_ASSERT_EQ_U64(99u, marker);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_parse_rejects_malformed_attr_segment_and_preserves_state)
{
    const uint8_t valid_empty[] = { 0u, 0u, 0u, 0u };
    const uint8_t invalid_as_path_segment[] = {
        0u, 0u,
        0u, 4u,
        0x40u, 2u, 1u, 3u
    };
    const uint8_t truncated_mp_reach_attr[] = {
        0u, 0u,
        0u, 7u,
        0x80u, 14u, 4u, 0u, 2u, 1u, 16u
    };
    size_t used = 0u;
    libbgp_update_msg_t msg;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_parse(&msg, valid_empty, sizeof(valid_empty), &used));
    LIBBGP_ASSERT_EQ_U64(sizeof(valid_empty), used);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN,
        libbgp_update_parse(&msg, invalid_as_path_segment, sizeof(invalid_as_path_segment), &used));
    LIBBGP_ASSERT_EQ_U64(0u, msg.attr_count);
    LIBBGP_ASSERT_EQ_U64(0u, msg.nlri_count);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN,
        libbgp_update_parse(&msg, truncated_mp_reach_attr, sizeof(truncated_mp_reach_attr), &used));
    LIBBGP_ASSERT_EQ_U64(0u, msg.attr_count);
    LIBBGP_ASSERT_EQ_U64(0u, msg.nlri_count);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_parse_allows_unknown_attr_passthrough_length)
{
    const uint8_t body[] = {
        0u, 0u,
        0u, 8u,
        0x80u, 99u, 5u, 1u, 2u, 3u, 4u, 5u
    };
    uint8_t out[32];
    size_t used = 0u;
    size_t out_len = 0u;
    libbgp_update_msg_t msg;
    libbgp_pattr_t *attr;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_parse(&msg, body, sizeof(body), &used));
    LIBBGP_ASSERT_EQ_U64(sizeof(body), used);
    LIBBGP_ASSERT_EQ_U64(1u, msg.attr_count);
    attr = msg.attrs[0];
    LIBBGP_ASSERT(attr != NULL);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PATTR_UNKNOWN, attr->type);
    LIBBGP_ASSERT_EQ_U64(99u, attr->type_code);
    LIBBGP_ASSERT_EQ_U64(5u, attr->data.unknown.len);
    LIBBGP_ASSERT_BYTES_EQ(body + 7u, attr->data.unknown.value, 5u);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_write(&msg, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(sizeof(body), out_len);
    LIBBGP_ASSERT_BYTES_EQ(body, out, sizeof(body));
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_rejects_malformed_as_path_public_arrays)
{
    uint32_t asns[] = { 64512u };
    uint8_t out[64];
    size_t out_len = 55u;
    libbgp_update_msg_t msg;
    libbgp_pattr_t *as_path = make_as_path_attr(LIBBGP_PATTR_AS_PATH, true, asns, 1u);

    LIBBGP_ASSERT(as_path != NULL);
    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));

    as_path->data.as_path.segments[0].type = 0u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_validate(&msg));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_write(&msg, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(55u, out_len);

    as_path->data.as_path.segments[0].type = 2u;
    as_path->data.as_path.segments[0].asn_count = 1u;
    free(as_path->data.as_path.segments[0].asns);
    as_path->data.as_path.segments[0].asns = NULL;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_validate(&msg));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_downgrade_as_path(&msg));

    libbgp_pattr_unref(as_path);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_restore_allows_as_set_boundary_at_first_asn)
{
    uint32_t set_asns[] = { LIBBGP_AS_TRANS, 64513u };
    uint32_t seq_asns[] = { LIBBGP_AS_TRANS };
    const uint32_t *path_asns[] = { set_asns, seq_asns };
    size_t path_counts[] = { 2u, 1u };
    uint8_t path_types[] = { 1u, 2u };
    uint32_t as4_asns[] = { 65551u, 65552u, 65553u };
    libbgp_update_msg_t msg;
    libbgp_pattr_t *as_path = make_as_path_attr_segments(
        LIBBGP_PATTR_AS_PATH, false, path_types, path_asns, path_counts, 2u);
    libbgp_pattr_t *as4_path = make_as_path_attr(LIBBGP_PATTR_AS4_PATH, true, as4_asns, 3u);
    libbgp_pattr_t *found;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as4_path));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_restore_as_path(&msg));
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT(found->data.as_path.is_4b);
    LIBBGP_ASSERT_EQ_U64(1u, found->data.as_path.segment_count);
    LIBBGP_ASSERT_EQ_U64(2u, found->data.as_path.segments[0].type);
    LIBBGP_ASSERT_EQ_U64(3u, found->data.as_path.segments[0].asn_count);
    LIBBGP_ASSERT_EQ_U64(65551u, found->data.as_path.segments[0].asns[0]);
    LIBBGP_ASSERT_EQ_U64(65552u, found->data.as_path.segments[0].asns[1]);
    LIBBGP_ASSERT_EQ_U64(65553u, found->data.as_path.segments[0].asns[2]);
    LIBBGP_ASSERT(libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS4_PATH) == NULL);

    libbgp_pattr_unref(as4_path);
    libbgp_pattr_unref(as_path);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_validate_rejects_nonzero_counts_with_null_arrays)
{
    uint8_t out[64];
    size_t out_len = 99u;
    libbgp_update_msg_t msg;

    libbgp_update_init(&msg);
    msg.withdrawn_count = 1u;
    msg.withdrawn = NULL;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_validate(&msg));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_write(&msg, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(99u, out_len);
    libbgp_update_destroy(&msg);

    libbgp_update_init(&msg);
    msg.attr_count = 1u;
    msg.attrs = NULL;
    out_len = 99u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_validate(&msg));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_write(&msg, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(99u, out_len);
    libbgp_update_destroy(&msg);

    libbgp_update_init(&msg);
    msg.nlri_count = 1u;
    msg.nlri = NULL;
    out_len = 99u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_validate(&msg));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_write(&msg, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(99u, out_len);
    libbgp_update_destroy(&msg);

    libbgp_update_init(&msg);
    msg.attr_count = 1u;
    msg.attrs = (libbgp_pattr_t **)calloc(1u, sizeof(msg.attrs[0]));
    LIBBGP_ASSERT(msg.attrs != NULL);
    msg.attrs[0] = NULL;
    out_len = 99u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_validate(&msg));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_write(&msg, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(99u, out_len);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_write_rejects_invalid_prefix_arrays_and_small_output)
{
    uint8_t out[4];
    size_t out_len = 44u;
    libbgp_update_msg_t msg;
    libbgp_prefix4_t bad_prefix;

    libbgp_update_init(&msg);
    bad_prefix.addr = 0u;
    bad_prefix.len = 33u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_add_nlri(&msg, &bad_prefix));

    msg.withdrawn = (libbgp_prefix4_t *)calloc(1u, sizeof(msg.withdrawn[0]));
    LIBBGP_ASSERT(msg.withdrawn != NULL);
    msg.withdrawn_count = 1u;
    msg.withdrawn[0].addr = 0u;
    msg.withdrawn[0].len = 33u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_write(&msg, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(44u, out_len);
    libbgp_update_destroy(&msg);

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BUFFER, libbgp_update_write(&msg, out, 3u, &out_len));
    LIBBGP_ASSERT_EQ_U64(44u, out_len);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_public_helpers_reject_null_inputs)
{
    libbgp_update_msg_t msg;
    libbgp_pattr_t *origin = libbgp_pattr_new(LIBBGP_PATTR_ORIGIN);
    libbgp_prefix4_t prefix;

    LIBBGP_ASSERT(origin != NULL);
    prefix.addr = 0u;
    prefix.len = 24u;
    libbgp_update_init(&msg);

    libbgp_update_init(NULL);
    libbgp_update_destroy(NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_add_withdrawn(NULL, &prefix));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_add_nlri(NULL, &prefix));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_add_attr(NULL, origin));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_add_attr(&msg, NULL));
    LIBBGP_ASSERT(libbgp_update_find_attr(NULL, LIBBGP_PATTR_ORIGIN) == NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_validate(NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_prepend_asn(NULL, 64512u, false));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_restore_as_path(NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_downgrade_as_path(NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_restore_aggregator(NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_downgrade_aggregator(NULL));

    libbgp_pattr_unref(origin);
}

LIBBGP_TEST(update_add_prefix_realloc_failure_preserves_empty_message)
{
    libbgp_update_msg_t msg;
    libbgp_prefix4_t prefix;
    update_fail_realloc_ctx_t fail = { 0u, 1u };
    libbgp_alloc_t alloc;

    prefix.addr = 0x7100cbu;
    prefix.len = 24u;
    libbgp_update_init(&msg);

    alloc = update_fail_realloc_make(&fail);
    libbgp_set_alloc(&alloc);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, libbgp_update_add_withdrawn(&msg, &prefix));
    fail.fail_on_realloc = 2u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, libbgp_update_add_nlri(&msg, &prefix));
    libbgp_set_alloc(NULL);

    LIBBGP_ASSERT_EQ_U64(2u, fail.realloc_calls);
    LIBBGP_ASSERT_EQ_U64(0u, msg.withdrawn_count);
    LIBBGP_ASSERT(msg.withdrawn == NULL);
    LIBBGP_ASSERT_EQ_U64(0u, msg.nlri_count);
    LIBBGP_ASSERT(msg.nlri == NULL);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_add_attr_rejects_broken_state_and_realloc_failure)
{
    libbgp_update_msg_t msg;
    libbgp_pattr_t *origin = libbgp_pattr_new(LIBBGP_PATTR_ORIGIN);
    update_fail_realloc_ctx_t fail = { 0u, 1u };
    libbgp_alloc_t alloc;

    LIBBGP_ASSERT(origin != NULL);
    libbgp_update_init(&msg);
    msg.attr_count = 1u;
    msg.attrs = NULL;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_add_attr(&msg, origin));
    msg.attr_count = 0u;

    alloc = update_fail_realloc_make(&fail);
    libbgp_set_alloc(&alloc);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, libbgp_update_add_attr(&msg, origin));
    libbgp_set_alloc(NULL);

    LIBBGP_ASSERT_EQ_U64(1u, fail.realloc_calls);
    LIBBGP_ASSERT_EQ_U64(0u, msg.attr_count);
    LIBBGP_ASSERT(msg.attrs == NULL);
    LIBBGP_ASSERT_EQ_U64(1u, origin->refcount);

    libbgp_pattr_unref(origin);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_validate_rejects_each_missing_mandatory_ipv4_attr)
{
    uint32_t asns[] = { 64512u };
    libbgp_prefix4_t nlri;
    libbgp_update_msg_t msg;
    libbgp_pattr_t *origin = libbgp_pattr_new(LIBBGP_PATTR_ORIGIN);
    libbgp_pattr_t *as_path = make_as_path_attr(LIBBGP_PATTR_AS_PATH, true, asns, 1u);
    libbgp_pattr_t *next_hop = libbgp_pattr_new(LIBBGP_PATTR_NEXT_HOP);

    LIBBGP_ASSERT(origin != NULL);
    LIBBGP_ASSERT(next_hop != NULL);
    nlri.addr = 0x7100cbu;
    nlri.len = 24u;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, next_hop));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_nlri(&msg, &nlri));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_update_validate(&msg));
    libbgp_update_destroy(&msg);

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, origin));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, next_hop));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_nlri(&msg, &nlri));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_update_validate(&msg));
    libbgp_update_destroy(&msg);

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, origin));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_nlri(&msg, &nlri));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_update_validate(&msg));
    libbgp_update_destroy(&msg);

    libbgp_pattr_unref(next_hop);
    libbgp_pattr_unref(as_path);
    libbgp_pattr_unref(origin);
}

LIBBGP_TEST(update_validate_rejects_mp_reach_without_origin_or_as_path)
{
    uint32_t asns[] = { 64512u };
    const uint8_t ipv6_nexthop[] = {
        0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0u, 0u, 0u,
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u
    };
    libbgp_prefix6_t ipv6_nlri;
    libbgp_update_msg_t msg;
    libbgp_pattr_t *origin = libbgp_pattr_new(LIBBGP_PATTR_ORIGIN);
    libbgp_pattr_t *as_path = make_as_path_attr(LIBBGP_PATTR_AS_PATH, true, asns, 1u);
    libbgp_pattr_t *mp_reach = libbgp_pattr_new(LIBBGP_PATTR_MP_REACH_IPV6);

    LIBBGP_ASSERT(origin != NULL);
    LIBBGP_ASSERT(mp_reach != NULL);
    memset(&ipv6_nlri, 0, sizeof(ipv6_nlri));
    ipv6_nlri.len = 32u;
    memcpy(mp_reach->data.mp_reach_ipv6.nexthop, ipv6_nexthop, sizeof(ipv6_nexthop));
    mp_reach->data.mp_reach_ipv6.nexthop_len = sizeof(ipv6_nexthop);
    mp_reach->data.mp_reach_ipv6.nlri = &ipv6_nlri;
    mp_reach->data.mp_reach_ipv6.nlri_count = 1u;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, mp_reach));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_update_validate(&msg));
    libbgp_update_destroy(&msg);

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, origin));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, mp_reach));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_update_validate(&msg));
    libbgp_update_destroy(&msg);

    mp_reach->data.mp_reach_ipv6.nlri = NULL;
    mp_reach->data.mp_reach_ipv6.nlri_count = 0u;
    libbgp_pattr_unref(mp_reach);
    libbgp_pattr_unref(as_path);
    libbgp_pattr_unref(origin);
}

LIBBGP_TEST(update_restore_and_prepend_reject_malformed_as_path_state)
{
    uint32_t path_asns[] = { LIBBGP_AS_TRANS };
    uint32_t as4_asns[] = { 65551u };
    libbgp_update_msg_t msg;
    libbgp_pattr_t *as_path = make_as_path_attr(LIBBGP_PATTR_AS_PATH, false, path_asns, 1u);
    libbgp_pattr_t *as4_path = make_as_path_attr(LIBBGP_PATTR_AS4_PATH, true, as4_asns, 1u);

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));
    as_path->data.as_path.segment_count = 1u;
    free(as_path->data.as_path.segments[0].asns);
    as_path->data.as_path.segments[0].asns = NULL;
    free(as_path->data.as_path.segments);
    as_path->data.as_path.segments = NULL;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_prepend_asn(&msg, 64512u, false));
    libbgp_update_destroy(&msg);

    as_path->data.as_path.segment_count = 1u;
    as_path->data.as_path.segments = (libbgp_as_path_segment_t *)calloc(1u, sizeof(as_path->data.as_path.segments[0]));
    LIBBGP_ASSERT(as_path->data.as_path.segments != NULL);
    as_path->data.as_path.segments[0].type = 2u;
    as_path->data.as_path.segments[0].asn_count = 1u;
    as_path->data.as_path.segments[0].asns = (uint32_t *)malloc(sizeof(as_path->data.as_path.segments[0].asns[0]));
    LIBBGP_ASSERT(as_path->data.as_path.segments[0].asns != NULL);
    as_path->data.as_path.segments[0].asns[0] = path_asns[0];

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as4_path));
    as4_path->data.as_path.is_4b = false;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_restore_as_path(&msg));
    free(as_path->data.as_path.segments[0].asns);
    as_path->data.as_path.segments[0].asns = NULL;
    as4_path->data.as_path.is_4b = true;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_restore_as_path(&msg));

    libbgp_pattr_unref(as4_path);
    libbgp_pattr_unref(as_path);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_public_helpers_reject_attr_semantic_duplicates_and_bad_prefixes)
{
    libbgp_update_msg_t msg;
    libbgp_pattr_t *unknown_a = libbgp_pattr_new(LIBBGP_PATTR_UNKNOWN);
    libbgp_pattr_t *unknown_b = libbgp_pattr_new(LIBBGP_PATTR_UNKNOWN);
    libbgp_prefix4_t prefix;

    LIBBGP_ASSERT(unknown_a != NULL);
    LIBBGP_ASSERT(unknown_b != NULL);
    unknown_a->type_code = 99u;
    unknown_b->type_code = 99u;
    prefix.addr = 0u;
    prefix.len = 33u;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_add_withdrawn(&msg, &prefix));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, unknown_a));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_EXISTS, libbgp_update_add_attr(&msg, unknown_b));
    LIBBGP_ASSERT_EQ_U64(1u, msg.attr_count);
    LIBBGP_ASSERT(libbgp_update_find_attr(&msg, LIBBGP_PATTR_UNKNOWN) == unknown_a);

    libbgp_pattr_unref(unknown_b);
    libbgp_pattr_unref(unknown_a);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_prepend_handles_empty_and_full_first_segments)
{
    uint32_t existing_asns[] = { 64512u };
    libbgp_update_msg_t msg;
    libbgp_pattr_t *empty_first = make_as_path_attr(LIBBGP_PATTR_AS_PATH, false, existing_asns, 0u);
    libbgp_pattr_t *found;
    size_t i;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, empty_first));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_prepend_asn(&msg, 64513u, false));
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(1u, found->data.as_path.segment_count);
    LIBBGP_ASSERT_EQ_U64(1u, found->data.as_path.segments[0].asn_count);
    LIBBGP_ASSERT_EQ_U64(64513u, found->data.as_path.segments[0].asns[0]);
    libbgp_update_destroy(&msg);

    empty_first->data.as_path.segments[0].asn_count = 255u;
    empty_first->data.as_path.segments[0].asns = (uint32_t *)calloc(255u, sizeof(empty_first->data.as_path.segments[0].asns[0]));
    LIBBGP_ASSERT(empty_first->data.as_path.segments[0].asns != NULL);
    for (i = 0u; i < 255u; i++) {
        empty_first->data.as_path.segments[0].asns[i] = 64512u + (uint32_t)i;
    }

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, empty_first));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_prepend_asn(&msg, 64511u, false));
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(2u, found->data.as_path.segment_count);
    LIBBGP_ASSERT_EQ_U64(1u, found->data.as_path.segments[0].asn_count);
    LIBBGP_ASSERT_EQ_U64(64511u, found->data.as_path.segments[0].asns[0]);
    LIBBGP_ASSERT_EQ_U64(255u, found->data.as_path.segments[1].asn_count);

    libbgp_pattr_unref(empty_first);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_prepend_allocation_failures_preserve_original_path)
{
    uint32_t asns[] = { 64512u };
    libbgp_update_msg_t msg;
    libbgp_pattr_t *as_path = make_as_path_attr(LIBBGP_PATTR_AS_PATH, false, asns, 1u);
    libbgp_pattr_t *found;
    update_fail_alloc_ctx_t fail = { 0u, 0u, 0u, 1u, 0u, 0u };
    libbgp_alloc_t alloc;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));

    alloc = update_fail_alloc_make(&fail);
    libbgp_set_alloc(&alloc);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, libbgp_update_prepend_asn(&msg, 64511u, false));
    libbgp_set_alloc(NULL);

    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(1u, found->data.as_path.segment_count);
    LIBBGP_ASSERT_EQ_U64(1u, found->data.as_path.segments[0].asn_count);
    LIBBGP_ASSERT_EQ_U64(64512u, found->data.as_path.segments[0].asns[0]);

    fail.malloc_calls = 0u;
    fail.calloc_calls = 0u;
    fail.realloc_calls = 0u;
    fail.fail_on_malloc = 0u;
    fail.fail_on_calloc = 2u;
    fail.fail_on_realloc = 0u;
    libbgp_set_alloc(&alloc);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, libbgp_update_prepend_asn(&msg, 64511u, false));
    libbgp_set_alloc(NULL);

    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(1u, found->data.as_path.segment_count);
    LIBBGP_ASSERT_EQ_U64(1u, found->data.as_path.segments[0].asn_count);
    LIBBGP_ASSERT_EQ_U64(64512u, found->data.as_path.segments[0].asns[0]);

    libbgp_pattr_unref(as_path);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_prepend_new_path_allocation_failures_leave_message_empty)
{
    libbgp_update_msg_t msg;
    update_fail_alloc_ctx_t fail = { 0u, 0u, 0u, 0u, 1u, 0u };
    libbgp_alloc_t alloc = update_fail_alloc_make(&fail);

    libbgp_update_init(&msg);
    libbgp_set_alloc(&alloc);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, libbgp_update_prepend_asn(&msg, 64512u, false));
    libbgp_set_alloc(NULL);
    LIBBGP_ASSERT_EQ_U64(0u, msg.attr_count);
    LIBBGP_ASSERT(msg.attrs == NULL);

    fail.calloc_calls = 0u;
    fail.realloc_calls = 0u;
    fail.fail_on_calloc = 0u;
    fail.fail_on_realloc = 1u;
    libbgp_set_alloc(&alloc);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, libbgp_update_prepend_asn(&msg, 64512u, false));
    libbgp_set_alloc(NULL);
    LIBBGP_ASSERT_EQ_U64(0u, msg.attr_count);
    LIBBGP_ASSERT(msg.attrs == NULL);

    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_downgrade_rejects_malformed_as_path_shadow_states)
{
    uint32_t asns[] = { 65551u };
    libbgp_update_msg_t msg;
    libbgp_pattr_t *as_path = make_as_path_attr(LIBBGP_PATTR_AS_PATH, true, asns, 1u);

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));
    as_path->data.as_path.segments[0].type = 3u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_downgrade_as_path(&msg));
    as_path->data.as_path.segments[0].type = 2u;
    as_path->data.as_path.segments[0].asn_count = 1u;
    free(as_path->data.as_path.segments[0].asns);
    as_path->data.as_path.segments[0].asns = NULL;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_downgrade_as_path(&msg));

    libbgp_pattr_unref(as_path);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_downgrade_allocation_failure_preserves_original_path)
{
    uint32_t asns[] = { 64512u, 65551u };
    libbgp_update_msg_t msg;
    libbgp_pattr_t *as_path = make_as_path_attr(LIBBGP_PATTR_AS_PATH, true, asns, 2u);
    libbgp_pattr_t *found;
    update_fail_alloc_ctx_t fail = { 0u, 0u, 0u, 0u, 2u, 0u };
    libbgp_alloc_t alloc;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));
    alloc = update_fail_alloc_make(&fail);
    libbgp_set_alloc(&alloc);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, libbgp_update_downgrade_as_path(&msg));
    libbgp_set_alloc(NULL);

    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT(found->data.as_path.is_4b);
    LIBBGP_ASSERT_EQ_U64(2u, found->data.as_path.segments[0].asn_count);
    LIBBGP_ASSERT_EQ_U64(64512u, found->data.as_path.segments[0].asns[0]);
    LIBBGP_ASSERT_EQ_U64(65551u, found->data.as_path.segments[0].asns[1]);
    LIBBGP_ASSERT(libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS4_PATH) == NULL);

    fail.malloc_calls = 0u;
    fail.calloc_calls = 0u;
    fail.realloc_calls = 0u;
    fail.fail_on_calloc = 0u;
    fail.fail_on_malloc = 2u;
    libbgp_set_alloc(&alloc);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, libbgp_update_downgrade_as_path(&msg));
    libbgp_set_alloc(NULL);

    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT(found->data.as_path.is_4b);
    LIBBGP_ASSERT_EQ_U64(2u, found->data.as_path.segments[0].asn_count);
    LIBBGP_ASSERT_EQ_U64(64512u, found->data.as_path.segments[0].asns[0]);
    LIBBGP_ASSERT_EQ_U64(65551u, found->data.as_path.segments[0].asns[1]);

    libbgp_pattr_unref(as_path);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_small_branch_regressions_cover_invalid_helpers)
{
    libbgp_update_msg_t msg;
    libbgp_prefix4_t prefix;
    uint8_t out[16];
    size_t out_len = 77u;

    prefix.addr = 0x7100cbu;
    prefix.len = 24u;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_add_withdrawn(&msg, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_add_nlri(&msg, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_withdrawn(&msg, &prefix));
    LIBBGP_ASSERT_EQ_U64(0u, msg.attr_count);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_downgrade_aggregator(&msg));
    LIBBGP_ASSERT_EQ_U64(0u, msg.attr_count);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_restore_aggregator(&msg));
    LIBBGP_ASSERT_EQ_U64(0u, msg.attr_count);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_write(&msg, out, sizeof(out), &out_len));
    LIBBGP_ASSERT(out_len > 0u);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_validate_rejects_duplicate_semantic_attrs_in_public_state)
{
    libbgp_update_msg_t msg;
    libbgp_pattr_t *first = libbgp_pattr_new(LIBBGP_PATTR_ORIGIN);
    libbgp_pattr_t *second = libbgp_pattr_new(LIBBGP_PATTR_ORIGIN);

    LIBBGP_ASSERT(first != NULL);
    LIBBGP_ASSERT(second != NULL);
    libbgp_update_init(&msg);
    msg.attrs = (libbgp_pattr_t **)calloc(2u, sizeof(msg.attrs[0]));
    LIBBGP_ASSERT(msg.attrs != NULL);
    msg.attr_count = 2u;
    msg.attrs[0] = libbgp_pattr_ref(first);
    msg.attrs[1] = libbgp_pattr_ref(second);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_update_validate(&msg));

    libbgp_pattr_unref(second);
    libbgp_pattr_unref(first);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_restore_as_path_rejects_invalid_as4_shadow_state)
{
    uint32_t path_asns[] = { LIBBGP_AS_TRANS };
    uint32_t as4_asns[] = { 65551u };
    libbgp_update_msg_t msg;
    libbgp_pattr_t *as_path = make_as_path_attr(LIBBGP_PATTR_AS_PATH, false, path_asns, 1u);
    libbgp_pattr_t *as4_path = make_as_path_attr(LIBBGP_PATTR_AS4_PATH, true, as4_asns, 1u);

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as4_path));
    free(as4_path->data.as_path.segments[0].asns);
    as4_path->data.as_path.segments[0].asns = NULL;
    free(as4_path->data.as_path.segments);
    as4_path->data.as_path.segments = NULL;
    as4_path->data.as_path.segment_count = 1u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_restore_as_path(&msg));
    LIBBGP_ASSERT(libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS4_PATH) != NULL);

    libbgp_pattr_unref(as4_path);
    libbgp_pattr_unref(as_path);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_restore_as_path_allocation_failure_preserves_shadow_attr)
{
    uint32_t path_asns[] = { LIBBGP_AS_TRANS };
    uint32_t as4_asns[] = { 65551u };
    libbgp_update_msg_t msg;
    libbgp_pattr_t *as_path = make_as_path_attr(LIBBGP_PATTR_AS_PATH, false, path_asns, 1u);
    libbgp_pattr_t *as4_path = make_as_path_attr(LIBBGP_PATTR_AS4_PATH, true, as4_asns, 1u);
    update_fail_alloc_ctx_t fail = { 0u, 0u, 0u, 0u, 1u, 0u };
    libbgp_alloc_t alloc;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as4_path));

    alloc = update_fail_alloc_make(&fail);
    libbgp_set_alloc(&alloc);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, libbgp_update_restore_as_path(&msg));
    libbgp_set_alloc(NULL);
    LIBBGP_ASSERT(libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS4_PATH) != NULL);

    libbgp_pattr_unref(as4_path);
    libbgp_pattr_unref(as_path);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_prepend_rejects_invalid_first_segment_state)
{
    libbgp_update_msg_t msg;
    libbgp_pattr_t *as_path = libbgp_pattr_new(LIBBGP_PATTR_AS_PATH);

    LIBBGP_ASSERT(as_path != NULL);
    as_path->data.as_path.segment_count = 1u;
    as_path->data.as_path.segments = (libbgp_as_path_segment_t *)calloc(1u, sizeof(as_path->data.as_path.segments[0]));
    LIBBGP_ASSERT(as_path->data.as_path.segments != NULL);
    as_path->data.as_path.segments[0].type = 2u;
    as_path->data.as_path.segments[0].asn_count = 1u;
    as_path->data.as_path.segments[0].asns = NULL;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_prepend_asn(&msg, 64512u, false));

    libbgp_pattr_unref(as_path);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_parse_rejects_duplicate_wire_attrs_and_nomem_paths)
{
    const uint8_t duplicate_origin_body[] = {
        0u, 0u,
        0u, 8u,
        0x40u, 1u, 1u, 0u,
        0x40u, 1u, 1u, 0u
    };
    const uint8_t withdrawn_body[] = {
        0u, 4u,
        24u, 198u, 51u, 100u,
        0u, 0u
    };
    const uint8_t origin_body[] = {
        0u, 0u,
        0u, 4u,
        0x40u, 1u, 1u, 0u
    };
    size_t used = 88u;
    libbgp_update_msg_t msg;
    update_fail_alloc_ctx_t fail = { 0u, 0u, 0u, 0u, 0u, 1u };
    libbgp_alloc_t alloc = update_fail_alloc_make(&fail);

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_EXISTS,
        libbgp_update_parse(&msg, duplicate_origin_body, sizeof(duplicate_origin_body), &used));
    LIBBGP_ASSERT_EQ_U64(88u, used);
    LIBBGP_ASSERT_EQ_U64(0u, msg.attr_count);

    libbgp_set_alloc(&alloc);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM,
        libbgp_update_parse(&msg, withdrawn_body, sizeof(withdrawn_body), &used));
    libbgp_set_alloc(NULL);
    LIBBGP_ASSERT_EQ_U64(1u, fail.realloc_calls);
    LIBBGP_ASSERT_EQ_U64(0u, msg.withdrawn_count);

    fail.realloc_calls = 0u;
    fail.fail_on_realloc = 0u;
    fail.fail_on_calloc = 1u;
    libbgp_set_alloc(&alloc);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM,
        libbgp_update_parse(&msg, origin_body, sizeof(origin_body), &used));
    libbgp_set_alloc(NULL);
    LIBBGP_ASSERT_EQ_U64(1u, fail.calloc_calls);
    LIBBGP_ASSERT_EQ_U64(0u, msg.attr_count);

    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_as4_aggregator_allocation_failures_preserve_state)
{
    libbgp_update_msg_t msg;
    libbgp_pattr_t *aggregator = make_aggregator_attr(LIBBGP_PATTR_AGGREGATOR, 65551u, 0xc6336401u, true);
    libbgp_pattr_t *as4_aggregator = make_aggregator_attr(LIBBGP_PATTR_AS4_AGGREGATOR, 65552u, 0xc6336402u, true);
    update_fail_alloc_ctx_t fail = { 0u, 0u, 0u, 0u, 1u, 0u };
    libbgp_alloc_t alloc = update_fail_alloc_make(&fail);

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as4_aggregator));
    libbgp_set_alloc(&alloc);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, libbgp_update_restore_aggregator(&msg));
    libbgp_set_alloc(NULL);
    LIBBGP_ASSERT(libbgp_update_find_attr(&msg, LIBBGP_PATTR_AGGREGATOR) == NULL);
    LIBBGP_ASSERT(libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS4_AGGREGATOR) == as4_aggregator);
    libbgp_update_destroy(&msg);

    fail.calloc_calls = 0u;
    fail.realloc_calls = 0u;
    fail.fail_on_calloc = 1u;
    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, aggregator));
    libbgp_set_alloc(&alloc);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, libbgp_update_downgrade_aggregator(&msg));
    libbgp_set_alloc(NULL);
    LIBBGP_ASSERT_EQ_U64(65551u, aggregator->data.aggregator.asn);
    LIBBGP_ASSERT(aggregator->data.aggregator.is_4b);
    LIBBGP_ASSERT(libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS4_AGGREGATOR) == NULL);

    libbgp_pattr_unref(as4_aggregator);
    libbgp_pattr_unref(aggregator);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_write_rejects_attr_length_boundary_and_prefix_overflow_state)
{
    uint8_t out[16];
    size_t out_len = 66u;
    libbgp_update_msg_t msg;
    libbgp_pattr_t *unknown = libbgp_pattr_new(LIBBGP_PATTR_UNKNOWN);

    LIBBGP_ASSERT(unknown != NULL);
    libbgp_update_init(&msg);
    unknown->flags = LIBBGP_PATTR_FLAG_OPTIONAL | LIBBGP_PATTR_FLAG_EXTENDED_LENGTH;
    unknown->type_code = 99u;
    unknown->data.unknown.len = 65536u;
    unknown->data.unknown.value = (uint8_t *)calloc(unknown->data.unknown.len, sizeof(unknown->data.unknown.value[0]));
    LIBBGP_ASSERT(unknown->data.unknown.value != NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, unknown));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_write(&msg, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(66u, out_len);

    libbgp_pattr_unref(unknown);
    libbgp_update_destroy(&msg);
}


LIBBGP_TEST(update_write_exact_buffer_and_one_byte_short)
{
    const uint8_t expected[] = {
        0u, 4u,
        24u, 198u, 51u, 100u,
        0u, 0u
    };
    uint8_t exact[sizeof(expected)];
    uint8_t short_buf[sizeof(expected) - 1u];
    size_t out_len = 123u;
    libbgp_update_msg_t msg;
    libbgp_prefix4_t withdrawn;

    withdrawn.addr = update_ip4(198u, 51u, 100u, 0u);
    withdrawn.len = 24u;
    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_withdrawn(&msg, &withdrawn));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BUFFER,
        libbgp_update_write(&msg, short_buf, sizeof(short_buf), &out_len));
    LIBBGP_ASSERT_EQ_U64(123u, out_len);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK,
        libbgp_update_write(&msg, exact, sizeof(exact), &out_len));
    LIBBGP_ASSERT_EQ_U64(sizeof(expected), out_len);
    LIBBGP_ASSERT_BYTES_EQ(expected, exact, sizeof(expected));

    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_parse_rejects_duplicate_unknown_wire_attrs)
{
    const uint8_t body[] = {
        0u, 0u,
        0u, 8u,
        0x80u, 99u, 1u, 1u,
        0x80u, 99u, 1u, 2u
    };
    size_t used = 77u;
    libbgp_update_msg_t msg;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_EXISTS, libbgp_update_parse(&msg, body, sizeof(body), &used));
    LIBBGP_ASSERT_EQ_U64(77u, used);
    LIBBGP_ASSERT_EQ_U64(0u, msg.attr_count);
    LIBBGP_ASSERT(msg.attrs == NULL);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_as4_public_state_edge_branches)
{
    uint32_t asns[] = { 64512u };
    libbgp_update_msg_t msg;
    libbgp_pattr_t *as_path = make_as_path_attr(LIBBGP_PATTR_AS_PATH, false, asns, 1u);
    libbgp_pattr_t *found;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_restore_as_path(&msg));
    LIBBGP_ASSERT_EQ_U64(0u, msg.attr_count);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_restore_as_path(&msg));
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT(found->data.as_path.is_4b);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_downgrade_as_path(&msg));
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT(!found->data.as_path.is_4b);
    LIBBGP_ASSERT(libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS4_PATH) == NULL);

    libbgp_pattr_unref(as_path);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_downgrade_as_path_realloc_failure_preserves_original_path)
{
    uint32_t asns[] = { 64512u, 65551u };
    libbgp_update_msg_t msg;
    libbgp_pattr_t *as_path = make_as_path_attr(LIBBGP_PATTR_AS_PATH, true, asns, 2u);
    libbgp_pattr_t *found;
    update_fail_alloc_ctx_t fail = { 0u, 0u, 0u, 0u, 0u, 1u };
    libbgp_alloc_t alloc = update_fail_alloc_make(&fail);

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));

    libbgp_set_alloc(&alloc);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, libbgp_update_downgrade_as_path(&msg));
    libbgp_set_alloc(NULL);
    LIBBGP_ASSERT_EQ_U64(1u, fail.realloc_calls);

    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT(found->data.as_path.is_4b);
    LIBBGP_ASSERT_EQ_U64(2u, found->data.as_path.segments[0].asn_count);
    LIBBGP_ASSERT_EQ_U64(64512u, found->data.as_path.segments[0].asns[0]);
    LIBBGP_ASSERT_EQ_U64(65551u, found->data.as_path.segments[0].asns[1]);
    LIBBGP_ASSERT(libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS4_PATH) == NULL);

    libbgp_pattr_unref(as_path);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_validate_rejects_as_path_width_mismatch_public_state)
{
    uint32_t wide_asn[] = { 65536u };
    libbgp_update_msg_t msg;
    libbgp_pattr_t *as_path = make_as_path_attr(LIBBGP_PATTR_AS_PATH, false, wide_asn, 1u);
    libbgp_pattr_t *as4_path = make_as_path_attr(LIBBGP_PATTR_AS4_PATH, true, wide_asn, 1u);

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_validate(&msg));
    libbgp_update_destroy(&msg);

    as4_path->data.as_path.is_4b = false;
    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as4_path));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_validate(&msg));
    libbgp_update_destroy(&msg);

    libbgp_pattr_unref(as4_path);
    libbgp_pattr_unref(as_path);
}

LIBBGP_TEST(update_parse_rejects_extended_attr_length_past_attribute_block)
{
    const uint8_t body[] = {
        0u, 0u,
        0u, 5u,
        0xd0u, 99u, 0u, 2u, 1u
    };
    size_t used = 42u;
    libbgp_update_msg_t msg;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_parse(&msg, body, sizeof(body), &used));
    LIBBGP_ASSERT_EQ_U64(42u, used);
    LIBBGP_ASSERT_EQ_U64(0u, msg.attr_count);
    LIBBGP_ASSERT(msg.attrs == NULL);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_parse_rejects_mp_reach_with_link_local_nexthop)
{
    const uint8_t body[] = {
        0u, 0u,
        0u, 45u,
        0x80u, 14u, 42u,
        0u, 2u,
        1u,
        32u,
        0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0u, 0u, 0u,
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u,
        0xfeu, 0x80u, 0u, 0u, 0u, 0u, 0u, 0u,
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u,
        0u,
        32u, 0x20u, 0x01u, 0x0du, 0xb8u
    };
    size_t used = 0u;
    libbgp_update_msg_t msg;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_update_parse(&msg, body, sizeof(body), &used));
    LIBBGP_ASSERT_EQ_U64(0u, msg.attr_count);
    LIBBGP_ASSERT(msg.attrs == NULL);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_write_mp_reach_ipv6_exact_and_short_buffer)
{
    uint32_t asns[] = { 64512u };
    uint8_t exact[64];
    uint8_t short_buf[45];
    size_t out_len = 123u;
    libbgp_update_msg_t msg;
    libbgp_pattr_t *origin = libbgp_pattr_new(LIBBGP_PATTR_ORIGIN);
    libbgp_pattr_t *as_path = make_as_path_attr(LIBBGP_PATTR_AS_PATH, true, asns, 1u);
    libbgp_pattr_t *mp_reach = libbgp_pattr_new(LIBBGP_PATTR_MP_REACH_IPV6);
    libbgp_prefix6_t nlri;
    const uint8_t nexthop[] = {
        0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0u, 0u, 0u,
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u
    };

    LIBBGP_ASSERT(origin != NULL);
    LIBBGP_ASSERT(mp_reach != NULL);
    memset(&nlri, 0, sizeof(nlri));
    nlri.len = 32u;
    nlri.addr[0] = 0x20u;
    nlri.addr[1] = 0x01u;
    nlri.addr[2] = 0x0du;
    nlri.addr[3] = 0xb8u;
    memcpy(mp_reach->data.mp_reach_ipv6.nexthop, nexthop, sizeof(nexthop));
    mp_reach->data.mp_reach_ipv6.nexthop_len = sizeof(nexthop);
    mp_reach->data.mp_reach_ipv6.nlri = &nlri;
    mp_reach->data.mp_reach_ipv6.nlri_count = 1u;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, origin));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, mp_reach));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BUFFER,
        libbgp_update_write(&msg, short_buf, sizeof(short_buf), &out_len));
    LIBBGP_ASSERT_EQ_U64(123u, out_len);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_write(&msg, exact, sizeof(exact), &out_len));
    LIBBGP_ASSERT_EQ_U64(46u, out_len);

    mp_reach->data.mp_reach_ipv6.nlri = NULL;
    mp_reach->data.mp_reach_ipv6.nlri_count = 0u;
    libbgp_pattr_unref(mp_reach);
    libbgp_pattr_unref(as_path);
    libbgp_pattr_unref(origin);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_parse_rejects_truncated_withdrawn_and_attr_blocks)
{
    const uint8_t truncated_withdrawn[] = {
        0u, 4u,
        24u, 198u, 51u
    };
    const uint8_t truncated_attrs[] = {
        0u, 0u,
        0u, 4u,
        0x40u, 1u, 1u
    };
    size_t used = 77u;
    libbgp_update_msg_t msg;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN,
        libbgp_update_parse(&msg, truncated_withdrawn, sizeof(truncated_withdrawn), &used));
    LIBBGP_ASSERT_EQ_U64(77u, used);
    LIBBGP_ASSERT_EQ_U64(0u, msg.withdrawn_count);
    libbgp_update_destroy(&msg);

    libbgp_update_init(&msg);
    used = 88u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN,
        libbgp_update_parse(&msg, truncated_attrs, sizeof(truncated_attrs), &used));
    LIBBGP_ASSERT_EQ_U64(88u, used);
    LIBBGP_ASSERT_EQ_U64(0u, msg.attr_count);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_validate_accepts_mp_reach_ipv6_with_mandatory_attrs)
{
    uint32_t asns[] = { 64512u };
    const uint8_t nexthop[] = {
        0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0u, 0u, 0u,
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u
    };
    libbgp_update_msg_t msg;
    libbgp_prefix6_t ipv6_nlri;
    libbgp_pattr_t *origin = libbgp_pattr_new(LIBBGP_PATTR_ORIGIN);
    libbgp_pattr_t *as_path = make_as_path_attr(LIBBGP_PATTR_AS_PATH, true, asns, 1u);
    libbgp_pattr_t *mp_reach = libbgp_pattr_new(LIBBGP_PATTR_MP_REACH_IPV6);

    LIBBGP_ASSERT(origin != NULL);
    LIBBGP_ASSERT(mp_reach != NULL);
    memset(&ipv6_nlri, 0, sizeof(ipv6_nlri));
    ipv6_nlri.len = 32u;
    ipv6_nlri.addr[0] = 0x20u;
    ipv6_nlri.addr[1] = 0x01u;
    ipv6_nlri.addr[2] = 0x0du;
    ipv6_nlri.addr[3] = 0xb8u;
    origin->data.origin.origin = 0u;
    memcpy(mp_reach->data.mp_reach_ipv6.nexthop, nexthop, sizeof(nexthop));
    mp_reach->data.mp_reach_ipv6.nexthop_len = sizeof(nexthop);
    mp_reach->data.mp_reach_ipv6.nlri = &ipv6_nlri;
    mp_reach->data.mp_reach_ipv6.nlri_count = 1u;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, origin));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, mp_reach));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_validate(&msg));

    mp_reach->data.mp_reach_ipv6.nlri = NULL;
    mp_reach->data.mp_reach_ipv6.nlri_count = 0u;
    libbgp_pattr_unref(mp_reach);
    libbgp_pattr_unref(as_path);
    libbgp_pattr_unref(origin);
    libbgp_update_destroy(&msg);
}

int main(void)
{
    const libbgp_test_case_t tests[] = {
        { "update_parse_write_empty_fixture_body", update_parse_write_empty_fixture_body },
        { "update_parse_write_with_withdrawn_attrs_and_nlri", update_parse_write_with_withdrawn_attrs_and_nlri },
        { "update_parse_write_withdraw_only_without_mandatory_attrs", update_parse_write_withdraw_only_without_mandatory_attrs },
        { "update_parse_rejects_ipv4_prefix_length_over_32", update_parse_rejects_ipv4_prefix_length_over_32 },
        { "update_rejects_duplicate_attrs_and_missing_mandatory_attrs", update_rejects_duplicate_attrs_and_missing_mandatory_attrs },
        { "update_parse_as4_reads_four_octet_as_path_and_aggregator", update_parse_as4_reads_four_octet_as_path_and_aggregator },
        { "update_as4_helpers_restore_downgrade_prepend_and_aggregator", update_as4_helpers_restore_downgrade_prepend_and_aggregator },
        { "update_prepend_asn_creates_missing_two_octet_as_path", update_prepend_asn_creates_missing_two_octet_as_path },
        { "update_prepend_asn_creates_missing_four_octet_as_path", update_prepend_asn_creates_missing_four_octet_as_path },
        { "update_prepend_asn_rejects_four_octet_mode_when_as4_path_exists", update_prepend_asn_rejects_four_octet_mode_when_as4_path_exists },
        { "update_prepend_asn_rejects_as_path_width_mismatch", update_prepend_asn_rejects_as_path_width_mismatch },
        { "update_restore_as_path_replaces_as_trans_positionally_when_counts_match", update_restore_as_path_replaces_as_trans_positionally_when_counts_match },
        { "update_restore_as_path_consumes_as4_path_only_for_as_trans_when_counts_differ", update_restore_as_path_consumes_as4_path_only_for_as_trans_when_counts_differ },
        { "update_restore_as_path_falls_back_to_suffix_when_sparse_counts_differ", update_restore_as_path_falls_back_to_suffix_when_sparse_counts_differ },
        { "update_restore_as_path_preserves_prefix_as_trans_for_mixed_suffix", update_restore_as_path_preserves_prefix_as_trans_for_mixed_suffix },
        { "update_restore_aggregator_creates_aggregator_from_as4_aggregator_only", update_restore_aggregator_creates_aggregator_from_as4_aggregator_only },
        { "update_prepend_2byte_peer_preserves_true_asn_in_as4_path", update_prepend_2byte_peer_preserves_true_asn_in_as4_path },
        { "update_prepend_2byte_peer_creates_as4_path_when_needed", update_prepend_2byte_peer_creates_as4_path_when_needed },
        { "update_restore_as_path_uses_as4_path_as_structural_suffix", update_restore_as_path_uses_as4_path_as_structural_suffix },
        { "update_restore_as_path_rejects_as4_path_longer_than_as_path", update_restore_as_path_rejects_as4_path_longer_than_as_path },
        { "update_prepend_partial_as4_path_restores_without_losing_prefix", update_prepend_partial_as4_path_restores_without_losing_prefix },
        { "update_prepend_as4_failure_leaves_paths_unchanged", update_prepend_as4_failure_leaves_paths_unchanged },
        { "update_restore_rejects_as4_boundary_inside_as_set", update_restore_rejects_as4_boundary_inside_as_set },
        { "update_restore_preserves_as_set_prefix_at_suffix_boundary", update_restore_preserves_as_set_prefix_at_suffix_boundary },
        { "update_restore_rejects_malformed_replaced_as_path_suffix", update_restore_rejects_malformed_replaced_as_path_suffix },
        { "update_rejects_as_path_segment_count_over_255", update_rejects_as_path_segment_count_over_255 },
        { "update_prepend_as4_attr_add_failure_leaves_paths_unchanged", update_prepend_as4_attr_add_failure_leaves_paths_unchanged },
        { "update_downgrade_2byte_as_path_omits_unneeded_as4_path", update_downgrade_2byte_as_path_omits_unneeded_as4_path },
        { "update_add_helpers_ref_attrs_and_write_fixture_body", update_add_helpers_ref_attrs_and_write_fixture_body },
        { "update_rejects_bad_lengths_and_small_output", update_rejects_bad_lengths_and_small_output },
        { "update_parse_rejects_malformed_attr_segment_and_preserves_state", update_parse_rejects_malformed_attr_segment_and_preserves_state },
        { "update_parse_allows_unknown_attr_passthrough_length", update_parse_allows_unknown_attr_passthrough_length },
        { "update_rejects_malformed_as_path_public_arrays", update_rejects_malformed_as_path_public_arrays },
        { "update_restore_allows_as_set_boundary_at_first_asn", update_restore_allows_as_set_boundary_at_first_asn },
        { "update_validate_rejects_nonzero_counts_with_null_arrays", update_validate_rejects_nonzero_counts_with_null_arrays },
        { "update_write_rejects_invalid_prefix_arrays_and_small_output", update_write_rejects_invalid_prefix_arrays_and_small_output },
        { "update_public_helpers_reject_null_inputs", update_public_helpers_reject_null_inputs },
        { "update_add_prefix_realloc_failure_preserves_empty_message", update_add_prefix_realloc_failure_preserves_empty_message },
        { "update_add_attr_rejects_broken_state_and_realloc_failure", update_add_attr_rejects_broken_state_and_realloc_failure },
        { "update_validate_rejects_each_missing_mandatory_ipv4_attr", update_validate_rejects_each_missing_mandatory_ipv4_attr },
        { "update_validate_rejects_mp_reach_without_origin_or_as_path", update_validate_rejects_mp_reach_without_origin_or_as_path },
        { "update_restore_and_prepend_reject_malformed_as_path_state", update_restore_and_prepend_reject_malformed_as_path_state },
        { "update_public_helpers_reject_attr_semantic_duplicates_and_bad_prefixes", update_public_helpers_reject_attr_semantic_duplicates_and_bad_prefixes },
        { "update_prepend_handles_empty_and_full_first_segments", update_prepend_handles_empty_and_full_first_segments },
        { "update_prepend_allocation_failures_preserve_original_path", update_prepend_allocation_failures_preserve_original_path },
        { "update_prepend_new_path_allocation_failures_leave_message_empty", update_prepend_new_path_allocation_failures_leave_message_empty },
        { "update_downgrade_rejects_malformed_as_path_shadow_states", update_downgrade_rejects_malformed_as_path_shadow_states },
        { "update_downgrade_allocation_failure_preserves_original_path", update_downgrade_allocation_failure_preserves_original_path },
        { "update_small_branch_regressions_cover_invalid_helpers", update_small_branch_regressions_cover_invalid_helpers },
        { "update_validate_rejects_duplicate_semantic_attrs_in_public_state", update_validate_rejects_duplicate_semantic_attrs_in_public_state },
        { "update_restore_as_path_rejects_invalid_as4_shadow_state", update_restore_as_path_rejects_invalid_as4_shadow_state },
        { "update_restore_as_path_allocation_failure_preserves_shadow_attr", update_restore_as_path_allocation_failure_preserves_shadow_attr },
        { "update_prepend_rejects_invalid_first_segment_state", update_prepend_rejects_invalid_first_segment_state },
        { "update_parse_rejects_duplicate_wire_attrs_and_nomem_paths", update_parse_rejects_duplicate_wire_attrs_and_nomem_paths },
        { "update_as4_aggregator_allocation_failures_preserve_state", update_as4_aggregator_allocation_failures_preserve_state },
        { "update_write_rejects_attr_length_boundary_and_prefix_overflow_state", update_write_rejects_attr_length_boundary_and_prefix_overflow_state },
        { "update_write_exact_buffer_and_one_byte_short", update_write_exact_buffer_and_one_byte_short },
        { "update_parse_rejects_duplicate_unknown_wire_attrs", update_parse_rejects_duplicate_unknown_wire_attrs },
        { "update_as4_public_state_edge_branches", update_as4_public_state_edge_branches },
        { "update_downgrade_as_path_realloc_failure_preserves_original_path", update_downgrade_as_path_realloc_failure_preserves_original_path },
        { "update_validate_rejects_as_path_width_mismatch_public_state", update_validate_rejects_as_path_width_mismatch_public_state },
        { "update_parse_rejects_extended_attr_length_past_attribute_block", update_parse_rejects_extended_attr_length_past_attribute_block },
        { "update_parse_rejects_mp_reach_with_link_local_nexthop", update_parse_rejects_mp_reach_with_link_local_nexthop },
        { "update_write_mp_reach_ipv6_exact_and_short_buffer", update_write_mp_reach_ipv6_exact_and_short_buffer },
        { "update_parse_rejects_truncated_withdrawn_and_attr_blocks", update_parse_rejects_truncated_withdrawn_and_attr_blocks },
        { "update_validate_accepts_mp_reach_ipv6_with_mandatory_attrs", update_validate_accepts_mp_reach_ipv6_with_mandatory_attrs }
    };

    return libbgp_run_tests("update", tests, LIBBGP_ARRAY_LEN(tests));
}
