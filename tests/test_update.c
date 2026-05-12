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
    LIBBGP_ASSERT_EQ_U64(65000u, as_path->data.as_path.segments[0].asns[0]);
    LIBBGP_ASSERT_EQ_U64(0xc00002feu, next_hop->data.next_hop.next_hop);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_write(&msg, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(sizeof(body), out_len);
    LIBBGP_ASSERT_BYTES_EQ(body, out, sizeof(body));
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
    uint32_t set_asns[] = { 64512u, 64513u };
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
    LIBBGP_ASSERT_EQ_U64(64512u, found->data.as_path.segments[0].asns[0]);
    LIBBGP_ASSERT_EQ_U64(64513u, found->data.as_path.segments[0].asns[1]);
    LIBBGP_ASSERT_EQ_U64(2u, found->data.as_path.segments[1].type);
    LIBBGP_ASSERT_EQ_U64(1u, found->data.as_path.segments[1].asn_count);
    LIBBGP_ASSERT_EQ_U64(65551u, found->data.as_path.segments[1].asns[0]);

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
    next_hop->data.next_hop.next_hop = 0xc00002feu;
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
}

int main(void)
{
    const libbgp_test_case_t tests[] = {
        { "update_parse_write_empty_fixture_body", update_parse_write_empty_fixture_body },
        { "update_parse_write_with_withdrawn_attrs_and_nlri", update_parse_write_with_withdrawn_attrs_and_nlri },
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
        { "update_validate_rejects_nonzero_counts_with_null_arrays", update_validate_rejects_nonzero_counts_with_null_arrays }
    };

    return libbgp_run_tests("update", tests, LIBBGP_ARRAY_LEN(tests));
}
