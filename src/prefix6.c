/**
 * @file prefix6.c
 * @brief IPv6 prefix wire-format and comparison helpers.
 */
#include "libbgp/prefix6.h"

#include <string.h>

static size_t prefix6_octets(uint8_t cidr)
{
    return ((size_t)cidr + 7u) / 8u;
}

static uint8_t partial_mask(uint8_t bits)
{
    return (uint8_t)(0xffu << (8u - bits));
}

static void prefix6_mask_addr(uint8_t addr[16], uint8_t cidr)
{
    size_t octets;

    if (cidr == 0u) {
        memset(addr, 0, 16u);
        return;
    }

    octets = prefix6_octets(cidr);
    if ((cidr % 8u) != 0u) {
        addr[octets - 1u] &= partial_mask((uint8_t)(cidr % 8u));
    }
    if (octets < 16u) {
        memset(addr + octets, 0, 16u - octets);
    }
}

void libbgp_cidr6_to_mask(uint8_t cidr, uint8_t out[16])
{
    size_t full;
    uint8_t rem;
    size_t i;

    if (out == NULL) {
        return;
    }

    memset(out, 0, 16u);
    if (cidr > 128u) {
        return;
    }

    full = (size_t)cidr / 8u;
    rem = (uint8_t)(cidr % 8u);
    for (i = 0u; i < full; i++) {
        out[i] = 0xffu;
    }
    if (rem != 0u) {
        out[full] = partial_mask(rem);
    }
}

libbgp_err_t libbgp_prefix6_parse(
    libbgp_prefix6_t *p,
    const uint8_t *buf,
    size_t len,
    size_t *consumed)
{
    uint8_t cidr;
    size_t octets;

    if (p == NULL || buf == NULL || len < 1u) {
        return LIBBGP_ERR_BAD_LEN;
    }

    cidr = buf[0];
    if (cidr > 128u) {
        return LIBBGP_ERR_INVALID;
    }

    octets = prefix6_octets(cidr);
    if (len < 1u + octets) {
        return LIBBGP_ERR_BAD_LEN;
    }

    memset(p->addr, 0, sizeof(p->addr));
    if (octets != 0u) {
        memcpy(p->addr, buf + 1u, octets);
        prefix6_mask_addr(p->addr, cidr);
    }
    p->len = cidr;
    if (consumed != NULL) {
        *consumed = 1u + octets;
    }

    return LIBBGP_OK;
}

libbgp_err_t libbgp_prefix6_write(
    const libbgp_prefix6_t *p,
    uint8_t *buf,
    size_t len,
    size_t *out_len)
{
    size_t octets;
    uint8_t addr[16];

    if (p == NULL || buf == NULL || p->len > 128u) {
        return LIBBGP_ERR_BAD_LEN;
    }

    octets = prefix6_octets(p->len);
    if (len < 1u + octets) {
        return LIBBGP_ERR_BUFFER;
    }

    memcpy(addr, p->addr, sizeof(addr));
    prefix6_mask_addr(addr, p->len);

    buf[0] = p->len;
    if (octets != 0u) {
        memcpy(buf + 1u, addr, octets);
    }
    if (out_len != NULL) {
        *out_len = 1u + octets;
    }

    return LIBBGP_OK;
}

bool libbgp_prefix6_eq(const libbgp_prefix6_t *a, const libbgp_prefix6_t *b)
{
    if (a == NULL || b == NULL) {
        return false;
    }

    return a->len == b->len && memcmp(a->addr, b->addr, sizeof(a->addr)) == 0;
}

bool libbgp_prefix6_includes(
    const libbgp_prefix6_t *outer,
    const libbgp_prefix6_t *inner)
{
    uint8_t outer_addr[16];
    uint8_t inner_addr[16];

    if (outer == NULL || inner == NULL || outer->len > 128u || inner->len > 128u) {
        return false;
    }
    if (inner->len < outer->len) {
        return false;
    }

    memcpy(outer_addr, outer->addr, sizeof(outer_addr));
    memcpy(inner_addr, inner->addr, sizeof(inner_addr));
    prefix6_mask_addr(outer_addr, outer->len);
    prefix6_mask_addr(inner_addr, outer->len);

    return memcmp(outer_addr, inner_addr, sizeof(outer_addr)) == 0;
}

int libbgp_prefix6_cmp(const libbgp_prefix6_t *a, const libbgp_prefix6_t *b)
{
    int cmp;

    if (a == b) {
        return 0;
    }
    if (a == NULL) {
        return -1;
    }
    if (b == NULL) {
        return 1;
    }

    cmp = memcmp(a->addr, b->addr, sizeof(a->addr));
    if (cmp != 0) {
        return cmp;
    }
    if (a->len < b->len) {
        return -1;
    }
    if (a->len > b->len) {
        return 1;
    }

    return 0;
}
