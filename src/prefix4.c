/**
 * @file prefix4.c
 * @brief IPv4 prefix wire-format and comparison helpers.
 */
#include "libbgp/prefix4.h"

#include <string.h>

#include "internal.h"

static size_t prefix4_octets(uint8_t cidr)
{
    return ((size_t)cidr + 7u) / 8u;
}

static uint8_t partial_mask(uint8_t bits)
{
    return (uint8_t)(0xffu << (8u - bits));
}

static const uint32_t cidr_masks_nbo[33] = {
    0x00000000u,
    0x80000000u, 0xc0000000u, 0xe0000000u, 0xf0000000u,
    0xf8000000u, 0xfc000000u, 0xfe000000u, 0xff000000u,
    0xff800000u, 0xffc00000u, 0xffe00000u, 0xfff00000u,
    0xfff80000u, 0xfffc0000u, 0xfffe0000u, 0xffff0000u,
    0xffff8000u, 0xffffc000u, 0xffffe000u, 0xfffff000u,
    0xfffff800u, 0xfffffc00u, 0xfffffe00u, 0xffffff00u,
    0xffffff80u, 0xffffffc0u, 0xffffffe0u, 0xfffffff0u,
    0xfffffff8u, 0xfffffffcu, 0xfffffffeu, 0xffffffffu
};

uint32_t libbgp_cidr_to_mask(uint8_t cidr)
{
    if (cidr > 32u) {
        return 0u;
    }
    /* Each entry N is the /N subnet mask in big-endian byte order:
     * index 8 -> 0xff000000u -> bytes {0xff, 0x00, 0x00, 0x00} */
    uint32_t hp = cidr_masks_nbo[cidr];
    uint8_t bytes[4];
    uint32_t result;
    bytes[0] = (uint8_t)(hp >> 24);
    bytes[1] = (uint8_t)(hp >> 16);
    bytes[2] = (uint8_t)(hp >> 8);
    bytes[3] = (uint8_t)(hp);
    memcpy(&result, bytes, sizeof(result));
    return result;
}

libbgp_err_t libbgp_prefix4_parse(
    libbgp_prefix4_t *p,
    const uint8_t *buf,
    size_t len,
    size_t *consumed)
{
    uint8_t cidr;
    size_t octets;
    uint8_t bytes[4] = { 0u, 0u, 0u, 0u };

    if (p == NULL || buf == NULL || len < 1u) {
        return LIBBGP_ERR_BAD_LEN;
    }

    cidr = buf[0];
    if (cidr > 32u) {
        return LIBBGP_ERR_INVALID;
    }

    octets = prefix4_octets(cidr);
    if (len < 1u + octets) {
        return LIBBGP_ERR_BAD_LEN;
    }

    if (octets != 0u) {
        memcpy(bytes, buf + 1u, octets);
        if ((cidr % 8u) != 0u) {
            bytes[octets - 1u] &= partial_mask((uint8_t)(cidr % 8u));
        }
    }

    memcpy(&p->addr, bytes, sizeof(p->addr));
    p->len = cidr;
    if (consumed != NULL) {
        *consumed = 1u + octets;
    }

    return LIBBGP_OK;
}

libbgp_err_t libbgp_prefix4_write(
    const libbgp_prefix4_t *p,
    uint8_t *buf,
    size_t len,
    size_t *out_len)
{
    size_t octets;
    uint8_t bytes[4];

    if (p == NULL || buf == NULL || p->len > 32u) {
        return LIBBGP_ERR_BAD_LEN;
    }

    octets = prefix4_octets(p->len);
    if (len < 1u + octets) {
        return LIBBGP_ERR_BUFFER;
    }

    memcpy(bytes, &p->addr, sizeof(bytes));
    if (octets != 0u && (p->len % 8u) != 0u) {
        bytes[octets - 1u] &= partial_mask((uint8_t)(p->len % 8u));
    }

    buf[0] = p->len;
    if (octets != 0u) {
        memcpy(buf + 1u, bytes, octets);
    }
    if (out_len != NULL) {
        *out_len = 1u + octets;
    }

    return LIBBGP_OK;
}

bool libbgp_prefix4_eq(const libbgp_prefix4_t *a, const libbgp_prefix4_t *b)
{
    if (a == NULL || b == NULL) {
        return false;
    }

    return a->addr == b->addr && a->len == b->len;
}

bool libbgp_prefix4_includes(
    const libbgp_prefix4_t *outer,
    const libbgp_prefix4_t *inner)
{
    uint32_t mask;

    if (outer == NULL || inner == NULL || outer->len > 32u || inner->len > 32u) {
        return false;
    }
    if (inner->len < outer->len) {
        return false;
    }

    mask = libbgp_cidr_to_mask(outer->len);
    return (inner->addr & mask) == (outer->addr & mask);
}

int libbgp_prefix4_cmp(const libbgp_prefix4_t *a, const libbgp_prefix4_t *b)
{
    uint8_t a_bytes[4];
    uint8_t b_bytes[4];
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

    memcpy(a_bytes, &a->addr, sizeof(a_bytes));
    memcpy(b_bytes, &b->addr, sizeof(b_bytes));
    cmp = memcmp(a_bytes, b_bytes, sizeof(a_bytes));
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
