#include "test_main.h"

#include "libbgp/prefix4.h"
#include "libbgp/prefix6.h"
#include "libbgp/types.h"

static uint32_t net32(const uint8_t bytes[4])
{
    uint32_t value;

    memcpy(&value, bytes, sizeof(value));
    return value;
}

LIBBGP_TEST(prefix4_parse_write_roundtrip_masks_partial)
{
    const uint8_t zero_in[] = { 0u };
    const uint8_t zero_out_exp[] = { 0u };
    const uint8_t p24_in[] = { 24u, 192u, 0u, 2u };
    const uint8_t p24_out_exp[] = { 24u, 192u, 0u, 2u };
    const uint8_t p9_in[] = { 9u, 192u, 255u };
    const uint8_t p9_out_exp[] = { 9u, 192u, 128u };
    libbgp_prefix4_t p;
    uint8_t out[5];
    size_t used;
    size_t out_len;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_prefix4_parse(&p, zero_in, sizeof(zero_in), &used));
    LIBBGP_ASSERT_EQ_U64(1u, used);
    LIBBGP_ASSERT_EQ_U64(0u, p.len);
    LIBBGP_ASSERT_EQ_U64(0u, p.addr);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_prefix4_write(&p, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(sizeof(zero_out_exp), out_len);
    LIBBGP_ASSERT_BYTES_EQ(zero_out_exp, out, sizeof(zero_out_exp));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_prefix4_parse(&p, p24_in, sizeof(p24_in), &used));
    LIBBGP_ASSERT_EQ_U64(sizeof(p24_in), used);
    LIBBGP_ASSERT_EQ_U64(24u, p.len);
    LIBBGP_ASSERT_EQ_U64(net32((const uint8_t[]){ 192u, 0u, 2u, 0u }), p.addr);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_prefix4_write(&p, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(sizeof(p24_out_exp), out_len);
    LIBBGP_ASSERT_BYTES_EQ(p24_out_exp, out, sizeof(p24_out_exp));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_prefix4_parse(&p, p9_in, sizeof(p9_in), &used));
    LIBBGP_ASSERT_EQ_U64(sizeof(p9_in), used);
    LIBBGP_ASSERT_EQ_U64(9u, p.len);
    LIBBGP_ASSERT_EQ_U64(net32((const uint8_t[]){ 192u, 128u, 0u, 0u }), p.addr);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_prefix4_write(&p, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(sizeof(p9_out_exp), out_len);
    LIBBGP_ASSERT_BYTES_EQ(p9_out_exp, out, sizeof(p9_out_exp));
}

LIBBGP_TEST(prefix4_rejects_invalid_lengths_and_buffers)
{
    const uint8_t invalid_len[] = { 33u, 1u, 2u, 3u, 4u };
    const uint8_t short_buf[] = { 24u, 203u, 0u };
    const uint8_t valid[] = { 24u, 203u, 0u, 113u };
    libbgp_prefix4_t p = { 0u, 0u };
    uint8_t out[3];
    size_t marker = 99u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_prefix4_parse(NULL, valid, sizeof(valid), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_prefix4_parse(&p, NULL, sizeof(valid), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_prefix4_parse(&p, valid, 0u, &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_prefix4_parse(&p, invalid_len, sizeof(invalid_len), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_prefix4_parse(&p, short_buf, sizeof(short_buf), &marker));
    LIBBGP_ASSERT_EQ_U64(99u, marker);

    p.addr = net32((const uint8_t[]){ 203u, 0u, 113u, 0u });
    p.len = 24u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_prefix4_write(NULL, out, sizeof(out), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_prefix4_write(&p, NULL, sizeof(out), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BUFFER, libbgp_prefix4_write(&p, out, sizeof(out), &marker));
    LIBBGP_ASSERT_EQ_U64(99u, marker);

    p.len = 33u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_prefix4_write(&p, out, sizeof(out), &marker));
}

LIBBGP_TEST(prefix4_parse_write_exact_32_boundary_and_nullable_lengths)
{
    const uint8_t in[] = { 32u, 203u, 0u, 113u, 255u };
    uint8_t out[sizeof(in)];
    size_t used = 99u;
    size_t out_len = 99u;
    libbgp_prefix4_t p;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_prefix4_parse(&p, in, sizeof(in), &used));
    LIBBGP_ASSERT_EQ_U64(sizeof(in), used);
    LIBBGP_ASSERT_EQ_U64(32u, p.len);
    LIBBGP_ASSERT_EQ_U64(net32((const uint8_t[]){ 203u, 0u, 113u, 255u }), p.addr);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_prefix4_parse(&p, in, sizeof(in), NULL));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_prefix4_write(&p, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(sizeof(in), out_len);
    LIBBGP_ASSERT_BYTES_EQ(in, out, sizeof(in));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_prefix4_write(&p, out, sizeof(out), NULL));
}

LIBBGP_TEST(prefix4_mask_eq_includes_cmp)
{
    libbgp_prefix4_t root = { 0u, 0u };
    libbgp_prefix4_t p24 = { net32((const uint8_t[]){ 192u, 0u, 2u, 0u }), 24u };
    libbgp_prefix4_t p25 = { net32((const uint8_t[]){ 192u, 0u, 2u, 128u }), 25u };
    libbgp_prefix4_t p24_copy = { net32((const uint8_t[]){ 192u, 0u, 2u, 0u }), 24u };
    libbgp_prefix4_t p24_high = { net32((const uint8_t[]){ 192u, 0u, 3u, 0u }), 24u };
    libbgp_prefix4_t invalid = { 0u, 33u };

    LIBBGP_ASSERT_EQ_U64(0x00000000u, libbgp_cidr_to_mask(0u));
    LIBBGP_ASSERT_EQ_U64(net32((const uint8_t[]){ 0xffu, 0u, 0u, 0u }), libbgp_cidr_to_mask(8u));
    LIBBGP_ASSERT_EQ_U64(net32((const uint8_t[]){ 0xffu, 0xffu, 0xffu, 0u }), libbgp_cidr_to_mask(24u));
    LIBBGP_ASSERT_EQ_U64(net32((const uint8_t[]){ 0xffu, 0xffu, 0xffu, 0xffu }), libbgp_cidr_to_mask(32u));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_cidr_to_mask(33u));

    LIBBGP_ASSERT(libbgp_prefix4_eq(&p24, &p24_copy));
    LIBBGP_ASSERT(!libbgp_prefix4_eq(&p24, &p25));
    LIBBGP_ASSERT(!libbgp_prefix4_eq(NULL, &p24));

    LIBBGP_ASSERT(libbgp_prefix4_includes(&root, &p24));
    LIBBGP_ASSERT(libbgp_prefix4_includes(&p24, &p25));
    LIBBGP_ASSERT(!libbgp_prefix4_includes(&p25, &p24));
    LIBBGP_ASSERT(!libbgp_prefix4_includes(&invalid, &p24));
    LIBBGP_ASSERT(!libbgp_prefix4_includes(&p24, NULL));

    LIBBGP_ASSERT_EQ_I64(0, libbgp_prefix4_cmp(&p24, &p24_copy));
    LIBBGP_ASSERT(libbgp_prefix4_cmp(NULL, &p24) < 0);
    LIBBGP_ASSERT(libbgp_prefix4_cmp(&p24, NULL) > 0);
    LIBBGP_ASSERT(libbgp_prefix4_cmp(&p24, &p25) < 0);
    LIBBGP_ASSERT(libbgp_prefix4_cmp(&p25, &p24) > 0);
    LIBBGP_ASSERT(libbgp_prefix4_cmp(&p24, &p24_high) < 0);
}

LIBBGP_TEST(prefix6_parse_write_roundtrip_masks_partial)
{
    const uint8_t zero_in[] = { 0u };
    const uint8_t zero_out_exp[] = { 0u };
    const uint8_t p64_in[] = { 64u, 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0u, 0u, 0u };
    const uint8_t p64_out_exp[] = { 64u, 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0u, 0u, 0u };
    const uint8_t p65_in[] = { 65u, 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0u, 0u, 0u, 0xffu };
    const uint8_t p65_out_exp[] = { 65u, 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0u, 0u, 0u, 0x80u };
    const uint8_t p65_addr_exp[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0u, 0u, 0u, 0x80u };
    libbgp_prefix6_t p;
    uint8_t out[18];
    size_t used;
    size_t out_len;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_prefix6_parse(&p, zero_in, sizeof(zero_in), &used));
    LIBBGP_ASSERT_EQ_U64(1u, used);
    LIBBGP_ASSERT_EQ_U64(0u, p.len);
    LIBBGP_ASSERT_BYTES_EQ((const uint8_t[16]){ 0u }, p.addr, 16u);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_prefix6_write(&p, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(sizeof(zero_out_exp), out_len);
    LIBBGP_ASSERT_BYTES_EQ(zero_out_exp, out, sizeof(zero_out_exp));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_prefix6_parse(&p, p64_in, sizeof(p64_in), &used));
    LIBBGP_ASSERT_EQ_U64(sizeof(p64_in), used);
    LIBBGP_ASSERT_EQ_U64(64u, p.len);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_prefix6_write(&p, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(sizeof(p64_out_exp), out_len);
    LIBBGP_ASSERT_BYTES_EQ(p64_out_exp, out, sizeof(p64_out_exp));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_prefix6_parse(&p, p65_in, sizeof(p65_in), &used));
    LIBBGP_ASSERT_EQ_U64(sizeof(p65_in), used);
    LIBBGP_ASSERT_EQ_U64(65u, p.len);
    LIBBGP_ASSERT_BYTES_EQ(p65_addr_exp, p.addr, 16u);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_prefix6_write(&p, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(sizeof(p65_out_exp), out_len);
    LIBBGP_ASSERT_BYTES_EQ(p65_out_exp, out, sizeof(p65_out_exp));
}

LIBBGP_TEST(prefix6_rejects_invalid_lengths_and_buffers)
{
    const uint8_t invalid_len[] = { 129u };
    const uint8_t short_buf[] = { 64u, 0x20u, 0x01u, 0x0du };
    const uint8_t valid[] = { 64u, 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0u, 0u, 0u };
    libbgp_prefix6_t p = { { 0u }, 0u };
    uint8_t out[8];
    size_t marker = 99u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_prefix6_parse(NULL, valid, sizeof(valid), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_prefix6_parse(&p, NULL, sizeof(valid), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_prefix6_parse(&p, valid, 0u, &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_prefix6_parse(&p, invalid_len, sizeof(invalid_len), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_prefix6_parse(&p, short_buf, sizeof(short_buf), &marker));
    LIBBGP_ASSERT_EQ_U64(99u, marker);

    p.addr[0] = 0x20u;
    p.addr[1] = 0x01u;
    p.len = 64u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_prefix6_write(NULL, out, sizeof(out), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_prefix6_write(&p, NULL, sizeof(out), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BUFFER, libbgp_prefix6_write(&p, out, sizeof(out), &marker));
    LIBBGP_ASSERT_EQ_U64(99u, marker);

    p.len = 129u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_prefix6_write(&p, out, sizeof(out), &marker));
}

LIBBGP_TEST(prefix6_parse_write_exact_128_boundary_and_nullable_lengths)
{
    const uint8_t in[] = {
        128u,
        0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0u, 0u, 0u,
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u
    };
    const uint8_t expected_addr[16] = {
        0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0u, 0u, 0u,
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u
    };
    uint8_t out[sizeof(in)];
    size_t used = 99u;
    size_t out_len = 99u;
    libbgp_prefix6_t p;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_prefix6_parse(&p, in, sizeof(in), &used));
    LIBBGP_ASSERT_EQ_U64(sizeof(in), used);
    LIBBGP_ASSERT_EQ_U64(128u, p.len);
    LIBBGP_ASSERT_BYTES_EQ(expected_addr, p.addr, sizeof(expected_addr));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_prefix6_parse(&p, in, sizeof(in), NULL));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_prefix6_write(&p, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(sizeof(in), out_len);
    LIBBGP_ASSERT_BYTES_EQ(in, out, sizeof(in));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_prefix6_write(&p, out, sizeof(out), NULL));
}

LIBBGP_TEST(prefix6_mask_eq_includes_cmp)
{
    libbgp_prefix6_t root = { { 0u }, 0u };
    libbgp_prefix6_t p64 = { { 0x20u, 0x01u, 0x0du, 0xb8u }, 64u };
    libbgp_prefix6_t p65 = { { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0u, 0u, 0u, 0x80u }, 65u };
    libbgp_prefix6_t p64_copy = { { 0x20u, 0x01u, 0x0du, 0xb8u }, 64u };
    libbgp_prefix6_t p64_high = { { 0x20u, 0x01u, 0x0du, 0xb9u }, 64u };
    libbgp_prefix6_t invalid = { { 0u }, 129u };
    const uint8_t zero_mask[16] = { 0u };
    const uint8_t p64_mask[16] = { 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu };
    const uint8_t p128_mask[16] = {
        0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu,
        0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu
    };
    uint8_t mask[16];

    libbgp_cidr6_to_mask(0u, mask);
    LIBBGP_ASSERT_BYTES_EQ(zero_mask, mask, 16u);
    libbgp_cidr6_to_mask(64u, mask);
    LIBBGP_ASSERT_BYTES_EQ(p64_mask, mask, 16u);
    libbgp_cidr6_to_mask(128u, mask);
    LIBBGP_ASSERT_BYTES_EQ(p128_mask, mask, 16u);
    libbgp_cidr6_to_mask(129u, mask);
    LIBBGP_ASSERT_BYTES_EQ(zero_mask, mask, 16u);
    libbgp_cidr6_to_mask(64u, NULL);

    LIBBGP_ASSERT(libbgp_prefix6_eq(&p64, &p64_copy));
    LIBBGP_ASSERT(!libbgp_prefix6_eq(&p64, &p65));
    LIBBGP_ASSERT(!libbgp_prefix6_eq(NULL, &p64));

    LIBBGP_ASSERT(libbgp_prefix6_includes(&root, &p64));
    LIBBGP_ASSERT(libbgp_prefix6_includes(&p64, &p65));
    LIBBGP_ASSERT(!libbgp_prefix6_includes(&p65, &p64));
    LIBBGP_ASSERT(!libbgp_prefix6_includes(&invalid, &p64));
    LIBBGP_ASSERT(!libbgp_prefix6_includes(&p64, NULL));

    LIBBGP_ASSERT_EQ_I64(0, libbgp_prefix6_cmp(&p64, &p64_copy));
    LIBBGP_ASSERT(libbgp_prefix6_cmp(NULL, &p64) < 0);
    LIBBGP_ASSERT(libbgp_prefix6_cmp(&p64, NULL) > 0);
    LIBBGP_ASSERT(libbgp_prefix6_cmp(&p64, &p65) < 0);
    LIBBGP_ASSERT(libbgp_prefix6_cmp(&p65, &p64) > 0);
    LIBBGP_ASSERT(libbgp_prefix6_cmp(&p64, &p64_high) < 0);
}

LIBBGP_TEST(test_cidr_to_mask_all_values)
{
    uint8_t bytes32[4];
    uint32_t mask32;
    uint8_t bytes8[4];
    uint32_t mask8;

    /* /0 should be all zeros */
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_cidr_to_mask(0));
    /* /32 should be all ones in NBO */
    mask32 = libbgp_cidr_to_mask(32);
    memcpy(bytes32, &mask32, 4);
    LIBBGP_ASSERT_EQ_U64(0xffu, bytes32[0]);
    LIBBGP_ASSERT_EQ_U64(0xffu, bytes32[1]);
    LIBBGP_ASSERT_EQ_U64(0xffu, bytes32[2]);
    LIBBGP_ASSERT_EQ_U64(0xffu, bytes32[3]);
    /* /8 */
    mask8 = libbgp_cidr_to_mask(8);
    memcpy(bytes8, &mask8, 4);
    LIBBGP_ASSERT_EQ_U64(0xffu, bytes8[0]);
    LIBBGP_ASSERT_EQ_U64(0x00u, bytes8[1]);
    LIBBGP_ASSERT_EQ_U64(0x00u, bytes8[2]);
    LIBBGP_ASSERT_EQ_U64(0x00u, bytes8[3]);
    /* /16 */
    uint8_t bytes16[4];
    uint32_t mask16 = libbgp_cidr_to_mask(16);
    memcpy(bytes16, &mask16, 4);
    LIBBGP_ASSERT_EQ_U64(0xffu, bytes16[0]);
    LIBBGP_ASSERT_EQ_U64(0xffu, bytes16[1]);
    LIBBGP_ASSERT_EQ_U64(0x00u, bytes16[2]);
    LIBBGP_ASSERT_EQ_U64(0x00u, bytes16[3]);
    /* /24 */
    uint8_t bytes24[4];
    uint32_t mask24 = libbgp_cidr_to_mask(24);
    memcpy(bytes24, &mask24, 4);
    LIBBGP_ASSERT_EQ_U64(0xffu, bytes24[0]);
    LIBBGP_ASSERT_EQ_U64(0xffu, bytes24[1]);
    LIBBGP_ASSERT_EQ_U64(0xffu, bytes24[2]);
    LIBBGP_ASSERT_EQ_U64(0x00u, bytes24[3]);
    /* /33 invalid */
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_cidr_to_mask(33));
}

int main(void)
{
    const libbgp_test_case_t tests[] = {
        { "prefix4_parse_write_roundtrip_masks_partial", prefix4_parse_write_roundtrip_masks_partial },
        { "prefix4_rejects_invalid_lengths_and_buffers", prefix4_rejects_invalid_lengths_and_buffers },
        { "prefix4_parse_write_exact_32_boundary_and_nullable_lengths", prefix4_parse_write_exact_32_boundary_and_nullable_lengths },
        { "prefix4_mask_eq_includes_cmp", prefix4_mask_eq_includes_cmp },
        { "prefix6_parse_write_roundtrip_masks_partial", prefix6_parse_write_roundtrip_masks_partial },
        { "prefix6_rejects_invalid_lengths_and_buffers", prefix6_rejects_invalid_lengths_and_buffers },
        { "prefix6_parse_write_exact_128_boundary_and_nullable_lengths", prefix6_parse_write_exact_128_boundary_and_nullable_lengths },
        { "prefix6_mask_eq_includes_cmp", prefix6_mask_eq_includes_cmp },
        { "test_cidr_to_mask_all_values", test_cidr_to_mask_all_values }
    };

    return libbgp_run_tests("prefix", tests, LIBBGP_ARRAY_LEN(tests));
}
