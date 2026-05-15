#ifndef LIBBGP_PATTR_H
#define LIBBGP_PATTR_H


/**
 * @file pattr.h
 * @brief BGP path attribute parsing, serialization, formatting, and reference counting.
 * @ingroup libbgp_packet
 */
/**
 * @file pattr.h
 * @brief BGP path attribute parsing, serialization, formatting, and reference counting.
 * @ingroup libbgp_packet
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "libbgp/types.h"
#include "libbgp/prefix6.h"

#define LIBBGP_PATTR_FLAG_OPTIONAL 0x80u          ///< Optional attribute flag
#define LIBBGP_PATTR_FLAG_TRANSITIVE 0x40u       ///< Transitive attribute flag
#define LIBBGP_PATTR_FLAG_PARTIAL 0x20u          ///< Partial attribute flag
#define LIBBGP_PATTR_FLAG_EXTENDED_LENGTH 0x10u  ///< Extended length attribute flag

#define LIBBGP_PATTR_CODE_ORIGIN 1u              ///< ORIGIN attribute type code
#define LIBBGP_PATTR_CODE_AS_PATH 2u             ///< AS_PATH attribute type code
#define LIBBGP_PATTR_CODE_NEXT_HOP 3u            ///< NEXT_HOP attribute type code
#define LIBBGP_PATTR_CODE_MED 4u                 ///< MULTI_EXIT_DISC (MED) attribute type code
#define LIBBGP_PATTR_CODE_LOCAL_PREF 5u          ///< LOCAL_PREF attribute type code
#define LIBBGP_PATTR_CODE_ATOMIC_AGGREGATE 6u    ///< ATOMIC_AGGREGATE attribute type code
#define LIBBGP_PATTR_CODE_AGGREGATOR 7u          ///< AGGREGATOR attribute type code
#define LIBBGP_PATTR_CODE_COMMUNITY 8u           ///< COMMUNITY attribute type code
#define LIBBGP_PATTR_CODE_MP_REACH_NLRI 14u      ///< MP_REACH_NLRI attribute type code
#define LIBBGP_PATTR_CODE_MP_UNREACH_NLRI 15u    ///< MP_UNREACH_NLRI attribute type code
#define LIBBGP_PATTR_CODE_AS4_PATH 17u           ///< AS4_PATH attribute type code
#define LIBBGP_PATTR_CODE_AS4_AGGREGATOR 18u     ///< AS4_AGGREGATOR attribute type code

typedef enum libbgp_pattr_type {
    LIBBGP_PATTR_ORIGIN,            ///< ORIGIN path attribute
    LIBBGP_PATTR_AS_PATH,           ///< AS_PATH path attribute
    LIBBGP_PATTR_NEXT_HOP,          ///< NEXT_HOP path attribute
    LIBBGP_PATTR_MED,               ///< MULTI_EXIT_DISC (MED) path attribute
    LIBBGP_PATTR_LOCAL_PREF,        ///< LOCAL_PREF path attribute
    LIBBGP_PATTR_ATOMIC_AGGREGATE,  ///< ATOMIC_AGGREGATE path attribute
    LIBBGP_PATTR_AGGREGATOR,        ///< AGGREGATOR path attribute
    LIBBGP_PATTR_COMMUNITY,         ///< COMMUNITY path attribute
    LIBBGP_PATTR_AS4_PATH,          ///< AS4_PATH path attribute (4-byte ASNs)
    LIBBGP_PATTR_AS4_AGGREGATOR,    ///< AS4_AGGREGATOR path attribute (4-byte ASNs)
    LIBBGP_PATTR_MP_REACH_IPV6,     ///< MP_REACH_NLRI for IPv6
    LIBBGP_PATTR_MP_UNREACH_IPV6,   ///< MP_UNREACH_NLRI for IPv6
    LIBBGP_PATTR_UNKNOWN            ///< Unknown/experimental attribute
} libbgp_pattr_type_t;

/**
 * @brief AS path segment container.
 */
typedef struct libbgp_as_path_segment {
    uint8_t type;
    size_t asn_count;
    uint32_t *asns;
} libbgp_as_path_segment_t;

/**
 * @brief BGP path attribute object.
 *
 * Objects are reference-counted. `*_new()` returns one reference, `*_ref()`
 * adds a reference, and `*_unref()` releases one reference and destroys the
 * object when the count reaches zero.
 */
struct libbgp_pattr {
    uint32_t refcount;
    uint8_t flags;
    uint8_t type_code;
    libbgp_pattr_type_t type;
    union {
        struct { uint8_t origin; } origin;
        struct {
            libbgp_as_path_segment_t *segments;
            size_t segment_count;
            bool is_4b;
        } as_path;
        struct { uint32_t next_hop; } next_hop;
        struct { uint32_t value; } med;
        struct { uint32_t value; } local_pref;
        struct {
            uint32_t asn;
            uint32_t router_id;
            bool is_4b;
        } aggregator;
        struct {
            uint32_t *values;
            size_t count;
        } community;
        struct {
            uint8_t nexthop[32];
            size_t nexthop_len;
            libbgp_prefix6_t *nlri;
            size_t nlri_count;
        } mp_reach_ipv6;
        struct {
            libbgp_prefix6_t *withdrawn;
            size_t withdrawn_count;
        } mp_unreach_ipv6;
        struct {
            uint8_t *value;
            size_t len;
        } unknown;
    } data;
};

/**
 * @brief Allocate a new path attribute object of the given type.
 * @param type Attribute type to create.
 * @return Newly allocated reference-counted object or NULL on allocation failure.
 */
LIBBGP_API libbgp_pattr_t *libbgp_pattr_new(libbgp_pattr_type_t type);

/**
 * @brief Increment the reference count of a path attribute object.
 * @param attr Object to add a reference to.
 * @return The same object pointer (or NULL if `attr` is NULL).
 */
LIBBGP_API libbgp_pattr_t *libbgp_pattr_ref(libbgp_pattr_t *attr);

/**
 * @brief Release a reference to a path attribute object; free when count reaches zero.
 * @param attr Object to unreference.
 */
LIBBGP_API void libbgp_pattr_unref(libbgp_pattr_t *attr);

/**
 * @brief Determine a path attribute type from wire buffer contents.
 * @param buf Buffer containing the attribute header and value.
 * @param len Length of |buf| in bytes.
 * @return The decoded libbgp_pattr_type_t value.
 */
LIBBGP_API libbgp_pattr_type_t libbgp_pattr_type_from_buf(const uint8_t *buf, size_t len);

/**
 * @brief Return a textual name for a path attribute type.
 * @param type Path attribute type value.
 * @return A static string naming |type|.
 */
LIBBGP_API const char *libbgp_pattr_type_name(libbgp_pattr_type_t type);

/**
 * @brief Parse a path attribute from wire data into |attr|.
 * @param attr Receives a newly allocated reference-counted object on success.
 * @param buf Source buffer containing the attribute (flags, type, length, value).
 * @param len Length of |buf| in bytes.
 * @param consumed Receives the number of bytes consumed from |buf|; may be NULL.
 * @return `LIBBGP_OK` on success, `LIBBGP_ERR_PARSE` for malformed input,
 *         `LIBBGP_ERR_BUFFER` for incomplete input, or `LIBBGP_ERR_NOMEM`.
 */
LIBBGP_API libbgp_err_t libbgp_pattr_parse(
    libbgp_pattr_t *attr,
    const uint8_t *buf,
    size_t len,
    size_t *consumed);

/**
 * @brief Parse a path attribute using optional 4-octet ASN parsing for AS fields.
 * @param attr Receives a newly allocated reference-counted object on success.
 * @param buf Source buffer containing the attribute.
 * @param len Length of |buf| in bytes.
 * @param use_4b_asn Parse AS_PATH and AGGREGATOR values using four-octet ASNs when `true`.
 * @param consumed Receives the number of bytes consumed from |buf|; may be NULL.
 * @return `LIBBGP_OK` on success, `LIBBGP_ERR_PARSE` for malformed input,
 *         `LIBBGP_ERR_BUFFER` for incomplete input, or `LIBBGP_ERR_NOMEM`.
 */
LIBBGP_API libbgp_err_t libbgp_pattr_parse_as4(
    libbgp_pattr_t *attr,
    const uint8_t *buf,
    size_t len,
    bool use_4b_asn,
    size_t *consumed);

/**
 * @brief Compute the wire length required to serialize |attr|.
 * @param attr Attribute to measure.
 * @param out_len Receives the required wire length in bytes.
 * @return `LIBBGP_OK` on success or `LIBBGP_ERR_INVALID` if the attribute cannot be serialized.
 */
LIBBGP_API libbgp_err_t libbgp_pattr_wire_len(const libbgp_pattr_t *attr, size_t *out_len);

/**
 * @brief Serialize a path attribute to wire format.
 * @param attr Attribute to serialize.
 * @param buf Destination buffer to write into.
 * @param buf_len Size of |buf| in bytes.
 * @param out_len Receives the number of bytes written; may be NULL.
 * @return `LIBBGP_OK` on success, `LIBBGP_ERR_BUFFER` if |buf_len| is too small,
 *         or `LIBBGP_ERR_INVALID` if the object cannot be serialized.
 */
LIBBGP_API libbgp_err_t libbgp_pattr_write(
    const libbgp_pattr_t *attr,
    uint8_t *buf,
    size_t buf_len,
    size_t *out_len);

/**
 * @brief Prepare an attribute for forwarding to an eBGP peer (may modify state).
 * @param attr Attribute to prepare.
 * @return `LIBBGP_OK` on success or `LIBBGP_ERR_INVALID` on failure.
 */
LIBBGP_API libbgp_err_t libbgp_pattr_prepare_for_ebgp_forward(libbgp_pattr_t *attr);

/**
 * @brief Format a path attribute to a textual representation.
 * @param attr Attribute to format.
 * @param buf Destination text buffer.
 * @param buf_len Size of |buf| in bytes.
 * @param out_len Receives the number of bytes written to |buf|; may be NULL.
 * @return `LIBBGP_OK` when formatting completed, or `LIBBGP_ERR_BUFFER` if |buf| is too small.
 */
LIBBGP_API libbgp_err_t libbgp_pattr_format(
    const libbgp_pattr_t *attr,
    char *buf,
    size_t buf_len,
    size_t *out_len);

#endif
