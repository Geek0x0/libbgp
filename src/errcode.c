#include "libbgp/types.h"

const char *libbgp_strerror(libbgp_err_t err)
{
    switch (err) {
    case LIBBGP_OK:            return "ok";
    case LIBBGP_ERR:           return "error";
    case LIBBGP_ERR_PARSE:     return "parse error";
    case LIBBGP_ERR_WRITE:     return "write error";
    case LIBBGP_ERR_BAD_TYPE:  return "bad type";
    case LIBBGP_ERR_BAD_LEN:   return "bad length";
    case LIBBGP_ERR_BUFFER:    return "buffer too small";
    case LIBBGP_ERR_INVALID:   return "invalid value";
    case LIBBGP_ERR_EXISTS:    return "already exists";
    case LIBBGP_ERR_NOT_FOUND: return "not found";
    case LIBBGP_ERR_NOMEM:     return "out of memory";
    default:                   return "unknown error";
    }
}
