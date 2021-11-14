#ifndef _HKDF_HMACSHA512_H
#define _HKDF_HMACSHA512_H

#include <sys/types.h>
#include <stdint.h>

/* This is an implementation of the Hashed Message Authentication Code
 * (HMAC)-based key derivation function (HKDF) using SHA-512.  The
 * specification is RFC5869 (https://tools.ietf.org/html/rfc5869).  All
 * buffer size and output length are in bytes (octets).  
 *
 * Return values: 
 * 0 for success, non-zero for errors 
 *
 * All sensitive data is zeroized before return.
 *
 */

#ifdef	__cplusplus
extern "C" {
#endif

// SHA-512 output length
#define HASH_LEN 64

/* Error codes */
#define E_HKDF_SUCCESS 0
#define E_HKDF_INIT 1
#define E_HKDF_NULLPTR 2
#define E_HKDF_LENGTH 3
#define E_HKDF_OVERFLOW 4
#define E_HKDF_FAILURE -1

/* Step 1: Extract
 *
 * HKDF-Extract(salt, IKM) -> PRK
 * Options:
 *    Hash     a hash function; we use SHA-512 in this implementation
 * Inputs:
 *    salt     optional salt value (a non-secret random value); if not
 * .           provided, it is set to a string of HASH_LEN zeros.
 *    ikm      input keying material
 * Output:
 *    prk      a pseudorandom key (of HASH_LEN octets)
*/
int
hkdf_hmacsha512_extract(
    const void *salt, 
    size_t salt_len,
    const void *ikm,
    size_t ikm_len,
    void * prk,
    size_t prk_len  /* must be HASH_LEN */
);

/* Step 2: Expand
 *
 * HKDF-Expand(PRK, info, L) -> OKM
 *
 * Options:
 *    Hash       a hash function; we use SHA-512 in this implementation
 *
 * Inputs:
 *    prk        a pseudorandom key of at least HashLen octet
 *               (usually, the output from the extract step)
 *    info       optional context and application specific information
 *               (can be a zero-length string)
 *    output_len length of output keying material in octets
 *               (<= 255 * HashLen)
 *
 * Output:
 *    output        output keying material (of output_len octets)
*/

int
hkdf_hmacsha512_expand(
    const void *prk,
    size_t prk_len,    /* must be >= HASH_LEN */
    const void *info,  /* can be NULL */
    size_t info_len,   /* can be 0 */
    void * output,
    size_t output_len /* must be <= 255 * HASH_LEN */
);

#ifdef	__cplusplus
}
#endif

#endif /* _HKDF_HMACSHA512_H */
