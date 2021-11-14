/* HKDF-HMACSHA512 (RFC 5869)
 *
 * This is an implementation of HKDF based on HMAC-SHA512, using the
 * Sodium crypto library's HMAC-SHA512 implementation
 * (http://doc.libsodium.org/).
 *
 */

#include <stdint.h> /* for uintptr_t */
#include <string.h> /* for memcpy */
#include <assert.h> /* for assert */
#include <sodium.h> /* Use libsodium's HMAC-SHA512 implementation */
#include "hkdf_hmacsha512.h"

int
hkdf_hmacsha512_extract(
    const void *salt, 
    size_t salt_len, 
    const void *ikm, 
    size_t ikm_len,
    void * prk,
    size_t prk_len  /* must be HASH_LEN */
)
{
    int ret = E_HKDF_SUCCESS;
    crypto_auth_hmacsha512_state state;

    /* Input validation */
    if ( NULL == salt && 0 != salt_len )
    {
        ret = E_HKDF_LENGTH;
        goto cleanup;
    }

    if ( (uintptr_t) salt + salt_len < (uintptr_t) salt )
    /* Address wraps around */
    {
        ret = E_HKDF_OVERFLOW;
        goto cleanup;
    }

    if ( NULL == ikm && 0 != ikm_len )
    {
        ret = E_HKDF_LENGTH;
        goto cleanup;
    }

    if ( (uintptr_t) ikm + ikm_len < (uintptr_t) ikm )
    /* Address wraps around */
    {
        ret = E_HKDF_OVERFLOW;
        goto cleanup;
    }

    if ( NULL == prk )
    {
        ret = E_HKDF_NULLPTR;
        goto cleanup;
    }

    if ( HASH_LEN != prk_len )
    {
        ret = E_HKDF_LENGTH;
        goto cleanup;
    }

    if ( (uintptr_t) prk + prk_len < (uintptr_t) prk )
    /* Address wraps around */
    {
        ret = E_HKDF_OVERFLOW;
        goto cleanup;
    }

    /* sodium_init() is not thread safe; add locks if needed */
    if (-1 == sodium_init())
    {
        ret = E_HKDF_INIT;
        goto cleanup;
    }

    if (0 != crypto_auth_hmacsha512_init(
                                    &state,
                                    salt,
                                    salt_len))
    {
        ret = E_HKDF_INIT;
        goto cleanup;
    }

    if ( 0 != crypto_auth_hmacsha512_update(
                                     &state, 
                                     ikm,
                                     (unsigned long long) ikm_len))
    {
        ret = E_HKDF_FAILURE;
        goto cleanup;
    }

    if ( 0 != crypto_auth_hmacsha512_final(&state, prk) )
    {
        ret = E_HKDF_FAILURE;
        goto cleanup;
    }

cleanup:

    sodium_memzero(&state, sizeof(state)); 
    return ret;
}

int
hkdf_hmacsha512_expand(
        const void *prk, 
        size_t prk_len,    /* must be >= HASH_LEN */
        const void *info,  /* can be NULL */
        size_t info_len,   /* can be 0 */
        void * output,
        size_t output_len /* must be <= 255 * HASH_LEN */
)

{
    int ret = E_HKDF_SUCCESS;
    crypto_auth_hmacsha512_state state;
    unsigned char tmp_block[HASH_LEN]; 
    unsigned char * T = NULL;
    int i;
    unsigned char seq = 0;


    assert(HASH_LEN == sizeof(tmp_block) / sizeof(tmp_block[0]));

    /* Input validation */
    if ( NULL == prk )
    {
        ret = E_HKDF_NULLPTR;
        goto cleanup;
    }

    if ( prk_len < HASH_LEN )
    {
        ret = E_HKDF_LENGTH;
        goto cleanup;
    }

    if ( (uintptr_t) prk + prk_len < (uintptr_t) prk )
    /* Address wraps around */
    {
        ret = E_HKDF_OVERFLOW;
        goto cleanup;
    }

    if ( NULL == info && 0 != info_len )
    {
        ret = E_HKDF_LENGTH;
        goto cleanup;
    }

    if ( (uintptr_t) info + info_len < (uintptr_t) info )
    /* Address wraps around */
    {
        ret = E_HKDF_OVERFLOW;
        goto cleanup;
    }

    if ( (NULL == output && 0 != output_len) || 
                 output_len > 255 * HASH_LEN )
    {
        ret = E_HKDF_LENGTH;
        goto cleanup;
    }

    if ( (uintptr_t) output + output_len < (uintptr_t) output )
    /* Address wraps around */
    {
        ret = E_HKDF_OVERFLOW;
        goto cleanup;
    }

    /* sodium_init() is not thread safe; add locks if needed */
    if (-1 == sodium_init())
    {
        ret = E_HKDF_INIT;
        goto cleanup;
    }

    size_t N = (output_len + HASH_LEN - 1) / HASH_LEN; /* ceiling */

    if ( 0 == N ) goto cleanup;

    for ( i = 0; i < N - 1; ++i )
    {
        /* need to call _init again after _final */
        if (0 != crypto_auth_hmacsha512_init(
                                    &state,
                                    prk,
                                    prk_len))
        {
            ret = E_HKDF_INIT;
            goto cleanup;
        }

        if ( 0 != crypto_auth_hmacsha512_update(
                                     &state,
                                     T,
                                     NULL == T ? 0 : HASH_LEN))
        {
            ret = E_HKDF_FAILURE;
            goto cleanup;
        }

        if ( 0 != crypto_auth_hmacsha512_update(
                                     &state,
                                     info,
                                     (unsigned long long) info_len))
        {
            ret = E_HKDF_FAILURE;
            goto cleanup;
        }


        seq = (unsigned char) (i + 1);
        if ( 0 != crypto_auth_hmacsha512_update(
                                     &state,
                                     &seq ,
                                     1))
        {
            ret = E_HKDF_FAILURE;
            goto cleanup;
        }

        if ( 0 != crypto_auth_hmacsha512_final(&state, 
                   (unsigned char *) output + i * HASH_LEN) )
        {
            ret = E_HKDF_FAILURE;
            goto cleanup;
        }
        T = (unsigned char *) output + i * HASH_LEN;

    }
    /* Last block */
     
    if (0 != crypto_auth_hmacsha512_init(
                                    &state,
                                    prk,
                                    prk_len))
    {
        ret = E_HKDF_INIT;
        goto cleanup;
    }

    if ( 0 != crypto_auth_hmacsha512_update(
                                     &state,
                                     T,
                                     NULL == T ? 0 : HASH_LEN))
    {
        ret = E_HKDF_FAILURE;
        goto cleanup;
    }

    if ( 0 != crypto_auth_hmacsha512_update(
                                     &state,
                                     info,
                                     (unsigned long long) info_len))
    {
        ret = E_HKDF_FAILURE;
        goto cleanup;
    }


    seq = (unsigned char) (i + 1);
    if ( 0 != crypto_auth_hmacsha512_update(
                                     &state,
                                     &seq ,
                                     1))
    {
        ret = E_HKDF_FAILURE;
        goto cleanup;
    }

    if ( 0 != crypto_auth_hmacsha512_final(&state, 
                                           tmp_block) )
    {
        ret = E_HKDF_FAILURE;
        goto cleanup;
    }

    if ( 0 == output_len % HASH_LEN )
    {
        memcpy( (unsigned char *) output + (N - 1) * HASH_LEN,
                tmp_block, 
                HASH_LEN);
    }
    else 
    {
        memcpy( (unsigned char *) output + (N - 1) * HASH_LEN,
                tmp_block,
                output_len % HASH_LEN);
    }

cleanup:

    sodium_memzero(&state, sizeof(state)); 
    sodium_memzero(tmp_block, sizeof(tmp_block) / sizeof(tmp_block[0]));
    return ret;
}

