#ifndef QCX_SPX_FORS_H
#define QCX_SPX_FORS_H

#include "common.h"

/**
 * Derives the FORS public key from a signature.
 * This can be used for verification by comparing to a known public key, or to
 * subsequently verify a signature on the derived public key. The latter is the
 * typical use-case when used as an FTS below an OTS in a hypertree.
 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
 */
void fors_pk_from_sig(uint8_t* pk, const uint8_t* sig, const uint8_t* m, const uint8_t* pub_seed, const uint32_t fors_addr[8]);

/**
 * Signs a message m, deriving the secret key from sk_seed and the FTS address.
 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
 */
void fors_sign(uint8_t* sig, uint8_t* pk, const uint8_t* m, const uint8_t* sk_seed, const uint8_t* pub_seed, const uint32_t fors_addr[8]);

#endif
