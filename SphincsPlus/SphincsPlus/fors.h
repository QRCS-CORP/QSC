/**
* \file fors.h
* \brief <b>Sphincs FORS functions</b> \n
* This is an internal class.
*
* \date October 29, 2018
*/

#ifndef SPX_FORS_H
#define SPX_FORS_H

#include "common.h"
#include "params.h"

 /**
 * \brief Derives the FORS public key from a signature.
 * This can be used for verification by comparing to a known public key, or to
 * subsequently verify a signature on the derived public key. The latter is the
 * typical use-case when used as an FTS below an OTS in a hypertree.
 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
 *
 * \param publickey The pubic verification key
 * \param signature The message signature
 * \param message The input message
 * \param publicseed The publickey seed array
 * \param forsaddress The fors address table
 */
void fors_pk_from_sig(uint8_t* publickey, const uint8_t* signature, const uint8_t* message, const uint8_t* publicseed, const uint32_t* forsaddress);

 /**
 * \brief Signs a message m, deriving the secret key from sk_seed and the FTS address.
 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
 *
 * \param signature The output signature
 * \param publickey The pubic verification key
 * \param message The input message
 * \param secretseed The secret key seed array
 * \param publicseed The publickey seed array
 * \param forsaddress The fors address table
 */
void fors_sign(uint8_t* signature, uint8_t* publickey, const uint8_t* message, const uint8_t* secretseed, const uint8_t* publicseed, const uint32_t* forsaddress);

#endif
