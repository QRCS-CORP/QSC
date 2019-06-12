#ifndef PACKING_H
#define PACKING_H

#include <stdint.h>
#include "params.h"
#include "polyvec.h"

/*************************************************
* Name:        pack_pk
*
* Description: Bit-pack public key pk = (rho, t1).
*
* Arguments:   - uint8_t pk[]: output byte array
*              - const uint8_t rho[]: byte array containing rho
*              - const polyveck *t1: pointer to vector t1
**************************************************/
void pack_pk(uint8_t pk[DILITHIUM_PUBLICKEY_SIZE], const uint8_t rho[DILITHIUM_SEED_SIZE], const polyveck* t1);

/*************************************************
* Name:        unpack_pk
*
* Description: Unpack public key pk = (rho, t1).
*
* Arguments:   - const uint8_t rho[]: output byte array for rho
*              - const polyveck *t1: pointer to output vector t1
*              - uint8_t pk[]: byte array containing bit-packed pk
**************************************************/
void unpack_pk(uint8_t rho[DILITHIUM_SEED_SIZE], polyveck* t1, const uint8_t pk[DILITHIUM_PUBLICKEY_SIZE]);

/*************************************************
* Name:        pack_sk
*
* Description: Bit-pack secret key sk = (rho, key, tr, s1, s2, t0).
*
* Arguments:   - uint8_t sk[]: output byte array
*              - const uint8_t rho[]: byte array containing rho
*              - const uint8_t key[]: byte array containing key
*              - const uint8_t tr[]: byte array containing tr
*              - const polyvecl *s1: pointer to vector s1
*              - const polyveck *s2: pointer to vector s2
*              - const polyveck *t0: pointer to vector t0
**************************************************/
void pack_sk(uint8_t sk[DILITHIUM_SECRETKEY_SIZE], const uint8_t rho[DILITHIUM_SEED_SIZE], const uint8_t key[DILITHIUM_SEED_SIZE], const uint8_t tr[DILITHIUM_CRH_SIZE], const polyvecl* s1, const polyveck* s2, const polyveck* t0);

/*************************************************
* Name:        unpack_sk
*
* Description: Unpack secret key sk = (rho, key, tr, s1, s2, t0).
*
* Arguments:   - const uint8_t rho[]: output byte array for rho
*              - const uint8_t key[]: output byte array for key
*              - const uint8_t tr[]: output byte array for tr
*              - const polyvecl *s1: pointer to output vector s1
*              - const polyveck *s2: pointer to output vector s2
*              - const polyveck *r0: pointer to output vector t0
*              - uint8_t sk[]: byte array containing bit-packed sk
**************************************************/
void unpack_sk(uint8_t rho[DILITHIUM_SEED_SIZE], uint8_t key[DILITHIUM_SEED_SIZE], uint8_t tr[DILITHIUM_CRH_SIZE], polyvecl* s1, polyveck* s2, polyveck* t0, const uint8_t sk[DILITHIUM_SECRETKEY_SIZE]);

/*************************************************
* Name:        pack_sig
*
* Description: Bit-pack signature sig = (z, h, c).
*
* Arguments:   - uint8_t sig[]: output byte array
*              - const polyvecl *z: pointer to vector z
*              - const polyveck *h: pointer to hint vector h
*              - const poly *c: pointer to challenge polynomial
**************************************************/
void pack_sig(uint8_t sig[DILITHIUM_SIGNATURE_SIZE], const polyvecl* z, const polyveck* h, const poly* c);

/*************************************************
* Name:        unpack_sig
*
* Description: Unpack signature sig = (z, h, c).
*
* Arguments:   - polyvecl *z: pointer to output vector z
*              - polyveck *h: pointer to output hint vector h
*              - poly *c: pointer to output challenge polynomial
*              - const uint8_t sig[]: byte array containing
*                bit-packed signature
*
* Returns 1 in case of malformed signature; otherwise 0.
**************************************************/
int32_t unpack_sig(polyvecl* z, polyveck* h, poly* c, const uint8_t sig[DILITHIUM_SIGNATURE_SIZE]);

#endif
