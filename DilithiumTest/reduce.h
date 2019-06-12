#ifndef REDUCE_H
#define REDUCE_H

#include <stdint.h>

 /* 2^32 % DILITHIUM_Q */
#define DILITHIUM_MONT 4193792U
 /* -q^(-1) mod 2^32 */
#define DILITHIUM_QINV 4236238847U

/*************************************************
* Name:        montgomery_reduce
*
* Description: For finite field element a with 0 <= a <= DILITHIUM_Q*2^32,
*              compute r \equiv a*2^{-32} (mod DILITHIUM_Q) such that 0 <= r < 2*DILITHIUM_Q.
*
* Arguments:   - uint64_t: finite field element a
*
* Returns r.
**************************************************/
uint32_t montgomery_reduce(uint64_t a);

/*************************************************
* Name:        reduce32
*
* Description: For finite field element a, compute r \equiv a (mod DILITHIUM_Q)
*              such that 0 <= r < 2*DILITHIUM_Q.
*
* Arguments:   - uint32_t: finite field element a
*
* Returns r.
**************************************************/
uint32_t reduce32(uint32_t a);

/*************************************************
* Name:        csubq
*
* Description: Subtract DILITHIUM_Q if input coefficient is bigger than DILITHIUM_Q.
*
* Arguments:   - uint32_t: finite field element a
*
* Returns r.
**************************************************/
uint32_t csubq(uint32_t a);

/*************************************************
* Name:        freeze
*
* Description: For finite field element a, compute standard
*              representative r = a mod DILITHIUM_Q.
*
* Arguments:   - uint32_t: finite field element a
*
* Returns r.
**************************************************/
uint32_t freeze(uint32_t a);

#endif
