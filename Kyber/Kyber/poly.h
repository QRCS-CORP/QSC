/**
* \file poly.h
* \brief <b>Kyber polynomial functions</b> \n
* This is an internal class.
*
* \date January 10, 2018
*/

#ifndef KYBER_POLY_H
#define KYBER_POLY_H

#include <stdint.h>
#include "params.h"
/* jgu -suppressing repeated include warning, using include guards */
/*lint -e537 */

/**
* \struct poly
* \brief Contains an N sized array of 16bit coefficients. /n
* Elements of R_q = Z_q[X] / (X^n + 1). /n
* Represents polynomial coeffs[0] + X * coeffs[1] + X^2 * xoeffs[2] + ... + X^{n-1} * coeffs[n-1] 
*
* \var poly::coeffs
* The array of 16bit coefficients
*/
typedef struct
{
	uint16_t coeffs[KYBER_N];
} poly;

/**
* \brief Given an array of uniformly random bytes,
* compute a polynomial with coefficients distributed according to
* a centered binomial distribution with parameter KYBER_ETA.
*
* \param r Pointer to output polynomial
* \param buf Pointer to input byte array
*/
void cbd(poly* r, const uint8_t* buf);

/**
* \brief Compression and subsequent serialization of a polynomial.
*
* \param r Pointer to output byte array
* \param a Pointer to input polynomial
*/
void poly_compress(uint8_t* r, poly* a);

/**
* \brief De-serialization and subsequent decompression of a polynomial;
* approximate inverse of poly_compress.
*
* \param r Pointer to output polynomial
* \param a Pointer to input byte array
*/
void poly_decompress(poly* r, const uint8_t* a);

/**
* \brief Serialization of a polynomial
*
* \param r Pointer to output byte array
* \param a Pointer to input polynomial
*/
void poly_tobytes(uint8_t* r, poly* a);

/**
* \brief De-serialization of a polynomial; inverse of poly_tobytes.
*
* \param r Pointer to output polynomial
* \param a Pointer to input byte array
*/
void poly_frombytes(poly* r, const uint8_t* a);

/**
* \brief Convert 32-byte message to polynomial.
*
* \param r Pointer to output polynomial
* \param msg Pointer to input message
*/
void poly_frommsg(poly *r, const uint8_t msg[KYBER_SYMBYTES]);

/**
* \brief Convert polynomial to 32-byte message.
*
* \param msg Pointer to output message
* \param a Pointer to input polynomial
*/
void poly_tomsg(uint8_t msg[KYBER_SYMBYTES], poly *a);

/**
* \brief Sample a polynomial deterministically from a seed and a nonce,
* with output polynomial close to centered binomial distribution with parameter KYBER_ETA.
*
* \param r Pointer to output polynomial
* \param seed Pointer to input seed
* \param nonce one-byte input nonce
*/
void poly_getnoise(poly* r, const uint8_t* seed, uint8_t nonce);

/**
* \brief Computes negacyclic number-theoretic transform (NTT) of a polynomial in place;
* inputs assumed to be in normal order, output in bitreversed order.
*
* \param r Pointer to input/output polynomial
*/
void poly_ntt(poly* r);

/**
* \brief Computes inverse of negacyclic number-theoretic transform (NTT) of a polynomial in place;
* inputs assumed to be in bitreversed order, output in normal order.
*
* \param r a Pointer to in/output polynomial
*/
void poly_invntt(poly* r);

/**
* \brief Add two polynomials.
*
* \param r Pointer to output polynomial
* \param a Pointer to first input polynomial
* \param b Pointer to second input polynomial
*/
void poly_add(poly* r, const poly* a, const poly* b);

/**
* \brief Applies conditional subtraction of q to each coefficient of a polynomial
*
* \param poly pointer to input/output polynomial
*/
void poly_csubq(poly *r);

/**
* \brief Applies Barrett reduction to all coefficients of a polynomial
*
* \param poly pointer to input/output polynomial
*/
void poly_reduce(poly *r);

/**
* \brief Subtract two polynomials.
*
* \param r Pointer to output polynomial
* \param a Pointer to first input polynomial
* \param b Pointer to second input polynomial
*/
void poly_sub(poly* r, const poly* a, const poly* b);

/**
* \brief Inplace conversion of all coefficients of a polynomial
* from Montgomery domain to normal domain
*
* \param r Pointer to output polynomial
*/
void poly_frommont(poly* r);

/**
* \brief Multiplication of two polynomials in NTT domain
*
* \param r Pointer to output polynomial
* \param a Pointer to first input polynomial
* \param b Pointer to second input polynomial
*/
void poly_basemul(poly* r, const poly* a, const poly* b);

#endif
