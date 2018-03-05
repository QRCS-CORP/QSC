/**
* \file poly.h
* \date February 16, 2018
*
* \brief <b>NewHope polynomial api</b> \n
* This is an internal class.
*/

#ifndef NEWHOPE_POLY_H
#define NEWHOPE_POLY_H

#include "common.h"
#include "params.h"

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
  uint16_t coeffs[NEWHOPE_N];
} poly;

/**
* \brief Sample a polynomial deterministically from a seed,
* with output polynomial looking uniformly random
*
* \param a pointer to output polynomial
* \param seed pointer to input seed
*/
void poly_uniform(poly *a, const uint8_t *seed);

/**
* \brief Sample a polynomial deterministically from a seed and a nonce,
*  with output polynomial close to centered binomial distribution with parameter k=8
*
* \param r pointer to output polynomial
* \param seed pointer to input seed
* \param nonce one-byte input nonce
*/
void poly_sample(poly *r, const uint8_t *seed, uint8_t nonce);

/**
* \brief Add two polynomials
*
* \param r pointer to output polynomial
* \param a pointer to first input polynomial
* \param b pointer to second input polynomial
*/
void poly_add(poly *r, const poly *a, const poly *b);

/**
* \brief Forward NTT transform of a polynomial in place
*  Input is assumed to have coefficients in bitreversed order Output has coefficients in normal order
*
* \param r pointer to in/output polynomial
*/
void poly_ntt(poly *r);

/**
* \brief Inverse NTT transform of a polynomial in place
*  Input is assumed to have coefficients in normal order Output has coefficients in normal order
*
* \param r pointer to in/output polynomial
*/
void poly_invntt(poly *r);

/**
* \brief Multiply two polynomials pointwise (i.e., coefficient-wise).
*
* \param r pointer to output polynomial
* \param a pointer to first input polynomial
* \param b pointer to second input polynomial
*/
void poly_mul_pointwise(poly *r, const poly *a, const poly *b);

/**
* \brief De-serialization of a polynomial
*
* \param r pointer to output polynomial
* \param a pointer to input byte array
*/
void poly_frombytes(poly *r, const uint8_t *a);

/**
* \brief Serialization of a polynomial
*
* \param r pointer to output byte array
* \param p pointer to input polynomial
*/
void poly_tobytes(uint8_t *r, const poly *p);

/**
* \brief Compression and subsequent serialization of a polynomial
*
* \param r pointer to output byte array
* \param p pointer to input polynomial
*/
void poly_compress(uint8_t *r, const poly *p);

/**
* \brief De-serialization and subsequent decompression of a polynomial;
*  approximate inverse of poly_compress
*
* \param r pointer to output polynomial
* \param a pointer to input byte array
*/
void poly_decompress(poly *r, const uint8_t *a);

/**
* \brief Convert 32-byte message to polynomial
*
* \param r pointer to output polynomial
* \param msg pointer to input message
*/
void poly_frommsg(poly *r, const uint8_t *msg);

/**
* \brief Convert polynomial to 32-byte message
*
* \param msg pointer to output message
* \param x pointer to input polynomial
*/
void poly_tomsg(uint8_t *msg, const poly *x);

/**
* \brief Subtract two polynomials
*
* \param r pointer to output polynomial
* \param a pointer to first input polynomial
* \param b pointer to second input polynomial
*/
void poly_sub(poly *r, const poly *a, const poly *b);

#endif
