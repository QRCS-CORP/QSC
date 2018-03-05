/**
* \file poly.h
* \brief <b>Kyber polynomial functions</b> \n
* This is an internal class.
*
* \date January 10, 2018
*/

#ifndef KYBER_POLY_H
#define KYBER_POLY_H

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
	uint16_t coeffs[KYBER_N];
} poly;

/**
* \brief Compression and subsequent serialization of a polynomial.
*
* \param r Pointer to output byte array
* \param a Pointer to input polynomial
*/
void poly_compress(uint8_t* r, const poly* a);

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
void poly_tobytes(uint8_t* r, const poly* a);

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
void poly_frommsg(poly* r, const uint8_t msg[KYBER_KEYBYTES]);

/**
* \brief Convert polynomial to 32-byte message.
*
* \param msg Pointer to output message
* \param a Pointer to input polynomial
*/
void poly_tomsg(uint8_t msg[KYBER_KEYBYTES], const poly* a);

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
* \brief Subtract two polynomials.
*
* \param r Pointer to output polynomial
* \param a Pointer to first input polynomial
* \param b Pointer to second input polynomial
*/
void poly_sub(poly* r, const poly* a, const poly* b);

#endif
