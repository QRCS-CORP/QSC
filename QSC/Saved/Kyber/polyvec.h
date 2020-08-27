/**
* \file polyvec.h
* \brief <b>Kyber polynomial vector functions</b> \n
* This is an internal class.
*
* \date May 09, 2019
*/

#ifndef KYBER_POLYVEC_H
#define KYBER_POLYVEC_H

#include "poly.h"
/* jgu -suppressing repeated include warning, using include guards */
/*lint -e537 */

/**
* \struct polyvec
* \brief Contains a K sized vector of poly structures
*
* \var polyvec::vec
* The polynomial vector array
*/
typedef struct
{
  poly vec[KYBER_K];
} polyvec;

/**
* \brief Compress and serialize vector of polynomials.
*
* \param r Pointer to output byte array
* \param a Pointer to input vector of polynomials
*/
void polyvec_compress(uint8_t* r, polyvec* a);

/**
* \brief De-serialize and decompress vector of polynomials;
* approximate inverse of polyvec_compress.
*
* \param r Pointer to output vector of polynomials
* \param a Pointer to input byte array
*/
void polyvec_decompress(polyvec* r, const uint8_t* a);

/**
* \brief Serialize a vector of polynomials.
*
* \param r Pointer to output byte array
* \param a Pointer to input vector of polynomials
*/
void polyvec_tobytes(uint8_t* r, polyvec* a);

/**
* \brief De-serialize vector of polynomials; inverse of polyvec_tobytes.
*
* \param r Pointer to output byte array
* \param a Pointer to input vector of polynomials
*/
void polyvec_frombytes(polyvec* r, const uint8_t* a);

/**
* \brief Apply forward NTT to all elements of a vector of polynomials.
*
* \param r Pointer to in/output vector of polynomials
*/
void polyvec_ntt(polyvec* r);

/**
* \brief Apply inverse NTT to all elements of a vector of polynomials.
*
* \param r Pointer to in/output vector of polynomials
*/
void polyvec_invntt(polyvec* r);

/**
* \brief Pointwise multiply elements of a and b and accumulate into r.
*
* \param r Pointer to output polynomial
* \param a Pointer to first input vector of polynomials
* \param b Pointer to second input vector of polynomials
*/
void polyvec_pointwise_acc(poly* r, const polyvec* a, const polyvec* b);

/**
* \brief Add vectors of polynomials.
*
* \param r Pointer to output vector of polynomials
* \param a Pointer to first input vector of polynomials
* \param b Pointer to second input vector of polynomials
*/
void polyvec_add(polyvec* r, const polyvec* a, const polyvec* b);

/**
* \brief Applies Barrett reduction to each coefficient
*  of each element of a vector of polynomials
*
* \param r Pointer to in/output vector of polynomials
*/
void polyvec_reduce(polyvec* r);

/**
* \brief Applies conditional subtraction of q to each coefficient
* of each element of a vector of polynomials.
*
* \param r Pointer to in/output vector of polynomials
*/
void polyvec_csubq(polyvec *r);

#endif
