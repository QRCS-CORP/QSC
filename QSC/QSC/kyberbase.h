/* The GPL version 3 License (GPLv3)
*
* Copyright (c) 2021 Digital Freedom Defence Inc.
* This file is part of the QSC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef QSC_KYBERBASE_H
#define QSC_KYBERBASE_H

#include "common.h"

#if defined(QSC_KYBER_S1Q3329N256)
#	define QSC_KYBER_K 2
#elif defined(QSC_KYBER_S2Q3329N256)
#	define QSC_KYBER_K 3
#elif defined(QSC_KYBER_S3Q3329N256)
#	define QSC_KYBER_K 4
#else
#	error No Kyber implementation is defined, check common.h!
#endif

/*!
\def QSC_KYBER_N
* Read Only: The polynomial dimension N
*/
#define QSC_KYBER_N 256

/*!
\def QSC_KYBER_Q
* Read Only: The modulus prime factor Q
*/
#define QSC_KYBER_Q 3329

/*!
\def QSC_KYBER_ETA
* Read Only: The binomial distribution factor
*/
#define QSC_KYBER_ETA 2

/*!
* \def QSC_KYBER_MAC_SIZE
* \brief The byte size of the internal shake implementationc output MAC code
*/
#define QSC_KYBER_MAC_SIZE 32

/*!
\def QSC_KYBER_SYMBYTES
* Read Only: The size in bytes of hashes, and seeds
*/
#define QSC_KYBER_SYMBYTES 32

/* indcpa.h */

/**
* \brief Decryption function of the CPA-secure public-key encryption scheme underlying Kyber.
*
* \param m Pointer to output decrypted message
* \param c Pointer to input ciphertext
* \param sk Pointer to input secret key
*/
void qsc_kyber_indcpa_dec(uint8_t* m, const uint8_t* c, const uint8_t* sk);

/**
* \brief Encryption function of the CPA-secure public-key encryption scheme underlying Kyber.
*
* \param c Pointer to output ciphertext
* \param m Pointer to input message (of length KYBER_KEYBYTES bytes)
* \param pk Pointer to input public key
* \param coins Pointer to input random coins used as seed to deterministically generate all randomness
*/
void qsc_kyber_indcpa_enc(uint8_t* c, const uint8_t* m, const uint8_t* pk, const uint8_t* coins);

/**
* \brief Generates public and private key for the CPA-secure public-key encryption scheme underlying Kyber.
*
* \param pk Pointer to output public key
* \param sk Pointer to output private key
*/
void qsc_kyber_indcpa_keypair(uint8_t* pk, uint8_t* sk, void (*rng_generate)(uint8_t*, size_t));

/* kem.h */

/**
* \brief Generates shared secret for given cipher text and private key
*
* \param ss Pointer to output shared secret (an already allocated array of KYBER_SECRET_BYTES bytes)
* \param ct Pointer to input cipher text (an already allocated array of KYBER_CIPHERTEXT_SIZE bytes)
* \param sk Pointer to input private key (an already allocated array of KYBER_SECRETKEY_SIZE bytes)
* \return Returns true for success
*/
bool qsc_kyber_crypto_kem_dec(uint8_t* ss, const uint8_t* ct, const uint8_t* sk);

/**
* \brief Generates cipher text and shared secret for given public key
*
* \param ct Pointer to output cipher text (an already allocated array of KYBER_CIPHERTEXT_SIZE bytes)
* \param ss Pointer to output shared secret (an already allocated array of KYBER_BYTES bytes)
* \param pk Pointer to input public key (an already allocated array of KYBER_PUBLICKEY_SIZE bytes)
*/
void qsc_kyber_crypto_kem_enc(uint8_t* ct, uint8_t* ss, const uint8_t* pk, void (*rng_generate)(uint8_t*, size_t));

/**
* \brief Generates public and private key for the CCA-Secure Kyber key encapsulation mechanism
*
* \param pk Pointer to output public key (an already allocated array of KYBER_PUBLICKEY_SIZE bytes)
* \param sk Pointer to output private key (an already allocated array of KYBER_SECRETKEY_SIZE bytes)
*/
void qsc_kyber_crypto_kem_keypair(uint8_t* pk, uint8_t* sk, void (*rng_generate)(uint8_t*, size_t));

/* ntt.h */

extern int16_t qsc_kyber_zetas[128];
extern int16_t qsc_kyber_zetasinv[128];

/**
* \brief Multiplication of polynomials in Zq[X]/((X^2-zeta))
* used for multiplication of elements in Rq in NTT domain.
*
* \param r pointer to the output polynomial
* \param a pointer to the first factor
* \param b pointer to the second factor
* \param zeta integer defining the reduction polynomial
*/
void qsc_kyber_basemul(uint16_t r[2], const uint16_t a[2], const uint16_t b[2], int16_t zeta);

/**
* \brief Computes inverse of negacyclic number-theoretic transform (NTT) of
* a polynomial (vector of 256 coefficients) in place;
* inputs assumed to be in bitreversed order, output in normal order.
*
* \param p Pointer to input/output polynomial
*/
void qsc_kyber_invntt(uint16_t* p);

/**
* \brief Computes negacyclic number-theoretic transform (NTT) of
* a polynomial (vector of 256 coefficients) in place;
* inputs assumed to be in normal order, output in bitreversed order.
*
* \param p Pointer to in/output polynomial
*/
void qsc_kyber_ntt(uint16_t* p);

/* poly.h */

/**
* \struct qsc_kyber_poly
* \brief Contains an N sized array of 16bit coefficients. /n
* Elements of R_q = Z_q[X] / (X^n + 1). /n
* Represents polynomial coeffs[0] + X * coeffs[1] + X^2 * xoeffs[2] + ... + X^{n-1} * coeffs[n-1]
*
* \var qsc_kyber_poly::coeffs
* The array of 16bit coefficients
*/
typedef struct
{
	uint16_t coeffs[QSC_KYBER_N];
} qsc_kyber_poly;

/**
* \brief Given an array of uniformly random bytes,
* compute a polynomial with coefficients distributed according to
* a centered binomial distribution with parameter QSC_KYBER_ETA.
*
* \param r Pointer to output polynomial
* \param buf Pointer to input byte array
*/
void qsc_kyber_cbd(qsc_kyber_poly* r, const uint8_t* buf);

/**
* \brief Compression and subsequent serialization of a polynomial.
*
* \param r Pointer to output byte array
* \param a Pointer to input polynomial
*/
void qsc_kyber_poly_compress(uint8_t* r, qsc_kyber_poly* a);

/**
* \brief De-serialization and subsequent decompression of a polynomial;
* approximate inverse of qsc_kyber_poly_compress.
*
* \param r Pointer to output polynomial
* \param a Pointer to input byte array
*/
void qsc_kyber_poly_decompress(qsc_kyber_poly* r, const uint8_t* a);

/**
* \brief Serialization of a polynomial
*
* \param r Pointer to output byte array
* \param a Pointer to input polynomial
*/
void qsc_kyber_poly_tobytes(uint8_t* r, qsc_kyber_poly* a);

/**
* \brief De-serialization of a polynomial; inverse of qsc_kyber_poly_tobytes.
*
* \param r Pointer to output polynomial
* \param a Pointer to input byte array
*/
void qsc_kyber_poly_frombytes(qsc_kyber_poly* r, const uint8_t* a);

/**
* \brief Convert 32-byte message to polynomial.
*
* \param r Pointer to output polynomial
* \param msg Pointer to input message
*/
void qsc_kyber_poly_frommsg(qsc_kyber_poly *r, const uint8_t msg[QSC_KYBER_SYMBYTES]);

/**
* \brief Convert polynomial to 32-byte message.
*
* \param msg Pointer to output message
* \param a Pointer to input polynomial
*/
void qsc_kyber_poly_tomsg(uint8_t msg[QSC_KYBER_SYMBYTES], qsc_kyber_poly *a);

/**
* \brief Sample a polynomial deterministically from a seed and a nonce,
* with output polynomial close to centered binomial distribution with parameter QSC_KYBER_ETA.
*
* \param r Pointer to output polynomial
* \param seed Pointer to input seed
* \param nonce one-byte input nonce
*/
void qsc_kyber_poly_getnoise(qsc_kyber_poly* r, const uint8_t* seed, uint8_t nonce);

/**
* \brief Computes negacyclic number-theoretic transform (NTT) of a polynomial in place;
* inputs assumed to be in normal order, output in bitreversed order.
*
* \param r Pointer to input/output polynomial
*/
void qsc_kyber_poly_ntt(qsc_kyber_poly* r);

/**
* \brief Computes inverse of negacyclic number-theoretic transform (NTT) of a polynomial in place;
* inputs assumed to be in bitreversed order, output in normal order.
*
* \param r a Pointer to in/output polynomial
*/
void qsc_kyber_poly_invntt(qsc_kyber_poly* r);

/**
* \brief Add two polynomials.
*
* \param r Pointer to output polynomial
* \param a Pointer to first input polynomial
* \param b Pointer to second input polynomial
*/
void qsc_kyber_poly_add(qsc_kyber_poly* r, const qsc_kyber_poly* a, const qsc_kyber_poly* b);

/**
* \brief Applies conditional subtraction of q to each coefficient of a polynomial
*
* \param qsc_kyber_poly pointer to input/output polynomial
*/
void qsc_kyber_poly_csubq(qsc_kyber_poly *r);

/**
* \brief Applies Barrett reduction to all coefficients of a polynomial
*
* \param qsc_kyber_poly pointer to input/output polynomial
*/
void qsc_kyber_poly_reduce(qsc_kyber_poly *r);

/**
* \brief Subtract two polynomials.
*
* \param r Pointer to output polynomial
* \param a Pointer to first input polynomial
* \param b Pointer to second input polynomial
*/
void qsc_kyber_poly_sub(qsc_kyber_poly* r, const qsc_kyber_poly* a, const qsc_kyber_poly* b);

/**
* \brief Inplace conversion of all coefficients of a polynomial
* from Montgomery domain to normal domain
*
* \param r Pointer to output polynomial
*/
void qsc_kyber_poly_frommont(qsc_kyber_poly* r);

/**
* \brief Multiplication of two polynomials in NTT domain
*
* \param r Pointer to output polynomial
* \param a Pointer to first input polynomial
* \param b Pointer to second input polynomial
*/
void qsc_kyber_poly_basemul(qsc_kyber_poly* r, const qsc_kyber_poly* a, const qsc_kyber_poly* b);

/* polyvec.h */

/**
* \struct qsc_kyber_polyvec
* \brief Contains a K sized vector of qsc_kyber_poly structures
*
* \var qsc_kyber_polyvec::vec
* The polynomial vector array
*/
typedef struct
{
	qsc_kyber_poly vec[QSC_KYBER_K];
} qsc_kyber_polyvec;

/**
* \brief Compress and serialize vector of polynomials.
*
* \param r Pointer to output byte array
* \param a Pointer to input vector of polynomials
*/
void qsc_kyber_polyvec_compress(uint8_t* r, qsc_kyber_polyvec* a);

/**
* \brief De-serialize and decompress vector of polynomials;
* approximate inverse of qsc_kyber_polyvec_compress.
*
* \param r Pointer to output vector of polynomials
* \param a Pointer to input byte array
*/
void qsc_kyber_polyvec_decompress(qsc_kyber_polyvec* r, const uint8_t* a);

/**
* \brief Serialize a vector of polynomials.
*
* \param r Pointer to output byte array
* \param a Pointer to input vector of polynomials
*/
void qsc_kyber_polyvec_tobytes(uint8_t* r, qsc_kyber_polyvec* a);

/**
* \brief De-serialize vector of polynomials; inverse of qsc_kyber_polyvec_tobytes.
*
* \param r Pointer to output byte array
* \param a Pointer to input vector of polynomials
*/
void qsc_kyber_polyvec_frombytes(qsc_kyber_polyvec* r, const uint8_t* a);

/**
* \brief Apply forward NTT to all elements of a vector of polynomials.
*
* \param r Pointer to in/output vector of polynomials
*/
void qsc_kyber_polyvec_ntt(qsc_kyber_polyvec* r);

/**
* \brief Apply inverse NTT to all elements of a vector of polynomials.
*
* \param r Pointer to in/output vector of polynomials
*/
void qsc_kyber_polyvec_invntt(qsc_kyber_polyvec* r);

/**
* \brief Pointwise multiply elements of a and b and accumulate into r.
*
* \param r Pointer to output polynomial
* \param a Pointer to first input vector of polynomials
* \param b Pointer to second input vector of polynomials
*/
void qsc_kyber_polyvec_pointwise_acc(qsc_kyber_poly* r, const qsc_kyber_polyvec* a, const qsc_kyber_polyvec* b);

/**
* \brief Add vectors of polynomials.
*
* \param r Pointer to output vector of polynomials
* \param a Pointer to first input vector of polynomials
* \param b Pointer to second input vector of polynomials
*/
void qsc_kyber_polyvec_add(qsc_kyber_polyvec* r, const qsc_kyber_polyvec* a, const qsc_kyber_polyvec* b);

/**
* \brief Applies Barrett reduction to each coefficient
*  of each element of a vector of polynomials
*
* \param r Pointer to in/output vector of polynomials
*/
void qsc_kyber_polyvec_reduce(qsc_kyber_polyvec* r);

/**
* \brief Applies conditional subtraction of q to each coefficient
* of each element of a vector of polynomials.
*
* \param r Pointer to in/output vector of polynomials
*/
void qsc_kyber_polyvec_csubq(qsc_kyber_polyvec *r);

/* reduce.h */

/**
* \brief Barrett reduction; given a 16-bit integer a, computes
* 16-bit integer congruent to a mod q in {0,...,11768}.
*
* \param x Input unsigned integer to be reduced
*/
int16_t qsc_kyber_barrett_reduce(int16_t a);

/**
* \brief Conditionallly subtract q
*
* \param a input integer
* \return a - q if a >= q, else a
*/
int16_t qsc_kyber_csubq(int16_t a);

/**
* \brief Montgomery reduction; given a 32-bit integer a, computes 16-bit integer
* congruent to a * R^-1 mod q, where R=2^18 (see value of rlog).
*
* \param x Input unsigned integer to be reduced; has to be in {0,...,2281446912}
* \return unsigned integer in {0,...,2^13-1} congruent to a * R^-1 modulo q
*/
int16_t qsc_kyber_montgomery_reduce(int32_t a);

#endif