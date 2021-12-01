#ifndef QSC_FALCONBASE_H
#define QSC_FALCONBASE_H

#include "common.h"

/* \cond DOXYGEN_IGNORE */

/* api.h */

#if defined(QSC_FALCON_S3SHAKE256F512)
#	define FALCON_CRYPTO_SECRETKEYBYTES 1281
#	define FALCON_CRYPTO_PUBLICKEY_BYTES 897
#	define FALCON_CRYPTO_SIGNATURE_BYTES 690
#elif defined(QSC_FALCON_S5SHAKE256F1024)
#	define FALCON_CRYPTO_SECRETKEYBYTES 2305
#	define FALCON_CRYPTO_PUBLICKEY_BYTES 1793
#	define FALCON_CRYPTO_SIGNATURE_BYTES 1330
#endif

/* fpr.h */

#define FALCON_FPR_GM_TAB_SIZE 2048
#define FALCON_FPR_INV_SIGMA_SIZE 11
#define FALCON_FPR_GM_P2_SIZE 11
#define FALCON_Q 12289
#define FALCON_Q0I 12287
#define FALCON_R 4091
#define FALCON_R2 10952
#define FALCON_GMB_SIZE 1024
#define FALCON_KEYGEN_TEMP_1 136
#define FALCON_KEYGEN_TEMP_2 272
#define FALCON_KEYGEN_TEMP_3 224
#define FALCON_KEYGEN_TEMP_4 448
#define FALCON_KEYGEN_TEMP_5 896
#define FALCON_KEYGEN_TEMP_6 1792
#define FALCON_KEYGEN_TEMP_7 3584
#define FALCON_KEYGEN_TEMP_8 7168
#define FALCON_KEYGEN_TEMP_9 14336
#define FALCON_KEYGEN_TEMP_10 28672
#define FALCON_SMALL_PRIME_SIZE 522
#define FALCON_GAUS_1024_12289_SIZE 27
#define FALCON_MAX_BL_SMALL_SIZE 11
#define FALCON_MAX_BL_LARGE_SIZE 10
#define FALCON_DEPTH_INT_FG 4
#define FALCON_NONCE_SIZE 40
#define FALCON_L2BOUND_SIZE 11
#define FALCON_MAXBITS_SIZE 11
#define FALCON_REV10_SIZE 1024

/* prng.c */

typedef struct
{
	QSC_ALIGN(8) uint8_t buf[512];
	QSC_ALIGN(8) uint8_t state[256];
	size_t ptr;
	int32_t type;
} falcon_prng_state;

/* fpr.c */

typedef uint64_t falcon_fpr;

static const falcon_fpr falcon_fpr_q = 4667981563525332992;
static const falcon_fpr falcon_fpr_inverse_of_q = 4545632735260551042;
static const falcon_fpr falcon_fpr_inv_2sqrsigma0 = 4594603506513722306;
static const falcon_fpr falcon_fpr_log2 = 4604418534313441775;
static const falcon_fpr falcon_fpr_inv_log2 = 4609176140021203710;
static const falcon_fpr falcon_fpr_bnorm_max = 4670353323383631276;
static const falcon_fpr falcon_fpr_zero = 0;
static const falcon_fpr falcon_fpr_one = 4607182418800017408;
static const falcon_fpr falcon_fpr_two = 4611686018427387904;
static const falcon_fpr falcon_fpr_onehalf = 4602678819172646912;
static const falcon_fpr falcon_fpr_invsqrt2 = 4604544271217802189;
static const falcon_fpr falcon_fpr_invsqrt8 = 4600040671590431693;
static const falcon_fpr falcon_fpr_ptwo31 = 4746794007248502784;
static const falcon_fpr falcon_fpr_ptwo31m1 = 4746794007244308480;
static const falcon_fpr falcon_fpr_mtwo31m1 = 13970166044099084288U;
static const falcon_fpr falcon_fpr_ptwo63m1 = 4890909195324358656;
static const falcon_fpr falcon_fpr_mtwo63m1 = 14114281232179134464U;
static const falcon_fpr falcon_fpr_ptwo63 = 4890909195324358656;

typedef struct
{
	uint32_t p;
	uint32_t g;
	uint32_t s;
} falcon_small_prime;

extern const falcon_fpr falcon_fpr_inv_sigma[FALCON_FPR_INV_SIGMA_SIZE];

extern const falcon_fpr falcon_fpr_sigma_min[FALCON_FPR_INV_SIGMA_SIZE];

extern const falcon_fpr falcon_fpr_gm_tab[FALCON_FPR_GM_TAB_SIZE];

extern const falcon_fpr falcon_fpr_p2_tab[FALCON_FPR_GM_P2_SIZE];

/* codec.c */

extern const uint8_t falcon_max_fg_bits[FALCON_MAXBITS_SIZE];

extern const uint8_t falcon_max_FG_bits[FALCON_MAXBITS_SIZE];

/* verify.c */

extern const uint16_t falcon_GMb[FALCON_GMB_SIZE];

extern const uint16_t falcon_iGMb[FALCON_GMB_SIZE];

extern const falcon_small_prime falcon_small_primes[FALCON_SMALL_PRIME_SIZE];

/* keygen.c */

/*
 * Table below incarnates a discrete Gaussian distribution:
 *    D(x) = exp(-(x^2)/(2*sigma^2))
 * where sigma = 1.17*sqrt(q/(2*N)), q = 12289, and N = 1024.
 * Element 0 of the table is P(x = 0).
 * For k > 0, element k is P(x >= k+1 | x > 0).
 * Probabilities are scaled up by 2^63.
 */
extern const uint64_t falcon_gauss_1024_12289[FALCON_GAUS_1024_12289_SIZE];

extern const uint16_t falcon_rev10[FALCON_REV10_SIZE];

/*
 * The falcon_max_bl_small[] and falcon_max_bl_large[] contain the lengths, in 31-bit
 * words, of intermediate values in the computation:
 *
 *   falcon_max_bl_small[depth]: length for the input f and g at that depth
 *   falcon_max_bl_large[depth]: length for the unreduced F and G at that depth
 *
 * Rules:
 *
 *  - Within an array, values grow.
 *
 *  - The 'SMALL' array must have an entry for maximum depth, corresponding
 *    to the size of values used in the binary GCD. There is no such value
 *    for the 'LARGE' array (the binary GCD yields already reduced
 *    coefficients).
 *
 *  - falcon_max_bl_large[depth] >= falcon_max_bl_small[depth + 1].
 *
 *  - Values must be large enough to handle the common cases, with some
 *    margins.
 *
 *  - Values must not be "too large" either because we will convert some
 *    integers into floating-point values by considering the top 10 words,
 *    i.e. 310 bits; hence, for values of length more than 10 words, we
 *    should take care to have the length centered on the expected size.
 *
 * The following average lengths, in bits, have been measured on thousands
 * of random keys (fg = max length of the absolute value of coefficients
 * of f and g at that depth; FG = idem for the unreduced F and G; for the
 * maximum depth, F and G are the output of binary GCD, multiplied by q;
 * for each value, the average and standard deviation are provided).
 *
 * Binary case:
 *    depth: 10    fg: 6307.52 (24.48)    FG: 6319.66 (24.51)
 *    depth:  9    fg: 3138.35 (12.25)    FG: 9403.29 (27.55)
 *    depth:  8    fg: 1576.87 ( 7.49)    FG: 4703.30 (14.77)
 *    depth:  7    fg:  794.17 ( 4.98)    FG: 2361.84 ( 9.31)
 *    depth:  6    fg:  400.67 ( 3.10)    FG: 1188.68 ( 6.04)
 *    depth:  5    fg:  202.22 ( 1.87)    FG:  599.81 ( 3.87)
 *    depth:  4    fg:  101.62 ( 1.02)    FG:  303.49 ( 2.38)
 *    depth:  3    fg:   50.37 ( 0.53)    FG:  153.65 ( 1.39)
 *    depth:  2    fg:   24.07 ( 0.25)    FG:   78.20 ( 0.73)
 *    depth:  1    fg:   10.99 ( 0.08)    FG:   39.82 ( 0.41)
 *    depth:  0    fg:    4.00 ( 0.00)    FG:   19.61 ( 0.49)
 *
 * Integers are actually represented either in binary notation over
 * 31-bit words (signed, using two's complement), or in RNS, modulo
 * many small primes. These small primes are close to, but slightly
 * lower than, 2^31. Use of RNS loses less than two bits, even for
 * the largest values.
 *
 * IMPORTANT: if these values are modified, then the temporary buffer
 * sizes (FALCON_KEYGEN_TEMP_*, in inner.h) must be recomputed
 * accordingly.
 */
extern const size_t falcon_max_bl_small[FALCON_MAX_BL_SMALL_SIZE];

extern const size_t falcon_max_bl_large[FALCON_MAX_BL_LARGE_SIZE];

/*
 * Average and standard deviation for the maximum size (in bits) of
 * coefficients of (f,g), depending on depth. These values are used
 * to compute bounds for Babai's reduction.
 */
static const struct
{
	int32_t avg;
	int32_t std;
} falcon_bit_length[] =
{
	{    4,  0 },
	{   11,  1 },
	{   24,  1 },
	{   50,  1 },
	{  102,  1 },
	{  202,  2 },
	{  401,  4 },
	{  794,  5 },
	{ 1577,  8 },
	{ 3138, 13 },
	{ 6308, 25 }
};

/* sign.c */

typedef struct
{
	falcon_prng_state p;
	falcon_fpr sigma_min;
} falcon_sampler_context;

typedef int32_t(*falcon_samplerZ)(void* ctx, falcon_fpr mu, falcon_fpr sigma);

/* common.c */

extern const uint32_t falcon_l2bound[FALCON_L2BOUND_SIZE];

/* public functions */

/**
* \brief Generates a Dilithium public/private key-pair.
* Arrays must be sized to FALCON_PUBLICKEY_SIZE and FALCON_SECRETKEY_SIZE.
*
* \param publickey: The public verification key
* \param secretkey: The private signature key
* \param rng_generate: The random generator
*/
int32_t qsc_falcon_ref_generate_keypair(uint8_t *pk, uint8_t *sk, bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Takes the message as input and returns an array containing the signature followed by the message
*
* \param signedmsg: The signed message
* \param smsglen: The signed message length
* \param message: The message to be signed
* \param msglen: The message length
* \param privatekey: The private signature key
* \param rng_generate: The random generator
*/
int32_t qsc_falcon_ref_sign(uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen, const uint8_t *sk, bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Verifies a signature-message pair with the public key.
*
* \param message: The message to be signed
* \param msglen: The message length
* \param signedmsg: The signed message
* \param smsglen: The signed message length
* \param publickey: The public verification key
* \return Returns true for success
*/
bool qsc_falcon_ref_open(uint8_t *m, size_t *mlen, const uint8_t *sm, size_t smlen, const uint8_t *pk);

/* \endcond DOXYGEN_IGNORE */

#endif
