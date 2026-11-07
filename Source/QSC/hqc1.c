#include "qsccommon.h"

#undef QSC_HQC_S1N2321
#undef QSC_HQC_S3N4602
#undef QSC_HQC_S5N7333

/** \def QSC_HQC_S1N2321
 * \brief Internal compile-time HQC-1 parameter selection.
 */
#define QSC_HQC_S1N2321
#include "hqc_multi.h"

 /* \cond DOXYGEN_NO_DOCUMENT */

/** \def qsc_hqc_ref_generate_keypair
 * \brief Private compile-time alias to the distinct HQC-1 qsc_hqc1_ref_generate_keypair implementation symbol.
 */
#define qsc_hqc_ref_generate_keypair qsc_hqc1_ref_generate_keypair

/** \def qsc_hqc_ref_generate_seeded_keypair
 * \brief Private compile-time alias to the distinct HQC-1 qsc_hqc1_ref_generate_seeded_keypair implementation symbol.
 */
#define qsc_hqc_ref_generate_seeded_keypair qsc_hqc1_ref_generate_seeded_keypair

/** \def qsc_hqc_ref_encapsulate
 * \brief Private compile-time alias to the distinct HQC-1 qsc_hqc1_ref_encapsulate implementation symbol.
 */
#define qsc_hqc_ref_encapsulate qsc_hqc1_ref_encapsulate

/** \def qsc_hqc_ref_seeded_encapsulate
 * \brief Private compile-time alias to the distinct HQC-1 qsc_hqc1_ref_seeded_encapsulate implementation symbol.
 */
#define qsc_hqc_ref_seeded_encapsulate qsc_hqc1_ref_seeded_encapsulate

/** \def qsc_hqc_ref_decapsulate
 * \brief Private compile-time alias to the distinct HQC-1 qsc_hqc1_ref_decapsulate implementation symbol.
 */
#define qsc_hqc_ref_decapsulate qsc_hqc1_ref_decapsulate

/** \def qsc_hqc_avx2_generate_keypair
 * \brief Private compile-time alias to the distinct HQC-1 qsc_hqc1_avx2_generate_keypair implementation symbol.
 */
#define qsc_hqc_avx2_generate_keypair qsc_hqc1_avx2_generate_keypair

/** \def qsc_hqc_avx2_generate_seeded_keypair
 * \brief Private compile-time alias to the distinct HQC-1 qsc_hqc1_avx2_generate_seeded_keypair implementation symbol.
 */
#define qsc_hqc_avx2_generate_seeded_keypair qsc_hqc1_avx2_generate_seeded_keypair

/** \def qsc_hqc_avx2_encapsulate
 * \brief Private compile-time alias to the distinct HQC-1 qsc_hqc1_avx2_encapsulate implementation symbol.
 */
#define qsc_hqc_avx2_encapsulate qsc_hqc1_avx2_encapsulate

/** \def qsc_hqc_avx2_seeded_encapsulate
 * \brief Private compile-time alias to the distinct HQC-1 qsc_hqc1_avx2_seeded_encapsulate implementation symbol.
 */
#define qsc_hqc_avx2_seeded_encapsulate qsc_hqc1_avx2_seeded_encapsulate

/** \def qsc_hqc_avx2_decapsulate
 * \brief Private compile-time alias to the distinct HQC-1 qsc_hqc1_avx2_decapsulate implementation symbol.
 */
#define qsc_hqc_avx2_decapsulate qsc_hqc1_avx2_decapsulate

#if defined(QSC_SYSTEM_HAS_AVX2) && defined(QSC_SYSTEM_HAS_PCLMUL)
#include "hqcbase_avx2.c"
#else
#include "hqcbase.c"
#endif

/** \brief HQC-1 explicit generate_keypair wrapper of the shared compile-time specialized backend.
 * \return True on successful operation for bool functions; void functions perform no operation for null arguments.
 * \note All buffers are caller-owned; the RNG callback controls concurrency safety.
 */
bool qsc_hqc1_generate_keypair(uint8_t* pk, uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t))
{
	bool res;

	res = false;

	if (pk != NULL && sk != NULL && rng_generate != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX2) && defined(QSC_SYSTEM_HAS_PCLMUL)
		res = qsc_hqc1_avx2_generate_keypair(pk, sk, rng_generate);
#else
		res = qsc_hqc1_ref_generate_keypair(pk, sk, rng_generate);
#endif
	}

	return res;
}

/** \brief HQC-1 explicit generate_seeded_keypair wrapper of the shared compile-time specialized backend.
 * \return True on successful operation for bool functions; void functions perform no operation for null arguments.
 * \note All buffers are caller-owned; the RNG callback controls concurrency safety.
 */
void qsc_hqc1_generate_seeded_keypair(uint8_t* pk, uint8_t* sk, uint8_t* seed)
{
	if (pk != NULL && sk != NULL && seed != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX2) && defined(QSC_SYSTEM_HAS_PCLMUL)
		qsc_hqc1_avx2_generate_seeded_keypair(pk, sk, seed);
#else
		qsc_hqc1_ref_generate_seeded_keypair(pk, sk, seed);
#endif
	}
}

/** \brief HQC-1 explicit encapsulate wrapper of the shared compile-time specialized backend.
 * \return True on successful operation for bool functions; void functions perform no operation for null arguments.
 * \note All buffers are caller-owned; the RNG callback controls concurrency safety.
 */
bool qsc_hqc1_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* pk, bool (*rng_generate)(uint8_t*, size_t))
{
	bool res;

	res = false;

	if (secret != NULL && ciphertext != NULL && pk != NULL && rng_generate != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX2) && defined(QSC_SYSTEM_HAS_PCLMUL)
		res = qsc_hqc1_avx2_encapsulate(secret, ciphertext, pk, rng_generate);
#else
		res = qsc_hqc1_ref_encapsulate(secret, ciphertext, pk, rng_generate);
#endif
	}

	return res;
}

/** \brief HQC-1 explicit seeded_encapsulate wrapper of the shared compile-time specialized backend.
 * \return True on successful operation for bool functions; void functions perform no operation for null arguments.
 * \note All buffers are caller-owned; the RNG callback controls concurrency safety.
 */
void qsc_hqc1_seeded_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* pk, const uint8_t seed[QSC_HQC_SEED_BYTES])
{
	if (secret != NULL && ciphertext != NULL && pk != NULL && seed != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX2) && defined(QSC_SYSTEM_HAS_PCLMUL)
		qsc_hqc1_avx2_seeded_encapsulate(secret, ciphertext, pk, seed);
#else
		qsc_hqc1_ref_seeded_encapsulate(secret, ciphertext, pk, seed);
#endif
	}
}

/** \brief HQC-1 explicit decapsulate wrapper of the shared compile-time specialized backend.
 * \return True on successful operation for bool functions; void functions perform no operation for null arguments.
 * \note All buffers are caller-owned; the RNG callback controls concurrency safety.
 */
bool qsc_hqc1_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* sk)
{
	bool res;

	res = false;

	if (secret != NULL && ciphertext != NULL && sk != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX2) && defined(QSC_SYSTEM_HAS_PCLMUL)
		res = qsc_hqc1_avx2_decapsulate(secret, ciphertext, sk);
#else
		res = qsc_hqc1_ref_decapsulate(secret, ciphertext, sk);
#endif
	}

	return res;
}

/* \endcond DOXYGEN_NO_DOCUMENT */
