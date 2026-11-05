/*! \def QSC_ECDH_P256_W6_TABLES_IMPLEMENTATION
 * \brief Private opt-in for emitting W6 lookup tables in this translation unit only.
 * \details Prevents public-header inclusions from duplicating tables; not a public build option.
 */
#if !defined(QSC_ECDH_P256_GENERATOR_COMPACT)
#	define QSC_ECDH_P256_W6_TABLES_IMPLEMENTATION
#endif

#include "ecdhp256.h"
#if defined(QSC_ECDH_P256_W6_TABLES_IMPLEMENTATION)
#	undef QSC_ECDH_P256_W6_TABLES_IMPLEMENTATION
#endif
#include "csp.h"
#include "intutils.h"
#include "memutils.h"
#include "intrinsics.h"
#include "sha2.h"
#if defined(__x86_64__) && defined(__SIZEOF_INT128__) && !defined(_MSC_VER) && !defined(QSC_ECDH_P256_PORTABLE)
#	include <immintrin.h>
#endif

 /* \cond NO_DOCUMENT */

/*! \brief 256-bit field element: 8 x uint32_t, little-endian (word 0 is least significant) */
typedef uint32_t ecdhp256_field[8U];

/*! \brief Jacobian projective point over P-256 (X:Y:Z), affine = (X/Z^2, Y/Z^3) */
typedef struct
{
	ecdhp256_field X; /*!< X coordinate. */
	ecdhp256_field Y; /*!< Y coordinate. */
	ecdhp256_field Z; /*!< Projective scale; zero encodes infinity. */
} ecdhp256_jac_t;

/*! \brief Affine point over P-256. */
typedef struct
{
	ecdhp256_field X; /*!< X coordinate. */
	ecdhp256_field Y; /*!< Y coordinate. */
} ecdhp256_aff_t;

/* field prime:  p = 2^256 - 2^224 + 2^192 + 2^96 - 1 */
static const uint32_t ECDHP256_P[8U] = {0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000001U, 0xFFFFFFFFU};

/* group order: n */
static const uint32_t ECDHP256_N[8U] = {0xFC632551U, 0xF3B9CAC2U, 0xA7179E84U, 0xBCE6FAADU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0x00000000U, 0xFFFFFFFFU};

/* base point Gx */
static const uint32_t ECDHP256_GX[8U] = {0xD898C296U, 0xF4A13945U, 0x2DEB33A0U, 0x77037D81U, 0x63A440F2U, 0xF8BCE6E5U, 0xE12C4247U, 0x6B17D1F2U};

/* base point Gy */
static const uint32_t ECDHP256_GY[8U] = {0x37BF51F5U, 0xCBB64068U, 0x6B315ECEU, 0x2BCE3357U, 0x7C0F9E16U, 0x8EE7EB4AU, 0xFE1A7F9BU, 0x4FE342E2U};

/* curve coefficient b */
static const uint32_t ECDHP256_B[8U] = {0x27D2604BU, 0x3BCE3C3EU, 0xCC53B0F6U, 0x651D06B0U, 0x769886BCU, 0xB3EBBD55U, 0xAA3A93E7U, 0x5AC635D8U};

/* Native P-256 field backend is isolated from ECDSA and uses fixed-length
 * Montgomery operations. MSVC and compilers without a double-width unsigned
 * integer retain the established portable 32-bit ECDH backend. */
#if defined(__SIZEOF_INT128__) && !defined(_MSC_VER) && !defined(QSC_ECDH_P256_PORTABLE)
	/*! \def QSC_ECDH_P256_NATIVE
	 * \brief Select the double-width native P-256 field engine.
	 */
#	define QSC_ECDH_P256_NATIVE 1

/*! \brief Square of the Montgomery radix modulo the P-256 prime. */
static const uint32_t ECDHP256_ECDH_R2[8U] = {0x00000003U, 0x00000000U, 0xFFFFFFFFU, 0xFFFFFFFBU, 0xFFFFFFFEU, 0xFFFFFFFFU, 0xFFFFFFFDU, 0x00000004U};

/*! \brief Four-limb native representation of the P-256 prime. */
static const uint64_t ECDHP256_ECDH_P64[4U] = {
	UINT64_C(0xFFFFFFFFFFFFFFFF), UINT64_C(0x00000000FFFFFFFF), UINT64_C(0x0000000000000000), UINT64_C(0xFFFFFFFF00000001)};
#endif

/* Native arithmetic call-boundary specialization. Compiler intrinsics remain
 * selected by the established Montgomery reducer, without inline assembly.
 * The portable and MSVC backends retain their existing function boundaries. */
#if defined(QSC_ECDH_P256_NATIVE) && defined(__x86_64__) && defined(__GNUC__)
	/*! \def ECDHP256_ECDH_NATIVE_INLINE
	 * \brief Compiler-specific native field inlining qualifier.
	 */
#	define ECDHP256_ECDH_NATIVE_INLINE static inline __attribute__((always_inline))
#	if !defined(__clang__)
	/*! \def ECDHP256_ECDH_GCC_COMBA_INLINE
	 * \brief Compiler-specific Comba arithmetic inlining qualifier.
	 */
#	define ECDHP256_ECDH_GCC_COMBA_INLINE static inline __attribute__((always_inline))
#else
#	define ECDHP256_ECDH_GCC_COMBA_INLINE static
#endif
#else
#	define ECDHP256_ECDH_NATIVE_INLINE static
#	define ECDHP256_ECDH_GCC_COMBA_INLINE static
#endif

/* Use the exchange doubling engine on the native backend.
 * Generator and exchange retain separate scalar engines; both use the native field backend.
 * Set QSC_ECDH_P256_EXCHANGE_LEGACY_DBL5 for baseline comparisons. */
#if defined(QSC_ECDH_P256_NATIVE) && !defined(QSC_ECDH_P256_EXCHANGE_LEGACY_DBL5)
	/*! \def ECDHP256_EXCHANGE_DBL5
	 * \brief Select the five-step repeated-doubling exchange recurrence.
	 */
#	define ECDHP256_EXCHANGE_DBL5 1
#endif

static void ecdhp256_field_select(uint32_t* r, const uint32_t* a, const uint32_t* b, uint32_t mask)
{
	/* mask must be either 0x00000000 or 0xFFFFFFFF */
	size_t i;

	for (i = 0U; i < 8U; ++i)
	{
		r[i] = (a[i] & mask) | (b[i] & ~mask);
	}
}

static void ecdhp256_field_copy(ecdhp256_field r, const ecdhp256_field a)
{
	int32_t i;

	for (i = 0; i < 8; ++i)
	{
		r[i] = a[i];
	}
}

#if !defined(QSC_ECDH_P256_NATIVE)

static void ecdhp256_field_zero(ecdhp256_field r)
{
	int32_t i;

	for (i = 0; i < 8; ++i)
	{
		r[i] = 0U;
	}
}

#endif

#if !defined(QSC_ECDH_P256_NATIVE)

static void ecdhp256_field_one(ecdhp256_field r)
{
	int32_t i;

	r[0U] = 1U;

	for (i = 1; i < 8; ++i)
	{
		r[i] = 0U;
	}
}
#endif

static uint32_t ecdhp256_field_is_zero(const ecdhp256_field a)
{
	/* returns 1 if a == 0, else 0, no data-dependent branches on a. */
	int32_t i;
	uint32_t t;

	t = 0U;

	for (i = 0; i < 8; ++i)
	{
		t |= a[i];
	}

	/* collapse to 0 or 1 without a branch */
	t = (t | (0U - t)) >> 31U;

	return (1U - t);
}

static uint32_t ecdhp256_private_scalar_ge_order(const uint32_t scalar[8U])
{
	uint64_t difference;
	uint64_t borrow;
	size_t i;

	borrow = 0U;

	for (i = 0U; i < 8U; ++i)
	{
		difference = (uint64_t)scalar[i] - (uint64_t)ECDHP256_N[i] - borrow;
		borrow = difference >> 63U;
	}

	return (uint32_t)(borrow ^ 1U);
}

static int32_t ecdhp256_field_cmp(const uint32_t* a, const uint32_t* b)
{
	int32_t i;
	uint64_t ai;
	uint32_t aigtbi;
	uint32_t ailtbi;
	uint64_t bi;
	uint32_t gt;
	uint32_t lt;
	uint32_t undecided;

	gt = 0U;
	lt = 0U;

	for (i = 7; i >= 0; --i)
	{
		ai = (uint64_t)a[i];
		bi = (uint64_t)b[i];

		aigtbi = (uint32_t)((bi - ai) >> 63); /* 1 if ai > bi */
		ailtbi = (uint32_t)((ai - bi) >> 63); /* 1 if ai < bi */
		undecided = (uint32_t)(1U ^ (gt | lt));

		gt |= aigtbi & undecided;
		lt |= ailtbi & undecided;
	}

	return (gt != 0U) ? 1 : ((lt != 0U) ? -1 : 0);
}

static uint32_t ecdhp256_ct_sel32(uint32_t sel, uint32_t a, uint32_t b)
{
	/* constant-time 32-bit word select: returns a if sel==1, b if sel==0 */
	uint32_t mask;

	/* 0xFFFFFFFF if sel=1, 0x00000000 if sel=0 */
	mask = (uint32_t)(0U - sel);

	return (a & mask) | (b & ~mask);
}

static void ecdhp256_field_ct_select(ecdhp256_field r, uint32_t sel, const ecdhp256_field a, const ecdhp256_field b)
{
	/* constant-time ecdhp256_field select: r = (sel ? a : b) */
	int32_t i;

	for (i = 0; i < 8; ++i)
	{
		r[i] = ecdhp256_ct_sel32(sel, a[i], b[i]);
	}
}

#if !defined(QSC_ECDH_P256_NATIVE)

static void ecdhp256_jac_ct_select(ecdhp256_jac_t* r, uint32_t sel, const ecdhp256_jac_t* a, const ecdhp256_jac_t* b)
{
	/* constant-time Jacobian point select */
	ecdhp256_field_ct_select(r->X, sel, a->X, b->X);
	ecdhp256_field_ct_select(r->Y, sel, a->Y, b->Y);
	ecdhp256_field_ct_select(r->Z, sel, a->Z, b->Z);
}

#endif

static void ecdhp256_field_from_bytes(ecdhp256_field r, const uint8_t* b)
{
	/* convert big-endian 32-byte buffer to little-endian ecdhp256_field */
	int32_t i;

	for (i = 0; i < 8; ++i)
	{
		const uint8_t* p = b + 4 * (7 - i);

		r[i] = ((uint32_t)p[0U] << 24U) | ((uint32_t)p[1U] << 16U) | ((uint32_t)p[2U] << 8U) | (uint32_t)p[3U];
	}
}

static void ecdhp256_field_to_bytes(uint8_t* b, const ecdhp256_field r)
{
	/* convert little-endian ecdhp256_field to big-endian 32-byte buffer */
	int32_t i;

	for (i = 0; i < 8; ++i)
	{
		uint8_t* p = b + 4 * (7 - i);

		p[0U] = (uint8_t)(r[i] >> 24U);
		p[1U] = (uint8_t)(r[i] >> 16U);
		p[2U] = (uint8_t)(r[i] >> 8U);
		p[3U] = (uint8_t)(r[i]);
	}
}

static void ecdhp256_field_cond_sub(ecdhp256_field r, const uint32_t mod[8U])
{
	/* conditional subtraction: if r >= mod, r -= mod */
	int32_t i;
	uint32_t tmp[8U] = { 0U };
	uint64_t borrow;

	borrow = 0U;

	for (i = 0; i < 8; ++i)
	{
		borrow = (uint64_t)r[i] - mod[i] - borrow;
		tmp[i] = (uint32_t)borrow;
		borrow = (borrow >> 32U) & 1U;
	}

	/* Accept tmp only if there was no borrow (r >= mod) */
	ecdhp256_field_ct_select(r, (uint32_t)(1U - (uint32_t)borrow), tmp, r);
}

static bool ecdhp256_prepare_blinding(uint32_t blinded[10U], ecdhp256_field projective, ecdhp256_field rerandomizers[4U], const uint32_t scalar[8U])
{
	uint8_t randomness[168U] = { 0U };
	static const uint32_t ONE[8U] = {1U, 0U, 0U, 0U, 0U, 0U, 0U, 0U};
	uint32_t multiplier[2U];
	uint64_t value;
	uint64_t carry;
	size_t i;
	size_t j;
	bool ret;

	ret = qsc_csp_generate(randomness, sizeof(randomness));

	if (ret == true)
	{
		ecdhp256_field_from_bytes(projective, randomness);
		ecdhp256_field_cond_sub(projective, ECDHP256_P);
		ecdhp256_field_ct_select(projective, ecdhp256_field_is_zero(projective), ONE, projective);

		/* A single entropy request supplies independent full-width projective
         * factors for accumulator rerandomization. Each public
         * schedule position receives a separate nonzero field element. */
		for (i = 0U; i < 4U; ++i)
		{
			ecdhp256_field_from_bytes(rerandomizers[i], randomness + 40U + (32U * i));
			ecdhp256_field_cond_sub(rerandomizers[i], ECDHP256_P);
			ecdhp256_field_ct_select(rerandomizers[i], ecdhp256_field_is_zero(rerandomizers[i]), ONE, rerandomizers[i]);
		}

		multiplier[0U] =
			(uint32_t)randomness[32U] | ((uint32_t)randomness[33U] << 8U) | ((uint32_t)randomness[34U] << 16U) | ((uint32_t)randomness[35U] << 24U);
		multiplier[1U] =
			(uint32_t)randomness[36U] | ((uint32_t)randomness[37U] << 8U) | ((uint32_t)randomness[38U] << 16U) | ((uint32_t)randomness[39U] << 24U);

		for (i = 0U; i < 10U; ++i)
		{
			blinded[i] = i < 8U ? scalar[i] : 0U;
		}

		for (j = 0U; j < 2U; ++j)
		{
			carry = 0U;

			for (i = 0U; i < 8U; ++i)
			{
				value = (uint64_t)ECDHP256_N[i] * multiplier[j] + blinded[i + j] + carry;
				blinded[i + j] = (uint32_t)value;
				carry = value >> 32U;
			}

			blinded[8U + j] = (uint32_t)carry;
		}
	}
	else
	{
		qsc_memutils_clear(blinded, 10U * sizeof(uint32_t));
		qsc_memutils_clear(projective, sizeof(ecdhp256_field));
		qsc_memutils_clear(rerandomizers, 4U * sizeof(ecdhp256_field));
	}

	qsc_memutils_secure_erase(randomness, sizeof(randomness));
	qsc_memutils_secure_erase(multiplier, sizeof(multiplier));

	return ret;
}

static void ecdhp256_fe_add(ecdhp256_field r, const ecdhp256_field a, const ecdhp256_field b)
{
	int32_t i;
	uint32_t t[8U] = { 0U };
	uint32_t u[8U] = { 0U };
	uint64_t carry;
	uint32_t csel;

	static const uint32_t ECDHP256_C[8U] = {0x00000001U, 0x00000000U, 0x00000000U, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFEU, 0x00000000U};

	/* t = a + b mod 2^256, csel = carry */
	carry = 0U;

	for (i = 0; i < 8; ++i)
	{
		uint64_t x;

		x = (uint64_t)a[i] + (uint64_t)b[i] + carry;
		t[i] = (uint32_t)x;
		carry = x >> 32U;
	}

	csel = (uint32_t)carry;

	/* u = t + (carry ? C : 0), where C = 2^256 - p */
	carry = 0U;

	for (i = 0; i < 8; ++i)
	{
		uint32_t addi;

		addi = ecdhp256_ct_sel32(csel, ECDHP256_C[i], 0U);
		uint64_t x;

		x = (uint64_t)t[i] + (uint64_t)addi + carry;
		u[i] = (uint32_t)x;
		carry = x >> 32U;
	}

	/* u is now in [0, 2p). Final conditional subtraction. */
	ecdhp256_field_copy(r, u);
	ecdhp256_field_cond_sub(r, ECDHP256_P);

	qsc_memutils_secure_erase(t, sizeof(t));
	qsc_memutils_secure_erase(u, sizeof(u));
}

static void ecdhp256_fe_sub(uint32_t* r, const uint32_t* a, const uint32_t* b)
{
	size_t i;
	uint32_t t[8U] = { 0U };
	uint64_t borrow;
	uint64_t carry;
	uint64_t ta;
	uint64_t x;
	uint32_t mask;

	borrow = 0ULL;

	for (i = 0U; i < 8U; ++i)
	{
		ta = (uint64_t)a[i] - b[i] - borrow;
		r[i] = (uint32_t)ta;
		borrow = (ta >> 63) & 1ULL;
	}

	carry = 0ULL;

	for (i = 0U; i < 8U; ++i)
	{
		x = (uint64_t)r[i] + ECDHP256_P[i] + carry;
		t[i] = (uint32_t)x;
		carry = x >> 32;
	}

	mask = (uint32_t) - (int32_t)borrow;

	ecdhp256_field_select(r, t, r, mask);
}

#if !defined(QSC_ECDH_P256_NATIVE)
/*! \brief The Montgomery radix squared modulo the P-256 field prime.
 * \note This constant is used solely to return the portable reducer to
 * the canonical, non-Montgomery field representation.
 */
static const uint32_t ECDHP256_ECDH_PORTABLE_R2[8U] = {0x00000003U, 0x00000000U, 0xFFFFFFFFU, 0xFFFFFFFBU, 0xFFFFFFFEU, 0xFFFFFFFFU, 0xFFFFFFFDU, 0x00000004U};

static void ecdhp256_field_mul_raw(uint32_t c[16U], const ecdhp256_field a, const ecdhp256_field b)
{
	uint64_t tmp;
	uint64_t carry;
	size_t i;
	size_t j;

	for (i = 0U; i < 16U; ++i)
	{
		c[i] = 0U;
	}

	for (i = 0U; i < 8U; ++i)
	{
		carry = 0U;

		for (j = 0U; j < 8U; ++j)
		{
			tmp = ((uint64_t)a[i] * b[j]) + c[i + j] + carry;
			c[i + j] = (uint32_t)tmp;
			carry = tmp >> 32U;
		}

		c[i + 8U] = (uint32_t)carry;
	}
}

static void ecdhp256_portable_montgomery_reduce(uint32_t output[8U], const uint32_t product[16U])
{
	uint32_t words[17U] = { 0U };
	uint32_t reduced[8U] = { 0U };
	uint64_t value;
	uint64_t carry;
	uint64_t borrow;
	uint32_t factor;
	uint32_t mask;
	size_t i;
	size_t j;

	for (i = 0U; i < 16U; ++i)
	{
		words[i] = product[i];
	}

	for (i = 0U; i < 8U; ++i)
	{
		factor = words[i];
		carry = 0U;

		for (j = 0U; j < 8U; ++j)
		{
			value = (uint64_t)words[i + j] + ((uint64_t)factor * ECDHP256_P[j]) + carry;
			words[i + j] = (uint32_t)value;
			carry = value >> 32U;
		}

		for (j = i + 8U; j < 17U; ++j)
		{
			value = (uint64_t)words[j] + carry;
			words[j] = (uint32_t)value;
			carry = value >> 32U;
		}
	}

	borrow = 0U;

	for (i = 0U; i < 8U; ++i)
	{
		value = (uint64_t)words[i + 8U] - ECDHP256_P[i] - borrow;
		reduced[i] = (uint32_t)value;
		borrow = value >> 63U;
	}

	mask = (uint32_t)(0U - (uint32_t)((borrow ^ 1U) | (uint64_t)(words[16U] != 0U)));

	for (i = 0U; i < 8U; ++i)
	{
		output[i] = (words[i + 8U] & ~mask) | (reduced[i] & mask);
	}

	qsc_memutils_secure_erase(words, sizeof(words));
	qsc_memutils_secure_erase(reduced, sizeof(reduced));
}

static void ecdhp256_field_reduce512(ecdhp256_field r, const uint32_t c[16U])
{
	ecdhp256_field intermediate = { 0U };
	uint32_t corrected[16U] = { 0U };

	ecdhp256_portable_montgomery_reduce(intermediate, c);
	ecdhp256_field_mul_raw(corrected, intermediate, ECDHP256_ECDH_PORTABLE_R2);
	ecdhp256_portable_montgomery_reduce(r, corrected);

	qsc_memutils_secure_erase(intermediate, sizeof(intermediate));
	qsc_memutils_secure_erase(corrected, sizeof(corrected));
}

#endif

/*! \brief Multiply two P-256 Montgomery field residues in constant-time.
 * \details The fixed-length reduction follows the P-256-specific native-word
 * approach from the existing QSC ECDSA P-256 signing engine, itself adapted
 * from Secp256r1MontgomeryRep (Simplified BSD license).
 * The implementation is private to this ECDH module.
 * \param r: Eight-word output residue; may alias either operand.
 * \param a: First canonical Montgomery residue.
 * \param b: Second canonical Montgomery residue.
 * \note Execution path and memory access do not depend on field values.
 */
#if defined(QSC_ECDH_P256_NATIVE)

static void ecdhp256_native_mont_mul(ecdhp256_field r, const ecdhp256_field a, const ecdhp256_field b)
{
	uint64_t left[4U] = { 0U };
	uint64_t right[4U] = { 0U };
	uint64_t product[8U] = { 0U };
	uint64_t reduced[4U] = { 0U };

	__uint128_t value;
	uint64_t carry;
	uint64_t borrow;
	uint64_t pending;
	uint64_t m;
	uint64_t q0;
	uint64_t q1;
	uint64_t q2;
	uint64_t q3;
	uint64_t selected;
	uint64_t mask;
	size_t i;
	size_t j;

	for (i = 0U; i < 4U; ++i)
	{
		left[i] = (uint64_t)a[2U * i] | ((uint64_t)a[2U * i + 1U] << 32U);
		right[i] = (uint64_t)b[2U * i] | ((uint64_t)b[2U * i + 1U] << 32U);
	}

	for (i = 0U; i < 4U; ++i)
	{
		carry = 0U;

		for (j = 0U; j < 4U; ++j)
		{
			value = ((__uint128_t)left[i] * right[j]) + product[i + j] + carry;
			product[i + j] = (uint64_t)value;
			carry = (uint64_t)(value >> 64U);
		}

		for (j = i + 4U; j < 8U; ++j)
		{
			value = (__uint128_t)product[j] + carry;
			product[j] = (uint64_t)value;
			carry = (uint64_t)(value >> 64U);
		}
	}

	pending = 0U;

	for (i = 0U; i < 4U; ++i)
	{
		m = product[i];
		q0 = m << 32U;
		q1 = m >> 32U;
		borrow = (uint64_t)(m < q0);
		q2 = m - q0;
		q3 = m - q1 - borrow;
		q3 += pending;
		carry = 0U;

		value = (__uint128_t)product[i + 1U] + q0 + carry;
		product[i + 1U] = (uint64_t)value;
		carry = (uint64_t)(value >> 64U);
		value = (__uint128_t)product[i + 2U] + q1 + carry;
		product[i + 2U] = (uint64_t)value;
		carry = (uint64_t)(value >> 64U);
		value = (__uint128_t)product[i + 3U] + q2 + carry;
		product[i + 3U] = (uint64_t)value;
		carry = (uint64_t)(value >> 64U);
		value = (__uint128_t)product[i + 4U] + q3 + carry;
		product[i + 4U] = (uint64_t)value;
		pending = (uint64_t)(value >> 64U);
	}

	borrow = 0U;

	for (i = 0U; i < 4U; ++i)
	{
		value = (__uint128_t)product[i + 4U] - ECDHP256_ECDH_P64[i] - borrow;
		reduced[i] = (uint64_t)value;
		borrow = (uint64_t)(value >> 127U);
	}

	mask = (uint64_t)(0U - (uint64_t)(borrow & (pending ^ 1U)));

	for (i = 0U; i < 4U; ++i)
	{
		selected = (product[i + 4U] & mask) | (reduced[i] & ~mask);
		r[2U * i] = (uint32_t)selected;
		r[2U * i + 1U] = (uint32_t)(selected >> 32U);
	}

	qsc_memutils_secure_erase(left, sizeof(left));
	qsc_memutils_secure_erase(right, sizeof(right));
	qsc_memutils_secure_erase(product, sizeof(product));
	qsc_memutils_secure_erase(reduced, sizeof(reduced));
}

static void ecdhp256_encode(ecdhp256_field r, const ecdhp256_field a)
{
	ecdhp256_native_mont_mul(r, a, ECDHP256_ECDH_R2);
}

static void ecdhp256_decode(ecdhp256_field r, const ecdhp256_field a)
{
	static const uint32_t one[8U] = {1U};

	ecdhp256_native_mont_mul(r, a, one);
}
#endif

static void ecdhp256_fe_mul(ecdhp256_field r, const ecdhp256_field a, const ecdhp256_field b)
{
#if defined(QSC_ECDH_P256_NATIVE)
	ecdhp256_native_mont_mul(r, a, b);
#else
	uint32_t c[16U] = { 0U };

	ecdhp256_field_mul_raw(c, a, b);
	ecdhp256_field_reduce512(r, c);
	qsc_memutils_secure_erase(c, sizeof(c));
#endif
}

static void ecdhp256_fe_sqr(ecdhp256_field r, const ecdhp256_field a)
{
	/* r = a^2 mod p */
	ecdhp256_fe_mul(r, a, a);
}

static void ecdhp256_fe_mul_small(ecdhp256_field r, const ecdhp256_field a, uint32_t k)
{
#if defined(QSC_ECDH_P256_NATIVE)
	ecdhp256_field twice;
	ecdhp256_field four;

	ecdhp256_fe_add(twice, a, a);
	ecdhp256_fe_add(four, twice, twice);

	if (k == 3U)
	{
		ecdhp256_fe_add(r, twice, a);
	}
	else if (k == 8U)
	{
		ecdhp256_fe_add(r, four, four);
	}
	else if (k == 4U)
	{
		ecdhp256_field_copy(r, four);
	}
	else
	{
		ecdhp256_field_copy(r, twice);
	}

	qsc_memutils_secure_erase(twice, sizeof(twice));
	qsc_memutils_secure_erase(four, sizeof(four));
#else
	ecdhp256_field twice;
	ecdhp256_field four;
	uint32_t product[16U] = { 0U };
	uint64_t carry;
	uint64_t value;
	size_t i;

	/* The active point formulas use public multipliers 2, 3, 4 and 8.
	 * Repeated modular addition avoids two full Montgomery reductions. */
	if ((k == 2U) || (k == 3U) || (k == 4U) || (k == 8U))
	{
		ecdhp256_fe_add(twice, a, a);
		ecdhp256_fe_add(four, twice, twice);

		if (k == 3U)
		{
			ecdhp256_fe_add(r, twice, a);
		}
		else if (k == 8U)
		{
			ecdhp256_fe_add(r, four, four);
		}
		else if (k == 4U)
		{
			ecdhp256_field_copy(r, four);
		}
		else
		{
			ecdhp256_field_copy(r, twice);
		}
	}
	else
	{
		/* Preserve the generic internal contract for other public k. */
		carry = 0U;

		for (i = 0U; i < 8U; ++i)
		{
			value = ((uint64_t)a[i] * k) + carry;
			product[i] = (uint32_t)value;
			carry = value >> 32U;
		}

		product[8U] = (uint32_t)carry;
		ecdhp256_field_reduce512(r, product);
	}

	qsc_memutils_secure_erase(twice, sizeof(twice));
	qsc_memutils_secure_erase(four, sizeof(four));
	qsc_memutils_secure_erase(product, sizeof(product));
#endif
}

#if !defined(QSC_ECDH_P256_NATIVE)

static void ecdhp256_fe_inv(uint32_t r[8U], const uint32_t a[8U])
{
	static const uint32_t p_minus_2[8U] = {0xFFFFFFFDU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000001U, 0xFFFFFFFFU};

#if defined(QSC_ECDH_P256_NATIVE)
	ecdhp256_field powers[16U] = {{ 0U }};
	ecdhp256_field accumulator = { 0U };
	uint32_t digit;
	size_t window;
	size_t j;

	ecdhp256_field_one(powers[0U]);
	ecdhp256_field_copy(powers[1U], a);

	for (window = 2U; window < 16U; ++window)
	{
		ecdhp256_fe_mul(powers[window], powers[window - 1U], a);
	}

	ecdhp256_field_one(accumulator);

	/* The exponent is public and constant (p - 2). All secret operands
     * follow the same number of multiplications and squarings. */
	for (window = 64U; window > 0U; --window)
	{
		for (j = 0U; j < 4U; ++j)
		{
			ecdhp256_fe_sqr(accumulator, accumulator);
		}

		digit = (p_minus_2[(window - 1U) / 8U] >> (4U * ((window - 1U) % 8U))) & 15U;
		ecdhp256_fe_mul(accumulator, accumulator, powers[digit]);
	}

	ecdhp256_field_copy(r, accumulator);
	qsc_memutils_secure_erase(powers, sizeof(powers));
	qsc_memutils_secure_erase(accumulator, sizeof(accumulator));
#else
	ecdhp256_field powers[16U] = {{ 0U }};
	ecdhp256_field accumulator = { 0U };
	uint32_t digit;
	size_t window;
	size_t j;

	/* The exponent p - 2 is fixed and public. A 4-bit exponent window
	 * reduces portable field multiplications without secret-dependent
	 * control flow or indexing. */
	ecdhp256_field_one(powers[0U]);
	ecdhp256_field_copy(powers[1U], a);

	for (window = 2U; window < 16U; ++window)
	{
		ecdhp256_fe_mul(powers[window], powers[window - 1U], a);
	}

	ecdhp256_field_one(accumulator);

	for (window = 64U; window > 0U; --window)
	{
		for (j = 0U; j < 4U; ++j)
		{
			ecdhp256_fe_sqr(accumulator, accumulator);
		}

		digit = (p_minus_2[(window - 1U) / 8U] >> (4U * ((window - 1U) % 8U))) & 15U;
		ecdhp256_fe_mul(accumulator, accumulator, powers[digit]);
	}

	ecdhp256_field_copy(r, accumulator);
	qsc_memutils_secure_erase(powers, sizeof(powers));
	qsc_memutils_secure_erase(accumulator, sizeof(accumulator));
#endif
}
#endif

static void ecdhp256_sc_from_bytes_reduce(uint32_t r[8U], const uint8_t b[32U])
{
	/* reduce a 256-bit big-endian byte array mod n into a little-endian ecdhp256_field */
	ecdhp256_field_from_bytes(r, b);
	ecdhp256_field_cond_sub(r, ECDHP256_N);
}

static uint32_t ecdhp256_is_infinity(const ecdhp256_jac_t* P)
{
	/* return 1 if the Jacobian point is the point at infinity (Z == 0) */
	return ecdhp256_field_is_zero(P->Z);
}

#if !defined(QSC_ECDH_P256_NATIVE)

static void ecdhp256_aff_to_jac(ecdhp256_jac_t* R, const ecdhp256_aff_t* P)
{
	/* lift an affine point to Jacobian (Z = 1) */
	ecdhp256_field_copy(R->X, P->X);
	ecdhp256_field_copy(R->Y, P->Y);
	ecdhp256_field_one(R->Z);
}

#if !defined(QSC_ECDH_P256_NATIVE)

static void ecdhp256_set_infinity(ecdhp256_jac_t* R)
{
	/* set Jacobian point to the point at infinity */
	ecdhp256_field_zero(R->X);
	ecdhp256_field_one(R->Y);
	ecdhp256_field_zero(R->Z);
}

#endif

static void ecdhp256_dbl(ecdhp256_jac_t* R, const ecdhp256_jac_t* P)
{
	/*
     * Branch-free Jacobian doubling.
     * For the Jacobian point-at-infinity representation used here, a result
     * with Z == 0 is treated as infinity by the rest of the code.
     */
	ecdhp256_field delta;
	ecdhp256_field gamma;
	ecdhp256_field beta;
	ecdhp256_field alpha;
	ecdhp256_field tmp;
	ecdhp256_field x3;
	ecdhp256_field y3;
	ecdhp256_field z3;

	/* delta = Z1^2 */
	ecdhp256_fe_sqr(delta, P->Z);

	/* gamma = Y1^2 */
	ecdhp256_fe_sqr(gamma, P->Y);

	/* beta = X1 * gamma */
	ecdhp256_fe_mul(beta, P->X, gamma);

	/* alpha = 3 * (X1 - delta) * (X1 + delta) */
	ecdhp256_fe_sub(alpha, P->X, delta);
	ecdhp256_fe_add(tmp, P->X, delta);
	ecdhp256_fe_mul(alpha, alpha, tmp);
	ecdhp256_fe_mul_small(alpha, alpha, 3U);

	/* X3 = alpha^2 - 8*beta */
	ecdhp256_fe_sqr(x3, alpha);
	ecdhp256_fe_mul_small(tmp, beta, 8U);
	ecdhp256_fe_sub(x3, x3, tmp);

	/* Z3 = (Y1 + Z1)^2 - gamma - delta */
	ecdhp256_fe_add(z3, P->Y, P->Z);
	ecdhp256_fe_sqr(z3, z3);
	ecdhp256_fe_sub(z3, z3, gamma);
	ecdhp256_fe_sub(z3, z3, delta);

	/* Y3 = alpha * (4*beta - X3) - 8*gamma^2 */
	ecdhp256_fe_mul_small(tmp, beta, 4U);
	ecdhp256_fe_sub(tmp, tmp, x3);
	ecdhp256_fe_mul(y3, alpha, tmp);
	ecdhp256_fe_sqr(tmp, gamma);
	ecdhp256_fe_mul_small(tmp, tmp, 8U);
	ecdhp256_fe_sub(y3, y3, tmp);

	ecdhp256_field_copy(R->X, x3);
	ecdhp256_field_copy(R->Y, y3);
	ecdhp256_field_copy(R->Z, z3);
}

static void ecdhp256_add(ecdhp256_jac_t* R, const ecdhp256_jac_t* P, const ecdhp256_jac_t* Q)
{
	/*
     * Constant-time Jacobian addition for distinct points in the ECDH ladder.
     * The ladder invariant ensures that P and Q differ by the non-identity
     * peer point, so the equal-point doubling case cannot occur.
     * An opposite-point sum naturally produces Z = 0 (infinity); input
     * infinity points are selected using word masks, not branches.
     */

	ecdhp256_field z1z1;
	ecdhp256_field z2z2;
	ecdhp256_field u1;
	ecdhp256_field u2;
	ecdhp256_field s1;
	ecdhp256_field s2;
	ecdhp256_field h;
	ecdhp256_field r2;
	ecdhp256_field i;
	ecdhp256_field j;
	ecdhp256_field v;
	ecdhp256_field x3;
	ecdhp256_field y3;
	ecdhp256_field z3;
	ecdhp256_field tmp;
	ecdhp256_jac_t Radd;
	uint32_t pinf;
	uint32_t qinf;
	ecdhp256_jac_t T;

	/* generic add candidate */
	ecdhp256_fe_sqr(z1z1, P->Z);
	ecdhp256_fe_sqr(z2z2, Q->Z);

	ecdhp256_fe_mul(u1, P->X, z2z2);
	ecdhp256_fe_mul(u2, Q->X, z1z1);

	ecdhp256_fe_mul(s1, P->Y, Q->Z);
	ecdhp256_fe_mul(s1, s1, z2z2);

	ecdhp256_fe_mul(s2, Q->Y, P->Z);
	ecdhp256_fe_mul(s2, s2, z1z1);

	ecdhp256_fe_sub(h, u2, u1);
	ecdhp256_fe_sub(r2, s2, s1);
	ecdhp256_fe_mul_small(r2, r2, 2U);

	ecdhp256_fe_mul_small(i, h, 2U);
	ecdhp256_fe_sqr(i, i);
	ecdhp256_fe_mul(j, h, i);
	ecdhp256_fe_mul(v, u1, i);

	ecdhp256_fe_sqr(x3, r2);
	ecdhp256_fe_sub(x3, x3, j);
	ecdhp256_fe_sub(x3, x3, v);
	ecdhp256_fe_sub(x3, x3, v);

	ecdhp256_fe_sub(tmp, v, x3);
	ecdhp256_fe_mul(y3, r2, tmp);

	ecdhp256_fe_mul(tmp, s1, j);
	ecdhp256_fe_mul_small(tmp, tmp, 2U);
	ecdhp256_fe_sub(y3, y3, tmp);

	ecdhp256_fe_add(z3, P->Z, Q->Z);
	ecdhp256_fe_sqr(z3, z3);
	ecdhp256_fe_sub(z3, z3, z1z1);
	ecdhp256_fe_sub(z3, z3, z2z2);
	ecdhp256_fe_mul(z3, z3, h);

	ecdhp256_field_copy(Radd.X, x3);
	ecdhp256_field_copy(Radd.Y, y3);
	ecdhp256_field_copy(Radd.Z, z3);

	pinf = ecdhp256_is_infinity(P);
	qinf = ecdhp256_is_infinity(Q);

	/* The normal formula also represents opposite points as infinity.
     * Lift the two legitimate input-infinity cases without scalar branching. */
	T = Radd;
	ecdhp256_jac_ct_select(&T, qinf, P, &T);
	ecdhp256_jac_ct_select(&T, pinf, Q, &T);

	*R = T;

	qsc_memutils_secure_erase(&Radd, sizeof(Radd));
	qsc_memutils_secure_erase(&T, sizeof(T));
}

#endif /* QSC_ECDH_P256_NATIVE */

#if defined(QSC_ECDH_P256_NATIVE)
/* Reused four-limb native Montgomery arithmetic from the frozen QSC P-256
 * signing implementation, derived from P-256 native-field approach.
 * Simplified BSD license; original QRCS license notice applies.
 * This independent ECDH point engine never calls or modifies ECDSA. */
/*! \brief One P-256 Montgomery residue, least significant word first. */
typedef uint64_t ecdhp256_native_fe[4U];

/*! \brief One P-256 Jacobian point over the native Montgomery representation. */
typedef struct
{
	/*! \brief Montgomery projective X coordinate. */
	ecdhp256_native_fe x;
	/*! \brief Montgomery projective Y coordinate. */
	ecdhp256_native_fe y;
	/*! \brief Montgomery projective Z coordinate, zero for infinity. */
	ecdhp256_native_fe z;
} ecdhp256_native_point;

/*! \brief P-256 field modulus as four little-endian words. */
static const uint64_t ECDHP256_NATIVE_PRIME[4U] = {
	UINT64_C(0xFFFFFFFFFFFFFFFF), UINT64_C(0x00000000FFFFFFFF), UINT64_C(0x0000000000000000), UINT64_C(0xFFFFFFFF00000001)};

/*! \brief The Montgomery representation of field identity. */
static const uint64_t ECDHP256_NATIVE_ONE[4U] = {
	UINT64_C(0x0000000000000001), UINT64_C(0xFFFFFFFF00000000), UINT64_C(0xFFFFFFFFFFFFFFFF), UINT64_C(0x00000000FFFFFFFE)};

static void ecdhp256_native_load(ecdhp256_native_fe output, const uint32_t input[8U])
{
	size_t i;

	for (i = 0U; i < 4U; ++i)
	{
		output[i] = (uint64_t)input[2U * i] | ((uint64_t)input[2U * i + 1U] << 32U);
	}
}

static void ecdhp256_native_store(uint32_t output[8U], const ecdhp256_native_fe input)
{
	size_t i;

	for (i = 0U; i < 4U; ++i)
	{
		output[2U * i] = (uint32_t)input[i];
		output[2U * i + 1U] = (uint32_t)(input[i] >> 32U);
	}
}

static uint64_t ecdhp256_native_is_zero(const ecdhp256_native_fe input)
{
	uint64_t bits;

	bits = input[0U] | input[1U] | input[2U] | input[3U];

	return (uint64_t)(1U ^ ((bits | (UINT64_C(0) - bits)) >> 63U));
}

static void ecdhp256_native_copy(ecdhp256_native_fe output, const ecdhp256_native_fe input)
{
	output[0U] = input[0U];
	output[1U] = input[1U];
	output[2U] = input[2U];
	output[3U] = input[3U];
}

static void ecdhp256_native_add(ecdhp256_native_fe output, const ecdhp256_native_fe a, const ecdhp256_native_fe b, uint64_t scratch[15U])
{
#if defined(__x86_64__) && defined(QSC_ECDH_P256_NATIVE) && !defined(QSC_ECDH_P256_NATIVE_LEGACY_ADDSUB)
	uint64_t* sum;
	uint64_t* reduced;
	uint64_t mask;

	unsigned long long word;
	unsigned char carry;
	unsigned char borrow;
	size_t i;

	sum = scratch;
	reduced = scratch + 4U;
	carry = 0U;

	for (i = 0U; i < 4U; ++i)
	{
		carry = _addcarry_u64(carry, (unsigned long long)a[i], (unsigned long long)b[i], &word);
		sum[i] = (uint64_t)word;
	}

	borrow = 0U;

	for (i = 0U; i < 4U; ++i)
	{
		borrow = _subborrow_u64(borrow, (unsigned long long)sum[i], (unsigned long long)ECDHP256_NATIVE_PRIME[i], &word);
		reduced[i] = (uint64_t)word;
	}

	mask = UINT64_C(0) - ((uint64_t)carry | ((uint64_t)borrow ^ UINT64_C(1)));

	for (i = 0U; i < 4U; ++i)
	{
		output[i] = reduced[i] ^ ((sum[i] ^ reduced[i]) & ~mask);
	}
#else
	uint64_t* sum;
	uint64_t* reduced;

	__uint128_t value;
	uint64_t carry;
	uint64_t borrow;
	uint64_t mask;
	size_t i;

	sum = scratch;
	reduced = scratch + 4U;
	carry = 0U;

	for (i = 0U; i < 4U; ++i)
	{
		value = (__uint128_t)a[i] + b[i] + carry;
		sum[i] = (uint64_t)value;
		carry = (uint64_t)(value >> 64U);
	}

	borrow = 0U;

	for (i = 0U; i < 4U; ++i)
	{
		value = (__uint128_t)sum[i] - ECDHP256_NATIVE_PRIME[i] - borrow;
		reduced[i] = (uint64_t)value;
		borrow = (uint64_t)(value >> 127U);
	}

	mask = UINT64_C(0) - (carry | (borrow ^ 1U));

	for (i = 0U; i < 4U; ++i)
	{
		output[i] = (reduced[i] & mask) | (sum[i] & ~mask);
	}

#endif
}

static void ecdhp256_native_sub(ecdhp256_native_fe output, const ecdhp256_native_fe a, const ecdhp256_native_fe b, uint64_t scratch[15U])
{
#if defined(__x86_64__) && defined(QSC_ECDH_P256_NATIVE) && !defined(QSC_ECDH_P256_NATIVE_LEGACY_ADDSUB)
	uint64_t* difference;
	uint64_t mask;

	unsigned long long word;
	unsigned char borrow;
	unsigned char carry;
	size_t i;

	difference = scratch;
	borrow = 0U;

	for (i = 0U; i < 4U; ++i)
	{
		borrow = _subborrow_u64(borrow, (unsigned long long)a[i], (unsigned long long)b[i], &word);
		difference[i] = (uint64_t)word;
	}

	mask = UINT64_C(0) - (uint64_t)borrow;
	carry = 0U;

	for (i = 0U; i < 4U; ++i)
	{
		carry = _addcarry_u64(carry, (unsigned long long)difference[i], (unsigned long long)(ECDHP256_NATIVE_PRIME[i] & mask), &word);
		output[i] = (uint64_t)word;
	}
#else
	uint64_t* difference;

	__uint128_t value;
	uint64_t borrow;
	uint64_t carry;
	uint64_t mask;
	size_t i;

	difference = scratch;
	borrow = 0U;

	for (i = 0U; i < 4U; ++i)
	{
		value = (__uint128_t)a[i] - b[i] - borrow;
		difference[i] = (uint64_t)value;
		borrow = (uint64_t)(value >> 127U);
	}

	mask = UINT64_C(0) - borrow;
	carry = 0U;

	for (i = 0U; i < 4U; ++i)
	{
		value = (__uint128_t)difference[i] + (ECDHP256_NATIVE_PRIME[i] & mask) + carry;
		output[i] = (uint64_t)value;
		carry = (uint64_t)(value >> 64U);
	}
#endif
}

ECDHP256_ECDH_GCC_COMBA_INLINE void ecdhp256_native_comba_acc_product(uint64_t accumulator[3U], __uint128_t product)
{
	__uint128_t value;

	value = (__uint128_t)accumulator[0U] + (uint64_t)product;
	accumulator[0U] = (uint64_t)value;
	value = (__uint128_t)accumulator[1U] + (uint64_t)(product >> 64U) + (uint64_t)(value >> 64U);
	accumulator[1U] = (uint64_t)value;
	accumulator[2U] += (uint64_t)(value >> 64U);
}

ECDHP256_ECDH_GCC_COMBA_INLINE void ecdhp256_native_comba_acc(uint64_t accumulator[3U], uint64_t a, uint64_t b)
{
	ecdhp256_native_comba_acc_product(accumulator, (__uint128_t)a * b);
}

ECDHP256_ECDH_GCC_COMBA_INLINE void ecdhp256_native_comba_acc_double(uint64_t accumulator[3U], __uint128_t product)
{
	uint64_t dlo;
	uint64_t dhi;
	uint64_t hcry;

	__uint128_t sum;

	dlo = (uint64_t)product << 1U;
	dhi = ((uint64_t)(product >> 64U) << 1U) | ((uint64_t)product >> 63U);
	hcry = (uint64_t)(product >> 127U);
	sum = (__uint128_t)accumulator[0U] + dlo;
	accumulator[0U] = (uint64_t)sum;
	sum = (__uint128_t)accumulator[1U] + dhi + (uint64_t)(sum >> 64U);
	accumulator[1U] = (uint64_t)sum;
	accumulator[2U] += hcry + (uint64_t)(sum >> 64U);
}

static void ecdhp256_native_comba_mul(uint64_t result[15U], const ecdhp256_native_fe a, const ecdhp256_native_fe b)
{
	uint64_t accumulator[3U];

	accumulator[0U] = 0U;
	accumulator[1U] = 0U;
	accumulator[2U] = 0U;

	ecdhp256_native_comba_acc(accumulator, a[0U], b[0U]);
	result[0U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	ecdhp256_native_comba_acc(accumulator, a[0U], b[1U]);
	ecdhp256_native_comba_acc(accumulator, a[1U], b[0U]);
	result[1U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	ecdhp256_native_comba_acc(accumulator, a[0U], b[2U]);
	ecdhp256_native_comba_acc(accumulator, a[1U], b[1U]);
	ecdhp256_native_comba_acc(accumulator, a[2U], b[0U]);
	result[2U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	ecdhp256_native_comba_acc(accumulator, a[0U], b[3U]);
	ecdhp256_native_comba_acc(accumulator, a[1U], b[2U]);
	ecdhp256_native_comba_acc(accumulator, a[2U], b[1U]);
	ecdhp256_native_comba_acc(accumulator, a[3U], b[0U]);
	result[3U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	ecdhp256_native_comba_acc(accumulator, a[1U], b[3U]);
	ecdhp256_native_comba_acc(accumulator, a[2U], b[2U]);
	ecdhp256_native_comba_acc(accumulator, a[3U], b[1U]);
	result[4U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	ecdhp256_native_comba_acc(accumulator, a[2U], b[3U]);
	ecdhp256_native_comba_acc(accumulator, a[3U], b[2U]);
	result[5U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	ecdhp256_native_comba_acc(accumulator, a[3U], b[3U]);
	result[6U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	result[7U] = accumulator[0U];
	qsc_memutils_secure_erase(accumulator, sizeof(accumulator));
}

static void ecdhp256_native_comba_square(uint64_t result[15U], const ecdhp256_native_fe a)
{
	uint64_t accumulator[3U];

	__uint128_t product;

	accumulator[0U] = 0U;
	accumulator[1U] = 0U;
	accumulator[2U] = 0U;

	product = (__uint128_t)a[0U] * a[0U];
	ecdhp256_native_comba_acc_product(accumulator, product);
	result[0U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	product = (__uint128_t)a[0U] * a[1U];
	ecdhp256_native_comba_acc_double(accumulator, product);
	result[1U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	product = (__uint128_t)a[0U] * a[2U];
	ecdhp256_native_comba_acc_double(accumulator, product);
	product = (__uint128_t)a[1U] * a[1U];
	ecdhp256_native_comba_acc_product(accumulator, product);
	result[2U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	product = (__uint128_t)a[0U] * a[3U];
	ecdhp256_native_comba_acc_double(accumulator, product);
	product = (__uint128_t)a[1U] * a[2U];
	ecdhp256_native_comba_acc_double(accumulator, product);
	result[3U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	product = (__uint128_t)a[1U] * a[3U];
	ecdhp256_native_comba_acc_double(accumulator, product);
	product = (__uint128_t)a[2U] * a[2U];
	ecdhp256_native_comba_acc_product(accumulator, product);
	result[4U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	product = (__uint128_t)a[2U] * a[3U];
	ecdhp256_native_comba_acc_double(accumulator, product);
	result[5U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	product = (__uint128_t)a[3U] * a[3U];
	ecdhp256_native_comba_acc_product(accumulator, product);
	result[6U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	result[7U] = accumulator[0U];
	qsc_memutils_secure_erase(accumulator, sizeof(accumulator));
	qsc_memutils_secure_erase(&product, sizeof(product));
}

#if !defined(__x86_64__) || defined(QSC_ECDH_P256_NATIVE_LEGACY_REDUCE) || defined(QSC_ECDH_P256_EXCHANGE_LEGACY_REDUCE)

static void ecdhp256_native_reduce(ecdhp256_native_fe output, uint64_t scratch[15U])
{
	uint64_t* words;
	uint64_t* reduced;

	__uint128_t value;
	uint64_t pending;
	uint64_t carry;
	uint64_t borrow;
	uint64_t m;
	uint64_t q0;
	uint64_t q1;
	uint64_t q2;
	uint64_t q3;
	uint64_t selected;
	uint64_t mask;
	size_t i;

	words = scratch;
	reduced = scratch + 8U;
	pending = 0U;

	for (i = 0U; i < 4U; ++i)
	{
		m = words[i];
		q0 = m << 32U;
		q1 = m >> 32U;
		borrow = (uint64_t)(m < q0);
		q2 = m - q0;
		q3 = m - q1 - borrow + pending;
		carry = 0U;

		value = (__uint128_t)words[i + 1U] + q0 + carry;
		words[i + 1U] = (uint64_t)value;
		carry = (uint64_t)(value >> 64U);
		value = (__uint128_t)words[i + 2U] + q1 + carry;
		words[i + 2U] = (uint64_t)value;
		carry = (uint64_t)(value >> 64U);
		value = (__uint128_t)words[i + 3U] + q2 + carry;
		words[i + 3U] = (uint64_t)value;
		carry = (uint64_t)(value >> 64U);
		value = (__uint128_t)words[i + 4U] + q3 + carry;
		words[i + 4U] = (uint64_t)value;
		pending = (uint64_t)(value >> 64U);
	}

	borrow = 0U;

	for (i = 0U; i < 4U; ++i)
	{
		value = (__uint128_t)words[i + 4U] - ECDHP256_NATIVE_PRIME[i] - borrow;
		reduced[i] = (uint64_t)value;
		borrow = (uint64_t)(value >> 127U);
	}

	mask = UINT64_C(0) - (borrow & (pending ^ 1U));

	for (i = 0U; i < 4U; ++i)
	{
		selected = reduced[i] ^ ((words[i + 4U] ^ reduced[i]) & mask);
		output[i] = selected;
	}
}

#endif /* Non-intrinsic native Montgomery reduction */

static void ecdhp256_native_reduce_intrinsic(uint64_t* restrict output, uint64_t* restrict scratch);

static void ecdhp256_native_mul(ecdhp256_native_fe output, const ecdhp256_native_fe a, const ecdhp256_native_fe b, uint64_t scratch[15U])
{
	ecdhp256_native_comba_mul(scratch, a, b);
	ecdhp256_native_reduce_intrinsic(output, scratch);
}

static void ecdhp256_native_square(ecdhp256_native_fe output, const ecdhp256_native_fe a, uint64_t scratch[15U])
{
	ecdhp256_native_comba_square(scratch, a);
	ecdhp256_native_reduce_intrinsic(output, scratch);
}

static void ecdhp256_native_square_n(ecdhp256_native_fe value, size_t rounds, uint64_t scratch[15U])
{
	size_t i;

	for (i = 0U; i < rounds; ++i)
	{
		ecdhp256_native_square(value, value, scratch);
	}
}

static void ecdhp256_native_inverse_square(ecdhp256_native_fe output, const ecdhp256_native_fe z, uint64_t scratch[15U])
{
	ecdhp256_native_fe t[2U] = {{ 0U }};
	ecdhp256_native_fe r = { 0U };

	ecdhp256_native_square(r, z, scratch);
	ecdhp256_native_mul(r, r, z, scratch);
	ecdhp256_native_square(r, r, scratch);
	ecdhp256_native_mul(r, r, z, scratch);
	ecdhp256_native_copy(t[0U], r);
	ecdhp256_native_square_n(t[0U], 3U, scratch);
	ecdhp256_native_mul(t[0U], t[0U], r, scratch);
	ecdhp256_native_copy(t[1U], t[0U]);
	ecdhp256_native_square_n(t[1U], 6U, scratch);
	ecdhp256_native_mul(t[0U], t[0U], t[1U], scratch);
	ecdhp256_native_square_n(t[0U], 3U, scratch);
	ecdhp256_native_mul(r, r, t[0U], scratch);
	ecdhp256_native_square(t[0U], r, scratch);
	ecdhp256_native_mul(t[0U], t[0U], z, scratch);
	ecdhp256_native_copy(t[1U], t[0U]);
	ecdhp256_native_square_n(t[1U], 16U, scratch);
	ecdhp256_native_mul(t[0U], t[0U], t[1U], scratch);
	ecdhp256_native_square_n(t[0U], 15U, scratch);
	ecdhp256_native_mul(r, r, t[0U], scratch);
	ecdhp256_native_square_n(t[0U], 17U, scratch);
	ecdhp256_native_mul(t[0U], t[0U], z, scratch);
	ecdhp256_native_square_n(t[0U], 143U, scratch);
	ecdhp256_native_mul(t[0U], t[0U], r, scratch);
	ecdhp256_native_square_n(t[0U], 47U, scratch);
	ecdhp256_native_mul(r, r, t[0U], scratch);
	ecdhp256_native_square_n(r, 2U, scratch);
	ecdhp256_native_copy(output, r);

	qsc_memutils_secure_erase(t, sizeof(t));
	qsc_memutils_secure_erase(r, sizeof(r));
}

static void ecdhp256_native_affine_x(ecdhp256_field output, const ecdhp256_jac_t* point)
{
	uint64_t scratch[15U] = { 0U };
	ecdhp256_native_fe x = { 0U };
	ecdhp256_native_fe z = { 0U };
	ecdhp256_native_fe inverse2 = { 0U };
	ecdhp256_native_fe product = { 0U };

	ecdhp256_native_load(x, point->X);
	ecdhp256_native_load(z, point->Z);
	ecdhp256_native_inverse_square(inverse2, z, scratch);
	ecdhp256_native_mul(product, x, inverse2, scratch);
	ecdhp256_native_mul(product, product, (const uint64_t[4U]){1U, 0U, 0U, 0U}, scratch);
	ecdhp256_native_store(output, product);
	qsc_memutils_secure_erase(x, sizeof(x));
	qsc_memutils_secure_erase(z, sizeof(z));
	qsc_memutils_secure_erase(inverse2, sizeof(inverse2));
	qsc_memutils_secure_erase(product, sizeof(product));
	qsc_memutils_secure_erase(scratch, sizeof(scratch));
}

/*! \brief Reusable native-width Jacobian mixed-add workspace.
 * \note Owned by one scalar multiplication and securely erased at its completion.
 */
typedef struct
{
	/*! \brief Projective Z square. */
	ecdhp256_native_fe zz;
	/*! \brief Second X scaled by first Z square. */
	ecdhp256_native_fe u;
	/*! \brief Second Y scaled by first Z cube. */
	ecdhp256_native_fe s;
	/*! \brief Jacobian X coordinate difference. */
	ecdhp256_native_fe h;
	/*! \brief Jacobian Y coordinate difference. */
	ecdhp256_native_fe delta; /*!< Cached squared projective scale. */

	/*! \brief Square of X difference. */
	ecdhp256_native_fe hh;
	/*! \brief Cube of X difference. */
	ecdhp256_native_fe hhh;
	/*! \brief First X times squared X difference. */
	ecdhp256_native_fe v;
	/*! \brief Temporary intermediate field value. */
	ecdhp256_native_fe tmp; /*!< Temporary field scratch. */

	/*! \brief Candidate sum point before constant-time infinity selection. */
	ecdhp256_native_point added;
} ecdhp256_native_window_workspace;

static void ecdhp256_native_add_candidate(const ecdhp256_native_point* first, const ecdhp256_native_point* second, ecdhp256_native_window_workspace* work, uint64_t scratch[15U])
{
	ecdhp256_native_square(work->zz, first->z, scratch);
	ecdhp256_native_mul(work->u, second->x, work->zz, scratch);
	ecdhp256_native_mul(work->s, second->y, first->z, scratch);
	ecdhp256_native_mul(work->s, work->s, work->zz, scratch);
	ecdhp256_native_sub(work->h, work->u, first->x, scratch);
	ecdhp256_native_sub(work->delta, work->s, first->y, scratch);
	ecdhp256_native_square(work->hh, work->h, scratch);
	ecdhp256_native_mul(work->hhh, work->h, work->hh, scratch);
	ecdhp256_native_mul(work->v, first->x, work->hh, scratch);
	ecdhp256_native_square(work->added.x, work->delta, scratch);
	ecdhp256_native_sub(work->added.x, work->added.x, work->hhh, scratch);
	ecdhp256_native_add(work->tmp, work->v, work->v, scratch);
	ecdhp256_native_sub(work->added.x, work->added.x, work->tmp, scratch);
	ecdhp256_native_sub(work->tmp, work->v, work->added.x, scratch);
	ecdhp256_native_mul(work->added.y, work->delta, work->tmp, scratch);
	ecdhp256_native_mul(work->tmp, first->y, work->hhh, scratch);
	ecdhp256_native_sub(work->added.y, work->added.y, work->tmp, scratch);
	ecdhp256_native_mul(work->added.z, first->z, work->h, scratch);
}

static void ecdhp256_native_add_generator(ecdhp256_native_point* output, const ecdhp256_native_point* first, const ecdhp256_native_point* second, ecdhp256_native_window_workspace* work, uint64_t scratch[15U])
{
	uint64_t finf;
	uint64_t sinf;

	ecdhp256_native_add_candidate(first, second, work, scratch);
	finf = ecdhp256_native_is_zero(first->z);
	sinf = ecdhp256_native_is_zero(second->z);
	qsc_intutils_cmov((uint8_t*)&work->added, (const uint8_t*)first, sizeof(work->added), (uint8_t)sinf);
	qsc_intutils_cmov((uint8_t*)&work->added, (const uint8_t*)second, sizeof(work->added), (uint8_t)finf);
	*output = work->added;
}

/*! \brief Reusable secret-point doubling workspace, cleared after the operation. */
typedef struct
{
	ecdhp256_native_fe delta; /*!< Cached squared projective scale. */

	ecdhp256_native_fe gamma; /*!< Squared y coordinate. */

	ecdhp256_native_fe beta; /*!< Product of x and squared y. */

	ecdhp256_native_fe alpha; /*!< Doubling slope numerator. */

	ecdhp256_native_fe tmp; /*!< Temporary field scratch. */

	ecdhp256_native_point next; /*!< Next projective point. */

} ecdhp256_ecdh_double_workspace;

static void ecdhp256_ecdh_native_double(ecdhp256_native_point* result, const ecdhp256_native_point* first, ecdhp256_ecdh_double_workspace* work, uint64_t scratch[15U])
{
	ecdhp256_native_square(work->delta, first->z, scratch);
	ecdhp256_native_square(work->gamma, first->y, scratch);
	ecdhp256_native_mul(work->beta, first->x, work->gamma, scratch);
	ecdhp256_native_sub(work->alpha, first->x, work->delta, scratch);
	ecdhp256_native_add(work->tmp, first->x, work->delta, scratch);
	ecdhp256_native_mul(work->alpha, work->alpha, work->tmp, scratch);
	ecdhp256_native_add(work->tmp, work->alpha, work->alpha, scratch);
	ecdhp256_native_add(work->alpha, work->tmp, work->alpha, scratch);

	ecdhp256_native_square(work->next.x, work->alpha, scratch);
	ecdhp256_native_add(work->tmp, work->beta, work->beta, scratch);
	ecdhp256_native_add(work->tmp, work->tmp, work->tmp, scratch);
	ecdhp256_native_add(work->tmp, work->tmp, work->tmp, scratch);
	ecdhp256_native_sub(work->next.x, work->next.x, work->tmp, scratch);

	ecdhp256_native_mul(work->next.z, first->y, first->z, scratch);
	ecdhp256_native_add(work->next.z, work->next.z, work->next.z, scratch);

	ecdhp256_native_add(work->tmp, work->beta, work->beta, scratch);
	ecdhp256_native_add(work->tmp, work->tmp, work->tmp, scratch);
	ecdhp256_native_sub(work->tmp, work->tmp, work->next.x, scratch);
	ecdhp256_native_mul(work->next.y, work->alpha, work->tmp, scratch);
	ecdhp256_native_square(work->tmp, work->gamma, scratch);
	ecdhp256_native_add(work->tmp, work->tmp, work->tmp, scratch);
	ecdhp256_native_add(work->tmp, work->tmp, work->tmp, scratch);
	ecdhp256_native_add(work->tmp, work->tmp, work->tmp, scratch);
	ecdhp256_native_sub(work->next.y, work->next.y, work->tmp, scratch);
	*result = work->next;
}

static void ecdhp256_ecdh_native_double_iso(ecdhp256_native_point* result, const ecdhp256_native_point* first, ecdhp256_ecdh_double_workspace* work, const ecdhp256_native_fe scale_squared, uint64_t scratch[15U])
{
	ecdhp256_native_square(work->delta, first->z, scratch);
	ecdhp256_native_square(work->gamma, first->y, scratch);
	ecdhp256_native_mul(work->beta, first->x, work->gamma, scratch);
	ecdhp256_native_mul(work->tmp, work->delta, scale_squared, scratch);
	ecdhp256_native_sub(work->alpha, first->x, work->tmp, scratch);
	ecdhp256_native_add(work->tmp, first->x, work->tmp, scratch);
	ecdhp256_native_mul(work->alpha, work->alpha, work->tmp, scratch);
	ecdhp256_native_add(work->tmp, work->alpha, work->alpha, scratch);
	ecdhp256_native_add(work->alpha, work->tmp, work->alpha, scratch);

	ecdhp256_native_square(work->next.x, work->alpha, scratch);
	ecdhp256_native_add(work->tmp, work->beta, work->beta, scratch);
	ecdhp256_native_add(work->tmp, work->tmp, work->tmp, scratch);
	ecdhp256_native_add(work->tmp, work->tmp, work->tmp, scratch);
	ecdhp256_native_sub(work->next.x, work->next.x, work->tmp, scratch);

	ecdhp256_native_mul(work->next.z, first->y, first->z, scratch);
	ecdhp256_native_add(work->next.z, work->next.z, work->next.z, scratch);

	ecdhp256_native_add(work->tmp, work->beta, work->beta, scratch);
	ecdhp256_native_add(work->tmp, work->tmp, work->tmp, scratch);
	ecdhp256_native_sub(work->tmp, work->tmp, work->next.x, scratch);
	ecdhp256_native_mul(work->next.y, work->alpha, work->tmp, scratch);
	ecdhp256_native_square(work->tmp, work->gamma, scratch);
	ecdhp256_native_add(work->tmp, work->tmp, work->tmp, scratch);
	ecdhp256_native_add(work->tmp, work->tmp, work->tmp, scratch);
	ecdhp256_native_add(work->tmp, work->tmp, work->tmp, scratch);
	ecdhp256_native_sub(work->next.y, work->next.y, work->tmp, scratch);
	*result = work->next;
}

#if !defined(ECDHP256_EXCHANGE_DBL5)

static void ecdhp256_ecdh_native_double_iso_cached(ecdhp256_native_point* result, const ecdhp256_native_point* first, ecdhp256_ecdh_double_workspace* work, uint64_t scratch[15U], bool update_delta)
{
	ecdhp256_native_square(work->gamma, first->y, scratch);
	ecdhp256_native_mul(work->beta, first->x, work->gamma, scratch);
	ecdhp256_native_sub(work->alpha, first->x, work->delta, scratch);
	ecdhp256_native_add(work->tmp, first->x, work->delta, scratch);
	ecdhp256_native_mul(work->alpha, work->alpha, work->tmp, scratch);
	ecdhp256_native_add(work->tmp, work->alpha, work->alpha, scratch);
	ecdhp256_native_add(work->alpha, work->tmp, work->alpha, scratch);

	ecdhp256_native_square(work->next.x, work->alpha, scratch);
	/* Preserve 4*beta across the X and Y formulas. The previous sequence
     * computed it twice, requiring two unnecessary field additions per
     * doubling. Both temporaries are already in the operation workspace. */
	ecdhp256_native_add(work->tmp, work->beta, work->beta, scratch);
	ecdhp256_native_add(work->tmp, work->tmp, work->tmp, scratch);
	ecdhp256_native_add(work->next.y, work->tmp, work->tmp, scratch);
	ecdhp256_native_sub(work->next.x, work->next.x, work->next.y, scratch);

	ecdhp256_native_mul(work->next.z, first->y, first->z, scratch);
	ecdhp256_native_add(work->next.z, work->next.z, work->next.z, scratch);

	ecdhp256_native_sub(work->tmp, work->tmp, work->next.x, scratch);
	ecdhp256_native_mul(work->next.y, work->alpha, work->tmp, scratch);
	ecdhp256_native_square(work->tmp, work->gamma, scratch);
	ecdhp256_native_add(work->tmp, work->tmp, work->tmp, scratch);
	ecdhp256_native_add(work->tmp, work->tmp, work->tmp, scratch);
	ecdhp256_native_add(work->tmp, work->tmp, work->tmp, scratch);
	ecdhp256_native_sub(work->next.y, work->next.y, work->tmp, scratch);

	if (update_delta)
	{
		/* Z' = 2YZ, so (scale*Z')^2 = 4*Y^2*(scale*Z)^2. */
		ecdhp256_native_mul(work->delta, work->delta, work->gamma, scratch);
		ecdhp256_native_add(work->delta, work->delta, work->delta, scratch);
		ecdhp256_native_add(work->delta, work->delta, work->delta, scratch);
	}

	*result = work->next;
}

#endif /* !ECDHP256_EXCHANGE_DBL5 */

ECDHP256_ECDH_NATIVE_INLINE void ecdhp256_native_reduce_intrinsic(uint64_t* restrict output, uint64_t* restrict scratch)
{
#if defined(__x86_64__) && defined(QSC_ECDH_P256_NATIVE) && !defined(QSC_ECDH_P256_EXCHANGE_LEGACY_REDUCE) && !defined(QSC_ECDH_P256_NATIVE_LEGACY_REDUCE)
	uint64_t* words;
	uint64_t* reduced;
	uint64_t m;
	uint64_t q0;
	uint64_t q1;
	uint64_t q2;
	uint64_t q3;
	uint64_t pending;
	uint64_t brwd;
	uint64_t mask;

	unsigned long long result_word;
	unsigned char carry;
	unsigned char borrow;
	size_t i;

	words = scratch;
	reduced = scratch + 8U;
	pending = 0U;

	for (i = 0U; i < 4U; ++i)
	{
		m = words[i];
		q0 = m << 32U;
		q1 = m >> 32U;
		brwd = (uint64_t)(m < q0);
		q2 = m - q0;
		q3 = m - q1 - brwd + pending;

		carry = _addcarry_u64(0U, (unsigned long long)words[i + 1U], (unsigned long long)q0, &result_word);
		words[i + 1U] = (uint64_t)result_word;
		carry = _addcarry_u64(carry, (unsigned long long)words[i + 2U], (unsigned long long)q1, &result_word);
		words[i + 2U] = (uint64_t)result_word;
		carry = _addcarry_u64(carry, (unsigned long long)words[i + 3U], (unsigned long long)q2, &result_word);
		words[i + 3U] = (uint64_t)result_word;
		carry = _addcarry_u64(carry, (unsigned long long)words[i + 4U], (unsigned long long)q3, &result_word);
		words[i + 4U] = (uint64_t)result_word;
		pending = (uint64_t)carry;
	}

	borrow = 0U;

	for (i = 0U; i < 4U; ++i)
	{
		borrow = _subborrow_u64(borrow, (unsigned long long)words[i + 4U], (unsigned long long)ECDHP256_NATIVE_PRIME[i], &result_word);
		reduced[i] = (uint64_t)result_word;
	}

	mask = UINT64_C(0) - ((uint64_t)borrow & (pending ^ 1U));

	for (i = 0U; i < 4U; ++i)
	{
		output[i] = reduced[i] ^ ((words[i + 4U] ^ reduced[i]) & mask);
	}
#else
	ecdhp256_native_reduce(output, scratch);
#endif
}

#if defined(ECDHP256_EXCHANGE_DBL5)
/*! \brief Owned scratch for the fixed five-doubling isomorphic recurrence. */
typedef struct
{
	ecdhp256_native_point current; /*!< Current repeated-doubling accumulator. */

	ecdhp256_native_fe twice_y; /*!< Doubled y coordinate. */

	ecdhp256_native_fe y2; /*!< Squared doubled y coordinate. */

	ecdhp256_native_fe y4; /*!< Fourth power of doubled y. */

	ecdhp256_native_fe w; /*!< Cached fourth power of projective scale. */

	ecdhp256_native_fe z2; /*!< Squared projective scale. */

	ecdhp256_native_fe t1; /*!< First field temporary. */

	ecdhp256_native_fe t2; /*!< Second field temporary. */

	ecdhp256_native_fe tmp; /*!< Temporary field scratch. */

	ecdhp256_native_fe half_tmp; /*!< Field-halving scratch words. */

	__uint128_t carry_sum; /*!< Carry propagation scratch. */

	uint64_t carry; /*!< Unsigned carry bit. */

	uint64_t odd_mask; /*!< All-one mask when the field input is odd. */

} ecdhp256_repeated_double_workspace;

ECDHP256_ECDH_GCC_COMBA_INLINE void ecdhp256_ecdh_group_comba_mul(uint64_t result[15U], const ecdhp256_native_fe a, const ecdhp256_native_fe b)
{
	uint64_t* accumulator;

	accumulator = result + 12U;
	accumulator[0U] = 0U;
	accumulator[1U] = 0U;
	accumulator[2U] = 0U;

	ecdhp256_native_comba_acc(accumulator, a[0U], b[0U]);
	result[0U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	ecdhp256_native_comba_acc(accumulator, a[0U], b[1U]);
	ecdhp256_native_comba_acc(accumulator, a[1U], b[0U]);
	result[1U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	ecdhp256_native_comba_acc(accumulator, a[0U], b[2U]);
	ecdhp256_native_comba_acc(accumulator, a[1U], b[1U]);
	ecdhp256_native_comba_acc(accumulator, a[2U], b[0U]);
	result[2U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	ecdhp256_native_comba_acc(accumulator, a[0U], b[3U]);
	ecdhp256_native_comba_acc(accumulator, a[1U], b[2U]);
	ecdhp256_native_comba_acc(accumulator, a[2U], b[1U]);
	ecdhp256_native_comba_acc(accumulator, a[3U], b[0U]);
	result[3U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	ecdhp256_native_comba_acc(accumulator, a[1U], b[3U]);
	ecdhp256_native_comba_acc(accumulator, a[2U], b[2U]);
	ecdhp256_native_comba_acc(accumulator, a[3U], b[1U]);
	result[4U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	ecdhp256_native_comba_acc(accumulator, a[2U], b[3U]);
	ecdhp256_native_comba_acc(accumulator, a[3U], b[2U]);
	result[5U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	ecdhp256_native_comba_acc(accumulator, a[3U], b[3U]);
	result[6U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	result[7U] = accumulator[0U];
}

ECDHP256_ECDH_GCC_COMBA_INLINE void ecdhp256_ecdh_group_comba_square(uint64_t result[15U], const ecdhp256_native_fe a)
{
	uint64_t* accumulator;

	__uint128_t product;

	accumulator = result + 12U;
	accumulator[0U] = 0U;
	accumulator[1U] = 0U;
	accumulator[2U] = 0U;

	product = (__uint128_t)a[0U] * a[0U];
	ecdhp256_native_comba_acc_product(accumulator, product);
	result[0U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	product = (__uint128_t)a[0U] * a[1U];
	ecdhp256_native_comba_acc_double(accumulator, product);
	result[1U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	product = (__uint128_t)a[0U] * a[2U];
	ecdhp256_native_comba_acc_double(accumulator, product);
	product = (__uint128_t)a[1U] * a[1U];
	ecdhp256_native_comba_acc_product(accumulator, product);
	result[2U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	product = (__uint128_t)a[0U] * a[3U];
	ecdhp256_native_comba_acc_double(accumulator, product);
	product = (__uint128_t)a[1U] * a[2U];
	ecdhp256_native_comba_acc_double(accumulator, product);
	result[3U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	product = (__uint128_t)a[1U] * a[3U];
	ecdhp256_native_comba_acc_double(accumulator, product);
	product = (__uint128_t)a[2U] * a[2U];
	ecdhp256_native_comba_acc_product(accumulator, product);
	result[4U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	product = (__uint128_t)a[2U] * a[3U];
	ecdhp256_native_comba_acc_double(accumulator, product);
	result[5U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	product = (__uint128_t)a[3U] * a[3U];
	ecdhp256_native_comba_acc_product(accumulator, product);
	result[6U] = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	result[7U] = accumulator[0U];
	qsc_memutils_secure_erase(&product, sizeof(product));
}

ECDHP256_ECDH_NATIVE_INLINE void ecdhp256_ecdh_group_mul(ecdhp256_native_fe output, const ecdhp256_native_fe a, const ecdhp256_native_fe b, uint64_t scratch[15U])
{
	ecdhp256_ecdh_group_comba_mul(scratch, a, b);
	ecdhp256_native_reduce_intrinsic(output, scratch);
}

ECDHP256_ECDH_NATIVE_INLINE void ecdhp256_ecdh_group_square(ecdhp256_native_fe output, const ecdhp256_native_fe a, uint64_t scratch[15U])
{
	ecdhp256_ecdh_group_comba_square(scratch, a);
	ecdhp256_native_reduce_intrinsic(output, scratch);
}

static void ecdhp256_double_iso5(ecdhp256_native_point* output, const ecdhp256_native_point* input, const ecdhp256_native_fe shared_z_squared, uint64_t scratch[15U], ecdhp256_repeated_double_workspace* bw)
{
	ecdhp256_native_fe zero = { 0U };
	size_t i;

	bw->current = *input;
	ecdhp256_ecdh_group_square(bw->z2, bw->current.z, scratch);
	ecdhp256_ecdh_group_mul(bw->z2, bw->z2, shared_z_squared, scratch);
	ecdhp256_ecdh_group_square(bw->w, bw->z2, scratch);
	ecdhp256_native_add(bw->tmp, bw->w, bw->w, scratch);
	ecdhp256_native_add(bw->tmp, bw->tmp, bw->w, scratch);
	ecdhp256_native_sub(bw->w, zero, bw->tmp, scratch);
	ecdhp256_native_add(bw->twice_y, bw->current.y, bw->current.y, scratch);

	for (i = 0U; i < 5U; ++i)
	{
		ecdhp256_ecdh_group_square(bw->y2, bw->twice_y, scratch);
		ecdhp256_ecdh_group_square(bw->y4, bw->y2, scratch);
		ecdhp256_ecdh_group_square(bw->t1, bw->current.x, scratch);
		ecdhp256_native_add(bw->tmp, bw->t1, bw->t1, scratch);
		ecdhp256_native_add(bw->t1, bw->tmp, bw->t1, scratch);
		ecdhp256_native_add(bw->t1, bw->t1, bw->w, scratch);
		ecdhp256_ecdh_group_mul(bw->t2, bw->current.x, bw->y2, scratch);
		ecdhp256_ecdh_group_square(bw->current.x, bw->t1, scratch);
		ecdhp256_native_add(bw->tmp, bw->t2, bw->t2, scratch);
		ecdhp256_native_sub(bw->current.x, bw->current.x, bw->tmp, scratch);
		ecdhp256_ecdh_group_mul(bw->current.z, bw->current.z, bw->twice_y, scratch);
		ecdhp256_native_sub(bw->tmp, bw->t2, bw->current.x, scratch);
		ecdhp256_native_add(bw->tmp, bw->tmp, bw->tmp, scratch);
		ecdhp256_ecdh_group_mul(bw->twice_y, bw->t1, bw->tmp, scratch);
		ecdhp256_native_sub(bw->twice_y, bw->twice_y, bw->y4, scratch);

		if (i < 4U)
		{
			ecdhp256_ecdh_group_mul(bw->w, bw->w, bw->y4, scratch);
		}
	}

	/* Montgomery residues can be halved directly modulo P using
     * (v + (v&1)*P) / 2. Preserve the 257th carry bit. */
	bw->odd_mask = UINT64_C(0) - (bw->twice_y[0U] & UINT64_C(1));
	bw->carry = 0U;

	for (i = 0U; i < 4U; ++i)
	{
		bw->carry_sum = (__uint128_t)bw->twice_y[i] + (ECDHP256_ECDH_P64[i] & bw->odd_mask) + bw->carry;
		bw->half_tmp[i] = (uint64_t)bw->carry_sum;
		bw->carry = (uint64_t)(bw->carry_sum >> 64U);
	}

	for (i = 0U; i < 3U; ++i)
	{
		bw->current.y[i] = (bw->half_tmp[i] >> 1U) | (bw->half_tmp[i + 1U] << 63U);
	}

	bw->current.y[3U] = (bw->half_tmp[3U] >> 1U) | (bw->carry << 63U);
	*output = bw->current;
	/* End the accumulator carry-state lifetime after each public five-doubling group.
     * The owning exchange also securely erases the entire scratch buffer at exit. */
	qsc_memutils_secure_erase(scratch + 12U, 3U * sizeof(uint64_t));
}
#endif /* ECDHP256_EXCHANGE_DBL5 */

#if defined(QSC_ECDH_P256_GENERATOR_W6) && !defined(QSC_ECDH_P256_GENERATOR_COMPACT)

static void ecdhp256_native_masked_coordinate(ecdhp256_native_fe output, const ecdhp256_native_fe sum, const ecdhp256_native_fe first, const ecdhp256_native_fe second, const ecdhp256_native_fe doubled, uint64_t first_mask, uint64_t second_mask, uint64_t double_mask, uint64_t sum_mask)
{
	size_t i;

	for (i = 0U; i < 4U; ++i)
	{
		output[i] = (sum[i] & sum_mask) | (first[i] & first_mask) | (second[i] & second_mask) | (doubled[i] & double_mask);
	}
}

static void ecdhp256_native_add_generator_safe(ecdhp256_native_point* output, const ecdhp256_native_point* first, const ecdhp256_native_point* second, const ecdhp256_native_point* doubled, ecdhp256_native_window_workspace* work, uint64_t scratch[15U])
{
	uint64_t finf;
	uint64_t sinf;
	uint64_t eqpt;
	uint64_t ufst;
	uint64_t usnd;
	uint64_t udbl;
	uint64_t usum;

	ecdhp256_native_add_candidate(first, second, work, scratch);
	finf = ecdhp256_native_is_zero(first->z);
	sinf = ecdhp256_native_is_zero(second->z);
	eqpt = ecdhp256_native_is_zero(work->h) & ecdhp256_native_is_zero(work->delta);
	eqpt &= (finf ^ 1U) & (sinf ^ 1U);

	ufst = UINT64_C(0) - ((finf ^ 1U) & sinf);
	usnd = UINT64_C(0) - finf;
	udbl = UINT64_C(0) - eqpt;
	usum = ~(ufst | usnd | udbl);

	ecdhp256_native_masked_coordinate(output->x, work->added.x, first->x, second->x, doubled->x, ufst, usnd, udbl, usum);
	ecdhp256_native_masked_coordinate(output->y, work->added.y, first->y, second->y, doubled->y, ufst, usnd, udbl, usum);
	ecdhp256_native_masked_coordinate(output->z, work->added.z, first->z, second->z, doubled->z, ufst, usnd, udbl, usum);
}

static void ecdhp256_native_add_generator_early(ecdhp256_native_point* output, const ecdhp256_native_point* first, const ecdhp256_native_point* second, ecdhp256_native_window_workspace* work, uint64_t scratch[15U])
{
	uint64_t finf;
	uint64_t sinf;
	uint64_t ufst;
	uint64_t usnd;
	uint64_t usum;

	ecdhp256_native_add_candidate(first, second, work, scratch);
	finf = ecdhp256_native_is_zero(first->z);
	sinf = ecdhp256_native_is_zero(second->z);
	ufst = UINT64_C(0) - ((finf ^ 1U) & sinf);
	usnd = UINT64_C(0) - finf;
	usum = ~(ufst | usnd);

	ecdhp256_native_masked_coordinate(output->x, work->added.x, first->x, second->x, first->x, ufst, usnd, UINT64_C(0), usum);
	ecdhp256_native_masked_coordinate(output->y, work->added.y, first->y, second->y, first->y, ufst, usnd, UINT64_C(0), usum);
	ecdhp256_native_masked_coordinate(output->z, work->added.z, first->z, second->z, first->z, ufst, usnd, UINT64_C(0), usum);
}

#endif /* QSC_ECDH_P256_GENERATOR_W6 */

static void ecdhp256_native_masked_coordinate_exchange(uint64_t* restrict output, const uint64_t* restrict sum, const uint64_t* restrict first, const uint64_t* restrict second, const uint64_t* restrict doubled, uint64_t first_mask, uint64_t second_mask, uint64_t double_mask, uint64_t sum_mask)
{
	size_t i;

	for (i = 0U; i < 4U; ++i)
	{
		output[i] = (sum[i] & sum_mask) | (first[i] & first_mask) | (second[i] & second_mask) | (doubled[i] & double_mask);
	}
}

static QSC_NO_INLINE void ecdhp256_native_add_exchange_safe(ecdhp256_native_point* output, const ecdhp256_native_point* first, const ecdhp256_native_point* second, const ecdhp256_native_point* doubled, ecdhp256_native_window_workspace* work, uint64_t scratch[15U])
{
	uint64_t finf;
	uint64_t sinf;
	uint64_t eqpt;
	uint64_t ufst;
	uint64_t usnd;
	uint64_t udbl;
	uint64_t usum;

	ecdhp256_native_add_candidate(first, second, work, scratch);
	finf = ecdhp256_native_is_zero(first->z);
	sinf = ecdhp256_native_is_zero(second->z);
	eqpt = ecdhp256_native_is_zero(work->h) & ecdhp256_native_is_zero(work->delta);
	eqpt &= (finf ^ 1U) & (sinf ^ 1U);

	ufst = UINT64_C(0) - ((finf ^ 1U) & sinf);
	usnd = UINT64_C(0) - finf;
	udbl = UINT64_C(0) - eqpt;
	usum = ~(ufst | usnd | udbl);

	ecdhp256_native_masked_coordinate_exchange(output->x, work->added.x, first->x, second->x, doubled->x, ufst, usnd, udbl, usum);
	ecdhp256_native_masked_coordinate_exchange(output->y, work->added.y, first->y, second->y, doubled->y, ufst, usnd, udbl, usum);
	ecdhp256_native_masked_coordinate_exchange(output->z, work->added.z, first->z, second->z, doubled->z, ufst, usnd, udbl, usum);
}

static void ecdhp256_native_precompute_window5(ecdhp256_native_point table[16U], ecdhp256_native_fe shared_z, ecdhp256_native_fe shared_z_squared, const ecdhp256_aff_t* point, uint64_t scratch[15U])
{
	ecdhp256_native_point multiples[16U];
	ecdhp256_native_point base;
	ecdhp256_native_fe prefix[16U];
	ecdhp256_native_fe suffix;
	ecdhp256_native_fe factor;
	ecdhp256_native_fe factor_squared;
	ecdhp256_native_fe factor_cubed;
	ecdhp256_native_window_workspace adding;
	ecdhp256_ecdh_double_workspace doubling;
	size_t i;

	ecdhp256_native_load(base.x, point->X);
	ecdhp256_native_load(base.y, point->Y);
	ecdhp256_native_copy(base.z, ECDHP256_NATIVE_ONE);
	multiples[0U] = base;
	ecdhp256_ecdh_native_double(&multiples[1U], &base, &doubling, scratch);

	for (i = 2U; i < 16U; ++i)
	{
		ecdhp256_native_add_generator(&multiples[i], &multiples[i - 1U], &base, &adding, scratch);
	}

	ecdhp256_native_copy(prefix[0U], multiples[0U].z);

	for (i = 1U; i < 16U; ++i)
	{
		ecdhp256_native_mul(prefix[i], prefix[i - 1U], multiples[i].z, scratch);
	}

	ecdhp256_native_copy(shared_z, prefix[15U]);
	ecdhp256_native_square(shared_z_squared, shared_z, scratch);
	ecdhp256_native_copy(suffix, ECDHP256_NATIVE_ONE);

	for (i = 16U; i > 0U; --i)
	{
		if (i > 1U)
		{
			ecdhp256_native_mul(factor, prefix[i - 2U], suffix, scratch);
		}
		else
		{
			ecdhp256_native_copy(factor, suffix);
		}

		ecdhp256_native_square(factor_squared, factor, scratch);
		ecdhp256_native_mul(factor_cubed, factor_squared, factor, scratch);
		ecdhp256_native_mul(table[i - 1U].x, multiples[i - 1U].x, factor_squared, scratch);
		ecdhp256_native_mul(table[i - 1U].y, multiples[i - 1U].y, factor_cubed, scratch);
		ecdhp256_native_copy(table[i - 1U].z, ECDHP256_NATIVE_ONE);
		ecdhp256_native_mul(suffix, suffix, multiples[i - 1U].z, scratch);
	}

	qsc_memutils_secure_erase(multiples, sizeof(multiples));
	qsc_memutils_secure_erase(&base, sizeof(base));
	qsc_memutils_secure_erase(prefix, sizeof(prefix));
	qsc_memutils_secure_erase(suffix, sizeof(suffix));
	qsc_memutils_secure_erase(factor, sizeof(factor));
	qsc_memutils_secure_erase(factor_squared, sizeof(factor_squared));
	qsc_memutils_secure_erase(factor_cubed, sizeof(factor_cubed));
	qsc_memutils_secure_erase(&adding, sizeof(adding));
	qsc_memutils_secure_erase(&doubling, sizeof(doubling));
}

static void ecdhp256_scalar_mult(ecdhp256_jac_t* result, const ecdhp256_aff_t* point, const uint32_t scalar[10U], const ecdhp256_field projective, const ecdhp256_field rerandomizers[4U])
{
	ecdhp256_native_point table[16U];
	/* Public-point doubles avoid a secret-dependent exceptional-path
     * recomputation in each blinded scalar window. */
	ecdhp256_native_point doubled_table[16U];
	ecdhp256_native_point selected;
	ecdhp256_native_point selected_twice;
	ecdhp256_native_point accumulator;
	ecdhp256_native_point added;
	ecdhp256_native_fe shared_z;
	ecdhp256_native_fe shared_z_squared;
	ecdhp256_native_window_workspace work;
	ecdhp256_ecdh_double_workspace doubling;
#if defined(ECDHP256_EXCHANGE_DBL5)
	ecdhp256_repeated_double_workspace double5_work;
#endif
	uint64_t scratch[15U] = { 0U };
	uint32_t digit;
	uint32_t digits[65U];
	uint32_t dsgn[65U];
	ecdhp256_field prjm;
	ecdhp256_native_fe blind_z;
	ecdhp256_native_fe blind_z2;
	ecdhp256_native_fe blind_z3;
	ecdhp256_native_fe random_z[4U];
	ecdhp256_native_fe random_z2[4U];
	ecdhp256_native_fe random_z3[4U];
	ecdhp256_field renc;
	uint32_t carry;
	uint32_t udgt;
	uint32_t index;
	uint32_t shift;
	ecdhp256_native_fe zero = { 0U };
	ecdhp256_native_fe neg_y;
	ecdhp256_native_fe neg_twice_y;
	uint32_t difference;
	uint32_t equal;
	uint32_t present;
	size_t i;
	size_t j;

	ecdhp256_native_precompute_window5(table, shared_z, shared_z_squared, point, scratch);
	ecdhp256_encode(prjm, projective);
	ecdhp256_native_load(blind_z, prjm);
	ecdhp256_native_square(blind_z2, blind_z, scratch);
	ecdhp256_native_mul(blind_z3, blind_z2, blind_z, scratch);

	/* Randomize the entire shared-Z isomorphism before processing any secret
     * window. Scaling every table point preserves its affine interpretation
     * while ensuring that leading zero digits and infinity transitions cannot
     * discard projective randomization. */
	for (i = 0U; i < 16U; ++i)
	{
		ecdhp256_native_mul(table[i].x, table[i].x, blind_z2, scratch);
		ecdhp256_native_mul(table[i].y, table[i].y, blind_z3, scratch);
	}

	ecdhp256_native_mul(shared_z, shared_z, blind_z, scratch);
	ecdhp256_native_square(shared_z_squared, shared_z, scratch);

	for (i = 0U; i < 4U; ++i)
	{
		ecdhp256_encode(renc, rerandomizers[i]);
		ecdhp256_native_load(random_z[i], renc);
		ecdhp256_native_square(random_z2[i], random_z[i], scratch);
		ecdhp256_native_mul(random_z3[i], random_z2[i], random_z[i], scratch);
	}

	/* The first eight doubles are already present in the shared-Z table.
     * Reuse the isomorphic affine representation without leaking a scalar.
     * The remaining doubles are computed once, before scalar recoding. */
	for (i = 0U; i < 8U; ++i)
	{
		doubled_table[i] = table[(2U * i) + 1U];
	}

	for (i = 8U; i < 16U; ++i)
	{
		ecdhp256_ecdh_native_double_iso(&doubled_table[i], &table[i], &doubling, shared_z_squared, scratch);
	}

	carry = 0U;

	for (i = 0U; i < 65U; ++i)
	{
		index = (uint32_t)((5U * i) / 32U);
		shift = (uint32_t)((5U * i) % 32U);
		udgt = index < 10U ? scalar[index] >> shift : 0U;

		if (shift > 27U && index < 9U)
		{
			udgt |= scalar[index + 1U] << (32U - shift);
		}

		udgt = (udgt & 31U) + carry;
		carry = (udgt + 15U) >> 5U;
		dsgn[i] = carry;
		digit = udgt - (carry << 5U);
		digits[i] = (digit ^ (0U - carry)) + carry;
	}

	qsc_memutils_clear(&selected, sizeof(selected));
	qsc_memutils_clear(&selected_twice, sizeof(selected_twice));
	qsc_memutils_clear(&accumulator, sizeof(accumulator));
	qsc_memutils_clear(&work, sizeof(work));
	qsc_memutils_clear(&doubling, sizeof(doubling));
	ecdhp256_native_copy(accumulator.y, ECDHP256_NATIVE_ONE);

	for (i = 65U; i > 0U; --i)
	{
		/* The leading five-bit window needs no preceding doublings.
         * The window index is public; the digit remains masked and secret. */
		if (i != 65U)
		{
#if defined(ECDHP256_EXCHANGE_DBL5)
			ecdhp256_double_iso5(&accumulator, &accumulator, shared_z_squared, scratch, &double5_work);
#else
			ecdhp256_native_square(doubling.delta, accumulator.z, scratch);
			ecdhp256_native_mul(doubling.delta, doubling.delta, shared_z_squared, scratch);

			for (j = 0U; j < 5U; ++j)
			{
				ecdhp256_ecdh_native_double_iso_cached(&accumulator, &accumulator, &doubling, scratch, j != 4U);
			}
#endif
		}

		digit = digits[i - 1U];
		present = ((digit | (0U - digit)) >> 31U);

		/* Volatile mask materialization prevents the optimizer from
         * rewriting the secret digit lookup as a branch cascade. */
		{
			volatile uint64_t opms;
			uint64_t mask;
			size_t word;

			opms = UINT64_C(0) - (uint64_t)present;
			mask = opms;

			for (word = 0U; word < 4U; ++word)
			{
				selected.x[word] = 0U;
				selected.y[word] = 0U;
				selected.z[word] = ECDHP256_NATIVE_ONE[word] & mask;
				selected_twice.x[word] = 0U;
				selected_twice.y[word] = 0U;
				selected_twice.z[word] = 0U;
			}

			for (j = 0U; j < 16U; ++j)
			{
				difference = digit ^ (uint32_t)(j + 1U);
				equal = 1U ^ ((difference | (0U - difference)) >> 31U);
				opms = UINT64_C(0) - (uint64_t)equal;
				mask = opms;

				for (word = 0U; word < 4U; ++word)
				{
					selected.x[word] |= table[j].x[word] & mask;
					selected.y[word] |= table[j].y[word] & mask;
					selected_twice.x[word] |= doubled_table[j].x[word] & mask;
					selected_twice.y[word] |= doubled_table[j].y[word] & mask;
					selected_twice.z[word] |= doubled_table[j].z[word] & mask;
				}
			}
		}

		/* Initial accumulator selection is public-position control flow;
         * no secret-window digit is ever used as a branch condition. */
		ecdhp256_native_sub(neg_y, zero, selected.y, scratch);
		qsc_intutils_cmov((uint8_t*)selected.y, (const uint8_t*)neg_y, sizeof(neg_y), (uint8_t)dsgn[i - 1U]);
		ecdhp256_native_sub(neg_twice_y, zero, selected_twice.y, scratch);
		qsc_intutils_cmov((uint8_t*)selected_twice.y, (const uint8_t*)neg_twice_y, sizeof(neg_twice_y), (uint8_t)dsgn[i - 1U]);

		if (i == 65U)
		{
			accumulator = selected;
		}
		else
		{
			ecdhp256_native_add_exchange_safe(&added, &accumulator, &selected, &selected_twice, &work, scratch);
			accumulator = added;
		}

		/* Fixed public positions, independent of scalar digits and point
         * equality. Preserve the isomorphic representation as in the reference implementation. */
		if (i > 61U)
		{
			size_t ridx;

			ridx = 65U - i;
			ecdhp256_native_mul(accumulator.x, accumulator.x, random_z2[ridx], scratch);
			ecdhp256_native_mul(accumulator.y, accumulator.y, random_z3[ridx], scratch);
			ecdhp256_native_mul(accumulator.z, accumulator.z, random_z[ridx], scratch);
		}
	}

	ecdhp256_native_store(result->X, accumulator.x);
	ecdhp256_native_store(result->Y, accumulator.y);
	ecdhp256_native_mul(accumulator.z, accumulator.z, shared_z, scratch);
	ecdhp256_native_store(result->Z, accumulator.z);
	qsc_memutils_secure_erase(prjm, sizeof(prjm));
	qsc_memutils_secure_erase(blind_z, sizeof(blind_z));
	qsc_memutils_secure_erase(blind_z2, sizeof(blind_z2));
	qsc_memutils_secure_erase(blind_z3, sizeof(blind_z3));
	qsc_memutils_secure_erase(random_z, sizeof(random_z));
	qsc_memutils_secure_erase(random_z2, sizeof(random_z2));
	qsc_memutils_secure_erase(random_z3, sizeof(random_z3));
	qsc_memutils_secure_erase(renc, sizeof(renc));
	qsc_memutils_secure_erase(neg_y, sizeof(neg_y));
	qsc_memutils_secure_erase(neg_twice_y, sizeof(neg_twice_y));
	qsc_memutils_secure_erase(digits, sizeof(digits));
	qsc_memutils_secure_erase(dsgn, sizeof(dsgn));
	qsc_memutils_secure_erase(shared_z, sizeof(shared_z));
	qsc_memutils_secure_erase(shared_z_squared, sizeof(shared_z_squared));
	qsc_memutils_secure_erase(table, sizeof(table));
	qsc_memutils_secure_erase(doubled_table, sizeof(doubled_table));
	qsc_memutils_secure_erase(&selected, sizeof(selected));
	qsc_memutils_secure_erase(&selected_twice, sizeof(selected_twice));
	qsc_memutils_secure_erase(&accumulator, sizeof(accumulator));
	qsc_memutils_secure_erase(&added, sizeof(added));
	qsc_memutils_secure_erase(&work, sizeof(work));
	qsc_memutils_secure_erase(&doubling, sizeof(doubling));
#if defined(ECDHP256_EXCHANGE_DBL5)
	qsc_memutils_secure_erase(&double5_work, sizeof(double5_work));
#endif
	qsc_memutils_secure_erase(scratch, sizeof(scratch));
}

/*! \def QSC_ECDH_P256_GENERATOR_W6
 * \brief Optional native P-256 generator multiplication using an immutable width-6 table.
 * \details Enabled by default; define QSC_ECDH_P256_GENERATOR_COMPACT to select the compact 320-bit blinded-scalar
 * implementation. Unsupported native targets retain the established portable path.
 */
/*! \def QSC_ECDH_P256_GENERATOR_W6_PREDBL
 * \brief Optional precomputed doubles for the final twelve W6 generator windows.
 * \details Requires QSC_ECDH_P256_GENERATOR_W6. Uses additional read-only
 * table storage instead of runtime doubling for masked exceptional-case handling.
 */
#if defined(QSC_ECDH_P256_GENERATOR_W6) && !defined(QSC_ECDH_P256_GENERATOR_COMPACT)

#if defined(__x86_64__)

static void ecdhp256_select_sse2(uint64_t x[4U], uint64_t y[4U], const uint64_t row[32U][2U][4U], uint32_t magnitude)
{
	__m128i x0;
	__m128i x1;
	__m128i y0;
	__m128i y1;
	__m128i digit;
	__m128i mask;
	size_t j;

	x0 = _mm_setzero_si128();
	x1 = _mm_setzero_si128();
	y0 = _mm_setzero_si128();
	y1 = _mm_setzero_si128();
	digit = _mm_set1_epi32((int32_t)magnitude);

	for (j = 0U; j < 32U; ++j)
	{
		mask = _mm_cmpeq_epi32(digit, _mm_set1_epi32((int32_t)(j + 1U)));
		x0 = _mm_or_si128(x0, _mm_and_si128(mask, _mm_loadu_si128((const __m128i*)(const void*)&row[j][0U][0U])));
		x1 = _mm_or_si128(x1, _mm_and_si128(mask, _mm_loadu_si128((const __m128i*)(const void*)&row[j][0U][2U])));
		y0 = _mm_or_si128(y0, _mm_and_si128(mask, _mm_loadu_si128((const __m128i*)(const void*)&row[j][1U][0U])));
		y1 = _mm_or_si128(y1, _mm_and_si128(mask, _mm_loadu_si128((const __m128i*)(const void*)&row[j][1U][2U])));
	}

	_mm_storeu_si128((__m128i*)(void*)&x[0U], x0);
	_mm_storeu_si128((__m128i*)(void*)&x[2U], x1);
	_mm_storeu_si128((__m128i*)(void*)&y[0U], y0);
	_mm_storeu_si128((__m128i*)(void*)&y[2U], y1);
}
#endif

static void ecdhp256_scalar_mult_fixed_generator(ecdhp256_jac_t* result, const uint32_t scalar[10U], const ecdhp256_field projective, const ecdhp256_field rerandomizers[4U])
{
	ecdhp256_native_point accumulator;
	ecdhp256_native_point selected;
	ecdhp256_native_point selected_twice;
	ecdhp256_native_point added;
	ecdhp256_native_window_workspace work;
	ecdhp256_ecdh_double_workspace doubling;
	uint64_t scratch[15U] = { 0U };
	ecdhp256_native_fe neg_y;
#if defined(QSC_ECDH_P256_GENERATOR_W6_PREDBL)
	ecdhp256_native_fe neg_twice_y;
#endif
	ecdhp256_native_fe first_z;
	ecdhp256_native_fe first_z2;
	ecdhp256_native_fe first_z3;
	ecdhp256_native_fe random_z[4U];
	ecdhp256_native_fe random_z2[4U];
	ecdhp256_native_fe random_z3[4U];
	ecdhp256_native_fe zero = { 0U };
	ecdhp256_field encoded;
#if !defined(__x86_64__)
	uint64_t opaque;
#endif
#if !defined(__x86_64__)
	uint64_t mask;
#endif
	uint64_t prms;
	uint64_t words;
	uint32_t raw;
	uint32_t inverted;
	uint32_t sign;
	uint32_t signmask;
	uint32_t canonical;
	uint32_t digit;
#if !defined(__x86_64__)
	uint32_t difference;
#endif
#if !defined(__x86_64__)
	uint32_t equal;
#endif
	uint32_t bitpos;
	uint32_t wordindex;
	uint32_t shift;
	size_t i;
#if !defined(__x86_64__)
	size_t j;
#endif
	size_t m;

	/* Fresh projective and accumulator masks, independent of table contents. */
	ecdhp256_encode(encoded, projective);
	ecdhp256_native_load(first_z, encoded);
	ecdhp256_native_square(first_z2, first_z, scratch);
	ecdhp256_native_mul(first_z3, first_z2, first_z, scratch);

	for (i = 0U; i < 4U; ++i)
	{
		ecdhp256_encode(encoded, rerandomizers[i]);
		ecdhp256_native_load(random_z[i], encoded);
		ecdhp256_native_square(random_z2[i], random_z[i], scratch);
		ecdhp256_native_mul(random_z3[i], random_z2[i], random_z[i], scratch);
	}

	qsc_memutils_clear(&accumulator, sizeof(accumulator));
	qsc_memutils_clear(&selected, sizeof(selected));
	qsc_memutils_clear(&selected_twice, sizeof(selected_twice));
	qsc_memutils_clear(&added, sizeof(added));
	qsc_memutils_clear(&work, sizeof(work));
	qsc_memutils_clear(&doubling, sizeof(doubling));

	for (i = 0U; i < ECDHP256_GENERATOR_W6_WINDOWS; ++i)
	{
		/* W+1 overlapping digits exactly reproduce Booth recoding. */
		if (i == 0U)
		{
			raw = (scalar[0U] & 63U) << 1U;
		}
		else
		{
			bitpos = (uint32_t)(6U * i - 1U);
			wordindex = bitpos / 32U;
			shift = bitpos % 32U;
			words = (uint64_t)scalar[wordindex] >> shift;

			if (wordindex < 9U)
			{
				words |= (uint64_t)scalar[wordindex + 1U] << (32U - shift);
			}

			raw = (uint32_t)words & 127U;
		}

		sign = raw >> 6U;
		inverted = 127U - raw;
		signmask = 0U - sign;
		canonical = raw ^ ((raw ^ inverted) & signmask);
		digit = (canonical >> 1U) + (canonical & 1U);
		prms = UINT64_C(0) - (uint64_t)((digit | (0U - digit)) >> 31U);

		for (m = 0U; m < 4U; ++m)
		{
			selected.x[m] = 0U;
			selected.y[m] = 0U;
			selected.z[m] = ECDHP256_NATIVE_ONE[m] & prms;
#if defined(QSC_ECDH_P256_GENERATOR_W6_PREDBL)
			selected_twice.x[m] = 0U;
			selected_twice.y[m] = 0U;
			selected_twice.z[m] = ECDHP256_NATIVE_ONE[m] & prms;
#endif
		}

#if defined(__x86_64__)
		ecdhp256_select_sse2(selected.x, selected.y, ECDHP256_GENERATOR_W6_MONT[i], digit);
#if defined(QSC_ECDH_P256_GENERATOR_W6_PREDBL)
		if (i >= ECDHP256_GENERATOR_W6_PROTECTED_START)
		{
			ecdhp256_select_sse2(selected_twice.x, selected_twice.y, ECDHP256_GENERATOR_W6_DOUBLE_MONT[i - ECDHP256_GENERATOR_W6_PROTECTED_START], digit);
		}
#endif
#else
		/* Fixed 32-entry scan; only public window i determines table location. */
		for (j = 0U; j < ECDHP256_GENERATOR_W6_MAGNITUDES; ++j)
		{
			difference = digit ^ (uint32_t)(j + 1U);
			equal = 1U ^ ((difference | (0U - difference)) >> 31U);
			opaque = UINT64_C(0) - (uint64_t)equal;
			{
				volatile uint64_t ptms;

				ptms = opaque;
				mask = ptms;
			}

			for (m = 0U; m < 4U; ++m)
			{
				selected.x[m] |= ECDHP256_GENERATOR_W6_MONT[i][j][0U][m] & mask;
				selected.y[m] |= ECDHP256_GENERATOR_W6_MONT[i][j][1U][m] & mask;
#if defined(QSC_ECDH_P256_GENERATOR_W6_PREDBL)
				if (i >= ECDHP256_GENERATOR_W6_PROTECTED_START)
				{
					selected_twice.x[m] |= ECDHP256_GENERATOR_W6_DOUBLE_MONT[i - ECDHP256_GENERATOR_W6_PROTECTED_START][j][0U][m] & mask;
					selected_twice.y[m] |= ECDHP256_GENERATOR_W6_DOUBLE_MONT[i - ECDHP256_GENERATOR_W6_PROTECTED_START][j][1U][m] & mask;
				}
#endif
			}
		}
#endif

		ecdhp256_native_sub(neg_y, zero, selected.y, scratch);
		qsc_intutils_cmov((uint8_t*)selected.y, (const uint8_t*)neg_y, sizeof(neg_y), (uint8_t)sign);
#if defined(QSC_ECDH_P256_GENERATOR_W6_PREDBL)
		if (i >= ECDHP256_GENERATOR_W6_PROTECTED_START)
		{
			ecdhp256_native_sub(neg_twice_y, zero, selected_twice.y, scratch);
			qsc_intutils_cmov((uint8_t*)selected_twice.y, (const uint8_t*)neg_twice_y, sizeof(neg_twice_y), (uint8_t)sign);
		}
#endif

		if (i == 0U)
		{
			accumulator = selected;
			ecdhp256_native_mul(accumulator.x, accumulator.x, first_z2, scratch);
			ecdhp256_native_mul(accumulator.y, accumulator.y, first_z3, scratch);
			ecdhp256_native_mul(accumulator.z, accumulator.z, first_z, scratch);
		}
		else
		{
			if (i < ECDHP256_GENERATOR_W6_PROTECTED_START)
			{
				/* The public radix bound excludes exceptional equality here. */
				ecdhp256_native_add_generator_early(&added, &accumulator, &selected, &work, scratch);
			}
			else
			{
				/* Late windows can wrap the group order. The selection must
				 * include a doubling candidate without secret-dependent flow. */
#if !defined(QSC_ECDH_P256_GENERATOR_W6_PREDBL)
				ecdhp256_ecdh_native_double(&selected_twice, &selected, &doubling, scratch);
#endif
				ecdhp256_native_add_generator_safe(&added, &accumulator, &selected, &selected_twice, &work, scratch);
			}

			accumulator = added;
		}

		/* The positions are public and fixed, independent of secret digits. */
		if (i < 4U)
		{
			ecdhp256_native_mul(accumulator.x, accumulator.x, random_z2[i], scratch);
			ecdhp256_native_mul(accumulator.y, accumulator.y, random_z3[i], scratch);
			ecdhp256_native_mul(accumulator.z, accumulator.z, random_z[i], scratch);
		}
	}

	ecdhp256_native_store(result->X, accumulator.x);
	ecdhp256_native_store(result->Y, accumulator.y);
	ecdhp256_native_store(result->Z, accumulator.z);

	qsc_memutils_secure_erase(&accumulator, sizeof(accumulator));
	qsc_memutils_secure_erase(&selected, sizeof(selected));
	qsc_memutils_secure_erase(&selected_twice, sizeof(selected_twice));
	qsc_memutils_secure_erase(&added, sizeof(added));
	qsc_memutils_secure_erase(&work, sizeof(work));
	qsc_memutils_secure_erase(&doubling, sizeof(doubling));
	qsc_memutils_secure_erase(scratch, sizeof(scratch));
	qsc_memutils_secure_erase(neg_y, sizeof(neg_y));
#if defined(QSC_ECDH_P256_GENERATOR_W6_PREDBL)
	qsc_memutils_secure_erase(neg_twice_y, sizeof(neg_twice_y));
#endif
	qsc_memutils_secure_erase(first_z, sizeof(first_z));
	qsc_memutils_secure_erase(first_z2, sizeof(first_z2));
	qsc_memutils_secure_erase(first_z3, sizeof(first_z3));
	qsc_memutils_secure_erase(random_z, sizeof(random_z));
	qsc_memutils_secure_erase(random_z2, sizeof(random_z2));
	qsc_memutils_secure_erase(random_z3, sizeof(random_z3));
	qsc_memutils_secure_erase(encoded, sizeof(encoded));
	qsc_memutils_secure_erase(&raw, sizeof(raw));
	qsc_memutils_secure_erase(&inverted, sizeof(inverted));
	qsc_memutils_secure_erase(&sign, sizeof(sign));
	qsc_memutils_secure_erase(&canonical, sizeof(canonical));
	qsc_memutils_secure_erase(&digit, sizeof(digit));
	qsc_memutils_secure_erase(&words, sizeof(words));
}
#endif /* QSC_ECDH_P256_GENERATOR_W6 */

#else

static void ecdhp256_ladder_cswap(ecdhp256_jac_t* first, ecdhp256_jac_t* second, uint32_t select)
{
	uint32_t mask;
	uint32_t t;
	size_t i;

	mask = (uint32_t)(0U - select);

	for (i = 0U; i < 8U; ++i)
	{
		t = (first->X[i] ^ second->X[i]) & mask;
		first->X[i] ^= t;
		second->X[i] ^= t;
		t = (first->Y[i] ^ second->Y[i]) & mask;
		first->Y[i] ^= t;
		second->Y[i] ^= t;
		t = (first->Z[i] ^ second->Z[i]) & mask;
		first->Z[i] ^= t;
		second->Z[i] ^= t;
	}
}

static void ecdhp256_scalar_mult(ecdhp256_jac_t* R, const ecdhp256_aff_t* P, const uint32_t k[10U], const ecdhp256_field projective, const ecdhp256_field rerandomizers[4U])
{
	ecdhp256_jac_t r0;
	ecdhp256_jac_t r1;
	ecdhp256_jac_t added;
	ecdhp256_jac_t doubled;
	uint32_t swap;
	uint32_t bit;
	ecdhp256_field z2;
	ecdhp256_field z3;
	ecdhp256_field mask2;
	ecdhp256_field mask3;
	size_t ridx;
	int32_t i;

	ecdhp256_set_infinity(&r0);
	ecdhp256_aff_to_jac(&r1, P);
	ecdhp256_fe_sqr(z2, projective);
	ecdhp256_fe_mul(z3, z2, projective);
	ecdhp256_fe_mul(r1.X, r1.X, z2);
	ecdhp256_fe_mul(r1.Y, r1.Y, z3);
	ecdhp256_field_copy(r1.Z, projective);
	swap = 0U;

	for (i = 319; i >= 0; --i)
	{
		bit = (k[(size_t)i / 32U] >> ((uint32_t)i % 32U)) & 1U;
		swap ^= bit;
		ecdhp256_ladder_cswap(&r0, &r1, swap);
		swap = bit;

		ecdhp256_add(&added, &r0, &r1);
		ecdhp256_dbl(&doubled, &r0);
		r1 = added;
		r0 = doubled;

		if (i >= 316)
		{
			ridx = 319U - (size_t)i;
			ecdhp256_fe_sqr(mask2, rerandomizers[ridx]);
			ecdhp256_fe_mul(mask3, mask2, rerandomizers[ridx]);
			ecdhp256_fe_mul(r0.X, r0.X, mask2);
			ecdhp256_fe_mul(r0.Y, r0.Y, mask3);
			ecdhp256_fe_mul(r0.Z, r0.Z, rerandomizers[ridx]);
			ecdhp256_fe_mul(r1.X, r1.X, mask2);
			ecdhp256_fe_mul(r1.Y, r1.Y, mask3);
			ecdhp256_fe_mul(r1.Z, r1.Z, rerandomizers[ridx]);
		}
	}

	ecdhp256_ladder_cswap(&r0, &r1, swap);
	*R = r0;
	qsc_memutils_secure_erase(z2, sizeof(z2));
	qsc_memutils_secure_erase(z3, sizeof(z3));
	qsc_memutils_secure_erase(mask2, sizeof(mask2));
	qsc_memutils_secure_erase(mask3, sizeof(mask3));
	qsc_memutils_secure_erase(&r0, sizeof(r0));
	qsc_memutils_secure_erase(&r1, sizeof(r1));
	qsc_memutils_secure_erase(&added, sizeof(added));
	qsc_memutils_secure_erase(&doubled, sizeof(doubled));
}

#endif /* QSC_ECDH_P256_NATIVE */

static bool ecdhp256_jac_to_aff(ecdhp256_aff_t* R, const ecdhp256_jac_t* P)
{
#if defined(QSC_ECDH_P256_NATIVE)
	ecdhp256_native_fe x;
	ecdhp256_native_fe y;
	ecdhp256_native_fe z;
	ecdhp256_native_fe inverse2;
	ecdhp256_native_fe inverse3;
	uint64_t scratch[15U] = { 0U };
	uint32_t finite;

	finite = ecdhp256_is_infinity(P) ^ 1U;
	ecdhp256_native_load(x, P->X);
	ecdhp256_native_load(y, P->Y);
	ecdhp256_native_load(z, P->Z);
	ecdhp256_native_inverse_square(inverse2, z, scratch);
	ecdhp256_native_square(inverse3, inverse2, scratch);
	ecdhp256_native_mul(inverse3, inverse3, z, scratch);
	ecdhp256_native_mul(x, x, inverse2, scratch);
	ecdhp256_native_mul(y, y, inverse3, scratch);
	ecdhp256_native_store(R->X, x);
	ecdhp256_native_store(R->Y, y);
	qsc_memutils_secure_erase(x, sizeof(x));
	qsc_memutils_secure_erase(y, sizeof(y));
	qsc_memutils_secure_erase(z, sizeof(z));
	qsc_memutils_secure_erase(inverse2, sizeof(inverse2));
	qsc_memutils_secure_erase(inverse3, sizeof(inverse3));
	qsc_memutils_secure_erase(scratch, sizeof(scratch));

	return finite != 0U;
#else

	ecdhp256_field zinv;
	ecdhp256_field zinv2;
	ecdhp256_field zinv3;
	uint32_t finite;

	finite = ecdhp256_is_infinity(P) ^ 1U;
	ecdhp256_fe_inv(zinv, P->Z);
	ecdhp256_fe_sqr(zinv2, zinv);
	ecdhp256_fe_mul(zinv3, zinv2, zinv);
	ecdhp256_fe_mul(R->X, P->X, zinv2);
	ecdhp256_fe_mul(R->Y, P->Y, zinv3);

	qsc_memutils_secure_erase(zinv, sizeof(zinv));
	qsc_memutils_secure_erase(zinv2, sizeof(zinv2));
	qsc_memutils_secure_erase(zinv3, sizeof(zinv3));

	return (finite != 0U);
#endif
}

static bool ecdhp256_point_is_on_curve(const ecdhp256_aff_t* Q)
{
	/* verify that a public key point lies on the curve.
     * checks the Weierstrass equation:  Y^2 = X^3 - 3X + b  (mod p)
     * and that the point is not the identity. */
	ecdhp256_field y2, x3, ax, rhs;

	/* y^2 mod p */
	ecdhp256_fe_sqr(y2, Q->Y);

	/* x^3 mod p */
	ecdhp256_fe_sqr(x3, Q->X);
	ecdhp256_fe_mul(x3, x3, Q->X);

	/* -3*x mod p (a = -3) */
	ecdhp256_fe_mul_small(ax, Q->X, 3U);
	ecdhp256_fe_sub(rhs, x3, ax);

	/* rhs = x^3 - 3x + b */
#if defined(QSC_ECDH_P256_NATIVE)
	{
		ecdhp256_field bm;

		ecdhp256_encode(bm, ECDHP256_B);
		ecdhp256_fe_add(rhs, rhs, bm);
		qsc_memutils_secure_erase(bm, sizeof(bm));
	}
#else
	ecdhp256_fe_add(rhs, rhs, ECDHP256_B);
#endif

	return (ecdhp256_field_cmp(y2, rhs) == 0);
}

static bool ecdhp256_prepare_peer_point(ecdhp256_aff_t* Q)
{
#if defined(QSC_ECDH_P256_NATIVE)
	ecdhp256_encode(Q->X, Q->X);
	ecdhp256_encode(Q->Y, Q->Y);
#endif
	return ecdhp256_point_is_on_curve(Q);
}

static void ecdhp256_sc_from_bytes(uint32_t r[8U], const uint8_t s[32U])
{
	int32_t i;
	int32_t j;

	for (i = 0, j = 28; i < 8; ++i, j -= 4)
	{
		r[i] = ((uint32_t)s[j] << 24) | ((uint32_t)s[j + 1U] << 16) | ((uint32_t)s[j + 2U] << 8) | ((uint32_t)s[j + 3U]);
	}
}

static bool ecdhp256_private_scalar_from_seed(uint8_t scalar[32U], const uint8_t seed[32U])
{
	uint8_t hash[32U] = { 0U };
	uint32_t d[8U] = { 0U };
	bool res;

	qsc_sha256_compute(hash, seed, QSC_ECDHP256_SEED_SIZE);
	ecdhp256_sc_from_bytes_reduce(d, hash);

	res = (ecdhp256_field_is_zero(d) == 0U);

	if (res == true)
	{
		ecdhp256_field_to_bytes(scalar, d);
	}
	else
	{
		qsc_memutils_clear(scalar, QSC_ECDHP256_PRIVATEKEY_SIZE);
	}

	qsc_memutils_secure_erase(hash, sizeof(hash));
	qsc_memutils_secure_erase(d, sizeof(d));

	return res;
}

int32_t qsc_ecdhp256_publickey_from_privatekey(uint8_t* publickey, const uint8_t* privatekey)
{

	ecdhp256_aff_t G;
	ecdhp256_aff_t Q;
	ecdhp256_jac_t R;
	uint32_t d[8U] = { 0U };
	uint32_t blinded[10U] = { 0U };
	ecdhp256_field projective = { 0U };
	ecdhp256_field rerandomizers[4U] = {{ 0U }};
	int32_t ret;

	ret = -1;

	if (publickey != NULL)
	{
		qsc_memutils_clear(publickey, 64U);
	}

	if (publickey != NULL && privatekey != NULL)
	{
		qsc_memutils_clear(publickey, QSC_ECDHP256_PUBLICKEY_SIZE);
		ecdhp256_sc_from_bytes(d, privatekey);

		if (ecdhp256_field_is_zero(d) != 0U)
		{
			ret = -2;
		}
		else if (ecdhp256_private_scalar_ge_order(d) != 0U)
		{
			ret = -3;
		}
		else if (ecdhp256_prepare_blinding(blinded, projective, rerandomizers, d) == false)
		{
			ret = -9;
		}
		else
		{
			ecdhp256_field_copy(G.X, ECDHP256_GX);
			ecdhp256_field_copy(G.Y, ECDHP256_GY);
#if defined(QSC_ECDH_P256_NATIVE)
			ecdhp256_encode(G.X, G.X);
			ecdhp256_encode(G.Y, G.Y);
#endif
#if defined(QSC_ECDH_P256_NATIVE) && defined(QSC_ECDH_P256_GENERATOR_W6) && !defined(QSC_ECDH_P256_GENERATOR_COMPACT)
			ecdhp256_scalar_mult_fixed_generator(&R, blinded, projective, rerandomizers);
#else
			ecdhp256_scalar_mult(&R, &G, blinded, projective, rerandomizers);
#endif

			if (ecdhp256_is_infinity(&R) != 0U)
			{
				ret = -4;
			}
			else if (ecdhp256_jac_to_aff(&Q, &R) != true)
			{
				ret = -5;
			}
			else
			{
#if defined(QSC_ECDH_P256_NATIVE)
				ecdhp256_decode(Q.X, Q.X);
				ecdhp256_decode(Q.Y, Q.Y);
#endif
				ecdhp256_field_to_bytes(publickey, Q.X);
				ecdhp256_field_to_bytes(publickey + 32U, Q.Y);
				ret = 0;
			}
		}
	}

	qsc_memutils_secure_erase(blinded, sizeof(blinded));
	qsc_memutils_secure_erase(projective, sizeof(projective));
	qsc_memutils_secure_erase(rerandomizers, sizeof(rerandomizers));
	qsc_memutils_secure_erase(d, sizeof(d));
	qsc_memutils_secure_erase(&Q, sizeof(Q));
	qsc_memutils_secure_erase(&R, sizeof(R));
	qsc_memutils_secure_erase(&G, sizeof(G));

	return ret;
}

int32_t qsc_ecdhp256_scalar_multiply(uint8_t* secret, const uint8_t* privatekey, const uint8_t* publickey)
{

	uint32_t d[8U] = { 0U };
	uint32_t blinded[10U] = { 0U };
	ecdhp256_field projective = { 0U };
	ecdhp256_field rerandomizers[4U] = {{ 0U }};
	ecdhp256_aff_t Q;
	ecdhp256_aff_t S;
	ecdhp256_jac_t J;
	int32_t ret;

	ret = -1;

	if (secret != NULL)
	{
		qsc_memutils_clear(secret, 32U);
	}

	if (secret != NULL && privatekey != NULL && publickey != NULL)
	{
		qsc_memutils_clear(secret, QSC_ECDHP256_SHAREDSECRET_SIZE);
		ecdhp256_sc_from_bytes(d, privatekey);

		if (ecdhp256_field_is_zero(d) != 0U)
		{
			ret = -2;
		}
		else if (ecdhp256_private_scalar_ge_order(d) != 0U)
		{
			ret = -3;
		}
		else
		{
			ecdhp256_field_from_bytes(Q.X, publickey);
			ecdhp256_field_from_bytes(Q.Y, publickey + 32U);

			if (ecdhp256_field_cmp(Q.X, ECDHP256_P) >= 0 || ecdhp256_field_cmp(Q.Y, ECDHP256_P) >= 0)
			{
				ret = -4;
			}
			else if (ecdhp256_prepare_peer_point(&Q) == false)
			{
				ret = -5;
			}
			else if (ecdhp256_prepare_blinding(blinded, projective, rerandomizers, d) == false)
			{
				ret = -9;
			}
			else
			{
				ecdhp256_scalar_mult(&J, &Q, blinded, projective, rerandomizers);

				if (ecdhp256_is_infinity(&J) != 0U)
				{
					ret = -6;
				}
#if defined(QSC_ECDH_P256_NATIVE)
				else
				{
					ecdhp256_native_affine_x(S.X, &J);

					ecdhp256_field_to_bytes(secret, S.X);
					ret = 0;
				}
#else
				else if (ecdhp256_jac_to_aff(&S, &J) != true)
				{
					ret = -7;
				}
				else
				{
#if defined(QSC_ECDH_P256_NATIVE)
					ecdhp256_decode(S.X, S.X);
#endif
					ecdhp256_field_to_bytes(secret, S.X);
					ret = 0;
				}
#endif
			}
		}
	}

	qsc_memutils_secure_erase(blinded, sizeof(blinded));
	qsc_memutils_secure_erase(projective, sizeof(projective));
	qsc_memutils_secure_erase(rerandomizers, sizeof(rerandomizers));
	qsc_memutils_secure_erase(d, sizeof(d));
	qsc_memutils_secure_erase(&Q, sizeof(Q));
	qsc_memutils_secure_erase(&S, sizeof(S));
	qsc_memutils_secure_erase(&J, sizeof(J));

	return ret;
}

bool qsc_ecdhp256_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed)
{
	bool ret;

	ret = false;

	if (publickey != NULL)
	{
		qsc_memutils_clear(publickey, 64U);
	}

	if (privatekey != NULL)
	{
		qsc_memutils_clear(privatekey, 32U);
	}

	if (publickey != NULL && privatekey != NULL && seed != NULL)
	{
		if (ecdhp256_private_scalar_from_seed(privatekey, seed) == true)
		{
			ret = (qsc_ecdhp256_publickey_from_privatekey(publickey, privatekey) == 0);
		}

		if (ret == false)
		{
			qsc_memutils_clear(publickey, 64U);
			qsc_memutils_secure_erase(privatekey, 32U);
		}
	}

	return ret;
}

bool qsc_ecdhp256_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	uint8_t seed[32U] = { 0U };
	bool ret;

	ret = false;

	if (publickey != NULL)
	{
		qsc_memutils_clear(publickey, 64U);
	}

	if (privatekey != NULL)
	{
		qsc_memutils_clear(privatekey, 32U);
	}

	if (publickey != NULL && privatekey != NULL && rng_generate != NULL)
	{
		if (rng_generate(seed, sizeof(seed)) == true)
		{
			ret = qsc_ecdhp256_generate_seeded_keypair(publickey, privatekey, seed);
		}
	}

	qsc_memutils_secure_erase(seed, sizeof(seed));

	return ret;
}

bool qsc_ecdhp256_key_exchange(uint8_t* secret, const uint8_t* publickey, const uint8_t* privatekey)
{
	uint8_t nonzero;
	size_t i;
	bool ret;

	ret = (qsc_ecdhp256_scalar_multiply(secret, privatekey, publickey) == 0);
	nonzero = 0U;

	if (ret == true)
	{
		for (i = 0U; i < 32U; ++i)
		{
			nonzero |= secret[i];
		}

		ret = (nonzero != 0U);
	}

	return ret;
}

void qsc_p256_public_from_private(uint8_t* publickey, const uint8_t* privatekey)
{
	(void)qsc_ecdhp256_publickey_from_privatekey(publickey, privatekey);
}

void qsc_p256_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed)
{
	(void)qsc_ecdhp256_generate_seeded_keypair(publickey, privatekey, seed);
}

void qsc_p256_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	(void)qsc_ecdhp256_generate_keypair(publickey, privatekey, rng_generate);
}

bool qsc_p256_key_exchange(uint8_t* secret, const uint8_t* publickey, const uint8_t* privatekey)
{
	return qsc_ecdhp256_key_exchange(secret, publickey, privatekey);
}

int32_t qsc_crypto_scalarmult_secp256r1_base(uint8_t* publickey, const uint8_t* privatekey)
{
	return qsc_ecdhp256_publickey_from_privatekey(publickey, privatekey);
}

int32_t qsc_crypto_scalarmult_secp256r1(uint8_t* secret, const uint8_t* privatekey, const uint8_t* publickey)
{
	return qsc_ecdhp256_scalar_multiply(secret, privatekey, publickey);
}

/* \endcond NO_DOCUMENT */

