#include "ecdsap521.h"
#include "async.h"
#include "memutils.h"
#include "intrinsics.h"
#include "csp.h"
#include "sha2.h"
#include "intutils.h"
#include <stdint.h>
#include <stddef.h>
#if !defined(QSC_ECDSAP521_FORCE_PORTABLE) && defined(_MSC_VER) && defined(_M_X64) && !defined(_M_ARM64EC)
#	include <intrin.h>
#endif
#if !defined(QSC_ECDSAP521_FORCE_PORTABLE) && (defined(__x86_64__) || defined(__amd64__)) && !defined(_MSC_VER) && !defined(_M_ARM64EC)
#	include <x86intrin.h>
#endif

/* \cond DOXYGEN_NO_DOCUMENT */

/*! \def ECDSAP521_RESTRICT
 * \brief Compiler spelling of the private nonaliasing pointer contract.
 */
#if defined(_MSC_VER) || defined(__cplusplus)
#	define ECDSAP521_RESTRICT __restrict
#else
#	define ECDSAP521_RESTRICT restrict
#endif

/*! \def ECDSAP521_LIMBS
 * \brief Number of 64-bit words in a P-521 field element.
 */
#define ECDSAP521_LIMBS 9U

/*! \def ECDSAP521_WIDE_LIMBS
 * \brief Number of 64-bit words in a wide P-521 product.
 */
#define ECDSAP521_WIDE_LIMBS 18U

/*! \brief Nine-limb native field representation of a P-521 residue.
 * \details Each caller owns its instance; the ninth limb contains at most nine
 * significant bits for canonical field values. No heap ownership.
 */
typedef struct
{
	uint64_t limbs[ECDSAP521_LIMBS]; /*!< Little-endian native 64-bit limbs. */
} ecdsap521_field;

static inline ecdsap521_field ecdsap521_one(void)
{
	ecdsap521_field result = {{UINT64_C(1)}};

	return result;
}

static inline uint64_t ecdsap521_word_add(uint64_t x, uint64_t y, uint64_t* carry)
{
	uint64_t cb;
	uint64_t z;
	uint64_t c1;

	cb = *carry & 1U;
	z = x + y;
	c1 = (uint64_t)(z < x);
	z += cb;
	*carry = c1 | (uint64_t)(z < cb);

	return z;
}

static inline uint64_t ecdsap521_word_sub(uint64_t x, uint64_t y, uint64_t* borrow)
{
	uint64_t cb;
	uint64_t t0;
	uint64_t c1;
	uint64_t z;

	cb = *borrow & 1U;
	t0 = x - y;
	c1 = (uint64_t)(t0 > x);
	z = t0 - cb;
	*borrow = c1 | (uint64_t)(z > t0);

	return z;
}

static inline void ecdsap521_redc(uint64_t* ECDSAP521_RESTRICT output, const uint64_t* ECDSAP521_RESTRICT z)
{
	uint64_t* t;
	uint64_t carry;
	uint64_t borrow;
	uint64_t ovp5;
	uint64_t eqp5;
	uint64_t nsub;
	uint64_t sum;
	size_t i;

	t = output;

	for (i = 0U; i != ECDSAP521_LIMBS; ++i)
	{
		t[i] = z[(ECDSAP521_LIMBS - 1U) + i] >> 9U;
	}

	for (i = 0U; i != ECDSAP521_LIMBS - 1U; ++i)
	{
		t[i] |= z[(ECDSAP521_LIMBS - 1U) + i + 1U] << 55U;
	}

	carry = 0U;

	for (i = 0U; i != ECDSAP521_LIMBS - 1U; ++i)
	{
		t[i] = ecdsap521_word_add(t[i], z[i], &carry);
	}

	t[ECDSAP521_LIMBS - 1U] += (z[ECDSAP521_LIMBS - 1U] & UINT64_C(0x1FF)) + carry;

	ovp5 = 0U - (uint64_t)(t[ECDSAP521_LIMBS - 1U] > UINT64_C(0x1FF));
	sum = UINT64_MAX;

	for (i = 0U; i != ECDSAP521_LIMBS - 1U; ++i)
	{
		sum &= t[i];
	}

	sum &= (UINT64_C(0xFFFFFFFFFFFFFE00) | t[ECDSAP521_LIMBS - 1U]);
	eqp5 = 0U - (uint64_t)(sum == UINT64_MAX);
	nsub = ovp5 | eqp5;
	borrow = 0U;

	for (i = 0U; i != ECDSAP521_LIMBS - 1U; ++i)
	{
		t[i] = ecdsap521_word_sub(t[i], nsub, &borrow);
	}

	t[ECDSAP521_LIMBS - 1U] = ecdsap521_word_sub(t[ECDSAP521_LIMBS - 1U], nsub & UINT64_C(0x1FF), &borrow);
}

/*! \brief Canonical P-521 field modulus, in little-endian native words.
 * \details The top limb has nine significant bits.
 */
static const uint64_t ECDSAP521_P[ECDSAP521_LIMBS] = {
	UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_C(0x1FF)};

static inline void ecdsap521_maybe_sub(uint64_t* ECDSAP521_RESTRICT output, uint64_t x0, const uint64_t* ECDSAP521_RESTRICT x)
{
	uint64_t borrow;
	uint64_t mask;
	size_t i;

	borrow = 0U;

	for (i = 0U; i != ECDSAP521_LIMBS; ++i)
	{
		output[i] = ecdsap521_word_sub(x[i], ECDSAP521_P[i], &borrow);
	}

	borrow = (uint64_t)((x0 - borrow) > x0);
	mask = UINT64_C(0) - borrow;

	for (i = 0U; i != ECDSAP521_LIMBS; ++i)
	{
		output[i] = (output[i] & ~mask) | (x[i] & mask);
	}
}

static inline ecdsap521_field ecdsap521_add(const ecdsap521_field* a, const ecdsap521_field* b)
{
	ecdsap521_field result;
	uint64_t t[ECDSAP521_LIMBS];
	uint64_t carry;
	size_t i;

	carry = 0U;

	for (i = 0U; i != ECDSAP521_LIMBS; ++i)
	{
		t[i] = ecdsap521_word_add(a->limbs[i], b->limbs[i], &carry);
	}

	ecdsap521_maybe_sub(result.limbs, carry, t);

	return result;
}

static inline ecdsap521_field ecdsap521_sub(const ecdsap521_field* a, const ecdsap521_field* b)
{
	ecdsap521_field result;
	uint64_t borrow;
	uint64_t carry;
	uint64_t mask;
	size_t i;

	borrow = 0U;

	for (i = 0U; i != ECDSAP521_LIMBS; ++i)
	{
		result.limbs[i] = ecdsap521_word_sub(a->limbs[i], b->limbs[i], &borrow);
	}

	mask = UINT64_C(0) - borrow;
	carry = 0U;

	for (i = 0U; i != ECDSAP521_LIMBS; ++i)
	{
		result.limbs[i] = ecdsap521_word_add(result.limbs[i], ECDSAP521_P[i] & mask, &carry);
	}

	return result;
}

static inline ecdsap521_field ecdsap521_mul2(const ecdsap521_field* x)
{
	ecdsap521_field result;
	uint64_t t[ECDSAP521_LIMBS];
	uint64_t carry;
	size_t i;

	for (i = 0U; i != ECDSAP521_LIMBS; ++i)
	{
		t[i] = x->limbs[i];
	}

	carry = t[ECDSAP521_LIMBS - 1U] >> 63U;

	for (i = ECDSAP521_LIMBS - 1U; i != 0U; --i)
	{
		t[i] = (t[i] << 1U) | (t[i - 1U] >> 63U);
	}

	t[0U] <<= 1U;
	ecdsap521_maybe_sub(result.limbs, carry, t);

	return result;
}

/*! \brief Three-word Comba product accumulator matching word3<uint64_t>.
 * \details The low, middle and high words carry 192 bits. All storage is owned
 *          by the caller; no allocation or shared state.
 */
typedef struct
{
	uint64_t w0; /*!< Least-significant accumulator word. */
	uint64_t w1; /*!< Middle accumulator word. */
	uint64_t w2; /*!< Most-significant accumulator word. */
} ecdsap521_accumulator;

#if !defined(QSC_ECDSAP521_FORCE_PORTABLE) && defined(__SIZEOF_INT128__) && !(defined(_MSC_VER) && defined(_M_X64) && !defined(_M_ARM64EC))
/*! \brief Native unsigned 128-bit intermediate used by supported compilers. */
__extension__ typedef unsigned __int128 ecdsap521_uint128;
#endif

static inline void ecdsap521_mul_wide(uint64_t* low, uint64_t* high, uint64_t x, uint64_t y)
{
#if !defined(QSC_ECDSAP521_FORCE_PORTABLE) && defined(_MSC_VER) && defined(_M_X64) && !defined(_M_ARM64EC)
	*low = _umul128(x, y, high);
#elif !defined(QSC_ECDSAP521_FORCE_PORTABLE) && defined(__SIZEOF_INT128__)
	ecdsap521_uint128 product;

	product = (ecdsap521_uint128)x * y;
	*low = (uint64_t)product;
	*high = (uint64_t)(product >> 64U);
#else
	uint64_t a0;
	uint64_t a1;
	uint64_t b0;
	uint64_t b1;
	uint64_t p0;
	uint64_t p1;
	uint64_t p2;
	uint64_t p3;
	uint64_t carry;

	a0 = x & UINT64_C(0xFFFFFFFF);
	a1 = x >> 32U;
	b0 = y & UINT64_C(0xFFFFFFFF);
	b1 = y >> 32U;
	p0 = a0 * b0;
	p1 = a0 * b1;
	p2 = a1 * b0;
	p3 = a1 * b1;
	carry = (p0 >> 32U) + (p1 & UINT64_C(0xFFFFFFFF)) + (p2 & UINT64_C(0xFFFFFFFF));
	*low = (p0 & UINT64_C(0xFFFFFFFF)) | (carry << 32U);
	*high = p3 + (p1 >> 32U) + (p2 >> 32U) + (carry >> 32U);
#endif
}

static inline void ecdsap521_accum_mul(ecdsap521_accumulator* accum, uint64_t x, uint64_t y)
{
	uint64_t low;
	uint64_t high;
#if !defined(QSC_ECDSAP521_FORCE_PORTABLE) && !defined(_M_ARM64EC) && !defined(_MSC_VER) && (defined(__GNUC__) || defined(__clang__)) &&                       \
	(defined(__x86_64__) || defined(__amd64__))
	__asm__("mulq %[y]" : "=a"(low), "=d"(high) : "a"(x), [y] "rm"(y) : "cc");
	__asm__("addq %[low],%[w0]\n\t"
			"adcq %[high],%[w1]\n\t"
			"adcq $0,%[w2]"
			: [w0] "+&r"(accum->w0), [w1] "+&r"(accum->w1), [w2] "+&r"(accum->w2)
			: [low] "r"(low), [high] "r"(high)
			: "cc");
#elif !defined(QSC_ECDSAP521_FORCE_PORTABLE) && !defined(_M_ARM64EC) && (defined(__x86_64__) || defined(__amd64__) || (defined(_MSC_VER) && defined(_M_X64)))
	unsigned long long tmp;
	unsigned char carry;

	ecdsap521_mul_wide(&low, &high, x, y);
	carry = _addcarry_u64(0U, (unsigned long long)accum->w0, (unsigned long long)low, &tmp);
	accum->w0 = (uint64_t)tmp;
	carry = _addcarry_u64(carry, (unsigned long long)accum->w1, (unsigned long long)high, &tmp);
	accum->w1 = (uint64_t)tmp;
	accum->w2 += (uint64_t)carry;
#else
	uint64_t carry;

	ecdsap521_mul_wide(&low, &high, x, y);
	carry = 0U;
	accum->w0 = ecdsap521_word_add(accum->w0, low, &carry);
	accum->w1 = ecdsap521_word_add(accum->w1, high, &carry);
	accum->w2 += carry;
#endif
}

static inline uint64_t ecdsap521_accum_extract(ecdsap521_accumulator* accum)
{
	uint64_t result;

	result = accum->w0;
	accum->w0 = accum->w1;
	accum->w1 = accum->w2;
	accum->w2 = 0U;

	return result;
}

static inline void ecdsap521_comba_mul9(uint64_t* z, const uint64_t* x, const uint64_t* y)
{
	ecdsap521_accumulator accum = {0U, 0U, 0U};

	ecdsap521_accum_mul(&accum, x[0U], y[0U]);
	z[0U] = ecdsap521_accum_extract(&accum);
	ecdsap521_accum_mul(&accum, x[0U], y[1U]);
	ecdsap521_accum_mul(&accum, x[1U], y[0U]);
	z[1U] = ecdsap521_accum_extract(&accum);
	ecdsap521_accum_mul(&accum, x[0U], y[2U]);
	ecdsap521_accum_mul(&accum, x[1U], y[1U]);
	ecdsap521_accum_mul(&accum, x[2U], y[0U]);
	z[2U] = ecdsap521_accum_extract(&accum);
	ecdsap521_accum_mul(&accum, x[0U], y[3U]);
	ecdsap521_accum_mul(&accum, x[1U], y[2U]);
	ecdsap521_accum_mul(&accum, x[2U], y[1U]);
	ecdsap521_accum_mul(&accum, x[3U], y[0U]);
	z[3U] = ecdsap521_accum_extract(&accum);
	ecdsap521_accum_mul(&accum, x[0U], y[4U]);
	ecdsap521_accum_mul(&accum, x[1U], y[3U]);
	ecdsap521_accum_mul(&accum, x[2U], y[2U]);
	ecdsap521_accum_mul(&accum, x[3U], y[1U]);
	ecdsap521_accum_mul(&accum, x[4U], y[0U]);
	z[4U] = ecdsap521_accum_extract(&accum);
	ecdsap521_accum_mul(&accum, x[0U], y[5U]);
	ecdsap521_accum_mul(&accum, x[1U], y[4U]);
	ecdsap521_accum_mul(&accum, x[2U], y[3U]);
	ecdsap521_accum_mul(&accum, x[3U], y[2U]);
	ecdsap521_accum_mul(&accum, x[4U], y[1U]);
	ecdsap521_accum_mul(&accum, x[5U], y[0U]);
	z[5U] = ecdsap521_accum_extract(&accum);
	ecdsap521_accum_mul(&accum, x[0U], y[6U]);
	ecdsap521_accum_mul(&accum, x[1U], y[5U]);
	ecdsap521_accum_mul(&accum, x[2U], y[4U]);
	ecdsap521_accum_mul(&accum, x[3U], y[3U]);
	ecdsap521_accum_mul(&accum, x[4U], y[2U]);
	ecdsap521_accum_mul(&accum, x[5U], y[1U]);
	ecdsap521_accum_mul(&accum, x[6U], y[0U]);
	z[6U] = ecdsap521_accum_extract(&accum);
	ecdsap521_accum_mul(&accum, x[0U], y[7U]);
	ecdsap521_accum_mul(&accum, x[1U], y[6U]);
	ecdsap521_accum_mul(&accum, x[2U], y[5U]);
	ecdsap521_accum_mul(&accum, x[3U], y[4U]);
	ecdsap521_accum_mul(&accum, x[4U], y[3U]);
	ecdsap521_accum_mul(&accum, x[5U], y[2U]);
	ecdsap521_accum_mul(&accum, x[6U], y[1U]);
	ecdsap521_accum_mul(&accum, x[7U], y[0U]);
	z[7U] = ecdsap521_accum_extract(&accum);
	ecdsap521_accum_mul(&accum, x[0U], y[8U]);
	ecdsap521_accum_mul(&accum, x[1U], y[7U]);
	ecdsap521_accum_mul(&accum, x[2U], y[6U]);
	ecdsap521_accum_mul(&accum, x[3U], y[5U]);
	ecdsap521_accum_mul(&accum, x[4U], y[4U]);
	ecdsap521_accum_mul(&accum, x[5U], y[3U]);
	ecdsap521_accum_mul(&accum, x[6U], y[2U]);
	ecdsap521_accum_mul(&accum, x[7U], y[1U]);
	ecdsap521_accum_mul(&accum, x[8U], y[0U]);
	z[8U] = ecdsap521_accum_extract(&accum);
	ecdsap521_accum_mul(&accum, x[1U], y[8U]);
	ecdsap521_accum_mul(&accum, x[2U], y[7U]);
	ecdsap521_accum_mul(&accum, x[3U], y[6U]);
	ecdsap521_accum_mul(&accum, x[4U], y[5U]);
	ecdsap521_accum_mul(&accum, x[5U], y[4U]);
	ecdsap521_accum_mul(&accum, x[6U], y[3U]);
	ecdsap521_accum_mul(&accum, x[7U], y[2U]);
	ecdsap521_accum_mul(&accum, x[8U], y[1U]);
	z[9U] = ecdsap521_accum_extract(&accum);
	ecdsap521_accum_mul(&accum, x[2U], y[8U]);
	ecdsap521_accum_mul(&accum, x[3U], y[7U]);
	ecdsap521_accum_mul(&accum, x[4U], y[6U]);
	ecdsap521_accum_mul(&accum, x[5U], y[5U]);
	ecdsap521_accum_mul(&accum, x[6U], y[4U]);
	ecdsap521_accum_mul(&accum, x[7U], y[3U]);
	ecdsap521_accum_mul(&accum, x[8U], y[2U]);
	z[10U] = ecdsap521_accum_extract(&accum);
	ecdsap521_accum_mul(&accum, x[3U], y[8U]);
	ecdsap521_accum_mul(&accum, x[4U], y[7U]);
	ecdsap521_accum_mul(&accum, x[5U], y[6U]);
	ecdsap521_accum_mul(&accum, x[6U], y[5U]);
	ecdsap521_accum_mul(&accum, x[7U], y[4U]);
	ecdsap521_accum_mul(&accum, x[8U], y[3U]);
	z[11U] = ecdsap521_accum_extract(&accum);
	ecdsap521_accum_mul(&accum, x[4U], y[8U]);
	ecdsap521_accum_mul(&accum, x[5U], y[7U]);
	ecdsap521_accum_mul(&accum, x[6U], y[6U]);
	ecdsap521_accum_mul(&accum, x[7U], y[5U]);
	ecdsap521_accum_mul(&accum, x[8U], y[4U]);
	z[12U] = ecdsap521_accum_extract(&accum);
	ecdsap521_accum_mul(&accum, x[5U], y[8U]);
	ecdsap521_accum_mul(&accum, x[6U], y[7U]);
	ecdsap521_accum_mul(&accum, x[7U], y[6U]);
	ecdsap521_accum_mul(&accum, x[8U], y[5U]);
	z[13U] = ecdsap521_accum_extract(&accum);
	ecdsap521_accum_mul(&accum, x[6U], y[8U]);
	ecdsap521_accum_mul(&accum, x[7U], y[7U]);
	ecdsap521_accum_mul(&accum, x[8U], y[6U]);
	z[14U] = ecdsap521_accum_extract(&accum);
	ecdsap521_accum_mul(&accum, x[7U], y[8U]);
	ecdsap521_accum_mul(&accum, x[8U], y[7U]);
	z[15U] = ecdsap521_accum_extract(&accum);
	ecdsap521_accum_mul(&accum, x[8U], y[8U]);
	z[16U] = ecdsap521_accum_extract(&accum);
	z[17U] = ecdsap521_accum_extract(&accum);
}

static inline void ecdsap521_accum_mul_x2(ecdsap521_accumulator* accum, uint64_t x, uint64_t y)
{
	uint64_t low;
	uint64_t high;
#if !defined(QSC_ECDSAP521_FORCE_PORTABLE) && !defined(_M_ARM64EC) && !defined(_MSC_VER) && (defined(__GNUC__) || defined(__clang__)) &&                       \
	(defined(__x86_64__) || defined(__amd64__))
	__asm__("mulq %[y]" : "=a"(low), "=d"(high) : "a"(x), [y] "rm"(y) : "cc");
	__asm__("addq %[low],%[w0]\n\t"
			"adcq %[high],%[w1]\n\t"
			"adcq $0,%[w2]\n\t"
			"addq %[low],%[w0]\n\t"
			"adcq %[high],%[w1]\n\t"
			"adcq $0,%[w2]"
			: [w0] "+&r"(accum->w0), [w1] "+&r"(accum->w1), [w2] "+&r"(accum->w2)
			: [low] "r"(low), [high] "r"(high)
			: "cc");
#elif !defined(QSC_ECDSAP521_FORCE_PORTABLE) && !defined(_M_ARM64EC) && (defined(__x86_64__) || defined(__amd64__) || (defined(_MSC_VER) && defined(_M_X64)))
	unsigned long long tmp;
	unsigned char carry;

	ecdsap521_mul_wide(&low, &high, x, y);
	carry = _addcarry_u64(0U, (unsigned long long)accum->w0, (unsigned long long)low, &tmp);
	accum->w0 = (uint64_t)tmp;
	carry = _addcarry_u64(carry, (unsigned long long)accum->w1, (unsigned long long)high, &tmp);
	accum->w1 = (uint64_t)tmp;
	accum->w2 += (uint64_t)carry;
	carry = _addcarry_u64(0U, (unsigned long long)accum->w0, (unsigned long long)low, &tmp);
	accum->w0 = (uint64_t)tmp;
	carry = _addcarry_u64(carry, (unsigned long long)accum->w1, (unsigned long long)high, &tmp);
	accum->w1 = (uint64_t)tmp;
	accum->w2 += (uint64_t)carry;
#else
	uint64_t carry;

	ecdsap521_mul_wide(&low, &high, x, y);
	carry = 0U;
	accum->w0 = ecdsap521_word_add(accum->w0, low, &carry);
	accum->w1 = ecdsap521_word_add(accum->w1, high, &carry);
	accum->w2 += carry;
	carry = 0U;
	accum->w0 = ecdsap521_word_add(accum->w0, low, &carry);
	accum->w1 = ecdsap521_word_add(accum->w1, high, &carry);
	accum->w2 += carry;
#endif
}

static inline void ecdsap521_comba_sqr9(uint64_t* z, const uint64_t* x)
{
	ecdsap521_accumulator accum = {0U, 0U, 0U};

	ecdsap521_accum_mul(&accum, x[0U], x[0U]);
	z[0U] = ecdsap521_accum_extract(&accum);
	ecdsap521_accum_mul_x2(&accum, x[0U], x[1U]);
	z[1U] = ecdsap521_accum_extract(&accum);
	ecdsap521_accum_mul_x2(&accum, x[0U], x[2U]);
	ecdsap521_accum_mul(&accum, x[1U], x[1U]);
	z[2U] = ecdsap521_accum_extract(&accum);
	ecdsap521_accum_mul_x2(&accum, x[0U], x[3U]);
	ecdsap521_accum_mul_x2(&accum, x[1U], x[2U]);
	z[3U] = ecdsap521_accum_extract(&accum);
	ecdsap521_accum_mul_x2(&accum, x[0U], x[4U]);
	ecdsap521_accum_mul_x2(&accum, x[1U], x[3U]);
	ecdsap521_accum_mul(&accum, x[2U], x[2U]);
	z[4U] = ecdsap521_accum_extract(&accum);
	ecdsap521_accum_mul_x2(&accum, x[0U], x[5U]);
	ecdsap521_accum_mul_x2(&accum, x[1U], x[4U]);
	ecdsap521_accum_mul_x2(&accum, x[2U], x[3U]);
	z[5U] = ecdsap521_accum_extract(&accum);
	ecdsap521_accum_mul_x2(&accum, x[0U], x[6U]);
	ecdsap521_accum_mul_x2(&accum, x[1U], x[5U]);
	ecdsap521_accum_mul_x2(&accum, x[2U], x[4U]);
	ecdsap521_accum_mul(&accum, x[3U], x[3U]);
	z[6U] = ecdsap521_accum_extract(&accum);
	ecdsap521_accum_mul_x2(&accum, x[0U], x[7U]);
	ecdsap521_accum_mul_x2(&accum, x[1U], x[6U]);
	ecdsap521_accum_mul_x2(&accum, x[2U], x[5U]);
	ecdsap521_accum_mul_x2(&accum, x[3U], x[4U]);
	z[7U] = ecdsap521_accum_extract(&accum);
	ecdsap521_accum_mul_x2(&accum, x[0U], x[8U]);
	ecdsap521_accum_mul_x2(&accum, x[1U], x[7U]);
	ecdsap521_accum_mul_x2(&accum, x[2U], x[6U]);
	ecdsap521_accum_mul_x2(&accum, x[3U], x[5U]);
	ecdsap521_accum_mul(&accum, x[4U], x[4U]);
	z[8U] = ecdsap521_accum_extract(&accum);
	ecdsap521_accum_mul_x2(&accum, x[1U], x[8U]);
	ecdsap521_accum_mul_x2(&accum, x[2U], x[7U]);
	ecdsap521_accum_mul_x2(&accum, x[3U], x[6U]);
	ecdsap521_accum_mul_x2(&accum, x[4U], x[5U]);
	z[9U] = ecdsap521_accum_extract(&accum);
	ecdsap521_accum_mul_x2(&accum, x[2U], x[8U]);
	ecdsap521_accum_mul_x2(&accum, x[3U], x[7U]);
	ecdsap521_accum_mul_x2(&accum, x[4U], x[6U]);
	ecdsap521_accum_mul(&accum, x[5U], x[5U]);
	z[10U] = ecdsap521_accum_extract(&accum);
	ecdsap521_accum_mul_x2(&accum, x[3U], x[8U]);
	ecdsap521_accum_mul_x2(&accum, x[4U], x[7U]);
	ecdsap521_accum_mul_x2(&accum, x[5U], x[6U]);
	z[11U] = ecdsap521_accum_extract(&accum);
	ecdsap521_accum_mul_x2(&accum, x[4U], x[8U]);
	ecdsap521_accum_mul_x2(&accum, x[5U], x[7U]);
	ecdsap521_accum_mul(&accum, x[6U], x[6U]);
	z[12U] = ecdsap521_accum_extract(&accum);
	ecdsap521_accum_mul_x2(&accum, x[5U], x[8U]);
	ecdsap521_accum_mul_x2(&accum, x[6U], x[7U]);
	z[13U] = ecdsap521_accum_extract(&accum);
	ecdsap521_accum_mul_x2(&accum, x[6U], x[8U]);
	ecdsap521_accum_mul(&accum, x[7U], x[7U]);
	z[14U] = ecdsap521_accum_extract(&accum);
	ecdsap521_accum_mul_x2(&accum, x[7U], x[8U]);
	z[15U] = ecdsap521_accum_extract(&accum);
	ecdsap521_accum_mul(&accum, x[8U], x[8U]);
	z[16U] = ecdsap521_accum_extract(&accum);
	z[17U] = ecdsap521_accum_extract(&accum);
}

static inline ecdsap521_field ecdsap521_mul(const ecdsap521_field* a, const ecdsap521_field* b)
{
	ecdsap521_field result;
	uint64_t z[ECDSAP521_WIDE_LIMBS];

	ecdsap521_comba_mul9(z, a->limbs, b->limbs);
	ecdsap521_redc(result.limbs, z);

	return result;
}

static inline ecdsap521_field* ecdsap521_mul_assign(ecdsap521_field* a, const ecdsap521_field* b)
{
	uint64_t z[ECDSAP521_WIDE_LIMBS];

	ecdsap521_comba_mul9(z, a->limbs, b->limbs);
	ecdsap521_redc(a->limbs, z);

	return a;
}

static inline ecdsap521_field ecdsap521_square(const ecdsap521_field* x)
{
	ecdsap521_field result;
	uint64_t z[ECDSAP521_WIDE_LIMBS];

	ecdsap521_comba_sqr9(z, x->limbs);
	ecdsap521_redc(result.limbs, z);

	return result;
}

static inline void ecdsap521_square_n(ecdsap521_field* x, size_t n)
{
	uint64_t z[ECDSAP521_WIDE_LIMBS];
	size_t i;

	for (i = 0U; i != n; ++i)
	{
		ecdsap521_comba_sqr9(z, x->limbs);
		ecdsap521_redc(x->limbs, z);
	}
}

static inline uint64_t ecdsap521_mask_barrier(uint64_t mask)
{
	volatile uint64_t ptms;

	ptms = mask;

	return ptms;
}

static inline uint64_t ecdsap521_is_zero(const ecdsap521_field* x)
{
	uint64_t sum;
	size_t i;

	sum = 0U;

	for (i = 0U; i != ECDSAP521_LIMBS; ++i)
	{
		sum |= x->limbs[i];
	}

	return (uint64_t)(1U ^ ((sum | (UINT64_C(0) - sum)) >> 63U));
}

static inline ecdsap521_field ecdsap521_negate(const ecdsap521_field* x)
{
	ecdsap521_field result;
	uint64_t xzer;
	uint64_t borrow;
	size_t i;

	xzer = ecdsap521_mask_barrier(UINT64_C(0) - (ecdsap521_is_zero(x) ^ UINT64_C(1)));
	borrow = 0U;

	for (i = 0U; i != ECDSAP521_LIMBS; ++i)
	{
		result.limbs[i] = ecdsap521_word_sub(ECDSAP521_P[i] & xzer, x->limbs[i], &borrow);
	}

	return result;
}

static inline void ecdsap521_conditional_assign(ecdsap521_field* x, uint64_t choice, const ecdsap521_field* nx)
{
	uint64_t mask;
	size_t i;

	mask = ecdsap521_mask_barrier(UINT64_C(0) - (choice & UINT64_C(1)));

	for (i = 0U; i != ECDSAP521_LIMBS; ++i)
	{
		x->limbs[i] = (mask & nx->limbs[i]) | (~mask & x->limbs[i]);
	}
}

static inline void ecdsap521_conditional_swap(uint64_t choice, ecdsap521_field* x, ecdsap521_field* y)
{
	uint64_t mask;
	uint64_t nx;
	uint64_t ny;
	size_t i;

	mask = ecdsap521_mask_barrier(UINT64_C(0) - (choice & UINT64_C(1)));

	for (i = 0U; i != ECDSAP521_LIMBS; ++i)
	{
		nx = (mask & y->limbs[i]) | (~mask & x->limbs[i]);
		ny = (mask & x->limbs[i]) | (~mask & y->limbs[i]);
		x->limbs[i] = nx;
		y->limbs[i] = ny;
	}
}

static inline ecdsap521_field ecdsap521_fe_invert2(const ecdsap521_field* x)
{
	ecdsap521_field r;
	ecdsap521_field rl;
	ecdsap521_field a7;

	r = ecdsap521_square(x);
	ecdsap521_mul_assign(&r, x);
	r = ecdsap521_square(&r);
	ecdsap521_mul_assign(&r, x);
	rl = r;
	ecdsap521_square_n(&r, 3U);
	ecdsap521_mul_assign(&r, &rl);
	ecdsap521_square_n(&r, 1U);
	ecdsap521_mul_assign(&r, x);
	a7 = r;
	ecdsap521_square_n(&r, 1U);
	ecdsap521_mul_assign(&r, x);
	rl = r;
	ecdsap521_square_n(&r, 8U);
	ecdsap521_mul_assign(&r, &rl);
	rl = r;
	ecdsap521_square_n(&r, 16U);
	ecdsap521_mul_assign(&r, &rl);
	rl = r;
	ecdsap521_square_n(&r, 32U);
	ecdsap521_mul_assign(&r, &rl);
	rl = r;
	ecdsap521_square_n(&r, 64U);
	ecdsap521_mul_assign(&r, &rl);
	rl = r;
	ecdsap521_square_n(&r, 128U);
	ecdsap521_mul_assign(&r, &rl);
	rl = r;
	ecdsap521_square_n(&r, 256U);
	ecdsap521_mul_assign(&r, &rl);
	ecdsap521_square_n(&r, 7U);
	ecdsap521_mul_assign(&r, &a7);
	ecdsap521_square_n(&r, 2U);

	return r;
}

static inline ecdsap521_field ecdsap521_zero(void)
{
	ecdsap521_field result = {{UINT64_C(0)}};

	return result;
}

/*! \brief An affine P-521 point in native coordinate representation.
 * \details The identity is encoded as x=0 and y=0. Each field element is
 * caller-owned. The structure has no dynamically allocated members.
 */
typedef struct
{
	ecdsap521_field x; /*!< Canonical affine x coordinate. */
	ecdsap521_field y; /*!< Canonical affine y coordinate. */
} ecdsap521_affine_point;

/*! \brief A Jacobian P-521 point in native coordinate representation.
 * \details The canonical identity encoding is (0,1,0). Coordinates are
 * caller-owned and the type contains no shared mutable state.
 */
typedef struct
{
	ecdsap521_field x; /*!< Jacobian x coordinate. */
	ecdsap521_field y; /*!< Jacobian y coordinate. */
	ecdsap521_field z; /*!< Jacobian z coordinate. */
} ecdsap521_projective_point;

static inline uint64_t ecdsap521_affine_is_identity(const ecdsap521_affine_point* pt)
{
	return ecdsap521_is_zero(&pt->x) & ecdsap521_is_zero(&pt->y);
}

static inline ecdsap521_projective_point ecdsap521_projective_identity(void)
{
	ecdsap521_projective_point result;

	result.x = ecdsap521_zero();
	result.y = ecdsap521_one();
	result.z = ecdsap521_zero();

	return result;
}

static inline ecdsap521_projective_point ecdsap521_projective_from_affine(const ecdsap521_affine_point* pt)
{
	ecdsap521_projective_point result;

	result.x = pt->x;
	result.y = pt->y;
	result.z = ecdsap521_one();
	ecdsap521_conditional_swap(ecdsap521_affine_is_identity(pt), &result.y, &result.z);

	return result;
}

static inline uint64_t ecdsap521_projective_is_identity(const ecdsap521_projective_point* pt)
{
	return ecdsap521_is_zero(&pt->z);
}

static inline ecdsap521_field ecdsap521_mul3(const ecdsap521_field* x)
{
	ecdsap521_field result;

	result = ecdsap521_mul2(x);
	result = ecdsap521_add(&result, x);

	return result;
}

static inline ecdsap521_field ecdsap521_mul4(const ecdsap521_field* x)
{
	ecdsap521_field result;

	result = ecdsap521_mul2(x);
	result = ecdsap521_mul2(&result);

	return result;
}

static inline ecdsap521_field ecdsap521_mul8(const ecdsap521_field* x)
{
	ecdsap521_field result;

	result = ecdsap521_mul2(x);
	result = ecdsap521_mul2(&result);
	result = ecdsap521_mul2(&result);

	return result;
}

static inline ecdsap521_projective_point ecdsap521_dbl_a_minus_3(const ecdsap521_projective_point* pt)
{
	ecdsap521_projective_point result;
	ecdsap521_field z2;
	ecdsap521_field m;
	ecdsap521_field y2;
	ecdsap521_field s;
	ecdsap521_field nx;
	ecdsap521_field ny;
	ecdsap521_field nz;
	ecdsap521_field t0;
	ecdsap521_field t1;

	z2 = ecdsap521_square(&pt->z);
	t0 = ecdsap521_sub(&pt->x, &z2);
	t0 = ecdsap521_mul3(&t0);
	t1 = ecdsap521_add(&pt->x, &z2);
	m = ecdsap521_mul(&t0, &t1);

	y2 = ecdsap521_square(&pt->y);
	t0 = ecdsap521_mul4(&pt->x);
	s = ecdsap521_mul(&t0, &y2);
	t0 = ecdsap521_square(&m);
	t1 = ecdsap521_mul2(&s);
	nx = ecdsap521_sub(&t0, &t1);
	t0 = ecdsap521_sub(&s, &nx);
	t1 = ecdsap521_mul(&m, &t0);
	t0 = ecdsap521_square(&y2);
	t0 = ecdsap521_mul8(&t0);
	ny = ecdsap521_sub(&t1, &t0);
	t0 = ecdsap521_mul2(&pt->y);
	nz = ecdsap521_mul(&t0, &pt->z);

	result.x = nx;
	result.y = ny;
	result.z = nz;

	return result;
}

static inline void ecdsap521_projective_conditional_assign(ecdsap521_projective_point* result, uint64_t choice, const ecdsap521_projective_point* replacement)
{
	uint64_t pcho;

	pcho = ecdsap521_mask_barrier(choice & UINT64_C(1));
	ecdsap521_conditional_assign(&result->x, pcho, &replacement->x);
	ecdsap521_conditional_assign(&result->y, pcho, &replacement->y);
	ecdsap521_conditional_assign(&result->z, pcho, &replacement->z);
}

/*! \brief Jacobian mixed-addition result and original H intermediate.
 * \details The caller owns both fields. The point is in Jacobian coordinates,
 * and H equals affine.x * projective.z^2 - projective.x.
 */
typedef struct
{
	ecdsap521_projective_point point; /*!< Jacobian sum, or the point at infinity. */
	ecdsap521_field h;				  /*!< Difference of normalized affine and projective x coordinates. */
} ecdsap521_mixed_result;

static inline ecdsap521_projective_point ecdsap521_point_add_or_sub_mixed(const ecdsap521_projective_point* a, const ecdsap521_affine_point* b, uint64_t sub, bool check_exception)
{
	ecdsap521_projective_point result;
	ecdsap521_projective_point doubled;
	ecdsap521_field by;
	ecdsap521_field ngby;
	ecdsap521_field z1z1;
	ecdsap521_field u2;
	ecdsap521_field s2;
	ecdsap521_field h;
	ecdsap521_field r;
	ecdsap521_field hh;
	ecdsap521_field hhh;
	ecdsap521_field v;
	ecdsap521_field t0;
	ecdsap521_field t2;
	ecdsap521_field t3;
	ecdsap521_field t4;
	ecdsap521_field t5;
	ecdsap521_field t6;
	ecdsap521_field t7;
	ecdsap521_field x3;
	ecdsap521_field y3;
	ecdsap521_field z3;
	ecdsap521_field one;
	uint64_t aidn;
	uint64_t bidn;
	uint64_t doubling;

	aidn = ecdsap521_projective_is_identity(a);
	bidn = ecdsap521_affine_is_identity(b);

	by = b->y;
	ngby = ecdsap521_negate(&by);
	ecdsap521_conditional_assign(&by, ecdsap521_mask_barrier(sub & UINT64_C(1)), &ngby);

	z1z1 = ecdsap521_square(&a->z);
	u2 = ecdsap521_mul(&b->x, &z1z1);
	t0 = ecdsap521_mul(&by, &a->z);
	s2 = ecdsap521_mul(&t0, &z1z1);
	h = ecdsap521_sub(&u2, &a->x);
	r = ecdsap521_sub(&s2, &a->y);

	hh = ecdsap521_square(&h);
	hhh = ecdsap521_mul(&h, &hh);
	v = ecdsap521_mul(&a->x, &hh);
	t2 = ecdsap521_square(&r);
	t3 = ecdsap521_add(&v, &v);
	t4 = ecdsap521_sub(&t2, &hhh);
	x3 = ecdsap521_sub(&t4, &t3);
	t5 = ecdsap521_sub(&v, &x3);
	t6 = ecdsap521_mul(&a->y, &hhh);
	t7 = ecdsap521_mul(&r, &t5);
	y3 = ecdsap521_sub(&t7, &t6);
	z3 = ecdsap521_mul(&a->z, &h);

	one = ecdsap521_one();
	ecdsap521_conditional_assign(&x3, aidn, &b->x);
	ecdsap521_conditional_assign(&y3, aidn, &by);
	ecdsap521_conditional_assign(&z3, aidn, &one);
	ecdsap521_conditional_assign(&x3, bidn, &a->x);
	ecdsap521_conditional_assign(&y3, bidn, &a->y);
	ecdsap521_conditional_assign(&z3, bidn, &a->z);

	result.x = x3;
	result.y = y3;
	result.z = z3;

	if (check_exception)
	{
		doubled = ecdsap521_dbl_a_minus_3(a);
		doubling = ecdsap521_is_zero(&r) & ecdsap521_is_zero(&h) & (aidn ^ UINT64_C(1)) & (bidn ^ UINT64_C(1));
		ecdsap521_projective_conditional_assign(&result, doubling, &doubled);
	}

	return result;
}

static inline ecdsap521_projective_point ecdsap521_point_add(const ecdsap521_projective_point* a, const ecdsap521_projective_point* b)
{
	ecdsap521_projective_point result;
	ecdsap521_projective_point doubled;
	ecdsap521_field z1z1;
	ecdsap521_field z2z2;
	ecdsap521_field u1;
	ecdsap521_field u2;
	ecdsap521_field s1;
	ecdsap521_field s2;
	ecdsap521_field h;
	ecdsap521_field r;
	ecdsap521_field hh;
	ecdsap521_field hhh;
	ecdsap521_field v;
	ecdsap521_field t0;
	ecdsap521_field t2;
	ecdsap521_field t3;
	ecdsap521_field t4;
	ecdsap521_field t5;
	ecdsap521_field t6;
	ecdsap521_field t7;
	ecdsap521_field t8;
	ecdsap521_field x3;
	ecdsap521_field y3;
	ecdsap521_field z3;
	uint64_t aidn;
	uint64_t bidn;
	uint64_t doubling;

	aidn = ecdsap521_projective_is_identity(a);
	bidn = ecdsap521_projective_is_identity(b);

	z1z1 = ecdsap521_square(&a->z);
	z2z2 = ecdsap521_square(&b->z);
	u1 = ecdsap521_mul(&a->x, &z2z2);
	u2 = ecdsap521_mul(&b->x, &z1z1);
	t0 = ecdsap521_mul(&a->y, &b->z);
	s1 = ecdsap521_mul(&t0, &z2z2);
	t0 = ecdsap521_mul(&b->y, &a->z);
	s2 = ecdsap521_mul(&t0, &z1z1);
	h = ecdsap521_sub(&u2, &u1);
	r = ecdsap521_sub(&s2, &s1);

	hh = ecdsap521_square(&h);
	hhh = ecdsap521_mul(&h, &hh);
	v = ecdsap521_mul(&u1, &hh);
	t2 = ecdsap521_square(&r);
	t3 = ecdsap521_add(&v, &v);
	t4 = ecdsap521_sub(&t2, &hhh);
	x3 = ecdsap521_sub(&t4, &t3);
	t5 = ecdsap521_sub(&v, &x3);
	t6 = ecdsap521_mul(&s1, &hhh);
	t7 = ecdsap521_mul(&r, &t5);
	y3 = ecdsap521_sub(&t7, &t6);
	t8 = ecdsap521_mul(&b->z, &h);
	z3 = ecdsap521_mul(&a->z, &t8);

	ecdsap521_conditional_assign(&x3, aidn, &b->x);
	ecdsap521_conditional_assign(&y3, aidn, &b->y);
	ecdsap521_conditional_assign(&z3, aidn, &b->z);
	ecdsap521_conditional_assign(&x3, bidn, &a->x);
	ecdsap521_conditional_assign(&y3, bidn, &a->y);
	ecdsap521_conditional_assign(&z3, bidn, &a->z);

	result.x = x3;
	result.y = y3;
	result.z = z3;
	doubled = ecdsap521_dbl_a_minus_3(a);
	doubling = ecdsap521_is_zero(&r) & ecdsap521_is_zero(&h) & ((aidn & bidn) ^ UINT64_C(1));
	ecdsap521_projective_conditional_assign(&result, doubling, &doubled);

	return result;
}

/*! \def ECDSAP521_BASE_WINDOW_BITS
 * \brief fixed-base Booth scalar-multiplication window width.
 */
#define ECDSAP521_BASE_WINDOW_BITS 6U

/*! \def ECDSAP521_BASE_WINDOW_ELEMENTS
 * \brief Number of nonidentity affine points per fixed-base Booth window.
 */
#define ECDSAP521_BASE_WINDOW_ELEMENTS 32U

static inline ecdsap521_field ecdsap521_invert_field_element(const ecdsap521_field* x)
{
	ecdsap521_field result;

	result = ecdsap521_fe_invert2(x);
	result = ecdsap521_mul(&result, x);

	return result;
}

static inline ecdsap521_affine_point ecdsap521_to_affine(const ecdsap521_projective_point* pt)
{
	ecdsap521_affine_point result;
	ecdsap521_field z2iv;
	ecdsap521_field z3iv;

	z2iv = ecdsap521_fe_invert2(&pt->z);
	z3iv = ecdsap521_square(&z2iv);
	z3iv = ecdsap521_mul(&z3iv, &pt->z);
	result.x = ecdsap521_mul(&pt->x, &z2iv);
	result.y = ecdsap521_mul(&pt->y, &z3iv);

	return result;
}

static inline bool ecdsap521_to_affine_batch(ecdsap521_affine_point* output, const ecdsap521_projective_point* input, size_t count, ecdsap521_field* scratch, size_t scratch_count)
{
	ecdsap521_field s_inv;
	ecdsap521_field z_inv;
	ecdsap521_field z2iv;
	ecdsap521_field z3iv;
	uint64_t ayin;
	bool success;
	size_t i;

	success = true;
	ayin = UINT64_C(0);

	if (count != 0U)
	{
		if (output == NULL || input == NULL)
		{
			success = false;
		}
		else
		{
			for (i = 0U; i != count; ++i)
			{
				ayin |= ecdsap521_projective_is_identity(&input[i]);
			}

			if (count <= 2U || ayin != UINT64_C(0))
			{
				for (i = 0U; i != count; ++i)
				{
					output[i] = ecdsap521_to_affine(&input[i]);
				}
			}
			else if (scratch == NULL || scratch_count < count)
			{
				success = false;
			}
			else
			{
				scratch[0U] = input[0U].z;

				for (i = 1U; i != count; ++i)
				{
					scratch[i] = ecdsap521_mul(&scratch[i - 1U], &input[i].z);
				}

				s_inv = ecdsap521_invert_field_element(&scratch[count - 1U]);

				for (i = count - 1U; i > 0U; --i)
				{
					z_inv = ecdsap521_mul(&s_inv, &scratch[i - 1U]);
					z2iv = ecdsap521_square(&z_inv);
					z3iv = ecdsap521_mul(&z_inv, &z2iv);
					s_inv = ecdsap521_mul(&s_inv, &input[i].z);
					output[i].x = ecdsap521_mul(&input[i].x, &z2iv);
					output[i].y = ecdsap521_mul(&input[i].y, &z3iv);
				}

				z2iv = ecdsap521_square(&s_inv);
				z3iv = ecdsap521_mul(&s_inv, &z2iv);
				output[0U].x = ecdsap521_mul(&input[0U].x, &z2iv);
				output[0U].y = ecdsap521_mul(&input[0U].y, &z3iv);
			}
		}
	}

	return success;
}

static inline size_t ecdsap521_basemul_booth_table_size(size_t max_scalar_bits)
{
	size_t windows;
	size_t result;

	result = 0U;

	if (max_scalar_bits <= SIZE_MAX - (ECDSAP521_BASE_WINDOW_BITS - 1U))
	{
		windows = (max_scalar_bits + (ECDSAP521_BASE_WINDOW_BITS - 1U)) / ECDSAP521_BASE_WINDOW_BITS;

		if (windows <= SIZE_MAX / ECDSAP521_BASE_WINDOW_ELEMENTS)
		{
			result = windows * ECDSAP521_BASE_WINDOW_ELEMENTS;
		}
	}

	return result;
}

static inline bool ecdsap521_basemul_booth_setup(ecdsap521_affine_point* output, size_t output_capacity, ecdsap521_projective_point* projective, size_t projective_capacity, ecdsap521_field* scratch, size_t scratch_capacity, const ecdsap521_affine_point* base, size_t max_scalar_bits)
{
	ecdsap521_projective_point accum;
	ecdsap521_projective_point point;
	size_t required;
	size_t i;
	size_t j;
	bool success;

	required = ecdsap521_basemul_booth_table_size(max_scalar_bits);
	success = false;

	if ((max_scalar_bits == 0U && required == 0U) || (required != 0U && base != NULL && output != NULL && projective != NULL && scratch != NULL &&
		output_capacity >= required && projective_capacity >= required && scratch_capacity >= required))
	{
		success = true;

		if (required != 0U)
		{
			accum = ecdsap521_projective_from_affine(base);

			for (i = 0U; i != required; i += ECDSAP521_BASE_WINDOW_ELEMENTS)
			{
				projective[i] = accum;

				for (j = 1U; j != ECDSAP521_BASE_WINDOW_ELEMENTS; ++j)
				{
					if ((j & 1U) != 0U)
					{
						projective[i + j] = ecdsap521_dbl_a_minus_3(&projective[i + j / 2U]);
					}
					else
					{
						projective[i + j] = ecdsap521_point_add(&projective[i + j - 1U], &projective[i]);
					}
				}

				point = projective[i + ECDSAP521_BASE_WINDOW_ELEMENTS - 1U];
				accum = ecdsap521_dbl_a_minus_3(&point);
			}

			success = ecdsap521_to_affine_batch(output, projective, required, scratch, scratch_capacity);
		}
	}

	return success;
}

/*! \def ECDSAP521_BOOTH_WINDOW_MASK
 * \brief Seven-bit input mask for the six-bit signed Booth representation.
 */
#define ECDSAP521_BOOTH_WINDOW_MASK UINT64_C(0x7F)

/*! \brief A signed Booth table index, with the sign represented separately.
 * \details Digit zero denotes the point at infinity. The negation flag has
 * value zero or one. Instances have automatic storage and no owner.
 */
typedef struct
{
	uint64_t digit;	   /*!< Affine table index in [0,32], zero denotes identity. */
	uint64_t negative; /*!< One means subtract selected table point. */
} ecdsap521_booth_digit;

static inline ecdsap521_booth_digit ecdsap521_booth_recode6(uint64_t raw)
{
	ecdsap521_booth_digit result;
	uint64_t sign;
	uint64_t mask;
	uint64_t negx;
	uint64_t digit;

	raw &= ECDSAP521_BOOTH_WINDOW_MASK;
	sign = raw >> ECDSAP521_BASE_WINDOW_BITS;
	mask = ecdsap521_mask_barrier(UINT64_C(0) - sign);
	negx = (UINT64_C(1) << (ECDSAP521_BASE_WINDOW_BITS + 1U)) - raw - UINT64_C(1);
	digit = (negx & mask) | (raw & ~mask);
	result.digit = (digit >> 1U) + (digit & UINT64_C(1));
	result.negative = sign;

	return result;
}

static inline uint64_t ecdsap521_scalar_window7(const uint8_t* scalar, size_t scalar_length, size_t offset)
{
	uint64_t result;
	uint64_t bit;
	size_t ypos;
	size_t bpos;
	size_t i;

	result = UINT64_C(0);

	for (i = 0U; i != 7U; ++i)
	{
		bpos = offset + i;
		ypos = bpos / 8U;
		bit = UINT64_C(0);

		if (ypos < scalar_length)
		{
			bit = ((uint64_t)scalar[scalar_length - 1U - ypos] >> (bpos & 7U)) & UINT64_C(1);
		}

		result |= bit << i;
	}

	return result;
}

static inline ecdsap521_affine_point ecdsap521_affine_ct_select32(const ecdsap521_affine_point* table, uint64_t digit)
{
	ecdsap521_affine_point result;
	uint64_t diff;
	uint64_t equal;
	size_t i;

	result.x = ecdsap521_zero();
	result.y = ecdsap521_zero();

	for (i = 0U; i != ECDSAP521_BASE_WINDOW_ELEMENTS; ++i)
	{
		diff = digit ^ ((uint64_t)i + UINT64_C(1));
		equal = UINT64_C(1) ^ ((diff | (UINT64_C(0) - diff)) >> 63U);
		ecdsap521_conditional_assign(&result.x, equal, &table[i].x);
		ecdsap521_conditional_assign(&result.y, equal, &table[i].y);
	}

	return result;
}

/*! \def ECDSAP521_BLIND_BITS
 * \brief scalar-blinding bit count for the P-521 subgroup order.
 */
#define ECDSAP521_BLIND_BITS 55U

/*! \def ECDSAP521_BLIND_BYTES
 * \brief Fixed 576-bit blinded scalar serialization length in bytes.
 */
#define ECDSAP521_BLIND_BYTES 72U

/*! \def ECDSAP521_RANDOM_FIELD_BYTES
 * \brief Oversampled field element length, 66 field bytes plus eight bytes.
 */
#define ECDSAP521_RANDOM_FIELD_BYTES 74U

/*! \def ECDSAP521_RERANDOMIZATIONS
 * \brief four projective representation rerandomizations.
 */
#define ECDSAP521_RERANDOMIZATIONS 4U

/*! \def ECDSAP521_BLIND_MATERIAL_BYTES
 * \brief One 64-bit mask and four oversampled field rerandomizers.
 */
#define ECDSAP521_BLIND_MATERIAL_BYTES (8U + ECDSAP521_RERANDOMIZATIONS * ECDSAP521_RANDOM_FIELD_BYTES)

/*! \brief Little-endian native representation of the P-521 subgroup order.
 * \details Constant, immutable nine-word representation; no ownership.
 */
static const uint64_t ECDSAP521_N[ECDSAP521_LIMBS] = {UINT64_C(0xBB6FB71E91386409), UINT64_C(0x3BB5C9B8899C47AE), UINT64_C(0x7FCC0148F709A5D0),
	UINT64_C(0x51868783BF2F966B), UINT64_C(0xFFFFFFFFFFFFFFFA), UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_C(0x1FF)};

static inline ecdsap521_field ecdsap521_field_from_wide_bytes(const uint8_t* wide)
{
	ecdsap521_field result;
	uint64_t product[ECDSAP521_WIDE_LIMBS] = { 0U };
	size_t i;

	for (i = 0U; i != ECDSAP521_RANDOM_FIELD_BYTES; ++i)
	{
		product[i / 8U] |= (uint64_t)wide[ECDSAP521_RANDOM_FIELD_BYTES - 1U - i] << ((i & 7U) * 8U);
	}

	ecdsap521_redc(result.limbs, product);
	qsc_memutils_secure_erase(product, sizeof(product));

	return result;
}

static inline void ecdsap521_blind_scalar55(uint8_t* output, const uint8_t* scalar, const uint8_t* mask)
{
	uint64_t product[ECDSAP521_LIMBS];
	uint64_t words[ECDSAP521_LIMBS] = { 0U };
	uint64_t k;
	uint64_t low;
	uint64_t high;
	uint64_t carry;
	uint64_t addcarry;
	size_t i;

	k = UINT64_C(0);

	for (i = 0U; i != 8U; ++i)
	{
		k |= (uint64_t)mask[i] << (i * 8U);
	}

	k &= (UINT64_C(1) << ECDSAP521_BLIND_BITS) - UINT64_C(1);
	k |= (UINT64_C(1) << (ECDSAP521_BLIND_BITS - 1U)) | UINT64_C(1);

	for (i = 0U; i != 66U; ++i)
	{
		words[i / 8U] |= (uint64_t)scalar[65U - i] << ((i & 7U) * 8U);
	}

	carry = UINT64_C(0);

	for (i = 0U; i != ECDSAP521_LIMBS; ++i)
	{
		ecdsap521_mul_wide(&low, &high, k, ECDSAP521_N[i]);
		addcarry = UINT64_C(0);
		product[i] = ecdsap521_word_add(low, carry, &addcarry);
		carry = high + addcarry;
	}

	addcarry = UINT64_C(0);

	for (i = 0U; i != ECDSAP521_LIMBS; ++i)
	{
		product[i] = ecdsap521_word_add(product[i], words[i], &addcarry);
	}

	for (i = 0U; i != ECDSAP521_BLIND_BYTES; ++i)
	{
		output[ECDSAP521_BLIND_BYTES - 1U - i] = (uint8_t)(product[i / 8U] >> ((i & 7U) * 8U));
	}

	qsc_memutils_secure_erase(product, sizeof(product));
	qsc_memutils_secure_erase(words, sizeof(words));
	qsc_memutils_secure_erase(&k, sizeof(k));
}

static inline void ecdsap521_projective_randomize_rep(ecdsap521_projective_point* point, const ecdsap521_field* r)
{
	ecdsap521_field r2;
	ecdsap521_field r3;

	r2 = ecdsap521_square(r);
	r3 = ecdsap521_mul(&r2, r);
	point->x = ecdsap521_mul(&point->x, &r2);
	point->y = ecdsap521_mul(&point->y, &r3);
	point->z = ecdsap521_mul(&point->z, r);
}

static inline bool ecdsap521_basemul_booth_exec_blinded(ecdsap521_projective_point* result, const ecdsap521_affine_point* table, size_t table_count, const uint8_t* scalar, const uint8_t* randomness)
{
	ecdsap521_projective_point accum;
	ecdsap521_projective_point negated;
	ecdsap521_affine_point selected;
	ecdsap521_field rerand[ECDSAP521_RERANDOMIZATIONS];
	ecdsap521_booth_digit digit;
	uint8_t blinded[ECDSAP521_BLIND_BYTES] = { 0U };
	uint64_t raw;
	size_t i;
	size_t offset;
	bool success;

	success = false;

	if (result != NULL && table != NULL && scalar != NULL && randomness != NULL && table_count >= (97U * ECDSAP521_BASE_WINDOW_ELEMENTS))
	{
		ecdsap521_blind_scalar55(blinded, scalar, randomness);
		success = true;

		for (i = 0U; i != ECDSAP521_RERANDOMIZATIONS; ++i)
		{
			rerand[i] = ecdsap521_field_from_wide_bytes(randomness + 8U + i * ECDSAP521_RANDOM_FIELD_BYTES);

			if (ecdsap521_is_zero(&rerand[i]) != UINT64_C(0))
			{
				success = false;
			}
		}

		if (success == true)
		{
			raw = (ecdsap521_scalar_window7(blinded, sizeof(blinded), 0U) & UINT64_C(0x3F)) << 1U;
			digit = ecdsap521_booth_recode6(raw);
			selected = ecdsap521_affine_ct_select32(table, digit.digit);
			accum = ecdsap521_projective_from_affine(&selected);
			negated = accum;
			negated.y = ecdsap521_negate(&accum.y);
			ecdsap521_projective_conditional_assign(&accum, digit.negative, &negated);
			ecdsap521_projective_randomize_rep(&accum, &rerand[0U]);

			for (i = 1U; i != 97U; ++i)
			{
				offset = ECDSAP521_BASE_WINDOW_BITS * i - 1U;
				raw = ecdsap521_scalar_window7(blinded, sizeof(blinded), offset);
				digit = ecdsap521_booth_recode6(raw);
				selected = ecdsap521_affine_ct_select32(&table[ECDSAP521_BASE_WINDOW_ELEMENTS * i], digit.digit);
				accum = ecdsap521_point_add_or_sub_mixed(&accum, &selected, digit.negative, i >= 86U);

				if (i < ECDSAP521_RERANDOMIZATIONS)
				{
					ecdsap521_projective_randomize_rep(&accum, &rerand[i]);
				}
			}

			*result = accum;
			qsc_memutils_secure_erase(&accum, sizeof(accum));
			qsc_memutils_secure_erase(&negated, sizeof(negated));
			qsc_memutils_secure_erase(&selected, sizeof(selected));
		}
	}

	qsc_memutils_secure_erase(blinded, sizeof(blinded));
	qsc_memutils_secure_erase(rerand, sizeof(rerand));
	qsc_memutils_secure_erase(&digit, sizeof(digit));

	return success;
}

static inline bool ecdsap521_basemul_booth_exec_csp(ecdsap521_projective_point* result, const ecdsap521_affine_point* table, size_t table_count, const uint8_t* scalar)
{
	uint8_t randomness[ECDSAP521_BLIND_MATERIAL_BYTES] = { 0U };
	bool success;

	success = false;

	if (result != NULL && table != NULL && scalar != NULL && table_count >= 97U * ECDSAP521_BASE_WINDOW_ELEMENTS)
	{
		if (qsc_csp_generate(randomness, sizeof(randomness)) == true)
		{
			success = ecdsap521_basemul_booth_exec_blinded(result, table, table_count, scalar, randomness);
		}
	}

	qsc_memutils_secure_erase(randomness, sizeof(randomness));

	return success;
}

static inline bool ecdsap521_scalar_valid(const uint8_t* scalar)
{
	uint64_t words[ECDSAP521_LIMBS] = { 0U };
	uint64_t carry;
	uint64_t nonzero;
	size_t i;
	bool valid;

	for (i = 0U; i != 66U; ++i)
	{
		words[i / 8U] |= (uint64_t)scalar[65U - i] << ((i & 7U) * 8U);
	}

	carry = UINT64_C(0);
	nonzero = UINT64_C(0);

	for (i = 0U; i != ECDSAP521_LIMBS; ++i)
	{
		uint64_t ignored;

		ignored = ecdsap521_word_sub(words[i], ECDSAP521_N[i], &carry);
		(void)ignored;
		nonzero |= words[i];
	}

	valid = (carry != UINT64_C(0)) && (nonzero != UINT64_C(0));
	qsc_memutils_secure_erase(words, sizeof(words));

	return valid;
}

static inline bool ecdsap521_publickey_derive(uint8_t* publickey, const uint8_t* scalar, const ecdsap521_affine_point* table, size_t table_count, bool x_only)
{
	ecdsap521_projective_point point;
	ecdsap521_affine_point affine;
	ecdsap521_field inv2;
	uint8_t encoded[132U] = { 0U };
	size_t i;
	bool success;

	success = false;

	if (publickey != NULL && scalar != NULL && table != NULL && table_count >= (97U * ECDSAP521_BASE_WINDOW_ELEMENTS))
	{
		if (ecdsap521_scalar_valid(scalar) == true)
		{
			if (ecdsap521_basemul_booth_exec_csp(&point, table, table_count, scalar) == true)
			{
				if (x_only)
				{
					inv2 = ecdsap521_fe_invert2(&point.z);
					affine.x = ecdsap521_mul(&point.x, &inv2);
				}
				else
				{
					affine = ecdsap521_to_affine(&point);
				}

				for (i = 0U; i != 66U; ++i)
				{
					encoded[65U - i] = (uint8_t)(affine.x.limbs[i / 8U] >> ((i & 7U) * 8U));
				}

				if (!x_only)
				{
					for (i = 0U; i < 66U; ++i)
					{
						encoded[131U - i] = (uint8_t)(affine.y.limbs[i / 8U] >> ((i & 7U) * 8U));
					}
				}

				qsc_memutils_copy(publickey, encoded, x_only ? 66U : sizeof(encoded));
				success = true;
			}
		}
	}

	qsc_memutils_secure_erase(encoded, sizeof(encoded));
	qsc_memutils_secure_erase(&point, sizeof(point));
	qsc_memutils_secure_erase(&affine, sizeof(affine));
	qsc_memutils_secure_erase(&inv2, sizeof(inv2));

	return success;
}

static inline bool ecdsap521_keypair_derive(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed, const ecdsap521_affine_point* table, size_t table_count)
{
	uint8_t digest[64U] = { 0U };
	uint8_t scalar[66U] = { 0U };
	uint8_t derived[132U] = { 0U };
	uint64_t nonzero;
	size_t i;
	bool success;

	success = false;

	if (publickey != NULL && privatekey != NULL && seed != NULL && table != NULL && table_count >= (97U * ECDSAP521_BASE_WINDOW_ELEMENTS))
	{
		qsc_sha512_compute(digest, seed, 66U);
		qsc_memutils_copy(scalar + 2U, digest, sizeof(digest));
		nonzero = UINT64_C(0);

		for (i = 0U; i != sizeof(digest); ++i)
		{
			nonzero |= digest[i];
		}

		if (nonzero == UINT64_C(0))
		{
			scalar[65U] = 1U;
		}

		if (ecdsap521_publickey_derive(derived, scalar, table, table_count, false) == true)
		{
			qsc_memutils_copy(publickey, derived, sizeof(derived));
			qsc_memutils_copy(privatekey, seed, 66U);
			qsc_memutils_copy(privatekey + 66U, derived, sizeof(derived));
			success = true;
		}
	}

	qsc_memutils_secure_erase(digest, sizeof(digest));
	qsc_memutils_secure_erase(scalar, sizeof(scalar));
	qsc_memutils_secure_erase(derived, sizeof(derived));

	return success;
}

/*! \def ECDSAP521_SCALAR_MONT_P_DASH
 * \brief Negative inverse of the P-521 subgroup order's low word modulo 2^64.
 */
#define ECDSAP521_SCALAR_MONT_P_DASH UINT64_C(0x1D2F5CCD79A995C7)

/*! \brief P-521 subgroup-order scalar represented by nine Montgomery limbs.
 * \details Values are reduced modulo n and multiplied by 2^576 modulo n.
 */
typedef struct
{
	uint64_t limbs[ECDSAP521_LIMBS]; /*!< Little-endian Montgomery residue. */
} ecdsap521_scalar;

/*! \brief Montgomery constant R^2 modulo the P-521 subgroup order.
 * \details Immutable constant used in the conversion to Montgomery form.
 */
static const uint64_t ECDSAP521_SCALAR_R2[ECDSAP521_LIMBS] = {UINT64_C(0x137CD04DCF15DD04), UINT64_C(0xF707BADCE5547EA3), UINT64_C(0x12A78D38794573FF),
	UINT64_C(0xD3721EF557F75E06), UINT64_C(0xDD6E23D82E49C7DB), UINT64_C(0xCFF3D142B7756E3E), UINT64_C(0x5BCC6D61A8E567BC), UINT64_C(0x2D8E03D1492D0D45),
	UINT64_C(0x000000000000003D)};

/*! \brief Montgomery constant R^3 modulo the P-521 subgroup order.
 * \details Immutable constant used for conversion of 18-limb scalars.
 */
static const uint64_t ECDSAP521_SCALAR_R3[ECDSAP521_LIMBS] = {UINT64_C(0xD35F2816760F23E2), UINT64_C(0x2767143C8C3184C1), UINT64_C(0xB268AD5BAC58D935),
	UINT64_C(0x3F3DEB9609930765), UINT64_C(0x6D4AF6CB8E6B92EA), UINT64_C(0xDF0F66F966E917A0), UINT64_C(0xC99C43FC5F7321CE), UINT64_C(0xDB25B1117A1814FD),
	UINT64_C(0x0000000000000097)};

static inline void ecdsap521_scalar_accum_add(ecdsap521_accumulator* accum, uint64_t word)
{
#if !defined(QSC_ECDSAP521_FORCE_PORTABLE) && !defined(_M_ARM64EC) && !defined(_MSC_VER) && (defined(__GNUC__) || defined(__clang__)) &&                       \
	(defined(__x86_64__) || defined(__amd64__))
	__asm__("addq %[word],%[w0]\n\t"
			"adcq $0,%[w1]\n\t"
			"adcq $0,%[w2]"
			: [w0] "+&r"(accum->w0), [w1] "+&r"(accum->w1), [w2] "+&r"(accum->w2)
			: [word] "r"(word)
			: "cc");
#else
	uint64_t carry;

	carry = 0U;
	accum->w0 = ecdsap521_word_add(accum->w0, word, &carry);
	accum->w1 = ecdsap521_word_add(accum->w1, UINT64_C(0), &carry);
	accum->w2 += carry;
#endif
}

static inline uint64_t ecdsap521_scalar_monty_step(ecdsap521_accumulator* accum)
{
	uint64_t result;

	result = accum->w0 * ECDSAP521_SCALAR_MONT_P_DASH;
	ecdsap521_accum_mul(accum, result, ECDSAP521_N[0U]);
	(void)ecdsap521_accum_extract(accum);

	return result;
}

static inline void ecdsap521_scalar_maybe_sub(uint64_t* output, uint64_t high, const uint64_t* x)
{
	uint64_t borrow;
	uint64_t mask;
	size_t i;

	borrow = 0U;

	for (i = 0U; i != ECDSAP521_LIMBS; ++i)
	{
		output[i] = ecdsap521_word_sub(x[i], ECDSAP521_N[i], &borrow);
	}

	borrow = (uint64_t)((high - borrow) > high);
	mask = ecdsap521_mask_barrier(UINT64_C(0) - borrow);

	for (i = 0U; i != ECDSAP521_LIMBS; ++i)
	{
		output[i] = (output[i] & ~mask) | (x[i] & mask);
	}
}

static inline void ecdsap521_scalar_monty_redc(uint64_t* output, const uint64_t* z)
{
	ecdsap521_accumulator accum = {0U, 0U, 0U};
	uint64_t workspace[ECDSAP521_LIMBS];
	uint64_t high;
	size_t i;
	size_t j;

	ecdsap521_scalar_accum_add(&accum, z[0U]);
	workspace[0U] = ecdsap521_scalar_monty_step(&accum);

	for (i = 1U; i != ECDSAP521_LIMBS; ++i)
	{
		for (j = 0U; j != i; ++j)
		{
			ecdsap521_accum_mul(&accum, workspace[j], ECDSAP521_N[i - j]);
		}

		ecdsap521_scalar_accum_add(&accum, z[i]);
		workspace[i] = ecdsap521_scalar_monty_step(&accum);
	}

	for (i = 0U; i != ECDSAP521_LIMBS - 1U; ++i)
	{
		for (j = i + 1U; j != ECDSAP521_LIMBS; ++j)
		{
			ecdsap521_accum_mul(&accum, workspace[j], ECDSAP521_N[ECDSAP521_LIMBS + i - j]);
		}

		ecdsap521_scalar_accum_add(&accum, z[ECDSAP521_LIMBS + i]);
		workspace[i] = ecdsap521_accum_extract(&accum);
	}

	ecdsap521_scalar_accum_add(&accum, z[ECDSAP521_WIDE_LIMBS - 1U]);
	workspace[ECDSAP521_LIMBS - 1U] = ecdsap521_accum_extract(&accum);
	high = ecdsap521_accum_extract(&accum);
	ecdsap521_scalar_maybe_sub(output, high, workspace);
}

static inline ecdsap521_scalar ecdsap521_scalar_to_rep(const uint64_t* x)
{
	ecdsap521_scalar result;
	uint64_t z[ECDSAP521_WIDE_LIMBS];

	ecdsap521_comba_mul9(z, x, ECDSAP521_SCALAR_R2);
	ecdsap521_scalar_monty_redc(result.limbs, z);

	return result;
}

static inline ecdsap521_scalar ecdsap521_scalar_wide_to_rep(const uint64_t* x)
{
	ecdsap521_scalar result;
	uint64_t reduced[ECDSAP521_LIMBS];
	uint64_t z[ECDSAP521_WIDE_LIMBS];

	ecdsap521_scalar_monty_redc(reduced, x);
	ecdsap521_comba_mul9(z, reduced, ECDSAP521_SCALAR_R3);
	ecdsap521_scalar_monty_redc(result.limbs, z);

	return result;
}

static inline void ecdsap521_scalar_from_rep(uint64_t* output, const ecdsap521_scalar* x)
{
	uint64_t z[ECDSAP521_WIDE_LIMBS] = { 0U };
	size_t i;

	for (i = 0U; i != ECDSAP521_LIMBS; ++i)
	{
		z[i] = x->limbs[i];
	}

	ecdsap521_scalar_monty_redc(output, z);
}

static inline ecdsap521_scalar ecdsap521_scalar_add(const ecdsap521_scalar* a, const ecdsap521_scalar* b)
{
	ecdsap521_scalar result;
	uint64_t t[ECDSAP521_LIMBS];
	uint64_t carry;
	size_t i;

	carry = UINT64_C(0);

	for (i = 0U; i != ECDSAP521_LIMBS; ++i)
	{
		t[i] = ecdsap521_word_add(a->limbs[i], b->limbs[i], &carry);
	}

	ecdsap521_scalar_maybe_sub(result.limbs, carry, t);

	return result;
}

static inline ecdsap521_scalar ecdsap521_scalar_mul(const ecdsap521_scalar* a, const ecdsap521_scalar* b)
{
	ecdsap521_scalar result;
	uint64_t z[ECDSAP521_WIDE_LIMBS];

	ecdsap521_comba_mul9(z, a->limbs, b->limbs);
	ecdsap521_scalar_monty_redc(result.limbs, z);

	return result;
}

static inline ecdsap521_scalar* ecdsap521_scalar_mul_assign(ecdsap521_scalar* a, const ecdsap521_scalar* b)
{
	uint64_t z[ECDSAP521_WIDE_LIMBS];

	ecdsap521_comba_mul9(z, a->limbs, b->limbs);
	ecdsap521_scalar_monty_redc(a->limbs, z);

	return a;
}

static inline ecdsap521_scalar ecdsap521_scalar_square(const ecdsap521_scalar* x)
{
	ecdsap521_scalar result;
	uint64_t z[ECDSAP521_WIDE_LIMBS];

	ecdsap521_comba_sqr9(z, x->limbs);
	ecdsap521_scalar_monty_redc(result.limbs, z);

	return result;
}

static inline void ecdsap521_scalar_square_n(ecdsap521_scalar* x, size_t n)
{
	uint64_t z[ECDSAP521_WIDE_LIMBS];
	size_t i;

	for (i = 0U; i != n; ++i)
	{
		ecdsap521_comba_sqr9(z, x->limbs);
		ecdsap521_scalar_monty_redc(x->limbs, z);
	}
}

static inline ecdsap521_scalar ecdsap521_scalar_invert(const ecdsap521_scalar* x)
{
	ecdsap521_scalar z;
	ecdsap521_scalar t0;
	ecdsap521_scalar t1;
	ecdsap521_scalar t2;
	ecdsap521_scalar t3;
	ecdsap521_scalar t4;
	ecdsap521_scalar t5;
	ecdsap521_scalar t6;
	ecdsap521_scalar t7;
	ecdsap521_scalar t8;
	ecdsap521_scalar t9;
	ecdsap521_scalar t10;
	ecdsap521_scalar t11;
	ecdsap521_scalar t12;
	ecdsap521_scalar t13;
	ecdsap521_scalar t14;
	ecdsap521_scalar t15;
	ecdsap521_scalar t16;
	ecdsap521_scalar t17;
	ecdsap521_scalar t18;
	ecdsap521_scalar t19;
	ecdsap521_scalar t20;

	t2 = ecdsap521_scalar_square(x);
	t13 = ecdsap521_scalar_mul(&t2, x);
	t4 = ecdsap521_scalar_mul(&t13, x);
	z = ecdsap521_scalar_mul(&t13, &t4);
	t5 = ecdsap521_scalar_mul(x, &z);
	t16 = ecdsap521_scalar_mul(&t13, &t5);
	t10 = ecdsap521_scalar_mul(&t16, &t2);
	t18 = ecdsap521_scalar_mul(&t10, &t2);
	t1 = ecdsap521_scalar_mul(&t18, &t2);
	t12 = ecdsap521_scalar_mul(&t1, &t2);
	t15 = ecdsap521_scalar_mul(&t12, &t4);
	t0 = ecdsap521_scalar_mul(&t15, &t2);
	t3 = ecdsap521_scalar_mul(&t0, &t2);
	t6 = ecdsap521_scalar_mul(&t2, &t3);
	t11 = ecdsap521_scalar_mul(&t5, &t6);
	t14 = ecdsap521_scalar_mul(&t11, &t4);
	t9 = ecdsap521_scalar_mul(&t14, &t4);
	t17 = ecdsap521_scalar_mul(&t2, &t9);
	t7 = ecdsap521_scalar_mul(&t17, &t4);
	(void)ecdsap521_scalar_mul_assign(&t4, &t7);
	t8 = ecdsap521_scalar_mul(&t2, &t4);
	t5 = ecdsap521_scalar_mul(&t2, &t8);
	(void)ecdsap521_scalar_mul_assign(&t2, &t5);
	t19 = t2;
	ecdsap521_scalar_square_n(&t19, 3U);
	(void)ecdsap521_scalar_mul_assign(&t15, &t19);
	t19 = ecdsap521_scalar_square(&t15);
	t20 = t19;
	ecdsap521_scalar_square_n(&t20, 8U);
	(void)ecdsap521_scalar_mul_assign(&t20, &t15);
	ecdsap521_scalar_square_n(&t20, 10U);
	(void)ecdsap521_scalar_mul_assign(&t19, &t20);
	t20 = t19;
	ecdsap521_scalar_square_n(&t20, 8U);
	(void)ecdsap521_scalar_mul_assign(&t20, &t15);
	ecdsap521_scalar_square_n(&t20, 28U);
	(void)ecdsap521_scalar_mul_assign(&t19, &t20);
	t20 = t19;
	ecdsap521_scalar_square_n(&t20, 63U);
	(void)ecdsap521_scalar_mul_assign(&t19, &t20);
	t20 = t19;
	ecdsap521_scalar_square_n(&t20, 8U);
	(void)ecdsap521_scalar_mul_assign(&t20, &t15);
	ecdsap521_scalar_square_n(&t20, 127U);
	(void)ecdsap521_scalar_mul_assign(&t19, &t20);
	(void)ecdsap521_scalar_mul_assign(&t19, x);
	ecdsap521_scalar_square_n(&t19, 7U);
	(void)ecdsap521_scalar_mul_assign(&t19, &t11);
	ecdsap521_scalar_square_n(&t19, 5U);
	(void)ecdsap521_scalar_mul_assign(&t19, &t13);
	ecdsap521_scalar_square_n(&t19, 8U);
	(void)ecdsap521_scalar_mul_assign(&t19, &t10);
	ecdsap521_scalar_square_n(&t19, 8U);
	(void)ecdsap521_scalar_mul_assign(&t19, &t18);
	ecdsap521_scalar_square_n(&t19, 11U);
	(void)ecdsap521_scalar_mul_assign(&t19, &t5);
	ecdsap521_scalar_square_n(&t19, 4U);
	(void)ecdsap521_scalar_mul_assign(&t18, &t19);
	ecdsap521_scalar_square_n(&t18, 8U);
	(void)ecdsap521_scalar_mul_assign(&t17, &t18);
	ecdsap521_scalar_square_n(&t17, 6U);
	(void)ecdsap521_scalar_mul_assign(&t17, &t11);
	ecdsap521_scalar_square_n(&t17, 5U);
	(void)ecdsap521_scalar_mul_assign(&t17, &t12);
	ecdsap521_scalar_square_n(&t17, 5U);
	(void)ecdsap521_scalar_mul_assign(&t16, &t17);
	ecdsap521_scalar_square_n(&t16, 10U);
	(void)ecdsap521_scalar_mul_assign(&t15, &t16);
	ecdsap521_scalar_square_n(&t15, 4U);
	(void)ecdsap521_scalar_mul_assign(&t15, &t13);
	ecdsap521_scalar_square_n(&t15, 15U);
	(void)ecdsap521_scalar_mul_assign(&t14, &t15);
	ecdsap521_scalar_square_n(&t14, 9U);
	(void)ecdsap521_scalar_mul_assign(&t14, &t2);
	ecdsap521_scalar_square_n(&t14, 2U);
	(void)ecdsap521_scalar_mul_assign(&t13, &t14);
	ecdsap521_scalar_square_n(&t13, 9U);
	(void)ecdsap521_scalar_mul_assign(&t12, &t13);
	ecdsap521_scalar_square_n(&t12, 7U);
	(void)ecdsap521_scalar_mul_assign(&t11, &t12);
	ecdsap521_scalar_square_n(&t11, 4U);
	(void)ecdsap521_scalar_mul_assign(&t10, &t11);
	ecdsap521_scalar_square_n(&t10, 12U);
	(void)ecdsap521_scalar_mul_assign(&t10, &t5);
	ecdsap521_scalar_square_n(&t10, 6U);
	(void)ecdsap521_scalar_mul_assign(&t9, &t10);
	ecdsap521_scalar_square_n(&t9, 7U);
	(void)ecdsap521_scalar_mul_assign(&t8, &t9);
	ecdsap521_scalar_square_n(&t8, 8U);
	(void)ecdsap521_scalar_mul_assign(&t8, &t4);
	ecdsap521_scalar_square_n(&t8, 8U);
	(void)ecdsap521_scalar_mul_assign(&t8, &t1);
	ecdsap521_scalar_square_n(&t8, 8U);
	(void)ecdsap521_scalar_mul_assign(&t7, &t8);
	ecdsap521_scalar_square_n(&t7, 5U);
	(void)ecdsap521_scalar_mul_assign(&t7, &t1);
	ecdsap521_scalar_square_n(&t7, 9U);
	(void)ecdsap521_scalar_mul_assign(&t7, &t2);
	ecdsap521_scalar_square_n(&t7, 6U);
	(void)ecdsap521_scalar_mul_assign(&t6, &t7);
	ecdsap521_scalar_square_n(&t6, 7U);
	(void)ecdsap521_scalar_mul_assign(&t5, &t6);
	ecdsap521_scalar_square_n(&t5, 7U);
	(void)ecdsap521_scalar_mul_assign(&t4, &t5);
	ecdsap521_scalar_square_n(&t4, 5U);
	(void)ecdsap521_scalar_mul_assign(&t3, &t4);
	ecdsap521_scalar_square_n(&t3, 4U);
	(void)ecdsap521_scalar_mul_assign(&t3, &z);
	ecdsap521_scalar_square_n(&t3, 9U);
	(void)ecdsap521_scalar_mul_assign(&t2, &t3);
	ecdsap521_scalar_square_n(&t2, 7U);
	(void)ecdsap521_scalar_mul_assign(&t1, &t2);
	ecdsap521_scalar_square_n(&t1, 5U);
	(void)ecdsap521_scalar_mul_assign(&t1, &z);
	ecdsap521_scalar_square_n(&t1, 9U);
	(void)ecdsap521_scalar_mul_assign(&t0, &t1);
	ecdsap521_scalar_square_n(&t0, 10U);
	(void)ecdsap521_scalar_mul_assign(&z, &t0);

	return z;
}

static inline bool ecdsap521_scalar_deserialize(ecdsap521_scalar* output, const uint8_t* input, size_t length)
{
	uint64_t words[ECDSAP521_LIMBS];
	uint64_t borrow;
	size_t i;
	bool success;

	success = false;

	if ((output != NULL) && (input != NULL) && (length == 66U))
	{
		for (i = 0U; i != ECDSAP521_LIMBS - 1U; ++i)
		{
			words[i] = qsc_intutils_be8to64(input + 58U - (i * 8U));
		}

		words[ECDSAP521_LIMBS - 1U] = ((uint64_t)input[0U] << 8U) | (uint64_t)input[1U];
		borrow = UINT64_C(0);

		for (i = 0U; i != ECDSAP521_LIMBS; ++i)
		{
			(void)ecdsap521_word_sub(words[i], ECDSAP521_N[i], &borrow);
		}

		if (borrow != UINT64_C(0))
		{
			*output = ecdsap521_scalar_to_rep(words);
			success = true;
		}

		qsc_memutils_secure_erase(words, sizeof(words));
	}

	return success;
}

static inline void ecdsap521_scalar_serialize(uint8_t* output, const ecdsap521_scalar* scalar)
{
	uint64_t words[ECDSAP521_LIMBS];
	size_t i;

	ecdsap521_scalar_from_rep(words, scalar);
	output[0U] = (uint8_t)(words[ECDSAP521_LIMBS - 1U] >> 8U);
	output[1U] = (uint8_t)words[ECDSAP521_LIMBS - 1U];

	for (i = 0U; i != ECDSAP521_LIMBS - 1U; ++i)
	{
		qsc_intutils_be64to8(output + 2U + (i * 8U), words[ECDSAP521_LIMBS - 2U - i]);
	}

	qsc_memutils_secure_erase(words, sizeof(words));
}

static inline bool ecdsap521_scalar_from_wide_bytes(ecdsap521_scalar* output, const uint8_t* input, size_t length)
{
	uint64_t wide[ECDSAP521_WIDE_LIMBS] = {UINT64_C(0)};
	size_t i;
	bool success;

	success = false;

	if ((output != NULL) && (length <= 132U) && ((input != NULL) || (length == 0U)))
	{
		for (i = 0U; i != length; ++i)
		{
			wide[i / 8U] |= (uint64_t)input[length - 1U - i] << ((i & 7U) * 8U);
		}

		*output = ecdsap521_scalar_wide_to_rep(wide);
		success = true;
		qsc_memutils_secure_erase(wide, sizeof(wide));
	}

	return success;
}

static inline uint64_t ecdsap521_scalar_is_zero(const ecdsap521_scalar* scalar)
{
	uint64_t accumulator;
	size_t i;

	accumulator = UINT64_C(0);

	for (i = 0U; i != ECDSAP521_LIMBS; ++i)
	{
		accumulator |= scalar->limbs[i];
	}

	return UINT64_C(1) ^ ((accumulator | (UINT64_C(0) - accumulator)) >> 63U);
}

static inline bool ecdsap521_ecdsa_sign_core(uint8_t* signature, const uint8_t* private_scalar, const uint8_t* nonce_scalar, const uint8_t* nonce_x, const uint8_t* digest, const uint8_t* blinder)
{
	ecdsap521_scalar d;
	ecdsap521_scalar k;
	ecdsap521_scalar b;
	ecdsap521_scalar r;
	ecdsap521_scalar s;
	ecdsap521_scalar m;
	ecdsap521_scalar k_inv;
	ecdsap521_scalar xr_m;
	ecdsap521_scalar t0;
	ecdsap521_scalar t1;
	uint8_t temporary[132U];
	bool success;

	success = false;

	if ((signature != NULL) && (private_scalar != NULL) && (nonce_scalar != NULL) && (nonce_x != NULL) && (digest != NULL) && (blinder != NULL))
	{
		if (ecdsap521_scalar_deserialize(&d, private_scalar, 66U) && ecdsap521_scalar_deserialize(&k, nonce_scalar, 66U) &&
			ecdsap521_scalar_deserialize(&b, blinder, 66U))
		{
			if ((ecdsap521_scalar_is_zero(&d) == UINT64_C(0)) && (ecdsap521_scalar_is_zero(&k) == UINT64_C(0)) && (ecdsap521_scalar_is_zero(&b) == UINT64_C(0)))
			{
				if (ecdsap521_scalar_from_wide_bytes(&r, nonce_x, 66U) && ecdsap521_scalar_from_wide_bytes(&m, digest, 64U))
				{
					if (ecdsap521_scalar_is_zero(&r) == UINT64_C(0))
					{
						t0 = ecdsap521_scalar_mul(&b, &k);
						k_inv = ecdsap521_scalar_invert(&t0);
						t0 = ecdsap521_scalar_mul(&d, &b);
						t0 = ecdsap521_scalar_mul(&t0, &r);
						t1 = ecdsap521_scalar_mul(&m, &b);
						xr_m = ecdsap521_scalar_add(&t0, &t1);
						s = ecdsap521_scalar_mul(&k_inv, &xr_m);

						if (ecdsap521_scalar_is_zero(&s) == UINT64_C(0))
						{
							ecdsap521_scalar_serialize(temporary, &r);
							ecdsap521_scalar_serialize(temporary + 66U, &s);
							qsc_memutils_copy(signature, temporary, sizeof(temporary));
							success = true;
						}
					}
				}
			}
		}
	}

	qsc_memutils_secure_erase(&d, sizeof(d));
	qsc_memutils_secure_erase(&k, sizeof(k));
	qsc_memutils_secure_erase(&b, sizeof(b));
	qsc_memutils_secure_erase(&r, sizeof(r));
	qsc_memutils_secure_erase(&s, sizeof(s));
	qsc_memutils_secure_erase(&m, sizeof(m));
	qsc_memutils_secure_erase(&k_inv, sizeof(k_inv));
	qsc_memutils_secure_erase(&xr_m, sizeof(xr_m));
	qsc_memutils_secure_erase(&t0, sizeof(t0));
	qsc_memutils_secure_erase(&t1, sizeof(t1));
	qsc_memutils_secure_erase(temporary, sizeof(temporary));

	return success;
}

/* The generator is defined with the public SEC 2 P-521 coordinates.
 * No separate 32-bit scalar or field arithmetic backend is required. */

/*! \brief Public SEC 2 P-521 generator x-coordinate in seventeen 32-bit limbs.
 * \details Little-endian limbs; constant and shared read-only.
 */
static const uint32_t ECDSAP521_GX[17U] = {0xC2E5BD66U, 0xF97E7E31U, 0x856A429BU, 0x3348B3C1U, 0xA2FFA8DEU, 0xFE1DC127U, 0xEFE75928U, 0xA14B5E77U, 0x6B4D3DBAU,
	0xF828AF60U, 0x053FB521U, 0x9C648139U, 0x2395B442U, 0x9E3ECB66U, 0x0404E9CDU, 0x858E06B7U, 0x000000C6U};

/*! \brief Public SEC 2 P-521 generator y-coordinate in seventeen 32-bit limbs.
 * \details Little-endian limbs; constant and shared read-only.
 */
static const uint32_t ECDSAP521_GY[17U] = {0x9FD16650U, 0x88BE9476U, 0xA272C240U, 0x353C7086U, 0x3FAD0761U, 0xC550B901U, 0x5EF42640U, 0x97EE7299U, 0x273E662CU,
	0x17AFBD17U, 0x579B4468U, 0x98F54449U, 0x2C7D1BD9U, 0x5C8A5FB4U, 0x9A3BC004U, 0x39296A78U, 0x00000118U};

static void ecdsap521_nonce_digest_encode(uint8_t out[66U], const uint8_t hash_be[64U])
{
	out[0U] = 0U;
	out[1U] = 0U;
	qsc_memutils_copy(out + 2U, hash_be, 64U);
}

static void ecdsap521_nonce_generate(uint8_t k_out[66U], const uint8_t priv_be[66U], const uint8_t h1_be[64U])
{
	uint8_t V[64U];
	uint8_t K[64U];
	uint8_t bh[66U];
	uint8_t blob[133U];
	uint8_t T[66U];
	uint8_t msg[197U];
	uint8_t mac[64U];
	uint32_t i;

	ecdsap521_nonce_digest_encode(bh, h1_be);

	for (i = 0U; i < 64U; ++i)
	{
		V[i] = 0x01U;
		K[i] = 0x00U;
	}

	blob[0U] = 0x00U;
	qsc_memutils_copy(blob + 1U, priv_be, 66U);
	qsc_memutils_copy(blob + 67U, bh, 66U);

	qsc_memutils_copy(msg, V, 64U);
	qsc_memutils_copy(msg + 64U, blob, 133U);
	qsc_hmac512_compute(mac, msg, sizeof(msg), K, sizeof(K));
	qsc_memutils_copy(K, mac, 64U);

	qsc_hmac512_compute(mac, V, sizeof(V), K, sizeof(K));
	qsc_memutils_copy(V, mac, 64U);

	blob[0U] = 0x01U;
	qsc_memutils_copy(msg, V, 64U);
	qsc_memutils_copy(msg + 64U, blob, 133U);
	qsc_hmac512_compute(mac, msg, sizeof(msg), K, sizeof(K));
	qsc_memutils_copy(K, mac, 64U);

	qsc_hmac512_compute(mac, V, sizeof(V), K, sizeof(K));
	qsc_memutils_copy(V, mac, 64U);

	for (;;)
	{
		qsc_hmac512_compute(mac, V, sizeof(V), K, sizeof(K));
		qsc_memutils_copy(V, mac, 64U);
		qsc_memutils_copy(T, V, 64U);

		qsc_hmac512_compute(mac, V, sizeof(V), K, sizeof(K));
		qsc_memutils_copy(V, mac, 64U);
		T[64U] = V[0U];
		T[65U] = V[1U];

		/*
         * RFC 6979 bits2int(T) for qlen = 521 and tlen = 528
         * is the leftmost 521 bits of T, which is equivalent to
         * shifting the 528-bit candidate right by 7 bits.
         */
		{
			uint8_t t521[66U];
			uint32_t carry;

			carry = 0U;

			for (i = 0U; i < 66U; ++i)
			{
				uint32_t cur;

				cur = T[i];
				t521[i] = (uint8_t)((cur >> 7U) | carry);
				carry = (cur & 0x7FU) << 1U;
			}

			qsc_memutils_copy(k_out, t521, sizeof(t521));
			qsc_memutils_secure_erase(t521, sizeof(t521));
		}

		if (ecdsap521_scalar_valid(k_out) == true)
		{
			break;
		}

		qsc_memutils_copy(msg, V, 64U);
		msg[64U] = 0x00U;
		qsc_hmac512_compute(mac, msg, 65U, K, sizeof(K));
		qsc_memutils_copy(K, mac, 64U);

		qsc_hmac512_compute(mac, V, sizeof(V), K, sizeof(K));
		qsc_memutils_copy(V, mac, 64U);
	}

	qsc_memutils_secure_erase(V, sizeof(V));
	qsc_memutils_secure_erase(K, sizeof(K));
	qsc_memutils_secure_erase(bh, sizeof(bh));
	qsc_memutils_secure_erase(blob, sizeof(blob));
	qsc_memutils_secure_erase(T, sizeof(T));
	qsc_memutils_secure_erase(msg, sizeof(msg));
	qsc_memutils_secure_erase(mac, sizeof(mac));
}

/*! \def ECDSAP521_GENERATOR_TABLE_CAPACITY
 * \brief Number of affine entries in the immutable-after-initialization P-521 Booth table.
 */
#define ECDSAP521_GENERATOR_TABLE_CAPACITY 3104U

/*! \brief Public fixed-generator table, populated only during guarded first use.
 * \details State 2 publishes immutable entries via a sequentially consistent atomic store.
 */
static ecdsap521_affine_point ecdsap521_generator_table[ECDSAP521_GENERATOR_TABLE_CAPACITY];

/*! \brief Atomic initialization state for the public generator table.
 * \details 0=uninitialized; 1=building; 2=ready; 3=failed. Access only via QSC atomic functions.
 */
static volatile int32_t ecdsap521_generator_table_state = 0;

static bool ecdsap521_generator_table_initialize(void)
{
	ecdsap521_projective_point* projective;
	ecdsap521_field* scratch;
	ecdsap521_affine_point generator;
	int32_t state;
	size_t i;
	bool ready;

	state = qsc_async_atomic_int32_load(&ecdsap521_generator_table_state);
	ready = (state == 2);

	if (state == 0)
	{
		if (qsc_async_atomic_int32_compare_exchange(&ecdsap521_generator_table_state, 0, 1) == true)
		{
			projective = (ecdsap521_projective_point*)qsc_memutils_calloc(ECDSAP521_GENERATOR_TABLE_CAPACITY, sizeof(ecdsap521_projective_point));
			scratch = (ecdsap521_field*)qsc_memutils_calloc(ECDSAP521_GENERATOR_TABLE_CAPACITY, sizeof(ecdsap521_field));
			ready = false;

			if (projective != NULL && scratch != NULL)
			{
				for (i = 0U; i != 8U; ++i)
				{
					generator.x.limbs[i] = ((uint64_t)ECDSAP521_GX[2U * i + 1U] << 32U) | ECDSAP521_GX[2U * i];
					generator.y.limbs[i] = ((uint64_t)ECDSAP521_GY[2U * i + 1U] << 32U) | ECDSAP521_GY[2U * i];
				}

				generator.x.limbs[8U] = ECDSAP521_GX[16U];
				generator.y.limbs[8U] = ECDSAP521_GY[16U];
				ready = ecdsap521_basemul_booth_setup(ecdsap521_generator_table, ECDSAP521_GENERATOR_TABLE_CAPACITY, projective,
					ECDSAP521_GENERATOR_TABLE_CAPACITY, scratch, ECDSAP521_GENERATOR_TABLE_CAPACITY, &generator, 577U);
			}

			if (projective != NULL)
			{
				qsc_memutils_alloc_free(projective);
			}

			if (scratch != NULL)
			{
				qsc_memutils_alloc_free(scratch);
			}

			qsc_async_atomic_int32_store(&ecdsap521_generator_table_state, ready == true ? 2 : 3);
		}
		else
		{
			state = 1;
		}
	}

	if (state == 1)
	{
		do
		{
			qsc_async_thread_sleep(1U);
			state = qsc_async_atomic_int32_load(&ecdsap521_generator_table_state);
		} while (state == 1);

		ready = (state == 2);
	}

	return ready;
}

int32_t qsc_ecdsap521_publickey_from_privatekey(uint8_t* publickey, const uint8_t* privatekey)
{
	int32_t result;

	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(privatekey != NULL);

	result = -1;

	if (publickey != NULL && privatekey != NULL)
	{
		if (ecdsap521_scalar_valid(privatekey) == true)
		{
			if (ecdsap521_generator_table_initialize() == true)
			{
				if (ecdsap521_publickey_derive(publickey, privatekey, ecdsap521_generator_table, ECDSAP521_GENERATOR_TABLE_CAPACITY, false) == true)
				{
					result = 0;
				}
			}
		}
	}

	return result;
}

int32_t qsc_ecdsap521_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed)
{
	int32_t result;

	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(seed != NULL);

	result = -1;

	if (publickey != NULL && privatekey != NULL && seed != NULL)
	{
		if (ecdsap521_generator_table_initialize() == true)
		{
			if (ecdsap521_keypair_derive(publickey, privatekey, seed, ecdsap521_generator_table, ECDSAP521_GENERATOR_TABLE_CAPACITY) == true)
			{
				result = 0;
			}
		}
	}

	return result;
}

static int32_t ecdsap521_sign_with_scalar(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* scalar)
{
	uint8_t digest[64U] = { 0U };
	uint8_t nbyt[66U] = { 0U };
	uint8_t npt[66U] = { 0U };
	uint8_t brnd[66U] = { 0U };
	uint8_t bbyt[66U] = { 0U };
	uint8_t signature[132U] = { 0U };
	ecdsap521_scalar blinder = {{ 0U }};
	int32_t result;

	result = -1;

	if (smsglen != NULL)
	{
		*smsglen = 0U;
	}

	if ((signedmsg != NULL) && (smsglen != NULL) && (message != NULL) && (scalar != NULL) && (msglen <= SIZE_MAX - EC_NISTP521_SIGNATURE_SIZE))
	{
		if (ecdsap521_scalar_valid(scalar) == true)
		{
			if (ecdsap521_generator_table_initialize() == true)
			{
				qsc_sha512_compute(digest, message, msglen);
				ecdsap521_nonce_generate(nbyt, scalar, digest);

				if (ecdsap521_publickey_derive(npt, nbyt, ecdsap521_generator_table, ECDSAP521_GENERATOR_TABLE_CAPACITY, true) == true)
				{
					if (qsc_csp_generate(brnd, sizeof(brnd)) == true)
					{
						if (ecdsap521_scalar_from_wide_bytes(&blinder, brnd, sizeof(brnd)) == true)
						{
							if (ecdsap521_scalar_is_zero(&blinder) == UINT64_C(0))
							{
								ecdsap521_scalar_serialize(bbyt, &blinder);

								if (ecdsap521_ecdsa_sign_core(signature, scalar, nbyt, npt, digest, bbyt) == true)
								{
									qsc_memutils_copy(signedmsg + EC_NISTP521_SIGNATURE_SIZE, message, msglen);
									qsc_memutils_copy(signedmsg, signature, sizeof(signature));
									*smsglen = msglen + EC_NISTP521_SIGNATURE_SIZE;
									result = 0;
								}
							}
						}
					}
				}
			}
		}
	}

	qsc_memutils_secure_erase(digest, sizeof(digest));
	qsc_memutils_secure_erase(nbyt, sizeof(nbyt));
	qsc_memutils_secure_erase(npt, sizeof(npt));
	qsc_memutils_secure_erase(brnd, sizeof(brnd));
	qsc_memutils_secure_erase(bbyt, sizeof(bbyt));
	qsc_memutils_secure_erase(signature, sizeof(signature));
	qsc_memutils_secure_erase(&blinder, sizeof(blinder));

	return result;
}

int32_t qsc_ecdsap521_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey)
{
	uint8_t digest[64U] = { 0U };
	uint8_t scalar[66U] = { 0U };
	uint64_t nonzero;
	size_t i;
	int32_t result;

	QSC_ASSERT(signedmsg != NULL);
	QSC_ASSERT(smsglen != NULL);
	QSC_ASSERT(message != NULL);
	QSC_ASSERT(privatekey != NULL);

	result = -1;

	if (smsglen != NULL)
	{
		*smsglen = 0U;
	}

	if ((signedmsg != NULL) && (smsglen != NULL) && (message != NULL) && (privatekey != NULL) && (msglen <= SIZE_MAX - EC_NISTP521_SIGNATURE_SIZE))
	{
		qsc_sha512_compute(digest, privatekey, EC_NISTP521_SEED_SIZE);
		qsc_memutils_copy(scalar + 2U, digest, sizeof(digest));
		nonzero = UINT64_C(0);

		for (i = 0U; i != sizeof(digest); ++i)
		{
			nonzero |= digest[i];
		}

		if (nonzero != UINT64_C(0))
		{
			result = ecdsap521_sign_with_scalar(signedmsg, smsglen, message, msglen, scalar);
		}
		else
		{
			result = -2;
		}
	}

	qsc_memutils_secure_erase(digest, sizeof(digest));
	qsc_memutils_secure_erase(scalar, sizeof(scalar));

	return result;
}

int32_t qsc_ecdsap521_sign_scalar(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey)
{
	uint64_t nonzero;
	size_t i;
	int32_t result;

	QSC_ASSERT(signedmsg != NULL);
	QSC_ASSERT(smsglen != NULL);
	QSC_ASSERT(message != NULL);
	QSC_ASSERT(privatekey != NULL);

	result = -1;

	if (smsglen != NULL)
	{
		*smsglen = 0U;
	}

	if ((signedmsg != NULL) && (smsglen != NULL) && (message != NULL) && (privatekey != NULL))
	{
		nonzero = UINT64_C(0);

		for (i = 0U; i != 66U; ++i)
		{
			nonzero |= privatekey[i];
		}

		if (nonzero != UINT64_C(0))
		{
			result = ecdsap521_sign_with_scalar(signedmsg, smsglen, message, msglen, privatekey);
		}
		else
		{
			result = -2;
		}
	}

	return result;
}

/*! \def ECDSAP521_VERIFY_WNAF_WIDTH
 * \brief Signed-window width for public-scalar verification multiplication.
 */
#define ECDSAP521_VERIFY_WNAF_WIDTH 5U

/*! \def ECDSAP521_VERIFY_WNAF_DIGITS
 * \brief Maximum wNAF digits, including the final recoding carry.
 */
#define ECDSAP521_VERIFY_WNAF_DIGITS 522U

/*! \def ECDSAP521_VERIFY_ODD_MULTIPLES
 * \brief Number of odd multiples required for width-five wNAF.
 */
#define ECDSAP521_VERIFY_ODD_MULTIPLES 8U

/*! \struct ecdsap521_verify_wnaf_scalar
 * \brief Width-five signed-digit representation of a public P-521 scalar.
 * \details Digits and storage are caller-owned. Never use on secret inputs.
 */
typedef struct
{
	int8_t digits[ECDSAP521_VERIFY_WNAF_DIGITS]; /*!< Signed digits, low to high. */
	size_t length;								 /*!< Last nonzero digit index plus one; zero for zero scalar. */
} ecdsap521_verify_wnaf_scalar;

static bool ecdsap521_verify_wnaf_recode(ecdsap521_verify_wnaf_scalar* result, const uint8_t* scalar)
{
	uint64_t words[ECDSAP521_LIMBS + 1U] = {UINT64_C(0)};
	uint64_t carry;
	uint64_t value;
	size_t i;
	size_t j;
	size_t shift;
	int32_t digit;
	bool nonzero;
	bool valid;

	valid = false;

	if (result != NULL && scalar != NULL && scalar[0U] <= 1U)
	{
		qsc_memutils_clear(result, sizeof(*result));

		for (i = 0U; i != 66U; ++i)
		{
			words[i / 8U] |= (uint64_t)scalar[65U - i] << ((i & 7U) * 8U);
		}

		i = 0U;
		valid = true;

		for (;;)
		{
			nonzero = false;

			for (j = 0U; j != ECDSAP521_LIMBS + 1U; ++j)
			{
				if (words[j] != UINT64_C(0))
				{
					nonzero = true;
				}
			}

			if (nonzero == false)
			{
				break;
			}

			if (i >= ECDSAP521_VERIFY_WNAF_DIGITS)
			{
				valid = false;
				break;
			}

			shift = 1U;

			if ((words[0U] & UINT64_C(1)) != UINT64_C(0))
			{
				digit = (int32_t)(words[0U] & UINT64_C(31));

				if (digit >= 16)
				{
					digit -= 32;
					carry = (uint64_t)(-digit);

					for (j = 0U; j != ECDSAP521_LIMBS + 1U && carry != UINT64_C(0); ++j)
					{
						value = words[j] + carry;
						carry = (uint64_t)(value < words[j]);
						words[j] = value;
					}
				}
				else
				{
					carry = (uint64_t)digit;

					for (j = 0U; j != ECDSAP521_LIMBS + 1U && carry != UINT64_C(0); ++j)
					{
						value = words[j] - carry;
						carry = (uint64_t)(words[j] < carry);
						words[j] = value;
					}
				}

				result->digits[i] = (int8_t)digit;
				result->length = i + 1U;
				shift = ECDSAP521_VERIFY_WNAF_WIDTH;
			}

			for (j = 0U; j != ECDSAP521_LIMBS + 1U; ++j)
			{
				words[j] >>= shift;

				if (j + 1U != ECDSAP521_LIMBS + 1U)
				{
					words[j] |= words[j + 1U] << (64U - shift);
				}
			}

			i += shift;
		}
	}

	qsc_memutils_secure_erase(words, sizeof(words));

	return valid;
}

static bool ecdsap521_verify_odd_multiples_setup_vartime(ecdsap521_affine_point* table, const ecdsap521_affine_point* point)
{
	ecdsap521_projective_point multiples[ECDSAP521_VERIFY_ODD_MULTIPLES];
	ecdsap521_projective_point doubled;
	ecdsap521_field scratch[ECDSAP521_VERIFY_ODD_MULTIPLES];
	size_t i;
	bool ret;

	ret = false;

	if (table != NULL && point != NULL && ecdsap521_affine_is_identity(point) == UINT64_C(0))
	{
		multiples[0U] = ecdsap521_projective_from_affine(point);
		doubled = ecdsap521_dbl_a_minus_3(&multiples[0U]);

		for (i = 1U; i != ECDSAP521_VERIFY_ODD_MULTIPLES; ++i)
		{
			multiples[i] = ecdsap521_point_add(&multiples[i - 1U], &doubled);
		}

		ret = ecdsap521_to_affine_batch(table, multiples, ECDSAP521_VERIFY_ODD_MULTIPLES, scratch, ECDSAP521_VERIFY_ODD_MULTIPLES);
	}

	qsc_memutils_secure_erase(multiples, sizeof(multiples));
	qsc_memutils_secure_erase(&doubled, sizeof(doubled));
	qsc_memutils_secure_erase(scratch, sizeof(scratch));

	return ret;
}

static inline ecdsap521_field ecdsap521_verify_div2(const ecdsap521_field* input)
{
	ecdsap521_field result;
	uint64_t words[ECDSAP521_LIMBS];
	uint64_t carry;
	uint64_t mask;
	size_t i;

	mask = UINT64_C(0) - (input->limbs[0U] & UINT64_C(1));
	carry = UINT64_C(0);

	for (i = 0U; i != ECDSAP521_LIMBS; ++i)
	{
		words[i] = ecdsap521_word_add(input->limbs[i], ECDSAP521_P[i] & mask, &carry);
	}

	for (i = 0U; i != ECDSAP521_LIMBS - 1U; ++i)
	{
		result.limbs[i] = (words[i] >> 1U) | (words[i + 1U] << 63U);
	}

	result.limbs[ECDSAP521_LIMBS - 1U] = (words[ECDSAP521_LIMBS - 1U] >> 1U) | (carry << 63U);
	qsc_memutils_secure_erase(words, sizeof(words));

	return result;
}

static ecdsap521_projective_point ecdsap521_verify_dbl_n_a_minus_3(const ecdsap521_projective_point* point, size_t count)
{
	ecdsap521_projective_point result;
	ecdsap521_field nx;
	ecdsap521_field ny;
	ecdsap521_field nz;
	ecdsap521_field w;
	ecdsap521_field ny2;
	ecdsap521_field ny4;
	ecdsap521_field t1;
	ecdsap521_field t2;
	ecdsap521_field tmp;

	nx = point->x;
	ny = ecdsap521_mul2(&point->y);
	nz = point->z;
	w = ecdsap521_square(&nz);
	w = ecdsap521_square(&w);

	while (count != 0U)
	{
		ny2 = ecdsap521_square(&ny);
		ny4 = ecdsap521_square(&ny2);
		t1 = ecdsap521_square(&nx);
		t1 = ecdsap521_sub(&t1, &w);
		t1 = ecdsap521_mul3(&t1);
		t2 = ecdsap521_mul(&nx, &ny2);
		nx = ecdsap521_square(&t1);
		tmp = ecdsap521_mul2(&t2);
		nx = ecdsap521_sub(&nx, &tmp);
		nz = ecdsap521_mul(&nz, &ny);
		tmp = ecdsap521_sub(&t2, &nx);
		tmp = ecdsap521_mul2(&tmp);
		ny = ecdsap521_mul(&t1, &tmp);
		ny = ecdsap521_sub(&ny, &ny4);
		--count;

		if (count != 0U)
		{
			w = ecdsap521_mul(&w, &ny4);
		}
	}

	result.x = nx;
	result.y = ecdsap521_verify_div2(&ny);
	result.z = nz;

	return result;
}

static inline ecdsap521_projective_point ecdsap521_verify_public_point_add_or_sub_mixed(const ecdsap521_projective_point* a, const ecdsap521_affine_point* b, uint64_t sub)
{
	ecdsap521_projective_point result;
	ecdsap521_affine_point selected;
	ecdsap521_field by;
	ecdsap521_field ngby;
	ecdsap521_field z1z1;
	ecdsap521_field u2;
	ecdsap521_field s2;
	ecdsap521_field h;
	ecdsap521_field r;
	ecdsap521_field hh;
	ecdsap521_field hhh;
	ecdsap521_field v;
	ecdsap521_field t0;
	ecdsap521_field t2;
	ecdsap521_field t3;
	ecdsap521_field t4;
	ecdsap521_field t5;
	ecdsap521_field t6;
	ecdsap521_field t7;
	ecdsap521_field x3;
	ecdsap521_field y3;
	ecdsap521_field z3;
	uint64_t aidn;
	uint64_t bidn;

	aidn = ecdsap521_projective_is_identity(a);
	bidn = ecdsap521_affine_is_identity(b);

	if (bidn != UINT64_C(0))
	{
		result = *a;
	}
	else
	{
		by = b->y;
		ngby = ecdsap521_negate(&by);

		if ((sub & UINT64_C(1)) != UINT64_C(0))
		{
			by = ngby;
		}

		if (aidn != UINT64_C(0))
		{
			selected.x = b->x;
			selected.y = by;
			result = ecdsap521_projective_from_affine(&selected);
		}
		else
		{
			z1z1 = ecdsap521_square(&a->z);
			u2 = ecdsap521_mul(&b->x, &z1z1);
			t0 = ecdsap521_mul(&by, &a->z);
			s2 = ecdsap521_mul(&t0, &z1z1);
			h = ecdsap521_sub(&u2, &a->x);
			r = ecdsap521_sub(&s2, &a->y);

			if (ecdsap521_is_zero(&h) != UINT64_C(0))
			{
				if (ecdsap521_is_zero(&r) != UINT64_C(0))
				{
					result = ecdsap521_dbl_a_minus_3(a);
				}
				else
				{
					result = ecdsap521_projective_identity();
				}
			}
			else
			{
				hh = ecdsap521_square(&h);
				hhh = ecdsap521_mul(&h, &hh);
				v = ecdsap521_mul(&a->x, &hh);
				t2 = ecdsap521_square(&r);
				t3 = ecdsap521_add(&v, &v);
				t4 = ecdsap521_sub(&t2, &hhh);
				x3 = ecdsap521_sub(&t4, &t3);
				t5 = ecdsap521_sub(&v, &x3);
				t6 = ecdsap521_mul(&a->y, &hhh);
				t7 = ecdsap521_mul(&r, &t5);
				y3 = ecdsap521_sub(&t7, &t6);
				z3 = ecdsap521_mul(&a->z, &h);
				result.x = x3;
				result.y = y3;
				result.z = z3;
			}
		}
	}

	return result;
}

static bool ecdsap521_verify_mul_vartime(ecdsap521_projective_point* result, const ecdsap521_affine_point* table, const uint8_t* scalar)
{
	ecdsap521_verify_wnaf_scalar naf;
	ecdsap521_projective_point accum;
	ecdsap521_field negy;
	int32_t digit;
	size_t i;
	size_t magnitude;
	size_t pending;
	bool ret;

	ret = false;

	if (result != NULL && table != NULL && scalar != NULL)
	{
		ret = ecdsap521_verify_wnaf_recode(&naf, scalar);

		if (ret == true)
		{
			accum = ecdsap521_projective_identity();
			i = naf.length;

			if (i != 0U)
			{
				--i;
				digit = naf.digits[i];
				magnitude = (size_t)((digit < 0) ? -digit : digit);
				accum = ecdsap521_projective_from_affine(&table[(magnitude - 1U) / 2U]);

				if (digit < 0)
				{
					negy = ecdsap521_negate(&accum.y);
					accum.y = negy;
				}

				pending = 0U;

				while (i != 0U)
				{
					--i;
					++pending;
					digit = naf.digits[i];

					if (digit != 0)
					{
						accum = ecdsap521_verify_dbl_n_a_minus_3(&accum, pending);
						pending = 0U;

						magnitude = (size_t)((digit < 0) ? -digit : digit);
						accum = ecdsap521_verify_public_point_add_or_sub_mixed(&accum, &table[(magnitude - 1U) / 2U], (uint64_t)(digit < 0));
					}
				}

				if (pending != 0U)
				{
					accum = ecdsap521_verify_dbl_n_a_minus_3(&accum, pending);
				}
			}

			*result = accum;
		}
	}

	qsc_memutils_secure_erase(&naf, sizeof(naf));
	qsc_memutils_secure_erase(&accum, sizeof(accum));
	qsc_memutils_secure_erase(&negy, sizeof(negy));

	return ret;
}

static bool ecdsap521_verify_basemul_booth_exec_vartime(ecdsap521_projective_point* result, const ecdsap521_affine_point* table, size_t table_count, const uint8_t* scalar)
{
	ecdsap521_booth_digit digit;
	uint64_t raw;
	size_t i;
	size_t offset;
	size_t windows;
	bool ret;

	ret = false;
	windows = (521U + ECDSAP521_BASE_WINDOW_BITS) / ECDSAP521_BASE_WINDOW_BITS;

	if (result != NULL && table != NULL && scalar != NULL && scalar[0U] <= 1U && table_count >= windows * ECDSAP521_BASE_WINDOW_ELEMENTS)
	{
		for (i = 0U; i != windows; ++i)
		{
			if (i == 0U)
			{
				raw = (ecdsap521_scalar_window7(scalar, 66U, 0U) & UINT64_C(63)) << 1U;
			}
			else
			{
				offset = ECDSAP521_BASE_WINDOW_BITS * i - 1U;
				raw = ecdsap521_scalar_window7(scalar, 66U, offset);
			}

			digit = ecdsap521_booth_recode6(raw);

			if (digit.digit != UINT64_C(0))
			{
				*result = ecdsap521_verify_public_point_add_or_sub_mixed(
					result, &table[ECDSAP521_BASE_WINDOW_ELEMENTS * i + (size_t)digit.digit - 1U], digit.negative);
			}
		}

		ret = true;
	}

	return ret;
}

static bool ecdsap521_verify_field_deserialize(ecdsap521_field* result, const uint8_t* bytes)
{
	size_t i;
	bool valid;

	valid = false;

	if (result != NULL && bytes != NULL && bytes[0U] <= 1U)
	{
		for (i = 0U; i != ECDSAP521_LIMBS - 1U; ++i)
		{
			result->limbs[i] = qsc_intutils_be8to64(bytes + 58U - i * 8U);
		}

		result->limbs[8U] = ((uint64_t)bytes[0U] << 8U) | bytes[1U];
		valid = true;

		for (i = ECDSAP521_LIMBS; i != 0U; --i)
		{
			if (result->limbs[i - 1U] < ECDSAP521_P[i - 1U])
			{
				break;
			}

			if (result->limbs[i - 1U] > ECDSAP521_P[i - 1U])
			{
				valid = false;
				break;
			}

			if (i == 1U)
			{
				valid = false;
			}
		}
	}

	return valid;
}

/*! \brief Canonical P-521 curve coefficient b in native field representation.
 * \details Public immutable curve parameter from FIPS 186 secp521r1. Nine
 * little-endian limbs, matching native P-521 field representation.
 */
static const ecdsap521_field ECDSAP521_VERIFY_CURVE_B = {
	{UINT64_C(0xEF451FD46B503F00), UINT64_C(0x3573DF883D2C34F1), UINT64_C(0x1652C0BD3BB1BF07), UINT64_C(0x56193951EC7E937B), UINT64_C(0xB8B489918EF109E1),
		UINT64_C(0xA2DA725B99B315F3), UINT64_C(0x929A21A0B68540EE), UINT64_C(0x953EB9618E1C9A1F), UINT64_C(0x0000000000000051)}};

static bool ecdsap521_verify_point_on_curve(const ecdsap521_affine_point* public_point)
{
	ecdsap521_field y2;
	ecdsap521_field x2;
	ecdsap521_field x3;
	ecdsap521_field thrx;
	ecdsap521_field rhs;
	ecdsap521_field difference;
	bool valid;

	valid = false;

	if (public_point != NULL)
	{
		y2 = ecdsap521_square(&public_point->y);
		x2 = ecdsap521_square(&public_point->x);
		x3 = ecdsap521_mul(&x2, &public_point->x);
		thrx = ecdsap521_mul3(&public_point->x);
		rhs = ecdsap521_sub(&x3, &thrx);
		rhs = ecdsap521_add(&rhs, &ECDSAP521_VERIFY_CURVE_B);
		difference = ecdsap521_sub(&y2, &rhs);
		valid = (ecdsap521_is_zero(&difference) != UINT64_C(0));
	}

	return valid;
}

static bool ecdsap521_verify_projective_x_mod_order_eq(const ecdsap521_projective_point* result, const uint8_t* rbytes)
{
	ecdsap521_field z2;
	ecdsap521_field candidate;
	ecdsap521_field product;
	ecdsap521_field difference;
	uint64_t carry;
	uint64_t value;
	size_t i;
	bool ret;
	bool less;

	ret = false;

	if (result != NULL && rbytes != NULL && ecdsap521_projective_is_identity(result) == UINT64_C(0))
	{
		if (ecdsap521_verify_field_deserialize(&candidate, rbytes) == true)
		{
			z2 = ecdsap521_square(&result->z);
			product = ecdsap521_mul(&candidate, &z2);
			difference = ecdsap521_sub(&product, &result->x);
			ret = (ecdsap521_is_zero(&difference) != UINT64_C(0));

			if (ret == false)
			{
				carry = UINT64_C(0);

				for (i = 0U; i != ECDSAP521_LIMBS; ++i)
				{
					value = ecdsap521_word_add(candidate.limbs[i], ECDSAP521_N[i], &carry);
					candidate.limbs[i] = value;
				}

				less = (carry == UINT64_C(0));

				if (less == true)
				{
					less = false;

					for (i = ECDSAP521_LIMBS; i != 0U; --i)
					{
						if (candidate.limbs[i - 1U] < ECDSAP521_P[i - 1U])
						{
							less = true;
							break;
						}

						if (candidate.limbs[i - 1U] > ECDSAP521_P[i - 1U])
						{
							break;
						}
					}
				}

				if (less == true)
				{
					product = ecdsap521_mul(&candidate, &z2);
					difference = ecdsap521_sub(&product, &result->x);
					ret = (ecdsap521_is_zero(&difference) != UINT64_C(0));
				}
			}
		}
	}

	return ret;
}

static bool ecdsap521_verify_mul2_vartime_x_mod_order_eq(bool* result, const ecdsap521_affine_point* public_point, const uint8_t* u1, const uint8_t* u2, const uint8_t* rbytes, const ecdsap521_affine_point* fixed_table, size_t table_count)
{
	ecdsap521_affine_point odd_table[ECDSAP521_VERIFY_ODD_MULTIPLES];
	ecdsap521_projective_point accum;
	bool ret;

	ret = false;

	if (result != NULL)
	{
		*result = false;
	}

	if (result != NULL && public_point != NULL && u1 != NULL && u2 != NULL && rbytes != NULL && fixed_table != NULL)
	{
		if (ecdsap521_verify_odd_multiples_setup_vartime(odd_table, public_point) == true)
		{
			if (ecdsap521_verify_mul_vartime(&accum, odd_table, u2) == true)
			{
				if (ecdsap521_verify_basemul_booth_exec_vartime(&accum, fixed_table, table_count, u1) == true)
				{
					*result = ecdsap521_verify_projective_x_mod_order_eq(&accum, rbytes);
					ret = true;
				}
			}
		}
	}

	qsc_memutils_secure_erase(odd_table, sizeof(odd_table));
	qsc_memutils_secure_erase(&accum, sizeof(accum));

	return ret;
}

static int32_t ecdsap521_verify_public_cmp(const uint64_t a[ECDSAP521_LIMBS], const uint64_t b[ECDSAP521_LIMBS])
{
	int32_t result;
	int32_t i;

	result = 0;

	for (i = (int32_t)ECDSAP521_LIMBS - 1; i >= 0; --i)
	{
		if (a[i] != b[i])
		{
			result = (a[i] > b[i]) ? 1 : -1;
			break;
		}
	}

	return result;
}

static void ecdsap521_verify_public_shift1(uint64_t value[ECDSAP521_LIMBS])
{
	uint64_t carry;
	uint64_t next;
	int32_t i;

	carry = UINT64_C(0);

	for (i = (int32_t)ECDSAP521_LIMBS - 1; i >= 0; --i)
	{
		next = value[i] << 63U;
		value[i] = (value[i] >> 1U) | carry;
		carry = next;
	}
}

static void ecdsap521_verify_public_half(uint64_t value[ECDSAP521_LIMBS])
{
	uint64_t carry;
	uint64_t sum;
	size_t i;

	if ((value[0U] & UINT64_C(1)) != UINT64_C(0))
	{
		carry = UINT64_C(0);

		for (i = 0U; i != ECDSAP521_LIMBS; ++i)
		{
			sum = value[i] + ECDSAP521_N[i];
			value[i] = sum + carry;
			carry = (uint64_t)(sum < ECDSAP521_N[i]) | (uint64_t)(value[i] < sum);
		}
	}

	ecdsap521_verify_public_shift1(value);
}

static void ecdsap521_verify_public_submod(uint64_t value[ECDSAP521_LIMBS], const uint64_t other[ECDSAP521_LIMBS])
{
	uint64_t borrow;
	uint64_t carry;
	size_t i;

	borrow = UINT64_C(0);

	for (i = 0U; i != ECDSAP521_LIMBS; ++i)
	{
		value[i] = ecdsap521_word_sub(value[i], other[i], &borrow);
	}

	if (borrow != UINT64_C(0))
	{
		carry = UINT64_C(0);

		for (i = 0U; i != ECDSAP521_LIMBS; ++i)
		{
			value[i] = ecdsap521_word_add(value[i], ECDSAP521_N[i], &carry);
		}
	}
}

static bool ecdsap521_verify_scalar_invert_vartime(ecdsap521_scalar* output, const ecdsap521_scalar* input)
{
	uint64_t u[ECDSAP521_LIMBS];
	uint64_t v[ECDSAP521_LIMBS];
	uint64_t x1[ECDSAP521_LIMBS] = {UINT64_C(1)};
	uint64_t x2[ECDSAP521_LIMBS] = {UINT64_C(0)};
	const uint64_t one[ECDSAP521_LIMBS] = {UINT64_C(1)};
	bool ret;

	ret = false;

	if (output != NULL && input != NULL)
	{
		ecdsap521_scalar_from_rep(u, input);
		qsc_memutils_copy(v, ECDSAP521_N, sizeof(v));

		if (ecdsap521_verify_public_cmp(u, x2) != 0)
		{
			while (ecdsap521_verify_public_cmp(u, one) != 0 && ecdsap521_verify_public_cmp(v, one) != 0)
			{
				while ((u[0U] & UINT64_C(1)) == UINT64_C(0))
				{
					ecdsap521_verify_public_shift1(u);
					ecdsap521_verify_public_half(x1);
				}

				while ((v[0U] & UINT64_C(1)) == UINT64_C(0))
				{
					ecdsap521_verify_public_shift1(v);
					ecdsap521_verify_public_half(x2);
				}

				if (ecdsap521_verify_public_cmp(u, v) >= 0)
				{
					ecdsap521_verify_public_submod(u, v);
					ecdsap521_verify_public_submod(x1, x2);
				}
				else
				{
					ecdsap521_verify_public_submod(v, u);
					ecdsap521_verify_public_submod(x2, x1);
				}
			}

			if (ecdsap521_verify_public_cmp(u, one) == 0)
			{
				*output = ecdsap521_scalar_to_rep(x1);
			}
			else
			{
				*output = ecdsap521_scalar_to_rep(x2);
			}

			ret = true;
		}
	}

	qsc_memutils_secure_erase(u, sizeof(u));
	qsc_memutils_secure_erase(v, sizeof(v));
	qsc_memutils_secure_erase(x1, sizeof(x1));
	qsc_memutils_secure_erase(x2, sizeof(x2));

	return ret;
}

bool qsc_ecdsap521_comb_verify_context_initialize(qsc_ecdsap521_comb_verify_context* context, const uint8_t* publickey)
{
	ecdsap521_affine_point q;
	ecdsap521_projective_point points[63U];
	ecdsap521_affine_point affine[63U];
	ecdsap521_field scratch[63U];
	size_t column;
	size_t base;
	size_t i;
	bool ret;

	ret = false;

	if (context != NULL)
	{
		qsc_memutils_clear(context, sizeof(*context));

		if (publickey != NULL && ecdsap521_verify_field_deserialize(&q.x, publickey) && ecdsap521_verify_field_deserialize(&q.y, publickey + 66U) &&
			ecdsap521_verify_point_on_curve(&q))
		{
			points[0U] = ecdsap521_projective_from_affine(&q);

			for (column = 1U; column < 6U; ++column)
			{
				base = (size_t)1U << column;
				points[base - 1U] = ecdsap521_verify_dbl_n_a_minus_3(&points[(base / 2U) - 1U], 87U);

				for (i = 1U; i < base; ++i)
				{
					points[base + i - 1U] = ecdsap521_point_add(&points[i - 1U], &points[base - 1U]);
				}
			}

			ret = ecdsap521_to_affine_batch(affine, points, 63U, scratch, 63U);

			if (ret)
			{
				for (i = 0U; i < 63U; ++i)
				{
					qsc_memutils_copy(context->comb[i][0U], affine[i].x.limbs, sizeof(affine[i].x.limbs));
					qsc_memutils_copy(context->comb[i][1U], affine[i].y.limbs, sizeof(affine[i].y.limbs));
				}

				qsc_memutils_copy(context->publickey, publickey, EC_NISTP521_PUBLICKEY_SIZE);
				context->initialized = true;
			}
		}
	}

	return ret;
}

static ecdsap521_projective_point ecdsap521_verify_comb_mul(const qsc_ecdsap521_comb_verify_context* context, const uint8_t scalar[66U])
{
	ecdsap521_projective_point accum = { 0 };
	ecdsap521_affine_point selected;
	size_t row;
	size_t column;
	size_t bit;
	uint32_t index;

	accum.y = ecdsap521_one();

	for (row = 87U; row > 0U; --row)
	{
		accum = ecdsap521_dbl_a_minus_3(&accum);
		index = 0U;

		for (column = 0U; column < 6U; ++column)
		{
			bit = row - 1U + 87U * column;

			if (bit < 521U)
			{
				index |= ((uint32_t)(scalar[65U - bit / 8U] >> (bit & 7U)) & 1U) << column;
			}
		}

		if (index != 0U)
		{
			qsc_memutils_copy(selected.x.limbs, context->comb[index - 1U][0U], sizeof(selected.x.limbs));
			qsc_memutils_copy(selected.y.limbs, context->comb[index - 1U][1U], sizeof(selected.y.limbs));
			accum = ecdsap521_verify_public_point_add_or_sub_mixed(&accum, &selected, 0U);
		}
	}

	return accum;
}

static bool ecdsap521_verify_digest(uint8_t* msgout, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey, const uint8_t* digest_bytes, size_t digest_length, const qsc_ecdsap521_comb_verify_context* context)
{
	ecdsap521_affine_point point = { 0 };
	ecdsap521_projective_point accum;
	ecdsap521_scalar r = {{ 0U }};
	ecdsap521_scalar s = {{ 0U }};
	ecdsap521_scalar digest = {{ 0U }};
	ecdsap521_scalar inverse = {{ 0U }};
	ecdsap521_scalar u1 = {{ 0U }};
	ecdsap521_scalar u2 = {{ 0U }};
	uint8_t u1by[66U] = { 0U };
	uint8_t u2by[66U] = { 0U };
	size_t mlen;
	bool valid;
	bool ret;

	ret = false;
	valid = false;
	mlen = 0U;

	if (msglen != NULL)
	{
		*msglen = 0U;
	}

	if (msgout != NULL && msglen != NULL && signedmsg != NULL && (publickey != NULL || context != NULL) && digest_bytes != NULL &&
		smsglen >= EC_NISTP521_SIGNATURE_SIZE && (digest_length == 32U || digest_length == 48U || digest_length == 64U))
	{
		mlen = smsglen - EC_NISTP521_SIGNATURE_SIZE;

		if (context != NULL)
		{
			valid = context->initialized;
		}
		else
		{
			valid = ecdsap521_verify_field_deserialize(&point.x, publickey) && ecdsap521_verify_field_deserialize(&point.y, publickey + 66U) &&
					ecdsap521_verify_point_on_curve(&point);
		}

		if (valid && ecdsap521_scalar_deserialize(&r, signedmsg, 66U) == true && ecdsap521_scalar_deserialize(&s, signedmsg + 66U, 66U) == true &&
			ecdsap521_scalar_is_zero(&r) == UINT64_C(0) && ecdsap521_scalar_is_zero(&s) == UINT64_C(0) && ecdsap521_generator_table_initialize() == true)
		{
			if (ecdsap521_scalar_from_wide_bytes(&digest, digest_bytes, digest_length) == true && ecdsap521_verify_scalar_invert_vartime(&inverse, &s) == true)
			{
				u1 = ecdsap521_scalar_mul(&digest, &inverse);
				u2 = ecdsap521_scalar_mul(&r, &inverse);
				ecdsap521_scalar_serialize(u1by, &u1);
				ecdsap521_scalar_serialize(u2by, &u2);

				if (context != NULL)
				{
					accum = ecdsap521_verify_comb_mul(context, u2by);
					valid = ecdsap521_verify_basemul_booth_exec_vartime(&accum, ecdsap521_generator_table, ECDSAP521_GENERATOR_TABLE_CAPACITY, u1by);
					valid = valid && ecdsap521_verify_projective_x_mod_order_eq(&accum, signedmsg);
				}
 else if (!ecdsap521_verify_mul2_vartime_x_mod_order_eq(&valid, &point, u1by, u2by, signedmsg, ecdsap521_generator_table, ECDSAP521_GENERATOR_TABLE_CAPACITY))
				{
					valid = false;
				}

				if (valid)
				{
					qsc_memutils_copy(msgout, signedmsg + EC_NISTP521_SIGNATURE_SIZE, mlen);
					*msglen = mlen;
					ret = true;
				}
			}
		}
	}

	qsc_memutils_secure_erase(&point, sizeof(point));
	qsc_memutils_secure_erase(&r, sizeof(r));
	qsc_memutils_secure_erase(&s, sizeof(s));
	qsc_memutils_secure_erase(&digest, sizeof(digest));
	qsc_memutils_secure_erase(&inverse, sizeof(inverse));
	qsc_memutils_secure_erase(&u1, sizeof(u1));
	qsc_memutils_secure_erase(&u2, sizeof(u2));
	qsc_memutils_secure_erase(u1by, sizeof(u1by));
	qsc_memutils_secure_erase(u2by, sizeof(u2by));

	return ret;
}

bool qsc_ecdsap521_verify(uint8_t* msgout, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey)
{
	uint8_t dbyt[64U] = { 0U };
	bool result;

	result = false;

	if (msglen != NULL)
	{
		*msglen = 0U;
	}

	if (msgout != NULL && msglen != NULL && signedmsg != NULL && publickey != NULL && smsglen >= EC_NISTP521_SIGNATURE_SIZE)
	{
		qsc_sha512_compute(dbyt, signedmsg + EC_NISTP521_SIGNATURE_SIZE, smsglen - EC_NISTP521_SIGNATURE_SIZE);
		result = ecdsap521_verify_digest(msgout, msglen, signedmsg, smsglen, publickey, dbyt, sizeof(dbyt), NULL);
	}

	qsc_memutils_secure_erase(dbyt, sizeof(dbyt));

	return result;
}

bool qsc_ecdsap521_verify_prehashed(uint8_t* msgout, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey, const uint8_t* digest, size_t digestlen)
{
	bool result;

	result = ecdsap521_verify_digest(msgout, msglen, signedmsg, smsglen, publickey, digest, digestlen, NULL);

	return result;
}

void qsc_ecdsap521_comb_verify_context_clear(qsc_ecdsap521_comb_verify_context* context)
{
	if (context != NULL)
	{
		qsc_memutils_clear(context, sizeof(*context));
	}
}

bool qsc_ecdsap521_verify_with_comb_context(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const qsc_ecdsap521_comb_verify_context* context)
{
	uint8_t digest[64U] = { 0U };
	bool ret;

	ret = false;

	if (msglen != NULL)
	{
		*msglen = 0U;
	}

	if (message != NULL && msglen != NULL && signedmsg != NULL && context != NULL && smsglen >= EC_NISTP521_SIGNATURE_SIZE && context->initialized)
	{
		qsc_sha512_compute(digest, signedmsg + EC_NISTP521_SIGNATURE_SIZE, smsglen - EC_NISTP521_SIGNATURE_SIZE);
		ret = qsc_ecdsap521_verify_prehashed_with_comb_context(message, msglen, signedmsg, smsglen, context, digest, sizeof(digest));
	}

	qsc_memutils_secure_erase(digest, sizeof(digest));

	return ret;
}

bool qsc_ecdsap521_verify_prehashed_with_comb_context(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const qsc_ecdsap521_comb_verify_context* context, const uint8_t* digest, size_t digestlen)
{
	bool ret;

	ret = false;

	if (msglen != NULL)
	{
		*msglen = 0U;
	}

	if (context != NULL && context->initialized)
	{
		ret = ecdsap521_verify_digest(message, msglen, signedmsg, smsglen, NULL, digest, digestlen, context);
	}

	return ret;
}

int32_t qsc_p521_publickey_from_privatekey(uint8_t* publickey, const uint8_t* privatekey)
{
	return qsc_ecdsap521_publickey_from_privatekey(publickey, privatekey);
}

int32_t qsc_p521_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed)
{
	return qsc_ecdsap521_keypair(publickey, privatekey, seed);
}

int32_t qsc_p521_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey)
{
	return qsc_ecdsap521_sign(signedmsg, smsglen, message, msglen, privatekey);
}

int32_t qsc_p521_sign_scalar(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey)
{
	return qsc_ecdsap521_sign_scalar(signedmsg, smsglen, message, msglen, privatekey);
}

bool qsc_p521_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey)
{
	return qsc_ecdsap521_verify(message, msglen, signedmsg, smsglen, publickey);
}

bool qsc_p521_verify_prehashed(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey, const uint8_t* digest, size_t digestlen)
{
	return qsc_ecdsap521_verify_prehashed(message, msglen, signedmsg, smsglen, publickey, digest, digestlen);
}

bool qsc_p521_comb_verify_context_initialize(qsc_p521_comb_verify_context* context, const uint8_t* publickey)
{
	return qsc_ecdsap521_comb_verify_context_initialize(context, publickey);
}

void qsc_p521_comb_verify_context_clear(qsc_p521_comb_verify_context* context)
{
	qsc_ecdsap521_comb_verify_context_clear(context);
}

bool qsc_p521_verify_with_comb_context(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const qsc_p521_comb_verify_context* context)
{
	return qsc_ecdsap521_verify_with_comb_context(message, msglen, signedmsg, smsglen, context);
}

bool qsc_p521_verify_prehashed_with_comb_context(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const qsc_p521_comb_verify_context* context, const uint8_t* digest, size_t digestlen)
{
	return qsc_ecdsap521_verify_prehashed_with_comb_context(message, msglen, signedmsg, smsglen, context, digest, digestlen);
}

/* \endcond DOXYGEN_NO_DOCUMENT */
