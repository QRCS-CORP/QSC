#include "eddh448.h"
#include "ed448.h"
#include "memutils.h"
#include "intrinsics.h"

/* \cond NO_DOCUMENT */

/*! \def EDDH448_NATIVE_CARRY
 * \brief Select x86-64 carry intrinsics, excluding ARM64EC and the portable override.
 */
#if !defined(QSC_EDDH448_FORCE_PORTABLE) && !defined(_M_ARM64EC) && (defined(__x86_64__) || (defined(_MSC_VER) && defined(_M_X64)))
#	define EDDH448_NATIVE_CARRY
#	if defined(_MSC_VER)
#		include <intrin.h>
#	else
#		include <x86intrin.h>
#	endif
#endif

/*! \def QSC_X448_WORDS
 * \brief Number of 64-bit words in an internal field element.
 */
#define QSC_X448_WORDS 7U

/*! \def QSC_X448_BYTES
 * \brief Number of bytes in a serialized X448 coordinate.
 */
#define QSC_X448_BYTES 56U

/*! \def QSC_X448_A24
 * \brief Curve448 Montgomery ladder constant (A - 2) / 4.
 */
#define QSC_X448_A24 39081U

/*! \struct eddh448_fe
 * \typedef eddh448_fe
 * \brief Private seven-word field representation, little-endian, residues not necessarily canonical.
 */
typedef struct eddh448_fe
{
	uint64_t v[QSC_X448_WORDS]; /*!< Seven 64-bit limbs, least significant first. */
} eddh448_fe;

/*! \brief Serialized RFC 7748 X448 base point. */
static const uint8_t eddh448_base_u[QSC_X448_BYTES] = {5U};

static uint64_t eddh448_add_word(uint64_t a, uint64_t b, uint64_t* carry)
{
	uint64_t result;

#if defined(EDDH448_NATIVE_CARRY)
	unsigned long long output;
	unsigned char c;

	c = _addcarry_u64((unsigned char)*carry, (unsigned long long)a, (unsigned long long)b, &output);
	*carry = (uint64_t)c;
	result = (uint64_t)output;
#else
	uint64_t c;
	uint64_t r;
	uint64_t t;

	t = a + b;
	c = (uint64_t)(t < a);
	r = t + *carry;
	*carry = c | (uint64_t)(r < t);

	result = r;
#endif

	return result;
}

static uint64_t eddh448_sub_word(uint64_t a, uint64_t b, uint64_t* borrow)
{
	uint64_t result;

#if defined(EDDH448_NATIVE_CARRY)
	unsigned long long output;
	unsigned char c;

	c = _subborrow_u64((unsigned char)*borrow, (unsigned long long)a, (unsigned long long)b, &output);
	*borrow = (uint64_t)c;
	result = (uint64_t)output;
#else
	uint64_t c;
	uint64_t r;
	uint64_t t;

	t = a - b;
	c = (uint64_t)(a < b);
	r = t - *borrow;
	*borrow = c | (uint64_t)(t < *borrow);

	result = r;
#endif

	return result;
}

static void eddh448_mul_word(uint64_t a, uint64_t b, uint64_t* low, uint64_t* high)
{
#if !defined(QSC_EDDH448_FORCE_PORTABLE) && defined(_MSC_VER) && defined(_M_X64) && !defined(_M_ARM64EC)
	*low = _umul128(a, b, high);
#elif defined(__SIZEOF_INT128__) && !defined(QSC_EDDH448_FORCE_PORTABLE)
	__uint128_t p;

	p = (__uint128_t)a * (__uint128_t)b;
	*low = (uint64_t)p;
	*high = (uint64_t)(p >> 64);
#else
	uint64_t p0;
	uint64_t p1;
	uint64_t p2;
	uint64_t p3;
	uint64_t middle;

	p0 = (a & UINT64_C(0xFFFFFFFF)) * (b & UINT64_C(0xFFFFFFFF));
	p1 = (a & UINT64_C(0xFFFFFFFF)) * (b >> 32);
	p2 = (a >> 32) * (b & UINT64_C(0xFFFFFFFF));
	p3 = (a >> 32) * (b >> 32);
	middle = (p0 >> 32) + (p1 & UINT64_C(0xFFFFFFFF)) + (p2 & UINT64_C(0xFFFFFFFF));
	*low = (p0 & UINT64_C(0xFFFFFFFF)) | (middle << 32);
	*high = p3 + (p1 >> 32) + (p2 >> 32) + (middle >> 32);
#endif
}

static void eddh448_accumulate(uint64_t acc[3U], uint64_t lo, uint64_t hi)
{
#if defined(EDDH448_NATIVE_CARRY)
	unsigned long long w0;
	unsigned long long w1;
	unsigned long long w2;
	unsigned char carry;

	w0 = (unsigned long long)acc[0U];
	w1 = (unsigned long long)acc[1U];
	w2 = (unsigned long long)acc[2U];
	carry = _addcarry_u64(0U, w0, (unsigned long long)lo, &w0);
	carry = _addcarry_u64(carry, w1, (unsigned long long)hi, &w1);
	(void)_addcarry_u64(carry, w2, 0U, &w2);
	acc[0U] = (uint64_t)w0;
	acc[1U] = (uint64_t)w1;
	acc[2U] = (uint64_t)w2;
#else
	uint64_t carry;
	uint64_t old;
	uint64_t t;

	old = acc[0U];
	acc[0U] += lo;
	carry = (uint64_t)(acc[0U] < old);
	old = acc[1U];
	t = old + hi;
	acc[1U] = t + carry;
	acc[2U] += (uint64_t)(t < old) + (uint64_t)(acc[1U] < t);
#endif
}

static void eddh448_comba_mul(uint64_t out[14U], const uint64_t a[7U], const uint64_t b[7U])
{
	uint64_t acc[3U] = {0U, 0U, 0U};
	uint64_t lo;
	uint64_t hi;

	eddh448_mul_word(a[0U], b[0U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	out[0U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	eddh448_mul_word(a[0U], b[1U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[1U], b[0U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	out[1U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	eddh448_mul_word(a[0U], b[2U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[1U], b[1U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[2U], b[0U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	out[2U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	eddh448_mul_word(a[0U], b[3U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[1U], b[2U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[2U], b[1U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[3U], b[0U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	out[3U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	eddh448_mul_word(a[0U], b[4U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[1U], b[3U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[2U], b[2U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[3U], b[1U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[4U], b[0U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	out[4U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	eddh448_mul_word(a[0U], b[5U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[1U], b[4U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[2U], b[3U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[3U], b[2U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[4U], b[1U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[5U], b[0U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	out[5U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	eddh448_mul_word(a[0U], b[6U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[1U], b[5U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[2U], b[4U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[3U], b[3U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[4U], b[2U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[5U], b[1U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[6U], b[0U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	out[6U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	eddh448_mul_word(a[1U], b[6U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[2U], b[5U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[3U], b[4U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[4U], b[3U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[5U], b[2U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[6U], b[1U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	out[7U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	eddh448_mul_word(a[2U], b[6U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[3U], b[5U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[4U], b[4U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[5U], b[3U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[6U], b[2U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	out[8U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	eddh448_mul_word(a[3U], b[6U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[4U], b[5U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[5U], b[4U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[6U], b[3U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	out[9U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	eddh448_mul_word(a[4U], b[6U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[5U], b[5U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[6U], b[4U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	out[10U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	eddh448_mul_word(a[5U], b[6U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[6U], b[5U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	out[11U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	eddh448_mul_word(a[6U], b[6U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	out[12U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	out[13U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;
}

static void eddh448_comba_square(uint64_t out[14U], const uint64_t a[7U])
{
	uint64_t acc[3U] = {0U, 0U, 0U};
	uint64_t lo;
	uint64_t hi;

	eddh448_mul_word(a[0U], a[0U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	out[0U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	eddh448_mul_word(a[0U], a[1U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_accumulate(acc, lo, hi);
	out[1U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	eddh448_mul_word(a[0U], a[2U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[1U], a[1U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	out[2U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	eddh448_mul_word(a[0U], a[3U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[1U], a[2U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_accumulate(acc, lo, hi);
	out[3U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	eddh448_mul_word(a[0U], a[4U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[1U], a[3U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[2U], a[2U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	out[4U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	eddh448_mul_word(a[0U], a[5U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[1U], a[4U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[2U], a[3U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_accumulate(acc, lo, hi);
	out[5U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	eddh448_mul_word(a[0U], a[6U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[1U], a[5U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[2U], a[4U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[3U], a[3U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	out[6U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	eddh448_mul_word(a[1U], a[6U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[2U], a[5U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[3U], a[4U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_accumulate(acc, lo, hi);
	out[7U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	eddh448_mul_word(a[2U], a[6U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[3U], a[5U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[4U], a[4U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	out[8U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	eddh448_mul_word(a[3U], a[6U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[4U], a[5U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_accumulate(acc, lo, hi);
	out[9U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	eddh448_mul_word(a[4U], a[6U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_mul_word(a[5U], a[5U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	out[10U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	eddh448_mul_word(a[5U], a[6U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	eddh448_accumulate(acc, lo, hi);
	out[11U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	eddh448_mul_word(a[6U], a[6U], &lo, &hi);
	eddh448_accumulate(acc, lo, hi);
	out[12U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;

	out[13U] = acc[0U];
	acc[0U] = acc[1U];
	acc[1U] = acc[2U];
	acc[2U] = 0U;
}

static void eddh448_reduce_add(eddh448_fe* out, const uint64_t in[8U])
{
	uint64_t w[8U];
	uint64_t carry;

	carry = 0U;
	w[0U] = eddh448_add_word(in[0U], in[7U], &carry);
	w[1U] = eddh448_add_word(in[1U], 0U, &carry);
	w[2U] = eddh448_add_word(in[2U], 0U, &carry);
	w[3U] = eddh448_add_word(in[3U], in[7U] << 32, &carry);
	w[4U] = eddh448_add_word(in[4U], 0U, &carry);
	w[5U] = eddh448_add_word(in[5U], 0U, &carry);
	w[6U] = eddh448_add_word(in[6U], 0U, &carry);
	w[7U] = carry;

	carry = 0U;
	out->v[0U] = eddh448_add_word(w[0U], w[7U], &carry);
	out->v[1U] = eddh448_add_word(w[1U], 0U, &carry);
	out->v[2U] = eddh448_add_word(w[2U], 0U, &carry);
	out->v[3U] = w[3U] + (w[7U] << 32) + carry;
	out->v[4U] = w[4U];
	out->v[5U] = w[5U];
	out->v[6U] = w[6U];
}

static void eddh448_reduce_mul(eddh448_fe* out, const uint64_t in[14U])
{
	uint64_t r[8U];
	uint64_t s[8U];
	uint64_t t[8U];
	uint64_t h[8U];
	uint64_t carry;
	size_t i;

	carry = 0U;

	for (i = 0U; i < 7U; ++i)
	{
		r[i] = eddh448_add_word(in[i], in[i + 7U], &carry);
	}

	r[7U] = carry;
	s[0U] = r[0U];
	s[1U] = r[1U];
	s[2U] = r[2U];
	carry = 0U;
	s[3U] = eddh448_add_word(r[3U], in[10U] & UINT64_C(0xFFFFFFFF00000000), &carry);
	s[4U] = eddh448_add_word(r[4U], in[11U], &carry);
	s[5U] = eddh448_add_word(r[5U], in[12U], &carry);
	s[6U] = eddh448_add_word(r[6U], in[13U], &carry);
	s[7U] = r[7U] + carry;
	t[0U] = (in[11U] << 32) | (in[10U] >> 32);
	t[1U] = (in[12U] << 32) | (in[11U] >> 32);
	t[2U] = (in[13U] << 32) | (in[12U] >> 32);
	t[3U] = (in[7U] << 32) | (in[13U] >> 32);
	t[4U] = (in[8U] << 32) | (in[7U] >> 32);
	t[5U] = (in[9U] << 32) | (in[8U] >> 32);
	t[6U] = (in[10U] << 32) | (in[9U] >> 32);
	carry = 0U;

	for (i = 0U; i < 7U; ++i)
	{
		h[i] = eddh448_add_word(s[i], t[i], &carry);
	}

	h[7U] = s[7U] + carry;
	eddh448_reduce_add(out, h);
}

static void eddh448_load(eddh448_fe* out, const uint8_t in[56U])
{
	size_t i;
	size_t j;

	for (i = 0U; i < 7U; ++i)
	{
		out->v[i] = 0U;

		for (j = 0U; j < 8U; ++j)
		{
			out->v[i] |= (uint64_t)in[8U * i + j] << (8U * j);
		}
	}
}

static inline uint64_t eddh448_mask_barrier(uint64_t mask)
{
#if defined(_MSC_VER)
	volatile uint64_t guarded;

	guarded = mask;
	mask = guarded;
#elif defined(__GNUC__) || defined(__clang__)
	__asm__("" : "+r"(mask));
#endif
	return mask;
}

static void eddh448_store(uint8_t out[56U], const eddh448_fe* in)
{
	static const uint64_t mod[7U] = {UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_C(0xFFFFFFFEFFFFFFFF), UINT64_MAX, UINT64_MAX, UINT64_MAX};
	uint64_t dif[7U];
	uint64_t borrow;
	uint64_t mask;
	uint64_t word;
	size_t i;
	size_t j;

	borrow = 0U;

	for (i = 0U; i < 7U; ++i)
	{
		dif[i] = eddh448_sub_word(in->v[i], mod[i], &borrow);
	}

	mask = eddh448_mask_barrier(0U - borrow);

	for (i = 0U; i < 7U; ++i)
	{
		word = (in->v[i] & mask) | (dif[i] & ~mask);

		for (j = 0U; j < 8U; ++j)
		{
			out[8U * i + j] = (uint8_t)(word >> (8U * j));
		}
	}
}

static void eddh448_add(eddh448_fe* out, const eddh448_fe* a, const eddh448_fe* b)
{
	uint64_t w[8U];
	uint64_t carry;
	size_t i;

	carry = 0U;

	for (i = 0U; i < 7U; ++i)
	{
		w[i] = eddh448_add_word(a->v[i], b->v[i], &carry);
	}

	w[7U] = carry;
	eddh448_reduce_add(out, w);
}

static void eddh448_sub(eddh448_fe* out, const eddh448_fe* a, const eddh448_fe* b)
{
	uint64_t w[7U];
	uint64_t x[7U];
	uint64_t borrow;
	uint64_t delta;
	size_t i;

	borrow = 0U;

	for (i = 0U; i < 7U; ++i)
	{
		w[i] = eddh448_sub_word(a->v[i], b->v[i], &borrow);
	}

	delta = borrow;
	borrow = 0U;
	x[0U] = eddh448_sub_word(w[0U], delta, &borrow);
	x[1U] = eddh448_sub_word(w[1U], 0U, &borrow);
	x[2U] = eddh448_sub_word(w[2U], 0U, &borrow);
	x[3U] = eddh448_sub_word(w[3U], delta << 32, &borrow);

	for (i = 4U; i < 7U; ++i)
	{
		x[i] = eddh448_sub_word(w[i], 0U, &borrow);
	}

	delta = borrow;
	borrow = 0U;
	out->v[0U] = eddh448_sub_word(x[0U], delta, &borrow);
	out->v[1U] = eddh448_sub_word(x[1U], 0U, &borrow);
	out->v[2U] = eddh448_sub_word(x[2U], 0U, &borrow);
	out->v[3U] = eddh448_sub_word(x[3U], delta << 32, &borrow);
	out->v[4U] = x[4U];
	out->v[5U] = x[5U];
	out->v[6U] = x[6U];
}

static void eddh448_mul(eddh448_fe* out, const eddh448_fe* a, const eddh448_fe* b)
{
	uint64_t w[14U];

	eddh448_comba_mul(w, a->v, b->v);
	eddh448_reduce_mul(out, w);
}

static void eddh448_square(eddh448_fe* out, const eddh448_fe* a)
{
	uint64_t w[14U];

	eddh448_comba_square(w, a->v);
	eddh448_reduce_mul(out, w);
}

static void eddh448_mul_small(eddh448_fe* out, const eddh448_fe* a, uint64_t factor)
{
	uint64_t w[8U];
	uint64_t carry;
	uint64_t hi;
	uint64_t lo;
	size_t i;

	carry = 0U;

	for (i = 0U; i < 7U; ++i)
	{
		eddh448_mul_word(a->v[i], factor, &lo, &hi);
		w[i] = lo + carry;
		carry = hi + (uint64_t)(w[i] < lo);
	}

	w[7U] = carry;
	eddh448_reduce_add(out, w);
}

static void eddh448_swap(eddh448_fe* a, eddh448_fe* b, uint64_t bit)
{
	uint64_t mask;
	uint64_t v;
	size_t i;

	mask = eddh448_mask_barrier(0U - bit);

	for (i = 0U; i < 7U; ++i)
	{
		v = (a->v[i] ^ b->v[i]) & mask;
		a->v[i] ^= v;
		b->v[i] ^= v;
	}
}

static void eddh448_square_n(eddh448_fe* out, const eddh448_fe* a, size_t count)
{
	size_t i;

	eddh448_square(out, a);

	for (i = 1U; i < count; ++i)
	{
		eddh448_square(out, out);
	}
}

static void eddh448_pow222(eddh448_fe* x222, eddh448_fe* x223, const eddh448_fe* a)
{
	eddh448_fe t;
	eddh448_fe a2;
	eddh448_fe a3;
	eddh448_fe a7;
	eddh448_fe a63;
	eddh448_fe x12;
	eddh448_fe x24;
	eddh448_fe i34;
	eddh448_fe x30;
	eddh448_fe x48;
	eddh448_fe x96;
	eddh448_fe x192;

	eddh448_square(&a2, a);
	eddh448_mul(&a3, a, &a2);
	eddh448_square(&t, &a3);
	eddh448_mul(&a7, a, &t);
	eddh448_square_n(&t, &a7, 3U);
	eddh448_mul(&a63, &a7, &t);
	eddh448_square_n(&t, &a63, 6U);
	eddh448_mul(&x12, &a63, &t);
	eddh448_square_n(&t, &x12, 12U);
	eddh448_mul(&x24, &x12, &t);
	eddh448_square_n(&i34, &x24, 6U);
	eddh448_mul(&x30, &a63, &i34);
	eddh448_square_n(&t, &i34, 18U);
	eddh448_mul(&x48, &x24, &t);
	eddh448_square_n(&t, &x48, 48U);
	eddh448_mul(&x96, &x48, &t);
	eddh448_square_n(&t, &x96, 96U);
	eddh448_mul(&x192, &x96, &t);
	eddh448_square_n(&t, &x192, 30U);
	eddh448_mul(x222, &x30, &t);
	eddh448_square(&t, x222);
	eddh448_mul(x223, a, &t);

	qsc_memutils_secure_erase(&t, sizeof(t));
	qsc_memutils_secure_erase(&a2, sizeof(a2));
	qsc_memutils_secure_erase(&a3, sizeof(a3));
	qsc_memutils_secure_erase(&a7, sizeof(a7));
	qsc_memutils_secure_erase(&a63, sizeof(a63));
	qsc_memutils_secure_erase(&x12, sizeof(x12));
	qsc_memutils_secure_erase(&x24, sizeof(x24));
	qsc_memutils_secure_erase(&i34, sizeof(i34));
	qsc_memutils_secure_erase(&x30, sizeof(x30));
	qsc_memutils_secure_erase(&x48, sizeof(x48));
	qsc_memutils_secure_erase(&x96, sizeof(x96));
	qsc_memutils_secure_erase(&x192, sizeof(x192));
}

static void eddh448_invert(eddh448_fe* out, const eddh448_fe* a)
{
	eddh448_fe x222;
	eddh448_fe x223;
	eddh448_fe t;

	eddh448_pow222(&x222, &x223, a);
	eddh448_square_n(&t, &x223, 223U);
	eddh448_mul(&t, &t, &x222);
	eddh448_square_n(&t, &t, 2U);
	eddh448_mul(out, &t, a);

	qsc_memutils_secure_erase(&x222, sizeof(x222));
	qsc_memutils_secure_erase(&x223, sizeof(x223));
	qsc_memutils_secure_erase(&t, sizeof(t));
}

static void eddh448_scalar_multiply(uint8_t out[56U], const uint8_t k[56U], const uint8_t u[56U], bool fixed_base)
{
	eddh448_fe a;
	eddh448_fe b;
	eddh448_fe aa;
	eddh448_fe bb;
	eddh448_fe c;
	eddh448_fe d;
	eddh448_fe da;
	eddh448_fe cb;
	eddh448_fe e;
	eddh448_fe t;
	eddh448_fe x1;
	eddh448_fe x2;
	eddh448_fe z2;
	eddh448_fe x3;
	eddh448_fe z3;
	eddh448_fe inv;
	uint64_t swap;
	uint64_t kbit;
	int32_t i;

	if (out != NULL && k != NULL && u != NULL)
	{
		eddh448_load(&x1, u);
		qsc_memutils_clear(&x2, sizeof(x2));
		qsc_memutils_clear(&z2, sizeof(z2));
		x2.v[0U] = 1U;
		x3 = x1;
		qsc_memutils_clear(&z3, sizeof(z3));
		z3.v[0U] = 1U;
		swap = 0U;

		for (i = 447; i >= 0; --i)
		{
			kbit = ((uint64_t)k[(size_t)i >> 3] >> ((uint32_t)i & 7U)) & 1U;
			swap ^= kbit;
			eddh448_swap(&x2, &x3, swap);
			eddh448_swap(&z2, &z3, swap);
			swap = kbit;
			eddh448_add(&a, &x2, &z2);
			eddh448_square(&aa, &a);
			eddh448_sub(&b, &x2, &z2);
			eddh448_square(&bb, &b);
			eddh448_sub(&e, &aa, &bb);
			eddh448_add(&c, &x3, &z3);
			eddh448_sub(&d, &x3, &z3);
			eddh448_mul(&da, &d, &a);
			eddh448_mul(&cb, &c, &b);
			eddh448_add(&t, &da, &cb);
			eddh448_square(&x3, &t);
			eddh448_sub(&t, &da, &cb);
			eddh448_square(&t, &t);

			if (fixed_base == true)
			{
				eddh448_mul_small(&z3, &t, 5U);
			}
			else
			{
				eddh448_mul(&z3, &x1, &t);
			}

			eddh448_mul(&x2, &aa, &bb);
			eddh448_mul_small(&t, &e, QSC_X448_A24);
			eddh448_add(&t, &aa, &t);
			eddh448_mul(&z2, &e, &t);
		}

		eddh448_swap(&x2, &x3, swap);
		eddh448_swap(&z2, &z3, swap);
		eddh448_invert(&inv, &z2);
		eddh448_mul(&x2, &x2, &inv);
		eddh448_store(out, &x2);

		qsc_memutils_secure_erase(&a, sizeof(a));
		qsc_memutils_secure_erase(&b, sizeof(b));
		qsc_memutils_secure_erase(&aa, sizeof(aa));
		qsc_memutils_secure_erase(&bb, sizeof(bb));
		qsc_memutils_secure_erase(&c, sizeof(c));
		qsc_memutils_secure_erase(&d, sizeof(d));
		qsc_memutils_secure_erase(&da, sizeof(da));
		qsc_memutils_secure_erase(&cb, sizeof(cb));
		qsc_memutils_secure_erase(&e, sizeof(e));
		qsc_memutils_secure_erase(&t, sizeof(t));
		qsc_memutils_secure_erase(&x1, sizeof(x1));
		qsc_memutils_secure_erase(&x2, sizeof(x2));
		qsc_memutils_secure_erase(&z2, sizeof(z2));
		qsc_memutils_secure_erase(&x3, sizeof(x3));
		qsc_memutils_secure_erase(&z3, sizeof(z3));
		qsc_memutils_secure_erase(&inv, sizeof(inv));
		swap = 0U;
		kbit = 0U;
	}
}

void qsc_crypto_scalarmult_curve448_ref10_base(uint8_t* q, const uint8_t* n)
{
	QSC_ASSERT(q != NULL);
	QSC_ASSERT(n != NULL);

	if (q != NULL && n != NULL)
	{
		eddh448_scalar_multiply(q, n, eddh448_base_u, true);
	}
	else if (q != NULL)
	{
		qsc_memutils_clear(q, QSC_X448_SECRET_SIZE);
	}
}

void qsc_crypto_scalarmult_curve448_ref10(uint8_t* r, const uint8_t* n, const uint8_t* q)
{
	QSC_ASSERT(r != NULL);
	QSC_ASSERT(n != NULL);
	QSC_ASSERT(q != NULL);

	if (r != NULL && n != NULL && q != NULL)
	{
		eddh448_scalar_multiply(r, n, q, false);
	}
	else if (r != NULL)
	{
		qsc_memutils_clear(r, QSC_X448_SECRET_SIZE);
	}
}

void qsc_crypto_sc448_clamp(uint8_t* k)
{
	QSC_ASSERT(k != NULL);

	if (k != NULL)
	{
		qsc_sc448_clamp(k);
	}
}

void qsc_crypto_scalarmult_curve448(uint8_t* q, const uint8_t* n, const uint8_t* p)
{
	uint8_t clamped[QSC_X448_PRIVATEKEY_SIZE];

	QSC_ASSERT(q != NULL);
	QSC_ASSERT(n != NULL);
	QSC_ASSERT(p != NULL);

	if (q != NULL && n != NULL && p != NULL)
	{
		qsc_memutils_copy(clamped, n, sizeof(clamped));
		qsc_sc448_clamp(clamped);
		eddh448_scalar_multiply(q, clamped, p, false);
		qsc_memutils_secure_erase(clamped, sizeof(clamped));
	}
	else if (q != NULL)
	{
		qsc_memutils_clear(q, QSC_X448_SECRET_SIZE);
	}
}

void qsc_x448_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
	bool generated;

	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(rng_generate != NULL);

	generated = false;

	if (publickey != NULL && privatekey != NULL && rng_generate != NULL)
	{
		generated = rng_generate(privatekey, QSC_X448_PRIVATEKEY_SIZE);

		if (generated == true)
		{
			qsc_x448_public_from_private(publickey, privatekey);
		}
	}

	if (generated == false)
	{
		if (publickey != NULL)
		{
			qsc_memutils_clear(publickey, QSC_X448_PUBLICKEY_SIZE);
		}

		if (privatekey != NULL)
		{
			qsc_memutils_secure_erase(privatekey, QSC_X448_PRIVATEKEY_SIZE);
		}
	}
}

void qsc_x448_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed)
{
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(seed != NULL);

	if (publickey != NULL && privatekey != NULL && seed != NULL)
	{
		if (privatekey != seed)
		{
			qsc_memutils_copy(privatekey, seed, QSC_X448_PRIVATEKEY_SIZE);
		}

		qsc_x448_public_from_private(publickey, privatekey);
	}
	else
	{
		if (publickey != NULL)
		{
			qsc_memutils_clear(publickey, QSC_X448_PUBLICKEY_SIZE);
		}

		if (privatekey != NULL)
		{
			qsc_memutils_secure_erase(privatekey, QSC_X448_PRIVATEKEY_SIZE);
		}
	}
}

bool qsc_x448_key_exchange(uint8_t* secret, const uint8_t* publickey, const uint8_t* privatekey)
{
	uint8_t combined;
	size_t i;

	QSC_ASSERT(secret != NULL);
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(publickey != NULL);

	combined = 0U;

	if (secret != NULL && privatekey != NULL && publickey != NULL)
	{
		qsc_crypto_scalarmult_curve448(secret, privatekey, publickey);

		for (i = 0U; i < QSC_X448_SECRET_SIZE; ++i)
		{
			combined |= secret[i];
		}
	}
	else if (secret != NULL)
	{
		qsc_memutils_clear(secret, QSC_X448_SECRET_SIZE);
	}

	return (combined != 0U);
}

void qsc_x448_public_from_private(uint8_t* publickey, const uint8_t* privatekey)
{
	uint8_t clamped[QSC_X448_PRIVATEKEY_SIZE];

	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(privatekey != NULL);

	if (publickey != NULL && privatekey != NULL)
	{
		qsc_memutils_copy(clamped, privatekey, sizeof(clamped));
		qsc_sc448_clamp(clamped);
		eddh448_scalar_multiply(publickey, clamped, eddh448_base_u, true);
		qsc_memutils_secure_erase(clamped, sizeof(clamped));
	}
	else if (publickey != NULL)
	{
		qsc_memutils_clear(publickey, QSC_X448_PUBLICKEY_SIZE);
	}
}

/* \endcond NO_DOCUMENT */
