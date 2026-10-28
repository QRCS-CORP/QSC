#include "sha3.h"
#include "intutils.h"
#include "memutils.h"

/** \def KPA_LEAF_HASH128
 * \brief Legacy KPA-128 leaf digest size in bytes. */
#define KPA_LEAF_HASH128 16ULL
/** \def KPA_LEAF_HASH256
 * \brief Legacy KPA-256 leaf digest size in bytes. */
#define KPA_LEAF_HASH256 32ULL
/** \def KPA_LEAF_HASH512
 * \brief Legacy KPA-512 leaf digest size in bytes. */
#define KPA_LEAF_HASH512 64ULL

/** \brief Round constants in QSC order; the first 24 define Keccak-f[1600]. */
static const uint64_t KECCAK_ROUND_CONSTANTS[QSC_KECCAK_PERMUTATION_MAX_ROUNDS] =
{
	0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL, 0x8000000080008000ULL,
	0x000000000000808BULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
	0x000000000000008AULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
	0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
	0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800AULL, 0x800000008000000AULL,
	0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
	0x8000000080008082ULL, 0x800000008000800AULL, 0x8000000000000003ULL, 0x8000000080000009ULL,
	0x8000000000008082ULL, 0x0000000000008009ULL, 0x8000000000000080ULL, 0x0000000000008083ULL,
	0x8000000000000081ULL, 0x0000000000000001ULL, 0x000000000000800BULL, 0x8000000080008001ULL,
	0x0000000000000080ULL, 0x8000000000008000ULL, 0x8000000080008001ULL, 0x0000000000000009ULL,
	0x800000008000808BULL, 0x0000000000000081ULL, 0x8000000000000082ULL, 0x000000008000008BULL,
	0x8000000080008009ULL, 0x8000000080000000ULL, 0x0000000080000080ULL, 0x0000000080008003ULL
};

/* Common */

/**
 * \brief Validate public sponge parameters without accessing message data.
 * \param rate: Sponge rate in bytes; a nonzero multiple of eight, at most 200.
 * \param rounds: Even QSC round count from zero through 48.
 * \return True when both parameters are within the implemented bounds.
 * \note No allocation or shared state; reentrant. Lengths and round counts are public.
 */
static bool keccak_parameters_valid(size_t rate, size_t rounds)
{
	bool valid;

	valid = rate != 0U && rate <= QSC_KECCAK_STATE_BYTE_SIZE && rate % sizeof(uint64_t) == 0U &&
		rounds <= QSC_KECCAK_PERMUTATION_MAX_ROUNDS && rounds % 2U == 0U;

	return valid;
}

/**
 * \brief XOR at most 200 input bytes into little-endian Keccak lanes.
 * \param state: Mutable array of 25 lanes.
 * \param message: Readable msglen-byte input, possibly unaligned.
 * \param msglen: Public byte count, including a possible partial final lane.
 * \note Borrowed storage; no allocation or shared state. Reentrant with independent
 * states and disjoint outputs. Callers validate storage and public lengths.
 */
static void keccak_fast_absorb(uint64_t* state, const uint8_t* message, size_t msglen)
{
#if defined(QSC_SYSTEM_IS_LITTLE_ENDIAN)
	qsc_memutils_xor((uint8_t*)state, message, msglen);
#else
	for (size_t i = 0U; i < msglen / sizeof(uint64_t); ++i)
	{
		state[i] ^= qsc_intutils_le8to64((message + (sizeof(uint64_t) * i)));
	}

	for (size_t i = msglen - msglen % sizeof(uint64_t); i < msglen; ++i)
	{
		state[i / sizeof(uint64_t)] ^= (uint64_t)message[i] << (8U * (i % sizeof(uint64_t)));
	}
#endif
}

/**
 * \brief Decode one little-endian Keccak lane from unaligned input.
 * \param input: Borrowed readable buffer of at least eight bytes.
 * \return Decoded 64-bit lane value.
 * \note Constant-time. No allocation, shared state, ownership transfer, or
 * thread-safety restrictions. Does not access bytes outside the input lane.
 */
static inline uint64_t keccak_load64(const uint8_t* input)
{
	uint64_t value;

	value = ((uint64_t)input[0U]) |
		((uint64_t)input[1U] << 8U) |
		((uint64_t)input[2U] << 16U) |
		((uint64_t)input[3U] << 24U) |
		((uint64_t)input[4U] << 32U) |
		((uint64_t)input[5U] << 40U) |
		((uint64_t)input[6U] << 48U) |
		((uint64_t)input[7U] << 56U);

	return value;
}

/**
 * \brief Encode one Keccak lane in little-endian byte order.
 * \param output: Borrowed writable buffer of at least eight bytes.
 * \param value: Lane value to encode.
 * \note Constant-time, reentrant, no allocation, ownership transfer, or
 * out-of-bounds accesses. The output may be unaligned.
 */
static inline void keccak_store64(uint8_t* output, uint64_t value)
{
	output[0U] = (uint8_t)value;
	output[1U] = (uint8_t)(value >> 8U);
	output[2U] = (uint8_t)(value >> 16U);
	output[3U] = (uint8_t)(value >> 24U);
	output[4U] = (uint8_t)(value >> 32U);
	output[5U] = (uint8_t)(value >> 40U);
	output[6U] = (uint8_t)(value >> 48U);
	output[7U] = (uint8_t)(value >> 56U);
}

static inline uint64_t keccak_rotl64(const uint64_t value, const uint32_t shift)
{
	/* rotate one scalar Keccak lane using a compile-time-fixed shift */
	uint64_t result;

	result = (value << shift) | (value >> (64U - shift));

	return result;
}

static size_t keccak_left_encode(uint8_t* buffer, size_t value)
{
	/* encode a nonnegative integer using SP 800-185 left_encode */
	size_t n;
	size_t v;

	for (v = value, n = 0U; v != 0U && n < sizeof(size_t); ++n, v >>= 8U) { /* increments n */ }

	if (n == 0U)
	{
		n = 1U;
	}

	for (size_t i = 1U; i <= n; ++i)
	{
		buffer[i] = (uint8_t)(value >> (8U * (n - i)));
	}

	buffer[0U] = (uint8_t)n;

	return n + 1U;
}

static size_t keccak_right_encode(uint8_t* buffer, size_t value)
{
	/* encode a nonnegative integer using SP 800-185 right_encode */
	size_t n;
	size_t v;

	for (v = value, n = 0U; v != 0U && (n < sizeof(size_t)); ++n, v >>= 8U) { /* increments n */ }

	if (n == 0U)
	{
		n = 1U;
	}

	for (size_t i = 1U; i <= n; ++i)
	{
		buffer[i - 1U] = (uint8_t)(value >> (8U * (n - i)));
	}

	buffer[n] = (uint8_t)n;

	return n + 1U;
}

#if defined(QSC_SYSTEM_ARM_INTRINSICS)

static inline uint64x2_t keccak_xor3_arm(uint64x2_t a, uint64x2_t b, uint64x2_t c)
{
	/* XOR three paired lanes; reentrant and storage-free */
#if defined(QSC_SYSTEM_ARM_SHA3_ENABLED)
	return veor3q_u64(a, b, c);
#else
	return veorq_u64(veorq_u64(a, b), c);
#endif
}

static inline uint64x2_t keccak_chi_arm(uint64x2_t a, uint64x2_t b, uint64x2_t c)
{
	/* evaluate paired Keccak chi lanes; reentrant and storage-free */
#if defined(QSC_SYSTEM_ARM_SHA3_ENABLED)
	return vbcaxq_u64(a, c, b);
#else
	return veorq_u64(a, vbicq_u64(c, b));
#endif
}

static inline uint64x2_t keccak_theta_arm(uint64x2_t a, uint64x2_t b)
{
	/* evaluate paired Keccak theta corrections; reentrant and storage-free */
#if defined(QSC_SYSTEM_ARM_SHA3_ENABLED)
	return vrax1q_u64(a, b);
#else
	return veorq_u64(a, vorrq_u64(vshlq_n_u64(b, 1), vshrq_n_u64(b, 63)));
#endif
}

static void keccak_permute_p2x1600_arm(uint64x2_t state[QSC_KECCAK_STATE_SIZE], size_t rounds)
{
	/* permute two independent Keccak states in NEON lanes */
	QSC_ASSERT(rounds % 2U == 0U);

	uint64x2_t a0;
	uint64x2_t a1;
	uint64x2_t a2;
	uint64x2_t a3;
	uint64x2_t a4;
	uint64x2_t a5;
	uint64x2_t a6;
	uint64x2_t a7;
	uint64x2_t a8;
	uint64x2_t a9;
	uint64x2_t a10;
	uint64x2_t a11;
	uint64x2_t a12;
	uint64x2_t a13;
	uint64x2_t a14;
	uint64x2_t a15;
	uint64x2_t a16;
	uint64x2_t a17;
	uint64x2_t a18;
	uint64x2_t a19;
	uint64x2_t a20;
	uint64x2_t a21;
	uint64x2_t a22;
	uint64x2_t a23;
	uint64x2_t a24;
	uint64x2_t c0;
	uint64x2_t c1;
	uint64x2_t c2;
	uint64x2_t c3;
	uint64x2_t c4;
	uint64x2_t d0;
	uint64x2_t d1;
	uint64x2_t d2;
	uint64x2_t d3;
	uint64x2_t d4;
	uint64x2_t e0;
	uint64x2_t e1;
	uint64x2_t e2;
	uint64x2_t e3;
	uint64x2_t e4;
	uint64x2_t e5;
	uint64x2_t e6;
	uint64x2_t e7;
	uint64x2_t e8;
	uint64x2_t e9;
	uint64x2_t e10;
	uint64x2_t e11;
	uint64x2_t e12;
	uint64x2_t e13;
	uint64x2_t e14;
	uint64x2_t e15;
	uint64x2_t e16;
	uint64x2_t e17;
	uint64x2_t e18;
	uint64x2_t e19;
	uint64x2_t e20;
	uint64x2_t e21;
	uint64x2_t e22;
	uint64x2_t e23;
	uint64x2_t e24;


	size_t i;

	a0 = state[0U];
	a1 = state[1U];
	a2 = state[2U];
	a3 = state[3U];
	a4 = state[4U];
	a5 = state[5U];
	a6 = state[6U];
	a7 = state[7U];
	a8 = state[8U];
	a9 = state[9U];
	a10 = state[10U];
	a11 = state[11U];
	a12 = state[12U];
	a13 = state[13U];
	a14 = state[14U];
	a15 = state[15U];
	a16 = state[16U];
	a17 = state[17U];
	a18 = state[18U];
	a19 = state[19U];
	a20 = state[20U];
	a21 = state[21U];
	a22 = state[22U];
	a23 = state[23U];
	a24 = state[24U];

	for (i = 0U; i < rounds; i += 2U)
	{
		/* round n */
		c0 = veorq_u64(keccak_xor3_arm(a0, a5, veorq_u64(a10, a15)), a20);
		c1 = veorq_u64(keccak_xor3_arm(a1, a6, veorq_u64(a11, a16)), a21);
		c2 = veorq_u64(keccak_xor3_arm(a2, a7, veorq_u64(a12, a17)), a22);
		c3 = veorq_u64(keccak_xor3_arm(a3, a8, veorq_u64(a13, a18)), a23);
		c4 = veorq_u64(keccak_xor3_arm(a4, a9, veorq_u64(a14, a19)), a24);
		d0 = keccak_theta_arm(c4, c1);
		d1 = keccak_theta_arm(c0, c2);
		d2 = keccak_theta_arm(c1, c3);
		d3 = keccak_theta_arm(c2, c4);
		d4 = keccak_theta_arm(c3, c0);
		a0 = veorq_u64(a0, d0);
		c0 = a0;
		a6 = veorq_u64(a6, d1);
		c1 = vorrq_u64(vshlq_n_u64(a6, 44), vshrq_n_u64(a6, 64 - 44));
		a12 = veorq_u64(a12, d2);
		c2 = vorrq_u64(vshlq_n_u64(a12, 43), vshrq_n_u64(a12, 64 - 43));
		a18 = veorq_u64(a18, d3);
		c3 = vorrq_u64(vshlq_n_u64(a18, 21), vshrq_n_u64(a18, 64 - 21));
		a24 = veorq_u64(a24, d4);
		c4 = vorrq_u64(vshlq_n_u64(a24, 14), vshrq_n_u64(a24, 64 - 14));
		e0 = keccak_chi_arm(c0, c1, c2);
		e0 = veorq_u64(e0, vdupq_n_u64(KECCAK_ROUND_CONSTANTS[i]));
		e1 = keccak_chi_arm(c1, c2, c3);
		e2 = keccak_chi_arm(c2, c3, c4);
		e3 = keccak_chi_arm(c3, c4, c0);
		e4 = keccak_chi_arm(c4, c0, c1);
		a3 = veorq_u64(a3, d3);
		c0 = vorrq_u64(vshlq_n_u64(a3, 28), vshrq_n_u64(a3, 64 - 28));
		a9 = veorq_u64(a9, d4);
		c1 = vorrq_u64(vshlq_n_u64(a9, 20), vshrq_n_u64(a9, 64 - 20));
		a10 = veorq_u64(a10, d0);
		c2 = vorrq_u64(vshlq_n_u64(a10, 3), vshrq_n_u64(a10, 64 - 3));
		a16 = veorq_u64(a16, d1);
		c3 = vorrq_u64(vshlq_n_u64(a16, 45), vshrq_n_u64(a16, 64 - 45));
		a22 = veorq_u64(a22, d2);
		c4 = vorrq_u64(vshlq_n_u64(a22, 61), vshrq_n_u64(a22, 64 - 61));
		e5 = keccak_chi_arm(c0, c1, c2);
		e6 = keccak_chi_arm(c1, c2, c3);
		e7 = keccak_chi_arm(c2, c3, c4);
		e8 = keccak_chi_arm(c3, c4, c0);
		e9 = keccak_chi_arm(c4, c0, c1);
		a1 = veorq_u64(a1, d1);
		c0 = vorrq_u64(vshlq_n_u64(a1, 1), vshrq_n_u64(a1, 64 - 1));
		a7 = veorq_u64(a7, d2);
		c1 = vorrq_u64(vshlq_n_u64(a7, 6), vshrq_n_u64(a7, 64 - 6));
		a13 = veorq_u64(a13, d3);
		c2 = vorrq_u64(vshlq_n_u64(a13, 25), vshrq_n_u64(a13, 64 - 25));
		a19 = veorq_u64(a19, d4);
		c3 = vorrq_u64(vshlq_n_u64(a19, 8), vshrq_n_u64(a19, 64 - 8));
		a20 = veorq_u64(a20, d0);
		c4 = vorrq_u64(vshlq_n_u64(a20, 18), vshrq_n_u64(a20, 64 - 18));
		e10 = keccak_chi_arm(c0, c1, c2);
		e11 = keccak_chi_arm(c1, c2, c3);
		e12 = keccak_chi_arm(c2, c3, c4);
		e13 = keccak_chi_arm(c3, c4, c0);
		e14 = keccak_chi_arm(c4, c0, c1);
		a4 = veorq_u64(a4, d4);
		c0 = vorrq_u64(vshlq_n_u64(a4, 27), vshrq_n_u64(a4, 64 - 27));
		a5 = veorq_u64(a5, d0);
		c1 = vorrq_u64(vshlq_n_u64(a5, 36), vshrq_n_u64(a5, 64 - 36));
		a11 = veorq_u64(a11, d1);
		c2 = vorrq_u64(vshlq_n_u64(a11, 10), vshrq_n_u64(a11, 64 - 10));
		a17 = veorq_u64(a17, d2);
		c3 = vorrq_u64(vshlq_n_u64(a17, 15), vshrq_n_u64(a17, 64 - 15));
		a23 = veorq_u64(a23, d3);
		c4 = vorrq_u64(vshlq_n_u64(a23, 56), vshrq_n_u64(a23, 64 - 56));
		e15 = keccak_chi_arm(c0, c1, c2);
		e16 = keccak_chi_arm(c1, c2, c3);
		e17 = keccak_chi_arm(c2, c3, c4);
		e18 = keccak_chi_arm(c3, c4, c0);
		e19 = keccak_chi_arm(c4, c0, c1);
		a2 = veorq_u64(a2, d2);
		c0 = vorrq_u64(vshlq_n_u64(a2, 62), vshrq_n_u64(a2, 64 - 62));
		a8 = veorq_u64(a8, d3);
		c1 = vorrq_u64(vshlq_n_u64(a8, 55), vshrq_n_u64(a8, 64 - 55));
		a14 = veorq_u64(a14, d4);
		c2 = vorrq_u64(vshlq_n_u64(a14, 39), vshrq_n_u64(a14, 64 - 39));
		a15 = veorq_u64(a15, d0);
		c3 = vorrq_u64(vshlq_n_u64(a15, 41), vshrq_n_u64(a15, 64 - 41));
		a21 = veorq_u64(a21, d1);
		c4 = vorrq_u64(vshlq_n_u64(a21, 2), vshrq_n_u64(a21, 64 - 2));
		e20 = keccak_chi_arm(c0, c1, c2);
		e21 = keccak_chi_arm(c1, c2, c3);
		e22 = keccak_chi_arm(c2, c3, c4);
		e23 = keccak_chi_arm(c3, c4, c0);
		e24 = keccak_chi_arm(c4, c0, c1);
		/* round n + 1 */
		c0 = veorq_u64(keccak_xor3_arm(e0, e5, veorq_u64(e10, e15)), e20);
		c1 = veorq_u64(keccak_xor3_arm(e1, e6, veorq_u64(e11, e16)), e21);
		c2 = veorq_u64(keccak_xor3_arm(e2, e7, veorq_u64(e12, e17)), e22);
		c3 = veorq_u64(keccak_xor3_arm(e3, e8, veorq_u64(e13, e18)), e23);
		c4 = veorq_u64(keccak_xor3_arm(e4, e9, veorq_u64(e14, e19)), e24);
		d0 = keccak_theta_arm(c4, c1);
		d1 = keccak_theta_arm(c0, c2);
		d2 = keccak_theta_arm(c1, c3);
		d3 = keccak_theta_arm(c2, c4);
		d4 = keccak_theta_arm(c3, c0);
		e0 = veorq_u64(e0, d0);
		c0 = e0;
		e6 = veorq_u64(e6, d1);
		c1 = vorrq_u64(vshlq_n_u64(e6, 44), vshrq_n_u64(e6, 64 - 44));
		e12 = veorq_u64(e12, d2);
		c2 = vorrq_u64(vshlq_n_u64(e12, 43), vshrq_n_u64(e12, 64 - 43));
		e18 = veorq_u64(e18, d3);
		c3 = vorrq_u64(vshlq_n_u64(e18, 21), vshrq_n_u64(e18, 64 - 21));
		e24 = veorq_u64(e24, d4);
		c4 = vorrq_u64(vshlq_n_u64(e24, 14), vshrq_n_u64(e24, 64 - 14));
		a0 = keccak_chi_arm(c0, c1, c2);
		a0 = veorq_u64(a0, vdupq_n_u64(KECCAK_ROUND_CONSTANTS[i + 1U]));
		a1 = keccak_chi_arm(c1, c2, c3);
		a2 = keccak_chi_arm(c2, c3, c4);
		a3 = keccak_chi_arm(c3, c4, c0);
		a4 = keccak_chi_arm(c4, c0, c1);
		e3 = veorq_u64(e3, d3);
		c0 = vorrq_u64(vshlq_n_u64(e3, 28), vshrq_n_u64(e3, 64 - 28));
		e9 = veorq_u64(e9, d4);
		c1 = vorrq_u64(vshlq_n_u64(e9, 20), vshrq_n_u64(e9, 64 - 20));
		e10 = veorq_u64(e10, d0);
		c2 = vorrq_u64(vshlq_n_u64(e10, 3), vshrq_n_u64(e10, 64 - 3));
		e16 = veorq_u64(e16, d1);
		c3 = vorrq_u64(vshlq_n_u64(e16, 45), vshrq_n_u64(e16, 64 - 45));
		e22 = veorq_u64(e22, d2);
		c4 = vorrq_u64(vshlq_n_u64(e22, 61), vshrq_n_u64(e22, 64 - 61));
		a5 = keccak_chi_arm(c0, c1, c2);
		a6 = keccak_chi_arm(c1, c2, c3);
		a7 = keccak_chi_arm(c2, c3, c4);
		a8 = keccak_chi_arm(c3, c4, c0);
		a9 = keccak_chi_arm(c4, c0, c1);
		e1 = veorq_u64(e1, d1);
		c0 = vorrq_u64(vshlq_n_u64(e1, 1), vshrq_n_u64(e1, 64 - 1));
		e7 = veorq_u64(e7, d2);
		c1 = vorrq_u64(vshlq_n_u64(e7, 6), vshrq_n_u64(e7, 64 - 6));
		e13 = veorq_u64(e13, d3);
		c2 = vorrq_u64(vshlq_n_u64(e13, 25), vshrq_n_u64(e13, 64 - 25));
		e19 = veorq_u64(e19, d4);
		c3 = vorrq_u64(vshlq_n_u64(e19, 8), vshrq_n_u64(e19, 64 - 8));
		e20 = veorq_u64(e20, d0);
		c4 = vorrq_u64(vshlq_n_u64(e20, 18), vshrq_n_u64(e20, 64 - 18));
		a10 = keccak_chi_arm(c0, c1, c2);
		a11 = keccak_chi_arm(c1, c2, c3);
		a12 = keccak_chi_arm(c2, c3, c4);
		a13 = keccak_chi_arm(c3, c4, c0);
		a14 = keccak_chi_arm(c4, c0, c1);
		e4 = veorq_u64(e4, d4);
		c0 = vorrq_u64(vshlq_n_u64(e4, 27), vshrq_n_u64(e4, 64 - 27));
		e5 = veorq_u64(e5, d0);
		c1 = vorrq_u64(vshlq_n_u64(e5, 36), vshrq_n_u64(e5, 64 - 36));
		e11 = veorq_u64(e11, d1);
		c2 = vorrq_u64(vshlq_n_u64(e11, 10), vshrq_n_u64(e11, 64 - 10));
		e17 = veorq_u64(e17, d2);
		c3 = vorrq_u64(vshlq_n_u64(e17, 15), vshrq_n_u64(e17, 64 - 15));
		e23 = veorq_u64(e23, d3);
		c4 = vorrq_u64(vshlq_n_u64(e23, 56), vshrq_n_u64(e23, 64 - 56));
		a15 = keccak_chi_arm(c0, c1, c2);
		a16 = keccak_chi_arm(c1, c2, c3);
		a17 = keccak_chi_arm(c2, c3, c4);
		a18 = keccak_chi_arm(c3, c4, c0);
		a19 = keccak_chi_arm(c4, c0, c1);
		e2 = veorq_u64(e2, d2);
		c0 = vorrq_u64(vshlq_n_u64(e2, 62), vshrq_n_u64(e2, 64 - 62));
		e8 = veorq_u64(e8, d3);
		c1 = vorrq_u64(vshlq_n_u64(e8, 55), vshrq_n_u64(e8, 64 - 55));
		e14 = veorq_u64(e14, d4);
		c2 = vorrq_u64(vshlq_n_u64(e14, 39), vshrq_n_u64(e14, 64 - 39));
		e15 = veorq_u64(e15, d0);
		c3 = vorrq_u64(vshlq_n_u64(e15, 41), vshrq_n_u64(e15, 64 - 41));
		e21 = veorq_u64(e21, d1);
		c4 = vorrq_u64(vshlq_n_u64(e21, 2), vshrq_n_u64(e21, 64 - 2));
		a20 = keccak_chi_arm(c0, c1, c2);
		a21 = keccak_chi_arm(c1, c2, c3);
		a22 = keccak_chi_arm(c2, c3, c4);
		a23 = keccak_chi_arm(c3, c4, c0);
		a24 = keccak_chi_arm(c4, c0, c1);
	}

	state[0U] = a0;
	state[1U] = a1;
	state[2U] = a2;
	state[3U] = a3;
	state[4U] = a4;
	state[5U] = a5;
	state[6U] = a6;
	state[7U] = a7;
	state[8U] = a8;
	state[9U] = a9;
	state[10U] = a10;
	state[11U] = a11;
	state[12U] = a12;
	state[13U] = a13;
	state[14U] = a14;
	state[15U] = a15;
	state[16U] = a16;
	state[17U] = a17;
	state[18U] = a18;
	state[19U] = a19;
	state[20U] = a20;
	state[21U] = a21;
	state[22U] = a22;
	state[23U] = a23;
	state[24U] = a24;
}


#endif

#if defined(QSC_SYSTEM_HAS_AVX512)

/**
 * \brief Apply QSC rounds to 8 independent interleaved Keccak states.
 * \param state: Mutable 25-vector state, aligned for 512-bit vectors.
 * \param rounds: Even public count from 0 through 48; 24 selects Keccak-f[1600].
 * \note Borrowed storage; no allocation or shared state. Reentrant with independent
 * states and disjoint outputs. Callers validate storage and public lengths.
 */
static void qsc_keccak_permute_p8x1600(__m512i state[QSC_KECCAK_STATE_SIZE], size_t rounds)
{
	QSC_ASSERT(rounds % 2U == 0U);

	__m512i a0;
	__m512i a1;
	__m512i a2;
	__m512i a3;
	__m512i a4;
	__m512i a5;
	__m512i a6;
	__m512i a7;
	__m512i a8;
	__m512i a9;
	__m512i a10;
	__m512i a11;
	__m512i a12;
	__m512i a13;
	__m512i a14;
	__m512i a15;
	__m512i a16;
	__m512i a17;
	__m512i a18;
	__m512i a19;
	__m512i a20;
	__m512i a21;
	__m512i a22;
	__m512i a23;
	__m512i a24;
	__m512i c0;
	__m512i c1;
	__m512i c2;
	__m512i c3;
	__m512i c4;
	__m512i d0;
	__m512i d1;
	__m512i d2;
	__m512i d3;
	__m512i d4;
	__m512i e0;
	__m512i e1;
	__m512i e2;
	__m512i e3;
	__m512i e4;
	__m512i e5;
	__m512i e6;
	__m512i e7;
	__m512i e8;
	__m512i e9;
	__m512i e10;
	__m512i e11;
	__m512i e12;
	__m512i e13;
	__m512i e14;
	__m512i e15;
	__m512i e16;
	__m512i e17;
	__m512i e18;
	__m512i e19;
	__m512i e20;
	__m512i e21;
	__m512i e22;
	__m512i e23;
	__m512i e24;
	size_t i;

	a0 = state[0U];
	a1 = state[1U];
	a2 = state[2U];
	a3 = state[3U];
	a4 = state[4U];
	a5 = state[5U];
	a6 = state[6U];
	a7 = state[7U];
	a8 = state[8U];
	a9 = state[9U];
	a10 = state[10U];
	a11 = state[11U];
	a12 = state[12U];
	a13 = state[13U];
	a14 = state[14U];
	a15 = state[15U];
	a16 = state[16U];
	a17 = state[17U];
	a18 = state[18U];
	a19 = state[19U];
	a20 = state[20U];
	a21 = state[21U];
	a22 = state[22U];
	a23 = state[23U];
	a24 = state[24U];

	for (i = 0U; i < rounds; i += 2U)
	{
		/* round n */
		c0 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(a0, a5), _mm512_xor_si512(a10, a15)), a20);
		c1 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(a1, a6), _mm512_xor_si512(a11, a16)), a21);
		c2 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(a2, a7), _mm512_xor_si512(a12, a17)), a22);
		c3 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(a3, a8), _mm512_xor_si512(a13, a18)), a23);
		c4 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(a4, a9), _mm512_xor_si512(a14, a19)), a24);
		d0 = _mm512_xor_si512(c4, _mm512_rol_epi64(c1, 1));
		d1 = _mm512_xor_si512(c0, _mm512_rol_epi64(c2, 1));
		d2 = _mm512_xor_si512(c1, _mm512_rol_epi64(c3, 1));
		d3 = _mm512_xor_si512(c2, _mm512_rol_epi64(c4, 1));
		d4 = _mm512_xor_si512(c3, _mm512_rol_epi64(c0, 1));
		a0 = _mm512_xor_si512(a0, d0);
		c0 = a0;
		a6 = _mm512_xor_si512(a6, d1);
		c1 = _mm512_rol_epi64(a6, 44);
		a12 = _mm512_xor_si512(a12, d2);
		c2 = _mm512_rol_epi64(a12, 43);
		a18 = _mm512_xor_si512(a18, d3);
		c3 = _mm512_rol_epi64(a18, 21);
		a24 = _mm512_xor_si512(a24, d4);
		c4 = _mm512_rol_epi64(a24, 14);
		e0 = _mm512_ternarylogic_epi64(c0, c1, c2, 0xD2);
		e0 = _mm512_xor_si512(e0, _mm512_set1_epi64(KECCAK_ROUND_CONSTANTS[i]));
		e1 = _mm512_ternarylogic_epi64(c1, c2, c3, 0xD2);
		e2 = _mm512_ternarylogic_epi64(c2, c3, c4, 0xD2);
		e3 = _mm512_ternarylogic_epi64(c3, c4, c0, 0xD2);
		e4 = _mm512_ternarylogic_epi64(c4, c0, c1, 0xD2);
		a3 = _mm512_xor_si512(a3, d3);
		c0 = _mm512_rol_epi64(a3, 28);
		a9 = _mm512_xor_si512(a9, d4);
		c1 = _mm512_rol_epi64(a9, 20);
		a10 = _mm512_xor_si512(a10, d0);
		c2 = _mm512_rol_epi64(a10, 3);
		a16 = _mm512_xor_si512(a16, d1);
		c3 = _mm512_rol_epi64(a16, 45);
		a22 = _mm512_xor_si512(a22, d2);
		c4 = _mm512_rol_epi64(a22, 61);
		e5 = _mm512_ternarylogic_epi64(c0, c1, c2, 0xD2);
		e6 = _mm512_ternarylogic_epi64(c1, c2, c3, 0xD2);
		e7 = _mm512_ternarylogic_epi64(c2, c3, c4, 0xD2);
		e8 = _mm512_ternarylogic_epi64(c3, c4, c0, 0xD2);
		e9 = _mm512_ternarylogic_epi64(c4, c0, c1, 0xD2);
		a1 = _mm512_xor_si512(a1, d1);
		c0 = _mm512_rol_epi64(a1, 1);
		a7 = _mm512_xor_si512(a7, d2);
		c1 = _mm512_rol_epi64(a7, 6);
		a13 = _mm512_xor_si512(a13, d3);
		c2 = _mm512_rol_epi64(a13, 25);
		a19 = _mm512_xor_si512(a19, d4);
		c3 = _mm512_rol_epi64(a19, 8);
		a20 = _mm512_xor_si512(a20, d0);
		c4 = _mm512_rol_epi64(a20, 18);
		e10 = _mm512_ternarylogic_epi64(c0, c1, c2, 0xD2);
		e11 = _mm512_ternarylogic_epi64(c1, c2, c3, 0xD2);
		e12 = _mm512_ternarylogic_epi64(c2, c3, c4, 0xD2);
		e13 = _mm512_ternarylogic_epi64(c3, c4, c0, 0xD2);
		e14 = _mm512_ternarylogic_epi64(c4, c0, c1, 0xD2);
		a4 = _mm512_xor_si512(a4, d4);
		c0 = _mm512_rol_epi64(a4, 27);
		a5 = _mm512_xor_si512(a5, d0);
		c1 = _mm512_rol_epi64(a5, 36);
		a11 = _mm512_xor_si512(a11, d1);
		c2 = _mm512_rol_epi64(a11, 10);
		a17 = _mm512_xor_si512(a17, d2);
		c3 = _mm512_rol_epi64(a17, 15);
		a23 = _mm512_xor_si512(a23, d3);
		c4 = _mm512_rol_epi64(a23, 56);
		e15 = _mm512_ternarylogic_epi64(c0, c1, c2, 0xD2);
		e16 = _mm512_ternarylogic_epi64(c1, c2, c3, 0xD2);
		e17 = _mm512_ternarylogic_epi64(c2, c3, c4, 0xD2);
		e18 = _mm512_ternarylogic_epi64(c3, c4, c0, 0xD2);
		e19 = _mm512_ternarylogic_epi64(c4, c0, c1, 0xD2);
		a2 = _mm512_xor_si512(a2, d2);
		c0 = _mm512_rol_epi64(a2, 62);
		a8 = _mm512_xor_si512(a8, d3);
		c1 = _mm512_rol_epi64(a8, 55);
		a14 = _mm512_xor_si512(a14, d4);
		c2 = _mm512_rol_epi64(a14, 39);
		a15 = _mm512_xor_si512(a15, d0);
		c3 = _mm512_rol_epi64(a15, 41);
		a21 = _mm512_xor_si512(a21, d1);
		c4 = _mm512_rol_epi64(a21, 2);
		e20 = _mm512_ternarylogic_epi64(c0, c1, c2, 0xD2);
		e21 = _mm512_ternarylogic_epi64(c1, c2, c3, 0xD2);
		e22 = _mm512_ternarylogic_epi64(c2, c3, c4, 0xD2);
		e23 = _mm512_ternarylogic_epi64(c3, c4, c0, 0xD2);
		e24 = _mm512_ternarylogic_epi64(c4, c0, c1, 0xD2);
		/* round n + 1 */
		c0 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(e0, e5), _mm512_xor_si512(e10, e15)), e20);
		c1 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(e1, e6), _mm512_xor_si512(e11, e16)), e21);
		c2 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(e2, e7), _mm512_xor_si512(e12, e17)), e22);
		c3 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(e3, e8), _mm512_xor_si512(e13, e18)), e23);
		c4 = _mm512_xor_si512(_mm512_xor_si512(_mm512_xor_si512(e4, e9), _mm512_xor_si512(e14, e19)), e24);
		d0 = _mm512_xor_si512(c4, _mm512_rol_epi64(c1, 1));
		d1 = _mm512_xor_si512(c0, _mm512_rol_epi64(c2, 1));
		d2 = _mm512_xor_si512(c1, _mm512_rol_epi64(c3, 1));
		d3 = _mm512_xor_si512(c2, _mm512_rol_epi64(c4, 1));
		d4 = _mm512_xor_si512(c3, _mm512_rol_epi64(c0, 1));
		e0 = _mm512_xor_si512(e0, d0);
		c0 = e0;
		e6 = _mm512_xor_si512(e6, d1);
		c1 = _mm512_rol_epi64(e6, 44);
		e12 = _mm512_xor_si512(e12, d2);
		c2 = _mm512_rol_epi64(e12, 43);
		e18 = _mm512_xor_si512(e18, d3);
		c3 = _mm512_rol_epi64(e18, 21);
		e24 = _mm512_xor_si512(e24, d4);
		c4 = _mm512_rol_epi64(e24, 14);
		a0 = _mm512_ternarylogic_epi64(c0, c1, c2, 0xD2);
		a0 = _mm512_xor_si512(a0, _mm512_set1_epi64(KECCAK_ROUND_CONSTANTS[i + 1U]));
		a1 = _mm512_ternarylogic_epi64(c1, c2, c3, 0xD2);
		a2 = _mm512_ternarylogic_epi64(c2, c3, c4, 0xD2);
		a3 = _mm512_ternarylogic_epi64(c3, c4, c0, 0xD2);
		a4 = _mm512_ternarylogic_epi64(c4, c0, c1, 0xD2);
		e3 = _mm512_xor_si512(e3, d3);
		c0 = _mm512_rol_epi64(e3, 28);
		e9 = _mm512_xor_si512(e9, d4);
		c1 = _mm512_rol_epi64(e9, 20);
		e10 = _mm512_xor_si512(e10, d0);
		c2 = _mm512_rol_epi64(e10, 3);
		e16 = _mm512_xor_si512(e16, d1);
		c3 = _mm512_rol_epi64(e16, 45);
		e22 = _mm512_xor_si512(e22, d2);
		c4 = _mm512_rol_epi64(e22, 61);
		a5 = _mm512_ternarylogic_epi64(c0, c1, c2, 0xD2);
		a6 = _mm512_ternarylogic_epi64(c1, c2, c3, 0xD2);
		a7 = _mm512_ternarylogic_epi64(c2, c3, c4, 0xD2);
		a8 = _mm512_ternarylogic_epi64(c3, c4, c0, 0xD2);
		a9 = _mm512_ternarylogic_epi64(c4, c0, c1, 0xD2);
		e1 = _mm512_xor_si512(e1, d1);
		c0 = _mm512_rol_epi64(e1, 1);
		e7 = _mm512_xor_si512(e7, d2);
		c1 = _mm512_rol_epi64(e7, 6);
		e13 = _mm512_xor_si512(e13, d3);
		c2 = _mm512_rol_epi64(e13, 25);
		e19 = _mm512_xor_si512(e19, d4);
		c3 = _mm512_rol_epi64(e19, 8);
		e20 = _mm512_xor_si512(e20, d0);
		c4 = _mm512_rol_epi64(e20, 18);
		a10 = _mm512_ternarylogic_epi64(c0, c1, c2, 0xD2);
		a11 = _mm512_ternarylogic_epi64(c1, c2, c3, 0xD2);
		a12 = _mm512_ternarylogic_epi64(c2, c3, c4, 0xD2);
		a13 = _mm512_ternarylogic_epi64(c3, c4, c0, 0xD2);
		a14 = _mm512_ternarylogic_epi64(c4, c0, c1, 0xD2);
		e4 = _mm512_xor_si512(e4, d4);
		c0 = _mm512_rol_epi64(e4, 27);
		e5 = _mm512_xor_si512(e5, d0);
		c1 = _mm512_rol_epi64(e5, 36);
		e11 = _mm512_xor_si512(e11, d1);
		c2 = _mm512_rol_epi64(e11, 10);
		e17 = _mm512_xor_si512(e17, d2);
		c3 = _mm512_rol_epi64(e17, 15);
		e23 = _mm512_xor_si512(e23, d3);
		c4 = _mm512_rol_epi64(e23, 56);
		a15 = _mm512_ternarylogic_epi64(c0, c1, c2, 0xD2);
		a16 = _mm512_ternarylogic_epi64(c1, c2, c3, 0xD2);
		a17 = _mm512_ternarylogic_epi64(c2, c3, c4, 0xD2);
		a18 = _mm512_ternarylogic_epi64(c3, c4, c0, 0xD2);
		a19 = _mm512_ternarylogic_epi64(c4, c0, c1, 0xD2);
		e2 = _mm512_xor_si512(e2, d2);
		c0 = _mm512_rol_epi64(e2, 62);
		e8 = _mm512_xor_si512(e8, d3);
		c1 = _mm512_rol_epi64(e8, 55);
		e14 = _mm512_xor_si512(e14, d4);
		c2 = _mm512_rol_epi64(e14, 39);
		e15 = _mm512_xor_si512(e15, d0);
		c3 = _mm512_rol_epi64(e15, 41);
		e21 = _mm512_xor_si512(e21, d1);
		c4 = _mm512_rol_epi64(e21, 2);
		a20 = _mm512_ternarylogic_epi64(c0, c1, c2, 0xD2);
		a21 = _mm512_ternarylogic_epi64(c1, c2, c3, 0xD2);
		a22 = _mm512_ternarylogic_epi64(c2, c3, c4, 0xD2);
		a23 = _mm512_ternarylogic_epi64(c3, c4, c0, 0xD2);
		a24 = _mm512_ternarylogic_epi64(c4, c0, c1, 0xD2);
	}

	state[0U] = a0;
	state[1U] = a1;
	state[2U] = a2;
	state[3U] = a3;
	state[4U] = a4;
	state[5U] = a5;
	state[6U] = a6;
	state[7U] = a7;
	state[8U] = a8;
	state[9U] = a9;
	state[10U] = a10;
	state[11U] = a11;
	state[12U] = a12;
	state[13U] = a13;
	state[14U] = a14;
	state[15U] = a15;
	state[16U] = a16;
	state[17U] = a17;
	state[18U] = a18;
	state[19U] = a19;
	state[20U] = a20;
	state[21U] = a21;
	state[22U] = a22;
	state[23U] = a23;
	state[24U] = a24;
}

#endif

#if defined(QSC_SYSTEM_HAS_AVX2)

static inline __m256i keccak_chi256(const __m256i a, const __m256i b, const __m256i c)
{
	/* evaluate Keccak Chi for four independent 64-bit lanes */
#if defined(QSC_SYSTEM_HAS_AVX512) && defined(__AVX512VL__)
	return _mm256_ternarylogic_epi64(a, b, c, 0xD2);
#else
	return _mm256_xor_si256(a, _mm256_andnot_si256(b, c));
#endif
}

static void qsc_keccak_permute_p4x1600(__m256i state[QSC_KECCAK_STATE_SIZE], size_t rounds)
{
	/* apply QSC rounds to 4 independent interleaved Keccak states */
	QSC_ASSERT(rounds % 2U == 0U);

	__m256i a0;
	__m256i a1;
	__m256i a2;
	__m256i a3;
	__m256i a4;
	__m256i a5;
	__m256i a6;
	__m256i a7;
	__m256i a8;
	__m256i a9;
	__m256i a10;
	__m256i a11;
	__m256i a12;
	__m256i a13;
	__m256i a14;
	__m256i a15;
	__m256i a16;
	__m256i a17;
	__m256i a18;
	__m256i a19;
	__m256i a20;
	__m256i a21;
	__m256i a22;
	__m256i a23;
	__m256i a24;
	__m256i c0;
	__m256i c1;
	__m256i c2;
	__m256i c3;
	__m256i c4;
	__m256i d0;
	__m256i d1;
	__m256i d2;
	__m256i d3;
	__m256i d4;
	__m256i e0;
	__m256i e1;
	__m256i e2;
	__m256i e3;
	__m256i e4;
	__m256i e5;
	__m256i e6;
	__m256i e7;
	__m256i e8;
	__m256i e9;
	__m256i e10;
	__m256i e11;
	__m256i e12;
	__m256i e13;
	__m256i e14;
	__m256i e15;
	__m256i e16;
	__m256i e17;
	__m256i e18;
	__m256i e19;
	__m256i e20;
	__m256i e21;
	__m256i e22;
	__m256i e23;
	__m256i e24;


	size_t i;

	a0 = state[0U];
	a1 = state[1U];
	a2 = state[2U];
	a3 = state[3U];
	a4 = state[4U];
	a5 = state[5U];
	a6 = state[6U];
	a7 = state[7U];
	a8 = state[8U];
	a9 = state[9U];
	a10 = state[10U];
	a11 = state[11U];
	a12 = state[12U];
	a13 = state[13U];
	a14 = state[14U];
	a15 = state[15U];
	a16 = state[16U];
	a17 = state[17U];
	a18 = state[18U];
	a19 = state[19U];
	a20 = state[20U];
	a21 = state[21U];
	a22 = state[22U];
	a23 = state[23U];
	a24 = state[24U];

	for (i = 0U; i < rounds; i += 2U)
	{
		/* round n */
		c0 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(a0, a5), _mm256_xor_si256(a10, a15)), a20);
		c1 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(a1, a6), _mm256_xor_si256(a11, a16)), a21);
		c2 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(a2, a7), _mm256_xor_si256(a12, a17)), a22);
		c3 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(a3, a8), _mm256_xor_si256(a13, a18)), a23);
		c4 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(a4, a9), _mm256_xor_si256(a14, a19)), a24);
		d0 = _mm256_xor_si256(c4, _mm256_or_si256(_mm256_slli_epi64(c1, 1), _mm256_srli_epi64(c1, 64 - 1)));
		d1 = _mm256_xor_si256(c0, _mm256_or_si256(_mm256_slli_epi64(c2, 1), _mm256_srli_epi64(c2, 64 - 1)));
		d2 = _mm256_xor_si256(c1, _mm256_or_si256(_mm256_slli_epi64(c3, 1), _mm256_srli_epi64(c3, 64 - 1)));
		d3 = _mm256_xor_si256(c2, _mm256_or_si256(_mm256_slli_epi64(c4, 1), _mm256_srli_epi64(c4, 64 - 1)));
		d4 = _mm256_xor_si256(c3, _mm256_or_si256(_mm256_slli_epi64(c0, 1), _mm256_srli_epi64(c0, 64 - 1)));
		a0 = _mm256_xor_si256(a0, d0);
		c0 = a0;
		a6 = _mm256_xor_si256(a6, d1);
		c1 = _mm256_or_si256(_mm256_slli_epi64(a6, 44), _mm256_srli_epi64(a6, 64 - 44));
		a12 = _mm256_xor_si256(a12, d2);
		c2 = _mm256_or_si256(_mm256_slli_epi64(a12, 43), _mm256_srli_epi64(a12, 64 - 43));
		a18 = _mm256_xor_si256(a18, d3);
		c3 = _mm256_or_si256(_mm256_slli_epi64(a18, 21), _mm256_srli_epi64(a18, 64 - 21));
		a24 = _mm256_xor_si256(a24, d4);
		c4 = _mm256_or_si256(_mm256_slli_epi64(a24, 14), _mm256_srli_epi64(a24, 64 - 14));
		e0 = keccak_chi256(c0, c1, c2);
		e0 = _mm256_xor_si256(e0, _mm256_set1_epi64x(KECCAK_ROUND_CONSTANTS[i]));
		e1 = keccak_chi256(c1, c2, c3);
		e2 = keccak_chi256(c2, c3, c4);
		e3 = keccak_chi256(c3, c4, c0);
		e4 = keccak_chi256(c4, c0, c1);
		a3 = _mm256_xor_si256(a3, d3);
		c0 = _mm256_or_si256(_mm256_slli_epi64(a3, 28), _mm256_srli_epi64(a3, 64 - 28));
		a9 = _mm256_xor_si256(a9, d4);
		c1 = _mm256_or_si256(_mm256_slli_epi64(a9, 20), _mm256_srli_epi64(a9, 64 - 20));
		a10 = _mm256_xor_si256(a10, d0);
		c2 = _mm256_or_si256(_mm256_slli_epi64(a10, 3), _mm256_srli_epi64(a10, 64 - 3));
		a16 = _mm256_xor_si256(a16, d1);
		c3 = _mm256_or_si256(_mm256_slli_epi64(a16, 45), _mm256_srli_epi64(a16, 64 - 45));
		a22 = _mm256_xor_si256(a22, d2);
		c4 = _mm256_or_si256(_mm256_slli_epi64(a22, 61), _mm256_srli_epi64(a22, 64 - 61));
		e5 = keccak_chi256(c0, c1, c2);
		e6 = keccak_chi256(c1, c2, c3);
		e7 = keccak_chi256(c2, c3, c4);
		e8 = keccak_chi256(c3, c4, c0);
		e9 = keccak_chi256(c4, c0, c1);
		a1 = _mm256_xor_si256(a1, d1);
		c0 = _mm256_or_si256(_mm256_slli_epi64(a1, 1), _mm256_srli_epi64(a1, 64 - 1));
		a7 = _mm256_xor_si256(a7, d2);
		c1 = _mm256_or_si256(_mm256_slli_epi64(a7, 6), _mm256_srli_epi64(a7, 64 - 6));
		a13 = _mm256_xor_si256(a13, d3);
		c2 = _mm256_or_si256(_mm256_slli_epi64(a13, 25), _mm256_srli_epi64(a13, 64 - 25));
		a19 = _mm256_xor_si256(a19, d4);
		c3 = _mm256_or_si256(_mm256_slli_epi64(a19, 8), _mm256_srli_epi64(a19, 64 - 8));
		a20 = _mm256_xor_si256(a20, d0);
		c4 = _mm256_or_si256(_mm256_slli_epi64(a20, 18), _mm256_srli_epi64(a20, 64 - 18));
		e10 = keccak_chi256(c0, c1, c2);
		e11 = keccak_chi256(c1, c2, c3);
		e12 = keccak_chi256(c2, c3, c4);
		e13 = keccak_chi256(c3, c4, c0);
		e14 = keccak_chi256(c4, c0, c1);
		a4 = _mm256_xor_si256(a4, d4);
		c0 = _mm256_or_si256(_mm256_slli_epi64(a4, 27), _mm256_srli_epi64(a4, 64 - 27));
		a5 = _mm256_xor_si256(a5, d0);
		c1 = _mm256_or_si256(_mm256_slli_epi64(a5, 36), _mm256_srli_epi64(a5, 64 - 36));
		a11 = _mm256_xor_si256(a11, d1);
		c2 = _mm256_or_si256(_mm256_slli_epi64(a11, 10), _mm256_srli_epi64(a11, 64 - 10));
		a17 = _mm256_xor_si256(a17, d2);
		c3 = _mm256_or_si256(_mm256_slli_epi64(a17, 15), _mm256_srli_epi64(a17, 64 - 15));
		a23 = _mm256_xor_si256(a23, d3);
		c4 = _mm256_or_si256(_mm256_slli_epi64(a23, 56), _mm256_srli_epi64(a23, 64 - 56));
		e15 = keccak_chi256(c0, c1, c2);
		e16 = keccak_chi256(c1, c2, c3);
		e17 = keccak_chi256(c2, c3, c4);
		e18 = keccak_chi256(c3, c4, c0);
		e19 = keccak_chi256(c4, c0, c1);
		a2 = _mm256_xor_si256(a2, d2);
		c0 = _mm256_or_si256(_mm256_slli_epi64(a2, 62), _mm256_srli_epi64(a2, 64 - 62));
		a8 = _mm256_xor_si256(a8, d3);
		c1 = _mm256_or_si256(_mm256_slli_epi64(a8, 55), _mm256_srli_epi64(a8, 64 - 55));
		a14 = _mm256_xor_si256(a14, d4);
		c2 = _mm256_or_si256(_mm256_slli_epi64(a14, 39), _mm256_srli_epi64(a14, 64 - 39));
		a15 = _mm256_xor_si256(a15, d0);
		c3 = _mm256_or_si256(_mm256_slli_epi64(a15, 41), _mm256_srli_epi64(a15, 64 - 41));
		a21 = _mm256_xor_si256(a21, d1);
		c4 = _mm256_or_si256(_mm256_slli_epi64(a21, 2), _mm256_srli_epi64(a21, 64 - 2));
		e20 = keccak_chi256(c0, c1, c2);
		e21 = keccak_chi256(c1, c2, c3);
		e22 = keccak_chi256(c2, c3, c4);
		e23 = keccak_chi256(c3, c4, c0);
		e24 = keccak_chi256(c4, c0, c1);
		/* round n + 1 */
		c0 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(e0, e5), _mm256_xor_si256(e10, e15)), e20);
		c1 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(e1, e6), _mm256_xor_si256(e11, e16)), e21);
		c2 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(e2, e7), _mm256_xor_si256(e12, e17)), e22);
		c3 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(e3, e8), _mm256_xor_si256(e13, e18)), e23);
		c4 = _mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(e4, e9), _mm256_xor_si256(e14, e19)), e24);
		d0 = _mm256_xor_si256(c4, _mm256_or_si256(_mm256_slli_epi64(c1, 1), _mm256_srli_epi64(c1, 64 - 1)));
		d1 = _mm256_xor_si256(c0, _mm256_or_si256(_mm256_slli_epi64(c2, 1), _mm256_srli_epi64(c2, 64 - 1)));
		d2 = _mm256_xor_si256(c1, _mm256_or_si256(_mm256_slli_epi64(c3, 1), _mm256_srli_epi64(c3, 64 - 1)));
		d3 = _mm256_xor_si256(c2, _mm256_or_si256(_mm256_slli_epi64(c4, 1), _mm256_srli_epi64(c4, 64 - 1)));
		d4 = _mm256_xor_si256(c3, _mm256_or_si256(_mm256_slli_epi64(c0, 1), _mm256_srli_epi64(c0, 64 - 1)));
		e0 = _mm256_xor_si256(e0, d0);
		c0 = e0;
		e6 = _mm256_xor_si256(e6, d1);
		c1 = _mm256_or_si256(_mm256_slli_epi64(e6, 44), _mm256_srli_epi64(e6, 64 - 44));
		e12 = _mm256_xor_si256(e12, d2);
		c2 = _mm256_or_si256(_mm256_slli_epi64(e12, 43), _mm256_srli_epi64(e12, 64 - 43));
		e18 = _mm256_xor_si256(e18, d3);
		c3 = _mm256_or_si256(_mm256_slli_epi64(e18, 21), _mm256_srli_epi64(e18, 64 - 21));
		e24 = _mm256_xor_si256(e24, d4);
		c4 = _mm256_or_si256(_mm256_slli_epi64(e24, 14), _mm256_srli_epi64(e24, 64 - 14));
		a0 = keccak_chi256(c0, c1, c2);
		a0 = _mm256_xor_si256(a0, _mm256_set1_epi64x(KECCAK_ROUND_CONSTANTS[i + 1U]));
		a1 = keccak_chi256(c1, c2, c3);
		a2 = keccak_chi256(c2, c3, c4);
		a3 = keccak_chi256(c3, c4, c0);
		a4 = keccak_chi256(c4, c0, c1);
		e3 = _mm256_xor_si256(e3, d3);
		c0 = _mm256_or_si256(_mm256_slli_epi64(e3, 28), _mm256_srli_epi64(e3, 64 - 28));
		e9 = _mm256_xor_si256(e9, d4);
		c1 = _mm256_or_si256(_mm256_slli_epi64(e9, 20), _mm256_srli_epi64(e9, 64 - 20));
		e10 = _mm256_xor_si256(e10, d0);
		c2 = _mm256_or_si256(_mm256_slli_epi64(e10, 3), _mm256_srli_epi64(e10, 64 - 3));
		e16 = _mm256_xor_si256(e16, d1);
		c3 = _mm256_or_si256(_mm256_slli_epi64(e16, 45), _mm256_srli_epi64(e16, 64 - 45));
		e22 = _mm256_xor_si256(e22, d2);
		c4 = _mm256_or_si256(_mm256_slli_epi64(e22, 61), _mm256_srli_epi64(e22, 64 - 61));
		a5 = keccak_chi256(c0, c1, c2);
		a6 = keccak_chi256(c1, c2, c3);
		a7 = keccak_chi256(c2, c3, c4);
		a8 = keccak_chi256(c3, c4, c0);
		a9 = keccak_chi256(c4, c0, c1);
		e1 = _mm256_xor_si256(e1, d1);
		c0 = _mm256_or_si256(_mm256_slli_epi64(e1, 1), _mm256_srli_epi64(e1, 64 - 1));
		e7 = _mm256_xor_si256(e7, d2);
		c1 = _mm256_or_si256(_mm256_slli_epi64(e7, 6), _mm256_srli_epi64(e7, 64 - 6));
		e13 = _mm256_xor_si256(e13, d3);
		c2 = _mm256_or_si256(_mm256_slli_epi64(e13, 25), _mm256_srli_epi64(e13, 64 - 25));
		e19 = _mm256_xor_si256(e19, d4);
		c3 = _mm256_or_si256(_mm256_slli_epi64(e19, 8), _mm256_srli_epi64(e19, 64 - 8));
		e20 = _mm256_xor_si256(e20, d0);
		c4 = _mm256_or_si256(_mm256_slli_epi64(e20, 18), _mm256_srli_epi64(e20, 64 - 18));
		a10 = keccak_chi256(c0, c1, c2);
		a11 = keccak_chi256(c1, c2, c3);
		a12 = keccak_chi256(c2, c3, c4);
		a13 = keccak_chi256(c3, c4, c0);
		a14 = keccak_chi256(c4, c0, c1);
		e4 = _mm256_xor_si256(e4, d4);
		c0 = _mm256_or_si256(_mm256_slli_epi64(e4, 27), _mm256_srli_epi64(e4, 64 - 27));
		e5 = _mm256_xor_si256(e5, d0);
		c1 = _mm256_or_si256(_mm256_slli_epi64(e5, 36), _mm256_srli_epi64(e5, 64 - 36));
		e11 = _mm256_xor_si256(e11, d1);
		c2 = _mm256_or_si256(_mm256_slli_epi64(e11, 10), _mm256_srli_epi64(e11, 64 - 10));
		e17 = _mm256_xor_si256(e17, d2);
		c3 = _mm256_or_si256(_mm256_slli_epi64(e17, 15), _mm256_srli_epi64(e17, 64 - 15));
		e23 = _mm256_xor_si256(e23, d3);
		c4 = _mm256_or_si256(_mm256_slli_epi64(e23, 56), _mm256_srli_epi64(e23, 64 - 56));
		a15 = keccak_chi256(c0, c1, c2);
		a16 = keccak_chi256(c1, c2, c3);
		a17 = keccak_chi256(c2, c3, c4);
		a18 = keccak_chi256(c3, c4, c0);
		a19 = keccak_chi256(c4, c0, c1);
		e2 = _mm256_xor_si256(e2, d2);
		c0 = _mm256_or_si256(_mm256_slli_epi64(e2, 62), _mm256_srli_epi64(e2, 64 - 62));
		e8 = _mm256_xor_si256(e8, d3);
		c1 = _mm256_or_si256(_mm256_slli_epi64(e8, 55), _mm256_srli_epi64(e8, 64 - 55));
		e14 = _mm256_xor_si256(e14, d4);
		c2 = _mm256_or_si256(_mm256_slli_epi64(e14, 39), _mm256_srli_epi64(e14, 64 - 39));
		e15 = _mm256_xor_si256(e15, d0);
		c3 = _mm256_or_si256(_mm256_slli_epi64(e15, 41), _mm256_srli_epi64(e15, 64 - 41));
		e21 = _mm256_xor_si256(e21, d1);
		c4 = _mm256_or_si256(_mm256_slli_epi64(e21, 2), _mm256_srli_epi64(e21, 64 - 2));
		a20 = keccak_chi256(c0, c1, c2);
		a21 = keccak_chi256(c1, c2, c3);
		a22 = keccak_chi256(c2, c3, c4);
		a23 = keccak_chi256(c3, c4, c0);
		a24 = keccak_chi256(c4, c0, c1);
	}

	state[0U] = a0;
	state[1U] = a1;
	state[2U] = a2;
	state[3U] = a3;
	state[4U] = a4;
	state[5U] = a5;
	state[6U] = a6;
	state[7U] = a7;
	state[8U] = a8;
	state[9U] = a9;
	state[10U] = a10;
	state[11U] = a11;
	state[12U] = a12;
	state[13U] = a13;
	state[14U] = a14;
	state[15U] = a15;
	state[16U] = a16;
	state[17U] = a17;
	state[18U] = a18;
	state[19U] = a19;
	state[20U] = a20;
	state[21U] = a21;
	state[22U] = a22;
	state[23U] = a23;
	state[24U] = a24;
}

#endif

/* Keccak */

void qsc_keccak_absorb(qsc_keccak_state* ctx, qsc_keccak_rate rate, const uint8_t* message, size_t msglen, uint8_t domain, size_t rounds)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(message != NULL);

	if (ctx != NULL && message != NULL && keccak_parameters_valid((size_t)rate, rounds) && ctx->position < (size_t)rate)
	{
		uint8_t msg[QSC_KECCAK_STATE_BYTE_SIZE];

		while (msglen >= (size_t)rate)
		{
#if defined(QSC_SYSTEM_IS_LITTLE_ENDIAN)
			qsc_memutils_xor((uint8_t*)ctx->state, message, (size_t)rate);
#else
			for (size_t i = 0U; i < (size_t)rate / sizeof(uint64_t); ++i)
			{
				ctx->state[i] ^= qsc_intutils_le8to64((message + (sizeof(uint64_t) * i)));
			}
#endif
			qsc_keccak_permute(ctx, rounds);
			msglen -= (size_t)rate;
			message += (size_t)rate;
		}

		qsc_memutils_copy(msg, message, msglen);
		msg[msglen] = domain;

		if ((size_t)rate - (msglen + 1U) != 0)
		{
			qsc_memutils_clear((msg + msglen + 1U), (size_t)rate - (msglen + 1U));
		}

		if ((domain & 0x80U) != 0U && msglen == (size_t)rate - 1U)
		{
			keccak_fast_absorb(ctx->state, msg, (size_t)rate);
			qsc_keccak_permute(ctx, rounds);
			qsc_memutils_clear(msg, sizeof(msg));
		}

		msg[(size_t)rate - 1U] |= 128U;

#if defined(QSC_SYSTEM_IS_LITTLE_ENDIAN)
		qsc_memutils_xor((uint8_t*)ctx->state, msg, (size_t)rate);
#else
		for (size_t i = 0U; i < (size_t)rate / 8U; ++i)
		{
			ctx->state[i] ^= qsc_intutils_le8to64((msg + (8U * i)));
		}
#endif
		qsc_memutils_secure_erase(msg, sizeof(msg));
	}
}

void qsc_keccak_absorb_custom(qsc_keccak_state* ctx, qsc_keccak_rate rate, const uint8_t* custom, size_t custlen, const uint8_t* name, size_t namelen, size_t rounds)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(custom != NULL || custlen == 0U);
	QSC_ASSERT(name != NULL || namelen == 0U);

	uint8_t encoded[sizeof(size_t) + 1U] = { 0U };
	size_t enclen;

	if (ctx != NULL && (custom != NULL || custlen == 0U) && (name != NULL || namelen == 0U) &&
		custlen <= SIZE_MAX / 8U && namelen <= SIZE_MAX / 8U && keccak_parameters_valid((size_t)rate, rounds))
	{
		ctx->position = 0U;
		enclen = keccak_left_encode(encoded, (size_t)rate);
		qsc_keccak_update(ctx, rate, encoded, enclen, rounds);
		enclen = keccak_left_encode(encoded, namelen * 8U);
		qsc_keccak_update(ctx, rate, encoded, enclen, rounds);

		if (namelen != 0U)
		{
			qsc_keccak_update(ctx, rate, name, namelen, rounds);
		}

		enclen = keccak_left_encode(encoded, custlen * 8U);
		qsc_keccak_update(ctx, rate, encoded, enclen, rounds);

		if (custlen != 0U)
		{
			qsc_keccak_update(ctx, rate, custom, custlen, rounds);
		}

		if (ctx->position != 0U)
		{
			qsc_memutils_clear(ctx->buffer + ctx->position, (size_t)rate - ctx->position);
			keccak_fast_absorb(ctx->state, ctx->buffer, (size_t)rate);
			qsc_keccak_permute(ctx, rounds);
			ctx->position = 0U;
		}

		qsc_memutils_secure_erase(ctx->buffer, sizeof(ctx->buffer));
	}

	qsc_memutils_secure_erase(encoded, sizeof(encoded));
}

void qsc_keccak_absorb_key_custom(qsc_keccak_state* ctx, qsc_keccak_rate rate, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t custlen, const uint8_t* name, size_t namelen, size_t rounds)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(custom != NULL || custlen == 0U);
	QSC_ASSERT(name != NULL || namelen == 0U);

	uint8_t encoded[sizeof(size_t) + 1U] = { 0U };
	size_t enclen;

	if (ctx != NULL && (custom != NULL || custlen == 0U) && (name != NULL || namelen == 0U) &&
		custlen <= SIZE_MAX / 8U && namelen <= SIZE_MAX / 8U && keccak_parameters_valid((size_t)rate, rounds) &&
		(key != NULL || keylen == 0U) && keylen <= SIZE_MAX / 8U)
	{
		qsc_keccak_absorb_custom(ctx, rate, custom, custlen, name, namelen, rounds);
		ctx->position = 0U;
		enclen = keccak_left_encode(encoded, (size_t)rate);
		qsc_keccak_update(ctx, rate, encoded, enclen, rounds);
		enclen = keccak_left_encode(encoded, keylen * 8U);
		qsc_keccak_update(ctx, rate, encoded, enclen, rounds);

		if (keylen != 0U)
		{
			qsc_keccak_update(ctx, rate, key, keylen, rounds);
		}

		if (ctx->position != 0U)
		{
			qsc_memutils_clear(ctx->buffer + ctx->position, (size_t)rate - ctx->position);
			keccak_fast_absorb(ctx->state, ctx->buffer, (size_t)rate);
			qsc_keccak_permute(ctx, rounds);
			ctx->position = 0U;
		}

		qsc_memutils_secure_erase(ctx->buffer, sizeof(ctx->buffer));
	}

	qsc_memutils_secure_erase(encoded, sizeof(encoded));
}

void qsc_keccak_dispose(qsc_keccak_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	if (ctx != NULL)
	{
		qsc_memutils_secure_erase(ctx->state, sizeof(ctx->state));
		qsc_memutils_secure_erase(ctx->buffer, sizeof(ctx->buffer));
		ctx->position = 0U;
	}
}

void qsc_keccak_finalize(qsc_keccak_state* ctx, qsc_keccak_rate rate, uint8_t* output, size_t outlen, uint8_t domain, size_t rounds)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(output != NULL);

	uint8_t buf[sizeof(size_t) + 1U] = { 0U };
	uint8_t pad[QSC_KECCAK_STATE_BYTE_SIZE] = { 0U };
	size_t bitlen;
	size_t take;

	if (ctx != NULL && output != NULL && outlen <= SIZE_MAX / 8U &&
		keccak_parameters_valid((size_t)rate, rounds) && ctx->position < (size_t)rate)
	{
		qsc_memutils_copy(pad, ctx->buffer, ctx->position);
		bitlen = keccak_right_encode(buf, outlen * 8U);

		if (ctx->position + bitlen >= (size_t)rate)
		{

			/* place the right-encoding prefix in the remaining rate
			 * bytes before permuting. A clean block holds the suffix. */
			take = (size_t)rate - ctx->position;
			qsc_memutils_copy(pad + ctx->position, buf, take);
			keccak_fast_absorb(ctx->state, pad, (size_t)rate);
			qsc_keccak_permute(ctx, rounds);
			qsc_memutils_clear(pad, sizeof(pad));
			bitlen -= take;
			qsc_memutils_copy(pad, buf + take, bitlen);
			ctx->position = 0U;
		}
		else
		{
			qsc_memutils_copy(pad + ctx->position, buf, bitlen);
		}

		pad[ctx->position + bitlen] = domain;
		if ((domain & 0x80U) != 0U && ctx->position + bitlen == (size_t)rate - 1U)
		{
			keccak_fast_absorb(ctx->state, pad, (size_t)rate);
			qsc_keccak_permute(ctx, rounds);
			qsc_memutils_clear(pad, sizeof(pad));
		}

		pad[(size_t)rate - 1U] |= 128U;
		keccak_fast_absorb(ctx->state, pad, (size_t)rate);

		while (outlen >= (size_t)rate)
		{
			qsc_keccak_squeezeblocks(ctx, pad, 1U, (size_t)rate, rounds);
			qsc_memutils_copy(output, pad, (size_t)rate);
			output += (size_t)rate;
			outlen -= (size_t)rate;
		}

		if (outlen > 0U)
		{
			qsc_keccak_squeezeblocks(ctx, pad, 1U, (size_t)rate, rounds);
			qsc_memutils_copy(output, pad, outlen);
		}

		qsc_memutils_secure_erase(ctx->buffer, sizeof(ctx->buffer));
		ctx->position = 0U;
	}

	qsc_memutils_secure_erase(pad, sizeof(pad));
	qsc_memutils_secure_erase(buf, sizeof(buf));
}

void qsc_keccak_incremental_absorb(qsc_keccak_state* ctx, uint32_t rate, const uint8_t* message, size_t msglen)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(message != NULL);

	uint8_t t[8U] = { 0U };
	size_t i;

	if (ctx != NULL && message != NULL && keccak_parameters_valid((size_t)rate, QSC_KECCAK_PERMUTATION_ROUNDS) && ctx->position < (size_t)rate)
	{
		if ((ctx->position & 7U) > 0U)
		{
			i = ctx->position & 7U;

			while (i < 8U && msglen > 0U)
			{
				t[i] = *message;
				message++;
				i++;
				msglen--;
				ctx->position++;
			}

			ctx->state[(ctx->position - i) / 8U] ^= keccak_load64(t);
		}

		if (ctx->position && msglen >= (size_t)rate - ctx->position)
		{
			for (i = 0U; i < ((size_t)rate - ctx->position) / 8U; ++i)
			{
				ctx->state[(ctx->position / 8U) + i] ^= keccak_load64(message + (8U * i));
			}

			message += (size_t)rate - ctx->position;
			msglen -= (size_t)rate - ctx->position;
			ctx->position = 0U;
			qsc_keccak_permute(ctx, QSC_KECCAK_PERMUTATION_ROUNDS);
		}

		while (msglen >= (size_t)rate)
		{
			for (i = 0U; i < (size_t)rate / 8U; i++)
			{
				ctx->state[i] ^= keccak_load64(message + (8U * i));
			}

			message += (size_t)rate;
			msglen -= (size_t)rate;
			qsc_keccak_permute(ctx, QSC_KECCAK_PERMUTATION_ROUNDS);
		}

		for (i = 0U; i < msglen / 8U; ++i)
		{
			ctx->state[(ctx->position / 8U) + i] ^= keccak_load64(message + (8U * i));
		}

		message += 8U * i;
		msglen -= 8U * i;
		ctx->position += 8U * i;

		if (msglen > 0U)
		{
			for (i = 0U; i < 8U; ++i)
			{
				t[i] = 0U;
			}

			for (i = 0U; i < msglen; ++i)
			{
				t[i] = message[i];
			}

			ctx->state[ctx->position / 8U] ^= keccak_load64(t);
			ctx->position += msglen;
		}
	}

	qsc_memutils_secure_erase(t, sizeof(t));
}

void qsc_keccak_incremental_finalize(qsc_keccak_state* ctx, uint32_t rate, uint8_t domain)
{
	QSC_ASSERT(ctx != NULL);

	size_t i;
	size_t j;

	if (ctx != NULL && keccak_parameters_valid((size_t)rate, QSC_KECCAK_PERMUTATION_ROUNDS) && ctx->position < (size_t)rate)
	{
		i = ctx->position >> 3;
		j = ctx->position & 7;
		ctx->state[i] ^= ((uint64_t)domain << (8U * j));
		if ((domain & 0x80U) != 0U && ctx->position == (size_t)rate - 1U)
		{
			qsc_keccak_permute(ctx, QSC_KECCAK_PERMUTATION_ROUNDS);
		}

		ctx->state[((size_t)rate / 8U) - 1U] ^= 1ULL << 63;
		ctx->position = 0U;
	}
}

void qsc_keccak_incremental_squeeze(qsc_keccak_state* ctx, size_t rate, uint8_t* output, size_t outlen)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(output != NULL);

	size_t i;
	uint8_t t[8U];

	if (ctx != NULL && output != NULL && keccak_parameters_valid((size_t)rate, QSC_KECCAK_PERMUTATION_ROUNDS) && ctx->position < (size_t)rate)
	{
		if ((ctx->position & 7) > 0U)
		{
			keccak_store64(t, ctx->state[ctx->position / 8U]);
			i = ctx->position & 7;

			while (i < 8U && outlen > 0U)
			{
				*output = t[i];
				output++;
				i++;
				outlen--;
				ctx->position++;
			}
		}

		if (ctx->position && outlen >= (size_t)rate - ctx->position)
		{
			for (i = 0U; i < ((size_t)rate - ctx->position) / 8U; ++i)
			{
				keccak_store64(output + (8U * i), ctx->state[(ctx->position / 8U) + i]);
			}

			output += (size_t)rate - ctx->position;
			outlen -= (size_t)rate - ctx->position;
			ctx->position = 0U;
		}

		while (outlen >= (size_t)rate)
		{
			qsc_keccak_permute(ctx, QSC_KECCAK_PERMUTATION_ROUNDS);

			for (i = 0U; i < (size_t)rate / 8U; ++i)
			{
				keccak_store64(output + (8U * i), ctx->state[i]);
			}

			output += (size_t)rate;
			outlen -= (size_t)rate;
		}

		if (outlen > 0U)
		{
			if (ctx->position == 0U)
			{
				qsc_keccak_permute(ctx, QSC_KECCAK_PERMUTATION_ROUNDS);
			}

			for (i = 0U; i < outlen / 8U; ++i)
			{
				keccak_store64(output + (8U * i), ctx->state[(ctx->position / 8U) + i]);
			}

			output += 8U * i;
			outlen -= 8U * i;
			ctx->position += 8U * i;

			keccak_store64(t, ctx->state[ctx->position / 8U]);

			for (i = 0U; i < outlen; ++i)
			{
				output[i] = t[i];
			}

			ctx->position += outlen;
		}
	}

	qsc_memutils_secure_erase(t, sizeof(t));
}

void qsc_keccak_permute(qsc_keccak_state* ctx, size_t rounds)
{
	QSC_ASSERT(ctx != NULL);

	if (ctx != NULL && rounds <= QSC_KECCAK_PERMUTATION_MAX_ROUNDS && rounds % 2U == 0U)
	{
#if defined(QSC_KECCAK_UNROLLED_PERMUTATION)
		if (rounds == QSC_KECCAK_PERMUTATION_ROUNDS)
		{
			qsc_keccak_permute_p1600u(ctx->state);
		}
		else
		{
			qsc_keccak_permute_p1600c(ctx->state, rounds);
		}
#else
		qsc_keccak_permute_p1600c(ctx->state, rounds);
#endif
	}
}

void qsc_keccak_permute_p1600c(uint64_t* state, size_t rounds)
{
	QSC_ASSERT(state != NULL);
	QSC_ASSERT(rounds % 2U == 0U);

#if defined(QSC_SYSTEM_ARM_SHA3_ENABLED)
	uint64x2_t lanes[QSC_KECCAK_STATE_SIZE];

	QSC_ASSERT(state != NULL);
	QSC_ASSERT(rounds % 2U == 0U);
	QSC_ASSERT(rounds <= QSC_KECCAK_PERMUTATION_MAX_ROUNDS);

	if (state != NULL && rounds % 2U == 0U && rounds <= QSC_KECCAK_PERMUTATION_MAX_ROUNDS)
	{
		for (size_t i = 0U; i < QSC_KECCAK_STATE_SIZE; ++i)
		{
			lanes[i] = vdupq_n_u64(state[i]);
		}

		keccak_permute_p2x1600_arm(lanes, rounds);

		for (size_t i = 0U; i < QSC_KECCAK_STATE_SIZE; ++i)
		{
			state[i] = vgetq_lane_u64(lanes[i], 0);
		}

		qsc_memutils_secure_erase(lanes, sizeof(lanes));
	}
#else

	uint64_t Aba;
	uint64_t Abe;
	uint64_t Abi;
	uint64_t Abo;
	uint64_t Abu;
	uint64_t Aga;
	uint64_t Age;
	uint64_t Agi;
	uint64_t Ago;
	uint64_t Agu;
	uint64_t Aka;
	uint64_t Ake;
	uint64_t Aki;
	uint64_t Ako;
	uint64_t Aku;
	uint64_t Ama;
	uint64_t Ame;
	uint64_t Ami;
	uint64_t Amo;
	uint64_t Amu;
	uint64_t Asa;
	uint64_t Ase;
	uint64_t Asi;
	uint64_t Aso;
	uint64_t Asu;
	uint64_t BCa;
	uint64_t BCe;
	uint64_t BCi;
	uint64_t BCo;
	uint64_t BCu;
	uint64_t Da;
	uint64_t De;
	uint64_t Di;
	uint64_t Do;
	uint64_t Du;
	uint64_t Eba;
	uint64_t Ebe;
	uint64_t Ebi;
	uint64_t Ebo;
	uint64_t Ebu;
	uint64_t Ega;
	uint64_t Ege;
	uint64_t Egi;
	uint64_t Ego;
	uint64_t Egu;
	uint64_t Eka;
	uint64_t Eke;
	uint64_t Eki;
	uint64_t Eko;
	uint64_t Eku;
	uint64_t Ema;
	uint64_t Eme;
	uint64_t Emi;
	uint64_t Emo;
	uint64_t Emu;
	uint64_t Esa;
	uint64_t Ese;
	uint64_t Esi;
	uint64_t Eso;
	uint64_t Esu;

	if (state != NULL && rounds % 2U == 0U && rounds <= QSC_KECCAK_PERMUTATION_MAX_ROUNDS)
	{
		/* copyFromState(A, state) */
		Aba = state[0U];
		Abe = state[1U];
		Abi = state[2U];
		Abo = state[3U];
		Abu = state[4U];
		Aga = state[5U];
		Age = state[6U];
		Agi = state[7U];
		Ago = state[8U];
		Agu = state[9U];
		Aka = state[10U];
		Ake = state[11U];
		Aki = state[12U];
		Ako = state[13U];
		Aku = state[14U];
		Ama = state[15U];
		Ame = state[16U];
		Ami = state[17U];
		Amo = state[18U];
		Amu = state[19U];
		Asa = state[20U];
		Ase = state[21U];
		Asi = state[22U];
		Aso = state[23U];
		Asu = state[24U];

		for (size_t i = 0U; i < rounds; i += 2U)
		{
			/* prepareTheta */
			BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
			BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;
			BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
			BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
			BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

			/* thetaRhoPiChiIotaPrepareTheta */
			Da = BCu ^ keccak_rotl64(BCe, 1U);
			De = BCa ^ keccak_rotl64(BCi, 1U);
			Di = BCe ^ keccak_rotl64(BCo, 1U);
			Do = BCi ^ keccak_rotl64(BCu, 1U);
			Du = BCo ^ keccak_rotl64(BCa, 1U);

			Aba ^= Da;
			BCa = Aba;
			Age ^= De;
			BCe = keccak_rotl64(Age, 44U);
			Aki ^= Di;
			BCi = keccak_rotl64(Aki, 43U);
			Amo ^= Do;
			BCo = keccak_rotl64(Amo, 21U);
			Asu ^= Du;
			BCu = keccak_rotl64(Asu, 14U);
			Eba = BCa ^ ((~BCe) & BCi);
			Eba ^= KECCAK_ROUND_CONSTANTS[i];
			Ebe = BCe ^ ((~BCi) & BCo);
			Ebi = BCi ^ ((~BCo) & BCu);
			Ebo = BCo ^ ((~BCu) & BCa);
			Ebu = BCu ^ ((~BCa) & BCe);

			Abo ^= Do;
			BCa = keccak_rotl64(Abo, 28U);
			Agu ^= Du;
			BCe = keccak_rotl64(Agu, 20U);
			Aka ^= Da;
			BCi = keccak_rotl64(Aka, 3U);
			Ame ^= De;
			BCo = keccak_rotl64(Ame, 45U);
			Asi ^= Di;
			BCu = keccak_rotl64(Asi, 61U);
			Ega = BCa ^ ((~BCe) & BCi);
			Ege = BCe ^ ((~BCi) & BCo);
			Egi = BCi ^ ((~BCo) & BCu);
			Ego = BCo ^ ((~BCu) & BCa);
			Egu = BCu ^ ((~BCa) & BCe);

			Abe ^= De;
			BCa = keccak_rotl64(Abe, 1U);
			Agi ^= Di;
			BCe = keccak_rotl64(Agi, 6U);
			Ako ^= Do;
			BCi = keccak_rotl64(Ako, 25U);
			Amu ^= Du;
			BCo = keccak_rotl64(Amu, 8U);
			Asa ^= Da;
			BCu = keccak_rotl64(Asa, 18U);
			Eka = BCa ^ ((~BCe) & BCi);
			Eke = BCe ^ ((~BCi) & BCo);
			Eki = BCi ^ ((~BCo) & BCu);
			Eko = BCo ^ ((~BCu) & BCa);
			Eku = BCu ^ ((~BCa) & BCe);

			Abu ^= Du;
			BCa = keccak_rotl64(Abu, 27U);
			Aga ^= Da;
			BCe = keccak_rotl64(Aga, 36U);
			Ake ^= De;
			BCi = keccak_rotl64(Ake, 10U);
			Ami ^= Di;
			BCo = keccak_rotl64(Ami, 15U);
			Aso ^= Do;
			BCu = keccak_rotl64(Aso, 56U);
			Ema = BCa ^ ((~BCe) & BCi);
			Eme = BCe ^ ((~BCi) & BCo);
			Emi = BCi ^ ((~BCo) & BCu);
			Emo = BCo ^ ((~BCu) & BCa);
			Emu = BCu ^ ((~BCa) & BCe);

			Abi ^= Di;
			BCa = keccak_rotl64(Abi, 62U);
			Ago ^= Do;
			BCe = keccak_rotl64(Ago, 55U);
			Aku ^= Du;
			BCi = keccak_rotl64(Aku, 39U);
			Ama ^= Da;
			BCo = keccak_rotl64(Ama, 41U);
			Ase ^= De;
			BCu = keccak_rotl64(Ase, 2U);
			Esa = BCa ^ ((~BCe) & BCi);
			Ese = BCe ^ ((~BCi) & BCo);
			Esi = BCi ^ ((~BCo) & BCu);
			Eso = BCo ^ ((~BCu) & BCa);
			Esu = BCu ^ ((~BCa) & BCe);

			/* prepareTheta */
			BCa = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
			BCe = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
			BCi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
			BCo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
			BCu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

			/* thetaRhoPiChiIotaPrepareTheta */
			Da = BCu ^ keccak_rotl64(BCe, 1U);
			De = BCa ^ keccak_rotl64(BCi, 1U);
			Di = BCe ^ keccak_rotl64(BCo, 1U);
			Do = BCi ^ keccak_rotl64(BCu, 1U);
			Du = BCo ^ keccak_rotl64(BCa, 1U);

			Eba ^= Da;
			BCa = Eba;
			Ege ^= De;
			BCe = keccak_rotl64(Ege, 44U);
			Eki ^= Di;
			BCi = keccak_rotl64(Eki, 43U);
			Emo ^= Do;
			BCo = keccak_rotl64(Emo, 21U);
			Esu ^= Du;
			BCu = keccak_rotl64(Esu, 14U);
			Aba = BCa ^ ((~BCe) & BCi);
			Aba ^= KECCAK_ROUND_CONSTANTS[i + 1U];
			Abe = BCe ^ ((~BCi) & BCo);
			Abi = BCi ^ ((~BCo) & BCu);
			Abo = BCo ^ ((~BCu) & BCa);
			Abu = BCu ^ ((~BCa) & BCe);

			Ebo ^= Do;
			BCa = keccak_rotl64(Ebo, 28U);
			Egu ^= Du;
			BCe = keccak_rotl64(Egu, 20U);
			Eka ^= Da;
			BCi = keccak_rotl64(Eka, 3U);
			Eme ^= De;
			BCo = keccak_rotl64(Eme, 45U);
			Esi ^= Di;
			BCu = keccak_rotl64(Esi, 61U);
			Aga = BCa ^ ((~BCe) & BCi);
			Age = BCe ^ ((~BCi) & BCo);
			Agi = BCi ^ ((~BCo) & BCu);
			Ago = BCo ^ ((~BCu) & BCa);
			Agu = BCu ^ ((~BCa) & BCe);

			Ebe ^= De;
			BCa = keccak_rotl64(Ebe, 1U);
			Egi ^= Di;
			BCe = keccak_rotl64(Egi, 6U);
			Eko ^= Do;
			BCi = keccak_rotl64(Eko, 25U);
			Emu ^= Du;
			BCo = keccak_rotl64(Emu, 8U);
			Esa ^= Da;
			BCu = keccak_rotl64(Esa, 18U);
			Aka = BCa ^ ((~BCe) & BCi);
			Ake = BCe ^ ((~BCi) & BCo);
			Aki = BCi ^ ((~BCo) & BCu);
			Ako = BCo ^ ((~BCu) & BCa);
			Aku = BCu ^ ((~BCa) & BCe);

			Ebu ^= Du;
			BCa = keccak_rotl64(Ebu, 27U);
			Ega ^= Da;
			BCe = keccak_rotl64(Ega, 36U);
			Eke ^= De;
			BCi = keccak_rotl64(Eke, 10U);
			Emi ^= Di;
			BCo = keccak_rotl64(Emi, 15U);
			Eso ^= Do;
			BCu = keccak_rotl64(Eso, 56U);
			Ama = BCa ^ ((~BCe) & BCi);
			Ame = BCe ^ ((~BCi) & BCo);
			Ami = BCi ^ ((~BCo) & BCu);
			Amo = BCo ^ ((~BCu) & BCa);
			Amu = BCu ^ ((~BCa) & BCe);

			Ebi ^= Di;
			BCa = keccak_rotl64(Ebi, 62U);
			Ego ^= Do;
			BCe = keccak_rotl64(Ego, 55U);
			Eku ^= Du;
			BCi = keccak_rotl64(Eku, 39U);
			Ema ^= Da;
			BCo = keccak_rotl64(Ema, 41U);
			Ese ^= De;
			BCu = keccak_rotl64(Ese, 2U);
			Asa = BCa ^ ((~BCe) & BCi);
			Ase = BCe ^ ((~BCi) & BCo);
			Asi = BCi ^ ((~BCo) & BCu);
			Aso = BCo ^ ((~BCu) & BCa);
			Asu = BCu ^ ((~BCa) & BCe);
		}

		/* copy to state */
		state[0U] = Aba;
		state[1U] = Abe;
		state[2U] = Abi;
		state[3U] = Abo;
		state[4U] = Abu;
		state[5U] = Aga;
		state[6U] = Age;
		state[7U] = Agi;
		state[8U] = Ago;
		state[9U] = Agu;
		state[10U] = Aka;
		state[11U] = Ake;
		state[12U] = Aki;
		state[13U] = Ako;
		state[14U] = Aku;
		state[15U] = Ama;
		state[16U] = Ame;
		state[17U] = Ami;
		state[18U] = Amo;
		state[19U] = Amu;
		state[20U] = Asa;
		state[21U] = Ase;
		state[22U] = Asi;
		state[23U] = Aso;
		state[24U] = Asu;
	}
#endif
}

void qsc_keccak_permute_p1600u(uint64_t* state)
{
	QSC_ASSERT(state != NULL);

	uint64_t Aba;
	uint64_t Abe;
	uint64_t Abi;
	uint64_t Abo;
	uint64_t Abu;
	uint64_t Aga;
	uint64_t Age;
	uint64_t Agi;
	uint64_t Ago;
	uint64_t Agu;
	uint64_t Aka;
	uint64_t Ake;
	uint64_t Aki;
	uint64_t Ako;
	uint64_t Aku;
	uint64_t Ama;
	uint64_t Ame;
	uint64_t Ami;
	uint64_t Amo;
	uint64_t Amu;
	uint64_t Asa;
	uint64_t Ase;
	uint64_t Asi;
	uint64_t Aso;
	uint64_t Asu;
	uint64_t Ca;
	uint64_t Ce;
	uint64_t Ci;
	uint64_t Co;
	uint64_t Cu;
	uint64_t Da;
	uint64_t De;
	uint64_t Di;
	uint64_t Do;
	uint64_t Du;
	uint64_t Eba;
	uint64_t Ebe;
	uint64_t Ebi;
	uint64_t Ebo;
	uint64_t Ebu;
	uint64_t Ega;
	uint64_t Ege;
	uint64_t Egi;
	uint64_t Ego;
	uint64_t Egu;
	uint64_t Eka;
	uint64_t Eke;
	uint64_t Eki;
	uint64_t Eko;
	uint64_t Eku;
	uint64_t Ema;
	uint64_t Eme;
	uint64_t Emi;
	uint64_t Emo;
	uint64_t Emu;
	uint64_t Esa;
	uint64_t Ese;
	uint64_t Esi;
	uint64_t Eso;
	uint64_t Esu;

	if (state != NULL)
	{
		Aba = state[0U];
		Abe = state[1U];
		Abi = state[2U];
		Abo = state[3U];
		Abu = state[4U];
		Aga = state[5U];
		Age = state[6U];
		Agi = state[7U];
		Ago = state[8U];
		Agu = state[9U];
		Aka = state[10U];
		Ake = state[11U];
		Aki = state[12U];
		Ako = state[13U];
		Aku = state[14U];
		Ama = state[15U];
		Ame = state[16U];
		Ami = state[17U];
		Amo = state[18U];
		Amu = state[19U];
		Asa = state[20U];
		Ase = state[21U];
		Asi = state[22U];
		Aso = state[23U];
		Asu = state[24U];

		/* round 1 */
		Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
		Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
		Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
		Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
		Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
		Da = Cu ^ keccak_rotl64(Ce, 1U);
		De = Ca ^ keccak_rotl64(Ci, 1U);
		Di = Ce ^ keccak_rotl64(Co, 1U);
		Do = Ci ^ keccak_rotl64(Cu, 1U);
		Du = Co ^ keccak_rotl64(Ca, 1U);
		Aba ^= Da;
		Ca = Aba;
		Age ^= De;
		Ce = keccak_rotl64(Age, 44U);
		Aki ^= Di;
		Ci = keccak_rotl64(Aki, 43U);
		Amo ^= Do;
		Co = keccak_rotl64(Amo, 21U);
		Asu ^= Du;
		Cu = keccak_rotl64(Asu, 14U);
		Eba = Ca ^ ((~Ce) & Ci);
		Eba ^= 0x0000000000000001ULL;
		Ebe = Ce ^ ((~Ci) & Co);
		Ebi = Ci ^ ((~Co) & Cu);
		Ebo = Co ^ ((~Cu) & Ca);
		Ebu = Cu ^ ((~Ca) & Ce);
		Abo ^= Do;
		Ca = keccak_rotl64(Abo, 28U);
		Agu ^= Du;
		Ce = keccak_rotl64(Agu, 20U);
		Aka ^= Da;
		Ci = keccak_rotl64(Aka, 3U);
		Ame ^= De;
		Co = keccak_rotl64(Ame, 45U);
		Asi ^= Di;
		Cu = keccak_rotl64(Asi, 61U);
		Ega = Ca ^ ((~Ce) & Ci);
		Ege = Ce ^ ((~Ci) & Co);
		Egi = Ci ^ ((~Co) & Cu);
		Ego = Co ^ ((~Cu) & Ca);
		Egu = Cu ^ ((~Ca) & Ce);
		Abe ^= De;
		Ca = keccak_rotl64(Abe, 1U);
		Agi ^= Di;
		Ce = keccak_rotl64(Agi, 6U);
		Ako ^= Do;
		Ci = keccak_rotl64(Ako, 25U);
		Amu ^= Du;
		Co = keccak_rotl64(Amu, 8U);
		Asa ^= Da;
		Cu = keccak_rotl64(Asa, 18U);
		Eka = Ca ^ ((~Ce) & Ci);
		Eke = Ce ^ ((~Ci) & Co);
		Eki = Ci ^ ((~Co) & Cu);
		Eko = Co ^ ((~Cu) & Ca);
		Eku = Cu ^ ((~Ca) & Ce);
		Abu ^= Du;
		Ca = keccak_rotl64(Abu, 27U);
		Aga ^= Da;
		Ce = keccak_rotl64(Aga, 36U);
		Ake ^= De;
		Ci = keccak_rotl64(Ake, 10U);
		Ami ^= Di;
		Co = keccak_rotl64(Ami, 15U);
		Aso ^= Do;
		Cu = keccak_rotl64(Aso, 56U);
		Ema = Ca ^ ((~Ce) & Ci);
		Eme = Ce ^ ((~Ci) & Co);
		Emi = Ci ^ ((~Co) & Cu);
		Emo = Co ^ ((~Cu) & Ca);
		Emu = Cu ^ ((~Ca) & Ce);
		Abi ^= Di;
		Ca = keccak_rotl64(Abi, 62U);
		Ago ^= Do;
		Ce = keccak_rotl64(Ago, 55U);
		Aku ^= Du;
		Ci = keccak_rotl64(Aku, 39U);
		Ama ^= Da;
		Co = keccak_rotl64(Ama, 41U);
		Ase ^= De;
		Cu = keccak_rotl64(Ase, 2U);
		Esa = Ca ^ ((~Ce) & Ci);
		Ese = Ce ^ ((~Ci) & Co);
		Esi = Ci ^ ((~Co) & Cu);
		Eso = Co ^ ((~Cu) & Ca);
		Esu = Cu ^ ((~Ca) & Ce);
		/* round 2 */
		Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
		Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
		Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
		Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
		Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
		Da = Cu ^ keccak_rotl64(Ce, 1U);
		De = Ca ^ keccak_rotl64(Ci, 1U);
		Di = Ce ^ keccak_rotl64(Co, 1U);
		Do = Ci ^ keccak_rotl64(Cu, 1U);
		Du = Co ^ keccak_rotl64(Ca, 1U);
		Eba ^= Da;
		Ca = Eba;
		Ege ^= De;
		Ce = keccak_rotl64(Ege, 44U);
		Eki ^= Di;
		Ci = keccak_rotl64(Eki, 43U);
		Emo ^= Do;
		Co = keccak_rotl64(Emo, 21U);
		Esu ^= Du;
		Cu = keccak_rotl64(Esu, 14U);
		Aba = Ca ^ ((~Ce) & Ci);
		Aba ^= 0x0000000000008082ULL;
		Abe = Ce ^ ((~Ci) & Co);
		Abi = Ci ^ ((~Co) & Cu);
		Abo = Co ^ ((~Cu) & Ca);
		Abu = Cu ^ ((~Ca) & Ce);
		Ebo ^= Do;
		Ca = keccak_rotl64(Ebo, 28U);
		Egu ^= Du;
		Ce = keccak_rotl64(Egu, 20U);
		Eka ^= Da;
		Ci = keccak_rotl64(Eka, 3U);
		Eme ^= De;
		Co = keccak_rotl64(Eme, 45U);
		Esi ^= Di;
		Cu = keccak_rotl64(Esi, 61U);
		Aga = Ca ^ ((~Ce) & Ci);
		Age = Ce ^ ((~Ci) & Co);
		Agi = Ci ^ ((~Co) & Cu);
		Ago = Co ^ ((~Cu) & Ca);
		Agu = Cu ^ ((~Ca) & Ce);
		Ebe ^= De;
		Ca = keccak_rotl64(Ebe, 1U);
		Egi ^= Di;
		Ce = keccak_rotl64(Egi, 6U);
		Eko ^= Do;
		Ci = keccak_rotl64(Eko, 25U);
		Emu ^= Du;
		Co = keccak_rotl64(Emu, 8U);
		Esa ^= Da;
		Cu = keccak_rotl64(Esa, 18);
		Aka = Ca ^ ((~Ce) & Ci);
		Ake = Ce ^ ((~Ci) & Co);
		Aki = Ci ^ ((~Co) & Cu);
		Ako = Co ^ ((~Cu) & Ca);
		Aku = Cu ^ ((~Ca) & Ce);
		Ebu ^= Du;
		Ca = keccak_rotl64(Ebu, 27U);
		Ega ^= Da;
		Ce = keccak_rotl64(Ega, 36U);
		Eke ^= De;
		Ci = keccak_rotl64(Eke, 10U);
		Emi ^= Di;
		Co = keccak_rotl64(Emi, 15U);
		Eso ^= Do;
		Cu = keccak_rotl64(Eso, 56U);
		Ama = Ca ^ ((~Ce) & Ci);
		Ame = Ce ^ ((~Ci) & Co);
		Ami = Ci ^ ((~Co) & Cu);
		Amo = Co ^ ((~Cu) & Ca);
		Amu = Cu ^ ((~Ca) & Ce);
		Ebi ^= Di;
		Ca = keccak_rotl64(Ebi, 62U);
		Ego ^= Do;
		Ce = keccak_rotl64(Ego, 55U);
		Eku ^= Du;
		Ci = keccak_rotl64(Eku, 39U);
		Ema ^= Da;
		Co = keccak_rotl64(Ema, 41U);
		Ese ^= De;
		Cu = keccak_rotl64(Ese, 2U);
		Asa = Ca ^ ((~Ce) & Ci);
		Ase = Ce ^ ((~Ci) & Co);
		Asi = Ci ^ ((~Co) & Cu);
		Aso = Co ^ ((~Cu) & Ca);
		Asu = Cu ^ ((~Ca) & Ce);
		/* round 3 */
		Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
		Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
		Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
		Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
		Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
		Da = Cu ^ keccak_rotl64(Ce, 1U);
		De = Ca ^ keccak_rotl64(Ci, 1U);
		Di = Ce ^ keccak_rotl64(Co, 1U);
		Do = Ci ^ keccak_rotl64(Cu, 1U);
		Du = Co ^ keccak_rotl64(Ca, 1U);
		Aba ^= Da;
		Ca = Aba;
		Age ^= De;
		Ce = keccak_rotl64(Age, 44U);
		Aki ^= Di;
		Ci = keccak_rotl64(Aki, 43U);
		Amo ^= Do;
		Co = keccak_rotl64(Amo, 21U);
		Asu ^= Du;
		Cu = keccak_rotl64(Asu, 14U);
		Eba = Ca ^ ((~Ce) & Ci);
		Eba ^= 0x800000000000808AULL;
		Ebe = Ce ^ ((~Ci) & Co);
		Ebi = Ci ^ ((~Co) & Cu);
		Ebo = Co ^ ((~Cu) & Ca);
		Ebu = Cu ^ ((~Ca) & Ce);
		Abo ^= Do;
		Ca = keccak_rotl64(Abo, 28U);
		Agu ^= Du;
		Ce = keccak_rotl64(Agu, 20U);
		Aka ^= Da;
		Ci = keccak_rotl64(Aka, 3U);
		Ame ^= De;
		Co = keccak_rotl64(Ame, 45U);
		Asi ^= Di;
		Cu = keccak_rotl64(Asi, 61U);
		Ega = Ca ^ ((~Ce) & Ci);
		Ege = Ce ^ ((~Ci) & Co);
		Egi = Ci ^ ((~Co) & Cu);
		Ego = Co ^ ((~Cu) & Ca);
		Egu = Cu ^ ((~Ca) & Ce);
		Abe ^= De;
		Ca = keccak_rotl64(Abe, 1U);
		Agi ^= Di;
		Ce = keccak_rotl64(Agi, 6U);
		Ako ^= Do;
		Ci = keccak_rotl64(Ako, 25U);
		Amu ^= Du;
		Co = keccak_rotl64(Amu, 8U);
		Asa ^= Da;
		Cu = keccak_rotl64(Asa, 18U);
		Eka = Ca ^ ((~Ce) & Ci);
		Eke = Ce ^ ((~Ci) & Co);
		Eki = Ci ^ ((~Co) & Cu);
		Eko = Co ^ ((~Cu) & Ca);
		Eku = Cu ^ ((~Ca) & Ce);
		Abu ^= Du;
		Ca = keccak_rotl64(Abu, 27U);
		Aga ^= Da;
		Ce = keccak_rotl64(Aga, 36U);
		Ake ^= De;
		Ci = keccak_rotl64(Ake, 10U);
		Ami ^= Di;
		Co = keccak_rotl64(Ami, 15U);
		Aso ^= Do;
		Cu = keccak_rotl64(Aso, 56);
		Ema = Ca ^ ((~Ce) & Ci);
		Eme = Ce ^ ((~Ci) & Co);
		Emi = Ci ^ ((~Co) & Cu);
		Emo = Co ^ ((~Cu) & Ca);
		Emu = Cu ^ ((~Ca) & Ce);
		Abi ^= Di;
		Ca = keccak_rotl64(Abi, 62U);
		Ago ^= Do;
		Ce = keccak_rotl64(Ago, 55U);
		Aku ^= Du;
		Ci = keccak_rotl64(Aku, 39U);
		Ama ^= Da;
		Co = keccak_rotl64(Ama, 41U);
		Ase ^= De;
		Cu = keccak_rotl64(Ase, 2U);
		Esa = Ca ^ ((~Ce) & Ci);
		Ese = Ce ^ ((~Ci) & Co);
		Esi = Ci ^ ((~Co) & Cu);
		Eso = Co ^ ((~Cu) & Ca);
		Esu = Cu ^ ((~Ca) & Ce);
		/* round 4 */
		Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
		Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
		Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
		Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
		Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
		Da = Cu ^ keccak_rotl64(Ce, 1U);
		De = Ca ^ keccak_rotl64(Ci, 1U);
		Di = Ce ^ keccak_rotl64(Co, 1U);
		Do = Ci ^ keccak_rotl64(Cu, 1U);
		Du = Co ^ keccak_rotl64(Ca, 1U);
		Eba ^= Da;
		Ca = Eba;
		Ege ^= De;
		Ce = keccak_rotl64(Ege, 44U);
		Eki ^= Di;
		Ci = keccak_rotl64(Eki, 43U);
		Emo ^= Do;
		Co = keccak_rotl64(Emo, 21U);
		Esu ^= Du;
		Cu = keccak_rotl64(Esu, 14U);
		Aba = Ca ^ ((~Ce) & Ci);
		Aba ^= 0x8000000080008000ULL;
		Abe = Ce ^ ((~Ci) & Co);
		Abi = Ci ^ ((~Co) & Cu);
		Abo = Co ^ ((~Cu) & Ca);
		Abu = Cu ^ ((~Ca) & Ce);
		Ebo ^= Do;
		Ca = keccak_rotl64(Ebo, 28U);
		Egu ^= Du;
		Ce = keccak_rotl64(Egu, 20U);
		Eka ^= Da;
		Ci = keccak_rotl64(Eka, 3U);
		Eme ^= De;
		Co = keccak_rotl64(Eme, 45U);
		Esi ^= Di;
		Cu = keccak_rotl64(Esi, 61U);
		Aga = Ca ^ ((~Ce) & Ci);
		Age = Ce ^ ((~Ci) & Co);
		Agi = Ci ^ ((~Co) & Cu);
		Ago = Co ^ ((~Cu) & Ca);
		Agu = Cu ^ ((~Ca) & Ce);
		Ebe ^= De;
		Ca = keccak_rotl64(Ebe, 1U);
		Egi ^= Di;
		Ce = keccak_rotl64(Egi, 6U);
		Eko ^= Do;
		Ci = keccak_rotl64(Eko, 25U);
		Emu ^= Du;
		Co = keccak_rotl64(Emu, 8U);
		Esa ^= Da;
		Cu = keccak_rotl64(Esa, 18U);
		Aka = Ca ^ ((~Ce) & Ci);
		Ake = Ce ^ ((~Ci) & Co);
		Aki = Ci ^ ((~Co) & Cu);
		Ako = Co ^ ((~Cu) & Ca);
		Aku = Cu ^ ((~Ca) & Ce);
		Ebu ^= Du;
		Ca = keccak_rotl64(Ebu, 27U);
		Ega ^= Da;
		Ce = keccak_rotl64(Ega, 36U);
		Eke ^= De;
		Ci = keccak_rotl64(Eke, 10U);
		Emi ^= Di;
		Co = keccak_rotl64(Emi, 15U);
		Eso ^= Do;
		Cu = keccak_rotl64(Eso, 56U);
		Ama = Ca ^ ((~Ce) & Ci);
		Ame = Ce ^ ((~Ci) & Co);
		Ami = Ci ^ ((~Co) & Cu);
		Amo = Co ^ ((~Cu) & Ca);
		Amu = Cu ^ ((~Ca) & Ce);
		Ebi ^= Di;
		Ca = keccak_rotl64(Ebi, 62U);
		Ego ^= Do;
		Ce = keccak_rotl64(Ego, 55U);
		Eku ^= Du;
		Ci = keccak_rotl64(Eku, 39U);
		Ema ^= Da;
		Co = keccak_rotl64(Ema, 41U);
		Ese ^= De;
		Cu = keccak_rotl64(Ese, 2U);
		Asa = Ca ^ ((~Ce) & Ci);
		Ase = Ce ^ ((~Ci) & Co);
		Asi = Ci ^ ((~Co) & Cu);
		Aso = Co ^ ((~Cu) & Ca);
		Asu = Cu ^ ((~Ca) & Ce);
		/* round 5 */
		Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
		Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
		Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
		Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
		Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
		Da = Cu ^ keccak_rotl64(Ce, 1U);
		De = Ca ^ keccak_rotl64(Ci, 1U);
		Di = Ce ^ keccak_rotl64(Co, 1U);
		Do = Ci ^ keccak_rotl64(Cu, 1U);
		Du = Co ^ keccak_rotl64(Ca, 1U);
		Aba ^= Da;
		Ca = Aba;
		Age ^= De;
		Ce = keccak_rotl64(Age, 44U);
		Aki ^= Di;
		Ci = keccak_rotl64(Aki, 43U);
		Amo ^= Do;
		Co = keccak_rotl64(Amo, 21U);
		Asu ^= Du;
		Cu = keccak_rotl64(Asu, 14U);
		Eba = Ca ^ ((~Ce) & Ci);
		Eba ^= 0x000000000000808BULL;
		Ebe = Ce ^ ((~Ci) & Co);
		Ebi = Ci ^ ((~Co) & Cu);
		Ebo = Co ^ ((~Cu) & Ca);
		Ebu = Cu ^ ((~Ca) & Ce);
		Abo ^= Do;
		Ca = keccak_rotl64(Abo, 28U);
		Agu ^= Du;
		Ce = keccak_rotl64(Agu, 20U);
		Aka ^= Da;
		Ci = keccak_rotl64(Aka, 3U);
		Ame ^= De;
		Co = keccak_rotl64(Ame, 45U);
		Asi ^= Di;
		Cu = keccak_rotl64(Asi, 61U);
		Ega = Ca ^ ((~Ce) & Ci);
		Ege = Ce ^ ((~Ci) & Co);
		Egi = Ci ^ ((~Co) & Cu);
		Ego = Co ^ ((~Cu) & Ca);
		Egu = Cu ^ ((~Ca) & Ce);
		Abe ^= De;
		Ca = keccak_rotl64(Abe, 1U);
		Agi ^= Di;
		Ce = keccak_rotl64(Agi, 6U);
		Ako ^= Do;
		Ci = keccak_rotl64(Ako, 25U);
		Amu ^= Du;
		Co = keccak_rotl64(Amu, 8U);
		Asa ^= Da;
		Cu = keccak_rotl64(Asa, 18U);
		Eka = Ca ^ ((~Ce) & Ci);
		Eke = Ce ^ ((~Ci) & Co);
		Eki = Ci ^ ((~Co) & Cu);
		Eko = Co ^ ((~Cu) & Ca);
		Eku = Cu ^ ((~Ca) & Ce);
		Abu ^= Du;
		Ca = keccak_rotl64(Abu, 27U);
		Aga ^= Da;
		Ce = keccak_rotl64(Aga, 36U);
		Ake ^= De;
		Ci = keccak_rotl64(Ake, 10U);
		Ami ^= Di;
		Co = keccak_rotl64(Ami, 15U);
		Aso ^= Do;
		Cu = keccak_rotl64(Aso, 56U);
		Ema = Ca ^ ((~Ce) & Ci);
		Eme = Ce ^ ((~Ci) & Co);
		Emi = Ci ^ ((~Co) & Cu);
		Emo = Co ^ ((~Cu) & Ca);
		Emu = Cu ^ ((~Ca) & Ce);
		Abi ^= Di;
		Ca = keccak_rotl64(Abi, 62U);
		Ago ^= Do;
		Ce = keccak_rotl64(Ago, 55U);
		Aku ^= Du;
		Ci = keccak_rotl64(Aku, 39U);
		Ama ^= Da;
		Co = keccak_rotl64(Ama, 41U);
		Ase ^= De;
		Cu = keccak_rotl64(Ase, 2U);
		Esa = Ca ^ ((~Ce) & Ci);
		Ese = Ce ^ ((~Ci) & Co);
		Esi = Ci ^ ((~Co) & Cu);
		Eso = Co ^ ((~Cu) & Ca);
		Esu = Cu ^ ((~Ca) & Ce);
		/* round 6 */
		Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
		Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
		Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
		Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
		Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
		Da = Cu ^ keccak_rotl64(Ce, 1U);
		De = Ca ^ keccak_rotl64(Ci, 1U);
		Di = Ce ^ keccak_rotl64(Co, 1U);
		Do = Ci ^ keccak_rotl64(Cu, 1U);
		Du = Co ^ keccak_rotl64(Ca, 1U);
		Eba ^= Da;
		Ca = Eba;
		Ege ^= De;
		Ce = keccak_rotl64(Ege, 44U);
		Eki ^= Di;
		Ci = keccak_rotl64(Eki, 43U);
		Emo ^= Do;
		Co = keccak_rotl64(Emo, 21U);
		Esu ^= Du;
		Cu = keccak_rotl64(Esu, 14U);
		Aba = Ca ^ ((~Ce) & Ci);
		Aba ^= 0x0000000080000001ULL;
		Abe = Ce ^ ((~Ci) & Co);
		Abi = Ci ^ ((~Co) & Cu);
		Abo = Co ^ ((~Cu) & Ca);
		Abu = Cu ^ ((~Ca) & Ce);
		Ebo ^= Do;
		Ca = keccak_rotl64(Ebo, 28U);
		Egu ^= Du;
		Ce = keccak_rotl64(Egu, 20U);
		Eka ^= Da;
		Ci = keccak_rotl64(Eka, 3U);
		Eme ^= De;
		Co = keccak_rotl64(Eme, 45U);
		Esi ^= Di;
		Cu = keccak_rotl64(Esi, 61U);
		Aga = Ca ^ ((~Ce) & Ci);
		Age = Ce ^ ((~Ci) & Co);
		Agi = Ci ^ ((~Co) & Cu);
		Ago = Co ^ ((~Cu) & Ca);
		Agu = Cu ^ ((~Ca) & Ce);
		Ebe ^= De;
		Ca = keccak_rotl64(Ebe, 1U);
		Egi ^= Di;
		Ce = keccak_rotl64(Egi, 6U);
		Eko ^= Do;
		Ci = keccak_rotl64(Eko, 25U);
		Emu ^= Du;
		Co = keccak_rotl64(Emu, 8U);
		Esa ^= Da;
		Cu = keccak_rotl64(Esa, 18U);
		Aka = Ca ^ ((~Ce) & Ci);
		Ake = Ce ^ ((~Ci) & Co);
		Aki = Ci ^ ((~Co) & Cu);
		Ako = Co ^ ((~Cu) & Ca);
		Aku = Cu ^ ((~Ca) & Ce);
		Ebu ^= Du;
		Ca = keccak_rotl64(Ebu, 27U);
		Ega ^= Da;
		Ce = keccak_rotl64(Ega, 36U);
		Eke ^= De;
		Ci = keccak_rotl64(Eke, 10U);
		Emi ^= Di;
		Co = keccak_rotl64(Emi, 15U);
		Eso ^= Do;
		Cu = keccak_rotl64(Eso, 56U);
		Ama = Ca ^ ((~Ce) & Ci);
		Ame = Ce ^ ((~Ci) & Co);
		Ami = Ci ^ ((~Co) & Cu);
		Amo = Co ^ ((~Cu) & Ca);
		Amu = Cu ^ ((~Ca) & Ce);
		Ebi ^= Di;
		Ca = keccak_rotl64(Ebi, 62U);
		Ego ^= Do;
		Ce = keccak_rotl64(Ego, 55U);
		Eku ^= Du;
		Ci = keccak_rotl64(Eku, 39U);
		Ema ^= Da;
		Co = keccak_rotl64(Ema, 41U);
		Ese ^= De;
		Cu = keccak_rotl64(Ese, 2U);
		Asa = Ca ^ ((~Ce) & Ci);
		Ase = Ce ^ ((~Ci) & Co);
		Asi = Ci ^ ((~Co) & Cu);
		Aso = Co ^ ((~Cu) & Ca);
		Asu = Cu ^ ((~Ca) & Ce);
		/* round 7 */
		Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
		Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
		Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
		Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
		Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
		Da = Cu ^ keccak_rotl64(Ce, 1U);
		De = Ca ^ keccak_rotl64(Ci, 1U);
		Di = Ce ^ keccak_rotl64(Co, 1U);
		Do = Ci ^ keccak_rotl64(Cu, 1U);
		Du = Co ^ keccak_rotl64(Ca, 1U);
		Aba ^= Da;
		Ca = Aba;
		Age ^= De;
		Ce = keccak_rotl64(Age, 44U);
		Aki ^= Di;
		Ci = keccak_rotl64(Aki, 43U);
		Amo ^= Do;
		Co = keccak_rotl64(Amo, 21U);
		Asu ^= Du;
		Cu = keccak_rotl64(Asu, 14U);
		Eba = Ca ^ ((~Ce) & Ci);
		Eba ^= 0x8000000080008081ULL;
		Ebe = Ce ^ ((~Ci) & Co);
		Ebi = Ci ^ ((~Co) & Cu);
		Ebo = Co ^ ((~Cu) & Ca);
		Ebu = Cu ^ ((~Ca) & Ce);
		Abo ^= Do;
		Ca = keccak_rotl64(Abo, 28U);
		Agu ^= Du;
		Ce = keccak_rotl64(Agu, 20U);
		Aka ^= Da;
		Ci = keccak_rotl64(Aka, 3U);
		Ame ^= De;
		Co = keccak_rotl64(Ame, 45U);
		Asi ^= Di;
		Cu = keccak_rotl64(Asi, 61U);
		Ega = Ca ^ ((~Ce) & Ci);
		Ege = Ce ^ ((~Ci) & Co);
		Egi = Ci ^ ((~Co) & Cu);
		Ego = Co ^ ((~Cu) & Ca);
		Egu = Cu ^ ((~Ca) & Ce);
		Abe ^= De;
		Ca = keccak_rotl64(Abe, 1U);
		Agi ^= Di;
		Ce = keccak_rotl64(Agi, 6U);
		Ako ^= Do;
		Ci = keccak_rotl64(Ako, 25U);
		Amu ^= Du;
		Co = keccak_rotl64(Amu, 8U);
		Asa ^= Da;
		Cu = keccak_rotl64(Asa, 18U);
		Eka = Ca ^ ((~Ce) & Ci);
		Eke = Ce ^ ((~Ci) & Co);
		Eki = Ci ^ ((~Co) & Cu);
		Eko = Co ^ ((~Cu) & Ca);
		Eku = Cu ^ ((~Ca) & Ce);
		Abu ^= Du;
		Ca = keccak_rotl64(Abu, 27U);
		Aga ^= Da;
		Ce = keccak_rotl64(Aga, 36U);
		Ake ^= De;
		Ci = keccak_rotl64(Ake, 10U);
		Ami ^= Di;
		Co = keccak_rotl64(Ami, 15U);
		Aso ^= Do;
		Cu = keccak_rotl64(Aso, 56U);
		Ema = Ca ^ ((~Ce) & Ci);
		Eme = Ce ^ ((~Ci) & Co);
		Emi = Ci ^ ((~Co) & Cu);
		Emo = Co ^ ((~Cu) & Ca);
		Emu = Cu ^ ((~Ca) & Ce);
		Abi ^= Di;
		Ca = keccak_rotl64(Abi, 62U);
		Ago ^= Do;
		Ce = keccak_rotl64(Ago, 55U);
		Aku ^= Du;
		Ci = keccak_rotl64(Aku, 39U);
		Ama ^= Da;
		Co = keccak_rotl64(Ama, 41U);
		Ase ^= De;
		Cu = keccak_rotl64(Ase, 2U);
		Esa = Ca ^ ((~Ce) & Ci);
		Ese = Ce ^ ((~Ci) & Co);
		Esi = Ci ^ ((~Co) & Cu);
		Eso = Co ^ ((~Cu) & Ca);
		Esu = Cu ^ ((~Ca) & Ce);
		/* round 8 */
		Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
		Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
		Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
		Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
		Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
		Da = Cu ^ keccak_rotl64(Ce, 1U);
		De = Ca ^ keccak_rotl64(Ci, 1U);
		Di = Ce ^ keccak_rotl64(Co, 1U);
		Do = Ci ^ keccak_rotl64(Cu, 1U);
		Du = Co ^ keccak_rotl64(Ca, 1U);
		Eba ^= Da;
		Ca = Eba;
		Ege ^= De;
		Ce = keccak_rotl64(Ege, 44U);
		Eki ^= Di;
		Ci = keccak_rotl64(Eki, 43U);
		Emo ^= Do;
		Co = keccak_rotl64(Emo, 21U);
		Esu ^= Du;
		Cu = keccak_rotl64(Esu, 14U);
		Aba = Ca ^ ((~Ce) & Ci);
		Aba ^= 0x8000000000008009ULL;
		Abe = Ce ^ ((~Ci) & Co);
		Abi = Ci ^ ((~Co) & Cu);
		Abo = Co ^ ((~Cu) & Ca);
		Abu = Cu ^ ((~Ca) & Ce);
		Ebo ^= Do;
		Ca = keccak_rotl64(Ebo, 28U);
		Egu ^= Du;
		Ce = keccak_rotl64(Egu, 20U);
		Eka ^= Da;
		Ci = keccak_rotl64(Eka, 3U);
		Eme ^= De;
		Co = keccak_rotl64(Eme, 45U);
		Esi ^= Di;
		Cu = keccak_rotl64(Esi, 61U);
		Aga = Ca ^ ((~Ce) & Ci);
		Age = Ce ^ ((~Ci) & Co);
		Agi = Ci ^ ((~Co) & Cu);
		Ago = Co ^ ((~Cu) & Ca);
		Agu = Cu ^ ((~Ca) & Ce);
		Ebe ^= De;
		Ca = keccak_rotl64(Ebe, 1U);
		Egi ^= Di;
		Ce = keccak_rotl64(Egi, 6U);
		Eko ^= Do;
		Ci = keccak_rotl64(Eko, 25U);
		Emu ^= Du;
		Co = keccak_rotl64(Emu, 8U);
		Esa ^= Da;
		Cu = keccak_rotl64(Esa, 18U);
		Aka = Ca ^ ((~Ce) & Ci);
		Ake = Ce ^ ((~Ci) & Co);
		Aki = Ci ^ ((~Co) & Cu);
		Ako = Co ^ ((~Cu) & Ca);
		Aku = Cu ^ ((~Ca) & Ce);
		Ebu ^= Du;
		Ca = keccak_rotl64(Ebu, 27U);
		Ega ^= Da;
		Ce = keccak_rotl64(Ega, 36U);
		Eke ^= De;
		Ci = keccak_rotl64(Eke, 10U);
		Emi ^= Di;
		Co = keccak_rotl64(Emi, 15U);
		Eso ^= Do;
		Cu = keccak_rotl64(Eso, 56U);
		Ama = Ca ^ ((~Ce) & Ci);
		Ame = Ce ^ ((~Ci) & Co);
		Ami = Ci ^ ((~Co) & Cu);
		Amo = Co ^ ((~Cu) & Ca);
		Amu = Cu ^ ((~Ca) & Ce);
		Ebi ^= Di;
		Ca = keccak_rotl64(Ebi, 62U);
		Ego ^= Do;
		Ce = keccak_rotl64(Ego, 55U);
		Eku ^= Du;
		Ci = keccak_rotl64(Eku, 39U);
		Ema ^= Da;
		Co = keccak_rotl64(Ema, 41U);
		Ese ^= De;
		Cu = keccak_rotl64(Ese, 2U);
		Asa = Ca ^ ((~Ce) & Ci);
		Ase = Ce ^ ((~Ci) & Co);
		Asi = Ci ^ ((~Co) & Cu);
		Aso = Co ^ ((~Cu) & Ca);
		Asu = Cu ^ ((~Ca) & Ce);
		/* round 9 */
		Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
		Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
		Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
		Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
		Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
		Da = Cu ^ keccak_rotl64(Ce, 1U);
		De = Ca ^ keccak_rotl64(Ci, 1U);
		Di = Ce ^ keccak_rotl64(Co, 1U);
		Do = Ci ^ keccak_rotl64(Cu, 1U);
		Du = Co ^ keccak_rotl64(Ca, 1U);
		Aba ^= Da;
		Ca = Aba;
		Age ^= De;
		Ce = keccak_rotl64(Age, 44U);
		Aki ^= Di;
		Ci = keccak_rotl64(Aki, 43U);
		Amo ^= Do;
		Co = keccak_rotl64(Amo, 21U);
		Asu ^= Du;
		Cu = keccak_rotl64(Asu, 14U);
		Eba = Ca ^ ((~Ce) & Ci);
		Eba ^= 0x000000000000008AULL;
		Ebe = Ce ^ ((~Ci) & Co);
		Ebi = Ci ^ ((~Co) & Cu);
		Ebo = Co ^ ((~Cu) & Ca);
		Ebu = Cu ^ ((~Ca) & Ce);
		Abo ^= Do;
		Ca = keccak_rotl64(Abo, 28U);
		Agu ^= Du;
		Ce = keccak_rotl64(Agu, 20U);
		Aka ^= Da;
		Ci = keccak_rotl64(Aka, 3U);
		Ame ^= De;
		Co = keccak_rotl64(Ame, 45U);
		Asi ^= Di;
		Cu = keccak_rotl64(Asi, 61U);
		Ega = Ca ^ ((~Ce) & Ci);
		Ege = Ce ^ ((~Ci) & Co);
		Egi = Ci ^ ((~Co) & Cu);
		Ego = Co ^ ((~Cu) & Ca);
		Egu = Cu ^ ((~Ca) & Ce);
		Abe ^= De;
		Ca = keccak_rotl64(Abe, 1U);
		Agi ^= Di;
		Ce = keccak_rotl64(Agi, 6U);
		Ako ^= Do;
		Ci = keccak_rotl64(Ako, 25U);
		Amu ^= Du;
		Co = keccak_rotl64(Amu, 8U);
		Asa ^= Da;
		Cu = keccak_rotl64(Asa, 18U);
		Eka = Ca ^ ((~Ce) & Ci);
		Eke = Ce ^ ((~Ci) & Co);
		Eki = Ci ^ ((~Co) & Cu);
		Eko = Co ^ ((~Cu) & Ca);
		Eku = Cu ^ ((~Ca) & Ce);
		Abu ^= Du;
		Ca = keccak_rotl64(Abu, 27U);
		Aga ^= Da;
		Ce = keccak_rotl64(Aga, 36U);
		Ake ^= De;
		Ci = keccak_rotl64(Ake, 10U);
		Ami ^= Di;
		Co = keccak_rotl64(Ami, 15U);
		Aso ^= Do;
		Cu = keccak_rotl64(Aso, 56U);
		Ema = Ca ^ ((~Ce) & Ci);
		Eme = Ce ^ ((~Ci) & Co);
		Emi = Ci ^ ((~Co) & Cu);
		Emo = Co ^ ((~Cu) & Ca);
		Emu = Cu ^ ((~Ca) & Ce);
		Abi ^= Di;
		Ca = keccak_rotl64(Abi, 62U);
		Ago ^= Do;
		Ce = keccak_rotl64(Ago, 55U);
		Aku ^= Du;
		Ci = keccak_rotl64(Aku, 39U);
		Ama ^= Da;
		Co = keccak_rotl64(Ama, 41U);
		Ase ^= De;
		Cu = keccak_rotl64(Ase, 2U);
		Esa = Ca ^ ((~Ce) & Ci);
		Ese = Ce ^ ((~Ci) & Co);
		Esi = Ci ^ ((~Co) & Cu);
		Eso = Co ^ ((~Cu) & Ca);
		Esu = Cu ^ ((~Ca) & Ce);
		/* round 10 */
		Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
		Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
		Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
		Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
		Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
		Da = Cu ^ keccak_rotl64(Ce, 1U);
		De = Ca ^ keccak_rotl64(Ci, 1U);
		Di = Ce ^ keccak_rotl64(Co, 1U);
		Do = Ci ^ keccak_rotl64(Cu, 1U);
		Du = Co ^ keccak_rotl64(Ca, 1U);
		Eba ^= Da;
		Ca = Eba;
		Ege ^= De;
		Ce = keccak_rotl64(Ege, 44U);
		Eki ^= Di;
		Ci = keccak_rotl64(Eki, 43U);
		Emo ^= Do;
		Co = keccak_rotl64(Emo, 21U);
		Esu ^= Du;
		Cu = keccak_rotl64(Esu, 14U);
		Aba = Ca ^ ((~Ce) & Ci);
		Aba ^= 0x0000000000000088ULL;
		Abe = Ce ^ ((~Ci) & Co);
		Abi = Ci ^ ((~Co) & Cu);
		Abo = Co ^ ((~Cu) & Ca);
		Abu = Cu ^ ((~Ca) & Ce);
		Ebo ^= Do;
		Ca = keccak_rotl64(Ebo, 28U);
		Egu ^= Du;
		Ce = keccak_rotl64(Egu, 20U);
		Eka ^= Da;
		Ci = keccak_rotl64(Eka, 3U);
		Eme ^= De;
		Co = keccak_rotl64(Eme, 45U);
		Esi ^= Di;
		Cu = keccak_rotl64(Esi, 61U);
		Aga = Ca ^ ((~Ce) & Ci);
		Age = Ce ^ ((~Ci) & Co);
		Agi = Ci ^ ((~Co) & Cu);
		Ago = Co ^ ((~Cu) & Ca);
		Agu = Cu ^ ((~Ca) & Ce);
		Ebe ^= De;
		Ca = keccak_rotl64(Ebe, 1U);
		Egi ^= Di;
		Ce = keccak_rotl64(Egi, 6U);
		Eko ^= Do;
		Ci = keccak_rotl64(Eko, 25U);
		Emu ^= Du;
		Co = keccak_rotl64(Emu, 8U);
		Esa ^= Da;
		Cu = keccak_rotl64(Esa, 18U);
		Aka = Ca ^ ((~Ce) & Ci);
		Ake = Ce ^ ((~Ci) & Co);
		Aki = Ci ^ ((~Co) & Cu);
		Ako = Co ^ ((~Cu) & Ca);
		Aku = Cu ^ ((~Ca) & Ce);
		Ebu ^= Du;
		Ca = keccak_rotl64(Ebu, 27U);
		Ega ^= Da;
		Ce = keccak_rotl64(Ega, 36U);
		Eke ^= De;
		Ci = keccak_rotl64(Eke, 10U);
		Emi ^= Di;
		Co = keccak_rotl64(Emi, 15U);
		Eso ^= Do;
		Cu = keccak_rotl64(Eso, 56U);
		Ama = Ca ^ ((~Ce) & Ci);
		Ame = Ce ^ ((~Ci) & Co);
		Ami = Ci ^ ((~Co) & Cu);
		Amo = Co ^ ((~Cu) & Ca);
		Amu = Cu ^ ((~Ca) & Ce);
		Ebi ^= Di;
		Ca = keccak_rotl64(Ebi, 62U);
		Ego ^= Do;
		Ce = keccak_rotl64(Ego, 55U);
		Eku ^= Du;
		Ci = keccak_rotl64(Eku, 39U);
		Ema ^= Da;
		Co = keccak_rotl64(Ema, 41U);
		Ese ^= De;
		Cu = keccak_rotl64(Ese, 2U);
		Asa = Ca ^ ((~Ce) & Ci);
		Ase = Ce ^ ((~Ci) & Co);
		Asi = Ci ^ ((~Co) & Cu);
		Aso = Co ^ ((~Cu) & Ca);
		Asu = Cu ^ ((~Ca) & Ce);
		/* round 11 */
		Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
		Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
		Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
		Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
		Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
		Da = Cu ^ keccak_rotl64(Ce, 1U);
		De = Ca ^ keccak_rotl64(Ci, 1U);
		Di = Ce ^ keccak_rotl64(Co, 1U);
		Do = Ci ^ keccak_rotl64(Cu, 1U);
		Du = Co ^ keccak_rotl64(Ca, 1U);
		Aba ^= Da;
		Ca = Aba;
		Age ^= De;
		Ce = keccak_rotl64(Age, 44U);
		Aki ^= Di;
		Ci = keccak_rotl64(Aki, 43U);
		Amo ^= Do;
		Co = keccak_rotl64(Amo, 21U);
		Asu ^= Du;
		Cu = keccak_rotl64(Asu, 14U);
		Eba = Ca ^ ((~Ce) & Ci);
		Eba ^= 0x0000000080008009ULL;
		Ebe = Ce ^ ((~Ci) & Co);
		Ebi = Ci ^ ((~Co) & Cu);
		Ebo = Co ^ ((~Cu) & Ca);
		Ebu = Cu ^ ((~Ca) & Ce);
		Abo ^= Do;
		Ca = keccak_rotl64(Abo, 28U);
		Agu ^= Du;
		Ce = keccak_rotl64(Agu, 20U);
		Aka ^= Da;
		Ci = keccak_rotl64(Aka, 3U);
		Ame ^= De;
		Co = keccak_rotl64(Ame, 45U);
		Asi ^= Di;
		Cu = keccak_rotl64(Asi, 61U);
		Ega = Ca ^ ((~Ce) & Ci);
		Ege = Ce ^ ((~Ci) & Co);
		Egi = Ci ^ ((~Co) & Cu);
		Ego = Co ^ ((~Cu) & Ca);
		Egu = Cu ^ ((~Ca) & Ce);
		Abe ^= De;
		Ca = keccak_rotl64(Abe, 1U);
		Agi ^= Di;
		Ce = keccak_rotl64(Agi, 6U);
		Ako ^= Do;
		Ci = keccak_rotl64(Ako, 25U);
		Amu ^= Du;
		Co = keccak_rotl64(Amu, 8U);
		Asa ^= Da;
		Cu = keccak_rotl64(Asa, 18U);
		Eka = Ca ^ ((~Ce) & Ci);
		Eke = Ce ^ ((~Ci) & Co);
		Eki = Ci ^ ((~Co) & Cu);
		Eko = Co ^ ((~Cu) & Ca);
		Eku = Cu ^ ((~Ca) & Ce);
		Abu ^= Du;
		Ca = keccak_rotl64(Abu, 27U);
		Aga ^= Da;
		Ce = keccak_rotl64(Aga, 36U);
		Ake ^= De;
		Ci = keccak_rotl64(Ake, 10U);
		Ami ^= Di;
		Co = keccak_rotl64(Ami, 15U);
		Aso ^= Do;
		Cu = keccak_rotl64(Aso, 56U);
		Ema = Ca ^ ((~Ce) & Ci);
		Eme = Ce ^ ((~Ci) & Co);
		Emi = Ci ^ ((~Co) & Cu);
		Emo = Co ^ ((~Cu) & Ca);
		Emu = Cu ^ ((~Ca) & Ce);
		Abi ^= Di;
		Ca = keccak_rotl64(Abi, 62U);
		Ago ^= Do;
		Ce = keccak_rotl64(Ago, 55U);
		Aku ^= Du;
		Ci = keccak_rotl64(Aku, 39U);
		Ama ^= Da;
		Co = keccak_rotl64(Ama, 41U);
		Ase ^= De;
		Cu = keccak_rotl64(Ase, 2U);
		Esa = Ca ^ ((~Ce) & Ci);
		Ese = Ce ^ ((~Ci) & Co);
		Esi = Ci ^ ((~Co) & Cu);
		Eso = Co ^ ((~Cu) & Ca);
		Esu = Cu ^ ((~Ca) & Ce);
		/* round 12 */
		Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
		Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
		Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
		Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
		Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
		Da = Cu ^ keccak_rotl64(Ce, 1U);
		De = Ca ^ keccak_rotl64(Ci, 1U);
		Di = Ce ^ keccak_rotl64(Co, 1U);
		Do = Ci ^ keccak_rotl64(Cu, 1U);
		Du = Co ^ keccak_rotl64(Ca, 1U);
		Eba ^= Da;
		Ca = Eba;
		Ege ^= De;
		Ce = keccak_rotl64(Ege, 44U);
		Eki ^= Di;
		Ci = keccak_rotl64(Eki, 43U);
		Emo ^= Do;
		Co = keccak_rotl64(Emo, 21U);
		Esu ^= Du;
		Cu = keccak_rotl64(Esu, 14U);
		Aba = Ca ^ ((~Ce) & Ci);
		Aba ^= 0x000000008000000AULL;
		Abe = Ce ^ ((~Ci) & Co);
		Abi = Ci ^ ((~Co) & Cu);
		Abo = Co ^ ((~Cu) & Ca);
		Abu = Cu ^ ((~Ca) & Ce);
		Ebo ^= Do;
		Ca = keccak_rotl64(Ebo, 28U);
		Egu ^= Du;
		Ce = keccak_rotl64(Egu, 20U);
		Eka ^= Da;
		Ci = keccak_rotl64(Eka, 3U);
		Eme ^= De;
		Co = keccak_rotl64(Eme, 45U);
		Esi ^= Di;
		Cu = keccak_rotl64(Esi, 61U);
		Aga = Ca ^ ((~Ce) & Ci);
		Age = Ce ^ ((~Ci) & Co);
		Agi = Ci ^ ((~Co) & Cu);
		Ago = Co ^ ((~Cu) & Ca);
		Agu = Cu ^ ((~Ca) & Ce);
		Ebe ^= De;
		Ca = keccak_rotl64(Ebe, 1U);
		Egi ^= Di;
		Ce = keccak_rotl64(Egi, 6U);
		Eko ^= Do;
		Ci = keccak_rotl64(Eko, 25U);
		Emu ^= Du;
		Co = keccak_rotl64(Emu, 8U);
		Esa ^= Da;
		Cu = keccak_rotl64(Esa, 18U);
		Aka = Ca ^ ((~Ce) & Ci);
		Ake = Ce ^ ((~Ci) & Co);
		Aki = Ci ^ ((~Co) & Cu);
		Ako = Co ^ ((~Cu) & Ca);
		Aku = Cu ^ ((~Ca) & Ce);
		Ebu ^= Du;
		Ca = keccak_rotl64(Ebu, 27U);
		Ega ^= Da;
		Ce = keccak_rotl64(Ega, 36U);
		Eke ^= De;
		Ci = keccak_rotl64(Eke, 10U);
		Emi ^= Di;
		Co = keccak_rotl64(Emi, 15U);
		Eso ^= Do;
		Cu = keccak_rotl64(Eso, 56U);
		Ama = Ca ^ ((~Ce) & Ci);
		Ame = Ce ^ ((~Ci) & Co);
		Ami = Ci ^ ((~Co) & Cu);
		Amo = Co ^ ((~Cu) & Ca);
		Amu = Cu ^ ((~Ca) & Ce);
		Ebi ^= Di;
		Ca = keccak_rotl64(Ebi, 62U);
		Ego ^= Do;
		Ce = keccak_rotl64(Ego, 55U);
		Eku ^= Du;
		Ci = keccak_rotl64(Eku, 39U);
		Ema ^= Da;
		Co = keccak_rotl64(Ema, 41U);
		Ese ^= De;
		Cu = keccak_rotl64(Ese, 2U);
		Asa = Ca ^ ((~Ce) & Ci);
		Ase = Ce ^ ((~Ci) & Co);
		Asi = Ci ^ ((~Co) & Cu);
		Aso = Co ^ ((~Cu) & Ca);
		Asu = Cu ^ ((~Ca) & Ce);
		/* round 13 */
		Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
		Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
		Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
		Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
		Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
		Da = Cu ^ keccak_rotl64(Ce, 1U);
		De = Ca ^ keccak_rotl64(Ci, 1U);
		Di = Ce ^ keccak_rotl64(Co, 1U);
		Do = Ci ^ keccak_rotl64(Cu, 1U);
		Du = Co ^ keccak_rotl64(Ca, 1U);
		Aba ^= Da;
		Ca = Aba;
		Age ^= De;
		Ce = keccak_rotl64(Age, 44U);
		Aki ^= Di;
		Ci = keccak_rotl64(Aki, 43U);
		Amo ^= Do;
		Co = keccak_rotl64(Amo, 21U);
		Asu ^= Du;
		Cu = keccak_rotl64(Asu, 14U);
		Eba = Ca ^ ((~Ce) & Ci);
		Eba ^= 0x000000008000808BULL;
		Ebe = Ce ^ ((~Ci) & Co);
		Ebi = Ci ^ ((~Co) & Cu);
		Ebo = Co ^ ((~Cu) & Ca);
		Ebu = Cu ^ ((~Ca) & Ce);
		Abo ^= Do;
		Ca = keccak_rotl64(Abo, 28U);
		Agu ^= Du;
		Ce = keccak_rotl64(Agu, 20U);
		Aka ^= Da;
		Ci = keccak_rotl64(Aka, 3U);
		Ame ^= De;
		Co = keccak_rotl64(Ame, 45U);
		Asi ^= Di;
		Cu = keccak_rotl64(Asi, 61U);
		Ega = Ca ^ ((~Ce) & Ci);
		Ege = Ce ^ ((~Ci) & Co);
		Egi = Ci ^ ((~Co) & Cu);
		Ego = Co ^ ((~Cu) & Ca);
		Egu = Cu ^ ((~Ca) & Ce);
		Abe ^= De;
		Ca = keccak_rotl64(Abe, 1U);
		Agi ^= Di;
		Ce = keccak_rotl64(Agi, 6U);
		Ako ^= Do;
		Ci = keccak_rotl64(Ako, 25U);
		Amu ^= Du;
		Co = keccak_rotl64(Amu, 8U);
		Asa ^= Da;
		Cu = keccak_rotl64(Asa, 18U);
		Eka = Ca ^ ((~Ce) & Ci);
		Eke = Ce ^ ((~Ci) & Co);
		Eki = Ci ^ ((~Co) & Cu);
		Eko = Co ^ ((~Cu) & Ca);
		Eku = Cu ^ ((~Ca) & Ce);
		Abu ^= Du;
		Ca = keccak_rotl64(Abu, 27U);
		Aga ^= Da;
		Ce = keccak_rotl64(Aga, 36U);
		Ake ^= De;
		Ci = keccak_rotl64(Ake, 10U);
		Ami ^= Di;
		Co = keccak_rotl64(Ami, 15U);
		Aso ^= Do;
		Cu = keccak_rotl64(Aso, 56U);
		Ema = Ca ^ ((~Ce) & Ci);
		Eme = Ce ^ ((~Ci) & Co);
		Emi = Ci ^ ((~Co) & Cu);
		Emo = Co ^ ((~Cu) & Ca);
		Emu = Cu ^ ((~Ca) & Ce);
		Abi ^= Di;
		Ca = keccak_rotl64(Abi, 62U);
		Ago ^= Do;
		Ce = keccak_rotl64(Ago, 55U);
		Aku ^= Du;
		Ci = keccak_rotl64(Aku, 39U);
		Ama ^= Da;
		Co = keccak_rotl64(Ama, 41U);
		Ase ^= De;
		Cu = keccak_rotl64(Ase, 2U);
		Esa = Ca ^ ((~Ce) & Ci);
		Ese = Ce ^ ((~Ci) & Co);
		Esi = Ci ^ ((~Co) & Cu);
		Eso = Co ^ ((~Cu) & Ca);
		Esu = Cu ^ ((~Ca) & Ce);
		/* round 14 */
		Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
		Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
		Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
		Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
		Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
		Da = Cu ^ keccak_rotl64(Ce, 1U);
		De = Ca ^ keccak_rotl64(Ci, 1U);
		Di = Ce ^ keccak_rotl64(Co, 1U);
		Do = Ci ^ keccak_rotl64(Cu, 1U);
		Du = Co ^ keccak_rotl64(Ca, 1U);
		Eba ^= Da;
		Ca = Eba;
		Ege ^= De;
		Ce = keccak_rotl64(Ege, 44U);
		Eki ^= Di;
		Ci = keccak_rotl64(Eki, 43U);
		Emo ^= Do;
		Co = keccak_rotl64(Emo, 21U);
		Esu ^= Du;
		Cu = keccak_rotl64(Esu, 14U);
		Aba = Ca ^ ((~Ce) & Ci);
		Aba ^= 0x800000000000008BULL;
		Abe = Ce ^ ((~Ci) & Co);
		Abi = Ci ^ ((~Co) & Cu);
		Abo = Co ^ ((~Cu) & Ca);
		Abu = Cu ^ ((~Ca) & Ce);
		Ebo ^= Do;
		Ca = keccak_rotl64(Ebo, 28U);
		Egu ^= Du;
		Ce = keccak_rotl64(Egu, 20U);
		Eka ^= Da;
		Ci = keccak_rotl64(Eka, 3U);
		Eme ^= De;
		Co = keccak_rotl64(Eme, 45U);
		Esi ^= Di;
		Cu = keccak_rotl64(Esi, 61U);
		Aga = Ca ^ ((~Ce) & Ci);
		Age = Ce ^ ((~Ci) & Co);
		Agi = Ci ^ ((~Co) & Cu);
		Ago = Co ^ ((~Cu) & Ca);
		Agu = Cu ^ ((~Ca) & Ce);
		Ebe ^= De;
		Ca = keccak_rotl64(Ebe, 1U);
		Egi ^= Di;
		Ce = keccak_rotl64(Egi, 6U);
		Eko ^= Do;
		Ci = keccak_rotl64(Eko, 25U);
		Emu ^= Du;
		Co = keccak_rotl64(Emu, 8U);
		Esa ^= Da;
		Cu = keccak_rotl64(Esa, 18U);
		Aka = Ca ^ ((~Ce) & Ci);
		Ake = Ce ^ ((~Ci) & Co);
		Aki = Ci ^ ((~Co) & Cu);
		Ako = Co ^ ((~Cu) & Ca);
		Aku = Cu ^ ((~Ca) & Ce);
		Ebu ^= Du;
		Ca = keccak_rotl64(Ebu, 27U);
		Ega ^= Da;
		Ce = keccak_rotl64(Ega, 36U);
		Eke ^= De;
		Ci = keccak_rotl64(Eke, 10U);
		Emi ^= Di;
		Co = keccak_rotl64(Emi, 15U);
		Eso ^= Do;
		Cu = keccak_rotl64(Eso, 56U);
		Ama = Ca ^ ((~Ce) & Ci);
		Ame = Ce ^ ((~Ci) & Co);
		Ami = Ci ^ ((~Co) & Cu);
		Amo = Co ^ ((~Cu) & Ca);
		Amu = Cu ^ ((~Ca) & Ce);
		Ebi ^= Di;
		Ca = keccak_rotl64(Ebi, 62U);
		Ego ^= Do;
		Ce = keccak_rotl64(Ego, 55U);
		Eku ^= Du;
		Ci = keccak_rotl64(Eku, 39U);
		Ema ^= Da;
		Co = keccak_rotl64(Ema, 41U);
		Ese ^= De;
		Cu = keccak_rotl64(Ese, 2U);
		Asa = Ca ^ ((~Ce) & Ci);
		Ase = Ce ^ ((~Ci) & Co);
		Asi = Ci ^ ((~Co) & Cu);
		Aso = Co ^ ((~Cu) & Ca);
		Asu = Cu ^ ((~Ca) & Ce);
		/* round 15 */
		Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
		Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
		Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
		Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
		Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
		Da = Cu ^ keccak_rotl64(Ce, 1U);
		De = Ca ^ keccak_rotl64(Ci, 1U);
		Di = Ce ^ keccak_rotl64(Co, 1U);
		Do = Ci ^ keccak_rotl64(Cu, 1U);
		Du = Co ^ keccak_rotl64(Ca, 1U);
		Aba ^= Da;
		Ca = Aba;
		Age ^= De;
		Ce = keccak_rotl64(Age, 44U);
		Aki ^= Di;
		Ci = keccak_rotl64(Aki, 43U);
		Amo ^= Do;
		Co = keccak_rotl64(Amo, 21U);
		Asu ^= Du;
		Cu = keccak_rotl64(Asu, 14U);
		Eba = Ca ^ ((~Ce) & Ci);
		Eba ^= 0x8000000000008089ULL;
		Ebe = Ce ^ ((~Ci) & Co);
		Ebi = Ci ^ ((~Co) & Cu);
		Ebo = Co ^ ((~Cu) & Ca);
		Ebu = Cu ^ ((~Ca) & Ce);
		Abo ^= Do;
		Ca = keccak_rotl64(Abo, 28U);
		Agu ^= Du;
		Ce = keccak_rotl64(Agu, 20U);
		Aka ^= Da;
		Ci = keccak_rotl64(Aka, 3U);
		Ame ^= De;
		Co = keccak_rotl64(Ame, 45U);
		Asi ^= Di;
		Cu = keccak_rotl64(Asi, 61U);
		Ega = Ca ^ ((~Ce) & Ci);
		Ege = Ce ^ ((~Ci) & Co);
		Egi = Ci ^ ((~Co) & Cu);
		Ego = Co ^ ((~Cu) & Ca);
		Egu = Cu ^ ((~Ca) & Ce);
		Abe ^= De;
		Ca = keccak_rotl64(Abe, 1U);
		Agi ^= Di;
		Ce = keccak_rotl64(Agi, 6U);
		Ako ^= Do;
		Ci = keccak_rotl64(Ako, 25U);
		Amu ^= Du;
		Co = keccak_rotl64(Amu, 8U);
		Asa ^= Da;
		Cu = keccak_rotl64(Asa, 18U);
		Eka = Ca ^ ((~Ce) & Ci);
		Eke = Ce ^ ((~Ci) & Co);
		Eki = Ci ^ ((~Co) & Cu);
		Eko = Co ^ ((~Cu) & Ca);
		Eku = Cu ^ ((~Ca) & Ce);
		Abu ^= Du;
		Ca = keccak_rotl64(Abu, 27U);
		Aga ^= Da;
		Ce = keccak_rotl64(Aga, 36U);
		Ake ^= De;
		Ci = keccak_rotl64(Ake, 10U);
		Ami ^= Di;
		Co = keccak_rotl64(Ami, 15U);
		Aso ^= Do;
		Cu = keccak_rotl64(Aso, 56U);
		Ema = Ca ^ ((~Ce) & Ci);
		Eme = Ce ^ ((~Ci) & Co);
		Emi = Ci ^ ((~Co) & Cu);
		Emo = Co ^ ((~Cu) & Ca);
		Emu = Cu ^ ((~Ca) & Ce);
		Abi ^= Di;
		Ca = keccak_rotl64(Abi, 62U);
		Ago ^= Do;
		Ce = keccak_rotl64(Ago, 55U);
		Aku ^= Du;
		Ci = keccak_rotl64(Aku, 39U);
		Ama ^= Da;
		Co = keccak_rotl64(Ama, 41U);
		Ase ^= De;
		Cu = keccak_rotl64(Ase, 2U);
		Esa = Ca ^ ((~Ce) & Ci);
		Ese = Ce ^ ((~Ci) & Co);
		Esi = Ci ^ ((~Co) & Cu);
		Eso = Co ^ ((~Cu) & Ca);
		Esu = Cu ^ ((~Ca) & Ce);
		/* round 16 */
		Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
		Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
		Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
		Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
		Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
		Da = Cu ^ keccak_rotl64(Ce, 1U);
		De = Ca ^ keccak_rotl64(Ci, 1U);
		Di = Ce ^ keccak_rotl64(Co, 1U);
		Do = Ci ^ keccak_rotl64(Cu, 1U);
		Du = Co ^ keccak_rotl64(Ca, 1U);
		Eba ^= Da;
		Ca = Eba;
		Ege ^= De;
		Ce = keccak_rotl64(Ege, 44U);
		Eki ^= Di;
		Ci = keccak_rotl64(Eki, 43U);
		Emo ^= Do;
		Co = keccak_rotl64(Emo, 21U);
		Esu ^= Du;
		Cu = keccak_rotl64(Esu, 14U);
		Aba = Ca ^ ((~Ce) & Ci);
		Aba ^= 0x8000000000008003ULL;
		Abe = Ce ^ ((~Ci) & Co);
		Abi = Ci ^ ((~Co) & Cu);
		Abo = Co ^ ((~Cu) & Ca);
		Abu = Cu ^ ((~Ca) & Ce);
		Ebo ^= Do;
		Ca = keccak_rotl64(Ebo, 28U);
		Egu ^= Du;
		Ce = keccak_rotl64(Egu, 20U);
		Eka ^= Da;
		Ci = keccak_rotl64(Eka, 3U);
		Eme ^= De;
		Co = keccak_rotl64(Eme, 45U);
		Esi ^= Di;
		Cu = keccak_rotl64(Esi, 61U);
		Aga = Ca ^ ((~Ce) & Ci);
		Age = Ce ^ ((~Ci) & Co);
		Agi = Ci ^ ((~Co) & Cu);
		Ago = Co ^ ((~Cu) & Ca);
		Agu = Cu ^ ((~Ca) & Ce);
		Ebe ^= De;
		Ca = keccak_rotl64(Ebe, 1U);
		Egi ^= Di;
		Ce = keccak_rotl64(Egi, 6U);
		Eko ^= Do;
		Ci = keccak_rotl64(Eko, 25U);
		Emu ^= Du;
		Co = keccak_rotl64(Emu, 8U);
		Esa ^= Da;
		Cu = keccak_rotl64(Esa, 18U);
		Aka = Ca ^ ((~Ce) & Ci);
		Ake = Ce ^ ((~Ci) & Co);
		Aki = Ci ^ ((~Co) & Cu);
		Ako = Co ^ ((~Cu) & Ca);
		Aku = Cu ^ ((~Ca) & Ce);
		Ebu ^= Du;
		Ca = keccak_rotl64(Ebu, 27U);
		Ega ^= Da;
		Ce = keccak_rotl64(Ega, 36U);
		Eke ^= De;
		Ci = keccak_rotl64(Eke, 10U);
		Emi ^= Di;
		Co = keccak_rotl64(Emi, 15U);
		Eso ^= Do;
		Cu = keccak_rotl64(Eso, 56U);
		Ama = Ca ^ ((~Ce) & Ci);
		Ame = Ce ^ ((~Ci) & Co);
		Ami = Ci ^ ((~Co) & Cu);
		Amo = Co ^ ((~Cu) & Ca);
		Amu = Cu ^ ((~Ca) & Ce);
		Ebi ^= Di;
		Ca = keccak_rotl64(Ebi, 62U);
		Ego ^= Do;
		Ce = keccak_rotl64(Ego, 55U);
		Eku ^= Du;
		Ci = keccak_rotl64(Eku, 39U);
		Ema ^= Da;
		Co = keccak_rotl64(Ema, 41U);
		Ese ^= De;
		Cu = keccak_rotl64(Ese, 2U);
		Asa = Ca ^ ((~Ce) & Ci);
		Ase = Ce ^ ((~Ci) & Co);
		Asi = Ci ^ ((~Co) & Cu);
		Aso = Co ^ ((~Cu) & Ca);
		Asu = Cu ^ ((~Ca) & Ce);
		/* round 17 */
		Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
		Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
		Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
		Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
		Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
		Da = Cu ^ keccak_rotl64(Ce, 1U);
		De = Ca ^ keccak_rotl64(Ci, 1U);
		Di = Ce ^ keccak_rotl64(Co, 1U);
		Do = Ci ^ keccak_rotl64(Cu, 1U);
		Du = Co ^ keccak_rotl64(Ca, 1U);
		Aba ^= Da;
		Ca = Aba;
		Age ^= De;
		Ce = keccak_rotl64(Age, 44U);
		Aki ^= Di;
		Ci = keccak_rotl64(Aki, 43U);
		Amo ^= Do;
		Co = keccak_rotl64(Amo, 21U);
		Asu ^= Du;
		Cu = keccak_rotl64(Asu, 14U);
		Eba = Ca ^ ((~Ce) & Ci);
		Eba ^= 0x8000000000008002ULL;
		Ebe = Ce ^ ((~Ci) & Co);
		Ebi = Ci ^ ((~Co) & Cu);
		Ebo = Co ^ ((~Cu) & Ca);
		Ebu = Cu ^ ((~Ca) & Ce);
		Abo ^= Do;
		Ca = keccak_rotl64(Abo, 28U);
		Agu ^= Du;
		Ce = keccak_rotl64(Agu, 20U);
		Aka ^= Da;
		Ci = keccak_rotl64(Aka, 3U);
		Ame ^= De;
		Co = keccak_rotl64(Ame, 45U);
		Asi ^= Di;
		Cu = keccak_rotl64(Asi, 61U);
		Ega = Ca ^ ((~Ce) & Ci);
		Ege = Ce ^ ((~Ci) & Co);
		Egi = Ci ^ ((~Co) & Cu);
		Ego = Co ^ ((~Cu) & Ca);
		Egu = Cu ^ ((~Ca) & Ce);
		Abe ^= De;
		Ca = keccak_rotl64(Abe, 1U);
		Agi ^= Di;
		Ce = keccak_rotl64(Agi, 6U);
		Ako ^= Do;
		Ci = keccak_rotl64(Ako, 25U);
		Amu ^= Du;
		Co = keccak_rotl64(Amu, 8U);
		Asa ^= Da;
		Cu = keccak_rotl64(Asa, 18U);
		Eka = Ca ^ ((~Ce) & Ci);
		Eke = Ce ^ ((~Ci) & Co);
		Eki = Ci ^ ((~Co) & Cu);
		Eko = Co ^ ((~Cu) & Ca);
		Eku = Cu ^ ((~Ca) & Ce);
		Abu ^= Du;
		Ca = keccak_rotl64(Abu, 27U);
		Aga ^= Da;
		Ce = keccak_rotl64(Aga, 36U);
		Ake ^= De;
		Ci = keccak_rotl64(Ake, 10U);
		Ami ^= Di;
		Co = keccak_rotl64(Ami, 15U);
		Aso ^= Do;
		Cu = keccak_rotl64(Aso, 56U);
		Ema = Ca ^ ((~Ce) & Ci);
		Eme = Ce ^ ((~Ci) & Co);
		Emi = Ci ^ ((~Co) & Cu);
		Emo = Co ^ ((~Cu) & Ca);
		Emu = Cu ^ ((~Ca) & Ce);
		Abi ^= Di;
		Ca = keccak_rotl64(Abi, 62U);
		Ago ^= Do;
		Ce = keccak_rotl64(Ago, 55U);
		Aku ^= Du;
		Ci = keccak_rotl64(Aku, 39U);
		Ama ^= Da;
		Co = keccak_rotl64(Ama, 41U);
		Ase ^= De;
		Cu = keccak_rotl64(Ase, 2U);
		Esa = Ca ^ ((~Ce) & Ci);
		Ese = Ce ^ ((~Ci) & Co);
		Esi = Ci ^ ((~Co) & Cu);
		Eso = Co ^ ((~Cu) & Ca);
		Esu = Cu ^ ((~Ca) & Ce);
		/* round 18 */
		Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
		Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
		Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
		Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
		Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
		Da = Cu ^ keccak_rotl64(Ce, 1U);
		De = Ca ^ keccak_rotl64(Ci, 1U);
		Di = Ce ^ keccak_rotl64(Co, 1U);
		Do = Ci ^ keccak_rotl64(Cu, 1U);
		Du = Co ^ keccak_rotl64(Ca, 1U);
		Eba ^= Da;
		Ca = Eba;
		Ege ^= De;
		Ce = keccak_rotl64(Ege, 44U);
		Eki ^= Di;
		Ci = keccak_rotl64(Eki, 43U);
		Emo ^= Do;
		Co = keccak_rotl64(Emo, 21U);
		Esu ^= Du;
		Cu = keccak_rotl64(Esu, 14U);
		Aba = Ca ^ ((~Ce) & Ci);
		Aba ^= 0x8000000000000080ULL;
		Abe = Ce ^ ((~Ci) & Co);
		Abi = Ci ^ ((~Co) & Cu);
		Abo = Co ^ ((~Cu) & Ca);
		Abu = Cu ^ ((~Ca) & Ce);
		Ebo ^= Do;
		Ca = keccak_rotl64(Ebo, 28U);
		Egu ^= Du;
		Ce = keccak_rotl64(Egu, 20U);
		Eka ^= Da;
		Ci = keccak_rotl64(Eka, 3U);
		Eme ^= De;
		Co = keccak_rotl64(Eme, 45U);
		Esi ^= Di;
		Cu = keccak_rotl64(Esi, 61U);
		Aga = Ca ^ ((~Ce) & Ci);
		Age = Ce ^ ((~Ci) & Co);
		Agi = Ci ^ ((~Co) & Cu);
		Ago = Co ^ ((~Cu) & Ca);
		Agu = Cu ^ ((~Ca) & Ce);
		Ebe ^= De;
		Ca = keccak_rotl64(Ebe, 1U);
		Egi ^= Di;
		Ce = keccak_rotl64(Egi, 6U);
		Eko ^= Do;
		Ci = keccak_rotl64(Eko, 25U);
		Emu ^= Du;
		Co = keccak_rotl64(Emu, 8U);
		Esa ^= Da;
		Cu = keccak_rotl64(Esa, 18U);
		Aka = Ca ^ ((~Ce) & Ci);
		Ake = Ce ^ ((~Ci) & Co);
		Aki = Ci ^ ((~Co) & Cu);
		Ako = Co ^ ((~Cu) & Ca);
		Aku = Cu ^ ((~Ca) & Ce);
		Ebu ^= Du;
		Ca = keccak_rotl64(Ebu, 27U);
		Ega ^= Da;
		Ce = keccak_rotl64(Ega, 36U);
		Eke ^= De;
		Ci = keccak_rotl64(Eke, 10U);
		Emi ^= Di;
		Co = keccak_rotl64(Emi, 15U);
		Eso ^= Do;
		Cu = keccak_rotl64(Eso, 56U);
		Ama = Ca ^ ((~Ce) & Ci);
		Ame = Ce ^ ((~Ci) & Co);
		Ami = Ci ^ ((~Co) & Cu);
		Amo = Co ^ ((~Cu) & Ca);
		Amu = Cu ^ ((~Ca) & Ce);
		Ebi ^= Di;
		Ca = keccak_rotl64(Ebi, 62U);
		Ego ^= Do;
		Ce = keccak_rotl64(Ego, 55U);
		Eku ^= Du;
		Ci = keccak_rotl64(Eku, 39U);
		Ema ^= Da;
		Co = keccak_rotl64(Ema, 41U);
		Ese ^= De;
		Cu = keccak_rotl64(Ese, 2U);
		Asa = Ca ^ ((~Ce) & Ci);
		Ase = Ce ^ ((~Ci) & Co);
		Asi = Ci ^ ((~Co) & Cu);
		Aso = Co ^ ((~Cu) & Ca);
		Asu = Cu ^ ((~Ca) & Ce);
		/* round 19 */
		Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
		Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
		Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
		Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
		Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
		Da = Cu ^ keccak_rotl64(Ce, 1U);
		De = Ca ^ keccak_rotl64(Ci, 1U);
		Di = Ce ^ keccak_rotl64(Co, 1U);
		Do = Ci ^ keccak_rotl64(Cu, 1U);
		Du = Co ^ keccak_rotl64(Ca, 1U);
		Aba ^= Da;
		Ca = Aba;
		Age ^= De;
		Ce = keccak_rotl64(Age, 44U);
		Aki ^= Di;
		Ci = keccak_rotl64(Aki, 43U);
		Amo ^= Do;
		Co = keccak_rotl64(Amo, 21U);
		Asu ^= Du;
		Cu = keccak_rotl64(Asu, 14U);
		Eba = Ca ^ ((~Ce) & Ci);
		Eba ^= 0x000000000000800AULL;
		Ebe = Ce ^ ((~Ci) & Co);
		Ebi = Ci ^ ((~Co) & Cu);
		Ebo = Co ^ ((~Cu) & Ca);
		Ebu = Cu ^ ((~Ca) & Ce);
		Abo ^= Do;
		Ca = keccak_rotl64(Abo, 28U);
		Agu ^= Du;
		Ce = keccak_rotl64(Agu, 20U);
		Aka ^= Da;
		Ci = keccak_rotl64(Aka, 3U);
		Ame ^= De;
		Co = keccak_rotl64(Ame, 45U);
		Asi ^= Di;
		Cu = keccak_rotl64(Asi, 61U);
		Ega = Ca ^ ((~Ce) & Ci);
		Ege = Ce ^ ((~Ci) & Co);
		Egi = Ci ^ ((~Co) & Cu);
		Ego = Co ^ ((~Cu) & Ca);
		Egu = Cu ^ ((~Ca) & Ce);
		Abe ^= De;
		Ca = keccak_rotl64(Abe, 1U);
		Agi ^= Di;
		Ce = keccak_rotl64(Agi, 6U);
		Ako ^= Do;
		Ci = keccak_rotl64(Ako, 25U);
		Amu ^= Du;
		Co = keccak_rotl64(Amu, 8U);
		Asa ^= Da;
		Cu = keccak_rotl64(Asa, 18U);
		Eka = Ca ^ ((~Ce) & Ci);
		Eke = Ce ^ ((~Ci) & Co);
		Eki = Ci ^ ((~Co) & Cu);
		Eko = Co ^ ((~Cu) & Ca);
		Eku = Cu ^ ((~Ca) & Ce);
		Abu ^= Du;
		Ca = keccak_rotl64(Abu, 27U);
		Aga ^= Da;
		Ce = keccak_rotl64(Aga, 36U);
		Ake ^= De;
		Ci = keccak_rotl64(Ake, 10U);
		Ami ^= Di;
		Co = keccak_rotl64(Ami, 15U);
		Aso ^= Do;
		Cu = keccak_rotl64(Aso, 56U);
		Ema = Ca ^ ((~Ce) & Ci);
		Eme = Ce ^ ((~Ci) & Co);
		Emi = Ci ^ ((~Co) & Cu);
		Emo = Co ^ ((~Cu) & Ca);
		Emu = Cu ^ ((~Ca) & Ce);
		Abi ^= Di;
		Ca = keccak_rotl64(Abi, 62U);
		Ago ^= Do;
		Ce = keccak_rotl64(Ago, 55U);
		Aku ^= Du;
		Ci = keccak_rotl64(Aku, 39U);
		Ama ^= Da;
		Co = keccak_rotl64(Ama, 41U);
		Ase ^= De;
		Cu = keccak_rotl64(Ase, 2U);
		Esa = Ca ^ ((~Ce) & Ci);
		Ese = Ce ^ ((~Ci) & Co);
		Esi = Ci ^ ((~Co) & Cu);
		Eso = Co ^ ((~Cu) & Ca);
		Esu = Cu ^ ((~Ca) & Ce);
		/* round 20 */
		Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
		Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
		Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
		Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
		Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
		Da = Cu ^ keccak_rotl64(Ce, 1U);
		De = Ca ^ keccak_rotl64(Ci, 1U);
		Di = Ce ^ keccak_rotl64(Co, 1U);
		Do = Ci ^ keccak_rotl64(Cu, 1U);
		Du = Co ^ keccak_rotl64(Ca, 1U);
		Eba ^= Da;
		Ca = Eba;
		Ege ^= De;
		Ce = keccak_rotl64(Ege, 44U);
		Eki ^= Di;
		Ci = keccak_rotl64(Eki, 43U);
		Emo ^= Do;
		Co = keccak_rotl64(Emo, 21U);
		Esu ^= Du;
		Cu = keccak_rotl64(Esu, 14U);
		Aba = Ca ^ ((~Ce) & Ci);
		Aba ^= 0x800000008000000AULL;
		Abe = Ce ^ ((~Ci) & Co);
		Abi = Ci ^ ((~Co) & Cu);
		Abo = Co ^ ((~Cu) & Ca);
		Abu = Cu ^ ((~Ca) & Ce);
		Ebo ^= Do;
		Ca = keccak_rotl64(Ebo, 28U);
		Egu ^= Du;
		Ce = keccak_rotl64(Egu, 20U);
		Eka ^= Da;
		Ci = keccak_rotl64(Eka, 3U);
		Eme ^= De;
		Co = keccak_rotl64(Eme, 45U);
		Esi ^= Di;
		Cu = keccak_rotl64(Esi, 61U);
		Aga = Ca ^ ((~Ce) & Ci);
		Age = Ce ^ ((~Ci) & Co);
		Agi = Ci ^ ((~Co) & Cu);
		Ago = Co ^ ((~Cu) & Ca);
		Agu = Cu ^ ((~Ca) & Ce);
		Ebe ^= De;
		Ca = keccak_rotl64(Ebe, 1U);
		Egi ^= Di;
		Ce = keccak_rotl64(Egi, 6U);
		Eko ^= Do;
		Ci = keccak_rotl64(Eko, 25U);
		Emu ^= Du;
		Co = keccak_rotl64(Emu, 8U);
		Esa ^= Da;
		Cu = keccak_rotl64(Esa, 18U);
		Aka = Ca ^ ((~Ce) & Ci);
		Ake = Ce ^ ((~Ci) & Co);
		Aki = Ci ^ ((~Co) & Cu);
		Ako = Co ^ ((~Cu) & Ca);
		Aku = Cu ^ ((~Ca) & Ce);
		Ebu ^= Du;
		Ca = keccak_rotl64(Ebu, 27U);
		Ega ^= Da;
		Ce = keccak_rotl64(Ega, 36U);
		Eke ^= De;
		Ci = keccak_rotl64(Eke, 10U);
		Emi ^= Di;
		Co = keccak_rotl64(Emi, 15U);
		Eso ^= Do;
		Cu = keccak_rotl64(Eso, 56U);
		Ama = Ca ^ ((~Ce) & Ci);
		Ame = Ce ^ ((~Ci) & Co);
		Ami = Ci ^ ((~Co) & Cu);
		Amo = Co ^ ((~Cu) & Ca);
		Amu = Cu ^ ((~Ca) & Ce);
		Ebi ^= Di;
		Ca = keccak_rotl64(Ebi, 62U);
		Ego ^= Do;
		Ce = keccak_rotl64(Ego, 55U);
		Eku ^= Du;
		Ci = keccak_rotl64(Eku, 39U);
		Ema ^= Da;
		Co = keccak_rotl64(Ema, 41U);
		Ese ^= De;
		Cu = keccak_rotl64(Ese, 2U);
		Asa = Ca ^ ((~Ce) & Ci);
		Ase = Ce ^ ((~Ci) & Co);
		Asi = Ci ^ ((~Co) & Cu);
		Aso = Co ^ ((~Cu) & Ca);
		Asu = Cu ^ ((~Ca) & Ce);
		/* round 21 */
		Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
		Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
		Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
		Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
		Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
		Da = Cu ^ keccak_rotl64(Ce, 1U);
		De = Ca ^ keccak_rotl64(Ci, 1U);
		Di = Ce ^ keccak_rotl64(Co, 1U);
		Do = Ci ^ keccak_rotl64(Cu, 1U);
		Du = Co ^ keccak_rotl64(Ca, 1U);
		Aba ^= Da;
		Ca = Aba;
		Age ^= De;
		Ce = keccak_rotl64(Age, 44U);
		Aki ^= Di;
		Ci = keccak_rotl64(Aki, 43U);
		Amo ^= Do;
		Co = keccak_rotl64(Amo, 21U);
		Asu ^= Du;
		Cu = keccak_rotl64(Asu, 14U);
		Eba = Ca ^ ((~Ce) & Ci);
		Eba ^= 0x8000000080008081ULL;
		Ebe = Ce ^ ((~Ci) & Co);
		Ebi = Ci ^ ((~Co) & Cu);
		Ebo = Co ^ ((~Cu) & Ca);
		Ebu = Cu ^ ((~Ca) & Ce);
		Abo ^= Do;
		Ca = keccak_rotl64(Abo, 28U);
		Agu ^= Du;
		Ce = keccak_rotl64(Agu, 20U);
		Aka ^= Da;
		Ci = keccak_rotl64(Aka, 3U);
		Ame ^= De;
		Co = keccak_rotl64(Ame, 45U);
		Asi ^= Di;
		Cu = keccak_rotl64(Asi, 61U);
		Ega = Ca ^ ((~Ce) & Ci);
		Ege = Ce ^ ((~Ci) & Co);
		Egi = Ci ^ ((~Co) & Cu);
		Ego = Co ^ ((~Cu) & Ca);
		Egu = Cu ^ ((~Ca) & Ce);
		Abe ^= De;
		Ca = keccak_rotl64(Abe, 1U);
		Agi ^= Di;
		Ce = keccak_rotl64(Agi, 6U);
		Ako ^= Do;
		Ci = keccak_rotl64(Ako, 25U);
		Amu ^= Du;
		Co = keccak_rotl64(Amu, 8U);
		Asa ^= Da;
		Cu = keccak_rotl64(Asa, 18U);
		Eka = Ca ^ ((~Ce) & Ci);
		Eke = Ce ^ ((~Ci) & Co);
		Eki = Ci ^ ((~Co) & Cu);
		Eko = Co ^ ((~Cu) & Ca);
		Eku = Cu ^ ((~Ca) & Ce);
		Abu ^= Du;
		Ca = keccak_rotl64(Abu, 27U);
		Aga ^= Da;
		Ce = keccak_rotl64(Aga, 36U);
		Ake ^= De;
		Ci = keccak_rotl64(Ake, 10U);
		Ami ^= Di;
		Co = keccak_rotl64(Ami, 15U);
		Aso ^= Do;
		Cu = keccak_rotl64(Aso, 56U);
		Ema = Ca ^ ((~Ce) & Ci);
		Eme = Ce ^ ((~Ci) & Co);
		Emi = Ci ^ ((~Co) & Cu);
		Emo = Co ^ ((~Cu) & Ca);
		Emu = Cu ^ ((~Ca) & Ce);
		Abi ^= Di;
		Ca = keccak_rotl64(Abi, 62U);
		Ago ^= Do;
		Ce = keccak_rotl64(Ago, 55U);
		Aku ^= Du;
		Ci = keccak_rotl64(Aku, 39U);
		Ama ^= Da;
		Co = keccak_rotl64(Ama, 41U);
		Ase ^= De;
		Cu = keccak_rotl64(Ase, 2U);
		Esa = Ca ^ ((~Ce) & Ci);
		Ese = Ce ^ ((~Ci) & Co);
		Esi = Ci ^ ((~Co) & Cu);
		Eso = Co ^ ((~Cu) & Ca);
		Esu = Cu ^ ((~Ca) & Ce);
		/* round 22 */
		Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
		Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
		Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
		Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
		Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
		Da = Cu ^ keccak_rotl64(Ce, 1U);
		De = Ca ^ keccak_rotl64(Ci, 1U);
		Di = Ce ^ keccak_rotl64(Co, 1U);
		Do = Ci ^ keccak_rotl64(Cu, 1U);
		Du = Co ^ keccak_rotl64(Ca, 1U);
		Eba ^= Da;
		Ca = Eba;
		Ege ^= De;
		Ce = keccak_rotl64(Ege, 44U);
		Eki ^= Di;
		Ci = keccak_rotl64(Eki, 43U);
		Emo ^= Do;
		Co = keccak_rotl64(Emo, 21U);
		Esu ^= Du;
		Cu = keccak_rotl64(Esu, 14U);
		Aba = Ca ^ ((~Ce) & Ci);
		Aba ^= 0x8000000000008080ULL;
		Abe = Ce ^ ((~Ci) & Co);
		Abi = Ci ^ ((~Co) & Cu);
		Abo = Co ^ ((~Cu) & Ca);
		Abu = Cu ^ ((~Ca) & Ce);
		Ebo ^= Do;
		Ca = keccak_rotl64(Ebo, 28U);
		Egu ^= Du;
		Ce = keccak_rotl64(Egu, 20U);
		Eka ^= Da;
		Ci = keccak_rotl64(Eka, 3U);
		Eme ^= De;
		Co = keccak_rotl64(Eme, 45U);
		Esi ^= Di;
		Cu = keccak_rotl64(Esi, 61U);
		Aga = Ca ^ ((~Ce) & Ci);
		Age = Ce ^ ((~Ci) & Co);
		Agi = Ci ^ ((~Co) & Cu);
		Ago = Co ^ ((~Cu) & Ca);
		Agu = Cu ^ ((~Ca) & Ce);
		Ebe ^= De;
		Ca = keccak_rotl64(Ebe, 1U);
		Egi ^= Di;
		Ce = keccak_rotl64(Egi, 6U);
		Eko ^= Do;
		Ci = keccak_rotl64(Eko, 25U);
		Emu ^= Du;
		Co = keccak_rotl64(Emu, 8U);
		Esa ^= Da;
		Cu = keccak_rotl64(Esa, 18U);
		Aka = Ca ^ ((~Ce) & Ci);
		Ake = Ce ^ ((~Ci) & Co);
		Aki = Ci ^ ((~Co) & Cu);
		Ako = Co ^ ((~Cu) & Ca);
		Aku = Cu ^ ((~Ca) & Ce);
		Ebu ^= Du;
		Ca = keccak_rotl64(Ebu, 27U);
		Ega ^= Da;
		Ce = keccak_rotl64(Ega, 36U);
		Eke ^= De;
		Ci = keccak_rotl64(Eke, 10U);
		Emi ^= Di;
		Co = keccak_rotl64(Emi, 15U);
		Eso ^= Do;
		Cu = keccak_rotl64(Eso, 56U);
		Ama = Ca ^ ((~Ce) & Ci);
		Ame = Ce ^ ((~Ci) & Co);
		Ami = Ci ^ ((~Co) & Cu);
		Amo = Co ^ ((~Cu) & Ca);
		Amu = Cu ^ ((~Ca) & Ce);
		Ebi ^= Di;
		Ca = keccak_rotl64(Ebi, 62U);
		Ego ^= Do;
		Ce = keccak_rotl64(Ego, 55U);
		Eku ^= Du;
		Ci = keccak_rotl64(Eku, 39U);
		Ema ^= Da;
		Co = keccak_rotl64(Ema, 41U);
		Ese ^= De;
		Cu = keccak_rotl64(Ese, 2U);
		Asa = Ca ^ ((~Ce) & Ci);
		Ase = Ce ^ ((~Ci) & Co);
		Asi = Ci ^ ((~Co) & Cu);
		Aso = Co ^ ((~Cu) & Ca);
		Asu = Cu ^ ((~Ca) & Ce);
		/* round 23 */
		Ca = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
		Ce = Abe ^ Age ^ Ake ^ Ame ^ Ase;
		Ci = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
		Co = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
		Cu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
		Da = Cu ^ keccak_rotl64(Ce, 1U);
		De = Ca ^ keccak_rotl64(Ci, 1U);
		Di = Ce ^ keccak_rotl64(Co, 1U);
		Do = Ci ^ keccak_rotl64(Cu, 1U);
		Du = Co ^ keccak_rotl64(Ca, 1U);
		Aba ^= Da;
		Ca = Aba;
		Age ^= De;
		Ce = keccak_rotl64(Age, 44U);
		Aki ^= Di;
		Ci = keccak_rotl64(Aki, 43U);
		Amo ^= Do;
		Co = keccak_rotl64(Amo, 21U);
		Asu ^= Du;
		Cu = keccak_rotl64(Asu, 14U);
		Eba = Ca ^ ((~Ce) & Ci);
		Eba ^= 0x0000000080000001ULL;
		Ebe = Ce ^ ((~Ci) & Co);
		Ebi = Ci ^ ((~Co) & Cu);
		Ebo = Co ^ ((~Cu) & Ca);
		Ebu = Cu ^ ((~Ca) & Ce);
		Abo ^= Do;
		Ca = keccak_rotl64(Abo, 28U);
		Agu ^= Du;
		Ce = keccak_rotl64(Agu, 20U);
		Aka ^= Da;
		Ci = keccak_rotl64(Aka, 3U);
		Ame ^= De;
		Co = keccak_rotl64(Ame, 45U);
		Asi ^= Di;
		Cu = keccak_rotl64(Asi, 61U);
		Ega = Ca ^ ((~Ce) & Ci);
		Ege = Ce ^ ((~Ci) & Co);
		Egi = Ci ^ ((~Co) & Cu);
		Ego = Co ^ ((~Cu) & Ca);
		Egu = Cu ^ ((~Ca) & Ce);
		Abe ^= De;
		Ca = keccak_rotl64(Abe, 1U);
		Agi ^= Di;
		Ce = keccak_rotl64(Agi, 6U);
		Ako ^= Do;
		Ci = keccak_rotl64(Ako, 25U);
		Amu ^= Du;
		Co = keccak_rotl64(Amu, 8U);
		Asa ^= Da;
		Cu = keccak_rotl64(Asa, 18U);
		Eka = Ca ^ ((~Ce) & Ci);
		Eke = Ce ^ ((~Ci) & Co);
		Eki = Ci ^ ((~Co) & Cu);
		Eko = Co ^ ((~Cu) & Ca);
		Eku = Cu ^ ((~Ca) & Ce);
		Abu ^= Du;
		Ca = keccak_rotl64(Abu, 27U);
		Aga ^= Da;
		Ce = keccak_rotl64(Aga, 36U);
		Ake ^= De;
		Ci = keccak_rotl64(Ake, 10U);
		Ami ^= Di;
		Co = keccak_rotl64(Ami, 15U);
		Aso ^= Do;
		Cu = keccak_rotl64(Aso, 56U);
		Ema = Ca ^ ((~Ce) & Ci);
		Eme = Ce ^ ((~Ci) & Co);
		Emi = Ci ^ ((~Co) & Cu);
		Emo = Co ^ ((~Cu) & Ca);
		Emu = Cu ^ ((~Ca) & Ce);
		Abi ^= Di;
		Ca = keccak_rotl64(Abi, 62U);
		Ago ^= Do;
		Ce = keccak_rotl64(Ago, 55U);
		Aku ^= Du;
		Ci = keccak_rotl64(Aku, 39U);
		Ama ^= Da;
		Co = keccak_rotl64(Ama, 41U);
		Ase ^= De;
		Cu = keccak_rotl64(Ase, 2U);
		Esa = Ca ^ ((~Ce) & Ci);
		Ese = Ce ^ ((~Ci) & Co);
		Esi = Ci ^ ((~Co) & Cu);
		Eso = Co ^ ((~Cu) & Ca);
		Esu = Cu ^ ((~Ca) & Ce);
		/* round 24 */
		Ca = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
		Ce = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
		Ci = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
		Co = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
		Cu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
		Da = Cu ^ keccak_rotl64(Ce, 1U);
		De = Ca ^ keccak_rotl64(Ci, 1U);
		Di = Ce ^ keccak_rotl64(Co, 1U);
		Do = Ci ^ keccak_rotl64(Cu, 1U);
		Du = Co ^ keccak_rotl64(Ca, 1U);
		Eba ^= Da;
		Ca = Eba;
		Ege ^= De;
		Ce = keccak_rotl64(Ege, 44U);
		Eki ^= Di;
		Ci = keccak_rotl64(Eki, 43U);
		Emo ^= Do;
		Co = keccak_rotl64(Emo, 21U);
		Esu ^= Du;
		Cu = keccak_rotl64(Esu, 14U);
		Aba = Ca ^ ((~Ce) & Ci);
		Aba ^= 0x8000000080008008ULL;
		Abe = Ce ^ ((~Ci) & Co);
		Abi = Ci ^ ((~Co) & Cu);
		Abo = Co ^ ((~Cu) & Ca);
		Abu = Cu ^ ((~Ca) & Ce);
		Ebo ^= Do;
		Ca = keccak_rotl64(Ebo, 28U);
		Egu ^= Du;
		Ce = keccak_rotl64(Egu, 20U);
		Eka ^= Da;
		Ci = keccak_rotl64(Eka, 3U);
		Eme ^= De;
		Co = keccak_rotl64(Eme, 45U);
		Esi ^= Di;
		Cu = keccak_rotl64(Esi, 61U);
		Aga = Ca ^ ((~Ce) & Ci);
		Age = Ce ^ ((~Ci) & Co);
		Agi = Ci ^ ((~Co) & Cu);
		Ago = Co ^ ((~Cu) & Ca);
		Agu = Cu ^ ((~Ca) & Ce);
		Ebe ^= De;
		Ca = keccak_rotl64(Ebe, 1U);
		Egi ^= Di;
		Ce = keccak_rotl64(Egi, 6U);
		Eko ^= Do;
		Ci = keccak_rotl64(Eko, 25U);
		Emu ^= Du;
		Co = keccak_rotl64(Emu, 8U);
		Esa ^= Da;
		Cu = keccak_rotl64(Esa, 18U);
		Aka = Ca ^ ((~Ce) & Ci);
		Ake = Ce ^ ((~Ci) & Co);
		Aki = Ci ^ ((~Co) & Cu);
		Ako = Co ^ ((~Cu) & Ca);
		Aku = Cu ^ ((~Ca) & Ce);
		Ebu ^= Du;
		Ca = keccak_rotl64(Ebu, 27U);
		Ega ^= Da;
		Ce = keccak_rotl64(Ega, 36U);
		Eke ^= De;
		Ci = keccak_rotl64(Eke, 10U);
		Emi ^= Di;
		Co = keccak_rotl64(Emi, 15U);
		Eso ^= Do;
		Cu = keccak_rotl64(Eso, 56U);
		Ama = Ca ^ ((~Ce) & Ci);
		Ame = Ce ^ ((~Ci) & Co);
		Ami = Ci ^ ((~Co) & Cu);
		Amo = Co ^ ((~Cu) & Ca);
		Amu = Cu ^ ((~Ca) & Ce);
		Ebi ^= Di;
		Ca = keccak_rotl64(Ebi, 62U);
		Ego ^= Do;
		Ce = keccak_rotl64(Ego, 55U);
		Eku ^= Du;
		Ci = keccak_rotl64(Eku, 39U);
		Ema ^= Da;
		Co = keccak_rotl64(Ema, 41U);
		Ese ^= De;
		Cu = keccak_rotl64(Ese, 2U);
		Asa = Ca ^ ((~Ce) & Ci);
		Ase = Ce ^ ((~Ci) & Co);
		Asi = Ci ^ ((~Co) & Cu);
		Aso = Co ^ ((~Cu) & Ca);
		Asu = Cu ^ ((~Ca) & Ce);

		state[0U] = Aba;
		state[1U] = Abe;
		state[2U] = Abi;
		state[3U] = Abo;
		state[4U] = Abu;
		state[5U] = Aga;
		state[6U] = Age;
		state[7U] = Agi;
		state[8U] = Ago;
		state[9U] = Agu;
		state[10U] = Aka;
		state[11U] = Ake;
		state[12U] = Aki;
		state[13U] = Ako;
		state[14U] = Aku;
		state[15U] = Ama;
		state[16U] = Ame;
		state[17U] = Ami;
		state[18U] = Amo;
		state[19U] = Amu;
		state[20U] = Asa;
		state[21U] = Ase;
		state[22U] = Asi;
		state[23U] = Aso;
		state[24U] = Asu;
	}
}

void qsc_keccak_squeezeblocks(qsc_keccak_state* ctx, uint8_t* output, size_t nblocks, qsc_keccak_rate rate, size_t rounds)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(output != NULL);

	if (ctx != NULL && output != NULL && keccak_parameters_valid((size_t)rate, rounds))
	{
		while (nblocks > 0U)
		{
			qsc_keccak_permute(ctx, rounds);

#if defined(QSC_SYSTEM_IS_LITTLE_ENDIAN)
			qsc_memutils_copy(output, (const uint8_t*)ctx->state, (size_t)rate);
#else
			for (size_t i = 0U; i < ((size_t)rate >> 3); ++i)
			{
				qsc_intutils_le64to8((output + sizeof(uint64_t) * i), ctx->state[i]);
			}
#endif
			output += (size_t)rate;
			nblocks--;
		}
	}
}

void qsc_keccak_initialize_state(qsc_keccak_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	if (ctx != NULL)
	{
		qsc_memutils_secure_erase(ctx->state, sizeof(ctx->state));
		qsc_memutils_secure_erase(ctx->buffer, sizeof(ctx->buffer));
		ctx->position = 0U;
	}
}

void qsc_keccak_update(qsc_keccak_state* ctx, qsc_keccak_rate rate, const uint8_t* message, size_t msglen, size_t rounds)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(message != NULL);

	if (ctx != NULL && message != NULL && keccak_parameters_valid((size_t)rate, rounds) && ctx->position < (size_t)rate && msglen != 0U)
	{
		if (ctx->position != 0U && (msglen >= (size_t)rate - ctx->position))
		{
			const size_t RMDLEN = (size_t)rate - ctx->position;

			if (RMDLEN != 0U)
			{
				qsc_memutils_copy((ctx->buffer + ctx->position), message, RMDLEN);
			}

			keccak_fast_absorb(ctx->state, ctx->buffer, (size_t)rate);
			qsc_keccak_permute(ctx, rounds);
			ctx->position = 0U;
			message += RMDLEN;
			msglen -= RMDLEN;
		}

		/* sequential loop through blocks */
		while (msglen >= (size_t)rate)
		{
			keccak_fast_absorb(ctx->state, message, (size_t)rate);
			qsc_keccak_permute(ctx, rounds);
			message += (size_t)rate;
			msglen -= (size_t)rate;
		}

		/* store unaligned bytes */
		if (msglen != 0U)
		{
			qsc_memutils_copy((ctx->buffer + ctx->position), message, msglen);
			ctx->position += msglen;
		}
	}
}

#if defined(QSC_SYSTEM_IS_LITTLE_ENDIAN)

static void keccak_oneshot(uint8_t* output, size_t outlen, const uint8_t* message, size_t msglen, qsc_keccak_rate rate, uint8_t domain)
{
	/* absorb a complete message and squeeze a fixed or variable length result */
    uint64_t state[QSC_KECCAK_STATE_SIZE] = { 0U };
    uint8_t* bytes;
    size_t take;

    bytes = (uint8_t*)state;

    while (msglen >= (size_t)rate)
    {
        qsc_memutils_xor(bytes, message, (size_t)rate);
        qsc_keccak_permute_p1600c(state, QSC_KECCAK_PERMUTATION_ROUNDS);
        msglen -= (size_t)rate;
        message += (size_t)rate;
    }

    if (msglen != 0U)
    {
        qsc_memutils_xor(bytes, message, msglen);
    }

    bytes[msglen] ^= domain;
    bytes[(size_t)rate - 1U] ^= 0x80U;

    while (outlen != 0U)
    {
        qsc_keccak_permute_p1600c(state, QSC_KECCAK_PERMUTATION_ROUNDS);
        take = qsc_intutils_min(outlen, (size_t)rate);
        qsc_memutils_copy(output, bytes, take);
        outlen -= take;
        output += take;
    }

    qsc_memutils_secure_erase(state, sizeof(state));
}
#endif

/* SHA3 */

void qsc_sha3_compute128(uint8_t* output, const uint8_t* message, size_t msglen)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(message != NULL);

	if (output != NULL && message != NULL)
	{
	#if defined(QSC_SYSTEM_IS_LITTLE_ENDIAN)
		if (msglen <= 256U)
		{
			keccak_oneshot(output, QSC_SHA3_128_HASH_SIZE, message, msglen, qsc_keccak_rate_128, QSC_KECCAK_SHA3_DOMAIN_ID);
		}
		else
	#endif
		{
			qsc_keccak_state ctx;
			uint8_t hash[QSC_KECCAK_128_RATE] = { 0U };

			qsc_sha3_initialize(&ctx);
			qsc_keccak_absorb(&ctx, qsc_keccak_rate_128, message, msglen, QSC_KECCAK_SHA3_DOMAIN_ID, QSC_KECCAK_PERMUTATION_ROUNDS);
			qsc_keccak_squeezeblocks(&ctx, hash, 1U, qsc_keccak_rate_128, QSC_KECCAK_PERMUTATION_ROUNDS);
			qsc_memutils_copy(output, hash, QSC_SHA3_128_HASH_SIZE);
			qsc_memutils_secure_erase(hash, sizeof(hash));
			qsc_keccak_dispose(&ctx);
		}
	}
}

void qsc_sha3_compute256(uint8_t* output, const uint8_t* message, size_t msglen)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(message != NULL);

	if (output != NULL && message != NULL)
	{
	#if defined(QSC_SYSTEM_IS_LITTLE_ENDIAN)
		if (msglen <= 256U)
		{
			keccak_oneshot(output, QSC_SHA3_256_HASH_SIZE, message, msglen, qsc_keccak_rate_256, QSC_KECCAK_SHA3_DOMAIN_ID);
		}
		else
	#endif
		{
			qsc_keccak_state ctx;
			uint8_t hash[QSC_KECCAK_256_RATE] = { 0U };

			qsc_sha3_initialize(&ctx);
			qsc_keccak_absorb(&ctx, qsc_keccak_rate_256, message, msglen, QSC_KECCAK_SHA3_DOMAIN_ID, QSC_KECCAK_PERMUTATION_ROUNDS);
			qsc_keccak_squeezeblocks(&ctx, hash, 1U, qsc_keccak_rate_256, QSC_KECCAK_PERMUTATION_ROUNDS);
			qsc_memutils_copy(output, hash, QSC_SHA3_256_HASH_SIZE);
			qsc_memutils_secure_erase(hash, sizeof(hash));
			qsc_keccak_dispose(&ctx);
		}
	}
}

void qsc_sha3_compute512(uint8_t* output, const uint8_t* message, size_t msglen)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(message != NULL);

	if (output != NULL && message != NULL)
	{
	#if defined(QSC_SYSTEM_IS_LITTLE_ENDIAN)
		if (msglen <= 256U)
		{
			keccak_oneshot(output, QSC_SHA3_512_HASH_SIZE, message, msglen, qsc_keccak_rate_512, QSC_KECCAK_SHA3_DOMAIN_ID);
		}
		else
	#endif
		{
			qsc_keccak_state ctx;
			uint8_t hash[QSC_KECCAK_512_RATE] = { 0U };

			qsc_sha3_initialize(&ctx);
			qsc_keccak_absorb(&ctx, qsc_keccak_rate_512, message, msglen, QSC_KECCAK_SHA3_DOMAIN_ID, QSC_KECCAK_PERMUTATION_ROUNDS);
			qsc_keccak_squeezeblocks(&ctx, hash, 1U, qsc_keccak_rate_512, QSC_KECCAK_PERMUTATION_ROUNDS);
			qsc_memutils_copy(output, hash, QSC_SHA3_512_HASH_SIZE);
			qsc_memutils_secure_erase(hash, sizeof(hash));
			qsc_keccak_dispose(&ctx);
		}
	}
}

void qsc_sha3_finalize(qsc_keccak_state* ctx, qsc_keccak_rate rate, uint8_t* output)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(output != NULL);

	size_t hlen;

	if (ctx != NULL && output != NULL && keccak_parameters_valid((size_t)rate, QSC_KECCAK_PERMUTATION_ROUNDS) &&
		ctx->position < (size_t)rate)
	{
		hlen = (((QSC_KECCAK_STATE_SIZE * sizeof(uint64_t)) - (size_t)rate) / 2U);
		qsc_memutils_secure_erase((ctx->buffer + ctx->position), sizeof(ctx->buffer) - ctx->position);
		ctx->buffer[ctx->position] = QSC_KECCAK_SHA3_DOMAIN_ID;
		ctx->buffer[(size_t)rate - 1U] |= 128U;
		keccak_fast_absorb(ctx->state, ctx->buffer, (size_t)rate);
		qsc_keccak_permute(ctx, QSC_KECCAK_PERMUTATION_ROUNDS);

	#if defined(QSC_SYSTEM_IS_LITTLE_ENDIAN)
		qsc_memutils_copy(output, (const uint8_t*)ctx->state, hlen);
	#else
		for (size_t i = 0U; i < hlen / sizeof(uint64_t); ++i)
		{
			qsc_intutils_le64to8(output, ctx->state[i]);
			output += sizeof(uint64_t);
		}
	#endif

		qsc_keccak_dispose(ctx);
	}
}

void qsc_sha3_initialize(qsc_keccak_state* ctx)
{
	qsc_keccak_initialize_state(ctx);
}

void qsc_sha3_update(qsc_keccak_state* ctx, qsc_keccak_rate rate, const uint8_t* message, size_t msglen)
{
	qsc_keccak_update(ctx, rate, message, msglen, QSC_KECCAK_PERMUTATION_ROUNDS);
}

/* SHAKE */

void qsc_shake128_compute(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(key != NULL);

	if (output != NULL && key != NULL)
	{
	#if defined(QSC_SYSTEM_IS_LITTLE_ENDIAN)
		if (keylen <= 256U && outlen <= (size_t)qsc_keccak_rate_128)
		{
			keccak_oneshot(output, outlen, key, keylen, qsc_keccak_rate_128, QSC_KECCAK_SHAKE_DOMAIN_ID);
		}
		else
	#endif
		{
			const size_t nblocks = outlen / QSC_KECCAK_128_RATE;
			qsc_keccak_state ctx;
			uint8_t hash[QSC_KECCAK_128_RATE] = { 0U };

			qsc_shake_initialize(&ctx, qsc_keccak_rate_128, key, keylen);
			qsc_shake_squeezeblocks(&ctx, qsc_keccak_rate_128, output, nblocks);
			output += (nblocks * QSC_KECCAK_128_RATE);
			outlen -= (nblocks * QSC_KECCAK_128_RATE);

			if (outlen != 0U)
			{
				qsc_shake_squeezeblocks(&ctx, qsc_keccak_rate_128, hash, 1U);
				qsc_memutils_copy(output, hash, outlen);
			}

			qsc_memutils_secure_erase(hash, sizeof(hash));
			qsc_keccak_dispose(&ctx);
		}
	}
}

void qsc_shake256_compute(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(key != NULL);

	if (output != NULL && key != NULL)
	{
	#if defined(QSC_SYSTEM_IS_LITTLE_ENDIAN)
		if (keylen <= 256U && outlen <= (size_t)qsc_keccak_rate_256)
		{
			keccak_oneshot(output, outlen, key, keylen, qsc_keccak_rate_256, QSC_KECCAK_SHAKE_DOMAIN_ID);
		}
		else
	#endif
		{
			const size_t nblocks = outlen / QSC_KECCAK_256_RATE;
			qsc_keccak_state ctx;
			uint8_t hash[QSC_KECCAK_256_RATE] = { 0U };

			qsc_shake_initialize(&ctx, qsc_keccak_rate_256, key, keylen);
			qsc_shake_squeezeblocks(&ctx, qsc_keccak_rate_256, output, nblocks);
			output += (nblocks * QSC_KECCAK_256_RATE);
			outlen -= (nblocks * QSC_KECCAK_256_RATE);

			if (outlen != 0U)
			{
				qsc_shake_squeezeblocks(&ctx, qsc_keccak_rate_256, hash, 1U);
				qsc_memutils_copy(output, hash, outlen);
			}

			qsc_memutils_secure_erase(hash, sizeof(hash));
			qsc_keccak_dispose(&ctx);
		}
	}
}

void qsc_shake512_compute(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(key != NULL);

	if (output != NULL && key != NULL)
	{
	#if defined(QSC_SYSTEM_IS_LITTLE_ENDIAN)
		if (keylen <= 256U && outlen <= (size_t)qsc_keccak_rate_512)
		{
			keccak_oneshot(output, outlen, key, keylen, qsc_keccak_rate_512, QSC_KECCAK_SHAKE_DOMAIN_ID);
		}
		else
	#endif
		{
			const size_t nblocks = outlen / QSC_KECCAK_512_RATE;
			qsc_keccak_state ctx;
			uint8_t hash[QSC_KECCAK_512_RATE] = { 0U };

			qsc_shake_initialize(&ctx, qsc_keccak_rate_512, key, keylen);
			qsc_shake_squeezeblocks(&ctx, qsc_keccak_rate_512, output, nblocks);
			output += (nblocks * QSC_KECCAK_512_RATE);
			outlen -= (nblocks * QSC_KECCAK_512_RATE);

			if (outlen != 0U)
			{
				qsc_shake_squeezeblocks(&ctx, qsc_keccak_rate_512, hash, 1U);
				qsc_memutils_copy(output, hash, outlen);
			}

			qsc_memutils_secure_erase(hash, sizeof(hash));
			qsc_keccak_dispose(&ctx);
		}
	}
}

void qsc_shake_initialize(qsc_keccak_state* ctx, qsc_keccak_rate rate, const uint8_t* key, size_t keylen)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(key != NULL);

	if (ctx != NULL && key != NULL && keccak_parameters_valid((size_t)rate, QSC_KECCAK_PERMUTATION_ROUNDS))
	{
		qsc_keccak_initialize_state(ctx);
		qsc_keccak_absorb(ctx, rate, key, keylen, QSC_KECCAK_SHAKE_DOMAIN_ID, QSC_KECCAK_PERMUTATION_ROUNDS);
	}
}

void qsc_shake_squeezeblocks(qsc_keccak_state* ctx, qsc_keccak_rate rate, uint8_t* output, size_t nblocks)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(output != NULL);

	qsc_keccak_squeezeblocks(ctx, output, nblocks, rate, QSC_KECCAK_PERMUTATION_ROUNDS);
}

/* cSHAKE */

void qsc_cshake128_compute(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t custlen)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(key != NULL);

	const size_t nblocks = outlen / QSC_KECCAK_128_RATE;
	qsc_keccak_state ctx;
	uint8_t hash[QSC_KECCAK_128_RATE] = { 0U };

	if (output != NULL && key != NULL && (name != NULL || namelen == 0U) &&
		(custom != NULL || custlen == 0U) && namelen <= SIZE_MAX / 8U && custlen <= SIZE_MAX / 8U)
	{
		if (custlen != 0U || namelen != 0U)
		{
			qsc_cshake_initialize(&ctx, qsc_keccak_rate_128, key, keylen, name, namelen, custom, custlen);
		}
		else
		{
			qsc_shake_initialize(&ctx, qsc_keccak_rate_128, key, keylen);
		}

		qsc_cshake_squeezeblocks(&ctx, qsc_keccak_rate_128, output, nblocks);
		output += (nblocks * QSC_KECCAK_128_RATE);
		outlen -= (nblocks * QSC_KECCAK_128_RATE);

		if (outlen != 0U)
		{
			qsc_cshake_squeezeblocks(&ctx, qsc_keccak_rate_128, hash, 1U);
			qsc_memutils_copy(output, hash, outlen);
		}

		qsc_memutils_secure_erase(hash, sizeof(hash));
		qsc_keccak_dispose(&ctx);
	}
}

void qsc_cshake256_compute(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t custlen)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(key != NULL);

	const size_t nblocks = outlen / QSC_KECCAK_256_RATE;
	qsc_keccak_state ctx;
	uint8_t hash[QSC_KECCAK_256_RATE] = { 0U };

	if (output != NULL && key != NULL && (name != NULL || namelen == 0U) &&
		(custom != NULL || custlen == 0U) && namelen <= SIZE_MAX / 8U && custlen <= SIZE_MAX / 8U)
	{
		if (custlen != 0U || namelen != 0U)
		{
			qsc_cshake_initialize(&ctx, qsc_keccak_rate_256, key, keylen, name, namelen, custom, custlen);
		}
		else
		{
			qsc_shake_initialize(&ctx, qsc_keccak_rate_256, key, keylen);
		}

		qsc_cshake_squeezeblocks(&ctx, qsc_keccak_rate_256, output, nblocks);

		output += (nblocks * QSC_KECCAK_256_RATE);
		outlen -= (nblocks * QSC_KECCAK_256_RATE);

		if (outlen != 0U)
		{
			qsc_cshake_squeezeblocks(&ctx, qsc_keccak_rate_256, hash, 1U);
			qsc_memutils_copy(output, hash, outlen);
		}

		qsc_memutils_secure_erase(hash, sizeof(hash));
		qsc_keccak_dispose(&ctx);
	}
}

void qsc_cshake512_compute(uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t custlen)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(key != NULL);

	const size_t nblocks = outlen / QSC_KECCAK_512_RATE;
	qsc_keccak_state ctx;
	uint8_t hash[QSC_KECCAK_512_RATE] = { 0U };

	if (output != NULL && key != NULL && (name != NULL || namelen == 0U) &&
		(custom != NULL || custlen == 0U) && namelen <= SIZE_MAX / 8U && custlen <= SIZE_MAX / 8U)
	{
		if (custlen != 0U || namelen != 0U)
		{
			qsc_cshake_initialize(&ctx, qsc_keccak_rate_512, key, keylen, name, namelen, custom, custlen);
		}
		else
		{
			qsc_shake_initialize(&ctx, qsc_keccak_rate_512, key, keylen);
		}

		qsc_cshake_squeezeblocks(&ctx, qsc_keccak_rate_512, output, nblocks);
		output += (nblocks * QSC_KECCAK_512_RATE);
		outlen -= (nblocks * QSC_KECCAK_512_RATE);

		if (outlen != 0U)
		{
			qsc_cshake_squeezeblocks(&ctx, qsc_keccak_rate_512, hash, 1U);
			qsc_memutils_copy(output, hash, outlen);
		}

		qsc_memutils_secure_erase(hash, sizeof(hash));
		qsc_keccak_dispose(&ctx);
	}
}

void qsc_cshake_initialize(qsc_keccak_state* ctx, qsc_keccak_rate rate, const uint8_t* key, size_t keylen, const uint8_t* name, size_t namelen, const uint8_t* custom, size_t custlen)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(key != NULL);

	if (ctx != NULL && key != NULL && (name != NULL || namelen == 0U) && (custom != NULL || custlen == 0U) &&
		namelen <= SIZE_MAX / 8U && custlen <= SIZE_MAX / 8U && keccak_parameters_valid((size_t)rate, QSC_KECCAK_PERMUTATION_ROUNDS))
	{
		qsc_keccak_initialize_state(ctx);
		if (namelen != 0U || custlen != 0U)
		{
			qsc_keccak_absorb_custom(ctx, rate, custom, custlen, name, namelen, QSC_KECCAK_PERMUTATION_ROUNDS);
			qsc_keccak_absorb(ctx, rate, key, keylen, QSC_KECCAK_CSHAKE_DOMAIN_ID, QSC_KECCAK_PERMUTATION_ROUNDS);
		}
		else
		{
			qsc_keccak_absorb(ctx, rate, key, keylen, QSC_KECCAK_SHAKE_DOMAIN_ID, QSC_KECCAK_PERMUTATION_ROUNDS);
		}
	}
}

void qsc_cshake_squeezeblocks(qsc_keccak_state* ctx, qsc_keccak_rate rate, uint8_t* output, size_t nblocks)
{
	qsc_keccak_squeezeblocks(ctx, output, nblocks, rate, QSC_KECCAK_PERMUTATION_ROUNDS);
}

void qsc_cshake_update(qsc_keccak_state* ctx, qsc_keccak_rate rate, const uint8_t* key, size_t keylen)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(key != NULL);

	if (ctx != NULL && key != NULL && keccak_parameters_valid((size_t)rate, QSC_KECCAK_PERMUTATION_ROUNDS))
	{
		while (keylen >= (size_t)rate)
		{
			keccak_fast_absorb(ctx->state, key, (size_t)rate);
			qsc_keccak_permute(ctx, QSC_KECCAK_PERMUTATION_ROUNDS);
			keylen -= (size_t)rate;
			key += (size_t)rate;
		}

		if (keylen != 0U)
		{
			keccak_fast_absorb(ctx->state, key, keylen);
			qsc_keccak_permute(ctx, QSC_KECCAK_PERMUTATION_ROUNDS);
		}
	}
}

/* KMAC */

void qsc_kmac128_compute(uint8_t* output, size_t outlen, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t custlen)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(message != NULL);
	QSC_ASSERT(key != NULL);

	qsc_keccak_state ctx;

	if (output != NULL && message != NULL && key != NULL && (custom != NULL || custlen == 0U) &&
		outlen <= SIZE_MAX / 8U && keylen <= SIZE_MAX / 8U && custlen <= SIZE_MAX / 8U)
	{
		qsc_kmac_initialize(&ctx, qsc_keccak_rate_128, key, keylen, custom, custlen);
		qsc_kmac_update(&ctx, qsc_keccak_rate_128, message, msglen);
		qsc_kmac_finalize(&ctx, qsc_keccak_rate_128, output, outlen);
		qsc_keccak_dispose(&ctx);
	}
}

void qsc_kmac256_compute(uint8_t* output, size_t outlen, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t custlen)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(message != NULL);
	QSC_ASSERT(key != NULL);

	qsc_keccak_state ctx;

	if (output != NULL && message != NULL && key != NULL && (custom != NULL || custlen == 0U) &&
		outlen <= SIZE_MAX / 8U && keylen <= SIZE_MAX / 8U && custlen <= SIZE_MAX / 8U)
	{
		qsc_kmac_initialize(&ctx, qsc_keccak_rate_256, key, keylen, custom, custlen);
		qsc_kmac_update(&ctx, qsc_keccak_rate_256, message, msglen);
		qsc_kmac_finalize(&ctx, qsc_keccak_rate_256, output, outlen);
		qsc_keccak_dispose(&ctx);
	}
}

void qsc_kmac512_compute(uint8_t* output, size_t outlen, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t custlen)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(message != NULL);
	QSC_ASSERT(key != NULL);

	qsc_keccak_state ctx;

	if (output != NULL && message != NULL && key != NULL && (custom != NULL || custlen == 0U) &&
		outlen <= SIZE_MAX / 8U && keylen <= SIZE_MAX / 8U && custlen <= SIZE_MAX / 8U)
	{
		qsc_kmac_initialize(&ctx, qsc_keccak_rate_512, key, keylen, custom, custlen);
		qsc_kmac_update(&ctx, qsc_keccak_rate_512, message, msglen);
		qsc_kmac_finalize(&ctx, qsc_keccak_rate_512, output, outlen);
		qsc_keccak_dispose(&ctx);
	}
}

void qsc_kmac_finalize(qsc_keccak_state* ctx, qsc_keccak_rate rate, uint8_t* output, size_t outlen)
{
	qsc_keccak_finalize(ctx, rate, output, outlen, QSC_KECCAK_KMAC_DOMAIN_ID, QSC_KECCAK_PERMUTATION_ROUNDS);
}

void qsc_kmac_initialize(qsc_keccak_state* ctx, qsc_keccak_rate rate, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t custlen)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(key != NULL);

	const uint8_t name[4U] = { 0x4BU, 0x4DU, 0x41U, 0x43U };

	if (ctx != NULL && key != NULL && (custom != NULL || custlen == 0U) &&
		keylen <= SIZE_MAX / 8U && custlen <= SIZE_MAX / 8U && keccak_parameters_valid((size_t)rate, QSC_KECCAK_PERMUTATION_ROUNDS))
	{
		qsc_keccak_initialize_state(ctx);
		qsc_keccak_absorb_key_custom(ctx, rate, key, keylen, custom, custlen, name, sizeof(name), QSC_KECCAK_PERMUTATION_ROUNDS);
	}
}

void qsc_kmac_update(qsc_keccak_state* ctx, qsc_keccak_rate rate, const uint8_t* message, size_t msglen)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(message != NULL);

	qsc_keccak_update(ctx, rate, message, msglen, QSC_KECCAK_PERMUTATION_ROUNDS);
}

static void keccak_kmac_xof_compute(uint8_t* output, size_t outlen, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen, const uint8_t* custom, size_t custlen, qsc_keccak_rate rate)
{
	/* compute KMACXOF with right_encode(0) and erase explicit temporary state */
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(message != NULL);
	QSC_ASSERT(key != NULL);

	qsc_keccak_state ctx;
	uint8_t pad[QSC_KECCAK_STATE_BYTE_SIZE] = { 0U };
	const uint8_t suffix[2U] = { 0U, 1U };
	size_t nblocks;
	size_t remainder;

	if (output != NULL && message != NULL && key != NULL && (custom != NULL || custlen == 0U) &&
		keylen <= SIZE_MAX / 8U && custlen <= SIZE_MAX / 8U)
	{
		qsc_kmac_initialize(&ctx, rate, key, keylen, custom, custlen);
		qsc_kmac_update(&ctx, rate, message, msglen);
		qsc_kmac_update(&ctx, rate, suffix, sizeof(suffix));

		qsc_memutils_copy(pad, ctx.buffer, ctx.position);
		pad[ctx.position] = QSC_KECCAK_KMAC_DOMAIN_ID;
		pad[(size_t)rate - 1U] |= 0x80U;
		keccak_fast_absorb(ctx.state, pad, (size_t)rate);

		nblocks = outlen / (size_t)rate;
		remainder = outlen % (size_t)rate;

		if (nblocks != 0U)
		{
			qsc_keccak_squeezeblocks(&ctx, output, nblocks, rate, QSC_KECCAK_PERMUTATION_ROUNDS);
			output += nblocks * (size_t)rate;
		}

		if (remainder != 0U)
		{
			qsc_keccak_squeezeblocks(&ctx, pad, 1U, rate, QSC_KECCAK_PERMUTATION_ROUNDS);
			qsc_memutils_copy(output, pad, remainder);
		}

		qsc_keccak_dispose(&ctx);
	}

	qsc_memutils_secure_erase(pad, sizeof(pad));
}

void qsc_kmac_xof128_compute(uint8_t* kout, size_t koutlen, const uint8_t* x, size_t xlen, const uint8_t* kin, size_t kinlen, const uint8_t* s, size_t slen)
{
    keccak_kmac_xof_compute(kout, koutlen, x, xlen, kin, kinlen, s, slen, qsc_keccak_rate_128);
}

void qsc_kmac_xof256_compute(uint8_t* kout, size_t koutlen, const uint8_t* x, size_t xlen, const uint8_t* kin, size_t kinlen, const uint8_t* s, size_t slen)
{
    keccak_kmac_xof_compute(kout, koutlen, x, xlen, kin, kinlen, s, slen, qsc_keccak_rate_256);
}

void qsc_kmac_xof512_compute(uint8_t* kout, size_t koutlen, const uint8_t* x, size_t xlen, const uint8_t* kin, size_t kinlen, const uint8_t* s, size_t slen)
{
    keccak_kmac_xof_compute(kout, koutlen, x, xlen, kin, kinlen, s, slen, qsc_keccak_rate_512);
}

/* parallel SHAKE x4 */

#if defined(QSC_SYSTEM_HAS_AVX2)

void qsc_keccakx4_absorb(__m256i state[QSC_KECCAK_STATE_SIZE], qsc_keccak_rate rate, const uint8_t* inp0, const uint8_t* inp1, const uint8_t* inp2, const uint8_t* inp3, size_t inplen, uint8_t domain)
{
	QSC_ASSERT(inp0 != NULL);
	QSC_ASSERT(inp1 != NULL);
	QSC_ASSERT(inp2 != NULL);
	QSC_ASSERT(inp3 != NULL);

	if (state != NULL && keccak_parameters_valid((size_t)rate, QSC_KECCAK_PERMUTATION_ROUNDS) && inp0 != NULL && inp1 != NULL && inp2 != NULL && inp3 != NULL)
	{
		__m256i t;
		uint64_t v0;
		uint64_t v1;
		uint64_t v2;
		uint64_t v3;
		size_t pos;
		size_t i;

		pos = 0U;

		/* process full blocks */
		while (inplen >= (size_t)rate)
		{
			for (i = 0U; i < (size_t)rate / sizeof(uint64_t); ++i)
			{
				v0 = keccak_load64(inp0 + pos);
				v1 = keccak_load64(inp1 + pos);
				v2 = keccak_load64(inp2 + pos);
				v3 = keccak_load64(inp3 + pos);

				t = _mm256_set_epi64x(v3, v2, v1, v0);
				state[i] = _mm256_xor_si256(state[i], t);

				pos += sizeof(uint64_t);
			}

			qsc_keccak_permute_p4x1600(state, QSC_KECCAK_PERMUTATION_ROUNDS);
			inplen -= (size_t)rate;
		}

		i = 0U;

		/* process remaining input */
		while (inplen >= sizeof(uint64_t))
		{
			v0 = keccak_load64(inp0 + pos);
			v1 = keccak_load64(inp1 + pos);
			v2 = keccak_load64(inp2 + pos);
			v3 = keccak_load64(inp3 + pos);

			t = _mm256_set_epi64x(v3, v2, v1, v0);
			state[i] = _mm256_xor_si256(state[i], t);

			++i;
			pos += sizeof(uint64_t);
			inplen -= sizeof(uint64_t);
		}

		/* partial block */
		if (inplen != 0U)
		{
			v0 = 0U;
			v1 = 0U;
			v2 = 0U;
			v3 = 0U;

			/* copy remaining bytes into temporary variables */
			for (size_t j = 0U; j < inplen; ++j)
			{
				((uint8_t*)&v0)[j] = inp0[pos + j];
				((uint8_t*)&v1)[j] = inp1[pos + j];
				((uint8_t*)&v2)[j] = inp2[pos + j];
				((uint8_t*)&v3)[j] = inp3[pos + j];
			}

			t = _mm256_set_epi64x(v3, v2, v1, v0);
			state[i] = _mm256_xor_si256(state[i], t);
		}

		/* apply domain separation and padding */
		t = _mm256_set1_epi64x((uint64_t)domain << (sizeof(uint64_t) * inplen));
		state[i] = _mm256_xor_si256(state[i], t);
		if ((domain & 0x80U) != 0U && i == (size_t)rate / sizeof(uint64_t) - 1U && inplen == 7U)
		{
			qsc_keccak_permute_p4x1600(state, QSC_KECCAK_PERMUTATION_ROUNDS);
		}

		t = _mm256_set1_epi64x(1ULL << 63);
		state[((size_t)rate / sizeof(uint64_t)) - 1U] = _mm256_xor_si256(state[((size_t)rate / sizeof(uint64_t)) - 1U], t);
	}
}

void qsc_keccakx4_squeezeblocks(__m256i state[QSC_KECCAK_STATE_SIZE], qsc_keccak_rate rate, uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3, size_t nblocks)
{
	QSC_ASSERT(out0 != NULL);
	QSC_ASSERT(out1 != NULL);
	QSC_ASSERT(out2 != NULL);
	QSC_ASSERT(out3 != NULL);

	QSC_ALIGN(32) uint64_t tmp[4U] = { 0U };

	if (state != NULL && keccak_parameters_valid((size_t)rate, QSC_KECCAK_PERMUTATION_ROUNDS) && out0 != NULL && out1 != NULL && out2 != NULL && out3 != NULL)
	{
		while (nblocks > 0U)
		{
			qsc_keccak_permute_p4x1600(state, QSC_KECCAK_PERMUTATION_ROUNDS);

			for (size_t i = 0U; i < (size_t)rate / sizeof(uint64_t); ++i)
			{
				_mm256_store_si256((__m256i*)tmp, state[i]);

				keccak_store64(out0, tmp[0U]);
				keccak_store64(out1, tmp[1U]);
				keccak_store64(out2, tmp[2U]);
				keccak_store64(out3, tmp[3U]);

				out0 += sizeof(uint64_t);
				out1 += sizeof(uint64_t);
				out2 += sizeof(uint64_t);
				out3 += sizeof(uint64_t);
			}

			--nblocks;
		}
	}

	qsc_memutils_secure_erase(tmp, sizeof(tmp));
}

#endif

#if defined(QSC_SYSTEM_HAS_AVX512)

/** \def _mm512_extract_epi64x
 * \brief Legacy extraction of constant-index lane i from vector b. 
 */
#define _mm512_extract_epi64x(b, i) (_mm_extract_epi64(_mm512_extracti64x2_epi64(b, i / 2U), i % 2U))

void qsc_keccakx8_absorb(__m512i state[QSC_KECCAK_STATE_SIZE], qsc_keccak_rate rate,
	const uint8_t* inp0, const uint8_t* inp1, const uint8_t* inp2, const uint8_t* inp3,
	const uint8_t* inp4, const uint8_t* inp5, const uint8_t* inp6, const uint8_t* inp7, 
	size_t inplen, uint8_t domain)
{
	QSC_ASSERT(inp0 != NULL);
	QSC_ASSERT(inp1 != NULL);
	QSC_ASSERT(inp2 != NULL);
	QSC_ASSERT(inp3 != NULL);
	QSC_ASSERT(inp4 != NULL);
	QSC_ASSERT(inp5 != NULL);
	QSC_ASSERT(inp6 != NULL);
	QSC_ASSERT(inp7 != NULL);

	if (state != NULL && keccak_parameters_valid((size_t)rate, QSC_KECCAK_PERMUTATION_ROUNDS) && inp0 != NULL && inp1 != NULL && inp2 != NULL && inp3 != NULL &&
		inp4 != NULL && inp5 != NULL && inp6 != NULL && inp7 != NULL)
	{

		__m512i t;
		uint64_t v0;
		uint64_t v1;
		uint64_t v2;
		uint64_t v3;
		uint64_t v4;
		uint64_t v5;
		uint64_t v6;
		uint64_t v7;
		size_t pos;
		size_t i;

		pos = 0U;

		/* process full blocks */
		while (inplen >= (size_t)rate)
		{
			for (i = 0U; i < (size_t)rate / sizeof(uint64_t); ++i)
			{
				v0 = keccak_load64(inp0 + pos);
				v1 = keccak_load64(inp1 + pos);
				v2 = keccak_load64(inp2 + pos);
				v3 = keccak_load64(inp3 + pos);
				v4 = keccak_load64(inp4 + pos);
				v5 = keccak_load64(inp5 + pos);
				v6 = keccak_load64(inp6 + pos);
				v7 = keccak_load64(inp7 + pos);

				t = _mm512_set_epi64(v7, v6, v5, v4, v3, v2, v1, v0);
				state[i] = _mm512_xor_si512(state[i], t);

				pos += sizeof(uint64_t);
			}

			qsc_keccak_permute_p8x1600(state, QSC_KECCAK_PERMUTATION_ROUNDS);
			inplen -= (size_t)rate;
		}

		i = 0U;

		/* process remaining input */
		while (inplen >= sizeof(uint64_t))
		{
			v0 = keccak_load64(inp0 + pos);
			v1 = keccak_load64(inp1 + pos);
			v2 = keccak_load64(inp2 + pos);
			v3 = keccak_load64(inp3 + pos);
			v4 = keccak_load64(inp4 + pos);
			v5 = keccak_load64(inp5 + pos);
			v6 = keccak_load64(inp6 + pos);
			v7 = keccak_load64(inp7 + pos);

			t = _mm512_set_epi64(v7, v6, v5, v4, v3, v2, v1, v0);
			state[i] = _mm512_xor_si512(state[i], t);

			i++;
			pos += sizeof(uint64_t);
			inplen -= sizeof(uint64_t);
		}

		/* handle the remaining partial block */
		if (inplen != 0U)
		{
			v0 = 0U;
			v1 = 0U;
			v2 = 0U;
			v3 = 0U;
			v4 = 0U;
			v5 = 0U;
			v6 = 0U;
			v7 = 0U;

			/* copy remaining bytes into temporary variables*/
			for (size_t j = 0U; j < inplen; ++j)
			{
				((uint8_t*)&v0)[j] = inp0[pos + j];
				((uint8_t*)&v1)[j] = inp1[pos + j];
				((uint8_t*)&v2)[j] = inp2[pos + j];
				((uint8_t*)&v3)[j] = inp3[pos + j];
				((uint8_t*)&v4)[j] = inp4[pos + j];
				((uint8_t*)&v5)[j] = inp5[pos + j];
				((uint8_t*)&v6)[j] = inp6[pos + j];
				((uint8_t*)&v7)[j] = inp7[pos + j];
			}

			t = _mm512_set_epi64(v7, v6, v5, v4, v3, v2, v1, v0);
			state[i] = _mm512_xor_si512(state[i], t);
		}

		/* apply domain separation and padding */
		t = _mm512_set1_epi64((uint64_t)domain << (sizeof(uint64_t) * inplen));
		state[i] = _mm512_xor_si512(state[i], t);
		if ((domain & 0x80U) != 0U && i == (size_t)rate / sizeof(uint64_t) - 1U && inplen == 7U)
		{
			qsc_keccak_permute_p8x1600(state, QSC_KECCAK_PERMUTATION_ROUNDS);
		}

		t = _mm512_set1_epi64(1ULL << 63);
		state[((size_t)rate / sizeof(uint64_t)) - 1U] = _mm512_xor_si512(state[((size_t)rate / sizeof(uint64_t)) - 1U], t);
	}
}

void qsc_keccakx8_squeezeblocks(__m512i state[QSC_KECCAK_STATE_SIZE], qsc_keccak_rate rate,
	uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3, uint8_t* out4,
	uint8_t* out5, uint8_t* out6, uint8_t* out7, size_t nblocks)
{
	QSC_ASSERT(out0 != NULL);
	QSC_ASSERT(out1 != NULL);
	QSC_ASSERT(out2 != NULL);
	QSC_ASSERT(out3 != NULL);
	QSC_ASSERT(out4 != NULL);
	QSC_ASSERT(out5 != NULL);
	QSC_ASSERT(out6 != NULL);
	QSC_ASSERT(out7 != NULL);

	QSC_ALIGN(64) uint64_t tmp[8U] = { 0U };
	size_t i;

	if (state != NULL && keccak_parameters_valid((size_t)rate, QSC_KECCAK_PERMUTATION_ROUNDS) && out0 != NULL && out1 != NULL && out2 != NULL && out3 != NULL && out4 != NULL && out5 != NULL && out6 != NULL && out7 != NULL)
	{
		while (nblocks > 0U)
		{
			qsc_keccak_permute_p8x1600(state, QSC_KECCAK_PERMUTATION_ROUNDS);



			for (i = 0U; i < (size_t)rate / sizeof(uint64_t); ++i)
			{
				_mm512_store_si512((__m512i*)tmp, state[i]);

				keccak_store64(out0, tmp[0U]);
				keccak_store64(out1, tmp[1U]);
				keccak_store64(out2, tmp[2U]);
				keccak_store64(out3, tmp[3U]);
				keccak_store64(out4, tmp[4U]);
				keccak_store64(out5, tmp[5U]);
				keccak_store64(out6, tmp[6U]);
				keccak_store64(out7, tmp[7U]);

				out0 += sizeof(uint64_t);
				out1 += sizeof(uint64_t);
				out2 += sizeof(uint64_t);
				out3 += sizeof(uint64_t);
				out4 += sizeof(uint64_t);
				out5 += sizeof(uint64_t);
				out6 += sizeof(uint64_t);
				out7 += sizeof(uint64_t);
			}

			--nblocks;
		}
	}

	qsc_memutils_secure_erase(tmp, sizeof(tmp));
}

#endif

#if defined(QSC_SYSTEM_ARM_INTRINSICS)

static void keccak_absorb_x2_arm(uint64x2_t* state, qsc_keccak_rate rate, const uint8_t* inp0, const uint8_t* inp1)
{
	/* XOR two full rate blocks into paired Keccak lanes */
	uint64x2_t lanes;

	for (size_t i = 0U; i < (size_t)rate / sizeof(uint64_t); ++i)
	{
		lanes = vcombine_u64(vcreate_u64(keccak_load64(inp0 + (i * 8U))), vcreate_u64(keccak_load64(inp1 + (i * 8U))));
		state[i] = veorq_u64(state[i], lanes);
	}
}

static void keccak_squeeze_x2_arm(uint64x2_t* state, qsc_keccak_rate rate, uint8_t* out0, uint8_t* out1, size_t outlen)
{
	/* squeeze equally sized outputs from two padded Keccak states */
	uint8_t tmp0[QSC_KECCAK_STATE_BYTE_SIZE] = { 0U };
	uint8_t tmp1[QSC_KECCAK_STATE_BYTE_SIZE] = { 0U };

	/* avoid staging and copying complete output blocks. */
	while (outlen >= (size_t)rate)
	{
		keccak_permute_p2x1600_arm(state, QSC_KECCAK_PERMUTATION_ROUNDS);

		for (size_t i = 0U; i < (size_t)rate / sizeof(uint64_t); ++i)
		{
			keccak_store64(out0 + (i * sizeof(uint64_t)), vgetq_lane_u64(state[i], 0));
			keccak_store64(out1 + (i * sizeof(uint64_t)), vgetq_lane_u64(state[i], 1));
		}

		out0 += (size_t)rate;
		out1 += (size_t)rate;
		outlen -= (size_t)rate;
	}

	/* stage only the final partial rate block. */
	if (outlen != 0U)
	{
		keccak_permute_p2x1600_arm(state, QSC_KECCAK_PERMUTATION_ROUNDS);

		for (size_t i = 0U; i < (size_t)rate / sizeof(uint64_t); ++i)
		{
			keccak_store64(tmp0 + (i * sizeof(uint64_t)), vgetq_lane_u64(state[i], 0));
			keccak_store64(tmp1 + (i * sizeof(uint64_t)), vgetq_lane_u64(state[i], 1));
		}

		qsc_memutils_copy(out0, tmp0, outlen);
		qsc_memutils_copy(out1, tmp1, outlen);
	}

	qsc_memutils_secure_erase(tmp0, sizeof(tmp0));
	qsc_memutils_secure_erase(tmp1, sizeof(tmp1));
}

static void keccak_shake_x2_arm(qsc_keccak_rate rate, uint8_t* out0, uint8_t* out1, size_t outlen, const uint8_t* inp0, const uint8_t* inp1, size_t inplen)
{
	/* compute two SHAKE instances using paired NEON lanes */
	uint64x2_t state[QSC_KECCAK_STATE_SIZE];
	uint8_t pad0[QSC_KECCAK_STATE_BYTE_SIZE] = { 0U };
	uint8_t pad1[QSC_KECCAK_STATE_BYTE_SIZE] = { 0U };

	for (size_t i = 0U; i < QSC_KECCAK_STATE_SIZE; ++i)
	{
		state[i] = vdupq_n_u64(0U);
	}

	while (inplen >= (size_t)rate)
	{
		keccak_absorb_x2_arm(state, rate, inp0, inp1);
		keccak_permute_p2x1600_arm(state, QSC_KECCAK_PERMUTATION_ROUNDS);
		inp0 += (size_t)rate;
		inp1 += (size_t)rate;
		inplen -= (size_t)rate;
	}

	qsc_memutils_copy(pad0, inp0, inplen);
	qsc_memutils_copy(pad1, inp1, inplen);
	pad0[inplen] = QSC_KECCAK_SHAKE_DOMAIN_ID;
	pad1[inplen] = QSC_KECCAK_SHAKE_DOMAIN_ID;
	pad0[(size_t)rate - 1U] |= 0x80U;
	pad1[(size_t)rate - 1U] |= 0x80U;
	keccak_absorb_x2_arm(state, rate, pad0, pad1);
	keccak_squeeze_x2_arm(state, rate, out0, out1, outlen);
	qsc_memutils_secure_erase(pad0, sizeof(pad0));
	qsc_memutils_secure_erase(pad1, sizeof(pad1));
	qsc_memutils_secure_erase(state, sizeof(state));
}

static void keccak_kmac_x2_arm(qsc_keccak_rate rate, uint8_t* out0, uint8_t* out1, size_t outlen,
	const uint8_t* key0, const uint8_t* key1, size_t keylen, const uint8_t* cst0, const uint8_t* cst1, size_t cstlen,
	const uint8_t* msg0, const uint8_t* msg1, size_t msglen)
{
	/* compute two KMAC instances using the existing QSC initialization and finalization format */
	qsc_keccak_state ctx0;
	qsc_keccak_state ctx1;
	uint64x2_t state[QSC_KECCAK_STATE_SIZE];
	uint8_t pad0[QSC_KECCAK_STATE_BYTE_SIZE] = { 0U };
	uint8_t pad1[QSC_KECCAK_STATE_BYTE_SIZE] = { 0U };
	uint8_t encoded[sizeof(size_t) + 1U];
	size_t enclen;
	size_t take;

	qsc_kmac_initialize(&ctx0, rate, key0, keylen, cst0, cstlen);
	qsc_kmac_initialize(&ctx1, rate, key1, keylen, cst1, cstlen);

	for (size_t i = 0U; i < QSC_KECCAK_STATE_SIZE; ++i)
	{
		state[i] = vcombine_u64(vcreate_u64(ctx0.state[i]), vcreate_u64(ctx1.state[i]));
	}

	qsc_keccak_dispose(&ctx0);
	qsc_keccak_dispose(&ctx1);

	while (msglen >= (size_t)rate)
	{
		keccak_absorb_x2_arm(state, rate, msg0, msg1);
		keccak_permute_p2x1600_arm(state, QSC_KECCAK_PERMUTATION_ROUNDS);
		msg0 += (size_t)rate;
		msg1 += (size_t)rate;
		msglen -= (size_t)rate;
	}

	qsc_memutils_copy(pad0, msg0, msglen);
	qsc_memutils_copy(pad1, msg1, msglen);
	enclen = keccak_right_encode(encoded, outlen * 8U);

	if (msglen + enclen >= (size_t)rate)
	{
		take = (size_t)rate - msglen;
		qsc_memutils_copy(pad0 + msglen, encoded, take);
		qsc_memutils_copy(pad1 + msglen, encoded, take);
		keccak_absorb_x2_arm(state, rate, pad0, pad1);
		keccak_permute_p2x1600_arm(state, QSC_KECCAK_PERMUTATION_ROUNDS);
		qsc_memutils_clear(pad0, sizeof(pad0));
		qsc_memutils_clear(pad1, sizeof(pad1));
		enclen -= take;
		qsc_memutils_copy(pad0, encoded + take, enclen);
		qsc_memutils_copy(pad1, encoded + take, enclen);
		msglen = 0U;
	}
	else
	{
		qsc_memutils_copy(pad0 + msglen, encoded, enclen);
		qsc_memutils_copy(pad1 + msglen, encoded, enclen);
	}
	pad0[msglen + enclen] = QSC_KECCAK_KMAC_DOMAIN_ID;
	pad1[msglen + enclen] = QSC_KECCAK_KMAC_DOMAIN_ID;
	pad0[(size_t)rate - 1U] |= 0x80U;
	pad1[(size_t)rate - 1U] |= 0x80U;
	keccak_absorb_x2_arm(state, rate, pad0, pad1);
	keccak_squeeze_x2_arm(state, rate, out0, out1, outlen);
	qsc_memutils_secure_erase(state, sizeof(state));
	qsc_memutils_secure_erase(pad0, sizeof(pad0));
	qsc_memutils_secure_erase(pad1, sizeof(pad1));
	qsc_memutils_secure_erase(encoded, sizeof(encoded));
}

#endif


#if defined(QSC_SYSTEM_HAS_AVX2)

static void keccakx4_squeezetail(__m256i state[QSC_KECCAK_STATE_SIZE], uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3, size_t outlen)
{
	/* final partial squeeze of four independent Keccak states */
    QSC_ALIGN(32) uint64_t words[4U] = { 0U };
    uint8_t tail[8U];
    size_t i;
    size_t length;

    qsc_keccak_permute_p4x1600(state, QSC_KECCAK_PERMUTATION_ROUNDS);
    length = outlen / sizeof(uint64_t);

    for (i = 0U; i < length; ++i)
    {
        _mm256_store_si256((__m256i*)words, state[i]);
        keccak_store64(out0 + (i * 8U), words[0U]);
        keccak_store64(out1 + (i * 8U), words[1U]);
        keccak_store64(out2 + (i * 8U), words[2U]);
        keccak_store64(out3 + (i * 8U), words[3U]);
    }

    if ((outlen & 7U) != 0U)
    {
        length = outlen & 7U;
        _mm256_store_si256((__m256i*)words, state[i]);
        keccak_store64(tail, words[0U]);
        qsc_memutils_copy(out0 + (8U * i), tail, length);
        keccak_store64(tail, words[1U]);
        qsc_memutils_copy(out1 + (8U * i), tail, length);
        keccak_store64(tail, words[2U]);
        qsc_memutils_copy(out2 + (8U * i), tail, length);
        keccak_store64(tail, words[3U]);
        qsc_memutils_copy(out3 + (8U * i), tail, length);
    }

    qsc_memutils_secure_erase(words, sizeof(words));
    qsc_memutils_secure_erase(tail, sizeof(tail));
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)

static void keccakx8_squeezetail(__m512i state[QSC_KECCAK_STATE_SIZE], uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3,
    uint8_t* out4, uint8_t* out5, uint8_t* out6, uint8_t* out7, size_t outlen)
{
	/* final partial squeeze of eight independent Keccak states */
    QSC_ALIGN(64) uint64_t words[8U] = { 0U };
    uint8_t tail[8U];
    size_t i;
    size_t length;

    qsc_keccak_permute_p8x1600(state, QSC_KECCAK_PERMUTATION_ROUNDS);
    length = outlen / sizeof(uint64_t);

    for (i = 0U; i < length; ++i)
    {
        _mm512_store_si512((__m512i*)words, state[i]);
        keccak_store64(out0 + (i * 8U), words[0U]);
        keccak_store64(out1 + (i * 8U), words[1U]);
        keccak_store64(out2 + (i * 8U), words[2U]);
        keccak_store64(out3 + (i * 8U), words[3U]);
        keccak_store64(out4 + (i * 8U), words[4U]);
        keccak_store64(out5 + (i * 8U), words[5U]);
        keccak_store64(out6 + (i * 8U), words[6U]);
        keccak_store64(out7 + (i * 8U), words[7U]);
    }

    if ((outlen & 7U) != 0U)
    {
        length = outlen & 7U;
        _mm512_store_si512((__m512i*)words, state[i]);
        keccak_store64(tail, words[0U]);
        qsc_memutils_copy(out0 + (8U * i), tail, length);
        keccak_store64(tail, words[1U]);
        qsc_memutils_copy(out1 + (8U * i), tail, length);
        keccak_store64(tail, words[2U]);
        qsc_memutils_copy(out2 + (8U * i), tail, length);
        keccak_store64(tail, words[3U]);
        qsc_memutils_copy(out3 + (8U * i), tail, length);
        keccak_store64(tail, words[4U]);
        qsc_memutils_copy(out4 + (8U * i), tail, length);
        keccak_store64(tail, words[5U]);
        qsc_memutils_copy(out5 + (8U * i), tail, length);
        keccak_store64(tail, words[6U]);
        qsc_memutils_copy(out6 + (8U * i), tail, length);
        keccak_store64(tail, words[7U]);
        qsc_memutils_copy(out7 + (8U * i), tail, length);
    }

    qsc_memutils_secure_erase(words, sizeof(words));
    qsc_memutils_secure_erase(tail, sizeof(tail));
}
#endif

void qsc_shake_128x4(uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3, size_t outlen,
	const uint8_t* inp0, const uint8_t* inp1, const uint8_t* inp2, const uint8_t* inp3, size_t inplen)
{
	QSC_ASSERT(inp0 != NULL);
	QSC_ASSERT(inp1 != NULL);
	QSC_ASSERT(inp2 != NULL);
	QSC_ASSERT(inp3 != NULL);
	QSC_ASSERT(out0 != NULL);
	QSC_ASSERT(out1 != NULL);
	QSC_ASSERT(out2 != NULL);
	QSC_ASSERT(out3 != NULL);

	if (out0 != NULL && out1 != NULL && out2 != NULL && out3 != NULL && inp0 != NULL && inp1 != NULL && inp2 != NULL && inp3 != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX2)

		size_t i;
		size_t nblocks = outlen / QSC_KECCAK_128_RATE;
		QSC_ALIGN(32) uint8_t t[4U][QSC_KECCAK_128_RATE] = { 0U };
		__m256i state[QSC_KECCAK_STATE_SIZE] = { 0U };

		qsc_keccakx4_absorb(state, qsc_keccak_rate_128, inp0, inp1, inp2, inp3, inplen, QSC_KECCAK_SHAKE_DOMAIN_ID);

		if (outlen >= QSC_KECCAK_128_RATE)
		{
			qsc_keccakx4_squeezeblocks(state, qsc_keccak_rate_128, out0, out1, out2, out3, nblocks);

			out0 += nblocks * QSC_KECCAK_128_RATE;
			out1 += nblocks * QSC_KECCAK_128_RATE;
			out2 += nblocks * QSC_KECCAK_128_RATE;
			out3 += nblocks * QSC_KECCAK_128_RATE;
			outlen -= nblocks * QSC_KECCAK_128_RATE;
		}

		if (outlen != 0U)
		{
			if (inplen <= 256U)
			{
				keccakx4_squeezetail(state, out0, out1, out2, out3, outlen);
			}
			else
			{
				qsc_keccakx4_squeezeblocks(state, qsc_keccak_rate_128, t[0U], t[1U], t[2U], t[3U], 1U);
	
				for (i = 0U; i < outlen; ++i)
				{
					out0[i] = t[0U][i];
					out1[i] = t[1U][i];
					out2[i] = t[2U][i];
					out3[i] = t[3U][i];
				}
				qsc_memutils_secure_erase(t, sizeof(t));
			}
		}

		qsc_memutils_secure_erase(state, sizeof(state));

#elif defined(QSC_SYSTEM_ARM_INTRINSICS)

		keccak_shake_x2_arm(qsc_keccak_rate_128, out0, out1, outlen, inp0, inp1, inplen);
		keccak_shake_x2_arm(qsc_keccak_rate_128, out2, out3, outlen, inp2, inp3, inplen);

#else

		qsc_shake128_compute(out0, outlen, inp0, inplen);
		qsc_shake128_compute(out1, outlen, inp1, inplen);
		qsc_shake128_compute(out2, outlen, inp2, inplen);
		qsc_shake128_compute(out3, outlen, inp3, inplen);

#endif
	}
}

void qsc_shake_256x4(uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3, size_t outlen,
	const uint8_t* inp0, const uint8_t* inp1, const uint8_t* inp2, const uint8_t* inp3, size_t inplen)
{
	QSC_ASSERT(inp0 != NULL);
	QSC_ASSERT(inp1 != NULL);
	QSC_ASSERT(inp2 != NULL);
	QSC_ASSERT(inp3 != NULL);
	QSC_ASSERT(out0 != NULL);
	QSC_ASSERT(out1 != NULL);
	QSC_ASSERT(out2 != NULL);
	QSC_ASSERT(out3 != NULL);

	if (out0 != NULL && out1 != NULL && out2 != NULL && out3 != NULL && inp0 != NULL && inp1 != NULL && inp2 != NULL && inp3 != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX2)

		size_t nblocks = outlen / QSC_KECCAK_256_RATE;
		QSC_ALIGN(32) uint8_t t[4U][QSC_KECCAK_256_RATE] = { 0U };
		__m256i state[QSC_KECCAK_STATE_SIZE] = { 0U };

		qsc_keccakx4_absorb(state, qsc_keccak_rate_256, inp0, inp1, inp2, inp3, inplen, QSC_KECCAK_SHAKE_DOMAIN_ID);

		if (outlen >= QSC_KECCAK_256_RATE)
		{
			qsc_keccakx4_squeezeblocks(state, qsc_keccak_rate_256, out0, out1, out2, out3, nblocks);

			out0 += nblocks * QSC_KECCAK_256_RATE;
			out1 += nblocks * QSC_KECCAK_256_RATE;
			out2 += nblocks * QSC_KECCAK_256_RATE;
			out3 += nblocks * QSC_KECCAK_256_RATE;
			outlen -= nblocks * QSC_KECCAK_256_RATE;
		}

		if (outlen != 0U)
		{
			if (inplen <= 256U)
			{
				keccakx4_squeezetail(state, out0, out1, out2, out3, outlen);
			}
			else
			{
				qsc_keccakx4_squeezeblocks(state, qsc_keccak_rate_256, t[0U], t[1U], t[2U], t[3U], 1U);
	
				for (size_t i = 0U; i < outlen; ++i)
				{
					out0[i] = t[0U][i];
					out1[i] = t[1U][i];
					out2[i] = t[2U][i];
					out3[i] = t[3U][i];
				}
				qsc_memutils_secure_erase(t, sizeof(t));
			}
		}

		qsc_memutils_secure_erase(state, sizeof(state));

#elif defined(QSC_SYSTEM_ARM_INTRINSICS)

		keccak_shake_x2_arm(qsc_keccak_rate_256, out0, out1, outlen, inp0, inp1, inplen);
		keccak_shake_x2_arm(qsc_keccak_rate_256, out2, out3, outlen, inp2, inp3, inplen);

#else

		qsc_shake256_compute(out0, outlen, inp0, inplen);
		qsc_shake256_compute(out1, outlen, inp1, inplen);
		qsc_shake256_compute(out2, outlen, inp2, inplen);
		qsc_shake256_compute(out3, outlen, inp3, inplen);

#endif
	}
}

void qsc_shake_512x4(uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3, size_t outlen,
	const uint8_t* inp0, const uint8_t* inp1, const uint8_t* inp2, const uint8_t* inp3, size_t inplen)
{
	QSC_ASSERT(inp0 != NULL);
	QSC_ASSERT(inp1 != NULL);
	QSC_ASSERT(inp2 != NULL);
	QSC_ASSERT(inp3 != NULL);
	QSC_ASSERT(out0 != NULL);
	QSC_ASSERT(out1 != NULL);
	QSC_ASSERT(out2 != NULL);
	QSC_ASSERT(out3 != NULL);

	if (out0 != NULL && out1 != NULL && out2 != NULL && out3 != NULL && inp0 != NULL && inp1 != NULL && inp2 != NULL && inp3 != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX2)

		size_t nblocks = outlen / QSC_KECCAK_512_RATE;
		QSC_ALIGN(32) uint8_t t[4U][QSC_KECCAK_512_RATE] = { 0U };
		__m256i state[QSC_KECCAK_STATE_SIZE] = { 0U };

		qsc_keccakx4_absorb(state, qsc_keccak_rate_512, inp0, inp1, inp2, inp3, inplen, QSC_KECCAK_SHAKE_DOMAIN_ID);

		if (outlen >= QSC_KECCAK_512_RATE)
		{
			qsc_keccakx4_squeezeblocks(state, qsc_keccak_rate_512, out0, out1, out2, out3, nblocks);

			out0 += nblocks * QSC_KECCAK_512_RATE;
			out1 += nblocks * QSC_KECCAK_512_RATE;
			out2 += nblocks * QSC_KECCAK_512_RATE;
			out3 += nblocks * QSC_KECCAK_512_RATE;
			outlen -= nblocks * QSC_KECCAK_512_RATE;
		}

		if (outlen != 0U)
		{
			if (inplen <= 256U)
			{
				keccakx4_squeezetail(state, out0, out1, out2, out3, outlen);
			}
			else
			{
				qsc_keccakx4_squeezeblocks(state, qsc_keccak_rate_512, t[0U], t[1U], t[2U], t[3U], 1U);
	
				for (size_t i = 0U; i < outlen; ++i)
				{
					out0[i] = t[0U][i];
					out1[i] = t[1U][i];
					out2[i] = t[2U][i];
					out3[i] = t[3U][i];
				}
				qsc_memutils_secure_erase(t, sizeof(t));
			}
		}

		qsc_memutils_secure_erase(state, sizeof(state));

#elif defined(QSC_SYSTEM_ARM_INTRINSICS)

		keccak_shake_x2_arm(qsc_keccak_rate_512, out0, out1, outlen, inp0, inp1, inplen);
		keccak_shake_x2_arm(qsc_keccak_rate_512, out2, out3, outlen, inp2, inp3, inplen);

#else

		qsc_shake512_compute(out0, outlen, inp0, inplen);
		qsc_shake512_compute(out1, outlen, inp1, inplen);
		qsc_shake512_compute(out2, outlen, inp2, inplen);
		qsc_shake512_compute(out3, outlen, inp3, inplen);

#endif
	}
}

/* parallel shake x8 */

void qsc_shake_128x8(uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3,
	uint8_t* out4, uint8_t* out5, uint8_t* out6, uint8_t* out7, size_t outlen,
	const uint8_t* inp0, const uint8_t* inp1, const uint8_t* inp2, const uint8_t* inp3,
	const uint8_t* inp4, const uint8_t* inp5, const uint8_t* inp6, const uint8_t* inp7, size_t inplen)
{
	QSC_ASSERT(inp0 != NULL);
	QSC_ASSERT(inp1 != NULL);
	QSC_ASSERT(inp2 != NULL);
	QSC_ASSERT(inp3 != NULL);
	QSC_ASSERT(inp4 != NULL);
	QSC_ASSERT(inp5 != NULL);
	QSC_ASSERT(inp6 != NULL);
	QSC_ASSERT(inp7 != NULL);
	QSC_ASSERT(out0 != NULL);
	QSC_ASSERT(out1 != NULL);
	QSC_ASSERT(out2 != NULL);
	QSC_ASSERT(out3 != NULL);
	QSC_ASSERT(out4 != NULL);
	QSC_ASSERT(out5 != NULL);
	QSC_ASSERT(out6 != NULL);
	QSC_ASSERT(out7 != NULL);

	if (out0 != NULL && out1 != NULL && out2 != NULL && out3 != NULL && out4 != NULL && out5 != NULL && out6 != NULL && out7 != NULL &&
		inp0 != NULL && inp1 != NULL && inp2 != NULL && inp3 != NULL && inp4 != NULL && inp5 != NULL && inp6 != NULL && inp7 != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX512)

		size_t nblocks = outlen / QSC_KECCAK_128_RATE;
		QSC_ALIGN(64) uint8_t t[8U][QSC_KECCAK_128_RATE] = { 0U };
		__m512i state[QSC_KECCAK_STATE_SIZE] = { 0U };

		qsc_keccakx8_absorb(state, qsc_keccak_rate_128, inp0, inp1, inp2, inp3, inp4, inp5, inp6, inp7, inplen, QSC_KECCAK_SHAKE_DOMAIN_ID);

		if (outlen >= QSC_KECCAK_128_RATE)
		{
			qsc_keccakx8_squeezeblocks(state, qsc_keccak_rate_128, out0, out1, out2, out3, out4, out5, out6, out7, nblocks);

			out0 += nblocks * QSC_KECCAK_128_RATE;
			out1 += nblocks * QSC_KECCAK_128_RATE;
			out2 += nblocks * QSC_KECCAK_128_RATE;
			out3 += nblocks * QSC_KECCAK_128_RATE;
			out4 += nblocks * QSC_KECCAK_128_RATE;
			out5 += nblocks * QSC_KECCAK_128_RATE;
			out6 += nblocks * QSC_KECCAK_128_RATE;
			out7 += nblocks * QSC_KECCAK_128_RATE;
			outlen -= nblocks * QSC_KECCAK_128_RATE;
		}

		if (outlen != 0U)
		{
			if (inplen <= 256U)
			{
				keccakx8_squeezetail(state, out0, out1, out2, out3, out4, out5, out6, out7, outlen);
			}
			else
			{
				qsc_keccakx8_squeezeblocks(state, qsc_keccak_rate_128, t[0U], t[1U], t[2U], t[3U], t[4U], t[5U], t[6U], t[7U], 1U);
	
				for (size_t i = 0U; i < outlen; ++i)
				{
					out0[i] = t[0U][i];
					out1[i] = t[1U][i];
					out2[i] = t[2U][i];
					out3[i] = t[3U][i];
					out4[i] = t[4U][i];
					out5[i] = t[5U][i];
					out6[i] = t[6U][i];
					out7[i] = t[7U][i];
				}
				qsc_memutils_secure_erase(t, sizeof(t));
			}
		}

		qsc_memutils_secure_erase(state, sizeof(state));

#elif defined(QSC_SYSTEM_HAS_AVX2) || defined(QSC_SYSTEM_ARM_INTRINSICS)

		qsc_shake_128x4(out0, out1, out2, out3, outlen, inp0, inp1, inp2, inp3, inplen);
		qsc_shake_128x4(out4, out5, out6, out7, outlen, inp4, inp5, inp6, inp7, inplen);

#else

		qsc_shake128_compute(out0, outlen, inp0, inplen);
		qsc_shake128_compute(out1, outlen, inp1, inplen);
		qsc_shake128_compute(out2, outlen, inp2, inplen);
		qsc_shake128_compute(out3, outlen, inp3, inplen);
		qsc_shake128_compute(out4, outlen, inp4, inplen);
		qsc_shake128_compute(out5, outlen, inp5, inplen);
		qsc_shake128_compute(out6, outlen, inp6, inplen);
		qsc_shake128_compute(out7, outlen, inp7, inplen);

#endif
	}
}

void qsc_shake_256x8(uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3,
	uint8_t* out4, uint8_t* out5, uint8_t* out6, uint8_t* out7, size_t outlen,
	const uint8_t* inp0, const uint8_t* inp1, const uint8_t* inp2, const uint8_t* inp3,
	const uint8_t* inp4, const uint8_t* inp5, const uint8_t* inp6, const uint8_t* inp7, size_t inplen)
{
	QSC_ASSERT(inp0 != NULL);
	QSC_ASSERT(inp1 != NULL);
	QSC_ASSERT(inp2 != NULL);
	QSC_ASSERT(inp3 != NULL);
	QSC_ASSERT(inp4 != NULL);
	QSC_ASSERT(inp5 != NULL);
	QSC_ASSERT(inp6 != NULL);
	QSC_ASSERT(inp7 != NULL);
	QSC_ASSERT(out0 != NULL);
	QSC_ASSERT(out1 != NULL);
	QSC_ASSERT(out2 != NULL);
	QSC_ASSERT(out3 != NULL);
	QSC_ASSERT(out4 != NULL);
	QSC_ASSERT(out5 != NULL);
	QSC_ASSERT(out6 != NULL);
	QSC_ASSERT(out7 != NULL);

	if (out0 != NULL && out1 != NULL && out2 != NULL && out3 != NULL && out4 != NULL && out5 != NULL && out6 != NULL && out7 != NULL &&
		inp0 != NULL && inp1 != NULL && inp2 != NULL && inp3 != NULL && inp4 != NULL && inp5 != NULL && inp6 != NULL && inp7 != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX512)

		size_t nblocks = outlen / QSC_KECCAK_256_RATE;
		QSC_ALIGN(64) uint8_t t[8U][QSC_KECCAK_256_RATE] = { 0U };
		__m512i state[QSC_KECCAK_STATE_SIZE] = { 0U };

		qsc_keccakx8_absorb(state, qsc_keccak_rate_256, inp0, inp1, inp2, inp3, inp4, inp5, inp6, inp7, inplen, QSC_KECCAK_SHAKE_DOMAIN_ID);

		if (outlen >= QSC_KECCAK_256_RATE)
		{
			qsc_keccakx8_squeezeblocks(state, qsc_keccak_rate_256, out0, out1, out2, out3, out4, out5, out6, out7, nblocks);

			out0 += nblocks * QSC_KECCAK_256_RATE;
			out1 += nblocks * QSC_KECCAK_256_RATE;
			out2 += nblocks * QSC_KECCAK_256_RATE;
			out3 += nblocks * QSC_KECCAK_256_RATE;
			out4 += nblocks * QSC_KECCAK_256_RATE;
			out5 += nblocks * QSC_KECCAK_256_RATE;
			out6 += nblocks * QSC_KECCAK_256_RATE;
			out7 += nblocks * QSC_KECCAK_256_RATE;
			outlen -= nblocks * QSC_KECCAK_256_RATE;
		}

		if (outlen != 0U)
		{
			if (inplen <= 256U)
			{
				keccakx8_squeezetail(state, out0, out1, out2, out3, out4, out5, out6, out7, outlen);
			}
			else
			{
				qsc_keccakx8_squeezeblocks(state, qsc_keccak_rate_256, t[0U], t[1U], t[2U], t[3U], t[4U], t[5U], t[6U], t[7U], 1U);
	
				for (size_t i = 0U; i < outlen; ++i)
				{
					out0[i] = t[0U][i];
					out1[i] = t[1U][i];
					out2[i] = t[2U][i];
					out3[i] = t[3U][i];
					out4[i] = t[4U][i];
					out5[i] = t[5U][i];
					out6[i] = t[6U][i];
					out7[i] = t[7U][i];
				}
				qsc_memutils_secure_erase(t, sizeof(t));
			}
		}

		qsc_memutils_secure_erase(state, sizeof(state));

#elif defined(QSC_SYSTEM_HAS_AVX2) || defined(QSC_SYSTEM_ARM_INTRINSICS)

		qsc_shake_256x4(out0, out1, out2, out3, outlen, inp0, inp1, inp2, inp3, inplen);
		qsc_shake_256x4(out4, out5, out6, out7, outlen, inp4, inp5, inp6, inp7, inplen);

#else

		qsc_shake256_compute(out0, outlen, inp0, inplen);
		qsc_shake256_compute(out1, outlen, inp1, inplen);
		qsc_shake256_compute(out2, outlen, inp2, inplen);
		qsc_shake256_compute(out3, outlen, inp3, inplen);
		qsc_shake256_compute(out4, outlen, inp4, inplen);
		qsc_shake256_compute(out5, outlen, inp5, inplen);
		qsc_shake256_compute(out6, outlen, inp6, inplen);
		qsc_shake256_compute(out7, outlen, inp7, inplen);

#endif
	}
}

void qsc_shake_512x8(uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3,
	uint8_t* out4, uint8_t* out5, uint8_t* out6, uint8_t* out7, size_t outlen,
	const uint8_t* inp0, const uint8_t* inp1, const uint8_t* inp2, const uint8_t* inp3,
	const uint8_t* inp4, const uint8_t* inp5, const uint8_t* inp6, const uint8_t* inp7, size_t inplen)
{
	QSC_ASSERT(inp0 != NULL);
	QSC_ASSERT(inp1 != NULL);
	QSC_ASSERT(inp2 != NULL);
	QSC_ASSERT(inp3 != NULL);
	QSC_ASSERT(inp4 != NULL);
	QSC_ASSERT(inp5 != NULL);
	QSC_ASSERT(inp6 != NULL);
	QSC_ASSERT(inp7 != NULL);
	QSC_ASSERT(out0 != NULL);
	QSC_ASSERT(out1 != NULL);
	QSC_ASSERT(out2 != NULL);
	QSC_ASSERT(out3 != NULL);
	QSC_ASSERT(out4 != NULL);
	QSC_ASSERT(out5 != NULL);
	QSC_ASSERT(out6 != NULL);
	QSC_ASSERT(out7 != NULL);

	if (out0 != NULL && out1 != NULL && out2 != NULL && out3 != NULL && out4 != NULL && out5 != NULL && out6 != NULL && out7 != NULL &&
		inp0 != NULL && inp1 != NULL && inp2 != NULL && inp3 != NULL && inp4 != NULL && inp5 != NULL && inp6 != NULL && inp7 != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX512)

		size_t nblocks = outlen / QSC_KECCAK_512_RATE;
		QSC_ALIGN(64) uint8_t t[8U][QSC_KECCAK_512_RATE] = { 0U };
		__m512i state[QSC_KECCAK_STATE_SIZE] = { 0U };

		qsc_keccakx8_absorb(state, qsc_keccak_rate_512, inp0, inp1, inp2, inp3, inp4, inp5, inp6, inp7, inplen, QSC_KECCAK_SHAKE_DOMAIN_ID);

		if (outlen >= QSC_KECCAK_512_RATE)
		{
			qsc_keccakx8_squeezeblocks(state, qsc_keccak_rate_512, out0, out1, out2, out3, out4, out5, out6, out7, nblocks);

			out0 += nblocks * QSC_KECCAK_512_RATE;
			out1 += nblocks * QSC_KECCAK_512_RATE;
			out2 += nblocks * QSC_KECCAK_512_RATE;
			out3 += nblocks * QSC_KECCAK_512_RATE;
			out4 += nblocks * QSC_KECCAK_512_RATE;
			out5 += nblocks * QSC_KECCAK_512_RATE;
			out6 += nblocks * QSC_KECCAK_512_RATE;
			out7 += nblocks * QSC_KECCAK_512_RATE;
			outlen -= nblocks * QSC_KECCAK_512_RATE;
		}

		if (outlen != 0U)
		{
			if (inplen <= 256U)
			{
				keccakx8_squeezetail(state, out0, out1, out2, out3, out4, out5, out6, out7, outlen);
			}
			else
			{
				qsc_keccakx8_squeezeblocks(state, qsc_keccak_rate_512, t[0U], t[1U], t[2U], t[3U], t[4U], t[5U], t[6U], t[7U], 1U);
	
				for (size_t i = 0U; i < outlen; ++i)
				{
					out0[i] = t[0U][i];
					out1[i] = t[1U][i];
					out2[i] = t[2U][i];
					out3[i] = t[3U][i];
					out4[i] = t[4U][i];
					out5[i] = t[5U][i];
					out6[i] = t[6U][i];
					out7[i] = t[7U][i];
				}
				qsc_memutils_secure_erase(t, sizeof(t));
			}
		}

		qsc_memutils_secure_erase(state, sizeof(state));

#elif defined(QSC_SYSTEM_HAS_AVX2) || defined(QSC_SYSTEM_ARM_INTRINSICS)

		qsc_shake_512x4(out0, out1, out2, out3, outlen, inp0, inp1, inp2, inp3, inplen);
		qsc_shake_512x4(out4, out5, out6, out7, outlen, inp4, inp5, inp6, inp7, inplen);

#else

		qsc_shake512_compute(out0, outlen, inp0, inplen);
		qsc_shake512_compute(out1, outlen, inp1, inplen);
		qsc_shake512_compute(out2, outlen, inp2, inplen);
		qsc_shake512_compute(out3, outlen, inp3, inplen);
		qsc_shake512_compute(out4, outlen, inp4, inplen);
		qsc_shake512_compute(out5, outlen, inp5, inplen);
		qsc_shake512_compute(out6, outlen, inp6, inplen);
		qsc_shake512_compute(out7, outlen, inp7, inplen);

#endif
	}
}

/* parallel kmac x4 */

#if defined(QSC_SYSTEM_HAS_AVX2)

static void kmacx4_fast_absorb(__m256i state[QSC_KECCAK_STATE_SIZE], const uint8_t* inp0, const uint8_t* inp1, const uint8_t* inp2, const uint8_t* inp3, size_t inplen)
{
	/* XOR complete words into 4 KMAC states */
	__m256i t;
	uint64_t v0;
	uint64_t v1;
	uint64_t v2;
	uint64_t v3;
	size_t pos;

	pos = 0U;

	for (size_t i = 0U; i < inplen / sizeof(uint64_t); ++i)
	{
		v0 = keccak_load64(inp0 + pos);
		v1 = keccak_load64(inp1 + pos);
		v2 = keccak_load64(inp2 + pos);
		v3 = keccak_load64(inp3 + pos);

		t = _mm256_set_epi64x(v3, v2, v1, v0);
		state[i] = _mm256_xor_si256(state[i], t);
		pos += 8U;
	}
}

static void kmacx4_customize(__m256i state[QSC_KECCAK_STATE_SIZE], qsc_keccak_rate rate,
	const uint8_t* key0, const uint8_t* key1, const uint8_t* key2, const uint8_t* key3, size_t keylen,
	const uint8_t* cst0, const uint8_t* cst1, const uint8_t* cst2, const uint8_t* cst3, size_t cstlen,
	const uint8_t* name, size_t nmelen)
{
	/* absorb SP 800-185 name/customization and key bytepads for 4 lanes */
	QSC_ALIGN(32) uint8_t pad[4U][QSC_KECCAK_STATE_BYTE_SIZE] = { 0U };
	size_t oft;
	size_t i;

	/* stage 1: name + custom */

	oft = keccak_left_encode(pad[0U], (size_t)rate);
	oft += keccak_left_encode((pad[0U] + oft), nmelen * 8U);

	for (i = 0U; i < nmelen; ++i)
	{
		pad[0U][oft + i] = name[i];
	}

	oft += nmelen;
	oft += keccak_left_encode((pad[0U] + oft), cstlen * 8U);
	qsc_memutils_copy(pad[1U], pad[0U], oft);
	qsc_memutils_copy(pad[2U], pad[0U], oft);
	qsc_memutils_copy(pad[3U], pad[0U], oft);

	for (i = 0U; i < cstlen; ++i)
	{
		if (oft == (size_t)rate)
		{
			kmacx4_fast_absorb(state, pad[0U], pad[1U], pad[2U], pad[3U], (size_t)rate);
			qsc_keccak_permute_p4x1600(state, QSC_KECCAK_PERMUTATION_ROUNDS);
			oft = 0U;
		}

		pad[0U][oft] = cst0[i];
		pad[1U][oft] = cst1[i];
		pad[2U][oft] = cst2[i];
		pad[3U][oft] = cst3[i];
		++oft;
	}

	if (oft < (size_t)rate)
	{
		qsc_memutils_clear(pad[0U] + oft, (size_t)rate - oft);
		qsc_memutils_clear(pad[1U] + oft, (size_t)rate - oft);
		qsc_memutils_clear(pad[2U] + oft, (size_t)rate - oft);
		qsc_memutils_clear(pad[3U] + oft, (size_t)rate - oft);
	}

	kmacx4_fast_absorb(state, pad[0U], pad[1U], pad[2U], pad[3U], oft + ((sizeof(uint64_t) - oft % sizeof(uint64_t)) % sizeof(uint64_t)));
	qsc_keccak_permute_p4x1600(state, QSC_KECCAK_PERMUTATION_ROUNDS);

	/* stage 2: key */

	qsc_memutils_clear(pad, sizeof(pad));


	oft = keccak_left_encode(pad[0U], (size_t)rate);
	oft += keccak_left_encode((pad[0U] + oft), keylen * 8U);
	qsc_memutils_copy(pad[1U], pad[0U], oft);
	qsc_memutils_copy(pad[2U], pad[0U], oft);
	qsc_memutils_copy(pad[3U], pad[0U], oft);

	for (i = 0U; i < keylen; ++i)
	{
		if (oft == (size_t)rate)
		{
			kmacx4_fast_absorb(state, pad[0U], pad[1U], pad[2U], pad[3U], (size_t)rate);
			qsc_keccak_permute_p4x1600(state, QSC_KECCAK_PERMUTATION_ROUNDS);
			oft = 0U;
		}

		pad[0U][oft] = key0[i];
		pad[1U][oft] = key1[i];
		pad[2U][oft] = key2[i];
		pad[3U][oft] = key3[i];
		++oft;
	}


	if (oft < (size_t)rate)
	{
		qsc_memutils_clear(pad[0U] + oft, (size_t)rate - oft);
		qsc_memutils_clear(pad[1U] + oft, (size_t)rate - oft);
		qsc_memutils_clear(pad[2U] + oft, (size_t)rate - oft);
		qsc_memutils_clear(pad[3U] + oft, (size_t)rate - oft);
	}

	kmacx4_fast_absorb(state, pad[0U], pad[1U], pad[2U], pad[3U], oft + ((sizeof(uint64_t) - oft % sizeof(uint64_t)) % sizeof(uint64_t)));
	qsc_keccak_permute_p4x1600(state, QSC_KECCAK_PERMUTATION_ROUNDS);

	qsc_memutils_secure_erase(pad, sizeof(pad));
}

static void kmacx4_finalize(__m256i state[QSC_KECCAK_STATE_SIZE], qsc_keccak_rate rate,
	const uint8_t* msg0, const uint8_t* msg1, const uint8_t* msg2, const uint8_t* msg3, size_t msglen,
	uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3, size_t outlen)
{
	/* append right_encode and padding, then squeeze 4 KMAC outputs */
	QSC_ALIGN(32) uint8_t tmps[4U][QSC_KECCAK_STATE_BYTE_SIZE] = { 0U };
	QSC_ALIGN(32) uint8_t buf[sizeof(size_t) + 1U] = { 0U };
	QSC_ALIGN(32) uint8_t pad[4U][QSC_KECCAK_STATE_BYTE_SIZE] = { 0U };
	const size_t BLKCNT = outlen / (size_t)rate;
	size_t bitlen;
	size_t i;
	size_t pos;
	size_t take;

	pos = 0U;

	while (msglen >= (size_t)rate)
	{
		kmacx4_fast_absorb(state, (msg0 + pos), (msg1 + pos), (msg2 + pos), (msg3 + pos), (size_t)rate);
		qsc_keccak_permute_p4x1600(state, QSC_KECCAK_PERMUTATION_ROUNDS);
		pos += (size_t)rate;
		msglen -= (size_t)rate;
	}

	if (msglen > 0U)
	{
		qsc_memutils_copy(pad[0U], (msg0 + pos), msglen);
		qsc_memutils_copy(pad[1U], (msg1 + pos), msglen);
		qsc_memutils_copy(pad[2U], (msg2 + pos), msglen);
		qsc_memutils_copy(pad[3U], (msg3 + pos), msglen);
	}

	pos = msglen;
	bitlen = keccak_right_encode(buf, outlen * 8U);

	if (pos + bitlen >= (size_t)rate)
	{
		/* right_encode may straddle the final input block. Retain the
		 * prefix in that block before continuing into a clean block. */
		take = (size_t)rate - pos;
		qsc_memutils_copy(pad[0U] + pos, buf, take);
		qsc_memutils_copy(pad[1U] + pos, pad[0U] + pos, take);
		qsc_memutils_copy(pad[2U] + pos, pad[0U] + pos, take);
		qsc_memutils_copy(pad[3U] + pos, pad[0U] + pos, take);
		kmacx4_fast_absorb(state, pad[0U], pad[1U], pad[2U], pad[3U], (size_t)rate);
		qsc_keccak_permute_p4x1600(state, QSC_KECCAK_PERMUTATION_ROUNDS);
		qsc_memutils_clear(pad, sizeof(pad));
		bitlen -= take;
		qsc_memutils_copy(pad[0U], buf + take, bitlen);
		pos = 0U;
	}
	else
	{
		qsc_memutils_copy(pad[0U] + pos, buf, bitlen);
	}
	pad[0U][pos + bitlen] = QSC_KECCAK_KMAC_DOMAIN_ID;
	pad[0U][(size_t)rate - 1U] |= 128U;
	qsc_memutils_copy((pad[1U] + pos), (pad[0U] + pos), (size_t)rate - pos);
	qsc_memutils_copy((pad[2U] + pos), (pad[0U] + pos), (size_t)rate - pos);
	qsc_memutils_copy((pad[3U] + pos), (pad[0U] + pos), (size_t)rate - pos);

	kmacx4_fast_absorb(state, pad[0U], pad[1U], pad[2U], pad[3U], (size_t)rate);

	if (outlen > (size_t)rate)
	{
		qsc_keccakx4_squeezeblocks(state, (size_t)rate, out0, out1, out2, out3, BLKCNT);

		out0 += BLKCNT * (size_t)rate;
		out1 += BLKCNT * (size_t)rate;
		out2 += BLKCNT * (size_t)rate;
		out3 += BLKCNT * (size_t)rate;
		outlen -= BLKCNT * (size_t)rate;
	}

	if (outlen != 0U)
	{
		qsc_keccakx4_squeezeblocks(state, (size_t)rate, tmps[0U], tmps[1U], tmps[2U], tmps[3U], 1U);

		for (i = 0U; i < outlen; ++i)
		{
			out0[i] = tmps[0U][i];
			out1[i] = tmps[1U][i];
			out2[i] = tmps[2U][i];
			out3[i] = tmps[3U][i];
		}
	}

	qsc_memutils_secure_erase(tmps, sizeof(tmps));
	qsc_memutils_secure_erase(buf, sizeof(buf));
	qsc_memutils_secure_erase(pad, sizeof(pad));
}

#endif

void qsc_kmac_128x4(uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3, size_t outlen,
	const uint8_t* key0, const uint8_t* key1, const uint8_t* key2, const uint8_t* key3, size_t keylen,
	const uint8_t* cst0, const uint8_t* cst1, const uint8_t* cst2, const uint8_t* cst3, size_t cstlen,
	const uint8_t* msg0, const uint8_t* msg1, const uint8_t* msg2, const uint8_t* msg3, size_t msglen)
{
	QSC_ASSERT(key0 != NULL);
	QSC_ASSERT(key1 != NULL);
	QSC_ASSERT(key2 != NULL);
	QSC_ASSERT(key3 != NULL);
	QSC_ASSERT(msg0 != NULL);
	QSC_ASSERT(msg1 != NULL);
	QSC_ASSERT(msg2 != NULL);
	QSC_ASSERT(msg3 != NULL);
	QSC_ASSERT(out0 != NULL);
	QSC_ASSERT(out1 != NULL);
	QSC_ASSERT(out2 != NULL);
	QSC_ASSERT(out3 != NULL);

	if (outlen <= SIZE_MAX / 8U && keylen <= SIZE_MAX / 8U && cstlen <= SIZE_MAX / 8U &&
		(cstlen == 0U || (cst0 != NULL && cst1 != NULL && cst2 != NULL && cst3 != NULL)) &&
		key0 != NULL && key1 != NULL && key2 != NULL && key3 != NULL && msg0 != NULL && msg1 != NULL &&
		msg2 != NULL && msg3 != NULL && out0 != NULL && out1 != NULL && out2 != NULL && out3 != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX2)

		__m256i state[QSC_KECCAK_STATE_SIZE] = { 0U };
		QSC_ALIGN(32) const uint8_t name[] = { 0x4BU, 0x4DU, 0x41U, 0x43U };

		kmacx4_customize(state, qsc_keccak_rate_128, key0, key1, key2, key3, keylen, cst0, cst1, cst2, cst3, cstlen, name, sizeof(name));
		kmacx4_finalize(state, qsc_keccak_rate_128, msg0, msg1, msg2, msg3, msglen, out0, out1, out2, out3, outlen);

		qsc_memutils_secure_erase(state, sizeof(state));

#elif defined(QSC_SYSTEM_ARM_INTRINSICS)

		keccak_kmac_x2_arm(qsc_keccak_rate_128, out0, out1, outlen, key0, key1, keylen, cst0, cst1, cstlen, msg0, msg1, msglen);
		keccak_kmac_x2_arm(qsc_keccak_rate_128, out2, out3, outlen, key2, key3, keylen, cst2, cst3, cstlen, msg2, msg3, msglen);

#else

		qsc_kmac128_compute(out0, outlen, msg0, msglen, key0, keylen, cst0, cstlen);
		qsc_kmac128_compute(out1, outlen, msg1, msglen, key1, keylen, cst1, cstlen);
		qsc_kmac128_compute(out2, outlen, msg2, msglen, key2, keylen, cst2, cstlen);
		qsc_kmac128_compute(out3, outlen, msg3, msglen, key3, keylen, cst3, cstlen);

#endif
	}
}

void qsc_kmac_256x4(uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3, size_t outlen,
	const uint8_t* key0, const uint8_t* key1, const uint8_t* key2, const uint8_t* key3, size_t keylen,
	const uint8_t* cst0, const uint8_t* cst1, const uint8_t* cst2, const uint8_t* cst3, size_t cstlen,
	const uint8_t* msg0, const uint8_t* msg1, const uint8_t* msg2, const uint8_t* msg3, size_t msglen)
{
	QSC_ASSERT(key0 != NULL);
	QSC_ASSERT(key1 != NULL);
	QSC_ASSERT(key2 != NULL);
	QSC_ASSERT(key3 != NULL);
	QSC_ASSERT(msg0 != NULL);
	QSC_ASSERT(msg1 != NULL);
	QSC_ASSERT(msg2 != NULL);
	QSC_ASSERT(msg3 != NULL);
	QSC_ASSERT(out0 != NULL);
	QSC_ASSERT(out1 != NULL);
	QSC_ASSERT(out2 != NULL);
	QSC_ASSERT(out3 != NULL);

	if (outlen <= SIZE_MAX / 8U && keylen <= SIZE_MAX / 8U && cstlen <= SIZE_MAX / 8U &&
		(cstlen == 0U || (cst0 != NULL && cst1 != NULL && cst2 != NULL && cst3 != NULL)) &&
		key0 != NULL && key1 != NULL && key2 != NULL && key3 != NULL && msg0 != NULL && msg1 != NULL &&
		msg2 != NULL && msg3 != NULL && out0 != NULL && out1 != NULL && out2 != NULL && out3 != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX2)

		__m256i state[QSC_KECCAK_STATE_SIZE] = { 0U };
		QSC_ALIGN(32) const uint8_t name[] = { 0x4BU, 0x4DU, 0x41U, 0x43U };

		kmacx4_customize(state, qsc_keccak_rate_256, key0, key1, key2, key3, keylen, cst0, cst1, cst2, cst3, cstlen, name, sizeof(name));
		kmacx4_finalize(state, qsc_keccak_rate_256, msg0, msg1, msg2, msg3, msglen, out0, out1, out2, out3, outlen);

		qsc_memutils_secure_erase(state, sizeof(state));

#elif defined(QSC_SYSTEM_ARM_INTRINSICS)

		keccak_kmac_x2_arm(qsc_keccak_rate_256, out0, out1, outlen, key0, key1, keylen, cst0, cst1, cstlen, msg0, msg1, msglen);
		keccak_kmac_x2_arm(qsc_keccak_rate_256, out2, out3, outlen, key2, key3, keylen, cst2, cst3, cstlen, msg2, msg3, msglen);

#else

		qsc_kmac256_compute(out0, outlen, msg0, msglen, key0, keylen, cst0, cstlen);
		qsc_kmac256_compute(out1, outlen, msg1, msglen, key1, keylen, cst1, cstlen);
		qsc_kmac256_compute(out2, outlen, msg2, msglen, key2, keylen, cst2, cstlen);
		qsc_kmac256_compute(out3, outlen, msg3, msglen, key3, keylen, cst3, cstlen);

#endif
	}
}

void qsc_kmac_512x4(uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3, size_t outlen,
	const uint8_t* key0, const uint8_t* key1, const uint8_t* key2, const uint8_t* key3, size_t keylen,
	const uint8_t* cst0, const uint8_t* cst1, const uint8_t* cst2, const uint8_t* cst3, size_t cstlen,
	const uint8_t* msg0, const uint8_t* msg1, const uint8_t* msg2, const uint8_t* msg3, size_t msglen)
{
	QSC_ASSERT(key0 != NULL);
	QSC_ASSERT(key1 != NULL);
	QSC_ASSERT(key2 != NULL);
	QSC_ASSERT(key3 != NULL);
	QSC_ASSERT(msg0 != NULL);
	QSC_ASSERT(msg1 != NULL);
	QSC_ASSERT(msg2 != NULL);
	QSC_ASSERT(msg3 != NULL);
	QSC_ASSERT(out0 != NULL);
	QSC_ASSERT(out1 != NULL);
	QSC_ASSERT(out2 != NULL);
	QSC_ASSERT(out3 != NULL);

	if (outlen <= SIZE_MAX / 8U && keylen <= SIZE_MAX / 8U && cstlen <= SIZE_MAX / 8U &&
		(cstlen == 0U || (cst0 != NULL && cst1 != NULL && cst2 != NULL && cst3 != NULL)) &&
		key0 != NULL && key1 != NULL && key2 != NULL && key3 != NULL && msg0 != NULL && msg1 != NULL &&
		msg2 != NULL && msg3 != NULL && out0 != NULL && out1 != NULL && out2 != NULL && out3 != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX2)

		__m256i state[QSC_KECCAK_STATE_SIZE] = { 0U };
		QSC_ALIGN(32) const uint8_t name[] = { 0x4B, 0x4D, 0x41, 0x43 };

		kmacx4_customize(state, qsc_keccak_rate_512, key0, key1, key2, key3, keylen, cst0, cst1, cst2, cst3, cstlen, name, sizeof(name));
		kmacx4_finalize(state, qsc_keccak_rate_512, msg0, msg1, msg2, msg3, msglen, out0, out1, out2, out3, outlen);

		qsc_memutils_secure_erase(state, sizeof(state));

#elif defined(QSC_SYSTEM_ARM_INTRINSICS)

		keccak_kmac_x2_arm(qsc_keccak_rate_512, out0, out1, outlen, key0, key1, keylen, cst0, cst1, cstlen, msg0, msg1, msglen);
		keccak_kmac_x2_arm(qsc_keccak_rate_512, out2, out3, outlen, key2, key3, keylen, cst2, cst3, cstlen, msg2, msg3, msglen);

#else

		qsc_kmac512_compute(out0, outlen, msg0, msglen, key0, keylen, cst0, cstlen);
		qsc_kmac512_compute(out1, outlen, msg1, msglen, key1, keylen, cst1, cstlen);
		qsc_kmac512_compute(out2, outlen, msg2, msglen, key2, keylen, cst2, cstlen);
		qsc_kmac512_compute(out3, outlen, msg3, msglen, key3, keylen, cst3, cstlen);

#endif
	}
}

/* parallel kmac x8 */

#if defined(QSC_SYSTEM_HAS_AVX512)

static void kmacx8_fast_absorb(__m512i state[QSC_KECCAK_STATE_SIZE],
	const uint8_t* inp0, const uint8_t* inp1, const uint8_t* inp2, const uint8_t* inp3,
	const uint8_t* inp4, const uint8_t* inp5, const uint8_t* inp6, const uint8_t* inp7,
	size_t inplen)
{
	/* XOR complete words into 8 KMAC states */
	__m512i t;
	uint64_t v0;
	uint64_t v1;
	uint64_t v2;
	uint64_t v3;
	uint64_t v4;
	uint64_t v5;
	uint64_t v6;
	uint64_t v7;
	size_t pos;

	pos = 0U;

	for (size_t i = 0U; i < inplen / sizeof(uint64_t); ++i)
	{
		v0 = keccak_load64((inp0 + pos));
		v1 = keccak_load64((inp1 + pos));
		v2 = keccak_load64((inp2 + pos));
		v3 = keccak_load64((inp3 + pos));
		v4 = keccak_load64((inp4 + pos));
		v5 = keccak_load64((inp5 + pos));
		v6 = keccak_load64((inp6 + pos));
		v7 = keccak_load64((inp7 + pos));

		t = _mm512_set_epi64(v7, v6, v5, v4, v3, v2, v1, v0);
		state[i] = _mm512_xor_si512(state[i], t);
		pos += 8U;
	}
}

static void kmacx8_customize(__m512i state[QSC_KECCAK_STATE_SIZE], qsc_keccak_rate rate,
	const uint8_t* key0, const uint8_t* key1, const uint8_t* key2, const uint8_t* key3,
	const uint8_t* key4, const uint8_t* key5, const uint8_t* key6, const uint8_t* key7, size_t keylen,
	const uint8_t* cst0, const uint8_t* cst1, const uint8_t* cst2, const uint8_t* cst3,
	const uint8_t* cst4, const uint8_t* cst5, const uint8_t* cst6, const uint8_t* cst7, size_t cstlen,
	const uint8_t* name, size_t nmelen)
{
	/* absorb SP 800-185 name/customization and key bytepads for 8 lanes */
	QSC_ALIGN(64) uint8_t pad[8U][QSC_KECCAK_STATE_BYTE_SIZE] = { 0U };
	size_t oft;
	size_t i;

	/* stage 1: name + custom */

	oft = keccak_left_encode(pad[0U], (size_t)rate);
	oft += keccak_left_encode((pad[0U] + oft), nmelen * 8U);

	for (i = 0U; i < nmelen; ++i)
	{
		pad[0U][oft + i] = name[i];
	}

	oft += nmelen;
	oft += keccak_left_encode((pad[0U] + oft), cstlen * 8U);
	qsc_memutils_copy(pad[1U], pad[0U], oft);
	qsc_memutils_copy(pad[2U], pad[0U], oft);
	qsc_memutils_copy(pad[3U], pad[0U], oft);
	qsc_memutils_copy(pad[4U], pad[0U], oft);
	qsc_memutils_copy(pad[5U], pad[0U], oft);
	qsc_memutils_copy(pad[6U], pad[0U], oft);
	qsc_memutils_copy(pad[7U], pad[0U], oft);

	for (i = 0U; i < cstlen; ++i)
	{
		if (oft == (size_t)rate)
		{
			kmacx8_fast_absorb(state, pad[0U], pad[1U], pad[2U], pad[3U], pad[4U], pad[5U], pad[6U], pad[7U], (size_t)rate);
			qsc_keccak_permute_p8x1600(state, QSC_KECCAK_PERMUTATION_ROUNDS);
			oft = 0U;
		}

		pad[0U][oft] = cst0[i];
		pad[1U][oft] = cst1[i];
		pad[2U][oft] = cst2[i];
		pad[3U][oft] = cst3[i];
		pad[4U][oft] = cst4[i];
		pad[5U][oft] = cst5[i];
		pad[6U][oft] = cst6[i];
		pad[7U][oft] = cst7[i];
		++oft;
	}

	if (oft < (size_t)rate)
	{
		qsc_memutils_clear(pad[0U] + oft, (size_t)rate - oft);
		qsc_memutils_clear(pad[1U] + oft, (size_t)rate - oft);
		qsc_memutils_clear(pad[2U] + oft, (size_t)rate - oft);
		qsc_memutils_clear(pad[3U] + oft, (size_t)rate - oft);
		qsc_memutils_clear(pad[4U] + oft, (size_t)rate - oft);
		qsc_memutils_clear(pad[5U] + oft, (size_t)rate - oft);
		qsc_memutils_clear(pad[6U] + oft, (size_t)rate - oft);
		qsc_memutils_clear(pad[7U] + oft, (size_t)rate - oft);
	}

	kmacx8_fast_absorb(state, pad[0U], pad[1U], pad[2U], pad[3U], pad[4U], pad[5U], pad[6U], pad[7U], oft + ((sizeof(uint64_t) - oft % sizeof(uint64_t)) % sizeof(uint64_t)));
	qsc_keccak_permute_p8x1600(state, QSC_KECCAK_PERMUTATION_ROUNDS);

	/* stage 2: key */

	qsc_memutils_clear(pad, sizeof(pad));


	oft = keccak_left_encode(pad[0U], (size_t)rate);
	oft += keccak_left_encode((pad[0U] + oft), keylen * 8U);
	qsc_memutils_copy(pad[1U], pad[0U], oft);
	qsc_memutils_copy(pad[2U], pad[0U], oft);
	qsc_memutils_copy(pad[3U], pad[0U], oft);
	qsc_memutils_copy(pad[4U], pad[0U], oft);
	qsc_memutils_copy(pad[5U], pad[0U], oft);
	qsc_memutils_copy(pad[6U], pad[0U], oft);
	qsc_memutils_copy(pad[7U], pad[0U], oft);

	for (i = 0U; i < keylen; ++i)
	{
		if (oft == (size_t)rate)
		{
			kmacx8_fast_absorb(state, pad[0U], pad[1U], pad[2U], pad[3U], pad[4U], pad[5U], pad[6U], pad[7U], rate);
			qsc_keccak_permute_p8x1600(state, QSC_KECCAK_PERMUTATION_ROUNDS);
			oft = 0U;
		}

		pad[0U][oft] = key0[i];
		pad[1U][oft] = key1[i];
		pad[2U][oft] = key2[i];
		pad[3U][oft] = key3[i];
		pad[4U][oft] = key4[i];
		pad[5U][oft] = key5[i];
		pad[6U][oft] = key6[i];
		pad[7U][oft] = key7[i];
		++oft;
	}

	if (oft < (size_t)rate)
	{
		qsc_memutils_clear(pad[0U] + oft, (size_t)rate - oft);
		qsc_memutils_clear(pad[1U] + oft, (size_t)rate - oft);
		qsc_memutils_clear(pad[2U] + oft, (size_t)rate - oft);
		qsc_memutils_clear(pad[3U] + oft, (size_t)rate - oft);
		qsc_memutils_clear(pad[4U] + oft, (size_t)rate - oft);
		qsc_memutils_clear(pad[5U] + oft, (size_t)rate - oft);
		qsc_memutils_clear(pad[6U] + oft, (size_t)rate - oft);
		qsc_memutils_clear(pad[7U] + oft, (size_t)rate - oft);
	}

	kmacx8_fast_absorb(state, pad[0U], pad[1U], pad[2U], pad[3U], pad[4U], pad[5U], pad[6U], pad[7U], oft + ((sizeof(uint64_t) - oft % sizeof(uint64_t)) % sizeof(uint64_t)));
	qsc_keccak_permute_p8x1600(state, QSC_KECCAK_PERMUTATION_ROUNDS);

	qsc_memutils_secure_erase(pad, sizeof(pad));
}

static void kmacx8_finalize(__m512i state[QSC_KECCAK_STATE_SIZE], qsc_keccak_rate rate,
	const uint8_t* msg0, const uint8_t* msg1, const uint8_t* msg2, const uint8_t* msg3,
	const uint8_t* msg4, const uint8_t* msg5, const uint8_t* msg6, const uint8_t* msg7, size_t msglen,
	uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3,
	uint8_t* out4, uint8_t* out5, uint8_t* out6, uint8_t* out7, size_t outlen)
{
	/* append right_encode and padding, then squeeze 8 KMAC outputs */
	QSC_ALIGN(64) uint8_t tmps[8U][QSC_KECCAK_STATE_BYTE_SIZE] = { 0U };
	QSC_ALIGN(64) uint8_t buf[sizeof(size_t) + 1U] = { 0U };
	QSC_ALIGN(64) uint8_t pad[8U][QSC_KECCAK_STATE_BYTE_SIZE] = { 0U };
	const size_t BLKCNT = outlen / (size_t)rate;
	size_t bitlen;
	size_t i;
	size_t pos;
	size_t take;

	pos = 0U;

	while (msglen >= (size_t)rate)
	{
		kmacx8_fast_absorb(state, (msg0 + pos), (msg1 + pos), (msg2 + pos), (msg3 + pos),
			(msg4 + pos), (msg5 + pos), (msg6 + pos), (msg7 + pos), (size_t)rate);

		qsc_keccak_permute_p8x1600(state, QSC_KECCAK_PERMUTATION_ROUNDS);
		pos += (size_t)rate;
		msglen -= (size_t)rate;
	}

	if (msglen > 0U)
	{
		qsc_memutils_copy(pad[0U], (msg0 + pos), msglen);
		qsc_memutils_copy(pad[1U], (msg1 + pos), msglen);
		qsc_memutils_copy(pad[2U], (msg2 + pos), msglen);
		qsc_memutils_copy(pad[3U], (msg3 + pos), msglen);
		qsc_memutils_copy(pad[4U], (msg4 + pos), msglen);
		qsc_memutils_copy(pad[5U], (msg5 + pos), msglen);
		qsc_memutils_copy(pad[6U], (msg6 + pos), msglen);
		qsc_memutils_copy(pad[7U], (msg7 + pos), msglen);
	}

	pos = msglen;
	bitlen = keccak_right_encode(buf, outlen * 8U);

	if (pos + bitlen >= (size_t)rate)
	{
		/* right_encode may straddle the final input block. Retain the
		 * prefix in that block before continuing into a clean block. */
		take = (size_t)rate - pos;
		qsc_memutils_copy(pad[0U] + pos, buf, take);
		qsc_memutils_copy(pad[1U] + pos, pad[0U] + pos, take);
		qsc_memutils_copy(pad[2U] + pos, pad[0U] + pos, take);
		qsc_memutils_copy(pad[3U] + pos, pad[0U] + pos, take);
		qsc_memutils_copy(pad[4U] + pos, pad[0U] + pos, take);
		qsc_memutils_copy(pad[5U] + pos, pad[0U] + pos, take);
		qsc_memutils_copy(pad[6U] + pos, pad[0U] + pos, take);
		qsc_memutils_copy(pad[7U] + pos, pad[0U] + pos, take);
		kmacx8_fast_absorb(state, pad[0U], pad[1U], pad[2U], pad[3U], pad[4U], pad[5U], pad[6U], pad[7U], (size_t)rate);
		qsc_keccak_permute_p8x1600(state, QSC_KECCAK_PERMUTATION_ROUNDS);
		qsc_memutils_clear(pad, sizeof(pad));
		bitlen -= take;
		qsc_memutils_copy(pad[0U], buf + take, bitlen);
		pos = 0U;
	}
	else
	{
		qsc_memutils_copy(pad[0U] + pos, buf, bitlen);
	}
	pad[0U][pos + bitlen] = QSC_KECCAK_KMAC_DOMAIN_ID;
	pad[0U][(size_t)rate - 1U] |= 128U;

	qsc_memutils_copy((pad[1U] + pos), (pad[0U] + pos), (size_t)rate - pos);
	qsc_memutils_copy((pad[2U] + pos), (pad[0U] + pos), (size_t)rate - pos);
	qsc_memutils_copy((pad[3U] + pos), (pad[0U] + pos), (size_t)rate - pos);
	qsc_memutils_copy((pad[4U] + pos), (pad[0U] + pos), (size_t)rate - pos);
	qsc_memutils_copy((pad[5U] + pos), (pad[0U] + pos), (size_t)rate - pos);
	qsc_memutils_copy((pad[6U] + pos), (pad[0U] + pos), (size_t)rate - pos);
	qsc_memutils_copy((pad[7U] + pos), (pad[0U] + pos), (size_t)rate - pos);

	kmacx8_fast_absorb(state, pad[0U], pad[1U], pad[2U], pad[3U], pad[4U], pad[5U], pad[6U], pad[7U], (size_t)rate);

	if (outlen > (size_t)rate)
	{
		qsc_keccakx8_squeezeblocks(state, rate, out0, out1, out2, out3, out4, out5, out6, out7, BLKCNT);

		out0 += BLKCNT * (size_t)rate;
		out1 += BLKCNT * (size_t)rate;
		out2 += BLKCNT * (size_t)rate;
		out3 += BLKCNT * (size_t)rate;
		out4 += BLKCNT * (size_t)rate;
		out5 += BLKCNT * (size_t)rate;
		out6 += BLKCNT * (size_t)rate;
		out7 += BLKCNT * (size_t)rate;
		outlen -= BLKCNT * (size_t)rate;
	}

	if (outlen != 0U)
	{
		qsc_keccakx8_squeezeblocks(state, rate, tmps[0U], tmps[1U], tmps[2U], tmps[3U], tmps[4U], tmps[5U], tmps[6U], tmps[7U], 1U);

		for (i = 0U; i < outlen; ++i)
		{
			out0[i] = tmps[0U][i];
			out1[i] = tmps[1U][i];
			out2[i] = tmps[2U][i];
			out3[i] = tmps[3U][i];
			out4[i] = tmps[4U][i];
			out5[i] = tmps[5U][i];
			out6[i] = tmps[6U][i];
			out7[i] = tmps[7U][i];
		}
	}

	qsc_memutils_secure_erase(tmps, sizeof(tmps));
	qsc_memutils_secure_erase(buf, sizeof(buf));
	qsc_memutils_secure_erase(pad, sizeof(pad));
}

#endif

void qsc_kmac_128x8(uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3,
	uint8_t* out4, uint8_t* out5, uint8_t* out6, uint8_t* out7, size_t outlen,
	const uint8_t* key0, const uint8_t* key1, const uint8_t* key2, const uint8_t* key3,
	const uint8_t* key4, const uint8_t* key5, const uint8_t* key6, const uint8_t* key7, size_t keylen,
	const uint8_t* cst0, const uint8_t* cst1, const uint8_t* cst2, const uint8_t* cst3,
	const uint8_t* cst4, const uint8_t* cst5, const uint8_t* cst6, const uint8_t* cst7, size_t cstlen,
	const uint8_t* msg0, const uint8_t* msg1, const uint8_t* msg2, const uint8_t* msg3,
	const uint8_t* msg4, const uint8_t* msg5, const uint8_t* msg6, const uint8_t* msg7, size_t msglen)
{
	QSC_ASSERT(key0 != NULL);
	QSC_ASSERT(key1 != NULL);
	QSC_ASSERT(key2 != NULL);
	QSC_ASSERT(key3 != NULL);
	QSC_ASSERT(key4 != NULL);
	QSC_ASSERT(key5 != NULL);
	QSC_ASSERT(key6 != NULL);
	QSC_ASSERT(key7 != NULL);
	QSC_ASSERT(msg0 != NULL);
	QSC_ASSERT(msg1 != NULL);
	QSC_ASSERT(msg2 != NULL);
	QSC_ASSERT(msg3 != NULL);
	QSC_ASSERT(msg4 != NULL);
	QSC_ASSERT(msg5 != NULL);
	QSC_ASSERT(msg6 != NULL);
	QSC_ASSERT(msg7 != NULL);
	QSC_ASSERT(out0 != NULL);
	QSC_ASSERT(out1 != NULL);
	QSC_ASSERT(out2 != NULL);
	QSC_ASSERT(out3 != NULL);
	QSC_ASSERT(out4 != NULL);
	QSC_ASSERT(out5 != NULL);
	QSC_ASSERT(out6 != NULL);
	QSC_ASSERT(out7 != NULL);

	if (outlen <= SIZE_MAX / 8U && keylen <= SIZE_MAX / 8U && cstlen <= SIZE_MAX / 8U &&
		(cstlen == 0U || (cst0 != NULL && cst1 != NULL && cst2 != NULL && cst3 != NULL && cst4 != NULL && cst5 != NULL && cst6 != NULL && cst7 != NULL)) &&
		key0 != NULL && key1 != NULL && key2 != NULL && key3 != NULL && key4 != NULL && key5 != NULL && key6 != NULL && key7 != NULL &&
		msg0 != NULL && msg1 != NULL && msg2 != NULL && msg3 != NULL && msg4 != NULL && msg5 != NULL && msg6 != NULL && msg7 != NULL &&
		out0 != NULL && out1 != NULL && out2 != NULL && out3 != NULL && out4 != NULL && out5 != NULL && out6 != NULL && out7 != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX512)

		__m512i state[QSC_KECCAK_STATE_SIZE] = { 0U };
		QSC_ALIGN(64) const uint8_t name[] = { 0x4BU, 0x4DU, 0x41U, 0x43U };

		kmacx8_customize(state, qsc_keccak_rate_128, key0, key1, key2, key3, key4, key5, key6, key7, keylen,
			cst0, cst1, cst2, cst3, cst4, cst5, cst6, cst7, cstlen, name, sizeof(name));
		kmacx8_finalize(state, qsc_keccak_rate_128, msg0, msg1, msg2, msg3, msg4, msg5, msg6, msg7, msglen,
			out0, out1, out2, out3, out4, out5, out6, out7, outlen);

		qsc_memutils_secure_erase(state, sizeof(state));

#elif defined(QSC_SYSTEM_HAS_AVX2) || defined(QSC_SYSTEM_ARM_INTRINSICS)

		qsc_kmac_128x4(out0, out1, out2, out3, outlen, key0, key1, key2, key3, keylen,
			cst0, cst1, cst2, cst3, cstlen, msg0, msg1, msg2, msg3, msglen);
		qsc_kmac_128x4(out4, out5, out6, out7, outlen, key4, key5, key6, key7, keylen,
			cst4, cst5, cst6, cst7, cstlen, msg4, msg5, msg6, msg7, msglen);

#else

		qsc_kmac128_compute(out0, outlen, msg0, msglen, key0, keylen, cst0, cstlen);
		qsc_kmac128_compute(out1, outlen, msg1, msglen, key1, keylen, cst1, cstlen);
		qsc_kmac128_compute(out2, outlen, msg2, msglen, key2, keylen, cst2, cstlen);
		qsc_kmac128_compute(out3, outlen, msg3, msglen, key3, keylen, cst3, cstlen);
		qsc_kmac128_compute(out4, outlen, msg4, msglen, key4, keylen, cst4, cstlen);
		qsc_kmac128_compute(out5, outlen, msg5, msglen, key5, keylen, cst5, cstlen);
		qsc_kmac128_compute(out6, outlen, msg6, msglen, key6, keylen, cst6, cstlen);
		qsc_kmac128_compute(out7, outlen, msg7, msglen, key7, keylen, cst7, cstlen);

#endif
	}
}

void qsc_kmac_256x8(uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3,
	uint8_t* out4, uint8_t* out5, uint8_t* out6, uint8_t* out7, size_t outlen,
	const uint8_t* key0, const uint8_t* key1, const uint8_t* key2, const uint8_t* key3,
	const uint8_t* key4, const uint8_t* key5, const uint8_t* key6, const uint8_t* key7, size_t keylen,
	const uint8_t* cst0, const uint8_t* cst1, const uint8_t* cst2, const uint8_t* cst3,
	const uint8_t* cst4, const uint8_t* cst5, const uint8_t* cst6, const uint8_t* cst7, size_t cstlen,
	const uint8_t* msg0, const uint8_t* msg1, const uint8_t* msg2, const uint8_t* msg3,
	const uint8_t* msg4, const uint8_t* msg5, const uint8_t* msg6, const uint8_t* msg7, size_t msglen)
{
	QSC_ASSERT(key0 != NULL);
	QSC_ASSERT(key1 != NULL);
	QSC_ASSERT(key2 != NULL);
	QSC_ASSERT(key3 != NULL);
	QSC_ASSERT(key4 != NULL);
	QSC_ASSERT(key5 != NULL);
	QSC_ASSERT(key6 != NULL);
	QSC_ASSERT(key7 != NULL);
	QSC_ASSERT(msg0 != NULL);
	QSC_ASSERT(msg1 != NULL);
	QSC_ASSERT(msg2 != NULL);
	QSC_ASSERT(msg3 != NULL);
	QSC_ASSERT(msg4 != NULL);
	QSC_ASSERT(msg5 != NULL);
	QSC_ASSERT(msg6 != NULL);
	QSC_ASSERT(msg7 != NULL);
	QSC_ASSERT(out0 != NULL);
	QSC_ASSERT(out1 != NULL);
	QSC_ASSERT(out2 != NULL);
	QSC_ASSERT(out3 != NULL);
	QSC_ASSERT(out4 != NULL);
	QSC_ASSERT(out5 != NULL);
	QSC_ASSERT(out6 != NULL);
	QSC_ASSERT(out7 != NULL);

	if (outlen <= SIZE_MAX / 8U && keylen <= SIZE_MAX / 8U && cstlen <= SIZE_MAX / 8U &&
		(cstlen == 0U || (cst0 != NULL && cst1 != NULL && cst2 != NULL && cst3 != NULL && cst4 != NULL && cst5 != NULL && cst6 != NULL && cst7 != NULL)) &&
		key0 != NULL && key1 != NULL && key2 != NULL && key3 != NULL && key4 != NULL && key5 != NULL && key6 != NULL && key7 != NULL &&
		msg0 != NULL && msg1 != NULL && msg2 != NULL && msg3 != NULL && msg4 != NULL && msg5 != NULL && msg6 != NULL && msg7 != NULL &&
		out0 != NULL && out1 != NULL && out2 != NULL && out3 != NULL && out4 != NULL && out5 != NULL && out6 != NULL && out7 != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX512)

		__m512i state[QSC_KECCAK_STATE_SIZE] = { 0U };
		QSC_ALIGN(64) const uint8_t name[] = { 0x4BU, 0x4DU, 0x41U, 0x43U };

		kmacx8_customize(state, qsc_keccak_rate_256, key0, key1, key2, key3, key4, key5, key6, key7, keylen,
			cst0, cst1, cst2, cst3, cst4, cst5, cst6, cst7, cstlen, name, sizeof(name));
		kmacx8_finalize(state, qsc_keccak_rate_256, msg0, msg1, msg2, msg3, msg4, msg5, msg6, msg7, msglen,
			out0, out1, out2, out3, out4, out5, out6, out7, outlen);

		qsc_memutils_secure_erase(state, sizeof(state));

#elif defined(QSC_SYSTEM_HAS_AVX2) || defined(QSC_SYSTEM_ARM_INTRINSICS)

		qsc_kmac_256x4(out0, out1, out2, out3, outlen, key0, key1, key2, key3, keylen,
			cst0, cst1, cst2, cst3, cstlen, msg0, msg1, msg2, msg3, msglen);
		qsc_kmac_256x4(out4, out5, out6, out7, outlen, key4, key5, key6, key7, keylen,
			cst4, cst5, cst6, cst7, cstlen, msg4, msg5, msg6, msg7, msglen);

#else

		qsc_kmac256_compute(out0, outlen, msg0, msglen, key0, keylen, cst0, cstlen);
		qsc_kmac256_compute(out1, outlen, msg1, msglen, key1, keylen, cst1, cstlen);
		qsc_kmac256_compute(out2, outlen, msg2, msglen, key2, keylen, cst2, cstlen);
		qsc_kmac256_compute(out3, outlen, msg3, msglen, key3, keylen, cst3, cstlen);
		qsc_kmac256_compute(out4, outlen, msg4, msglen, key4, keylen, cst4, cstlen);
		qsc_kmac256_compute(out5, outlen, msg5, msglen, key5, keylen, cst5, cstlen);
		qsc_kmac256_compute(out6, outlen, msg6, msglen, key6, keylen, cst6, cstlen);
		qsc_kmac256_compute(out7, outlen, msg7, msglen, key7, keylen, cst7, cstlen);

#endif
	}
}

void qsc_kmac_512x8(uint8_t* out0, uint8_t* out1, uint8_t* out2, uint8_t* out3,
	uint8_t* out4, uint8_t* out5, uint8_t* out6, uint8_t* out7, size_t outlen,
	const uint8_t* key0, const uint8_t* key1, const uint8_t* key2, const uint8_t* key3,
	const uint8_t* key4, const uint8_t* key5, const uint8_t* key6, const uint8_t* key7, size_t keylen,
	const uint8_t* cst0, const uint8_t* cst1, const uint8_t* cst2, const uint8_t* cst3,
	const uint8_t* cst4, const uint8_t* cst5, const uint8_t* cst6, const uint8_t* cst7, size_t cstlen,
	const uint8_t* msg0, const uint8_t* msg1, const uint8_t* msg2, const uint8_t* msg3,
	const uint8_t* msg4, const uint8_t* msg5, const uint8_t* msg6, const uint8_t* msg7, size_t msglen)
{
	QSC_ASSERT(key0 != NULL);
	QSC_ASSERT(key1 != NULL);
	QSC_ASSERT(key2 != NULL);
	QSC_ASSERT(key3 != NULL);
	QSC_ASSERT(key4 != NULL);
	QSC_ASSERT(key5 != NULL);
	QSC_ASSERT(key6 != NULL);
	QSC_ASSERT(key7 != NULL);
	QSC_ASSERT(msg0 != NULL);
	QSC_ASSERT(msg1 != NULL);
	QSC_ASSERT(msg2 != NULL);
	QSC_ASSERT(msg3 != NULL);
	QSC_ASSERT(msg4 != NULL);
	QSC_ASSERT(msg5 != NULL);
	QSC_ASSERT(msg6 != NULL);
	QSC_ASSERT(msg7 != NULL);
	QSC_ASSERT(out0 != NULL);
	QSC_ASSERT(out1 != NULL);
	QSC_ASSERT(out2 != NULL);
	QSC_ASSERT(out3 != NULL);
	QSC_ASSERT(out4 != NULL);
	QSC_ASSERT(out5 != NULL);
	QSC_ASSERT(out6 != NULL);
	QSC_ASSERT(out7 != NULL);

	if (outlen <= SIZE_MAX / 8U && keylen <= SIZE_MAX / 8U && cstlen <= SIZE_MAX / 8U &&
		(cstlen == 0U || (cst0 != NULL && cst1 != NULL && cst2 != NULL && cst3 != NULL && cst4 != NULL && cst5 != NULL && cst6 != NULL && cst7 != NULL)) &&
		key0 != NULL && key1 != NULL && key2 != NULL && key3 != NULL && key4 != NULL && key5 != NULL && key6 != NULL && key7 != NULL &&
		msg0 != NULL && msg1 != NULL && msg2 != NULL && msg3 != NULL && msg4 != NULL && msg5 != NULL && msg6 != NULL && msg7 != NULL &&
		out0 != NULL && out1 != NULL && out2 != NULL && out3 != NULL && out4 != NULL && out5 != NULL && out6 != NULL && out7 != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX512)

		__m512i state[QSC_KECCAK_STATE_SIZE] = { 0U };
		QSC_ALIGN(64) const uint8_t name[] = { 0x4BU, 0x4DU, 0x41U, 0x43U };

		kmacx8_customize(state, qsc_keccak_rate_512, key0, key1, key2, key3, key4, key5, key6, key7, keylen,
			cst0, cst1, cst2, cst3, cst4, cst5, cst6, cst7, cstlen, name, sizeof(name));
		kmacx8_finalize(state, qsc_keccak_rate_512, msg0, msg1, msg2, msg3, msg4, msg5, msg6, msg7, msglen,
			out0, out1, out2, out3, out4, out5, out6, out7, outlen);

		qsc_memutils_secure_erase(state, sizeof(state));

#elif defined(QSC_SYSTEM_HAS_AVX2) || defined(QSC_SYSTEM_ARM_INTRINSICS)

		qsc_kmac_512x4(out0, out1, out2, out3, outlen, key0, key1, key2, key3, keylen,
			cst0, cst1, cst2, cst3, cstlen, msg0, msg1, msg2, msg3, msglen);
		qsc_kmac_512x4(out4, out5, out6, out7, outlen, key4, key5, key6, key7, keylen,
			cst4, cst5, cst6, cst7, cstlen, msg4, msg5, msg6, msg7, msglen);

#else

		qsc_kmac512_compute(out0, outlen, msg0, msglen, key0, keylen, cst0, cstlen);
		qsc_kmac512_compute(out1, outlen, msg1, msglen, key1, keylen, cst1, cstlen);
		qsc_kmac512_compute(out2, outlen, msg2, msglen, key2, keylen, cst2, cstlen);
		qsc_kmac512_compute(out3, outlen, msg3, msglen, key3, keylen, cst3, cstlen);
		qsc_kmac512_compute(out4, outlen, msg4, msglen, key4, keylen, cst4, cstlen);
		qsc_kmac512_compute(out5, outlen, msg5, msglen, key5, keylen, cst5, cstlen);
		qsc_kmac512_compute(out6, outlen, msg6, msglen, key6, keylen, cst6, cstlen);
		qsc_kmac512_compute(out7, outlen, msg7, msglen, key7, keylen, cst7, cstlen);

#endif
	}
}
