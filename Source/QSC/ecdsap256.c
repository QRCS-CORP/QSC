#include "ecdsap256.h"
#include "csp.h"
#include "intutils.h"
#include "memutils.h"
#include "intrinsics.h"
#include "sha2.h"

/* \cond DOXYGEN_NO_DOCUMENT */

/*! \def ECDSAP256_X64
 * \brief Native x86-64 compiler target, excluding ARM64EC.
 */
#if (defined(_M_X64) || defined(__x86_64__)) && !defined(_M_ARM64EC)
#	define ECDSAP256_X64
#endif

/*! \def ECDSAP256_NATIVE_64
 * \brief Enable four-word arithmetic with either a wide C type or MSVC x64.
 */
#if !QSC_ECDSAP256_FORCE_PORTABLE && (defined(__SIZEOF_INT128__) || (defined(_MSC_VER) && defined(ECDSAP256_X64)))
#	define ECDSAP256_NATIVE_64
#endif

/*! \def ECDSAP256_X64_INTRINSICS
 * \brief Enable baseline x64 carry and multiplication intrinsics.
 */
#if defined(ECDSAP256_NATIVE_64) && defined(ECDSAP256_X64) && QSC_ECDSAP256_USE_INTRINSICS
#	define ECDSAP256_X64_INTRINSICS
#endif

#if defined(ECDSAP256_NATIVE_64) && defined(ECDSAP256_X64)
#	include <immintrin.h>
#	if defined(_MSC_VER)
#		include <intrin.h>
#		if (QSC_ECDSAP256_ENABLE_BMI2 && QSC_ECDSAP256_USE_INTRINSICS) || (QSC_ECDSAP256_ENABLE_AVX2 && QSC_ECDSAP256_USE_SIMD)
#			include "async.h"
#			include "cpuidex.h"
#		endif
#	endif
#endif

#if defined(ECDSAP256_NATIVE_64) && !defined(__SIZEOF_INT128__) && !defined(ECDSAP256_X64_INTRINSICS)
#include "donna128.h"
#endif

/*! \def ECDSAP256_RESTRICT
 * \brief Nonaliasing workspace qualifier for internal Comba kernels.
 */
#if defined(_MSC_VER)
#define ECDSAP256_RESTRICT __restrict
#else
#define ECDSAP256_RESTRICT restrict
#endif

/*! \def ECDSAP256_BMI2_KERNEL
 * \brief BMI2 kernel compiled with an isolated compiler target.
 */
#if defined(ECDSAP256_X64_INTRINSICS) && QSC_ECDSAP256_ENABLE_BMI2
#define ECDSAP256_BMI2_KERNEL
#endif

/*! \def ECDSAP256_AVX2_KERNEL
 * \brief AVX2 table scan compiled with an isolated compiler target.
 */
#if defined(ECDSAP256_NATIVE_64) && defined(ECDSAP256_X64) && QSC_ECDSAP256_USE_SIMD && QSC_ECDSAP256_ENABLE_AVX2
#define ECDSAP256_AVX2_KERNEL
#endif

/*! \def ECDSAP256_TARGET_BMI2
 * \brief Isolate the BMI2 function from baseline callers.
 */
/*! \def ECDSAP256_TARGET_AVX2
 * \brief Isolate the AVX2 function from baseline callers.
 */
#if defined(_MSC_VER)
#define ECDSAP256_TARGET_BMI2 __declspec(noinline)
#define ECDSAP256_TARGET_AVX2 __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
#define ECDSAP256_TARGET_BMI2 __attribute__((target("bmi2"), noinline))
#define ECDSAP256_TARGET_AVX2 __attribute__((target("avx2"), noinline))
#else
#define ECDSAP256_TARGET_BMI2
#define ECDSAP256_TARGET_AVX2
#endif

#if defined(ECDSAP256_NATIVE_64)
/* Internal declarations; contracts are documented with their definitions. */
static void ecdsap256_native_load(uint64_t output[4U], const uint32_t input[8U]);
static void ecdsap256_native_store(uint32_t output[8U], const uint64_t input[4U]);
static void ecdsap256_native_mul(uint64_t output[4U], const uint64_t a[4U], const uint64_t b[4U], uint64_t scratch[15U]);
static void ecdsap256_native_square(uint64_t output[4U], const uint64_t a[4U], uint64_t scratch[15U]);
static void ecdsap256_native_order_mul(uint64_t output[4U], const uint64_t a[4U], const uint64_t b[4U], uint64_t scratch[15U]);

static void ecdsap256_native_scalar_product(uint32_t output[8U], const uint32_t a[8U], const uint32_t b[8U]);
#endif

#if defined(ECDSAP256_NATIVE_64)

static inline uint64_t ecdsap256_word_add_c(uint64_t a, uint64_t b, uint64_t* carry)
{
#if defined(__SIZEOF_INT128__)
	__uint128_t value;
	uint64_t result;

	value = (__uint128_t)a + b + *carry;
	result = (uint64_t)value;
	*carry = (uint64_t)(value >> 64U);
#else
	uint64_t sum;
	uint64_t result;
	uint64_t overflow;

	sum = a + b;
	overflow = (uint64_t)(sum < a);
	result = sum + *carry;
	*carry = overflow | (uint64_t)(result < sum);

#endif

	return result;
}

static inline uint64_t ecdsap256_word_sub_c(uint64_t a, uint64_t b, uint64_t* borrow)
{
#if defined(__SIZEOF_INT128__)
	__uint128_t value;
	uint64_t result;

	value = (__uint128_t)a - b - *borrow;
	result = (uint64_t)value;
	*borrow = (uint64_t)(value >> 127U);
#else
	uint64_t difference;
	uint64_t result;
	uint64_t underflow;

	difference = a - b;
	underflow = (uint64_t)(a < b);
	result = difference - *borrow;
	*borrow = underflow | (uint64_t)(difference < *borrow);

#endif

	return result;
}

static inline uint64_t ecdsap256_word_add(uint64_t a, uint64_t b, uint64_t* carry)
{
	uint64_t result;
#if defined(ECDSAP256_X64_INTRINSICS)
	unsigned long long word;

	*carry = (uint64_t)_addcarry_u64((unsigned char)*carry, a, b, &word);
	result = (uint64_t)word;
#else
	result = ecdsap256_word_add_c(a, b, carry);
#endif

	return result;
}

static inline uint64_t ecdsap256_word_sub(uint64_t a, uint64_t b, uint64_t* borrow)
{
	uint64_t result;
#if defined(ECDSAP256_X64_INTRINSICS)
	unsigned long long word;

	*borrow = (uint64_t)_subborrow_u64((unsigned char)*borrow, a, b, &word);
	result = (uint64_t)word;
#else
	result = ecdsap256_word_sub_c(a, b, borrow);
#endif

	return result;
}

static inline uint64_t ecdsap256_word_multiply(uint64_t a, uint64_t b, uint64_t* high)
{
	uint64_t low;
#if defined(_MSC_VER) && defined(ECDSAP256_X64_INTRINSICS)
	unsigned __int64 upper;

	low = (uint64_t)_umul128(a, b, &upper);
	*high = (uint64_t)upper;
#elif defined(__SIZEOF_INT128__)
	__uint128_t product;

	product = (__uint128_t)a * b;
	low = (uint64_t)product;
	*high = (uint64_t)(product >> 64U);
#else
	uint128 input;
	uint128 product;

	input.high = 0U;
	input.low = a;
	product = qsc_donna128_multiply(&input, b);
	low = product.low;
	*high = product.high;
	qsc_memutils_secure_erase(&input, sizeof(input));
	qsc_memutils_secure_erase(&product, sizeof(product));
#endif

	return low;
}
#endif

#if defined(ECDSAP256_BMI2_KERNEL) || defined(ECDSAP256_AVX2_KERNEL)

static inline uint32_t ecdsap256_optional_features(void)
{
	uint32_t result;
#if defined(_MSC_VER)
	/*! \brief Atomically published public capabilities; bit 2 marks initialization. */
	static volatile int32_t cached = 0;
	int32_t flags;
#if defined(ECDSAP256_BMI2_KERNEL)
	int info[4U];
#endif
#if defined(ECDSAP256_AVX2_KERNEL)
	qsc_cpuidex_cpu_features features;
#endif

	flags = qsc_async_atomic_int32_load(&cached);

	if (flags == 0)
	{
		flags = 4;
#if defined(ECDSAP256_BMI2_KERNEL)
		__cpuidex(info, 0, 0);

		if ((uint32_t)info[0U] >= 7U)
		{
			__cpuidex(info, 7, 0);
			flags |= (int32_t)(((uint32_t)info[1U] >> 8U) & 1U);
		}
#endif
#if defined(ECDSAP256_AVX2_KERNEL)
		if (qsc_cpuidex_features_set_cached(&features) && features.avx2)
		{
			flags |= 2;
		}
#endif
		qsc_async_atomic_int32_store(&cached, flags);
	}

	result = (uint32_t)flags & 3U;
#else
	result = 0U;
#if defined(ECDSAP256_BMI2_KERNEL)
	result |= (uint32_t)(__builtin_cpu_supports("bmi2") != 0);
#endif
#if defined(ECDSAP256_AVX2_KERNEL)
	result |= (uint32_t)(__builtin_cpu_supports("avx2") != 0) << 1U;
#endif
#endif

	return result;
}
#endif

/*! \brief Eight little-endian 32-bit words representing a field value. */
typedef uint32_t ecdsap256_field[8U];

/* jacobian projective point over P-256 (X:Y:Z), affine = (X/Z^2, Y/Z^3) */
/*! \brief Jacobian point with eight-word Montgomery coordinates.
 * \details Caller-owned value; contains no dynamically allocated storage.
 */
typedef struct
{
	ecdsap256_field X; /*!< Jacobian x-coordinate. */
	ecdsap256_field Y; /*!< Jacobian y-coordinate. */
	ecdsap256_field Z; /*!< Projective scale; zero encodes the identity. */
} ecdsap256_jac_t;

/*! \brief Affine point with eight-word Montgomery coordinates.
 * \details Caller-owned value; contains no dynamically allocated storage.
 */
typedef struct
{
	ecdsap256_field X; /*!< Affine x-coordinate. */
	ecdsap256_field Y; /*!< Affine y-coordinate. */
} ecdsap256_aff_t;

/* field prime:  p = 2^256 - 2^224 + 2^192 + 2^96 - 1 */
static const uint32_t ECDSAP256_P[8U] = {0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000001U, 0xFFFFFFFFU};

/* group order: n */
static const uint32_t ECDSAP256_N[8U] = {0xFC632551U, 0xF3B9CAC2U, 0xA7179E84U, 0xBCE6FAADU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0x00000000U, 0xFFFFFFFFU};

/* base point Gx */
static const uint32_t ECDSAP256_GX[8U] = {0xD898C296U, 0xF4A13945U, 0x2DEB33A0U, 0x77037D81U, 0x63A440F2U, 0xF8BCE6E5U, 0xE12C4247U, 0x6B17D1F2U};

/* base point Gy */
static const uint32_t ECDSAP256_GY[8U] = {0x37BF51F5U, 0xCBB64068U, 0x6B315ECEU, 0x2BCE3357U, 0x7C0F9E16U, 0x8EE7EB4AU, 0xFE1A7F9BU, 0x4FE342E2U};

/* curve coefficient b */
static const uint32_t ECDSAP256_B[8U] = {0x27D2604BU, 0x3BCE3C3EU, 0xCC53B0F6U, 0x651D06B0U, 0x769886BCU, 0xB3EBBD55U, 0xAA3A93E7U, 0x5AC635D8U};

/*! \brief Montgomery representation of field element one, 2^256 mod p. */
static const uint32_t ECDSAP256_MONT_ONE[8U] = {0x00000001U, 0x00000000U, 0x00000000U, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFEU, 0x00000000U};

/*! \brief Independently derived canonical generator multiples in Montgomery representation.
 * \details Every coordinate is generated from the published NIST domain parameters,
 * not copied from another software implementation; entry 0 represents infinity.
 * \note The read-only data are public, shared without synchronization, and never
 * indexed using a secret scalar. The table is scanned in constant time.
 */
#if (defined(ECDSAP256_NATIVE_64)) || defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)
static const uint32_t ECDSAP256_GENERATOR_MONT[16U][2U][8U] = {
	{{0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U},
		{0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U}} /* 0G */,
	{{0x18A9143CU, 0x79E730D4U, 0x5FEDB601U, 0x75BA95FCU, 0x77622510U, 0x79FB732BU, 0xA53755C6U, 0x18905F76U},
		{0xCE95560AU, 0xDDF25357U, 0xBA19E45CU, 0x8B4AB8E4U, 0xDD21F325U, 0xD2E88688U, 0x25885D85U, 0x8571FF18U}} /* 1G */,
	{{0x10DDD64DU, 0x850046D4U, 0xA433827DU, 0xAA6AE3C1U, 0x8D1490D9U, 0x73220503U, 0x3DCF3A3BU, 0xF6BB32E4U},
		{0x61BEE1A5U, 0x2F3648D3U, 0xEB236FF8U, 0x152CD7CBU, 0x92042DBEU, 0x19A8FB0EU, 0x0A5B8A3BU, 0x78C57751U}} /* 2G */,
	{{0x4EEBC127U, 0xFFAC3F90U, 0x087D81FBU, 0xB027F84AU, 0x87CBBC98U, 0x66AD77DDU, 0xB6FF747EU, 0x26936A3FU},
		{0xC983A7EBU, 0xB04C5C1FU, 0x0861FE1AU, 0x583E47ADU, 0x1A2EE98EU, 0x78820831U, 0xE587CC07U, 0xD5F06A29U}} /* 3G */,
	{{0x46918DCCU, 0x74B0B50DU, 0xC623C173U, 0x4650A6EDU, 0xE8100AF2U, 0x0CDAACACU, 0x41B0176BU, 0x577362F5U},
		{0xE4CBABA6U, 0x2D96F24CU, 0xFAD6F447U, 0x17628471U, 0xE5DDD22EU, 0x6B6C36DEU, 0x4C5AB863U, 0x84B14C39U}} /* 4G */,
	{{0xC45C61F5U, 0xBE1B8AAEU, 0x94B9537DU, 0x90EC649AU, 0xD076C20CU, 0x941CB5AAU, 0x890523C8U, 0xC9079605U},
		{0xE7BA4F10U, 0xEB309B4AU, 0xE5EB882BU, 0x73C568EFU, 0x7E7A1F68U, 0x3540A987U, 0x2DD1E916U, 0x73A076BBU}} /* 5G */,
	{{0x3E77664AU, 0x40394737U, 0x346CEE3EU, 0x55AE744FU, 0x5B17A3ADU, 0xD50A961AU, 0x54213673U, 0x13074B59U},
		{0xD377E44BU, 0x93D36220U, 0xADFF14B5U, 0x299C2B53U, 0xEF639F11U, 0xF424D44CU, 0x4A07F75FU, 0xA4C9916DU}} /* 6G */,
	{{0xA0173B4FU, 0x0746354EU, 0xD23C00F7U, 0x2BD20213U, 0x0C23BB08U, 0xF43EAAB5U, 0xC3123E03U, 0x13BA5119U},
		{0x3F5B9D4DU, 0x2847D030U, 0x5DA67BDDU, 0x6742F2F2U, 0x77C94195U, 0xEF933BDCU, 0x6E240867U, 0xEAEDD915U}} /* 7G */,
	{{0x9499A78FU, 0x27F14CD1U, 0x6F9B3455U, 0x462AB5C5U, 0xF02CFC6BU, 0x8F90F02AU, 0xB265230DU, 0xB763891EU},
		{0x532D4977U, 0xF59DA3A9U, 0xCF9EBA15U, 0x21E3327DU, 0xBE60BBF0U, 0x123C7B84U, 0x7706DF76U, 0x56EC12F2U}} /* 8G */,
	{{0x264E20E8U, 0x75C96E8FU, 0x59A7A841U, 0xABE6BFEDU, 0x44C8EB00U, 0x2CC09C04U, 0xF0C4E16BU, 0xE05B3080U},
		{0xA45F3314U, 0x1EB7777AU, 0xCE5D45E3U, 0x56AF7BEDU, 0x88B12F1AU, 0x2B6E019AU, 0xFD835F9BU, 0x086659CDU}} /* 9G */,
	{{0x9DC21EC8U, 0x2C18DBD1U, 0x0FCF8139U, 0x98F9868AU, 0x48250B49U, 0x737D2CD6U, 0x24B3428FU, 0xCC61C947U},
		{0x80DD9E76U, 0x0C2B4078U, 0x383FBE08U, 0xC43A8991U, 0x779BE5D2U, 0x5F7D2D65U, 0xEB3B4AB5U, 0x78719A54U}} /* 10G */,
	{{0x6245E404U, 0xEA7D260AU, 0x6E7FDFE0U, 0x9DE40795U, 0x8DAC1AB5U, 0x1FF3A415U, 0x649C9073U, 0x3E7090F1U},
		{0x2B944E88U, 0x1A768561U, 0xE57F61C8U, 0x250F939EU, 0x1EAD643DU, 0x0C0DAA89U, 0xE125B88EU, 0x68930023U}} /* 11G */,
	{{0xD2697768U, 0x04B71AA7U, 0xCA345A33U, 0xABDEDEF5U, 0xEE37385EU, 0x2409D29DU, 0xCB83E156U, 0x4EE1DF77U},
		{0x1CBB5B43U, 0x0CAC12D9U, 0xCA895637U, 0x170ED2F6U, 0x8ADE6D66U, 0x28228CFAU, 0x53238ACAU, 0x7FF57C95U}} /* 12G */,
	{{0x4B2ED709U, 0xCCC42563U, 0x856FD30DU, 0x0E356769U, 0x559E9811U, 0xBCBCD43FU, 0x5395B759U, 0x738477ACU},
		{0xC00EE17FU, 0x35752B90U, 0x742ED2E3U, 0x68748390U, 0xBD1F5BC1U, 0x7CD06422U, 0xC9E7B797U, 0xFBC08769U}} /* 13G */,
	{{0xB0CF664AU, 0xA242A35BU, 0x7F9707E3U, 0x126E48F7U, 0xC6832660U, 0x1717BF54U, 0xFD12C72EU, 0xFAAE7332U},
		{0x995D586BU, 0x27B52DB7U, 0x832237C2U, 0xBE29569EU, 0x2A65E7DBU, 0xE8E4193EU, 0x2EAA1BBBU, 0x152706DCU}} /* 14G */,
	{{0xBC60055BU, 0x72BCD8B7U, 0x56E27E4BU, 0x03CC23EEU, 0xE4819370U, 0xEE337424U, 0x0AD3DA09U, 0xE2AA0E43U},
		{0x6383C45DU, 0x40B8524FU, 0x42A41B25U, 0xD7663554U, 0x778A4797U, 0x64EFA6DEU, 0x7079ADF4U, 0x2042170AU}} /* 15G */
};
#endif

static void ecdsap256_field_select(uint32_t* r, const uint32_t* a, const uint32_t* b, uint32_t mask)
{
	/* mask must be either 0x00000000 or 0xFFFFFFFF */
	size_t i;

	for (i = 0U; i < 8U; ++i)
	{
		r[i] = (a[i] & mask) | (b[i] & ~mask);
	}
}

static void ecdsap256_field_copy(ecdsap256_field r, const ecdsap256_field a)
{
	int32_t i;

	for (i = 0; i < 8; ++i)
	{
		r[i] = a[i];
	}
}

static void ecdsap256_field_zero(ecdsap256_field r)
{
	int32_t i;

	for (i = 0; i < 8; ++i)
	{
		r[i] = 0U;
	}
}

static void ecdsap256_field_one(ecdsap256_field r)
{
	/* set a field element to the Montgomery-domain multiplicative identity */
	ecdsap256_field_copy(r, ECDSAP256_MONT_ONE);
}

static uint32_t ecdsap256_field_is_zero(const ecdsap256_field a)
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

static int32_t ecdsap256_field_cmp(const uint32_t* a, const uint32_t* b)
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

static uint32_t ecdsap256_ct_sel32(uint32_t sel, uint32_t a, uint32_t b)
{
	/* constant-time 32-bit word select: returns a if sel==1, b if sel==0 */
	uint32_t mask;

	/* 0xFFFFFFFF if sel=1, 0x00000000 if sel=0 */
	mask = (uint32_t)(0U - sel);

	return (a & mask) | (b & ~mask);
}

static void ecdsap256_field_ct_select(ecdsap256_field r, uint32_t sel, const ecdsap256_field a, const ecdsap256_field b)
{
	/* constant-time ecdsap256_field select: r = (sel ? a : b) */
	int32_t i;

	for (i = 0; i < 8; ++i)
	{
		r[i] = ecdsap256_ct_sel32(sel, a[i], b[i]);
	}
}

static void ecdsap256_jac_ct_select(ecdsap256_jac_t* r, uint32_t sel, const ecdsap256_jac_t* a, const ecdsap256_jac_t* b)
{
	/* constant-time Jacobian point select */
	ecdsap256_field_ct_select(r->X, sel, a->X, b->X);
	ecdsap256_field_ct_select(r->Y, sel, a->Y, b->Y);
	ecdsap256_field_ct_select(r->Z, sel, a->Z, b->Z);
}

static void ecdsap256_field_from_bytes(ecdsap256_field r, const uint8_t* b)
{
	/* convert big-endian 32-byte buffer to little-endian ecdsap256_field */
	int32_t i;

	for (i = 0; i < 8; ++i)
	{
		const uint8_t* p = b + 4 * (7 - i);

		r[i] = ((uint32_t)p[0U] << 24U) | ((uint32_t)p[1U] << 16U) | ((uint32_t)p[2U] << 8U) | (uint32_t)p[3U];
	}
}

static void ecdsap256_field_to_bytes(uint8_t* b, const ecdsap256_field r)
{
	/* convert little-endian ecdsap256_field to big-endian 32-byte buffer */
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

/* Field arithmetic mod p (Solinas reduction) */

static void ecdsap256_field_cond_sub(ecdsap256_field r, const uint32_t mod[8U])
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

	/* accept tmp only if there was no borrow (r >= mod) */
	ecdsap256_field_ct_select(r, (uint32_t)(1U - (uint32_t)borrow), tmp, r);
}

static void ecdsap256_fe_add(ecdsap256_field r, const ecdsap256_field a, const ecdsap256_field b)
{
	int32_t i;
	uint32_t t[8U] = { 0U };
	uint32_t u[8U] = { 0U };
	uint64_t carry;
	uint32_t csel;

	static const uint32_t ECDSAP256_C[8U] = {0x00000001U, 0x00000000U, 0x00000000U, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFEU, 0x00000000U};

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

		addi = ecdsap256_ct_sel32(csel, ECDSAP256_C[i], 0U);
		uint64_t x;

		x = (uint64_t)t[i] + (uint64_t)addi + carry;
		u[i] = (uint32_t)x;
		carry = x >> 32U;
	}

	/* u is now in [0, 2p). Final conditional subtraction. */
	ecdsap256_field_copy(r, u);
	ecdsap256_field_cond_sub(r, ECDSAP256_P);

	qsc_memutils_secure_erase(t, sizeof(t));
	qsc_memutils_secure_erase(u, sizeof(u));
}

static void ecdsap256_fe_sub(uint32_t* r, const uint32_t* a, const uint32_t* b)
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
		x = (uint64_t)r[i] + ECDSAP256_P[i] + carry;
		t[i] = (uint32_t)x;
		carry = x >> 32;
	}

	mask = (uint32_t) - (int32_t)borrow;

	ecdsap256_field_select(r, t, r, mask);
}

static uint32_t ecdsap256_ct_ge_9x32(const uint32_t a[9U], const uint32_t b[9U])
{
	uint64_t diff;
	uint32_t borrow;
	size_t i;

	borrow = 0U;

	for (i = 0U; i < 9U; ++i)
	{
		diff = (uint64_t)a[i] - (uint64_t)b[i] - (uint64_t)borrow;
		borrow = (uint32_t)((diff >> 63) & 1U);
	}

	return (uint32_t)(borrow ^ 1U);
}

static void ecdsap256_ct_sub_9x32(uint32_t out[9U], const uint32_t a[9U], const uint32_t b[9U])
{
	uint64_t diff;
	uint32_t borrow;
	size_t i;

	borrow = 0U;

	for (i = 0U; i < 9U; ++i)
	{
		diff = (uint64_t)a[i] - (uint64_t)b[i] - (uint64_t)borrow;
		out[i] = (uint32_t)diff;
		borrow = (uint32_t)((diff >> 63) & 1U);
	}
}

/*! \brief Montgomery R-squared constant for the ECDSAP256_P modulus. */
static const uint32_t ECDSAP256_P_R2[8U] = {0x00000003U, 0x00000000U, 0xFFFFFFFFU, 0xFFFFFFFBU, 0xFFFFFFFEU, 0xFFFFFFFFU, 0xFFFFFFFDU, 0x00000004U};

#if !defined(ECDSAP256_NATIVE_64) || defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)
/*! \brief Montgomery R-squared constant for the ECDSAP256_N modulus. */
static const uint32_t ECDSAP256_N_R2[8U] = {0xBE79EEA2U, 0x83244C95U, 0x49BD6FA6U, 0x4699799CU, 0x2B6BEC59U, 0x2845B239U, 0xF3D95620U, 0x66E12D94U};
#endif

/* multiply two 256-bit values to form a double-width integer */

static void ecdsap256_field_mul_raw(uint32_t c[16U], const ecdsap256_field a, const ecdsap256_field b);

static void ecdsap256_mod_montgomery512(uint32_t out[8U], const uint32_t in[16U], const uint32_t mod[8U], uint32_t inverse)
{
	/* constant-iteration Montgomery reduction of a double-width integer */
	uint32_t t[18U] = { 0U };
	uint32_t candidate[9U] = { 0U };
	uint32_t reduced[9U] = { 0U };
	uint32_t modulus[9U] = { 0U };
	uint32_t selected;
	uint32_t word;
	uint64_t carry;
	uint64_t value;
	size_t i;
	size_t j;

	for (i = 0U; i < 16U; ++i)
	{
		t[i] = in[i];
	}

	for (i = 0U; i < 8U; ++i)
	{
		word = (uint32_t)((uint64_t)t[i] * (uint64_t)inverse);
		carry = 0U;

		for (j = 0U; j < 8U; ++j)
		{
			value = ((uint64_t)word * (uint64_t)mod[j]) + (uint64_t)t[i + j] + carry;
			t[i + j] = (uint32_t)value;
			carry = value >> 32U;
		}

		for (j = i + 8U; j < 18U; ++j)
		{
			value = (uint64_t)t[j] + carry;
			t[j] = (uint32_t)value;
			carry = value >> 32U;
		}
	}

	for (i = 0U; i < 8U; ++i)
	{
		modulus[i] = mod[i];
	}

	for (i = 0U; i < 9U; ++i)
	{
		candidate[i] = t[i + 8U];
	}

	ecdsap256_ct_sub_9x32(reduced, candidate, modulus);
	selected = (uint32_t)(0U - ecdsap256_ct_ge_9x32(candidate, modulus));

	for (i = 0U; i < 8U; ++i)
	{
		out[i] = (candidate[i] & ~selected) | (reduced[i] & selected);
	}

	qsc_memutils_secure_erase(t, sizeof(t));
	qsc_memutils_secure_erase(candidate, sizeof(candidate));
	qsc_memutils_secure_erase(reduced, sizeof(reduced));
}

#if !defined(ECDSAP256_NATIVE_64)

static void ecdsap256_mod_reduce512_montgomery(uint32_t out[8U], const uint32_t in[16U], const uint32_t mod[8U], uint32_t inverse, const uint32_t squared_radix[8U])
{
	/* reduce a 512-bit product in standard representation using two Montgomery steps */
	uint32_t intermediate[8U] = { 0U };
	uint32_t product[16U] = { 0U };

	ecdsap256_mod_montgomery512(intermediate, in, mod, inverse);
	ecdsap256_field_mul_raw(product, intermediate, squared_radix);
	ecdsap256_mod_montgomery512(out, product, mod, inverse);

	qsc_memutils_secure_erase(intermediate, sizeof(intermediate));
	qsc_memutils_secure_erase(product, sizeof(product));
}
#endif

static void ecdsap256_field_mul_raw(uint32_t c[16U], const ecdsap256_field a, const ecdsap256_field b)
{
	/* schoolbook 256x256 -> 512-bit multiplication */
	int32_t i;
	uint64_t tmp;

	for (i = 0; i < 16; ++i)
	{
		c[i] = 0U;
	}

	for (i = 0; i < 8; ++i)
	{
		int32_t j;
		uint64_t carry;

		carry = 0U;

		for (j = 0; j < 8; ++j)
		{
			tmp = (uint64_t)a[i] * b[j] + c[i + j] + carry;
			c[i + j] = (uint32_t)tmp;
			carry = tmp >> 32U;
		}

		c[i + 8U] = (uint32_t)carry;
	}
}

static void ecdsap256_fe_copy(uint32_t dst[8U], const uint32_t src[8U])
{
	size_t i;

	for (i = 0U; i < 8U; ++i)
	{
		dst[i] = src[i];
	}
}

static void ecdsap256_field_mont_encode(ecdsap256_field r, const ecdsap256_field a)
{
	/* encode a standard field element into Montgomery coordinates */
	uint32_t product[16U] = { 0U };

	ecdsap256_field_mul_raw(product, a, ECDSAP256_P_R2);
	ecdsap256_mod_montgomery512(r, product, ECDSAP256_P, 1U);
	qsc_memutils_secure_erase(product, sizeof(product));
}

static void ecdsap256_field_mont_decode(ecdsap256_field r, const ecdsap256_field a)
{
	/* decode a Montgomery element to the canonical external field representation */
	uint32_t product[16U] = { 0U };
	size_t i;

	for (i = 0U; i < 8U; ++i)
	{
		product[i] = a[i];
	}

	ecdsap256_mod_montgomery512(r, product, ECDSAP256_P, 1U);
	qsc_memutils_secure_erase(product, sizeof(product));
}

#if defined(ECDSAP256_NATIVE_64) && !defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)
/*! \brief Public field modulus in four little-endian words; immutable and shared. */
static const uint64_t ECDSAP256_P64[4U] = {
	UINT64_C(0xFFFFFFFFFFFFFFFF), UINT64_C(0x00000000FFFFFFFF), UINT64_C(0x0000000000000000), UINT64_C(0xFFFFFFFF00000001)};
#endif

#if defined(ECDSAP256_NATIVE_64)

static void ecdsap256_field_montgomery_multiply(ecdsap256_field r, const ecdsap256_field a, const ecdsap256_field b)
{
	uint64_t left[4U];
	uint64_t right[4U];
	uint64_t result[4U];
	uint64_t scratch[15U];

	ecdsap256_native_load(left, a);
	ecdsap256_native_load(right, b);
	ecdsap256_native_mul(result, left, right, scratch);
	ecdsap256_native_store(r, result);
	qsc_memutils_secure_erase(left, sizeof(left));
	qsc_memutils_secure_erase(right, sizeof(right));
	qsc_memutils_secure_erase(result, sizeof(result));
	qsc_memutils_secure_erase(scratch, sizeof(scratch));
}
#endif

static void ecdsap256_fe_mul(ecdsap256_field r, const ecdsap256_field a, const ecdsap256_field b)
{
	/* multiply two Montgomery field residues without decoding intermediate values */
#if defined(ECDSAP256_NATIVE_64)
	ecdsap256_field_montgomery_multiply(r, a, b);
#else
	uint32_t product[16U] = { 0U };

	ecdsap256_field_mul_raw(product, a, b);
	ecdsap256_mod_montgomery512(r, product, ECDSAP256_P, 1U);
	qsc_memutils_secure_erase(product, sizeof(product));
#endif
}

static void ecdsap256_fe_sqr(ecdsap256_field r, const ecdsap256_field a)
{
#if defined(ECDSAP256_NATIVE_64)
	uint64_t input[4U];
	uint64_t result[4U];
	uint64_t scratch[15U];

	ecdsap256_native_load(input, a);
	ecdsap256_native_square(result, input, scratch);
	ecdsap256_native_store(r, result);
	qsc_memutils_secure_erase(input, sizeof(input));
	qsc_memutils_secure_erase(result, sizeof(result));
	qsc_memutils_secure_erase(scratch, sizeof(scratch));
#else
	ecdsap256_fe_mul(r, a, a);
#endif
}

static void ecdsap256_fe_mul_small(ecdsap256_field r, const ecdsap256_field a, uint32_t k)
{
	/* multiply a field element by a small public scalar */
	ecdsap256_field doubled = { 0U };
	ecdsap256_field quadrupled = { 0U };

	if (k == 2U || k == 3U || k == 4U || k == 8U)
	{
		ecdsap256_fe_add(doubled, a, a);

		if (k == 2U)
		{
			ecdsap256_field_copy(r, doubled);
		}
		else if (k == 3U)
		{
			ecdsap256_fe_add(r, doubled, a);
		}
		else
		{
			ecdsap256_fe_add(quadrupled, doubled, doubled);

			if (k == 4U)
			{
				ecdsap256_field_copy(r, quadrupled);
			}
			else
			{
				ecdsap256_fe_add(r, quadrupled, quadrupled);
			}
		}
	}
	else
	{
		ecdsap256_field accumulator = { 0U };
		ecdsap256_field current = { 0U };
		ecdsap256_field summed = { 0U };
		uint32_t digit;
		size_t bit;

		ecdsap256_field_copy(current, a);

		for (bit = 0U; bit < 32U; ++bit)
		{
			ecdsap256_fe_add(summed, accumulator, current);
			digit = (k >> bit) & 1U;
			ecdsap256_field_ct_select(accumulator, digit, summed, accumulator);
			ecdsap256_fe_add(current, current, current);
		}

		ecdsap256_field_copy(r, accumulator);
		qsc_memutils_secure_erase(accumulator, sizeof(accumulator));
		qsc_memutils_secure_erase(current, sizeof(current));
		qsc_memutils_secure_erase(summed, sizeof(summed));
	}

	qsc_memutils_secure_erase(doubled, sizeof(doubled));
	qsc_memutils_secure_erase(quadrupled, sizeof(quadrupled));
}

static void ecdsap256_fe_inv(uint32_t r[8U], const uint32_t a[8U])
{
	static const uint32_t p_minus_2[8U] = {0xFFFFFFFDU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000001U, 0xFFFFFFFFU};
	uint32_t powers[16U][8U] = {{ 0U }};
	uint32_t accumulator[8U] = { 0U };
	uint32_t digit;
	size_t i;
	size_t j;

	ecdsap256_field_copy(powers[0U], ECDSAP256_MONT_ONE);
	ecdsap256_fe_copy(powers[1U], a);

	for (i = 2U; i < 16U; ++i)
	{
		ecdsap256_fe_mul(powers[i], powers[i - 1U], a);
	}

	ecdsap256_field_copy(accumulator, ECDSAP256_MONT_ONE);

	for (i = 64U; i > 0U; --i)
	{
		for (j = 0U; j < 4U; ++j)
		{
			ecdsap256_fe_sqr(accumulator, accumulator);
		}

		digit = (p_minus_2[(i - 1U) / 8U] >> (((uint32_t)((i - 1U) % 8U)) * 4U)) & 15U;
		ecdsap256_fe_mul(accumulator, accumulator, powers[digit]);
	}

	ecdsap256_fe_copy(r, accumulator);
	qsc_memutils_secure_erase(powers, sizeof(powers));
	qsc_memutils_secure_erase(accumulator, sizeof(accumulator));
}

#if !defined(ECDSAP256_NATIVE_64)

static void ecdsap256_sc256_mul_raw(uint32_t c[16U], const uint32_t a[8U], const uint32_t b[8U])
{
	/* 256x256 -> 512-bit schoolbook multiplication (same as ecdsap256_field_mul_raw,
     * reused for scalar field - separate alias for clarity). */
	ecdsap256_field_mul_raw(c, a, b);
}

static void ecdsap256_sc256_reduce512(uint32_t r[8U], const uint32_t c[16U])
{
	/* conservative correctness-first reduction of a 512-bit value modulo n.
     * replaces the previous Barrett reduction implementation. */
	ecdsap256_mod_reduce512_montgomery(r, c, ECDSAP256_N, 0xEE00BC4FU, ECDSAP256_N_R2);
}

#endif

#if !defined(ECDSAP256_NATIVE_64) || defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)

static void ecdsap256_sc_copy(uint32_t dst[8U], const uint32_t src[8U])
{
	size_t i;

	for (i = 0U; i < 8U; ++i)
	{
		dst[i] = src[i];
	}
}
#endif /* Native public scalar inversion selection */

#if !defined(ECDSAP256_NATIVE_64)

static void ecdsap256_sc_add(uint32_t* r, const uint32_t* a, const uint32_t* b)
{
	size_t i;
	uint32_t t[8U] = { 0U };
	uint32_t u[8U] = { 0U };
	uint64_t borrow;
	uint64_t carry;
	uint64_t x;
	uint32_t mask;
	uint32_t reduce;

	/* t = a + b mod 2^256, keep the carry */
	carry = 0U;

	for (i = 0U; i < 8U; ++i)
	{
		x = (uint64_t)a[i] + (uint64_t)b[i] + carry;
		t[i] = (uint32_t)x;
		carry = x >> 32U;
	}

	/* u = t - n */
	borrow = 0U;

	for (i = 0U; i < 8U; ++i)
	{
		x = (uint64_t)t[i] - (uint64_t)ECDSAP256_N[i] - borrow;
		u[i] = (uint32_t)x;
		borrow = (x >> 63U) & 1U;
	}

	/* reduce if carry occurred, or if t >= n (i.e. subtraction did not borrow) */
	reduce = (uint32_t)carry | (uint32_t)(1U ^ (uint32_t)borrow);
	mask = (uint32_t)(0U - reduce);

	for (i = 0U; i < 8U; ++i)
	{
		r[i] = (u[i] & mask) | (t[i] & ~mask);
	}

	qsc_memutils_secure_erase(t, sizeof(t));
	qsc_memutils_secure_erase(u, sizeof(u));
}
#endif

static void ecdsap256_sc_mul(uint32_t r[8U], const uint32_t a[8U], const uint32_t b[8U])
{
#if defined(ECDSAP256_NATIVE_64)
	ecdsap256_native_scalar_product(r, a, b);
#else
	uint32_t c[16U] = { 0U };

	ecdsap256_sc256_mul_raw(c, a, b);
	ecdsap256_sc256_reduce512(r, c);
	qsc_memutils_secure_erase(c, sizeof(c));
#endif
}

#if !defined(ECDSAP256_NATIVE_64) || defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)

static void ecdsap256_sc_mont_mul(uint32_t r[8U], const uint32_t a[8U], const uint32_t b[8U])
{
	/* compute one Montgomery product modulo the ECDSA subgroup order */
#if defined(ECDSAP256_NATIVE_64)
	uint64_t left[4U];
	uint64_t right[4U];
	uint64_t result[4U];
	uint64_t scratch[15U];

	ecdsap256_native_load(left, a);
	ecdsap256_native_load(right, b);
	ecdsap256_native_order_mul(result, left, right, scratch);
	ecdsap256_native_store(r, result);
	qsc_memutils_secure_erase(left, sizeof(left));
	qsc_memutils_secure_erase(right, sizeof(right));
	qsc_memutils_secure_erase(result, sizeof(result));
	qsc_memutils_secure_erase(scratch, sizeof(scratch));
#else
	uint32_t product[16U] = { 0U };

	ecdsap256_field_mul_raw(product, a, b);
	ecdsap256_mod_montgomery512(r, product, ECDSAP256_N, 0xEE00BC4FU);
	qsc_memutils_secure_erase(product, sizeof(product));
#endif
}
#endif

#if !defined(ECDSAP256_NATIVE_64) || defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)

static void ecdsap256_sc_mont_encode(uint32_t r[8U], const uint32_t a[8U])
{
	/* encode a canonical subgroup scalar into Montgomery representation */
	ecdsap256_sc_mont_mul(r, a, ECDSAP256_N_R2);
}
#endif

#if !defined(ECDSAP256_NATIVE_64) || defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)

static void ecdsap256_sc_mont_decode(uint32_t r[8U], const uint32_t a[8U])
{
	/* decode an ECDSA subgroup scalar from Montgomery representation */
	static const uint32_t one[8U] = {1U};

	ecdsap256_sc_mont_mul(r, a, one);
}
#endif

#if !defined(ECDSAP256_NATIVE_64) || defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)

static void ecdsap256_sc_mont_square_n(uint32_t value[8U], size_t count)
{
	/* envert a nonzero subgroup-order residue using a fixed public exponent */
	size_t i;

	for (i = 0U; i < count; ++i)
	{
		ecdsap256_sc_mont_mul(value, value, value);
	}
}
#endif

#if !defined(ECDSAP256_NATIVE_64) || defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)

static void ecdsap256_sc_inv_mont(uint32_t r[8U], const uint32_t a[8U])
{
	/* invert a nonzero Montgomery scalar using P-256 addition chain */
	uint32_t t[15U][8U] = {{ 0U }};
	uint32_t z[8U] = { 0U };

	ecdsap256_sc_mont_mul(t[1U], a, a);
	ecdsap256_sc_mont_mul(t[5U], t[1U], t[1U]);
	ecdsap256_sc_mont_mul(t[2U], t[5U], a);
	ecdsap256_sc_mont_mul(t[10U], t[2U], a);
	ecdsap256_sc_mont_mul(t[3U], t[2U], t[5U]);
	ecdsap256_sc_mont_mul(z, t[10U], t[3U]);
	ecdsap256_sc_mont_mul(t[9U], t[3U], t[3U]);
	ecdsap256_sc_mont_mul(t[4U], t[10U], z);
	ecdsap256_sc_mont_mul(t[0U], t[10U], t[9U]);
	ecdsap256_sc_mont_mul(t[13U], t[0U], t[1U]);
	ecdsap256_sc_mont_mul(t[8U], t[13U], t[4U]);
	ecdsap256_sc_mont_mul(t[4U], t[3U], t[8U]);
	ecdsap256_sc_mont_mul(t[7U], t[2U], t[4U]);
	ecdsap256_sc_mont_mul(t[2U], t[1U], t[7U]);
	ecdsap256_sc_mont_mul(t[6U], t[7U], t[9U]);
	ecdsap256_sc_mont_mul(t[3U], t[6U], t[9U]);
	ecdsap256_sc_mont_mul(t[1U], t[1U], t[3U]);
	ecdsap256_sc_mont_mul(t[12U], t[3U], t[9U]);
	ecdsap256_sc_mont_mul(t[5U], t[5U], t[12U]);
	ecdsap256_sc_mont_mul(t[11U], t[10U], t[5U]);
	ecdsap256_sc_mont_mul(t[0U], t[0U], t[11U]);
	ecdsap256_sc_mont_mul(t[9U], t[9U], t[0U]);
	ecdsap256_sc_mont_mul(t[10U], t[10U], t[9U]);
	ecdsap256_sc_mont_mul(t[4U], t[4U], t[10U]);
	ecdsap256_sc_mont_mul(t[13U], t[13U], t[4U]);
	ecdsap256_sc_copy(t[14U], t[13U]);
	ecdsap256_sc_mont_square_n(t[14U], 8U);
	ecdsap256_sc_mont_mul(t[13U], t[13U], t[14U]);
	ecdsap256_sc_copy(t[14U], t[13U]);
	ecdsap256_sc_mont_square_n(t[14U], 16U);
	ecdsap256_sc_mont_mul(t[14U], t[14U], t[13U]);
	ecdsap256_sc_mont_square_n(t[14U], 48U);
	ecdsap256_sc_mont_mul(t[14U], t[14U], t[13U]);
	ecdsap256_sc_mont_square_n(t[14U], 16U);
	ecdsap256_sc_mont_mul(t[14U], t[14U], t[13U]);
	ecdsap256_sc_mont_square_n(t[14U], 16U);
	ecdsap256_sc_mont_mul(t[14U], t[14U], t[13U]);
	ecdsap256_sc_mont_square_n(t[14U], 16U);
	ecdsap256_sc_mont_mul(t[13U], t[13U], t[14U]);
	ecdsap256_sc_mont_square_n(t[13U], 6U);
	ecdsap256_sc_mont_mul(t[13U], t[13U], t[8U]);
	ecdsap256_sc_mont_square_n(t[13U], 9U);
	ecdsap256_sc_mont_mul(t[12U], t[12U], t[13U]);
	ecdsap256_sc_mont_square_n(t[12U], 8U);
	ecdsap256_sc_mont_mul(t[11U], t[11U], t[12U]);
	ecdsap256_sc_mont_square_n(t[11U], 9U);
	ecdsap256_sc_mont_mul(t[10U], t[10U], t[11U]);
	ecdsap256_sc_mont_square_n(t[10U], 8U);
	ecdsap256_sc_mont_mul(t[9U], t[9U], t[10U]);
	ecdsap256_sc_mont_square_n(t[9U], 9U);
	ecdsap256_sc_mont_mul(t[8U], t[8U], t[9U]);
	ecdsap256_sc_mont_square_n(t[8U], 8U);
	ecdsap256_sc_mont_mul(t[7U], t[7U], t[8U]);
	ecdsap256_sc_mont_square_n(t[7U], 11U);
	ecdsap256_sc_mont_mul(t[6U], t[6U], t[7U]);
	ecdsap256_sc_mont_square_n(t[6U], 9U);
	ecdsap256_sc_mont_mul(t[5U], t[5U], t[6U]);
	ecdsap256_sc_mont_square_n(t[5U], 10U);
	ecdsap256_sc_mont_mul(t[4U], t[4U], t[5U]);
	ecdsap256_sc_mont_square_n(t[4U], 8U);
	ecdsap256_sc_mont_mul(t[3U], t[3U], t[4U]);
	ecdsap256_sc_mont_square_n(t[3U], 7U);
	ecdsap256_sc_mont_mul(t[2U], t[2U], t[3U]);
	ecdsap256_sc_mont_square_n(t[2U], 10U);
	ecdsap256_sc_mont_mul(t[1U], t[1U], t[2U]);
	ecdsap256_sc_mont_square_n(t[1U], 10U);
	ecdsap256_sc_mont_mul(t[0U], t[0U], t[1U]);
	ecdsap256_sc_mont_square_n(t[0U], 6U);
	ecdsap256_sc_mont_mul(z, z, t[0U]);

	ecdsap256_sc_copy(r, z);
	qsc_memutils_secure_erase(t, sizeof(t));
	qsc_memutils_secure_erase(z, sizeof(z));
}
#endif

#if defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)

static void ecdsap256_sc_inv(uint32_t r[8U], const uint32_t a[8U])
{
	/* invert a canonical P-256 order scalar for constant-time verification */
	uint32_t mont[8U] = { 0U };

	ecdsap256_sc_mont_encode(mont, a);
	ecdsap256_sc_inv_mont(mont, mont);
	ecdsap256_sc_mont_decode(r, mont);
	qsc_memutils_secure_erase(mont, sizeof(mont));
}
#endif

static void ecdsap256_sc_from_bytes_reduce(uint32_t r[8U], const uint8_t b[32U])
{
	/* reduce a 256-bit big-endian byte array mod n into a little-endian ecdsap256_field */
	ecdsap256_field_from_bytes(r, b);
	ecdsap256_field_cond_sub(r, ECDSAP256_N);
}

/* Elliptic curve point arithmetic (Jacobian projective coordinates) */

static uint32_t ecdsap256_is_infinity(const ecdsap256_jac_t* P)
{
	/* return 1 if the Jacobian point is the point at infinity (Z == 0) */
	return ecdsap256_field_is_zero(P->Z);
}

static void ecdsap256_aff_to_jac(ecdsap256_jac_t* R, const ecdsap256_aff_t* P)
{
	/* lift an affine point to Jacobian (Z = 1) */
	ecdsap256_field_copy(R->X, P->X);
	ecdsap256_field_copy(R->Y, P->Y);
	ecdsap256_field_one(R->Z);
}

static void ecdsap256_set_infinity(ecdsap256_jac_t* R)
{
	/* set Jacobian point to the point at infinity */
	ecdsap256_field_zero(R->X);
	ecdsap256_field_one(R->Y);
	ecdsap256_field_zero(R->Z);
}

static void ecdsap256_dbl(ecdsap256_jac_t* R, const ecdsap256_jac_t* P)
{
	/* branch-free Jacobian doubling.
	* for the Jacobian point-at-infinity representation used here, a result
	* with Z == 0 is treated as infinity by the rest of the code. */
	ecdsap256_field delta;
	ecdsap256_field gamma;
	ecdsap256_field beta;
	ecdsap256_field alpha;
	ecdsap256_field tmp;
	ecdsap256_field x3;
	ecdsap256_field y3;
	ecdsap256_field z3;

	/* delta = Z1^2 */
	ecdsap256_fe_sqr(delta, P->Z);

	/* gamma = Y1^2 */
	ecdsap256_fe_sqr(gamma, P->Y);

	/* beta = X1 * gamma */
	ecdsap256_fe_mul(beta, P->X, gamma);

	/* alpha = 3 * (X1 - delta) * (X1 + delta) */
	ecdsap256_fe_sub(alpha, P->X, delta);
	ecdsap256_fe_add(tmp, P->X, delta);
	ecdsap256_fe_mul(alpha, alpha, tmp);
	ecdsap256_fe_mul_small(alpha, alpha, 3U);

	/* X3 = alpha^2 - 8*beta */
	ecdsap256_fe_sqr(x3, alpha);
	ecdsap256_fe_mul_small(tmp, beta, 8U);
	ecdsap256_fe_sub(x3, x3, tmp);

	/* Z3 = (Y1 + Z1)^2 - gamma - delta */
	ecdsap256_fe_add(z3, P->Y, P->Z);
	ecdsap256_fe_sqr(z3, z3);
	ecdsap256_fe_sub(z3, z3, gamma);
	ecdsap256_fe_sub(z3, z3, delta);

	/* Y3 = alpha * (4*beta - X3) - 8*gamma^2 */
	ecdsap256_fe_mul_small(tmp, beta, 4U);
	ecdsap256_fe_sub(tmp, tmp, x3);
	ecdsap256_fe_mul(y3, alpha, tmp);
	ecdsap256_fe_sqr(tmp, gamma);
	ecdsap256_fe_mul_small(tmp, tmp, 8U);
	ecdsap256_fe_sub(y3, y3, tmp);

	ecdsap256_field_copy(R->X, x3);
	ecdsap256_field_copy(R->Y, y3);
	ecdsap256_field_copy(R->Z, z3);

	qsc_memutils_secure_erase(delta, sizeof(delta));
	qsc_memutils_secure_erase(gamma, sizeof(gamma));
	qsc_memutils_secure_erase(beta, sizeof(beta));
	qsc_memutils_secure_erase(alpha, sizeof(alpha));
	qsc_memutils_secure_erase(tmp, sizeof(tmp));
	qsc_memutils_secure_erase(x3, sizeof(x3));
	qsc_memutils_secure_erase(y3, sizeof(y3));
	qsc_memutils_secure_erase(z3, sizeof(z3));
}

static void ecdsap256_add(ecdsap256_jac_t* R, const ecdsap256_jac_t* P, const ecdsap256_jac_t* Q)
{
	/* Constant-time Jacobian addition with masked exceptional-case handling.
     *
     * Cases handled without branches:
     *   1. P = inf  -> R = Q
     *   2. Q = inf  -> R = P
     *   3. P = Q    -> R = 2P
     *   4. P = -Q   -> R = inf
     *   5. general  -> standard add-2007-bl result */

	ecdsap256_field z1z1;
	ecdsap256_field z2z2;
	ecdsap256_field u1;
	ecdsap256_field u2;
	ecdsap256_field s1;
	ecdsap256_field s2;
	ecdsap256_field h;
	ecdsap256_field r2;
	ecdsap256_field i;
	ecdsap256_field j;
	ecdsap256_field v;
	ecdsap256_field x3;
	ecdsap256_field y3;
	ecdsap256_field z3;
	ecdsap256_field tmp;
	ecdsap256_jac_t Radd;
	ecdsap256_jac_t Rdbl;
	ecdsap256_jac_t Rinf;
	uint32_t pinf;
	uint32_t qinf;
	uint32_t hzer;
	uint32_t rzer;
	uint32_t smpt;
	uint32_t oppt;
	uint32_t genc;
	ecdsap256_jac_t T;

	/* generic add candidate */
	ecdsap256_fe_sqr(z1z1, P->Z);
	ecdsap256_fe_sqr(z2z2, Q->Z);

	ecdsap256_fe_mul(u1, P->X, z2z2);
	ecdsap256_fe_mul(u2, Q->X, z1z1);

	ecdsap256_fe_mul(s1, P->Y, Q->Z);
	ecdsap256_fe_mul(s1, s1, z2z2);

	ecdsap256_fe_mul(s2, Q->Y, P->Z);
	ecdsap256_fe_mul(s2, s2, z1z1);

	ecdsap256_fe_sub(h, u2, u1);
	ecdsap256_fe_sub(r2, s2, s1);
	ecdsap256_fe_mul_small(r2, r2, 2U);

	ecdsap256_fe_mul_small(i, h, 2U);
	ecdsap256_fe_sqr(i, i);
	ecdsap256_fe_mul(j, h, i);
	ecdsap256_fe_mul(v, u1, i);

	ecdsap256_fe_sqr(x3, r2);
	ecdsap256_fe_sub(x3, x3, j);
	ecdsap256_fe_sub(x3, x3, v);
	ecdsap256_fe_sub(x3, x3, v);

	ecdsap256_fe_sub(tmp, v, x3);
	ecdsap256_fe_mul(y3, r2, tmp);

	ecdsap256_fe_mul(tmp, s1, j);
	ecdsap256_fe_mul_small(tmp, tmp, 2U);
	ecdsap256_fe_sub(y3, y3, tmp);

	ecdsap256_fe_add(z3, P->Z, Q->Z);
	ecdsap256_fe_sqr(z3, z3);
	ecdsap256_fe_sub(z3, z3, z1z1);
	ecdsap256_fe_sub(z3, z3, z2z2);
	ecdsap256_fe_mul(z3, z3, h);

	ecdsap256_field_copy(Radd.X, x3);
	ecdsap256_field_copy(Radd.Y, y3);
	ecdsap256_field_copy(Radd.Z, z3);

	/* doubling candidate */
	ecdsap256_dbl(&Rdbl, P);

	/* infinity candidate */
	ecdsap256_set_infinity(&Rinf);

	/* masks */
	pinf = ecdsap256_is_infinity(P);
	qinf = ecdsap256_is_infinity(Q);
	hzer = ecdsap256_field_is_zero(h);
	rzer = ecdsap256_field_is_zero(r2);

	smpt = hzer & rzer;
	oppt = hzer & (rzer ^ 1U);

	/* general case is only selected when no exceptional case applies */
	genc = (pinf | qinf | smpt | oppt) ^ 1U;

	/* start from infinity so all paths are explicit */
	ecdsap256_set_infinity(&T);

	/* general add */
	ecdsap256_jac_ct_select(&T, genc, &Radd, &T);

	/* P == Q */
	ecdsap256_jac_ct_select(&T, smpt, &Rdbl, &T);

	/* P == -Q */
	ecdsap256_jac_ct_select(&T, oppt, &Rinf, &T);

	/* Q = inf => R = P */
	ecdsap256_jac_ct_select(&T, qinf, P, &T);

	/* P = inf => R = Q */
	ecdsap256_jac_ct_select(&T, pinf, Q, &T);

	*R = T;

	qsc_memutils_secure_erase(&Radd, sizeof(Radd));
	qsc_memutils_secure_erase(&Rdbl, sizeof(Rdbl));
	qsc_memutils_secure_erase(&Rinf, sizeof(Rinf));
	qsc_memutils_secure_erase(&T, sizeof(T));
}

#if defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)

static void ecdsap256_add_mixed(ecdsap256_jac_t* R, const ecdsap256_jac_t* P, const ecdsap256_jac_t* Q)
{
	/* constant-time Jacobian plus affine-point addition with masked exceptional cases */
	ecdsap256_field z1z1;
	ecdsap256_field u2;
	ecdsap256_field s2;
	ecdsap256_field h;
	ecdsap256_field r2;
	ecdsap256_field i;
	ecdsap256_field j;
	ecdsap256_field v;
	ecdsap256_field x3;
	ecdsap256_field y3;
	ecdsap256_field z3;
	ecdsap256_field tmp;
	ecdsap256_jac_t sum;
	ecdsap256_jac_t doubled;
	ecdsap256_jac_t infinity;
	ecdsap256_jac_t selected;
	uint32_t pinf;
	uint32_t qinf;
	uint32_t hzero;
	uint32_t rzero;
	uint32_t equal;
	uint32_t opposite;
	uint32_t regular;

	ecdsap256_fe_sqr(z1z1, P->Z);
	ecdsap256_fe_mul(u2, Q->X, z1z1);
	ecdsap256_fe_mul(s2, Q->Y, P->Z);
	ecdsap256_fe_mul(s2, s2, z1z1);
	ecdsap256_fe_sub(h, u2, P->X);
	ecdsap256_fe_sub(r2, s2, P->Y);
	ecdsap256_fe_mul_small(r2, r2, 2U);
	ecdsap256_fe_mul_small(i, h, 2U);
	ecdsap256_fe_sqr(i, i);
	ecdsap256_fe_mul(j, h, i);
	ecdsap256_fe_mul(v, P->X, i);
	ecdsap256_fe_sqr(x3, r2);
	ecdsap256_fe_sub(x3, x3, j);
	ecdsap256_fe_sub(x3, x3, v);
	ecdsap256_fe_sub(x3, x3, v);
	ecdsap256_fe_sub(tmp, v, x3);
	ecdsap256_fe_mul(y3, r2, tmp);
	ecdsap256_fe_mul(tmp, P->Y, j);
	ecdsap256_fe_mul_small(tmp, tmp, 2U);
	ecdsap256_fe_sub(y3, y3, tmp);
	ecdsap256_fe_mul(z3, P->Z, h);
	ecdsap256_fe_mul_small(z3, z3, 2U);
	ecdsap256_field_copy(sum.X, x3);
	ecdsap256_field_copy(sum.Y, y3);
	ecdsap256_field_copy(sum.Z, z3);

	ecdsap256_dbl(&doubled, P);
	ecdsap256_set_infinity(&infinity);
	pinf = ecdsap256_is_infinity(P);
	qinf = ecdsap256_is_infinity(Q);
	hzero = ecdsap256_field_is_zero(h);
	rzero = ecdsap256_field_is_zero(r2);
	equal = hzero & rzero;
	opposite = hzero & (rzero ^ 1U);
	regular = (pinf | qinf | equal | opposite) ^ 1U;
	ecdsap256_set_infinity(&selected);
	ecdsap256_jac_ct_select(&selected, regular, &sum, &selected);
	ecdsap256_jac_ct_select(&selected, equal, &doubled, &selected);
	ecdsap256_jac_ct_select(&selected, opposite, &infinity, &selected);
	ecdsap256_jac_ct_select(&selected, qinf, P, &selected);
	ecdsap256_jac_ct_select(&selected, pinf, Q, &selected);
	*R = selected;

	qsc_memutils_secure_erase(&sum, sizeof(sum));
	qsc_memutils_secure_erase(&doubled, sizeof(doubled));
	qsc_memutils_secure_erase(&infinity, sizeof(infinity));
	qsc_memutils_secure_erase(&selected, sizeof(selected));
}
#endif

static uint32_t ecdsap256_booth_digit(const uint32_t scalar[10U], size_t window, uint32_t* negative)
{
	uint64_t value;
	uint32_t raw;
	uint32_t mask;
	size_t bit;
	size_t word;

	if (window == 0U)
	{
		raw = (scalar[0U] & 63U) << 1U;
	}
	else
	{
		bit = 6U * window - 1U;
		word = bit / 32U;
		value = (uint64_t)scalar[word] | ((uint64_t)scalar[word + 1U] << 32U);
		raw = (uint32_t)(value >> (bit % 32U)) & 127U;
	}

	*negative = raw >> 6U;
	mask = 0U - *negative;
	raw ^= mask & 127U;

	return (raw >> 1U) + (raw & 1U);
}

static bool ecdsap256_generator_blinding(uint32_t scalar[10U], ecdsap256_field factors[4U], const uint32_t input[8U])
{
	uint8_t random[164U] = { 0U };
	uint32_t wide[16U] = { 0U };
	uint32_t reduced[8U] = { 0U };
	uint32_t mask;
	uint64_t carry;
	uint64_t value;
	size_t i;
	size_t j;
	bool ok;

	qsc_memutils_clear(scalar, 10U * sizeof(uint32_t));
	qsc_memutils_clear(factors, 4U * sizeof(ecdsap256_field));
	ok = qsc_csp_generate(random, sizeof(random));

	if (ok)
	{
		mask = qsc_intutils_le8to32(random) | 0x80000001U;
		carry = 0U;

		for (i = 0U; i < 8U; ++i)
		{
			value = (uint64_t)ECDSAP256_N[i] * mask + input[i] + carry;
			scalar[i] = (uint32_t)value;
			carry = value >> 32U;
		}

		scalar[8U] = (uint32_t)carry;

		for (i = 0U; i < 4U; ++i)
		{
			for (j = 0U; j < 10U; ++j)
			{
				wide[j] = qsc_intutils_be8to32(random + 4U + i * 40U + (9U - j) * 4U);
			}

			/* REDC then two encodings maps the 320-bit sample to sample*R. */
			ecdsap256_mod_montgomery512(reduced, wide, ECDSAP256_P, 1U);
			ecdsap256_field_mont_encode(reduced, reduced);
			ecdsap256_field_mont_encode(factors[i], reduced);
			ecdsap256_field_ct_select(factors[i], ecdsap256_field_is_zero(factors[i]), ECDSAP256_MONT_ONE, factors[i]);
		}
	}

	qsc_memutils_secure_erase(random, sizeof(random));
	qsc_memutils_secure_erase(wide, sizeof(wide));
	qsc_memutils_secure_erase(reduced, sizeof(reduced));

	return ok;
}

/*!
 * \brief 6-bit signed Booth generator table in Montgomery form.
 * \details Entry [i][j] is (j+1) * 2^(6*i) * G; coordinates are eight
 * little-endian 32-bit words. The 49 windows cover a 288-bit blinded scalar
 * plus its carry. Constants are generated from the NIST domain parameters.
 * Read-only, shared and thread-safe. Secret lookups scan all 32 entries.
 */
static const uint32_t ECDSAP256_GENERATOR_TABLE[49U][32U][2U][8U] = {
	{
		{{0x18A9143CU, 0x79E730D4U, 0x5FEDB601U, 0x75BA95FCU, 0x77622510U, 0x79FB732BU, 0xA53755C6U, 0x18905F76U},
			{0xCE95560AU, 0xDDF25357U, 0xBA19E45CU, 0x8B4AB8E4U, 0xDD21F325U, 0xD2E88688U, 0x25885D85U, 0x8571FF18U}},
		{{0x10DDD64DU, 0x850046D4U, 0xA433827DU, 0xAA6AE3C1U, 0x8D1490D9U, 0x73220503U, 0x3DCF3A3BU, 0xF6BB32E4U},
			{0x61BEE1A5U, 0x2F3648D3U, 0xEB236FF8U, 0x152CD7CBU, 0x92042DBEU, 0x19A8FB0EU, 0x0A5B8A3BU, 0x78C57751U}},
		{{0x4EEBC127U, 0xFFAC3F90U, 0x087D81FBU, 0xB027F84AU, 0x87CBBC98U, 0x66AD77DDU, 0xB6FF747EU, 0x26936A3FU},
			{0xC983A7EBU, 0xB04C5C1FU, 0x0861FE1AU, 0x583E47ADU, 0x1A2EE98EU, 0x78820831U, 0xE587CC07U, 0xD5F06A29U}},
		{{0x46918DCCU, 0x74B0B50DU, 0xC623C173U, 0x4650A6EDU, 0xE8100AF2U, 0x0CDAACACU, 0x41B0176BU, 0x577362F5U},
			{0xE4CBABA6U, 0x2D96F24CU, 0xFAD6F447U, 0x17628471U, 0xE5DDD22EU, 0x6B6C36DEU, 0x4C5AB863U, 0x84B14C39U}},
		{{0xC45C61F5U, 0xBE1B8AAEU, 0x94B9537DU, 0x90EC649AU, 0xD076C20CU, 0x941CB5AAU, 0x890523C8U, 0xC9079605U},
			{0xE7BA4F10U, 0xEB309B4AU, 0xE5EB882BU, 0x73C568EFU, 0x7E7A1F68U, 0x3540A987U, 0x2DD1E916U, 0x73A076BBU}},
		{{0x3E77664AU, 0x40394737U, 0x346CEE3EU, 0x55AE744FU, 0x5B17A3ADU, 0xD50A961AU, 0x54213673U, 0x13074B59U},
			{0xD377E44BU, 0x93D36220U, 0xADFF14B5U, 0x299C2B53U, 0xEF639F11U, 0xF424D44CU, 0x4A07F75FU, 0xA4C9916DU}},
		{{0xA0173B4FU, 0x0746354EU, 0xD23C00F7U, 0x2BD20213U, 0x0C23BB08U, 0xF43EAAB5U, 0xC3123E03U, 0x13BA5119U},
			{0x3F5B9D4DU, 0x2847D030U, 0x5DA67BDDU, 0x6742F2F2U, 0x77C94195U, 0xEF933BDCU, 0x6E240867U, 0xEAEDD915U}},
		{{0x9499A78FU, 0x27F14CD1U, 0x6F9B3455U, 0x462AB5C5U, 0xF02CFC6BU, 0x8F90F02AU, 0xB265230DU, 0xB763891EU},
			{0x532D4977U, 0xF59DA3A9U, 0xCF9EBA15U, 0x21E3327DU, 0xBE60BBF0U, 0x123C7B84U, 0x7706DF76U, 0x56EC12F2U}},
		{{0x264E20E8U, 0x75C96E8FU, 0x59A7A841U, 0xABE6BFEDU, 0x44C8EB00U, 0x2CC09C04U, 0xF0C4E16BU, 0xE05B3080U},
			{0xA45F3314U, 0x1EB7777AU, 0xCE5D45E3U, 0x56AF7BEDU, 0x88B12F1AU, 0x2B6E019AU, 0xFD835F9BU, 0x086659CDU}},
		{{0x9DC21EC8U, 0x2C18DBD1U, 0x0FCF8139U, 0x98F9868AU, 0x48250B49U, 0x737D2CD6U, 0x24B3428FU, 0xCC61C947U},
			{0x80DD9E76U, 0x0C2B4078U, 0x383FBE08U, 0xC43A8991U, 0x779BE5D2U, 0x5F7D2D65U, 0xEB3B4AB5U, 0x78719A54U}},
		{{0x6245E404U, 0xEA7D260AU, 0x6E7FDFE0U, 0x9DE40795U, 0x8DAC1AB5U, 0x1FF3A415U, 0x649C9073U, 0x3E7090F1U},
			{0x2B944E88U, 0x1A768561U, 0xE57F61C8U, 0x250F939EU, 0x1EAD643DU, 0x0C0DAA89U, 0xE125B88EU, 0x68930023U}},
		{{0xD2697768U, 0x04B71AA7U, 0xCA345A33U, 0xABDEDEF5U, 0xEE37385EU, 0x2409D29DU, 0xCB83E156U, 0x4EE1DF77U},
			{0x1CBB5B43U, 0x0CAC12D9U, 0xCA895637U, 0x170ED2F6U, 0x8ADE6D66U, 0x28228CFAU, 0x53238ACAU, 0x7FF57C95U}},
		{{0x4B2ED709U, 0xCCC42563U, 0x856FD30DU, 0x0E356769U, 0x559E9811U, 0xBCBCD43FU, 0x5395B759U, 0x738477ACU},
			{0xC00EE17FU, 0x35752B90U, 0x742ED2E3U, 0x68748390U, 0xBD1F5BC1U, 0x7CD06422U, 0xC9E7B797U, 0xFBC08769U}},
		{{0xB0CF664AU, 0xA242A35BU, 0x7F9707E3U, 0x126E48F7U, 0xC6832660U, 0x1717BF54U, 0xFD12C72EU, 0xFAAE7332U},
			{0x995D586BU, 0x27B52DB7U, 0x832237C2U, 0xBE29569EU, 0x2A65E7DBU, 0xE8E4193EU, 0x2EAA1BBBU, 0x152706DCU}},
		{{0xBC60055BU, 0x72BCD8B7U, 0x56E27E4BU, 0x03CC23EEU, 0xE4819370U, 0xEE337424U, 0x0AD3DA09U, 0xE2AA0E43U},
			{0x6383C45DU, 0x40B8524FU, 0x42A41B25U, 0xD7663554U, 0x778A4797U, 0x64EFA6DEU, 0x7079ADF4U, 0x2042170AU}},
		{{0x0BC6FB80U, 0x808B0B65U, 0x3FFE2E6BU, 0x5882E075U, 0x2C83F549U, 0xD5EF2F7CU, 0x9103B723U, 0x54D63C80U},
			{0x52A23F9BU, 0xF2F11BD6U, 0x4B0B6587U, 0x3670C319U, 0xB1580E9EU, 0x55C4623BU, 0x01EFE220U, 0x64EDF7B2U}},
		{{0xD53C5C9DU, 0x97091DCBU, 0xAC0A177BU, 0xF17624B6U, 0x2CFE2DFFU, 0xB0F13975U, 0x6C7A574EU, 0xC1A35C0AU},
			{0x93E79987U, 0x227D3146U, 0xE89CB80EU, 0x0575BF30U, 0x0D1883BBU, 0x2F4E247FU, 0x3274C3D0U, 0xEBD51226U}},
		{{0x56ADA97AU, 0x5F3E51C8U, 0x8F8B403EU, 0x4AFC964DU, 0x412E2979U, 0xA6F247ABU, 0x6F80EBDAU, 0x675ABD1BU},
			{0x5E485A1DU, 0x66A2BD72U, 0x8F4F0B3CU, 0x4B2A5CAFU, 0x1B847BBAU, 0x2626927FU, 0x0502394DU, 0x6C6FC7D9U}},
		{{0xA5659AE8U, 0xFEA912BAU, 0x25E1A16EU, 0x68363ABAU, 0x752C41ACU, 0xB8842277U, 0x2897C3FCU, 0xFE545C28U},
			{0xDC4C696BU, 0x2D36E9E7U, 0xFBA977C5U, 0x5806244AU, 0xE39508C1U, 0x85665E9BU, 0x6D12597BU, 0xF720EE25U}},
		{{0xD2337A31U, 0x8A979129U, 0x0F862BDCU, 0x5916868FU, 0x5DD283BAU, 0x048099D9U, 0xFE5BFB4EU, 0xE2D1EEB6U},
			{0x7884005DU, 0x82EF1C41U, 0xFFFFCBAEU, 0xA2D4EC17U, 0x8AA95E66U, 0x9161C53FU, 0xC5FEE0D0U, 0x5EE104E1U}},
		{{0xC135B208U, 0x562E4CECU, 0x4783F47DU, 0x74E1B265U, 0x5A3F3B30U, 0x6D2A506CU, 0xC16762FCU, 0xECEAD9F4U},
			{0xE286E5B9U, 0xF29DD4B2U, 0x83BB3C61U, 0x1B0FADC0U, 0x7FAC29A4U, 0x7A75023EU, 0xC9477FA3U, 0xC086D5F1U}},
		{{0x2F6F3076U, 0x0FC61135U, 0xE3912A9AU, 0xC99FFA23U, 0xD2F8BA3DU, 0x6A0B0685U, 0xE93358A4U, 0xFDC777E8U},
			{0x35415F04U, 0x94A787BBU, 0x4D23FEA4U, 0x640C2D6AU, 0x153A35B5U, 0x9DE917DAU, 0x5D5CD074U, 0x793E8D07U}},
		{{0x2DE45068U, 0xF4F87653U, 0x9E2E1F6EU, 0x37C7A7E8U, 0xA3584069U, 0xD0825FA2U, 0x1727BF42U, 0xAF2CEA7CU},
			{0x9E4785A9U, 0x0360A4FBU, 0x27299F4AU, 0xE5FDA49CU, 0x71AC2F71U, 0x48068E13U, 0x9077666FU, 0x83D0687BU}},
		{{0x15D02819U, 0x6D3883B2U, 0x40DD9A35U, 0x6D0D7550U, 0x1D2B469FU, 0x61D7CBF9U, 0x2EFC3115U, 0xF97B232FU},
			{0xB24BCBC7U, 0xA551D750U, 0x88A1E356U, 0x11EA4949U, 0x93CB7501U, 0x7669F031U, 0xCA737B8AU, 0x595DC55EU}},
		{{0xD837879FU, 0xA4A319ACU, 0xED6B67B0U, 0x6FC1B49EU, 0x32F1F3AFU, 0xE3959933U, 0x65432A2EU, 0x966742EBU},
			{0xB4966228U, 0x4B8DC9FEU, 0x43F43950U, 0x96CC6312U, 0xC9B731EEU, 0x12068859U, 0x56F79968U, 0x7B948DC3U}},
		{{0xED1F8008U, 0x61E4AD32U, 0xD8B17538U, 0xE6C9267AU, 0x857FF6FBU, 0x1AC7C5EBU, 0x55F2FB10U, 0x994BAAA8U},
			{0x1D248018U, 0x84CF14E1U, 0x628AC508U, 0x5A39898BU, 0x5FA944F5U, 0x14FDE97BU, 0xD12E5AC7U, 0xED178030U}},
		{{0x97E2FEB4U, 0x042C2AF4U, 0xAEBF7313U, 0xD36A42D7U, 0x084FFDD7U, 0x49D2C9EBU, 0x2EF7C76AU, 0x9F8AA54BU},
			{0x09895E70U, 0x9200B7BAU, 0xDDB7FB58U, 0x3BD0C66FU, 0x78EB4CBBU, 0x2D97D108U, 0xD84BDE31U, 0x2D431068U}},
		{{0x172CCD1FU, 0x4B523EB7U, 0x30A6A892U, 0x7323CB28U, 0xCFE153EBU, 0x97082EC0U, 0xF2AADB97U, 0xE97F6B6AU},
			{0xD1A83DA1U, 0x1D3D393EU, 0x804B2A68U, 0xA6A7F9C7U, 0x2D0CB71EU, 0x4A688B48U, 0x40585278U, 0xA9B4CC5FU}},
		{{0xCB66E132U, 0x5E5DB46AU, 0x0D925880U, 0xF1BE963AU, 0x0317B9E2U, 0x944A7027U, 0x48603D48U, 0xE266F959U},
			{0x5C208899U, 0x98DB6673U, 0xA2FB18A3U, 0x90472447U, 0x777C619FU, 0x8A966939U, 0x2A3BE21BU, 0x3798142AU}},
		{{0x3298B343U, 0xB4241CB1U, 0xB44F65A1U, 0xA3A14E49U, 0x3AC77ACDU, 0xC5F4D6CDU, 0x52B6FC3CU, 0xD0288CB5U},
			{0x1C040ABCU, 0xD5CC8C2FU, 0x06BF9B4AU, 0xB675511EU, 0x9B3AA441U, 0xD667DA37U, 0x51601F72U, 0x460D45CEU}},
		{{0x6755FF89U, 0xE2F73C69U, 0x473017E6U, 0xDD3CF7E7U, 0x3CF7600DU, 0x8EF5689DU, 0xB1FC87B4U, 0x948DC4F8U},
			{0x4EA53299U, 0xD9E9FE81U, 0x98EB6028U, 0x2D921CA2U, 0x0C9803FCU, 0xFAECEDFDU, 0x4D7B4745U, 0xF38AE891U}},
		{{0xC5E3A3D8U, 0xD8C5FCCFU, 0x4079DFBFU, 0xBEFD904CU, 0xFEAD0197U, 0xBC6D6A58U, 0x695532A4U, 0x39227077U},
			{0xDBEF42F5U, 0x09E23E6DU, 0x480A9908U, 0x7E449B64U, 0xAD9A2E40U, 0x7B969C1AU, 0x9591C2A4U, 0x6231D792U}},
	},
	{
		{{0x05968B80U, 0xDB6D96F3U, 0x089F73B9U, 0x380A0913U, 0xC2C61E01U, 0x7DA70B83U, 0x569B38C7U, 0x95FB8394U},
			{0x80EDFE2FU, 0x9A3C6512U, 0x8FAEAF82U, 0x8F726BB9U, 0x78424BF8U, 0x8010A4A0U, 0x0E844970U, 0x29672044U}},
		{{0x7A2AD62AU, 0x63C5CB81U, 0xAC62FF54U, 0x7EF2B6B9U, 0xB3AD9DB5U, 0x3749BBA4U, 0x46D5A617U, 0xAD311F2CU},
			{0xC2FF3B6DU, 0xB77A8087U, 0x367834FFU, 0xB46FEAF3U, 0x75D6B138U, 0xF8AA266DU, 0xEC008188U, 0xFA38D320U}},
		{{0x4E6916C6U, 0xC0F2AFFCU, 0x811842DAU, 0x6FB94957U, 0x24B4D157U, 0x6034BCB6U, 0x992EFB90U, 0xDE2EFDC7U},
			{0xAC793C87U, 0xD66F7ECEU, 0x7DC6FDCDU, 0x02F02626U, 0x9AA1C501U, 0x90D3235CU, 0x2B4666F0U, 0xF6E49496U}},
		{{0x696946FCU, 0x486D8FFAU, 0xB9CBA56DU, 0x50FBC6D8U, 0x90F35A15U, 0x7E3D423EU, 0xC0DD962CU, 0x7C3DA195U},
			{0x3CFD5D8BU, 0xE673FDB0U, 0x889DFCA5U, 0x0704B7C2U, 0xF52305AAU, 0xF6CE581FU, 0x914D5E53U, 0x399D49EBU}},
		{{0x7B92D453U, 0x24C97C36U, 0x249A26C0U, 0xD2C271A2U, 0x89D14A39U, 0x60EB4B2BU, 0x432E8005U, 0x1198DE20U},
			{0x799B80D9U, 0x9EABEA75U, 0x8F826AE5U, 0xAB6E0C2BU, 0xD10061ECU, 0xCA004EEDU, 0xE99C4FD8U, 0x31A9F439U}},
		{{0x6EC293CDU, 0x380A496DU, 0x8E7051F5U, 0x733DBDA7U, 0xB849140AU, 0x037E388DU, 0x5946DBF6U, 0xEE4B32B0U},
			{0xCAE368D1U, 0xB1C4FDA9U, 0xFDB0B2F3U, 0x5001A7B0U, 0x2E3AC46EU, 0x6DF59374U, 0x39B3E656U, 0x4AF675F2U}},
		{{0xD67826EBU, 0xB20E7C44U, 0xAC379637U, 0x1212D3CFU, 0x7DE03A5DU, 0x614F6787U, 0x802BAA26U, 0x7538A2FCU},
			{0x9D252415U, 0x133C37A1U, 0x6EB4B587U, 0x7DB39050U, 0x4C49D1D9U, 0x5D40D757U, 0xA801C4BAU, 0xF1126B99U}},
		{{0x39949296U, 0x44E38110U, 0x361DB1B5U, 0x5B63827BU, 0x206EAFF5U, 0x3E5323EDU, 0xC21F4290U, 0x942370D2U},
			{0xE0D985A1U, 0xF2CAAF2EU, 0x7239846DU, 0x192CC64BU, 0xAE6312F8U, 0x7C0B8F47U, 0x96620108U, 0x7DC61F91U}},
		{{0x70961147U, 0x40FFC996U, 0xC7C22C8CU, 0x79E06842U, 0x1A97BBBDU, 0x63F1ABCCU, 0xF0730388U, 0xE9EA74D0U},
			{0xD9EFFF66U, 0xA6C3504DU, 0x57E02015U, 0x5354EE38U, 0x6D7040FAU, 0x3BFED7FEU, 0x99CA82ACU, 0x692C95CCU}},
		{{0xC2DA7DE9U, 0xB830FB5BU, 0x0FF8D3BEU, 0xD0E643DFU, 0x188A9641U, 0x31EE77BAU, 0xBCF6D502U, 0x4E8AA3AAU},
			{0x9A49110FU, 0xF9FB6532U, 0x2DD6B220U, 0xD18317F6U, 0x52C3EA5AU, 0x7E3CED41U, 0x7D579C4AU, 0x0D296A14U}},
		{{0x942F6C58U, 0x688B5ACAU, 0x495D9439U, 0x6F2789C5U, 0x504C501DU, 0xD54DDB0CU, 0xBCACE3A7U, 0xF16A4D0FU},
			{0x056A41EBU, 0xB76FBC6FU, 0x825BD6C5U, 0xE288C255U, 0x0F42E2D3U, 0x95037796U, 0xDEB57B44U, 0x9A3C47E3U}},
		{{0xED4C3717U, 0x35D6A53EU, 0x3D0ED2A3U, 0x9F8240CFU, 0xE5543AA5U, 0x8C0D4D05U, 0xDD33B4B4U, 0x45D5BBFBU},
			{0x137FD28EU, 0xFA04CC73U, 0xC73B3FFDU, 0x862AC6EFU, 0x31F51EF2U, 0x403FF9F5U, 0xBC73F5A2U, 0x34D5E0FCU}},
		{{0x9559FAB0U, 0x2C9AEF21U, 0x62322F2DU, 0x833361CEU, 0x72BA0DF9U, 0xD3FD5E2BU, 0x9D2D8C0AU, 0xFC85E732U},
			{0xF15DB8D4U, 0xCE234675U, 0xF52D3F9AU, 0x6AF7AC2EU, 0x3DBF6592U, 0x2D55F169U, 0xD7098E38U, 0xB1C9CC6CU}},
		{{0x08913F4FU, 0xF2526820U, 0xEAC93D95U, 0xEA20ED61U, 0x6CA6B26CU, 0x51ED38B4U, 0xEA4327B0U, 0x8662DCBCU},
			{0x725D2AAAU, 0x6DAF295CU, 0x8E52DCDAU, 0xBAD2752FU, 0x0B17DACCU, 0x2210E721U, 0xD51E8232U, 0xA37F7912U}},
		{{0xD540CAEBU, 0x2A00160CU, 0xA41A2788U, 0x6F66145EU, 0x51C811FAU, 0xF9C81C33U, 0x646F5403U, 0xEEE58E0FU},
			{0xFC18FAE3U, 0x8DF920EFU, 0x0971EA6CU, 0x7923425EU, 0xCBA0AEA7U, 0xE0E3DCB2U, 0x4A852DFCU, 0xBF1DAF5EU}},
		{{0x44CC3ADDU, 0x4F7081E1U, 0x87BE82CFU, 0xD5FFA1D6U, 0x0EDD6472U, 0x89890B6CU, 0x3ED17863U, 0xADA26E1AU},
			{0x63483CAAU, 0x276F2715U, 0x2F6077FDU, 0xE6924CD9U, 0x0A466E3CU, 0x05A7FE98U, 0xB1902D1FU, 0xF1C794B0U}},
		{{0xAAF09C1CU, 0xEE066357U, 0xAB2776D2U, 0x1C53878DU, 0xAE4E324AU, 0x2CB5724CU, 0xE0FE8352U, 0x13307CADU},
			{0x54395696U, 0xEF02BB78U, 0xB3B64D31U, 0x2C592DF3U, 0xBC8B6AEBU, 0xF005951AU, 0x6B91275EU, 0x5760BE82U}},
		{{0x82A8042CU, 0xE5213688U, 0xCD278298U, 0xD931CFAFU, 0xF597A740U, 0x069A0AE0U, 0xEB59107CU, 0x0ADBB3F3U},
			{0x5EAA8EB8U, 0x983E951EU, 0x11B48E78U, 0xE663A8B5U, 0x8A03F2C5U, 0x1631CC0DU, 0x11E271E2U, 0x7577C11EU}},
		{{0x74A08FF6U, 0x085DBF41U, 0xA576460BU, 0x80BACE40U, 0x27C1BA49U, 0xD204CBCFU, 0xE4806949U, 0x64D12F32U},
			{0x01DFE8E3U, 0xCDD42222U, 0xD05C83D4U, 0x3B5B3C6EU, 0xFCEB00C0U, 0xB2C081B3U, 0xDD67D769U, 0xE2C23EECU}},
		{{0x08369A90U, 0x33B2385CU, 0x190EB4F8U, 0x2990C59BU, 0xC68EAC80U, 0x819A6145U, 0x2EC4A014U, 0x7A786D62U},
			{0x20AC3A8DU, 0x33FAADBEU, 0x5ABA2D30U, 0x31A21781U, 0xDBA4F565U, 0x209D2742U, 0x55AA0FBBU, 0xDB2CE9E3U}},
		{{0x63CCE1ADU, 0x6F4F24B5U, 0x9FB43A77U, 0x5166672AU, 0x4FC79D1FU, 0xBB784078U, 0xF774BBF5U, 0xB3821A6CU},
			{0xDF02F441U, 0xA27BD4CEU, 0xB84E2ADFU, 0xC5FA4EB9U, 0xF0B7CDDEU, 0x910BCBD7U, 0x2E5A1EECU, 0xB7E64048U}},
		{{0x168984DFU, 0x8CEF334BU, 0x33879638U, 0xE81DCE17U, 0x263720F0U, 0xF6E6949CU, 0xF593CBECU, 0x5C56FEAFU},
			{0xFDE58C84U, 0x8BFF5601U, 0x2ECCB314U, 0x74E24117U, 0x4C9A8A78U, 0xBCF01B61U, 0x544C9868U, 0xA233E35EU}},
		{{0xC765D8FBU, 0x54934BC9U, 0xB30B751EU, 0xC1966571U, 0x91A7C817U, 0xC4FD2FCFU, 0xDCB1C888U, 0x246FBC7EU},
			{0x59CC1BFFU, 0x27304FFDU, 0xE59C5811U, 0xC35C4D8DU, 0x401F9921U, 0xD863FFB9U, 0x2E806961U, 0x5B14482EU}},
		{{0x8BD7AFF1U, 0xB3156BF3U, 0x1D81B146U, 0x1B5EE4CBU, 0xD628A915U, 0x7BA1AC41U, 0xFD89699EU, 0x8F3A8F9CU},
			{0xA0748BE7U, 0x7329B9C9U, 0xA92E621FU, 0x1D391C95U, 0x4D10A837U, 0xE51E6B21U, 0x4947B435U, 0xD255F53AU}},
		{{0x1F20882BU, 0xC137045AU, 0x9B7A050CU, 0x924B16F4U, 0xEA6694AFU, 0x8ABA26F5U, 0x69826A3EU, 0x29062854U},
			{0xB08C1627U, 0x2EF6D1CBU, 0xC58C0C34U, 0x61313884U, 0xD8F6F1B4U, 0xA5C7C299U, 0xFF3E9F87U, 0xCD5AAEC0U}},
		{{0xF1788EE3U, 0x07669E04U, 0xA86938A2U, 0xC14F27AFU, 0xE93A01C0U, 0x8B47A334U, 0xD9366808U, 0xFF627438U},
			{0xCA2A5965U, 0x7A0985D8U, 0xD6E9B9B3U, 0x3D9A5542U, 0x4CF972E8U, 0xC23EB80BU, 0x4FDF72FDU, 0x5C1C33BBU}},
		{{0x4CB3D45AU, 0x3BCABDDDU, 0x417D67A1U, 0xA9384D6BU, 0x6AA8FA54U, 0x659F5BBAU, 0xCD0EF0CBU, 0x04937621U},
			{0x518B2347U, 0xD480B2F5U, 0x1FE38780U, 0x153C971EU, 0xFE07B538U, 0x157108EDU, 0xAB110129U, 0xCA0D8003U}},
		{{0x74A86108U, 0x0C4A58D4U, 0xEE4C5D90U, 0xF8048A8FU, 0xE86D4C80U, 0xE3C7C924U, 0x056A1E60U, 0x28C889DEU},
			{0xB214A040U, 0x57E2662EU, 0x37E10347U, 0xE8C48E98U, 0x80AC748AU, 0x87742862U, 0x186B06F2U, 0xF1C24022U}},
		{{0x094E51D7U, 0xD0BB3376U, 0x42CD877AU, 0x5110CC22U, 0xCFD197C6U, 0x7BD65729U, 0x8ACA3171U, 0xF2299405U},
			{0x2155AEA5U, 0x07847515U, 0x9A821A54U, 0x84F12D48U, 0x3737AF5CU, 0xB18CC1F9U, 0xBA485845U, 0x4FBA0CE2U}},
		{{0x5F74040AU, 0xAC2DD4C3U, 0xFCEAC957U, 0x409AEB71U, 0x55C4EC23U, 0x4FBAD782U, 0x8A7B76ECU, 0xB359ED61U},
			{0xED6F4A60U, 0x12744926U, 0x4B912DE3U, 0xE21E8D7FU, 0xFC705A59U, 0xE2575A59U, 0xED2DBC0EU, 0x72F1D4DEU}},
		{{0xB99772D2U, 0x9679D85AU, 0xDDCD1C25U, 0x8269717CU, 0xEBDCC377U, 0x50972045U, 0x6EE2C9DFU, 0xED13DE83U},
			{0x50A7217AU, 0x9F39F504U, 0xAEE007B6U, 0xD33BA941U, 0xFC2BEC9AU, 0x914F7190U, 0xB0D92487U, 0x70D2254EU}},
		{{0xEB7926B8U, 0x3D2B24B9U, 0xCDBE5509U, 0xBFF88CB3U, 0xE4DD640BU, 0xD0F399AFU, 0x2F76ED45U, 0x3C5FE130U},
			{0x3764FB3DU, 0x6F3562F4U, 0x3151B62DU, 0x7B5AF318U, 0xD79CE5F3U, 0xD5BD0BC7U, 0xEC66890FU, 0xFDAF6B20U}},
	},
	{
		{{0xAB4B35A2U, 0x6772B0E5U, 0xF5EEAACFU, 0x1D8B6001U, 0x795B9580U, 0x728F7CE4U, 0x41FB81DAU, 0x4A20ED2AU},
			{0x4FEC01E6U, 0x9F685CD4U, 0xA7FF50ADU, 0x3ED7DDCCU, 0x0C2D97FDU, 0x460FD264U, 0xEB82F4F9U, 0x3A241426U}},
		{{0xD5D721D5U, 0x80009862U, 0x5BD3A182U, 0x0C3357A3U, 0x7AA2CDA4U, 0x27F3A83BU, 0xF6F83085U, 0xB58AE74EU},
			{0x2E6DAD6BU, 0x2A911A81U, 0xF43D6C5BU, 0xDE286051U, 0xF996C4D8U, 0x4BDCCC41U, 0x0AE1E24EU, 0xE7312EC0U}},
		{{0xAAE6EE70U, 0x6FAF68FEU, 0x5602B0C9U, 0x78F4CC15U, 0x6E94052AU, 0x7E3321A8U, 0x734D5D80U, 0x2FB3A0D6U},
			{0xB25A43BAU, 0xF3B98F3BU, 0x19EE2951U, 0x30BF8031U, 0x21B0612AU, 0x7FFEE433U, 0x2EB821D0U, 0x12F775E4U}},
		{{0x6E6485B3U, 0xF8D112E7U, 0x771C52F8U, 0x4D3E24DBU, 0x684A2F6DU, 0x48E3EE41U, 0x21D95551U, 0x7161957DU},
			{0xCDB12A6CU, 0x19631283U, 0x2E50E164U, 0xBF3FA882U, 0x3166CC73U, 0xF6254B63U, 0xAEE8CC38U, 0x3AEFA7AEU}},
		{{0x37A929A9U, 0x46F70080U, 0x19FEC6BDU, 0x65601A8EU, 0x12AB8B62U, 0x537F5EDCU, 0x5E5990CFU, 0xE497CD95U},
			{0x9AA5B2F9U, 0x2FCD387FU, 0x67B78FE8U, 0xE5FAA3FFU, 0x295D5E30U, 0x1BCF538DU, 0xA813A7ECU, 0x3A573239U}},
		{{0xD17C2409U, 0xE9F5286BU, 0x63264D9BU, 0x2C4E4793U, 0x17F6880FU, 0x177042B1U, 0x4CE1EE43U, 0x39B7E2C8U},
			{0xD096F4A9U, 0xCEC8E722U, 0xBED5E697U, 0x6861AECBU, 0x6C231911U, 0xC2D153F0U, 0x2890537AU, 0xCC2F42B8U}},
		{{0xD0A917B4U, 0x33E2CB51U, 0x4899F931U, 0xC2CFA3F3U, 0xE9A2F6B6U, 0xB2C94F4BU, 0x7CA162B7U, 0x9707B181U},
			{0xD5F8B10DU, 0xB602A172U, 0x4FD4542AU, 0xFD307835U, 0xDD996992U, 0xEEF226DDU, 0xEB0A15E1U, 0x221FA989U}},
		{{0x3B36F9FDU, 0x79B0FE62U, 0xFDE19FC0U, 0x26543B23U, 0x958482EFU, 0x136E64A0U, 0x9B095825U, 0x23F63771U},
			{0xB6A1142EU, 0x14CFD596U, 0x335AAC0BU, 0x5EA6AAC6U, 0xF3081DD5U, 0x86A0E8BDU, 0x003DC12AU, 0x5FB89D79U}},
		{{0xDE1132A3U, 0x73628677U, 0x2FA88847U, 0x75127E64U, 0x5B49E660U, 0x192F7A30U, 0x11436AA9U, 0x1A063CFEU},
			{0x4B710189U, 0x72001457U, 0x2A57378DU, 0xFAA946DEU, 0x191C3066U, 0x5C495C63U, 0x6B7DB4DBU, 0x2B4B7E65U}},
		{{0xD0630413U, 0xA4E3D27AU, 0x19FA56EBU, 0x5770E382U, 0x754C0666U, 0x4465CF7AU, 0x6169C5F3U, 0xFE9161D2U},
			{0xDC0EE348U, 0x5DF62722U, 0x29890454U, 0x9CC6596AU, 0x9F5D322AU, 0xF043D618U, 0x181EE3E9U, 0xB4CE957AU}},
		{{0xFE5C62EDU, 0x08190A49U, 0x3691183DU, 0x2C57543DU, 0xA9044823U, 0x75EE318BU, 0xAEF28F58U, 0xD20CE09EU},
			{0x848A4A66U, 0x10613D50U, 0x9FCF2EFBU, 0x4B98A1A8U, 0x98FC6427U, 0x415F1ED9U, 0xE3852B50U, 0x086ABB56U}},
		{{0xF72E34D4U, 0xF615C33AU, 0x110EEC35U, 0x0BD9EA40U, 0xC1DEA34EU, 0x1C12BC5BU, 0x49AE4699U, 0x686584C9U},
			{0x8C97B942U, 0x13AD95D3U, 0x4E5C7562U, 0x4609561AU, 0xF2737F89U, 0x9E94A4AEU, 0x371C78B6U, 0xF57594C6U}},
		{{0x19EDA9DEU, 0x5A768CD9U, 0x8E2A51D2U, 0x6E3206F4U, 0x8678A3EFU, 0xD356E8C0U, 0x543F91C9U, 0x93F8D36DU},
			{0xA4086743U, 0xFEF231F4U, 0x9148C6C9U, 0x4D379A11U, 0xDC8232CEU, 0x00B5581DU, 0xD702214BU, 0xA67A72EFU}},
		{{0x17B4E892U, 0x6145A9F6U, 0x5F229FF1U, 0xFE640227U, 0xDC046BA3U, 0x6DB03EA8U, 0x0351DACCU, 0x71C873D6U},
			{0xC2947B5BU, 0x4BAEE337U, 0xB08B4380U, 0x900885C7U, 0xC84579B9U, 0x1F1EA661U, 0xA5017818U, 0xCCDDBB93U}},
		{{0xCF9FB480U, 0x554D883DU, 0x0DFB9A4DU, 0x76CA71C5U, 0xE04240EAU, 0xC251142BU, 0xFA7AFC99U, 0x899BA63DU},
			{0x9FBBCDA3U, 0xED945B12U, 0xA299A4CCU, 0x3C4DD528U, 0x8A63C092U, 0x68E8B609U, 0x3F40621BU, 0xECF50A6CU}},
		{{0xE3779EE3U, 0x0F0165FCU, 0xBD495D9EU, 0xE00E7F9DU, 0x20284E7AU, 0x1FA4EFA2U, 0x47AC6219U, 0x4564BADEU},
			{0xC4708E8EU, 0x90E6312AU, 0xA71E9ADFU, 0x4F5725FBU, 0x3D684B9FU, 0xE95F55AEU, 0x1E94B415U, 0x47F7CCB1U}},
		{{0xA8ADC201U, 0x50FD48BEU, 0x40DF06A8U, 0xCE181800U, 0xDE82CE22U, 0x6C07CA42U, 0x5A24761AU, 0x23646C51U},
			{0xB268392FU, 0x46CF91F8U, 0x81811486U, 0xE4B757FFU, 0xD26102A0U, 0x94DD570BU, 0x3E65DF80U, 0x2DC34D2DU}},
		{{0x56DE56D3U, 0x18FEAF44U, 0x61027922U, 0xB39568E8U, 0x28A458DCU, 0xA2B8685CU, 0x6295A817U, 0x41A8BF6CU},
			{0xCA98D1DCU, 0x7B294074U, 0xB3E013BEU, 0x94C48259U, 0x2C4F5256U, 0xB42ED524U, 0xDA7C9FECU, 0x308E8950U}},
		{{0x316C541DU, 0x46027083U, 0xD39EABCCU, 0x7F05BC6BU, 0x60C20CDCU, 0xB837FAA1U, 0xACD39D06U, 0x4F8BF31AU},
			{0x00512051U, 0x8331DC95U, 0xAF2AA2ACU, 0x5374F462U, 0xF32AB1A3U, 0x7673D9B4U, 0xD64F49FCU, 0xA6E151ACU}},
		{{0x8D946581U, 0x7322851BU, 0xBDF4A012U, 0xF0D13133U, 0x6584DAE0U, 0xA3510F69U, 0x3C9F6C6DU, 0x03A7C171U},
			{0xE475381AU, 0x5BE97F38U, 0x85823334U, 0xCA1BA422U, 0x0BE17DDAU, 0xF83CC5C7U, 0x0B918C0FU, 0x158B1494U}},
		{{0xDBA5F705U, 0xB7188A88U, 0xA1FAD88BU, 0x5CFEFCA6U, 0x338E8595U, 0xED2D8804U, 0x7EB40981U, 0xC0230BF8U},
			{0x4B87F7C7U, 0x3ED1F178U, 0x7F9ED02AU, 0x9D1D6076U, 0xF23F8D5BU, 0x2290268BU, 0x86D368B9U, 0xAD904C35U}},
		{{0x2AFBD682U, 0xDC649605U, 0x1637B0B1U, 0xAC08FB13U, 0xA184F39DU, 0xDF9FD488U, 0xACE325B2U, 0x1FC2BC23U},
			{0xBD6C9A84U, 0x29873B36U, 0x3CF8529DU, 0x462C1115U, 0xC555212DU, 0xB3E0370DU, 0x89AAECC6U, 0x31F83F75U}},
		{{0xB7DE5A99U, 0xB1DF7431U, 0xF295873CU, 0xFB528EE6U, 0xCC303C95U, 0xECA1500FU, 0xCE33B760U, 0xDB390597U},
			{0xE4769736U, 0xD6961486U, 0xC3339DA2U, 0xD245E428U, 0xFA106CCEU, 0xF5CA7F41U, 0x7080ACDDU, 0x37EDB132U}},
		{{0x522E6B69U, 0xDA3A77E5U, 0xBBCD6C18U, 0x69C908C3U, 0xD924FD56U, 0x1F1B9E48U, 0xAA4BB3F7U, 0x37C64E36U},
			{0xEE478D7DU, 0x5A4FDBDFU, 0x0193F7A0U, 0xBA75C8BCU, 0x56CD16DFU, 0x84BC1E84U, 0x46FAD151U, 0x1FB08F08U}},
		{{0xB26BBB36U, 0x293301EFU, 0xA9644DFAU, 0x4568CAF8U, 0x3E0C3C0CU, 0x0DACAE05U, 0xECA651A8U, 0x2BA6D502U},
			{0x6004610BU, 0xE3BD5968U, 0x282B7245U, 0xC2076AF6U, 0x1E94E9A4U, 0xAE61F24AU, 0x1576F163U, 0x0315995CU}},
		{{0x74571547U, 0x2AF8FF3DU, 0x2CE19B19U, 0x7EB3EA07U, 0x9B099985U, 0xB81B6288U, 0xEAA309C5U, 0xDFEC22D6U},
			{0xCFC33419U, 0xF9B5A0E2U, 0xDB65B3A0U, 0x70BFB69CU, 0x3F524D95U, 0x75EC1556U, 0xE0802F30U, 0xE5ED9737U}},
		{{0x04C753E0U, 0x6AE7F42BU, 0xE606D46CU, 0x26094200U, 0xF680DCA4U, 0x3AB02F39U, 0x733B37DAU, 0x9B8853A9U},
			{0x855D386AU, 0x2E1134AEU, 0x88ED9B61U, 0xD8A8BEE1U, 0x83EDD459U, 0x2FA08BC0U, 0x2D0FE168U, 0x944D2151U}},
		{{0x842E9F30U, 0x8A7CABF9U, 0x5EAB83AFU, 0xA331D4BFU, 0x017F2A6AU, 0xD272CFBAU, 0x83ABA0E3U, 0x27560ABCU},
			{0x0E3A6B75U, 0x94B83387U, 0x6B9F50F5U, 0x25C6AEA2U, 0xB5FDF6D0U, 0x803D691DU, 0xE6333514U, 0x03B77509U}},
		{{0xBD14CF6FU, 0x745EE234U, 0x49C024BBU, 0xDE8B5084U, 0xEF35D7B4U, 0x9C334FDDU, 0xB764B2B4U, 0xFF647728U},
			{0xCC21E031U, 0xF94DEED7U, 0xA0D82885U, 0xE34740B8U, 0xC785D2FBU, 0xA70317C4U, 0xF8A58CAEU, 0xDC056AC5U}},
		{{0x8878045FU, 0xC4274E8EU, 0xEBC325E0U, 0x216698EBU, 0x09396C56U, 0x0FEFBBCFU, 0x0491805EU, 0xDC191915U},
			{0x5C5480A2U, 0xA74C4E87U, 0x72C8CE0AU, 0xDEA8D1B3U, 0x7F77FAC1U, 0x679F701DU, 0x6D6AB570U, 0x3EBA00B5U}},
		{{0xF22350CEU, 0x08004E20U, 0x8D601C4EU, 0x6B454519U, 0xD5E177D5U, 0xEA09DC5AU, 0x7534BAD9U, 0x923E19AAU},
			{0x3180C046U, 0xA42905A6U, 0xD3C864AAU, 0x0C279ED0U, 0xFF905A51U, 0x49F341B6U, 0xA7966B32U, 0x2BE20988U}},
		{{0x61A341C1U, 0x36178903U, 0x0CFD6142U, 0x3604DC60U, 0x8533316CU, 0x022295EBU, 0x44AF2922U, 0x3DBDE4ACU},
			{0x1C7EEF69U, 0x898AFC5DU, 0xD14F4FA1U, 0x58896805U, 0x203C21CAU, 0x05002160U, 0x40EF730BU, 0x6F0D1F30U}},
	},
	{
		{{0x77F7195AU, 0xFABF7709U, 0xADEB838FU, 0x8EC86167U, 0xBB4F012DU, 0xEA1285A8U, 0x9A3EAB3FU, 0xD6883503U},
			{0x309004C2U, 0xEE5D24F8U, 0x13FFE95EU, 0xA96E4B76U, 0xBD223EA4U, 0x0CDFFE12U, 0xB6739A53U, 0x8F5C2EE5U}},
		{{0xBD763802U, 0xED406AA9U, 0x65303DA1U, 0xC21486A0U, 0xC7E62EC4U, 0x61AE291EU, 0xDF99333EU, 0x622A0492U},
			{0xBB7A8EE0U, 0x7FD80C9DU, 0x6C01AEDBU, 0xDC2ED3BCU, 0x08BE74ECU, 0x35C35A12U, 0x469F671FU, 0xD540CB1AU}},
		{{0xBF776F5BU, 0x2CE53C5AU, 0x60357B05U, 0x6F724071U, 0x71BF3F7AU, 0xB2593717U, 0x440C4A9FU, 0x87D2501CU},
			{0x87B05340U, 0x440552E1U, 0x21624C32U, 0xB7BF7CC8U, 0x22FACDDBU, 0x4155A6CEU, 0x889837EFU, 0x5A4228CBU}},
		{{0x584C5E20U, 0xA7A8746AU, 0xB9DC7035U, 0x267E4EA1U, 0xB9548C9BU, 0x593A15CFU, 0x4BD012F3U, 0x5E6E2135U},
			{0x8C8F936EU, 0xDF31CC6AU, 0xB5C241DCU, 0x8AF84D04U, 0x345EFB86U, 0x63990A6FU, 0xB9B962CBU, 0x6FEF4E61U}},
		{{0xE1A2E48DU, 0x23C48246U, 0x543DCE5CU, 0xF015E6D1U, 0x286D1DE9U, 0xD19EDB52U, 0xDF826F56U, 0xD60787F6U},
			{0x1C1459E3U, 0x6E1D5DFEU, 0x9EB06CDCU, 0x26E899A4U, 0x14A1FBDBU, 0x029560C9U, 0xB3D3B4F5U, 0x8B78842FU}},
		{{0x22BEECCBU, 0xC56DFA9CU, 0xA188D7C0U, 0x9C41A94AU, 0x70324729U, 0x36C283A1U, 0xB63F6511U, 0x2DA0E250U},
			{0x7B5E24A0U, 0x834D9FD2U, 0x6C34DD42U, 0xAC26B71BU, 0x329336D9U, 0xE5F1B497U, 0x39E94A9DU, 0xDC681ACFU}},
		{{0x6CD77B30U, 0x5C80CCEFU, 0xEC99B6D0U, 0x49978299U, 0xB939D335U, 0x6BF4485EU, 0x86D7C147U, 0xC53E61ABU},
			{0xFB601DDDU, 0xDD948052U, 0x3511DD48U, 0x34C5EB39U, 0x00E6F61CU, 0x91F5C676U, 0xB1E71F34U, 0x33F1B525U}},
		{{0x25722608U, 0xF6368F09U, 0x131CF5C6U, 0x131260DBU, 0xFAB4F7ACU, 0x40EB353BU, 0x37EEE829U, 0x85C78880U},
			{0xC3BDF24EU, 0x4C1581FFU, 0xF5C3C5A8U, 0x5BFF75CBU, 0xA14E6F40U, 0x35E8C83FU, 0x0295E0CAU, 0xB81D1C0FU}},
		{{0xEED9DD1DU, 0xDE7153F8U, 0x52EBCB2EU, 0xBA09AD11U, 0xE1843FB6U, 0xAA41B015U, 0xDD4CE6F0U, 0xF933A2ABU},
			{0x13F6B83FU, 0x777F8343U, 0xDB113A75U, 0x28DF7DA4U, 0x72A5D143U, 0x6D7D1B3CU, 0x966C6DDFU, 0x6F789698U}},
		{{0xA72BA054U, 0xED439A33U, 0xEAD265BAU, 0xA3170A15U, 0xFE99A58EU, 0xCF7EB903U, 0x33D80C26U, 0xCF6DB0C6U},
			{0xF613E71AU, 0xD031255EU, 0x18CA255CU, 0x12CCBE57U, 0x7808C40DU, 0xDD21D053U, 0x3AF2BE6BU, 0xF5488EBCU}},
		{{0x1BE3F9C5U, 0x47110D7CU, 0x5EADB4DDU, 0x12B9E448U, 0x0B713D41U, 0x6E8C0987U, 0x733D56AEU, 0xE1E20356U},
			{0x445EA727U, 0xE68D6BABU, 0xC934A1A4U, 0x9EF4F6EAU, 0xF8CEF1C3U, 0xE0155547U, 0x159BDCBFU, 0xDB5C3909U}},
		{{0x442A8AD1U, 0xF2EFE23DU, 0x06B9C164U, 0xC3816A7DU, 0xDC0AA5E5U, 0xA9DF2D8BU, 0x120A8E65U, 0x191AE46FU},
			{0x00611C5BU, 0x83667F87U, 0xFF109948U, 0x83171ED7U, 0xCA695952U, 0x33A2ECF8U, 0xF48D1A13U, 0xFA4A73EEU}},
		{{0x6604007DU, 0x97CACF84U, 0x2D47A9F1U, 0x1E92B4B2U, 0x374ED165U, 0x858AE0D6U, 0x307AEFB8U, 0x4C973E6FU},
			{0x8A10EB72U, 0x6F524A23U, 0xEB2849D6U, 0x7B4A92A9U, 0x2FE91EDDU, 0x3678BDA4U, 0x7C0FC35CU, 0x56092ACDU}},
		{{0x0B10E517U, 0x3513E9F1U, 0x6981C1D4U, 0x407D2544U, 0x60D9ABC1U, 0x4953A848U, 0x8C4FD5D0U, 0xE38DBDE4U},
			{0x81BB5AB1U, 0x7E5216C5U, 0x06C5E0A1U, 0x328A046BU, 0x91165EA6U, 0x5234F644U, 0xCFAC0D36U, 0xB6E68B0FU}},
		{{0x1A093B40U, 0x091D5B63U, 0x5862F24AU, 0xB85C1C07U, 0x3E8F85BFU, 0xC5D74EB5U, 0xCAB22456U, 0xF51C7746U},
			{0xE761DA89U, 0xC25CB8D9U, 0xC0F028B5U, 0x2670EC2FU, 0x2DB9AF5CU, 0x873FD30DU, 0x8262565EU, 0x3D0F1EA1U}},
		{{0xF43A730FU, 0xFCDE7CC8U, 0x33AB590EU, 0xE89B6F3CU, 0xAD03240BU, 0xC823F529U, 0x98BEA5DBU, 0x82B79AFEU},
			{0x962FE5DEU, 0x568F2856U, 0x60C591F3U, 0x0C590ADBU, 0x4A28A858U, 0x1FC74A14U, 0xB3203F4CU, 0x3B662498U}},
		{{0x88CE8C4FU, 0x755C30E2U, 0x21633C3DU, 0x56638FC8U, 0xA05A7C2DU, 0x886000FFU, 0x010218C6U, 0x8F92E531U},
			{0xB81764A3U, 0x09EE7903U, 0x3C634791U, 0x95C23697U, 0x4E8E2F13U, 0x3CECF522U, 0x23C34FF8U, 0x5D1ED66CU}},
		{{0x1930B3BFU, 0x9EAEFB22U, 0x22A19C73U, 0x25C06B08U, 0x4BD3A498U, 0xD0A8572AU, 0x0CD76351U, 0x20BC852FU},
			{0xB38925DAU, 0x8301386DU, 0x64ECF285U, 0x85FBE66AU, 0xC0C9617FU, 0x53747E84U, 0x1DBE1772U, 0xB0D61D26U}},
		{{0x8D0DFF8AU, 0xE584C295U, 0xEF246305U, 0x552BF48BU, 0x4F45DB3EU, 0xC09C21A5U, 0x3CEEBB8FU, 0xCA3083ECU},
			{0x406DC6E2U, 0xBF4DD07CU, 0xA7F63001U, 0x0E96626DU, 0xAA16CBD3U, 0x81A9FBFEU, 0x673A1300U, 0xFE7ECA5CU}},
		{{0x82DD1B6AU, 0x48FC4ED0U, 0x67B703AFU, 0x5783A138U, 0x005D6AAAU, 0x2463CB9AU, 0x706ECD43U, 0xD31EC55CU},
			{0x8E9A7641U, 0x9F8ED33FU, 0x098D9E7AU, 0x625453EDU, 0xEC887493U, 0xA3BEADE4U, 0x5A795566U, 0x442B8050U}},
		{{0x0C965017U, 0x980C6231U, 0x400D7A4FU, 0xAF8CC0B3U, 0x48F4CF97U, 0xEE5812E2U, 0xBB90D95EU, 0xE4587EB8U},
			{0x8152045EU, 0x1B42A57FU, 0x641C7C2EU, 0xD792B906U, 0xA71C87DAU, 0x9DFCF593U, 0x1B0400B9U, 0xC7AB7D77U}},
		{{0xD85A70E2U, 0x16952D34U, 0xC32E1A52U, 0x7D09FF97U, 0xA62D8ABFU, 0xCAD6E43EU, 0x25AAFEBBU, 0x747646DAU},
			{0xE54E24BDU, 0x0365C496U, 0x24E850E3U, 0x1499A416U, 0x6781D22BU, 0x24F6DDF7U, 0xBFC35981U, 0x42E555F1U}},
		{{0xFACD3338U, 0x5B2319C2U, 0x6F883ED1U, 0xED965047U, 0x16831619U, 0x370796C3U, 0x206B61AAU, 0x8DB73469U},
			{0x1FA908E8U, 0x0A0E5D17U, 0xB45440FAU, 0xE87271E3U, 0x072BDB98U, 0x7F6AE03EU, 0x28C3B98AU, 0x0687F755U}},
		{{0x6C39765AU, 0x91E3CF0DU, 0xAC3CCA0BU, 0xA2DB3ACDU, 0xCB953B50U, 0x288F2F08U, 0xCF43CF1AU, 0x2414582CU},
			{0x60EEE9A8U, 0x8DEC8BBCU, 0x729AA042U, 0x54C79F02U, 0x6532F5D5U, 0xD81CD5ECU, 0xCF82E15FU, 0xA672303AU}},
		{{0xC373F5FFU, 0xB3BD03E2U, 0xE7FC6341U, 0x80A8A8B4U, 0xA0087BDFU, 0xB72952D6U, 0xC048A38EU, 0x803CBB9DU},
			{0xCCF8B000U, 0xCF0A657EU, 0x67E1EB09U, 0x8C54C018U, 0xF0B646FCU, 0x88F91026U, 0x7DFF4BD8U, 0x9D0DF253U}},
		{{0x48C6D542U, 0x4EFBC980U, 0xC925F42EU, 0x269CC200U, 0xBCF6FE3EU, 0xB55A446AU, 0xAC67E5C5U, 0xB002DBD5U},
			{0xEEDA8ED8U, 0x91ECEE64U, 0xBAE071D2U, 0x8989F92DU, 0xAF7EBF53U, 0x9245DBE0U, 0x9EEFA781U, 0xD141E6E7U}},
		{{0x2DEB7E9FU, 0x9728490BU, 0x02C7256BU, 0x8877C3C6U, 0x2232AF73U, 0xD29DAA1DU, 0x1AB049E8U, 0xC94B9021U},
			{0xE6E4BF94U, 0xDBE4DF53U, 0x4D7B1006U, 0x4A7324E7U, 0x0A6A8BDFU, 0x0446D456U, 0x5CA35589U, 0xABF2F98BU}},
		{{0x3BFAB839U, 0x46DF582DU, 0x2F8ADADEU, 0x92474E04U, 0x147A1BC3U, 0x36A7766AU, 0x0DC0F979U, 0xB6940F54U},
			{0xF2759F25U, 0x44738EF2U, 0xA719F4C6U, 0x9DD95789U, 0x0750C345U, 0x2859B7F4U, 0xB22180D5U, 0x5E788BF2U}},
		{{0x6671B47EU, 0x4B215F01U, 0x4A8DAE2AU, 0xB67633CAU, 0x79FD3CDBU, 0x2915120FU, 0xB064E6DEU, 0xC1F8A06FU},
			{0xC1D57420U, 0xF4D5368CU, 0xE18DE475U, 0x6ADA51A8U, 0xC749D4B0U, 0xA0F0D47CU, 0x74526AA5U, 0xABFA2C00U}},
		{{0xFC59173CU, 0x3FF2B773U, 0xA2A0919CU, 0xF68612A5U, 0x234C7B15U, 0x9CA8AE28U, 0xEDBEE7DCU, 0xFDF658AFU},
			{0xAB18965FU, 0x2C55D9ADU, 0x5C00DE44U, 0xB9901F12U, 0xEE360B51U, 0x8B70AAF1U, 0x05604FE0U, 0x3E4BA9D5U}},
		{{0xF0D2772BU, 0xBEB8E482U, 0x2DE60699U, 0xC516AB65U, 0xC6D4F7F9U, 0x1E4F1E34U, 0x5CECE4EEU, 0x239888BFU},
			{0xBC03D238U, 0x7AC586FEU, 0x7D353A6FU, 0x8CD3C715U, 0xB3F1FD65U, 0x0296AADEU, 0x3A1E535FU, 0xE3B8EDD4U}},
		{{0x719C0563U, 0x376AAFA8U, 0xBC5FC79FU, 0xCD8AD2DCU, 0xCB750CD3U, 0x303FDB9FU, 0x4418B08EU, 0x14FF052FU},
			{0x3E2D6520U, 0xF75084CFU, 0x144ED509U, 0x7EBDF0F8U, 0xD3F25B98U, 0xF43BF0F2U, 0xA354D837U, 0x86AD71CFU}},
	},
	{
		{{0x868AF75DU, 0xD9D0C8C4U, 0x45C8C7EAU, 0xD7325CFFU, 0xCC81ECB0U, 0xAB471996U, 0x611824EDU, 0xFF5D55F3U},
			{0x1977A0EEU, 0xBE314541U, 0x722038C6U, 0x5085C4C5U, 0xF94BB495U, 0x2D5335BFU, 0xC8E2A082U, 0x894AD8A6U}},
		{{0x2C11BB37U, 0x540234B2U, 0xED4C74A3U, 0x2D0366DDU, 0xEEC5F25DU, 0xF9A968DAU, 0x67B63142U, 0x36601068U},
			{0x68D7B6D4U, 0x07CD6D2CU, 0x0C842942U, 0xA8F74F09U, 0x7768B1EEU, 0xE2751404U, 0xFE62AEE4U, 0x4B5F7E89U}},
		{{0x1994EF20U, 0xD1E059B2U, 0x638AE318U, 0x2A653B69U, 0x2F699010U, 0x70D5EB58U, 0x09F5F84AU, 0x279739F7U},
			{0x8B799336U, 0x5DA4663CU, 0x203C37EBU, 0xFDFDF14DU, 0xA1DBFB2DU, 0x32D8A9DCU, 0x77D48F9BU, 0xAB40CFF0U}},
		{{0x879FBBEDU, 0xF2369F0BU, 0xDA9D1869U, 0x0FF0AE86U, 0x56766F45U, 0x5251D759U, 0x2BE8D0FCU, 0x4984D8C0U},
			{0xD21008F0U, 0x7ECC95A6U, 0x3A1A1C49U, 0x29BD54A0U, 0xD26C50F3U, 0xAB9828C5U, 0x51D0D251U, 0x32C0087CU}},
		{{0xFBAF50A5U, 0xF61790ABU, 0x684E0750U, 0xDF55E76BU, 0xF176B005U, 0xEC516DA7U, 0x7A2DDDC7U, 0x575553BBU},
			{0x553AFA73U, 0x37C87CA3U, 0x4D55C251U, 0x315F3FFCU, 0xAF3E5D35U, 0xE846442AU, 0x6495FF28U, 0x61B91149U}},
		{{0x62B5F3AFU, 0x47FEEB66U, 0x0ABB3734U, 0xCEFAB561U, 0x19F35CB1U, 0x449DE60EU, 0x157F0EB9U, 0x39F8DB14U},
			{0x3C61BFD6U, 0xFFAECC5BU, 0x41216703U, 0xA5A4D41DU, 0x224E1CC2U, 0x7F8FABEDU, 0x871AD953U, 0x0D5A8186U}},
		{{0x56F90823U, 0x4BDF3A49U, 0x741D777BU, 0xBA0F5080U, 0xF38BF760U, 0x091D71C3U, 0x9B625B02U, 0x9633D50FU},
			{0xB8C9DE61U, 0x03ECB743U, 0x5DE74720U, 0xB4751254U, 0x74CE1CB2U, 0x9F9DEFC9U, 0x00BD32EFU, 0x774A4F6AU}},
		{{0x01799A52U, 0x190D8EA6U, 0xB86D2952U, 0xA20CEC41U, 0x7FFF2A7CU, 0x3062FFB2U, 0x79F19D37U, 0x741B32E5U},
			{0x4EB57D47U, 0xF80D8181U, 0x16AEF06BU, 0x7A2D0ED4U, 0x1CECB588U, 0x09735FB0U, 0xC6061F5BU, 0x1641CAAAU}},
		{{0xB0131E5BU, 0x327BC002U, 0xCB2514D9U, 0x1739E6D5U, 0x55A81543U, 0xC8CBDAFEU, 0xE1137243U, 0x5BB1A36CU},
			{0x17325327U, 0x205DA3C5U, 0x515A057EU, 0xC35C1A36U, 0x42925F9BU, 0xF00F64C9U, 0xB7D59F7AU, 0xBD14633CU}},
		{{0x656E8C3AU, 0xAE2AD171U, 0x1ACD0705U, 0xC0E2A463U, 0xA0B6055CU, 0x006F6A8AU, 0x2B65A26EU, 0xAF4513D7U},
			{0xD616D5BCU, 0x3F549E14U, 0x71253B1FU, 0x64EE3955U, 0xB8CE243AU, 0xE8B10BC1U, 0x913A4E77U, 0xBCBEACE5U}},
		{{0x41F37DBDU, 0x47C10043U, 0x6168ECF6U, 0x96ECCAE3U, 0x1CA46AA3U, 0x65BDE59DU, 0xB8698FFAU, 0x38A7027AU},
			{0x6DC34437U, 0xA2B89DC8U, 0x43A4153FU, 0x5A0A118DU, 0x1CE22FD8U, 0x9E330A86U, 0xB3BBD3BCU, 0x28382AF6U}},
		{{0xF779D6A7U, 0x68D32256U, 0x19E7284EU, 0x20423B4DU, 0x38F3B153U, 0xDE19AA1BU, 0x8444F703U, 0x73D0B6C2U},
			{0x9C64E6A3U, 0x66616148U, 0x37256224U, 0x99587C37U, 0x61331563U, 0x6F5277FEU, 0xA656502EU, 0x7174AD4AU}},
		{{0xD81E0271U, 0x0B2E27C0U, 0x117A317CU, 0xA67A7596U, 0xA6723D99U, 0x17F08928U, 0x485310A3U, 0x71A75681U},
			{0xAFB66CA9U, 0x90465462U, 0xFBBE229DU, 0x185E97CCU, 0xDDAD8FC2U, 0x6A1A606AU, 0xB3C797CFU, 0x2431F316U}},
		{{0x0133918DU, 0xEC1FFC92U, 0xB2C9EF97U, 0x15D9BF5EU, 0xFC6CBB9AU, 0x7885B542U, 0x5720CF5DU, 0x8ABE6453U},
			{0xD4EC68ABU, 0x4E715DCEU, 0x279C24A3U, 0x57A67614U, 0x31BB61CFU, 0x788ED52AU, 0xF437A003U, 0xABA82444U}},
		{{0x93529432U, 0x47034011U, 0x30743462U, 0x1F106BDDU, 0xCD66D8CAU, 0xABFB9964U, 0xE9BDADD5U, 0x934D9D5AU},
			{0x908E3D22U, 0x5976D815U, 0x28E057BDU, 0x344A362FU, 0x5443DFB3U, 0xF92CDADCU, 0xF089603BU, 0x001297ADU}},
		{{0x20151427U, 0x7F99824FU, 0x92430206U, 0x206828B6U, 0xE1112357U, 0xAA9097D7U, 0x09E414ECU, 0xACF9A2F2U},
			{0x27915356U, 0xDBDAC9DAU, 0x001EFEE3U, 0x7E0734B7U, 0xD2B288E2U, 0x54FAB5BBU, 0xF62DD09CU, 0x4C630FC4U}},
		{{0x5044066BU, 0x4A2FCE60U, 0xFA3A47F4U, 0x904A019CU, 0x0C5C0A60U, 0xBA81EA9CU, 0x96C098BDU, 0xD7E4EA0DU},
			{0x9CD50A02U, 0xEFE70041U, 0x2D7F048CU, 0xC0C839D4U, 0xE09B561FU, 0xE2DAF264U, 0x5034B18BU, 0x0CBC1318U}},
		{{0xBD70A5E1U, 0x6D883E66U, 0xD05DE713U, 0x9BD884C1U, 0xD4D8487DU, 0x48D9D445U, 0x0EEAE405U, 0x8440CD8BU},
			{0x3D26F83EU, 0xA3CD0F29U, 0x22A3C5E4U, 0x3FD94530U, 0x3FFA2CA7U, 0x63A07866U, 0x00D4A097U, 0xBFEADD29U}},
		{{0x88323F7AU, 0x11E5F2E3U, 0x927584CDU, 0xE07A74C2U, 0x95613D2DU, 0x1E774B34U, 0x2C787488U, 0x9C9B52C5U},
			{0xBE421F08U, 0x3CDD3C3EU, 0x223E3D5FU, 0x5FF7819EU, 0xC1DA09B9U, 0xBA8739B2U, 0x4E8B491BU, 0x6B726316U}},
		{{0xD68432BAU, 0x13AEA559U, 0xD33915DBU, 0x940043FBU, 0xE2E8DA08U, 0x476C7C94U, 0x443065BBU, 0x6B1630C4U},
			{0x19F06C75U, 0xD6D8546DU, 0x2EB35ABDU, 0x7E1E98C2U, 0xF0157D8EU, 0x751C9310U, 0xF6FA6075U, 0xDEF84327U}},
		{{0xA0943BEFU, 0xB5AFD13CU, 0x57ABB1CCU, 0xD6517729U, 0x9B61B5BCU, 0x9D5A52DCU, 0x806E31CDU, 0x85CEFAA6U},
			{0x720A1DEAU, 0xAB84257AU, 0xCED70D35U, 0x6A60261BU, 0xB9D6DA61U, 0xC023F94DU, 0x54A0AE0EU, 0x947F7EECU}},
		{{0x3A7A4E0EU, 0x765B993CU, 0x9D79D314U, 0xFB8F4AEFU, 0x2A19EB24U, 0x5EA2C50EU, 0xB891BC8CU, 0x925016E5U},
			{0x3AD1ECE7U, 0x8F70AFDCU, 0xF08FABE2U, 0x0ABBA84CU, 0x15F6132BU, 0x0A9922C8U, 0x5D076D77U, 0x6C021373U}},
		{{0x9F83B787U, 0xC3B78756U, 0x3694DDD7U, 0xD6D24926U, 0x5D70A02EU, 0x58D24894U, 0x8C278C6AU, 0xAC16670EU},
			{0xE370B6E6U, 0x71A94D58U, 0x0253DB05U, 0xE4D76384U, 0x14B32CFEU, 0x99B1C988U, 0xCC78CC95U, 0x4E6BD870U}},
		{{0xA4453961U, 0x00AF2615U, 0x993D112CU, 0x1705494BU, 0xA1CDD652U, 0x0032E12AU, 0x046D9CB3U, 0x0EBFA612U},
			{0x1B63728CU, 0x9F03A9F3U, 0xDE022B05U, 0x8F3618A2U, 0x3E77C5C9U, 0xD5B24D90U, 0x72ACB77CU, 0x837838A3U}},
		{{0xC8B63614U, 0xF5F7CA79U, 0x8AF4903CU, 0xF3BFB215U, 0x96D47BD3U, 0x2BDB9F54U, 0x0E8A63BAU, 0xD6E71530U},
			{0x7A93BEC4U, 0x67E90A49U, 0x8C1E63EEU, 0x8613478BU, 0xF2DDE561U, 0xE36BD9C8U, 0x8A768689U, 0x68148651U}},
		{{0x8FCEB047U, 0xFE65CBD9U, 0x3F8B11A1U, 0xDE872EF5U, 0x8FEC802FU, 0x9ABA0D3DU, 0x9A9F381DU, 0x139F1D32U},
			{0xC587958DU, 0x0721AED9U, 0xB9F6A7DAU, 0x066A015CU, 0xED5D9D06U, 0x059EC4E3U, 0x6CBACA1FU, 0x14428571U}},
		{{0x94AA531CU, 0xEF617A94U, 0xD6F4AD87U, 0x9AC35E2FU, 0x122468FBU, 0xBCD2A047U, 0xEF7C5CA6U, 0xBD7A423FU},
			{0x064C8040U, 0xAB58CB52U, 0x4A644716U, 0x93EF4ED5U, 0xC32CD48DU, 0xF7D17097U, 0xD17FCF42U, 0xB249A173U}},
		{{0xE298CDF5U, 0x66FE0FFFU, 0x7B2E51B6U, 0x3F61BEA4U, 0xBAD3AFA4U, 0x7D372117U, 0xEF656E2FU, 0x6521A09CU},
			{0xE8A58FE7U, 0xB3B8C966U, 0x5A47EBC7U, 0x25203A11U, 0x5C4BE573U, 0xFE81588DU, 0x1F49A03CU, 0x6132E2F3U}},
		{{0xB7A7ECC4U, 0xBBE5C108U, 0xBFD22E4CU, 0x62A5A78EU, 0xDF188BD2U, 0xB7974033U, 0x4DF7D1AEU, 0xCF11DEEAU},
			{0x53ACE3EAU, 0x99CC774AU, 0x105CC1F6U, 0xE0373A71U, 0x133D7A20U, 0xD751987FU, 0xAE215871U, 0xAB86EE04U}},
		{{0x0F8C2C99U, 0xEC1AB013U, 0xF17725C2U, 0x60E8968FU, 0x940A980BU, 0xE1A4A593U, 0x20E9CCB1U, 0x15ED15B0U},
			{0x64A00BECU, 0x77D754CCU, 0x41687382U, 0x90D09C33U, 0xC31FB651U, 0x294FE02DU, 0x1C94AE53U, 0x8372CD1AU}},
		{{0x80CD10E6U, 0x2094F9A2U, 0x7B8A0DA7U, 0x045232AAU, 0x9C03244EU, 0x969A81B6U, 0x7E98D955U, 0x1293B4CAU},
			{0xD68F3AB0U, 0x1631421DU, 0xC3738C82U, 0xA0106422U, 0xF82C4FF9U, 0xC5F43845U, 0x1AA0F58FU, 0xB479ACBEU}},
		{{0x1AC2703BU, 0x8537107AU, 0x6BC857B5U, 0xB49258D8U, 0xBCDACCD1U, 0x57DF14DEU, 0xC4AE8529U, 0x24AB68D7U},
			{0x734E59D0U, 0x7ED8B5D4U, 0xC495CC80U, 0x5F8740C8U, 0x291DB9B3U, 0x84AEDD5AU, 0x4FB995BEU, 0x80B360F8U}},
	},
	{
		{{0xA61A76FAU, 0x55D5C68DU, 0xCA1554DCU, 0x598B441DU, 0x773B279CU, 0xD39923B9U, 0x36BF9EFCU, 0x33331D3CU},
			{0x298DE399U, 0x2D4C848EU, 0xA1A27F56U, 0xCFDB8E77U, 0x57B8AB70U, 0x94C855EAU, 0x6F7879BAU, 0xDCDB9DAEU}},
		{{0x7F636A38U, 0x4C4F0736U, 0x0E76D5CBU, 0x9F943FB7U, 0xA8B68B8BU, 0xB03510BAU, 0x9ED07A1FU, 0xC246780AU},
			{0x6D549FC2U, 0x3C051415U, 0x607781CAU, 0xC2953F31U, 0xD8D95413U, 0x955E2C69U, 0x7BD282E3U, 0xB300FADCU}},
		{{0xC27901B4U, 0xA14B1163U, 0x899B8BF3U, 0xFD9236E0U, 0xCBC6DA0AU, 0x42B091ECU, 0x5AD1D297U, 0xBB1DAC6FU},
			{0xA91CF76EU, 0x80E61D53U, 0xD31F1EE7U, 0x4110A412U, 0x13EFCF77U, 0x2D87C3BAU, 0xDF450D76U, 0x1F374BB4U}},
		{{0x4147519AU, 0x20288602U, 0x26B372F0U, 0xD0981EACU, 0xA785EBC8U, 0xA9D4A7CAU, 0xDBDF58E9U, 0xD953C50DU},
			{0xFD590F8FU, 0x9D6361CCU, 0x44E6C917U, 0x72E9626BU, 0x22EB64CFU, 0x7FD96110U, 0x9EB288F3U, 0x863EBB7EU}},
		{{0x097E4403U, 0x15E10A0AU, 0x19854665U, 0xCB3D0A86U, 0xD67D4826U, 0x88D8E211U, 0x0B9D2839U, 0xB39AF66EU},
			{0xBD475CA8U, 0xA5F94588U, 0xC077B80BU, 0xE06B7966U, 0xDA27C26CU, 0xFEDB1485U, 0xFE0FD5E0U, 0xD290D33AU}},
		{{0x1306583DU, 0x686202F3U, 0x437C622EU, 0x05B10DA0U, 0x076A7BC8U, 0xBF9AAA0FU, 0x8F8F4E43U, 0x25E94EFBU},
			{0xFA3DC26DU, 0x8A35C9B7U, 0x96FF03C5U, 0xE0E5FB93U, 0xEBC394CEU, 0xA77E3843U, 0x8361DE60U, 0xCEDE6595U}},
		{{0x0C22B540U, 0xBF907509U, 0xB7C267D4U, 0x2CDE42AAU, 0x5AB0D693U, 0xBA18F9EDU, 0x6E4660D9U, 0x3BA62AA6U},
			{0xAB9EA96AU, 0xB24BF97BU, 0xE3B60E32U, 0x5D039642U, 0x7C4D9BD5U, 0x4E6A4506U, 0x7ED4A6A4U, 0x666C5B9EU}},
		{{0x678A31B0U, 0x877B7CF5U, 0x3998B620U, 0xD50301AEU, 0xC00FB396U, 0x734257C5U, 0x04E672A6U, 0xF9FB18A0U},
			{0xE8758851U, 0xFF8BD8EBU, 0x5D99BA44U, 0x1E64E4C6U, 0x7DFD93B7U, 0x4B8EAEDFU, 0x04E76B8CU, 0xBA2F2A98U}},
		{{0x9B56DDBDU, 0xAE02A2F0U, 0x8A2F1CF3U, 0x1339B5ACU, 0x839DFF0DU, 0xF2B569C7U, 0xFEE9A43DU, 0xB0B9E864U},
			{0x77BB064EU, 0x4FF8CA41U, 0xFD249F63U, 0x145A2812U, 0xF86F689AU, 0x3AB7BEACU, 0x01D35F5EU, 0x9BAFEC27U}},
		{{0xAE57C7B7U, 0xBBA23FDDU, 0x1B932522U, 0x345342F2U, 0x556D4AA3U, 0xFD9C80FEU, 0x6525BB61U, 0xA03907BAU},
			{0xFF218933U, 0x38B010E1U, 0xAA52117BU, 0xC066B654U, 0x94F2E6EAU, 0x8E141920U, 0x0D32F2B2U, 0x66A27DCAU}},
		{{0xFBABBE92U, 0xB2E6B121U, 0xE1330076U, 0x281850FBU, 0x97890015U, 0x093581ECU, 0x75FF77F5U, 0x69B1DDEDU},
			{0xAB105105U, 0x7CF0B18FU, 0xA89CCFEFU, 0x953CED31U, 0xEB914009U, 0x3151F85FU, 0x88ED48ADU, 0x3C9F1B87U}},
		{{0xE90FB21EU, 0xA18F07E0U, 0xBBA7FCA1U, 0x00FD2B80U, 0x95CD67B5U, 0x20387F27U, 0xD39707F7U, 0x5B89A4E7U},
			{0x894407CEU, 0x8F83AD3FU, 0x6C226132U, 0xA0025B94U, 0xF906C13BU, 0xC79563C7U, 0x4E7BB025U, 0x5F548F31U}},
		{{0x4FDE0C1FU, 0xFF758949U, 0xE5B6EC20U, 0xBF8A1ABEU, 0x87E1DB6CU, 0x702278FBU, 0x35ED658FU, 0xC447AD7AU},
			{0x03D0CCF2U, 0x48D4AA38U, 0x819A7C03U, 0x80ACB338U, 0x6E17CECCU, 0x9BC7C89EU, 0x03BE1D82U, 0x46736B8BU}},
		{{0xD43B5EAAU, 0x2126F742U, 0xDFA59B85U, 0x054A0766U, 0x126BFD45U, 0x9D0D5E36U, 0x384F8A8FU, 0xA1F8FBD7U},
			{0xD563FCCCU, 0x317680F5U, 0xF280A928U, 0x48CA5055U, 0x27B578CFU, 0xE00B81B2U, 0x2994A514U, 0x10AAD918U}},
		{{0x358BCDC0U, 0xE63F301FU, 0x0A9D47F8U, 0x07689E99U, 0x4F43D43AU, 0x1F689E2FU, 0x90920904U, 0x4D542A16U},
			{0x9CA0A707U, 0xAEA293D5U, 0x8AC68065U, 0xD061FE45U, 0x0090008CU, 0x1033BF1BU, 0xC08A6DB6U, 0x29749558U}},
		{{0xC35D8794U, 0x0EE6D3A7U, 0x0356BAE5U, 0x042E6558U, 0x643322FDU, 0x9F59698DU, 0x50A61967U, 0x9379AE15U},
			{0xFCC9981EU, 0x64B9AE62U, 0x6D2934C6U, 0xAED3D631U, 0x5E4E65EBU, 0x2454B302U, 0xF9950428U, 0xAB09F647U}},
		{{0xA66E71CDU, 0x34C99E50U, 0x75B713E9U, 0x1794F915U, 0xE04557B9U, 0x1E40DE90U, 0x267D5618U, 0x3C178C8BU},
			{0xC97932ADU, 0x9062107DU, 0x81311BD3U, 0xA2201D52U, 0xBC5BB79EU, 0x35D65EEBU, 0xB75CF4D0U, 0xEF610FA6U}},
		{{0x99E0CA30U, 0xC1702A61U, 0x99560AE8U, 0xBFD46A6BU, 0x611CC30CU, 0xB76BD5E6U, 0x755B986AU, 0x1E0EB78BU},
			{0x34914BBDU, 0x7EF39F77U, 0xA19556EAU, 0xE2C04CFFU, 0x69D53157U, 0xF78B8ECEU, 0xA6E10465U, 0xD4E52678U}},
		{{0xF614A37BU, 0x3E40E5ECU, 0x06FA74C2U, 0x74F29D04U, 0x61280D86U, 0x6AFC95D8U, 0xAEF1089FU, 0xBAEAC702U},
			{0x3466B4ABU, 0xE42A7D2BU, 0xC85DD595U, 0x20F319D4U, 0xD4F5C254U, 0xBA48491EU, 0x3331438AU, 0xEDC1DDDBU}},
		{{0x31B85F09U, 0xC1B3D3D3U, 0xA88AE64AU, 0x0F45354AU, 0x2FEC50FDU, 0xA8B626D3U, 0xE828834FU, 0x1BDCFBD4U},
			{0xCD522539U, 0xE45A2866U, 0x810F7AB3U, 0xFA9D4732U, 0xC905F293U, 0xD8C1D6B4U, 0x3461B597U, 0x10AC8047U}},
		{{0xC2436A05U, 0x11EF9236U, 0xE54B303DU, 0x97633EB6U, 0xFD9E0CF1U, 0xD2174994U, 0x98D5EB8DU, 0x9511C144U},
			{0xE78C2E6CU, 0xE577FDC1U, 0xBE4F6577U, 0x8DF37401U, 0xD38156A7U, 0x3B1282A5U, 0x0716BE53U, 0xE07F96EBU}},
		{{0x741F2591U, 0x29CD3837U, 0x64396EE2U, 0x4BDBC49DU, 0x269D268FU, 0xE6597102U, 0xCE9A6305U, 0x896B39C6U},
			{0x10B30245U, 0xC05E2471U, 0xA9130072U, 0x845219A8U, 0x0E2A9FC2U, 0x88158CB1U, 0x39F191C6U, 0xCBC6F641U}},
		{{0xD3B68256U, 0x7EA34678U, 0x94D90831U, 0x01FD4AF5U, 0x6F2F9592U, 0x7C914F2FU, 0xF5B35508U, 0xBA09D623U},
			{0xC1957C1AU, 0x27BBDD74U, 0xD716D57CU, 0xAB2A5517U, 0x8F3F8552U, 0xD3A4292DU, 0xC6047C50U, 0x46979CB2U}},
		{{0x6D91CD2CU, 0xE2C81536U, 0xDAA3F0E4U, 0x40A2BEEAU, 0x2441E083U, 0xFB167A59U, 0xE9240347U, 0x004675E9U},
			{0x840E446EU, 0x7848AAFFU, 0xEA308F72U, 0x9F9F258FU, 0x639BFAD9U, 0x50F12899U, 0x205C0AF6U, 0x0939AE63U}},
		{{0x486D7938U, 0xBCCDDE3EU, 0x81EA8F45U, 0xAFB4C0EAU, 0xB2B552DAU, 0x3EF12A5CU, 0x3878EAE2U, 0x6FE6A378U},
			{0x8D548F55U, 0x3FB85398U, 0x793C33AFU, 0x47AAA3C5U, 0x115AAB29U, 0x494E2D21U, 0x50BEACDEU, 0xD2ADCEBAU}},
		{{0xF195AFE5U, 0x465D1236U, 0x2DCD4413U, 0x03DB3C12U, 0xC8F7B15DU, 0xF1CF3B35U, 0xB54FC17FU, 0xBC8D30E2U},
			{0x40E672AEU, 0xE73AA3B9U, 0x02F38F75U, 0xA032848DU, 0x3BB10A05U, 0x1CA0DB21U, 0x688D902AU, 0xC5E9A72FU}},
		{{0xE7E4DDBCU, 0xF567DB5DU, 0xE7613B63U, 0xBE839B28U, 0x7DA6040DU, 0x81CC77C6U, 0x234D1026U, 0x692B88FBU},
			{0xD0593582U, 0x6E9D35FAU, 0x56051B98U, 0xC7413CFEU, 0xF46B2352U, 0x3CCEED5EU, 0x3AA45285U, 0xB76F1621U}},
		{{0x6FC627E2U, 0xBBB17514U, 0x91573A51U, 0xA0569BC5U, 0x358243D5U, 0xA7016D9EU, 0xAC1D6692U, 0x0DAC0C56U},
			{0xDA590D5FU, 0x993833B5U, 0xDE817491U, 0xA8067803U, 0x4DBF75D0U, 0x65B4F212U, 0xCCF80CFBU, 0xCC960232U}},
		{{0xBECC3C5EU, 0x87DDF5F7U, 0x6D35F8B9U, 0x21FEAFA7U, 0x751D77CFU, 0x41279C51U, 0x6FC92B50U, 0x47C726EBU},
			{0x4CFB54F4U, 0x4B18B7C8U, 0xA618CFEEU, 0xB0F88DABU, 0x5C95E0C8U, 0x3F469A00U, 0xD11839DFU, 0xCF1228F3U}},
		{{0xBD057D98U, 0x1F32CB54U, 0xE1C45787U, 0x79051A02U, 0x7D7632CBU, 0xAC859420U, 0xFE039421U, 0xCE8B265BU},
			{0x597E6848U, 0x1F9E0D3EU, 0xE2640918U, 0xD001F414U, 0x8A350DC9U, 0xE83748CDU, 0x7B4F0444U, 0x0EDDC81EU}},
		{{0x45C6A9D0U, 0x7A08948EU, 0x0C20D8B7U, 0xB7293CE5U, 0x74670371U, 0x715A5729U, 0xAE724540U, 0x6AA9E798U},
			{0xF971B642U, 0x79D5EBECU, 0xAAD498F3U, 0x6FD7B2BBU, 0x3969D46BU, 0xFF46B6F9U, 0x29D2E155U, 0xD7389AE3U}},
		{{0x22248ACCU, 0xB2083A12U, 0x3264E366U, 0x1F6EC0EFU, 0x5AFDEE28U, 0x5659B704U, 0xE6430BB5U, 0x7A823A40U},
			{0xE1900A79U, 0x24592A04U, 0xC9EE6576U, 0xCDE09D4AU, 0x4B5EA54AU, 0x52B6463FU, 0xD3CA65A7U, 0x1EFE9ED3U}},
	},
	{
		{{0x305406DDU, 0xE27A6DBEU, 0xDD5D1957U, 0x8EB7DC7FU, 0x387D4D8FU, 0xF54A6876U, 0xC7762DE4U, 0x9C479409U},
			{0x99B30778U, 0xBE4D5B5DU, 0x6E793682U, 0x25380C56U, 0xDAC740E3U, 0x602D37F3U, 0x1566E4AEU, 0x140DEABEU}},
		{{0xC49A861EU, 0xEAEE6126U, 0xE14F0D06U, 0x024F3B65U, 0xC69BFC17U, 0x51A3F1E8U, 0xA7686381U, 0xC3C3A8E9U},
			{0xB103D4C8U, 0x3400752CU, 0x9218B36BU, 0x02BC4613U, 0x7651504AU, 0xC67F75EBU, 0xD02AEBFAU, 0xD6848B56U}},
		{{0x1782269BU, 0x958381DBU, 0x2597E550U, 0xAE34BF79U, 0x5F385153U, 0xBB5C6064U, 0xE3088048U, 0x6F0E96AFU},
			{0x77884456U, 0xBF6A0215U, 0x69310EA7U, 0xB3B5688CU, 0x04FAD2DEU, 0x17C94295U, 0x17896D4DU, 0xE020F0E5U}},
		{{0xBBE5A1A9U, 0xCCA4428DU, 0x3126BD67U, 0x8187FD5FU, 0x48105826U, 0x0036973AU, 0xB8BD61A0U, 0xA39B6663U},
			{0x2D65A808U, 0x6D42DEEFU, 0x94636B19U, 0x4969044FU, 0xDD5D564CU, 0xF611EE47U, 0xD2873077U, 0x7B2F3A49U}},
		{{0x0F82B214U, 0x03B0D8DDU, 0xF103CBC6U, 0x460C34F9U, 0x18D79E19U, 0xF32E5C03U, 0xA84117F8U, 0x8B8888BAU},
			{0xC0722677U, 0x8F3C37DCU, 0x1C1C0F27U, 0x10D21BE9U, 0xE0F7A0C6U, 0xD47C8468U, 0xADECC0E0U, 0x9BF02213U}},
		{{0xB7FE7B6EU, 0x97554160U, 0x400A3FB2U, 0x7D16189AU, 0xE328CA1EU, 0xD73E9BEAU, 0xE793D8CCU, 0x0DD04B97U},
			{0x506DB8CCU, 0xA9C83C9BU, 0xCF38814CU, 0x5CD47AAEU, 0xB64B45E6U, 0x26FC430DU, 0xD818EA84U, 0x079B5499U}},
		{{0xE0AC2941U, 0x03B5D21AU, 0xC2D31937U, 0x279B0254U, 0xCAC992D0U, 0x3307C052U, 0xEFA8B1F3U, 0x6AA7CB92U},
			{0x0D37C7A5U, 0x5A182580U, 0x342D5422U, 0x13380C37U, 0xD5D2EF92U, 0x92AC2D66U, 0x030C63C6U, 0x035A70C9U}},
		{{0x71BA1861U, 0x5109B785U, 0xD0C8F93DU, 0x48B22D5CU, 0x8633BB93U, 0xE8FA84A7U, 0x5AEBBD08U, 0x53FBA6BAU},
			{0xE5EEA7D8U, 0x7FF27DF3U, 0x68CA7158U, 0x521C8796U, 0xCE6F1A05U, 0xB9D5133BU, 0xFD0EBEE4U, 0x2D50CD53U}},
		{{0xF74CFF17U, 0x14EBA133U, 0xECB813F2U, 0x240AAA03U, 0x6F665BEEU, 0xCFBB6540U, 0xA425AD73U, 0x084B1FE4U},
			{0xD081F6A6U, 0x009D5D16U, 0xEEF82C90U, 0x35304FE8U, 0xAA9EAA22U, 0xF20346D5U, 0xAC1C91E3U, 0x0ADA9F07U}},
		{{0xB40DF1CFU, 0x7D9B3E23U, 0x94E971B4U, 0x59337373U, 0x669CF921U, 0xBF57BD14U, 0x0C1A1064U, 0x865DAEDFU},
			{0x83279125U, 0x3EB70BD3U, 0x34ECDAABU, 0xBC3D5B9FU, 0x5F755CAFU, 0x91E3ED7EU, 0xD41E6F02U, 0x49699F54U}},
		{{0x0F3E4834U, 0x30417758U, 0x17A9AFCBU, 0xFDBB21C2U, 0x2F9A67B3U, 0x756FA17FU, 0xA245C1A8U, 0x2A6B2421U},
			{0x4AF02291U, 0x64BE2794U, 0x2A5804FEU, 0xADE465C6U, 0xA6F08FD7U, 0x8DFFBD39U, 0xAA14403BU, 0xC4EFA84CU}},
		{{0x47718427U, 0xDAB48046U, 0x6E830F8BU, 0xDF17FF9BU, 0xE49A1347U, 0x408D7EE8U, 0x91C1D4AEU, 0x6AC71E23U},
			{0x1DEFD73CU, 0xC8CBB9FDU, 0xBBBBFEC5U, 0x19840657U, 0x9E7EF8EAU, 0x39DB1CB5U, 0x64105F30U, 0x78AA8296U}},
		{{0x065FEF4AU, 0xCDBEF1C2U, 0xFD5B92E3U, 0x77E60F7DU, 0x26708350U, 0xD7C549F0U, 0x34F121BFU, 0x201B3AD0U},
			{0x0334FC14U, 0x5FCAC2A1U, 0x344552F6U, 0x8A9A9E09U, 0x97653082U, 0x7DD8A1D3U, 0x79D4F289U, 0x5FC0738FU}},
		{{0xBD3502BAU, 0x67608E71U, 0xB4DE75A0U, 0x4EF41F24U, 0xFD6125E5U, 0xB08DDE5EU, 0xA409543FU, 0xDE484825U},
			{0x65CC2295U, 0x1F198D98U, 0x6E0EDFA2U, 0x428A3771U, 0xADF35FC7U, 0x4F9697A2U, 0xF7CAC3C7U, 0x01A43C79U}},
		{{0x7CAE440CU, 0xC1258D5BU, 0x402B7531U, 0x21C08B41U, 0xDE932321U, 0xF61A8955U, 0x2D1408AFU, 0x3568FAF8U},
			{0x9ECF965BU, 0x71B15E99U, 0xE917276FU, 0xF14ED248U, 0x820CF9E2U, 0xC6F4CAA1U, 0x18D83C7EU, 0x681B20B2U}},
		{{0x533EF217U, 0x889F6D65U, 0xC3CA2E87U, 0x7158C7E4U, 0xDC2B4167U, 0xFB670DFBU, 0x844C257FU, 0x75910A01U},
			{0xCF88577DU, 0xF336BF07U, 0xE45E2ACEU, 0x22245250U, 0x7CA23D85U, 0x2ED92E8DU, 0x2B812F58U, 0x29F8BE4CU}},
		{{0x3467BA92U, 0xD65BF197U, 0xF70954B0U, 0x8C9B46DBU, 0x0E78F15DU, 0x97C8A0F3U, 0x85A4C961U, 0xA8F3A69AU},
			{0x61E4CE9BU, 0x4242660FU, 0x6EA6790CU, 0xBF06AAB3U, 0xEC986416U, 0xC6706F8EU, 0x9A9FC225U, 0x9E56DEC1U}},
		{{0x9A5103F1U, 0x4BEE3271U, 0xF50EAC06U, 0x5243EFC6U, 0x6ADCC119U, 0xB8E122CBU, 0xC0B80A08U, 0x1B7FAA84U},
			{0x6DFCD08CU, 0x32C3D1BDU, 0x0BE427DEU, 0x129DEC4EU, 0x1D263C83U, 0x98AB679CU, 0xCEF64EFFU, 0xAFC83CB7U}},
		{{0x3FDF5A51U, 0x1D87E47DU, 0x55C9CAB0U, 0x7AFB5F93U, 0x89E0586EU, 0x91BBF58FU, 0x0D843709U, 0x7C72C018U},
			{0x99B5C3DCU, 0xA9A5AAFBU, 0x3844AEB0U, 0xA48A0F1DU, 0xB667E482U, 0x7178B7DDU, 0x6E23A59AU, 0x453985E9U}},
		{{0xEAF4B8A5U, 0xAA6A4DE0U, 0x4BC60E32U, 0x68CFD9CAU, 0x7FD15E70U, 0x668A4B01U, 0xF27DC09DU, 0xD9F0694AU},
			{0xBA708BCDU, 0xF6C3CAD5U, 0x5BB95C2AU, 0x5CD2BA69U, 0x33C0A58FU, 0xAA28C1D3U, 0xABC77870U, 0x23E274E3U}},
		{{0x1CC1884BU, 0xECCFC82DU, 0x5D4753B4U, 0xC85AC201U, 0x658E099FU, 0xC7A6CAACU, 0x04B27390U, 0xCF46369EU},
			{0x506467EAU, 0xE2E7D049U, 0x37CDECCCU, 0x481B63A2U, 0xED80143AU, 0x4029ABD8U, 0xBCB00B88U, 0x28BFE3C7U}},
		{{0x33E24A0BU, 0xFF57F82FU, 0xF2565079U, 0x9CBEE23FU, 0xEB5F5825U, 0x16353427U, 0xE948D662U, 0x276FEEC4U},
			{0xDA10032BU, 0xD1B62BC6U, 0xF0E72A53U, 0x718351DDU, 0x2420E7BAU, 0x93452076U, 0x3A00118DU, 0x96368FFFU}},
		{{0x9C7C4C6BU, 0xD8975315U, 0xD7409AF7U, 0x603AA3C0U, 0x007132FBU, 0xB8D53D0CU, 0xA6849238U, 0x68D12AF7U},
			{0xBF5D9279U, 0xBE0607E7U, 0xAADA74CEU, 0x9AA50055U, 0xBA7E8CCBU, 0xE81079CBU, 0xA5F4FF5EU, 0x610C71D1U}},
		{{0xE3B6A661U, 0x184781BFU, 0xE6D279F7U, 0x7751CB1DU, 0xC59EB662U, 0xF8FF95D6U, 0x58D3DEA7U, 0x186D90B7U},
			{0xDFB4F754U, 0x0E4BB6C1U, 0x2B2801DCU, 0x5C5CF56BU, 0x1F54564DU, 0xC561E452U, 0xF0DD7F13U, 0xB4FB8C60U}},
		{{0x29FC81B3U, 0xAC4C200BU, 0x171D87C1U, 0xEBC3E09FU, 0x1481AA9EU, 0x91799530U, 0x92E114FAU, 0x051B92E1U},
			{0xECB5537FU, 0xDF8F92E9U, 0x290C7483U, 0x44B1B2CCU, 0x2ADEB016U, 0xA711455AU, 0x81A10C2CU, 0x964B6856U}},
		{{0x4088567AU, 0x73F45908U, 0x1F214A61U, 0xEB6B280EU, 0xCAF0C13DU, 0x8C9ADC34U, 0xF561FB80U, 0x39D12938U},
			{0xBC6EDFB4U, 0xB2DC3A5EU, 0xFE4D210EU, 0x7485B1B1U, 0xE186AE72U, 0x062E0400U, 0x6EEB3B88U, 0x91E32D5CU}},
		{{0xB134DEFAU, 0xC7E9AE85U, 0x1BB2D475U, 0x6073B1D0U, 0x2863C00DU, 0xB9AD615EU, 0x525F4AC4U, 0x9E29493DU},
			{0x4E9ACF4FU, 0xC32B1DEAU, 0xA50DB88DU, 0x3E1F01C8U, 0x04DA916CU, 0xB05D70EAU, 0xD865803EU, 0x714B0D0AU}},
		{{0xE079AFEEU, 0x5945920CU, 0x6789831FU, 0x686E17A0U, 0xB74A5AE5U, 0x5966BEE8U, 0x1E258D46U, 0x38A673A2U},
			{0x83141C95U, 0xBD1CC1F2U, 0x0E96E486U, 0x3B2ECF4FU, 0x74E5FC78U, 0xCD3AA896U, 0x2482FA7AU, 0x415EC10CU}},
		{{0x6EC3F510U, 0x85205A31U, 0xD2980475U, 0x2C7E4A14U, 0x6F30EBFDU, 0xDE3C19C0U, 0xD4B7E644U, 0xDB1C1F38U},
			{0x5DCE364AU, 0xFE291A75U, 0x058F5BE3U, 0xB7B22A3CU, 0x37FEA38CU, 0x2CD2C302U, 0x2E17BE17U, 0x2930967AU}},
		{{0xA15B0A44U, 0x020F795EU, 0x8958A958U, 0x8F37C8D7U, 0xA4B675B5U, 0x63B7E89BU, 0x0FC31AEAU, 0xB4FB0C0CU},
			{0xA7FF1F2EU, 0xED95E639U, 0x619614FBU, 0x9880F5A3U, 0x947151ABU, 0xDEB6FF02U, 0xA868DCDBU, 0x5BC5118CU}},
		{{0x349F7AEDU, 0xF197CB91U, 0x8FCA8420U, 0x3B2B5A00U, 0x23AAF6D8U, 0x7C175EE8U, 0x35AF32B6U, 0x54DCF421U},
			{0x27D6561EU, 0x0BA14307U, 0xD175B1E2U, 0x879D5EE4U, 0x99807DB5U, 0xC7C43673U, 0x9CD55BCDU, 0x77A54455U}},
		{{0x2133FFD9U, 0xFBB9B245U, 0x830F1A20U, 0x39A8B2F1U, 0xD5A1F52AU, 0x484BC97DU, 0xA40EDDF8U, 0xD6AEBF56U},
			{0x76CCDAC6U, 0x32257ACBU, 0x1586FF27U, 0xAF4D36ECU, 0xF8DE7DD1U, 0x8EAA8863U, 0x88647C16U, 0x0045D5CFU}},
	},
	{
		{{0xC005979DU, 0xA6F3D574U, 0x6A40E350U, 0xC2072B42U, 0x8DE2ECF9U, 0xFCA5C156U, 0xA515344EU, 0xA8C8BF5BU},
			{0x114DF14AU, 0x97AEE555U, 0xFDC5EC6BU, 0xD4374A4DU, 0x2CA85418U, 0x754CC28FU, 0xD3C41F78U, 0x71CB9E27U}},
		{{0x03605C39U, 0x89105079U, 0xA142C96CU, 0xF0843D9EU, 0x16923684U, 0xF3744934U, 0xFA0A2893U, 0x732CAA2FU},
			{0x61160170U, 0xB2E8C270U, 0x437FBAA3U, 0xC32788CCU, 0xA6EDA3ACU, 0x39CD818EU, 0x9E2B2E07U, 0xE2E94239U}},
		{{0x0260E52AU, 0x6967D39BU, 0x90653325U, 0xD42585CCU, 0x21CA7954U, 0x0D9BD605U, 0x81ED57B3U, 0x4FA20877U},
			{0xE34A0BBEU, 0x60C1EFF8U, 0x84F6EF64U, 0x56B0040CU, 0xB1AF8483U, 0x28BE2B24U, 0xF5531614U, 0xB2278163U}},
		{{0x5922AC1CU, 0x8DF27545U, 0xA52B3F63U, 0xA7B3EF5CU, 0x71DE57C4U, 0x8E77B214U, 0x834C008BU, 0x31682C10U},
			{0x4BD55D31U, 0xC76824F0U, 0x17B61C71U, 0xB6D1C086U, 0xC2A5089DU, 0x31DB0903U, 0x184E5D3FU, 0x9C092172U}},
		{{0xC00CC638U, 0xDD7CED5BU, 0x61278FC2U, 0x1A2015EBU, 0x6A37F8D6U, 0x2E8E5288U, 0xE79933ADU, 0xC457786FU},
			{0x2C51211AU, 0xB3FE4CCEU, 0x24C20498U, 0xAD9B10B2U, 0xD28DB5E5U, 0x90D87A4FU, 0x3ACA2FC3U, 0x698CD105U}},
		{{0xE91B536DU, 0x4F112D07U, 0x9EBA09D6U, 0xCEB982F2U, 0x197C396FU, 0x3C157B2CU, 0x7B66EB24U, 0xE23C2D41U},
			{0x3F330D37U, 0x480C57D9U, 0x79108DEBU, 0xB3A4C8A1U, 0xCB199CE5U, 0x702388DEU, 0xB944A8D4U, 0x0B019211U}},
		{{0x840BB336U, 0x24F2A692U, 0xA669FA7BU, 0x7C353BDCU, 0xDEC9C300U, 0xDA20D6FCU, 0xA13A4F17U, 0x625FBE2FU},
			{0xDBC17328U, 0xA2B1B61AU, 0xA9515621U, 0x008965BFU, 0xC620FF46U, 0x49690939U, 0x8717E91CU, 0x182DD27DU}},
		{{0xEA6C3997U, 0x5ACE5035U, 0xC2610BEFU, 0x54259AAAU, 0x3C80DD39U, 0xEF18BB3FU, 0x5FC3FA39U, 0x6910B95BU},
			{0x43E09AEEU, 0xFCE2F510U, 0xA7675665U, 0xCED56C9FU, 0xD872DB61U, 0x10E265ACU, 0xAE9FCE69U, 0x6982812EU}},
		{{0xCE800998U, 0x29BE11C6U, 0xB90360D9U, 0x72BB1752U, 0x5A4AD590U, 0x2C193197U, 0x9FC1DBC0U, 0x2BA2F548U},
			{0xE490EBE0U, 0x7FE4EEBBU, 0x7FAE11C0U, 0x12A0A4CDU, 0xE903BA37U, 0x7197CF81U, 0xDE1C6DD8U, 0xCF7D4AA8U}},
		{{0x3FD5684CU, 0x92AF6BF4U, 0x80360AA1U, 0x2B26EECFU, 0x00546A82U, 0xBD960F30U, 0xF59AD8FEU, 0x407B3C43U},
			{0x249C82BAU, 0x86CAE5FEU, 0x2463744CU, 0x9E0FAEC7U, 0x94916272U, 0x87F551E8U, 0x6CEB0615U, 0x033F9344U}},
		{{0x8BE82E84U, 0x1E5EB0D1U, 0x7A582FEFU, 0x89967F0EU, 0xA6E921FAU, 0xBCF687D5U, 0xD37A09BAU, 0xDFEE4CF3U},
			{0xB493C465U, 0x94F06965U, 0x7635C030U, 0x638B9A1CU, 0x66F05E9FU, 0x76667864U, 0xC04DA725U, 0xCCAF6808U}},
		{{0x768FCCFCU, 0xCA2EB690U, 0xB835B362U, 0xF402D37DU, 0xE2FDFCCEU, 0x0EFAC0D0U, 0xB638D990U, 0xEFC9CDEFU},
			{0xD1669A8BU, 0x2AF12B72U, 0x5774CCBDU, 0x33C536BCU, 0xFB34870EU, 0x30B21909U, 0x7DF25ACAU, 0xC38FA2F7U}},
		{{0xBF81F3F5U, 0x74C5F02BU, 0xAF7E4581U, 0x0525A5AEU, 0x433C54AEU, 0x88D2AABAU, 0x806A56C5U, 0xED9775DBU},
			{0xC0EDB37DU, 0xD320738AU, 0x66CC1F51U, 0x25FDB6EEU, 0x10600D76U, 0xAC661D17U, 0xBDD1ED76U, 0x931EC1F3U}},
		{{0x19EE43F1U, 0x65C11D62U, 0x60829D97U, 0x5CD57C3EU, 0x984BE6E8U, 0xD26C91A3U, 0x8B0C53BDU, 0xF08D9309U},
			{0xC016E4EAU, 0x94BC9E5BU, 0x11D43D2BU, 0xD3916839U, 0x73701155U, 0x886C5AD7U, 0x20B00715U, 0xE0377626U}},
		{{0xAA80BA59U, 0x7F01C9ECU, 0x68538E51U, 0x3083411AU, 0xE88128AFU, 0x970370F1U, 0x91DEC14BU, 0x625CC3DBU},
			{0x01AC3107U, 0xFEF9666CU, 0xD5057AC3U, 0xB2A8D577U, 0x92BE5DF7U, 0xB0F26299U, 0x00353924U, 0xF579C8E5U}},
		{{0x1341ED7AU, 0xB8FA3D93U, 0xA7B59D49U, 0x4223272CU, 0x83B8C4A4U, 0x3DCB1947U, 0xED1302E4U, 0x4E413C01U},
			{0xE17E44CEU, 0x6D999127U, 0x33B3ADFBU, 0xEE86BF75U, 0x25AA96CAU, 0xF6902FE6U, 0xE5AAE47DU, 0xB73540E4U}},
		{{0x1B4A158CU, 0x32801D7BU, 0x27E2A369U, 0xE571C99EU, 0x10D9F197U, 0x40CB76C0U, 0x3167C0AEU, 0xC308C289U},
			{0xEB7958F2U, 0xA6EF9DD3U, 0x300879B1U, 0xA7226DFCU, 0x7EDF0636U, 0x6CD0B362U, 0x7BC37EEDU, 0x4EFBCE6CU}},
		{{0x8D699021U, 0x75F92A05U, 0x772566E3U, 0x586D4C79U, 0x761AD23AU, 0x378CA5F1U, 0x1465A8ACU, 0x650D86FCU},
			{0x842BA251U, 0x7A4ED457U, 0x42234933U, 0x6B65E3E6U, 0x31AAD657U, 0xAF1543B7U, 0xCBFEC369U, 0xA4CEFE98U}},
		{{0x9F47BEFBU, 0xB587DA90U, 0x41312D13U, 0x6562E9FBU, 0xEFF1CEFEU, 0xA691EA59U, 0x05FC4CF6U, 0xCC30477AU},
			{0x0B0FFD3DU, 0xA1632461U, 0x5B355956U, 0xA1F16F3BU, 0x4224EC24U, 0x5B148D53U, 0xF977012AU, 0xDC834E7BU}},
		{{0xB2C69DBCU, 0x7BFC5E75U, 0x03C3DA6CU, 0x3AA77A29U, 0xCA910271U, 0xDE0DF03CU, 0x7806DC55U, 0xCBD5CA4AU},
			{0x6DB476CBU, 0xE1CA5807U, 0x5F37A31EU, 0xFDE15D62U, 0xF41AF416U, 0xF49AF520U, 0x7D342DB5U, 0x96C5C5B1U}},
		{{0xEB4CEB9BU, 0x155C43B7U, 0x4E77371AU, 0x2E993010U, 0x675D43AFU, 0x1D2987DAU, 0x8599FD72U, 0xEF2BC1C0U},
			{0x9342F6B2U, 0x96894B7BU, 0x7C8E71F0U, 0x201EADF2U, 0x4A1F3EFCU, 0xF3479D9FU, 0x702A9704U, 0xE0F8A742U}},
		{{0xB3EBA40CU, 0xEAFD44B6U, 0xC1C1E0D0U, 0xF9739F29U, 0x619D505EU, 0x0091471AU, 0x9D7C263EU, 0xC15F9C96U},
			{0x83AFBE33U, 0x5BE47285U, 0x04F1E092U, 0xA3B6D6AFU, 0x751A9D11U, 0xE76526B9U, 0x9A4AE4D2U, 0x2EC5B26DU}},
		{{0x02F6FB8DU, 0xEB66F4D9U, 0x96912164U, 0x4063C561U, 0x80EF3000U, 0xEB7050C1U, 0xEAA5B3F0U, 0x288D1C33U},
			{0x07806FD8U, 0xE87C68D6U, 0x4BBBF50FU, 0xB2F7F9D5U, 0xAC8D6627U, 0x25972F3AU, 0x10E8C13BU, 0xF8547774U}},
		{{0x872B4A60U, 0xCC50EF6CU, 0x4613521BU, 0xAB2A34A4U, 0x983E15D1U, 0x39C5C190U, 0x59905512U, 0x61DDE5DFU},
			{0x9F2275F3U, 0xE417F621U, 0x451D894BU, 0x0750C8B6U, 0x78B0BDAAU, 0x75B04AB9U, 0x458589BDU, 0x3BFD9FD4U}},
		{{0xEE9120B6U, 0xF1013E30U, 0x23A4743EU, 0x2B51AF93U, 0x48D14D9EU, 0xEA96FFAEU, 0x698A1D32U, 0x71DC0DBEU},
			{0x0180CCA4U, 0x914962D2U, 0xC3568963U, 0x1AE60677U, 0x437BC444U, 0x8CF227B1U, 0xC9962C7AU, 0xC650C83BU}},
		{{0xFE7CCFC4U, 0x23C2C7DDU, 0x1B929D48U, 0xF925C89DU, 0x06783C33U, 0x4460F74BU, 0xA590475AU, 0xAC2C8D49U},
			{0xB807BBA0U, 0xFB40B407U, 0x69FF8F3AU, 0x9D1E362DU, 0xCBEF64A4U, 0xA33E9681U, 0x332FB4B2U, 0x67ECE5FAU}},
		{{0x739F10E3U, 0x6900A99BU, 0xFF525925U, 0xC3341CA9U, 0xA9E2D041U, 0xEE18A626U, 0x29580DDDU, 0xA5A83685U},
			{0x9D7DE3CDU, 0xF3470C81U, 0x2062CF9CU, 0xEDF02586U, 0xC010EDB0U, 0xF43522FAU, 0x13A4B1AEU, 0x30314135U}},
		{{0xDB22B94BU, 0xC792E02AU, 0xA1EAA45BU, 0x993D8AE9U, 0xCD1E1C63U, 0x8AAD6CD3U, 0xC5CE688AU, 0x89529CA7U},
			{0xE572A253U, 0x2CCEE3AAU, 0x02A21EFBU, 0xE02B6438U, 0xC9430358U, 0xA7091B6EU, 0x9D7DB504U, 0x06D1B1FAU}},
		{{0xC4744733U, 0x58846D32U, 0x379F9E34U, 0x40517C71U, 0x130EF6CAU, 0x2F65655FU, 0xF1F3503FU, 0x526E4488U},
			{0x7EE4A976U, 0x8467BD17U, 0x921363D1U, 0x1D9DC913U, 0xB069E041U, 0xD8D24C33U, 0x2CDF7F51U, 0x5EB5DA0AU}},
		{{0x197B994FU, 0x1C0F3CB1U, 0x2843EAE9U, 0x3C95A6C5U, 0xA6097EA5U, 0x7766FFC9U, 0xD723B867U, 0x7BEA4093U},
			{0x4DB378F9U, 0xB48E1F73U, 0xE37B77ACU, 0x70025B00U, 0xAF24AD46U, 0x943DC8E7U, 0x16D00A85U, 0xB98A15ACU}},
		{{0x2743B004U, 0x3ADC38BAU, 0x334415EEU, 0xB1C7F4F7U, 0x1E62D05AU, 0xEA43DF8FU, 0x9D76A3B6U, 0x32618905U},
			{0xA23A0F46U, 0x2FBD0BB5U, 0x6A01918CU, 0x5BC971DBU, 0xB4743F94U, 0x7801D94AU, 0x676AE22BU, 0xB94DF65EU}},
		{{0xAF95894CU, 0xAAFCBFABU, 0x276B2241U, 0x7B9BDC07U, 0x5BDDA48BU, 0xEAF98362U, 0xA3FCB4DFU, 0x5977FAF2U},
			{0x052C4B5BU, 0xBED042EFU, 0x067591F0U, 0x9FE87F71U, 0x22F24EC7U, 0xC89C73CAU, 0xE64A9F1BU, 0x7D37FA9EU}},
	},
	{
		{{0x0A750C0FU, 0xCC7A6488U, 0x4E548E83U, 0x39BACFE3U, 0x0C110F05U, 0x3D418C76U, 0xB1F11588U, 0x3E4DAA4CU},
			{0x5FFC69FFU, 0x2733E7B5U, 0x92053127U, 0x46F147BCU, 0xD722DF94U, 0x885B2434U, 0xE6FC6B7CU, 0x6A444F65U}},
		{{0xC3F16EA8U, 0x7A1A465AU, 0xB2F1D11CU, 0x115A461DU, 0x6C68A172U, 0x4767DD95U, 0xD13A4698U, 0x3392F2EBU},
			{0xE526CDC7U, 0xC7A99CCDU, 0x22292B81U, 0x8E537FDCU, 0xA6D39198U, 0x76D8CF69U, 0x2446852DU, 0xFFC5FF43U}},
		{{0xBDAEDFBDU, 0x6D0B16F4U, 0x86746CEDU, 0x23FD3260U, 0xFF4B3E17U, 0x8BFB1D2FU, 0x019C14C8U, 0xC7F2EC2DU},
			{0x45104B0DU, 0x3E0832F2U, 0xADEA2B7EU, 0x5F00DAFBU, 0x99FBFB0FU, 0x29E5CF66U, 0x61827CDAU, 0x264F9723U}},
		{{0xA90567E6U, 0x97B14F7EU, 0xB6AE5CB7U, 0x513257B7U, 0x9F10903DU, 0x85454A3CU, 0x69BC3724U, 0xD8D2C9ADU},
			{0x6B29CB44U, 0x38DA9324U, 0x77C8CBACU, 0xB540A21DU, 0x01918E42U, 0x9BBFE435U, 0x56C3614EU, 0xFFFA707AU}},
		{{0xE30BC27FU, 0x6EB1A2F3U, 0xB0836511U, 0xE5F0C05AU, 0x4965AB0EU, 0x4D741BBFU, 0x83464BBDU, 0xFEEC41CAU},
			{0x99D0B09FU, 0x1ACA705FU, 0xF42DA5FAU, 0xC5D6CC56U, 0xCC52B931U, 0x49964EDDU, 0xC884D8D8U, 0x8AE59615U}},
		{{0xD4E353B7U, 0x0CE4E3F1U, 0xEF46B0A0U, 0x062D8A14U, 0x574B73FDU, 0x6408D5ABU, 0xD3273FFDU, 0xBC41D1C9U},
			{0x6BE77800U, 0x3538E1E7U, 0xC5655031U, 0x71FE8B37U, 0x6B9B331AU, 0x1CD91621U, 0xBB388F73U, 0xAD825D0BU}},
		{{0x39F8868AU, 0xF634B57BU, 0x75CC69AFU, 0xE27F4FD4U, 0xD0D5496EU, 0xA47E58CBU, 0xD323E07FU, 0x8A26793FU},
			{0xFA30F349U, 0xC61A9B72U, 0xB696D134U, 0x94C9D9C9U, 0x5880A6D1U, 0x792BECA8U, 0xAF039995U, 0xBDCC4645U}},
		{{0x1CB76219U, 0x56C2E05BU, 0x71567E7EU, 0x0EC0BF91U, 0x61C4C910U, 0xE7076F86U, 0xBABC04D9U, 0xD67B085BU},
			{0x5E93A96AU, 0x9FB90459U, 0xFBDC249AU, 0x7526C1EAU, 0xECDD0BB7U, 0x0D44D367U, 0x9DC0D695U, 0x95399917U}},
		{{0x8C796C3CU, 0xCE7EF8E5U, 0xDD66E57AU, 0x9ADAAE84U, 0x45227F33U, 0x784AE13EU, 0x2A85E757U, 0xB046C5B8U},
			{0xEC37631FU, 0xB7AA50AEU, 0x3B300758U, 0xBEDC4FCAU, 0x0AC9700BU, 0x0F82567EU, 0x4FF5F8D2U, 0x1071D9D4U}},
		{{0x9E240D18U, 0x61360EE9U, 0xB4B94466U, 0x057CDCACU, 0x2FE5325CU, 0xE7667CD1U, 0x21974E3BU, 0x1FA297B5U},
			{0xDB083D76U, 0xFA4081E7U, 0xF206BD15U, 0x31993BE6U, 0x14C19F8CU, 0x8949269BU, 0xA9D92357U, 0x21468D72U}},
		{{0xE51A2811U, 0xD09EF6C4U, 0xB8FB66B9U, 0x39F6862BU, 0x22DFAA99U, 0x64E77F8DU, 0x61B08AACU, 0x7B105044U},
			{0x4A7DF332U, 0x71704E4CU, 0x2FFE015BU, 0xD0973434U, 0x08D3020EU, 0xAB0EAF44U, 0xED63B97AU, 0x28B1909EU}},
		{{0xA4C506ECU, 0x2CCBC583U, 0xD1ACFE97U, 0x957ED188U, 0x12F1AEA2U, 0x8BAED833U, 0x8325362DU, 0xEF2A6CB4U},
			{0x8E195C43U, 0x130DDE42U, 0x0E6050C6U, 0xC842025AU, 0x08686A5DU, 0x2DA972A7U, 0xE508B4A8U, 0xB52999A1U}},
		{{0xCDADCD4FU, 0x2F3FA882U, 0x5F631995U, 0xA4EF6859U, 0xE531766FU, 0xE52CA2F9U, 0x57E2C1D3U, 0x20AF5C30U},
			{0xE51E94B8U, 0x1E4828F6U, 0x1A2F5D4FU, 0xF900A175U, 0x392C58A0U, 0xE831ADB3U, 0x1B6E5866U, 0x4C5A90CAU}},
		{{0x10A5A8BDU, 0xD9F090B9U, 0x096864DAU, 0xCA91D249U, 0x3F67DBC1U, 0x8E6A93BEU, 0xF5F4764CU, 0xACAE6FBAU},
			{0xD21411A0U, 0x1563C6E0U, 0xDA0A4AD8U, 0x28FA787FU, 0x908C8030U, 0xD524491CU, 0x4C795F07U, 0x1257BA0EU}},
		{{0x6182827CU, 0x5F3DCBA8U, 0xBD7E7252U, 0xD1A448DDU, 0xF493B815U, 0x2D8F96FCU, 0x3B0AA95FU, 0xBA0A4C26U},
			{0x63A0007FU, 0x88A15140U, 0x6A9C5846U, 0x9564C25EU, 0xDC0FCBCAU, 0x5A4D7B0FU, 0x3F8A740EU, 0x2275DAA3U}},
		{{0xCECA9754U, 0x83F49167U, 0x4B7939A0U, 0x426D2CF6U, 0x723FD0BFU, 0x2555E355U, 0xC4F144E2U, 0xA96E6D06U},
			{0x87880E61U, 0x4768A8DDU, 0xE508E4D5U, 0x15543815U, 0xB1B65E15U, 0x09D7E772U, 0xAC302FA0U, 0x63439DD6U}},
		{{0x0461086BU, 0x159591CCU, 0x95E66E51U, 0xB695AA94U, 0x79DED531U, 0x2D4C9467U, 0x89C2BE79U, 0xBD2482BAU},
			{0xA20BBF19U, 0x8EE2658AU, 0x32247917U, 0xC000528AU, 0xFFEAE845U, 0xD924BE4AU, 0xED992C8BU, 0x51312BEBU}},
		{{0xC14E35C2U, 0xB93F802FU, 0x4341333CU, 0x71735B7CU, 0x16D4F362U, 0x03A25104U, 0xBF433C8EU, 0x3F4D069BU},
			{0xF78F5A7CU, 0x0D83AE01U, 0x7C4EED07U, 0x50A8FFBEU, 0x76E10F83U, 0xC74F8906U, 0x9DDAF8E1U, 0x7D080966U}},
		{{0xDC752BD9U, 0x3A01B958U, 0x0C215D45U, 0x2BABDBC2U, 0x131641C1U, 0xE689D79AU, 0x80E05ED4U, 0x48E8F0DAU},
			{0x77BB70C4U, 0x4B505FEBU, 0xB6057EF7U, 0xEFBD3E2BU, 0xCE603CA5U, 0x7583E22DU, 0x2C5C70C7U, 0xFBE3B1F2U}},
		{{0x698E04CCU, 0xB11DF8E1U, 0x169005C8U, 0x877BE203U, 0x4F3C6179U, 0x32749E8CU, 0x7853FC05U, 0x2DBC9D0AU},
			{0x9454D937U, 0x187D4F93U, 0xB4800E1BU, 0xE682CE9DU, 0x165E68E8U, 0xA9129AD8U, 0xBE7F785BU, 0x0FE29735U}},
		{{0x29E5E35AU, 0x8EC1ECF0U, 0x8645C2B3U, 0x2F3168E5U, 0xC7F94CB2U, 0xE9297362U, 0xD1C90B39U, 0x4FBF1466U},
			{0x920BAE2AU, 0x3E4F7656U, 0xF1BEB172U, 0x805D04B9U, 0xDBDBD4B4U, 0x729A7208U, 0x87AECA53U, 0x1AADE456U}},
		{{0x5B9E02B7U, 0x5303F40CU, 0x35EE04E8U, 0xA37C9692U, 0x34D6632BU, 0x5F46CC20U, 0x96AC545BU, 0x55EF72B2U},
			{0x7B91B062U, 0xABEC5C1FU, 0xBB33E821U, 0x0A79E1C7U, 0x3A9F4117U, 0xBB04B428U, 0xFD2A475AU, 0x0DE1F28FU}},
		{{0x1934A508U, 0xB0FF1F54U, 0x04BBF31AU, 0x19E13976U, 0x3717A6B4U, 0xB2A8E603U, 0x0EF12CB9U, 0xD601E45DU},
			{0xB515E98EU, 0x563F0AF5U, 0x33984F9BU, 0x9B129DB6U, 0xA47E4A65U, 0xE34ABA2FU, 0x9E3F9D82U, 0xB56F82D1U}},
		{{0x3A4434B4U, 0x31019CCFU, 0x1A7954DCU, 0xA3458111U, 0xE34972A7U, 0xA9DAC80DU, 0x74F6B8DDU, 0xB043D054U},
			{0x11137B1AU, 0x021C319EU, 0xED5CC03FU, 0x00A754CEU, 0xCBEA5AD4U, 0x0AA2C794U, 0x70C015B6U, 0x093E67F4U}},
		{{0xB1209B86U, 0x0203EFFDU, 0xB19D6CBFU, 0x21F063EDU, 0x980F275BU, 0x59F53476U, 0xB7AC5E80U, 0x202456D7U},
			{0x4900EDC9U, 0xE5A8C05FU, 0x70F01E86U, 0x04C08EB4U, 0x1DCD98CEU, 0xF74AC224U, 0xE2E830DBU, 0x7E77CC0CU}},
		{{0xC97E3F6BU, 0x72CDFEE9U, 0xB6DA7461U, 0xC10BCAB4U, 0xB59806B9U, 0x3B02D2FCU, 0xA1DE6F47U, 0x85185E89U},
			{0x0EB6C4D4U, 0x39E6931FU, 0xD4FA5B04U, 0x4D4440BDU, 0x34BE7EB8U, 0x5418786EU, 0x9D7259BCU, 0x6380E521U}},
		{{0xA9747EDEU, 0x74E37234U, 0x361B1013U, 0x4FC9FBB1U, 0x3CF357EFU, 0xE7B53373U, 0x991C4193U, 0x6AA2DD2CU},
			{0xA770917AU, 0x7887E4D2U, 0xC20D24CBU, 0xDD1809B4U, 0x8E9C2D3EU, 0x004CD7C3U, 0xA9970ABEU, 0xC77C5BABU}},
		{{0xD598D710U, 0x20AC0351U, 0xCB3A4DA4U, 0x272C4166U, 0xCA71DE1FU, 0xDB82FE1AU, 0xD8F54B0FU, 0x746E79F2U},
			{0x4B573E9BU, 0x6E7FC736U, 0xFD4B5040U, 0x75D03F46U, 0x0B98D87BU, 0x5C1CC36DU, 0x1F472DA1U, 0x513BA3F1U}},
		{{0xC3AF237FU, 0x52927EAAU, 0xD7398767U, 0xFAA06065U, 0x97C6CE0BU, 0x042E72B4U, 0x0A9F2361U, 0xDAED0CC4U},
			{0x2FC1BB4AU, 0xDDC2E11CU, 0x0C1A9EF8U, 0x631DA577U, 0x680272BFU, 0x8A4CFE44U, 0x62FB5CC3U, 0xC76B9F72U}},
		{{0xABB177DDU, 0x79D0AF26U, 0x7891D564U, 0xF82AB568U, 0x72232173U, 0x2B6768A9U, 0x8C1F6619U, 0xEFBB3BB0U},
			{0xA6D18358U, 0xB29C11DBU, 0xB0916D3AU, 0x519E2797U, 0x9188E290U, 0xD4DC18F0U, 0x98B0CA7FU, 0x648E86E3U}},
		{{0x38B3AAE3U, 0x248F8145U, 0xBC204334U, 0xB5345864U, 0x1D127524U, 0x66D6B5BCU, 0x14F572D3U, 0xE312080DU},
			{0x16ABAFEBU, 0x13ED15A7U, 0xDBA967BEU, 0x6F18CE27U, 0xEF08552DU, 0x96C9E826U, 0xBE2B63E0U, 0x2C191B06U}},
		{{0x983C38B5U, 0x859D3145U, 0x637ABC8BU, 0xB14F176CU, 0xCAFF7BE6U, 0x2793FB9DU, 0x35A66A5AU, 0xEBE5A55FU},
			{0x9F87DC59U, 0x7CEC1DCDU, 0xFBDBF560U, 0x7C595CD3U, 0x26EB3257U, 0x5B543B22U, 0xC4C935FDU, 0x69080646U}},
	},
	{
		{{0x1D531696U, 0xB9345238U, 0x88CDDE69U, 0x57201C00U, 0x9A86AFC7U, 0xDDE92251U, 0xBD35CEA8U, 0xE3043895U},
			{0x8555970DU, 0x7608C1E1U, 0x2535935EU, 0x8267DFA9U, 0x322EA38BU, 0xD4C60A57U, 0x804EF8B5U, 0xE0BF7977U}},
		{{0xC094DBB5U, 0x6233EA68U, 0xD968D410U, 0xB77D062EU, 0x58B3002DU, 0x3E719BBCU, 0x3DC49D58U, 0x68E7DD3DU},
			{0x013A5E58U, 0x8D825740U, 0x3C9E3C1BU, 0x21311747U, 0x7C99B6ABU, 0x0CB0A2A7U, 0xC2F888F2U, 0x5C48A3B3U}},
		{{0x2927D4CAU, 0x4C5C4BE1U, 0x518F848EU, 0xB0F23F16U, 0x0C757BCBU, 0x84F78922U, 0x325DEB96U, 0x35BD1CBBU},
			{0x7D0DE10AU, 0xBDB186FBU, 0xB22C9685U, 0xD07350E3U, 0xEF45C641U, 0x3F95393EU, 0xD07B6D44U, 0xB8870FF1U}},
		{{0x991724F3U, 0xC7913E91U, 0x39CBD686U, 0x5EDA799CU, 0x63D4FC1EU, 0xDDB595C7U, 0xAC4FED54U, 0x6B63B80BU},
			{0x7E5FB516U, 0x6EA0FC69U, 0xD0F1C964U, 0x737708BAU, 0x11A92CA5U, 0x9628745FU, 0x9A86967AU, 0x61F37958U}},
		{{0x47A2659FU, 0x64CF0A65U, 0x33380BCBU, 0x1218F430U, 0x0FD98A74U, 0xFC1DE4E4U, 0xF09EEDB8U, 0xAEC4EC8FU},
			{0x95C56083U, 0xDE6DB5E1U, 0x07DC16A1U, 0x3307B056U, 0xC0D47097U, 0x1482C186U, 0x514C3A66U, 0xA08319ACU}},
		{{0x0979E6B3U, 0x5320FD61U, 0x93D40723U, 0x1D0BD3E5U, 0xAA80BACCU, 0x0AC006FCU, 0xD2002515U, 0xB1D9C60EU},
			{0xAF780B92U, 0x610E7ED0U, 0x80A9CE31U, 0xF5BF446EU, 0x3C20B54BU, 0x441C011DU, 0x191596C3U, 0x77F76DA1U}},
		{{0x4D4094B4U, 0x972E5B2BU, 0x5E96DE5FU, 0x4B49954FU, 0x4F870D59U, 0x6CA8E40AU, 0x45A68DEFU, 0x9EE2886FU},
			{0xC4439A13U, 0xAE0260ECU, 0xB4CFB71FU, 0x45AECD3EU, 0x4E327620U, 0x50C5D9B6U, 0x86182CF3U, 0x470ADADBU}},
		{{0xAA665072U, 0x9AF39B2CU, 0xEFD324EFU, 0x78322FA4U, 0xC327BD31U, 0x3D153394U, 0x3129DAB0U, 0x81D5F271U},
			{0xF48027F5U, 0xC72E0C42U, 0x8536E717U, 0xAA40CDBCU, 0x2D369D0FU, 0xF45A657AU, 0xEA7F74E6U, 0xB03BBFC4U}},
		{{0xF37C69F0U, 0x4AB70789U, 0x01C5802DU, 0x3226D878U, 0x360DF497U, 0x4FE7424CU, 0x5F890D50U, 0x9EAED4E5U},
			{0xDD3729C6U, 0x208E995CU, 0xD00DEAF3U, 0xF743BD5CU, 0xF161847DU, 0xFE5A1310U, 0x941A3F25U, 0x34E775A2U}},
		{{0x9B6A42EAU, 0x7A04D542U, 0x3DAF41B9U, 0xFA597E85U, 0x726B0B89U, 0x4C58EC27U, 0x030D43DEU, 0xED8EB16AU},
			{0xEC9DCF57U, 0x65E1E5E1U, 0x697CFF81U, 0xB7A770C1U, 0x9F6E2B22U, 0x1E6D918FU, 0xC64E82B7U, 0x7C277A9AU}},
		{{0x7B1F35CFU, 0xE5C869C8U, 0x55D1D237U, 0x29FA6937U, 0xDE579C44U, 0x05C574EEU, 0x336D590CU, 0x45BB912BU},
			{0x777D4DEBU, 0x5D172D85U, 0x7B6C6567U, 0x1A37CCA9U, 0x25373A8AU, 0x1CA1433AU, 0x1C77353AU, 0xD23C94A8U}},
		{{0x0D738DEDU, 0x46A8C418U, 0xE0DE5729U, 0x6F1A5BB0U, 0x8BA81675U, 0xF10230B9U, 0x112B33D4U, 0x32C6F30CU},
			{0xD8FFFB62U, 0x7559129DU, 0xB459BF05U, 0x6A281B47U, 0xFA3B6776U, 0x77C1BD3AU, 0x7829973AU, 0x0709B380U}},
		{{0xC935A361U, 0x7989227CU, 0xE39A0A7EU, 0xFD17F8AAU, 0x269163BAU, 0x2E5C5E86U, 0xC663EAF4U, 0x07C98E78U},
			{0x422EA36EU, 0x64E8209AU, 0x4C6A0882U, 0x1BE8B391U, 0xEC4FA55EU, 0x4BAC4503U, 0xAD7868DFU, 0xBAEEA7CAU}},
		{{0xDA36CB47U, 0x0875E0C1U, 0x1E0210F0U, 0xFDF5B7CBU, 0x3A3787C8U, 0x7E0C7E4DU, 0x2B1C741FU, 0xF043F526U},
			{0x6D74D72DU, 0x76DF1B00U, 0x38B45BA9U, 0x0514DF73U, 0x0A6B797AU, 0xAECF7C3EU, 0xDDEAAC39U, 0x5E30B285U}},
		{{0xAC69E3DBU, 0xFF69339CU, 0x59E9D6BDU, 0x74ECC83CU, 0x820A8482U, 0x67237B37U, 0x072DFA23U, 0x943A3035U},
			{0x8F48BDB8U, 0x6E4210D2U, 0x2EECC7F4U, 0x88517516U, 0x632A187FU, 0x0B05C5F4U, 0xD97D1D4CU, 0xCAFDFB5EU}},
		{{0xA3326505U, 0x8C26B232U, 0xEE1D41BFU, 0x38D69272U, 0xFFE32AFAU, 0x0459453EU, 0x7CB3EA87U, 0xCE8143ADU},
			{0x7E6AB666U, 0x932EC1FAU, 0x22286264U, 0x6CD2D230U, 0x6736F8EDU, 0x459A46FEU, 0x9ECA85BBU, 0x50BF0D00U}},
		{{0x3DA2EBB4U, 0x06C16BBAU, 0x32557C3EU, 0xF35B21BBU, 0x30076711U, 0x95B12312U, 0x1B7611F0U, 0x873AA076U},
			{0xEA3A6D61U, 0x31F69026U, 0x42A6BE4CU, 0x7AC9B86BU, 0x4B6C2802U, 0xD3B5D7C7U, 0xAB281DE0U, 0xCD4894ACU}},
		{{0x605238A5U, 0x15C78F7DU, 0x448496ABU, 0xE9D87842U, 0xD210ACC1U, 0xCFCF75D0U, 0x5C8C14E2U, 0x2948F229U},
			{0xE8DAF0CBU, 0xE81FD76DU, 0xA03BE800U, 0xD02D11E4U, 0x8778D30CU, 0x0C4DF351U, 0x965139CBU, 0x3482BC96U}},
		{{0x49811D68U, 0xEFA0D701U, 0x1EA1A04EU, 0xE4F6C8E5U, 0x82237640U, 0x5990E1FDU, 0x1D80DB96U, 0xEFA225F9U},
			{0x3A96CCDAU, 0x17431C95U, 0xFC3FA192U, 0x461BAAC1U, 0xBBC184B4U, 0x3BE2F407U, 0x0D05D39CU, 0xD776DE1DU}},
		{{0x877A21ECU, 0x0B825852U, 0x0F537A94U, 0x300414A7U, 0x21A9A6A2U, 0x3F1CBA40U, 0x76943C00U, 0x50824EEEU},
			{0xF83CBA5DU, 0xA0DBFCECU, 0x93B4F3C0U, 0xF9538148U, 0x48F24DD7U, 0x61744162U, 0xE4FB09DDU, 0x5322D64DU}},
		{{0xDC73A705U, 0xF1B09ED2U, 0x01A11A6EU, 0x142B00C8U, 0x98A132C9U, 0x726484B0U, 0x26E1567AU, 0xF3B5EF63U},
			{0x574BFC03U, 0x43BED2D0U, 0x768F722FU, 0x74791E38U, 0x4CE97ED8U, 0x7A189FB3U, 0x168A5F43U, 0x2B9B2C96U}},
		{{0x8A448BBCU, 0x56B6CF27U, 0xC85251DAU, 0x0CA898DFU, 0x36E79B24U, 0x9082CAD8U, 0x1A8E51A7U, 0x2E7B9ED3U},
			{0x43E1C802U, 0xDC7D318AU, 0xCBF8689DU, 0x4750E523U, 0xF0071B1AU, 0x9887A072U, 0x814BFDC1U, 0x52090F87U}},
		{{0x8D736EB9U, 0x4821852EU, 0x544C1E6BU, 0x29A928D3U, 0x77800586U, 0x1AA411AEU, 0x1B0A5793U, 0xE94D067BU},
			{0xA65E46ADU, 0xB59D8B4BU, 0xCD941804U, 0x3C62BA87U, 0x9920E61BU, 0xFDB54B78U, 0x0A181AACU, 0xE923F284U}},
		{{0x3D9325F3U, 0x57447384U, 0xF371CB84U, 0xA9BEF2D0U, 0xA61E36C5U, 0x77D2188BU, 0xC602DF72U, 0xBBD6A7D7U},
			{0x8F61BC0BU, 0xBA3AA902U, 0x6ED0B6A1U, 0xF49085EDU, 0xAE6E8298U, 0x8BC625D6U, 0xA2E9C01DU, 0x832B0B1DU}},
		{{0x70D1CAA0U, 0xC2B45C82U, 0x724AB557U, 0x44CE41D0U, 0x138271FDU, 0x57984BACU, 0xCB3608C8U, 0x67E0C934U},
			{0x5455F703U, 0xC888FA45U, 0x727B02B0U, 0xE9C5B8B4U, 0x7C7130A4U, 0xDC3EF0F0U, 0x4B09270CU, 0xD9E4BEA3U}},
		{{0x6196BC6EU, 0x5BEBF219U, 0xEF097EFDU, 0x0E66736BU, 0xEA87293AU, 0x1128F3B8U, 0x6ADDFCDEU, 0x2998E405U},
			{0x5D16C961U, 0x55CC31B8U, 0x2418F056U, 0x87A434E1U, 0xDC9FE819U, 0x2E94AACCU, 0xA56490C6U, 0x94A486C1U}},
		{{0xCB8D2BB3U, 0x8A4D83D4U, 0xFFD2B1FDU, 0xEA796AA8U, 0x04CA79F6U, 0x6575AB51U, 0xC46B86CFU, 0xF4F0D536U},
			{0x670E6B58U, 0x461EC5D9U, 0x0EAED108U, 0x705053F8U, 0x14DD16F7U, 0xDAF45BCEU, 0xC4B2CF65U, 0x406F2D49U}},
		{{0xF1F0CED1U, 0xA337C447U, 0x9492DD2BU, 0x800CC793U, 0xBEA08EFAU, 0x4B93151DU, 0xDE0A741EU, 0x820CF3F8U},
			{0x1C0F7D13U, 0xFF1982DCU, 0x84DDE6CAU, 0xEF921960U, 0x45F96EE3U, 0x1AD7D972U, 0x29DEA0C7U, 0x319C8DBEU}},
		{{0xE82EF5F8U, 0x6D1CDC80U, 0x2F1C7FB3U, 0x095DF9F0U, 0xA3CFD888U, 0xC87F34B9U, 0x340208E1U, 0xD5D77095U},
			{0x918851CBU, 0x4A1AECE4U, 0x602B7142U, 0xD7B1F5C1U, 0xC6524F82U, 0xF0D39813U, 0x6BB01DB5U, 0xF6D96EAEU}},
		{{0xDE259EC8U, 0x1FF2385BU, 0x30F67B0DU, 0xF6B0836AU, 0x06661CFFU, 0x04CC65B0U, 0xD4230F5CU, 0x467E6358U},
			{0x2DBED3D3U, 0xCE468C80U, 0xF1920DA6U, 0x7B984262U, 0x1537479FU, 0x34D25742U, 0x87BB8DE1U, 0x5C8AA88CU}},
		{{0x54AFA56AU, 0x32F768A1U, 0xFAF184E5U, 0xA51EECA3U, 0x618C7468U, 0x20CECB44U, 0x87862CC0U, 0x3434D15FU},
			{0xAEF55DF6U, 0x713C3811U, 0x81E3F8F0U, 0x2CD7C049U, 0xFF2F99BEU, 0xEE68D439U, 0x2B5DA6A6U, 0x79B64EE7U}},
		{{0x7B82B99BU, 0xD3EA3871U, 0x470EB624U, 0x75922D4DU, 0x3B95D466U, 0x8F66EC54U, 0xBEE1E346U, 0x66E673CCU},
			{0xB5F2B89AU, 0x6AFE67C4U, 0x290E5CD3U, 0x3DE9C1E6U, 0x310A2ADAU, 0x8C278BB6U, 0x0BDB323BU, 0x420FA384U}},
	},
	{
		{{0x6424C49BU, 0x646F9679U, 0x67C241C9U, 0xF888DFE8U, 0x24F68B49U, 0xE12D4B93U, 0xA571DF20U, 0x9A6B62D8U},
			{0x179483CBU, 0x81B4B26DU, 0x9511FAE2U, 0x666F9632U, 0xD53AA51FU, 0xD281B3E4U, 0x7F3DBD16U, 0x7F96A765U}},
		{{0x051AF62BU, 0x8553D37CU, 0x0BF94496U, 0xE9A998EBU, 0xB0D59AA1U, 0xE0844F9FU, 0xE6AFB813U, 0x983FD558U},
			{0x65D69804U, 0x9670C0CAU, 0x6EA5FF2DU, 0x732B22DEU, 0x5FD8623BU, 0xD7640BA9U, 0xA6351782U, 0x9F619163U}},
		{{0xBDEFDD4FU, 0xF167B4E0U, 0xF366E401U, 0x69958465U, 0xA73BBEC0U, 0x5AA368ABU, 0x7B240C21U, 0x12148709U},
			{0x18969006U, 0x378C3233U, 0xE1FE53D1U, 0xCB4D73CEU, 0x130C4361U, 0x5F50A80EU, 0x7EF5212BU, 0xD67F5951U}},
		{{0x8CAD38C0U, 0x332F8108U, 0x6BD68AE2U, 0x471B7E90U, 0x0D8E27A3U, 0x56AC3FB2U, 0x136B4B0DU, 0xB54660DBU},
			{0xA6FD8DE4U, 0x123A1E11U, 0xA37799EFU, 0x44DBFFEAU, 0xCE6AC17CU, 0x4540B977U, 0xAF60ACEFU, 0x495173A8U}},
		{{0x4573EAB0U, 0xEB443743U, 0xD1AC6031U, 0x11570DFBU, 0x44DD9AFDU, 0xF7D9B45BU, 0x22067231U, 0xB8066ADDU},
			{0xF8A3F0B4U, 0x15F92AD8U, 0xE0ACE2A2U, 0x9E0E4899U, 0xFAB38B80U, 0xBDCD0AADU, 0x17020052U, 0x46506AE9U}},
		{{0x8FCA399DU, 0x429A69F7U, 0x0207BB63U, 0xFE9E27D2U, 0x8788F582U, 0xEC655ED6U, 0xADB75F6EU, 0xA426D748U},
			{0xCA81C66DU, 0x18695C02U, 0xA531D425U, 0x84FB8D27U, 0xDEFF48BAU, 0x3A3A8956U, 0x766D2247U, 0xAF1D0D56U}},
		{{0x352C4B5CU, 0x5A059565U, 0x590BC3E2U, 0x49261531U, 0xF66F9F5FU, 0x809F7521U, 0xC70A4A9BU, 0x2BAEF6BFU},
			{0x09ED3561U, 0xE7E6FA65U, 0x984B230CU, 0x11370233U, 0xD04CDC69U, 0x2151659BU, 0xF007D416U, 0xBDB83C63U}},
		{{0x391C2A82U, 0x9EBB284DU, 0x158308E8U, 0xBCDD4863U, 0x83F1EDCAU, 0x006F16ECU, 0x695DC6C8U, 0xA13E2C37U},
			{0x4A057A87U, 0x2AB756F0U, 0xA6B48F98U, 0xA8765500U, 0x68651C44U, 0x4252FACEU, 0xE1765E02U, 0xA52B540BU}},
		{{0x5CA37FF0U, 0xCB35A1A8U, 0xCD2F1C8FU, 0xE1A04F1CU, 0x15A26112U, 0x238816CEU, 0x095B177EU, 0xE206A111U},
			{0x8A424149U, 0x3C10B604U, 0x74752CFBU, 0xC6A3F567U, 0x47F1DBB8U, 0xBF16A37AU, 0xD31A3DFBU, 0x7C372F9AU}},
		{{0xC20B4D2AU, 0x122D05B5U, 0x0C662A67U, 0xFF659CF5U, 0xE8FFC9E9U, 0xED57C128U, 0x9E987683U, 0x0FBB1585U},
			{0x47319A2BU, 0xADD70DF2U, 0x374BE470U, 0x4B98BABAU, 0x56A7B307U, 0xF03D7473U, 0x3EFEBF30U, 0x342E696EU}},
		{{0x864AC537U, 0xF84B48F7U, 0xA6940D3DU, 0x04713409U, 0x6174C7AEU, 0x014DB22DU, 0x8C213034U, 0xC73A1C43U},
			{0xFFDD93ECU, 0x18AC4EA5U, 0x6102783EU, 0x724FC757U, 0x91C3E83FU, 0x9FE13FCCU, 0xF08F0BF5U, 0x92A8C2C8U}},
		{{0x8F67F6DEU, 0x7F2E22FDU, 0xD8693177U, 0xAB018833U, 0x863ECA95U, 0x266D1DB6U, 0x31B5EF2BU, 0x6BB7732BU},
			{0x915F80CEU, 0x4FA927C6U, 0x5F90EFD8U, 0x6FA1D6D2U, 0x456B48ADU, 0x7BD75DE8U, 0x845B6429U, 0xD2CB507AU}},
		{{0xE255D7ECU, 0xA72CF82AU, 0xA460E204U, 0x52025C23U, 0x7D5B0A44U, 0x10AE542DU, 0x9305AEDAU, 0xA8514310U},
			{0xA14BBFE8U, 0x958315F5U, 0x385365FEU, 0x3F361826U, 0x66D95040U, 0xC2B3A36BU, 0x7CF4EDA2U, 0x12C7B334U}},
		{{0xE744119DU, 0xA545B4D1U, 0x829A71E7U, 0x4C93B169U, 0x6117FCBFU, 0x2DBB908CU, 0xB35A3D85U, 0x4DC97320U},
			{0x6BF88105U, 0x94C04F85U, 0x1B51BC1FU, 0x452E1BCEU, 0xB3013AF3U, 0x0C41FF50U, 0x224D7E24U, 0xF07AF445U}},
		{{0xA3D24F6AU, 0xBDB9E57CU, 0xF345A763U, 0x8A8246D7U, 0x98CFBB5FU, 0x73BD2A6DU, 0x86ED04DBU, 0x1DD8E85EU},
			{0xC01F420BU, 0x76F2DA42U, 0x64407BC7U, 0x7EF05473U, 0xAFF548F5U, 0x7E98BA7FU, 0xFD30B64AU, 0x6B7AFBEEU}},
		{{0x16A0D2BBU, 0x4F922FC5U, 0x1A623499U, 0x0D5CC16CU, 0x57C62C8BU, 0x9241CF3AU, 0xFD1B667FU, 0x2F5E6961U},
			{0xF5A01797U, 0x5C15C70BU, 0x60956192U, 0x3D20B44DU, 0x071FDB52U, 0x04911B37U, 0x8D6F0F7BU, 0xF648F916U}},
		{{0xEB2572F8U, 0x067639EAU, 0xD70853CEU, 0xB0CEF632U, 0xE9989004U, 0xD87F1F31U, 0xA26582C0U, 0x94AA7236U},
			{0xB0C2C656U, 0x4211B8E5U, 0xA257414EU, 0x05AAA79BU, 0xE0F09AB0U, 0x0672F841U, 0x3EC81C65U, 0xA3C5F9BFU}},
		{{0xE003F0FAU, 0x4CF6379AU, 0x1E75C8B0U, 0x7917E087U, 0xA1383C9FU, 0x1DC059FCU, 0x64480967U, 0xA8614EA6U},
			{0x79625DD1U, 0xC34D0D01U, 0x4200E788U, 0x7D47A1E1U, 0xA754A59DU, 0xAEF99D1EU, 0x49B14178U, 0x1C812D00U}},
		{{0x0877B3A7U, 0xA4A11BB6U, 0x2CD521A9U, 0x244D11A6U, 0xBFF5C62CU, 0x464B19B7U, 0x9076657CU, 0x27F3EBA7U},
			{0x0C7581A9U, 0x483ABF97U, 0xAE0B22F3U, 0x2EF108E0U, 0x5064BCD5U, 0xD603F366U, 0x5BF5025EU, 0xCF4875A7U}},
		{{0xD0D5D22CU, 0xAB9302E5U, 0x30124030U, 0xD0A7E6B0U, 0x4F0AA1F4U, 0xE262C57BU, 0x0BBA202EU, 0x497A58A5U},
			{0xE6CFCCACU, 0x109FD21EU, 0x8A1927ECU, 0xB596CCE6U, 0x3B02E85AU, 0x48B9F7E8U, 0x08591134U, 0xBF7EF83CU}},
		{{0x62EDC562U, 0xE05E91B1U, 0x62BCD185U, 0xB5E1FE72U, 0xB8105B19U, 0x1D526908U, 0x896BBB22U, 0x0D11447EU},
			{0x2C2213F0U, 0x647AAA49U, 0x2E2FC14BU, 0xF6C9F8C6U, 0xBC4168C6U, 0x90CA259AU, 0xDD8E3461U, 0x3BB92762U}},
		{{0x5B20189AU, 0x157FC094U, 0x0BF5C8ABU, 0x6E72C62DU, 0x357750B7U, 0xF7F489E1U, 0xF87D31C5U, 0x18511AB2U},
			{0x005F35C5U, 0xA4267827U, 0x9480ED6DU, 0xA28CA054U, 0x77247DB2U, 0x20EFDE7CU, 0xA4149D60U, 0x5E160439U}},
		{{0xF3DEAE70U, 0x5C10B148U, 0x6EABC433U, 0x02044B53U, 0xFE63F18EU, 0x1E82790CU, 0xAA695FF1U, 0x2886B65AU},
			{0x4627A4EDU, 0x994FDF93U, 0x872EB0B9U, 0xE9B4DEC0U, 0x58F7A28FU, 0x4C0BEC8DU, 0xEAF9C5FEU, 0xC30C4DEDU}},
		{{0xE60B7CF7U, 0x6DC1ACAFU, 0x84A9D869U, 0x25860A50U, 0xE7BA8AC4U, 0x56FC6F09U, 0x6148D29EU, 0x828C5BD0U},
			{0xDC55AE5FU, 0xAC6B435EU, 0xC0117411U, 0xA527F56CU, 0xFD24342CU, 0x94D5045EU, 0x70B67C0DU, 0x2C4C0A35U}},
		{{0xB65579CDU, 0x69F63538U, 0xADF933A1U, 0xD070605CU, 0x83BE9F6CU, 0x017E8705U, 0xB247B8A1U, 0xE9442FAAU},
			{0x540D3D68U, 0x54EEFF9EU, 0xCAE3BE19U, 0x1F3EDEABU, 0x7035311BU, 0x95C528B0U, 0x96BCC0A7U, 0xB35D3AB7U}},
		{{0x5ED398B5U, 0x9BCA3CFAU, 0x1353DDD7U, 0x6A60B465U, 0x1A1C51D1U, 0x905C17BBU, 0x7F5CF91BU, 0x27A30481U},
			{0x9ED6BF0AU, 0xC4660CF3U, 0xF79E1D56U, 0xB0B03FB1U, 0x36001354U, 0xE3A13BF1U, 0x1F2B2B2AU, 0x9A725054U}},
		{{0x2106E16DU, 0xB4897D05U, 0x50A07F8CU, 0x85BBDF9BU, 0x6C49FFD7U, 0x42632A3DU, 0x600720B8U, 0xB7885E7CU},
			{0xDEB694ACU, 0x6FA47FDCU, 0x8AE0D179U, 0x384614F5U, 0xBD124AB3U, 0x78FCBA29U, 0x748F12EAU, 0xBB113D9EU}},
		{{0xA7CD3018U, 0x3C23EF99U, 0x83DEFD8FU, 0x2C3FC506U, 0x2B88499BU, 0xF97A45FFU, 0x346E7F6AU, 0xAEAA3221U},
			{0x50F32730U, 0xE7473484U, 0x0FD6CA41U, 0xC2C0B8BBU, 0xAF17C114U, 0xA9882079U, 0x1BDE7204U, 0x0635F7A6U}},
		{{0xF38493FEU, 0xC3B013D0U, 0x07BAF718U, 0xA32CAE96U, 0x2095B3BAU, 0x371DA6C2U, 0xB041909EU, 0x031C0ABDU},
			{0x431A9E60U, 0x11CC6DBEU, 0x5BF38F6EU, 0x7E919476U, 0x462A4A33U, 0xBE47F076U, 0x3041B830U, 0x33B3C9DFU}},
		{{0x7B63BD85U, 0xA7D74D4EU, 0x43E23DA6U, 0xEA36C655U, 0xE5A79629U, 0xCD7B7D7FU, 0x13CAC01DU, 0x1FB1F747U},
			{0x9028DED3U, 0xAA0FE145U, 0x19572097U, 0xB123CA3BU, 0x74838677U, 0x21A8746DU, 0x63ABCCC6U, 0x1CFC7ACBU}},
		{{0xE5053D70U, 0x02653302U, 0xB8C6BFC9U, 0x3C33E35BU, 0x9A021EE9U, 0xA72C4B40U, 0x3F6527E4U, 0xE11B800DU},
			{0xB6DC37B5U, 0x8FC1D44AU, 0xF580E474U, 0x5D8606B5U, 0x87B5B0FAU, 0xDF25754AU, 0xBB692A5EU, 0xBAF50CE8U}},
		{{0xFAC61D9AU, 0x027CC8B8U, 0xE3C6FE8AU, 0x7D25E062U, 0xE5BFF503U, 0xE08805BFU, 0x6FF632F7U, 0x13271E6CU},
			{0x232F76A5U, 0x55DCA6C0U, 0x701EF426U, 0x8957C32DU, 0xA10A5178U, 0xEE728BCBU, 0xB62C5173U, 0x5EA60411U}},
	},
	{
		{{0xB4D8BC50U, 0x9AD5462BU, 0xA9195770U, 0x181C0B16U, 0x78412A68U, 0xEBD4FE1CU, 0xC0DFF48CU, 0xAE0341BCU},
			{0x7003E866U, 0xB6BC45CFU, 0x8A24A41BU, 0xF11A6DEAU, 0xD04C24C2U, 0x5407151AU, 0xDA5B7B68U, 0x62C9D27DU}},
		{{0x523B8BF6U, 0x0A50B12EU, 0x8F910C1BU, 0x8009EB5BU, 0x4A167588U, 0xF535AF82U, 0xFB2A2ABDU, 0x0F835F9CU},
			{0x2AFCEB62U, 0xF59B2931U, 0x169D383FU, 0xC797DF2AU, 0x66AC02B0U, 0xEB3F5FB0U, 0xDAA2D0CAU, 0x029D4C6FU}},
		{{0x2B7CE542U, 0xB8222605U, 0x7472BDE1U, 0xE6D4CE99U, 0x09D2F4DAU, 0x53E16EBEU, 0x53B92B2EU, 0x180FF42EU},
			{0x2C34A1C6U, 0xC59BCC02U, 0x422C46C2U, 0x3803D6F9U, 0x5C14A8A2U, 0x18AFF74FU, 0x10A08B28U, 0x55AEBF80U}},
		{{0xF5B343BCU, 0x58AF2010U, 0xF2F142FEU, 0x0F2E400AU, 0xA85F4BDFU, 0x3483BFDEU, 0x03BFEAA9U, 0xF0B1D093U},
			{0xC7081603U, 0x2EA01B95U, 0x3DBA1097U, 0xE943E4C9U, 0xB438F3A6U, 0x47BE92ADU, 0xE5BF6636U, 0x00BB7742U}},
		{{0x86DF2A61U, 0x137A4FB4U, 0xECF7B4A2U, 0xA1ED9C07U, 0x7BD042FFU, 0xB2E460E2U, 0x5F62F5ECU, 0xB7F5E2FAU},
			{0xCC2423B7U, 0x7AA6EC6BU, 0xBA63EEA7U, 0x75CE0A7FU, 0xF250A6E1U, 0x67A45FB1U, 0xE53CDC9FU, 0x93BC919CU}},
		{{0xDDCE3345U, 0xEC2FCCAAU, 0x012A4350U, 0x2A6811B7U, 0xAC598BDCU, 0x96760FF1U, 0xD1BF4128U, 0x054D652AU},
			{0x92A21005U, 0x0A1151D4U, 0x33110FDFU, 0xAD7F3971U, 0x1960100FU, 0x8C95928CU, 0x7BF03362U, 0x6C91C825U}},
		{{0xEC3F1DECU, 0x19E6125DU, 0x911178DAU, 0x07B1F040U, 0x904A6738U, 0xD93EDEDAU, 0x0BEBEDCDU, 0x55187A5AU},
			{0xEB329D41U, 0xF7D04722U, 0xF170B391U, 0xF449099EU, 0xCA99F828U, 0xFD317A69U, 0x34A4976DU, 0x50C3DB2BU}},
		{{0x7BFE7178U, 0xB674481BU, 0x65405868U, 0x4E1DEBAEU, 0xC48C867DU, 0x061B2821U, 0x513B30EAU, 0x69C15B35U},
			{0x36871088U, 0x3B4A1666U, 0x1220B1FFU, 0xE5E29F5DU, 0x233D9F4DU, 0x4B82BB35U, 0x18CDC675U, 0x4E076333U}},
		{{0xCB564473U, 0x78D2E8DFU, 0x57D5621AU, 0x4349A973U, 0x218F8B24U, 0x9D835D89U, 0x079B6EE2U, 0x01FE7BC5U},
			{0x5B3B5DCEU, 0xE57F2A2BU, 0x5FE55565U, 0x5A8637B7U, 0xA41DBAE7U, 0x83FF34AEU, 0x950A7A8FU, 0xFCE1199CU}},
		{{0x3E707706U, 0x374F541FU, 0xA831D0CFU, 0x9A4D3638U, 0x1518CA04U, 0x4AB4F483U, 0xFE38C318U, 0x54E3EE5DU},
			{0x03C8819BU, 0x383AE364U, 0x2E17864CU, 0xA9D1DAA1U, 0x50EEAA5BU, 0x245A97B3U, 0x99BF4E83U, 0x5362D009U}},
		{{0x9BD43980U, 0xFC0313C2U, 0xF172DB29U, 0x9C954B70U, 0xF954A21AU, 0x679BDCB7U, 0x54E2E4FCU, 0x6B481709U},
			{0x30BAF1D0U, 0x318AF5F5U, 0xCBF92060U, 0x26EA8A3CU, 0xCD5AE258U, 0xC3C69D7CU, 0x0EAD07C9U, 0xA73BA047U}},
		{{0x31815E69U, 0x3A63C397U, 0xDCDD2802U, 0x6DF9CBD6U, 0x15B4F6AFU, 0x4C47ED4AU, 0x6AC0F978U, 0x62009D82U},
			{0x8B898FC7U, 0x664D80D2U, 0x2C17C91FU, 0x72F1EEDAU, 0x7AAE6609U, 0x9E84D3BCU, 0x28376895U, 0x58C7C195U}},
		{{0xD9294F07U, 0xDCFF7630U, 0x8DBA8FD0U, 0x89B765D6U, 0x8DBCACCDU, 0x553E55DEU, 0xED702BF8U, 0x9B4A009EU},
			{0x27B8CA0DU, 0xF6E534DDU, 0x6177FD52U, 0xC4496B34U, 0xC87BB7B7U, 0x378CE6F6U, 0x44CC19F0U, 0x68633D48U}},
		{{0x5E422063U, 0x73DEB991U, 0x4A751BC0U, 0x7AD26427U, 0x4414344FU, 0xE6DCE222U, 0x85811F28U, 0xAD01EFF7U},
			{0xBA68B72BU, 0x25486590U, 0x203635AFU, 0xDB93264AU, 0x2822660AU, 0x1EB01F8AU, 0xEE598C64U, 0xAE2DCEE8U}},
		{{0x7DC17874U, 0x3559E7B6U, 0x8195CC2AU, 0xD0CAF0EFU, 0x0CD24DD9U, 0x07C06788U, 0x02857C41U, 0x01A99EA0U},
			{0x90F82F63U, 0xD86579E4U, 0xE41C9237U, 0xB1E0658AU, 0x93FD1E79U, 0x075FFAFDU, 0x47F60B8FU, 0x6E704035U}},
		{{0xA3E6FCEDU, 0x0D53F5C7U, 0xF45FBDEBU, 0xE8CBBDD5U, 0x13339A70U, 0xF85C01DFU, 0x142CEB81U, 0x0FF71880U},
			{0xBD70437AU, 0x4C4E8774U, 0xBA0BDA6AU, 0x5FB32891U, 0xF18BD26EU, 0x1CDBEBD2U, 0x03A9D522U, 0x2F9526F1U}},
		{{0xBE51B0A6U, 0x765186DAU, 0x73CE9088U, 0x5376E9F4U, 0x5B5BD85AU, 0xE3ED800BU, 0x4DC1E604U, 0x24289552U},
			{0xEF27D35EU, 0xE76DCC47U, 0x9000A67DU, 0x4396EED6U, 0x84DE92C1U, 0x73B33BA0U, 0x377601FEU, 0x226453AEU}},
		{{0xC1F7E9C2U, 0xECFC6075U, 0xBE5AEC34U, 0x6A217620U, 0x9EA33BA8U, 0x3781D054U, 0xD86B85D4U, 0x84EF35ABU},
			{0x461FEE83U, 0x914AA33CU, 0xB25F7D6CU, 0xF311E5C9U, 0xC33D495CU, 0xC6110DAAU, 0x818554B9U, 0x8A7EE583U}},
		{{0xA7F4EC0EU, 0x3612732AU, 0x9D71348FU, 0xEE3E88D0U, 0x7599CFDBU, 0xB7A107E4U, 0x611B51C6U, 0x1F5DE7E8U},
			{0x1051AAAAU, 0xD6A11D59U, 0x55F0C386U, 0x3DE531F0U, 0x09F20E66U, 0x09F95C73U, 0x9E414B79U, 0x6421AA1AU}},
		{{0xA8271D7EU, 0xA752C905U, 0x58E5810BU, 0x4735DFA5U, 0x5D925AEBU, 0xE18A44EEU, 0x13C8A853U, 0x9708697FU},
			{0xBFCC9A0BU, 0x8377D540U, 0xE574D403U, 0x7B27E01CU, 0xCF60A8A6U, 0x3D3D180CU, 0xF1C298BFU, 0xE48EF152U}},
		{{0xB829B060U, 0xB8B660B1U, 0x5F55C69BU, 0x9FA73EF1U, 0xEF207888U, 0xC75F19ECU, 0x282B129EU, 0xB19B2B60U},
			{0xBF4730C7U, 0xB2F327EEU, 0xC973C0BEU, 0xEB9DF659U, 0x65C1DB98U, 0xD14913C1U, 0xF79D1A9CU, 0x80F57DD4U}},
		{{0x66392821U, 0x1104026FU, 0xE1798449U, 0x253DBEF7U, 0x3F3E5618U, 0x3C4B3437U, 0x2C64E041U, 0x5B5546D6U},
			{0x57C5762BU, 0xADB53279U, 0x92958DF3U, 0x5DCBD0F0U, 0xF64FBDBEU, 0x2C457444U, 0x1D408175U, 0xB4ABC382U}},
		{{0xE919D779U, 0x0C2DE79BU, 0x242E78BDU, 0x1584694AU, 0xF61376C9U, 0xA4756D94U, 0x34DC2798U, 0xFBCCA7BCU},
			{0x108DF0A1U, 0x5E875319U, 0x293E899DU, 0xE2EC01AEU, 0x92357091U, 0xC928A4EFU, 0xF62ED065U, 0xD5A28987U}},
		{{0x0AEAA3C0U, 0x313A2E8CU, 0xABE85B0AU, 0x89F46D9EU, 0x2DA97D3AU, 0xD2889EBDU, 0x103F8CBAU, 0x9484026AU},
			{0x87D83B5FU, 0x52159F8AU, 0xB1EF0295U, 0xDB2220D6U, 0x03C01ACFU, 0xBDA0746EU, 0x14419FE3U, 0x4F97B2A7U}},
		{{0x2555209FU, 0xAC0436F7U, 0x162773ECU, 0x203466A2U, 0xB48E59FEU, 0xC53F8739U, 0x88845660U, 0xB24CDA2BU},
			{0xFA5E399AU, 0x8D74B5F9U, 0x6F92255EU, 0xFF3DED0BU, 0x045C9E0AU, 0xC76C31FEU, 0x6D2B4662U, 0x85BAA044U}},
		{{0xEDF05D51U, 0xB8AF8BBEU, 0x718F8DB8U, 0x8653C7A6U, 0xCF00FFDDU, 0x14FEB48BU, 0x5CA9E140U, 0xFCBCF7DBU},
			{0xD9D8FDB7U, 0x73B4ECE8U, 0x2F389921U, 0xDC69D368U, 0xC88BC219U, 0x10D32EE4U, 0x921C2D96U, 0xC04D2C27U}},
		{{0x3D1073FDU, 0x6981FDB8U, 0x6C78200EU, 0x252AF70DU, 0xA9EF577EU, 0x60D0E867U, 0xA413E067U, 0x66E63FE8U},
			{0xB914153AU, 0xBBDCB173U, 0xCCB4A0A8U, 0xB59AE623U, 0x3C35B8A0U, 0x34053020U, 0x30DAF2FFU, 0x19B8816FU}},
		{{0xC880E5CAU, 0xCCBF7AC2U, 0x8D11C450U, 0x8299DBEEU, 0x0F77A6BFU, 0xBB27D11BU, 0x5EDCE793U, 0xC601630BU},
			{0x79E7F8EAU, 0xDB73B9FBU, 0xF4367288U, 0xE448BBA7U, 0xB035571BU, 0xF5B6416FU, 0xA48891A2U, 0x981B8F5DU}},
		{{0xB4FBFAA0U, 0x009690FFU, 0x3619C6DBU, 0x8BBBDAB7U, 0x728356E8U, 0xC6D44273U, 0xE453EC35U, 0xFD76F0D8U},
			{0xAAC28A29U, 0x775C2554U, 0x5C55E4F0U, 0x28F7AF9DU, 0x88E8AD4DU, 0xBACF54A6U, 0x0AA76DDFU, 0x85B018E8U}},
		{{0x09C37A93U, 0x8FC8B3B9U, 0xA199B02CU, 0x758FEBCBU, 0x8F3B208CU, 0x5C9B4538U, 0xF2BA90F0U, 0x7C8584DEU},
			{0xB395CCE3U, 0x52751A1CU, 0xC1D45F50U, 0xBB59E4EBU, 0xB0635DACU, 0xF7CDB911U, 0xD3243694U, 0xE924D371U}},
		{{0x6553A8D6U, 0x6532C0FDU, 0x45165A6DU, 0x42B8CBA5U, 0x3CF12D92U, 0x9C6D88EAU, 0x906DB0C5U, 0x0EC93530U},
			{0xECCC6CDFU, 0x494606F8U, 0xC6387899U, 0xA7ED66FCU, 0x8A35AE4CU, 0x91022E17U, 0xECA7BEC3U, 0x28DBCAE6U}},
		{{0x92C4D684U, 0x40CE3051U, 0x7612EFCDU, 0x8B04D725U, 0x6F9CAE20U, 0xB9DCDA36U, 0xF058856CU, 0x0EDC4D24U},
			{0x85427900U, 0x64F2E6BFU, 0xDC09DFEAU, 0x3DE81295U, 0x379BF26CU, 0xD41B4487U, 0x6DF135A9U, 0x50B62C6DU}},
	},
	{
		{{0xD005832AU, 0x0DB2FB5EU, 0x91042E4FU, 0x5F5EFD3BU, 0xED70F8CAU, 0x8C4FFDC6U, 0xB52DA9CCU, 0xE4645D0BU},
			{0xC9001D1FU, 0x9596F58BU, 0x4E117205U, 0x52C8F0BCU, 0xE398A084U, 0xFD4AA0D2U, 0x104F49DEU, 0x815BFE3AU}},
		{{0xE548B37BU, 0x54EB3ACCU, 0x84D40549U, 0xB38E7542U, 0x7B341B4FU, 0x8C3DAA51U, 0x690BF7FAU, 0x2F6928ECU},
			{0x86CE6C41U, 0x0496B323U, 0x10ADADCDU, 0x01BE1C55U, 0x4BB5FAF9U, 0xC04E67E7U, 0xE15C9985U, 0x3CBAF678U}},
		{{0xD7AB9A2DU, 0x524D226AU, 0x7DFAE958U, 0x9C00090DU, 0x8751D8C2U, 0x0BA5F539U, 0x3AB8262DU, 0x8AFCBCDDU},
			{0xE99D043BU, 0x57392729U, 0xAEBC943AU, 0xEF51263BU, 0x20862935U, 0x9FEACE93U, 0xB06C817BU, 0x639EFC03U}},
		{{0x341D81DCU, 0xE839BE7DU, 0x32148379U, 0xCDDB6889U, 0xF7026EADU, 0xDA6211A1U, 0xF4D1CC5EU, 0xF3B2575FU},
			{0xA7A73AE6U, 0x40CFC8F6U, 0x61D5B483U, 0x83879A5EU, 0x41A50EBCU, 0xC5ACB1EDU, 0x3C07D8FAU, 0x59A60CC8U}},
		{{0xC3B81990U, 0xDEC98D4AU, 0x9E0CC8FEU, 0x1CB83722U, 0xD2B427B9U, 0xFE0B0491U, 0xE983A66CU, 0x0F2386ACU},
			{0xB3291213U, 0x930C4D1EU, 0x59A62AE4U, 0xA2F82B2EU, 0xF93E89E3U, 0x77233853U, 0x11777C7FU, 0x7F8063ACU}},
		{{0x59371000U, 0x604AC97CU, 0x7F759C18U, 0xE1C48C70U, 0xA5DB6B65U, 0x3F62ECC5U, 0x38A21495U, 0x0A78B173U},
			{0xBCC8AD94U, 0x6BE1819DU, 0xD89C3400U, 0x70DC04F6U, 0xA6B4840AU, 0x462557B4U, 0x60BD21C0U, 0x544C6ADEU}},
		{{0x02FF6072U, 0x36E607CFU, 0x8AD98CDCU, 0xA47D2CA9U, 0xF5F56609U, 0xBF471D1EU, 0xF264ADA0U, 0xBCF86623U},
			{0xAA9E5CB6U, 0xB70C0687U, 0x17401C6CU, 0xC98124F2U, 0xD4A61435U, 0x8189635FU, 0xA9D98EA6U, 0xD28FB8AFU}},
		{{0x65C7322DU, 0x439530B6U, 0xB3C1B3FBU, 0xCF12CC01U, 0x0172F685U, 0xC70B0186U, 0x1B58391DU, 0xB915EE22U},
			{0xA317DB24U, 0x9AFDF03BU, 0x17B8FFC4U, 0x87DEC659U, 0xE4D3D050U, 0x7F46597BU, 0x006500E7U, 0x80A1C1EDU}},
		{{0x017025F3U, 0x3D4DA8C3U, 0xFB9579B4U, 0xEFCF628CU, 0x1F3716ECU, 0x5C4D0016U, 0x6801116EU, 0x9C27EBC4U},
			{0x1DA1767EU, 0x5EBA0EA1U, 0x47004C57U, 0xFE151452U, 0x8C2373B7U, 0x3ACE6DF6U, 0x5DBC37ACU, 0x75C3DFFEU}},
		{{0xA28A0749U, 0xA2A147DBU, 0xEE519165U, 0x246C20D6U, 0xD3810715U, 0x5068D1B1U, 0x748160B9U, 0xB1E7018CU},
			{0xF380FF62U, 0x03F5B1FAU, 0xF3CB2C1EU, 0xEF7FB1DDU, 0xFC91A7DAU, 0xEAB539A8U, 0xF3F9B561U, 0x83DDB707U}},
		{{0x80101B98U, 0xB57276D9U, 0xB82F0F66U, 0x760883FDU, 0x4BC3EFF3U, 0x89D7DE75U, 0x5DC2AB40U, 0x03B60643U},
			{0xE05BEEACU, 0xCD6E53DFU, 0xBC3325CDU, 0xF2F1E862U, 0x774F03C3U, 0xDD0F7921U, 0x4552CC1BU, 0x97CA7221U}},
		{{0x9CEC46EAU, 0xE79A4AF0U, 0x658B9BC7U, 0xB15347A1U, 0x35AF2F75U, 0x6BD2796FU, 0x4051C435U, 0xAC957990U},
			{0xC33A655DU, 0x2669DDA3U, 0x88514AA3U, 0x5D503C2EU, 0x3753DD41U, 0xDFA11337U, 0x0B754F78U, 0x3F054673U}},
		{{0xE224C5D7U, 0x760CB3B5U, 0x68616919U, 0xFA3BAF8CU, 0x8D142552U, 0x9FBCA113U, 0x7669EBF5U, 0x1AB18BF1U},
			{0x9BDF25DDU, 0x55E6F53EU, 0xCB6CD154U, 0x04CC0BF3U, 0x95E89080U, 0x595BEF49U, 0x104A9AC1U, 0xFE9459A8U}},
		{{0xA8123EF0U, 0x49D66316U, 0xE7F95438U, 0x73C32DB4U, 0x0D9E7854U, 0x2E2ED209U, 0x9D9F0507U, 0xF98A9329U},
			{0x0C6AA20AU, 0xC5D33CF6U, 0x75279BB2U, 0x9A32BA14U, 0x774A7307U, 0x7E3202CBU, 0xE8C42DBDU, 0x64ED4BC4U}},
		{{0xABB020E8U, 0x694B64C5U, 0x19C4EEC7U, 0x3D18C184U, 0x1C4793E5U, 0x9C4673EFU, 0x056092E6U, 0xC7B8AEB5U},
			{0xF0F8C16BU, 0x3AA1CA43U, 0xD679B2F6U, 0x224ED5ECU, 0x55A205C9U, 0x0D56EEAFU, 0x4B8E028BU, 0xBFE115BAU}},
		{{0x97ACF4ECU, 0x3E22A7B3U, 0x5EA8B640U, 0x0426C400U, 0x4E969285U, 0x5E3295A6U, 0xA6A45670U, 0x22AABC59U},
			{0x5F5942BCU, 0xB929714CU, 0xFA3182EDU, 0x9A6168BDU, 0x104152BAU, 0x2216A665U, 0xB6926368U, 0x46908D03U}},
		{{0x7FCBA850U, 0x9B8BE024U, 0x820A181EU, 0x81EB5797U, 0x30A01211U, 0xA0F28122U, 0xAE7B8821U, 0x7E9CDC3CU},
			{0x72CE15E7U, 0x202332CCU, 0xCB8238D7U, 0xCD3CB2BBU, 0xC6E82C43U, 0xE4AB63DFU, 0x3183D717U, 0x58BD0028U}},
		{{0xF32942ABU, 0xD18D46E8U, 0x10882418U, 0x6C766EF6U, 0x0CC6CD6BU, 0x8EFFCB1AU, 0x68D85960U, 0x5A1DA05CU},
			{0x32296E1CU, 0xC7A5F4A5U, 0xC90D2EC8U, 0x3D0F1E43U, 0x899729D9U, 0x29943A22U, 0x360E5317U, 0x877A8A26U}},
		{{0x717ED7B5U, 0x02D57B7EU, 0x4DBCE1A2U, 0xD22E5B24U, 0x2A4CDCF5U, 0x174BD771U, 0x408205BBU, 0xA6FDB801U},
			{0x5E1387E9U, 0x67B4B069U, 0x0591A442U, 0x332B19A1U, 0xCCACF366U, 0x24EDD916U, 0x34958A50U, 0xBE34CC45U}},
		{{0x061C184BU, 0x81597699U, 0x63898952U, 0x653D105CU, 0x7B5EFCADU, 0xDA9106DEU, 0x8AA61452U, 0xA0335AA6U},
			{0x4FFABA04U, 0x337D7C89U, 0x8EA990F6U, 0x9DCED4FEU, 0x268C5728U, 0x3628B3B6U, 0xC2AA21ECU, 0xF9937089U}},
		{{0x3E66D391U, 0xA3F46E1EU, 0x7D6369B2U, 0xB4A732CDU, 0x402C1022U, 0x99C3B85DU, 0x2B54932EU, 0x7DCCFCBEU},
			{0x56B1DFE2U, 0xA6DDAA7BU, 0xE34A82C9U, 0x31DC78A5U, 0x704F3941U, 0x8ABEB3DAU, 0xCA55FA98U, 0xDF11A36CU}},
		{{0x89861966U, 0xD53B8E34U, 0xA0EA996BU, 0x79FB20A1U, 0x5AD37F43U, 0x300647D9U, 0x53A7E3CDU, 0xB44DB4A8U},
			{0x2E6659FBU, 0x9EE3E1B9U, 0x5F687220U, 0x4B326372U, 0xB1A10143U, 0x6EC26825U, 0x867D6F0BU, 0xB4B6762BU}},
		{{0x16E00C1BU, 0x6C01F77AU, 0x839EAAACU, 0x82515490U, 0x3470D334U, 0x62F3A4EFU, 0x1C1DCD6CU, 0x5A29A649U},
			{0xCE997A25U, 0x46B6782EU, 0xD3579953U, 0x9978FB35U, 0x0960E0CEU, 0x98F5A9DFU, 0x1F527A4CU, 0x547DC839U}},
		{{0xC2BABCC1U, 0x52CB8AC6U, 0xFE81AE8DU, 0x4748D448U, 0x80F1A711U, 0x5844F03FU, 0xF8DF4AC4U, 0x3DB784B2U},
			{0x2DF1FE36U, 0xAD918F12U, 0xF33CC7C0U, 0xE40F25B9U, 0x3B5E5555U, 0x4700D0E7U, 0xB03326F9U, 0x5C28FA08U}},
		{{0x5D9DC24FU, 0x395B1583U, 0xC73AE680U, 0xA4256932U, 0xFAA2C8E9U, 0x0542960EU, 0x71068C6AU, 0x2BB3ADEEU},
			{0x570B4554U, 0xA706099BU, 0xF4E278D6U, 0x85D12BB5U, 0x64296843U, 0xD78AF6F6U, 0x8428C633U, 0xC7D3B388U}},
		{{0xDB3F9758U, 0x4C3B6709U, 0x341D8C1AU, 0x169EDA4EU, 0x9613A6D2U, 0xBD4F2F18U, 0xD7CDA536U, 0x9A002B4EU},
			{0x776103B9U, 0x97BDF8D1U, 0xB37945BAU, 0x9C670D34U, 0xD78C5BBFU, 0x9B83E384U, 0x518D14B2U, 0x6E2D3BCFU}},
		{{0x43B7E597U, 0x34D44F93U, 0xC2530F42U, 0xDDE440A7U, 0x7856BDB9U, 0x7270A081U, 0x5353032FU, 0x86A945EBU},
			{0x66D39810U, 0x6C2F8E99U, 0x9B8B4B6BU, 0x0642A31BU, 0xD1509D82U, 0x51679E62U, 0x90F8FF16U, 0x0120001CU}},
		{{0x2E36E34AU, 0x50A1C106U, 0xE024ED1AU, 0x74E8F58CU, 0x1300D726U, 0x3F0F1DFAU, 0x7B4A2D18U, 0x6680DF26U},
			{0x8235B3B7U, 0x12B5979DU, 0x8A611493U, 0x1D2FAFCBU, 0x8848ECE5U, 0x73EBDA96U, 0xA413E399U, 0xE996C275U}},
		{{0x495FF000U, 0x46B7D7C7U, 0xBAED95D1U, 0xE60ED097U, 0x6E38F9C0U, 0xAA8804ACU, 0x45C6F9BBU, 0x92990C06U},
			{0xC0919851U, 0xCAE6A439U, 0x1BF5E1F2U, 0x713DFF15U, 0x2EB38CDBU, 0x5D262C30U, 0x90DF31DFU, 0xB73D5051U}},
		{{0xE55B2FE5U, 0x85C832C2U, 0x9119DEFCU, 0xF2512165U, 0x99B00FE4U, 0xFCFDE3BCU, 0xD1908B17U, 0x8067F5E3U},
			{0x1443AE42U, 0xE921F6B3U, 0x64EA593BU, 0xA2CFED92U, 0x59E07A35U, 0x1589B962U, 0x0DA762DDU, 0xC6BB390AU}},
		{{0x32D9268CU, 0x921E7B1CU, 0x4276FAD4U, 0x34DB2B96U, 0xCC44E730U, 0x0EC56D34U, 0x096545B7U, 0x59BE3A46U},
			{0x66CF3A6AU, 0xE9FDBC97U, 0xD04E9B53U, 0x7B2F83EDU, 0x8FBAE3E7U, 0x6D99B3CCU, 0x7ADA3A40U, 0x8EB5646CU}},
		{{0x5A1251FBU, 0xA9F5D874U, 0xC72725C7U, 0x967747A8U, 0x31FFE89EU, 0x195C33E5U, 0xE964935EU, 0x609D210FU},
			{0x2FE12227U, 0xCAFD6CA8U, 0x0426469DU, 0xAF9B5B96U, 0x5693183CU, 0x2E9EE04CU, 0xC8146FEFU, 0x1084A333U}},
	},
	{
		{{0xAED1D1F7U, 0x96649933U, 0x50563090U, 0x566EAFF3U, 0xAD2E39CFU, 0x345057F0U, 0x1F832124U, 0x148FF65BU},
			{0xCF94CF0DU, 0x042E89D4U, 0x520C58B3U, 0x319BEC84U, 0x5361AA0DU, 0x2A267626U, 0x8FBC87ADU, 0xC86FA302U}},
		{{0xADC1696FU, 0x6B66D7E1U, 0x0ACD72D0U, 0x98EBE593U, 0xCC1B7435U, 0x65F24550U, 0xB4B9A5ECU, 0xCE231393U},
			{0xDB067DF9U, 0x234A22D4U, 0xCAFF9B00U, 0x98DDA095U, 0x6100C9C1U, 0x1BBC75A0U, 0x939CF695U, 0x1560A9C8U}},
		{{0xFE51BF74U, 0x0850325EU, 0x5E460094U, 0x9C4F579EU, 0x76DA2F25U, 0x5C87B92AU, 0x6FEBEF33U, 0x889DE4E0U},
			{0x646083CEU, 0x6900EC06U, 0xBFE12773U, 0xBE2A0335U, 0xC5344110U, 0xADD1DA35U, 0xB802CD20U, 0x757568B7U}},
		{{0xF1C367CAU, 0xE4050F1CU, 0xC90FBC7DU, 0x9BC85A9BU, 0xE1A11032U, 0xA373C4A2U, 0xAD0393A9U, 0xB64232B7U},
			{0x167DAD29U, 0xF5577EB0U, 0x94B78AB2U, 0x1604F301U, 0xE829348BU, 0x0BAA94AFU, 0x41654342U, 0x77FBD8DDU}},
		{{0x94A7CD2EU, 0x6FF651B4U, 0x0699336CU, 0x5671FFD1U, 0x979A896AU, 0x6F5FD2CCU, 0xD8148CEFU, 0x11E893A8U},
			{0x65CF7B10U, 0x988906A1U, 0xC50D8485U, 0x81B67178U, 0x8A35B3DEU, 0x7C0DEB35U, 0xC1D29799U, 0x423AC855U}},
		{{0x09618708U, 0x719F69E1U, 0xC183F9B1U, 0xCC9E8364U, 0x366A21AFU, 0xEC203A95U, 0x068B141FU, 0x6AEC5D6DU},
			{0x994F04E9U, 0xEE2DF78AU, 0x271245B0U, 0xB39CCAE8U, 0x97E43F4FU, 0xB875A4A9U, 0xDB2CEA98U, 0x507DFE11U}},
		{{0x5232123DU, 0x314B7AEAU, 0x65AE86DBU, 0x08307C8CU, 0xAA4668EDU, 0x06E7165CU, 0xB4D3EC39U, 0xB170458BU},
			{0xC19BB986U, 0x4D2E3EC6U, 0xAE0304EDU, 0xC5F34846U, 0x6C9F9722U, 0x917695A0U, 0x4CAB1C0AU, 0x6C7F7317U}},
		{{0xFCF0A7FDU, 0x31F14802U, 0x5488B01EU, 0x42FD0789U, 0x9952B498U, 0x71D78D6DU, 0x07AC5201U, 0x8EB572D9U},
			{0x4D194A88U, 0xE0A2A44CU, 0xBA017E66U, 0xD2B63FD9U, 0xF888AEFCU, 0x78EFC6C8U, 0x4A881A11U, 0xB76F6BDAU}},
		{{0xB2A67238U, 0xBF0BE101U, 0xAF9C14F2U, 0x3556D367U, 0xA5662075U, 0x104B7831U, 0x79D9E60AU, 0x58CA59BBU},
			{0xA569A73BU, 0x4BC45392U, 0x5698F6C9U, 0x517A52E8U, 0xAEADD755U, 0x85643DA5U, 0x2A581B84U, 0x1AED0CD5U}},
		{{0x19F9E967U, 0xA0F726BCU, 0xE8FBBF4EU, 0xD9D03152U, 0xB7707D40U, 0xCFD6F51DU, 0x63F6E6E0U, 0x633084D9U},
			{0x55667EAFU, 0xEDCD9CDCU, 0x2E44D56FU, 0x73B7F92BU, 0x4E962B14U, 0xFB2E39B6U, 0xF671FCBFU, 0x7D408F6EU}},
		{{0xF8DFCF8AU, 0x9EEA3075U, 0x95669825U, 0xA284F0AAU, 0x867D3FD8U, 0xB3FCA250U, 0x269D691EU, 0x20757B5FU},
			{0x93B8A5DEU, 0xF2C24020U, 0xEBC06DA6U, 0xD3F93359U, 0xB2739C33U, 0x1178293EU, 0xBCD686E5U, 0xD2A3E770U}},
		{{0x68AF43EEU, 0xA2F7932CU, 0x703D00BDU, 0x5502468EU, 0x2FB061F5U, 0xE5DC978FU, 0x28C815ADU, 0xC9A1904AU},
			{0x470C56A4U, 0xD3AF538DU, 0x193D8CEDU, 0x159ABC5FU, 0x20108EF3U, 0x2A37245FU, 0x223F7178U, 0xFA17081EU}},
		{{0xECF2A73AU, 0x2A206E8DU, 0x8E551994U, 0x066A6397U, 0xB98D53A2U, 0x3A6A088AU, 0x2D1124AAU, 0x0CE7C67CU},
			{0x759A113CU, 0x48CEC671U, 0x4F6F67FAU, 0xE3B373D3U, 0xFD36727BU, 0x5455D479U, 0xA13C0D81U, 0xE5A428EEU}},
		{{0x16B1BD5EU, 0x6BFEEA5FU, 0x4DE30AD3U, 0xF957E420U, 0x6A353B9EU, 0xCBAF664EU, 0x26D14FEBU, 0x5C873312U},
			{0xB65F57CBU, 0x4E87F98CU, 0x5E0CDD41U, 0xDB60A621U, 0xA6881440U, 0x67C16865U, 0x46AB52AAU, 0x1093EF1AU}},
		{{0xBB2EEC64U, 0x93BCCBBAU, 0xDA03ADBEU, 0xA0C23B64U, 0xE0E86AC4U, 0x5F7AA00AU, 0xFC1401E6U, 0x470B941EU},
			{0x9DF43574U, 0x5AD8D679U, 0x0F65D810U, 0x4CCFB8A9U, 0xAA7FBD81U, 0x1BCE80E3U, 0x9508D20AU, 0x273291ADU}},
		{{0xB4B4B67CU, 0x1FE2A9B2U, 0xE8020604U, 0xC1D10DF0U, 0xBC8058D8U, 0x9D64ABFCU, 0x712A0FBBU, 0x8943B9B2U},
			{0x3B3DEF04U, 0x90EED914U, 0x4CE775FFU, 0x85AB3AA2U, 0x7BBC9040U, 0x605FD4CAU, 0xE2C75DFBU, 0x8B34A564U}},
		{{0xE382360FU, 0x25759F7CU, 0x88BF5857U, 0xB6DB05C9U, 0x6C58D46CU, 0x2917D61DU, 0xFD20CB7AU, 0x14F8E491U},
			{0x11C20340U, 0xB68A727AU, 0xAF7CCBB6U, 0x0386F86FU, 0xFEE09A20U, 0x5C8BC6CCU, 0xBB7EEA35U, 0x7D76FF4AU}},
		{{0xAA8A5288U, 0x4DABCAAAU, 0xAF23A1C9U, 0x91CC0C8AU, 0x3F220E0CU, 0x34C72C6AU, 0x1232144AU, 0xBCC20BDFU},
			{0xA20EDE1BU, 0x6E2F42DAU, 0x74A00515U, 0xC441F00CU, 0x734B8C4BU, 0xBF46A5B6U, 0x7B56C9A4U, 0x57409503U}},
		{{0x3FF3571BU, 0xB46836A5U, 0x837927C1U, 0x24F98B78U, 0x4533C716U, 0x6254256AU, 0xD07EE196U, 0xF27ABB0BU},
			{0x5C6D5BFDU, 0xD7CF64FCU, 0xF0CD7A77U, 0x6915C751U, 0x8798F534U, 0xD9F59012U, 0xF81D8B5FU, 0x772B0DA8U}},
		{{0x8E2F7D90U, 0x5C18ACF8U, 0x77BE32CDU, 0xFDBF33D7U, 0xD2EB5EE9U, 0x0A085CD7U, 0xB3201115U, 0x2D702CFBU},
			{0x85C88CE8U, 0xB6E0EBDBU, 0x1E01D617U, 0x23A3CE3CU, 0x567333ACU, 0x3041618EU, 0x157EDB6BU, 0x9DD0FD8FU}},
		{{0xCE07D1B0U, 0x386BDA73U, 0x58AD4178U, 0xD82910C2U, 0xCD2617F4U, 0x124F82CFU, 0xEF691770U, 0xCC2F5E8DU},
			{0xB8C30CCCU, 0x82702550U, 0x1A8E575AU, 0x7B856AEAU, 0xB1AB9459U, 0xBB822FEFU, 0xEC24E38EU, 0x085928BCU}},
		{{0x8FB98871U, 0x80463D11U, 0xBBC76AFFU, 0xCB26F5C3U, 0xFBE03614U, 0xD4AB8EDDU, 0xC0CF2DEEU, 0xC8EB579BU},
			{0xC93BAE41U, 0xCC004C15U, 0x3AECA3B2U, 0x46FBAE5DU, 0x0F1E9AB1U, 0x671235CFU, 0x9EC285C1U, 0xADFBA934U}},
		{{0xB57C6477U, 0xA36C936BU, 0xE94DBCC6U, 0x871F8B64U, 0xA591A67BU, 0x28D0FB62U, 0xC1D926F5U, 0x9D40E081U},
			{0xF2D84B5AU, 0x3111EAF6U, 0xA565B644U, 0x228993F9U, 0x2C83188BU, 0x0CCBF592U, 0x3DF3E197U, 0xF87B30ABU}},
		{{0x98FA7AAAU, 0xB2B26107U, 0xF073AA4EU, 0x41209EE4U, 0xF2D6B19BU, 0xF1570359U, 0xFC577CAFU, 0xCBE6868CU},
			{0x32C04DD3U, 0x186C4BDCU, 0xCFEEE397U, 0xA6C35FAEU, 0xF086C0CFU, 0xB4A1B312U, 0xD9461FE2U, 0xE0A5CCC6U}},
		{{0xA7AAE5D3U, 0xD24E2679U, 0x0DE5C1C4U, 0x7076013DU, 0xBB05B629U, 0x2D50F8BAU, 0x6E66EFBBU, 0x73C1ABE2U},
			{0xF2488AF7U, 0xEFD4B422U, 0x663BA575U, 0xE4105D02U, 0x53A69457U, 0x7EB60A8BU, 0xC945973BU, 0x62210008U}},
		{{0x4B66ABFBU, 0x1D8E3286U, 0x59030900U, 0xD26F52E5U, 0x5584941AU, 0x1EE3F643U, 0x569F5958U, 0x6D3B3730U},
			{0x4789DBA5U, 0x9FF2A62FU, 0x72B5C9B7U, 0x91FCB815U, 0x6C8F9A0EU, 0xF446CB7DU, 0x39B7ECB5U, 0x48F625C1U}},
		{{0x30448112U, 0x7B7C1477U, 0xE4A38656U, 0x82B51AF1U, 0x2F315010U, 0x2BF2028AU, 0x6EA88CD4U, 0xC9A4A01FU},
			{0x257E5818U, 0xF63E95D8U, 0xB4519B16U, 0xDD8EFA10U, 0x0DA910BFU, 0xED8973E0U, 0x5C0FE4A9U, 0xED49D077U}},
		{{0x6FA6110CU, 0x516FF3A3U, 0xFB93561FU, 0x74FB1EB1U, 0x8457522BU, 0x6C0C9047U, 0x6BB8BDC6U, 0xCFD32104U},
			{0xCC80AD57U, 0x2D6884A2U, 0x86A9B637U, 0x7C27FC35U, 0xADF4E8CDU, 0x3461BAEDU, 0x617242F0U, 0x1D56251AU}},
		{{0xA995E094U, 0x719946D1U, 0xE51E04D8U, 0x65E848F6U, 0x6A1E3113U, 0xE62F3300U, 0x501DE503U, 0x1541C7C1U},
			{0xF4ACFADEU, 0x4DAAC9FAU, 0x44CD0B71U, 0x0E585897U, 0x0A51CD77U, 0x544FD869U, 0x0031016DU, 0x60FC20EDU}},
		{{0x64DB4444U, 0x3FE712AFU, 0xBECDD480U, 0x19E9D634U, 0xA930978AU, 0xE08BC047U, 0xA1280733U, 0x2DBF24ECU},
			{0x2CD706B2U, 0x3C0AE38CU, 0x359017B9U, 0x5B012A5BU, 0x72E0F5AEU, 0x3943C38CU, 0x57176FA3U, 0x786167EAU}},
		{{0xABEA49B1U, 0xFA979FB7U, 0x10E2C6C5U, 0xB4B1D27DU, 0x23AFDE7AU, 0xBD61C2C4U, 0x9786D358U, 0xEB6614F8U},
			{0x7F6F7459U, 0x4A5D816BU, 0x09360E7BU, 0xE431A44FU, 0xC309914CU, 0x8C27A032U, 0xCAEDE3D8U, 0xCEA5D68AU}},
		{{0x431DD80EU, 0xB84011A9U, 0x73306CD9U, 0xEB7C7CCAU, 0xD1B3B730U, 0x20FADD29U, 0xFE37B3D3U, 0x83858B5BU},
			{0xB6251D5CU, 0xBF4CD193U, 0x1352D952U, 0x1CCA1FD3U, 0x90FBC051U, 0xC66157A4U, 0x89B98636U, 0x7990A638U}},
	},
	{
		{{0x87DEC0E1U, 0xE5AA692AU, 0xF7B39D00U, 0x010DED8DU, 0x54CFA0B5U, 0x7B1B80C8U, 0xA0F8EA28U, 0x66BEB876U},
			{0x3476CD0EU, 0x50D7F531U, 0xB08D3949U, 0xA63D0E65U, 0x53479FC6U, 0x1A09EEA9U, 0xF499E742U, 0x82AE9891U}},
		{{0x5CA7D866U, 0xAB58B910U, 0x3ADB3B34U, 0x582967E2U, 0xCCEAC0BCU, 0x89AE4447U, 0x7BF56AF5U, 0x919C667CU},
			{0x60F5DCD7U, 0x9AEC17B1U, 0xDDCAADBCU, 0xEC697B9FU, 0x463467F5U, 0x0B98F341U, 0xA967132FU, 0xB187F1F7U}},
		{{0x214AEB18U, 0x90FE7A1DU, 0x741432F7U, 0x1506AF3CU, 0xE591A0C4U, 0xBB5565F9U, 0xB44F1BC3U, 0x10D41A77U},
			{0xA84BDE96U, 0xA09D65E4U, 0xF20A6A1CU, 0x42F060D8U, 0xF27F9CE7U, 0x652A3BFDU, 0x3B3D739FU, 0xB6BDB65CU}},
		{{0xEC7FAE9FU, 0xEB5DDCB6U, 0xEFB66E5AU, 0x995F2714U, 0x69445D52U, 0xDEE95D8EU, 0x09E27620U, 0x1B6C2D46U},
			{0x8129D716U, 0x32621C31U, 0x0958C1AAU, 0xB03909F1U, 0x1AF4AF63U, 0x8C468EF9U, 0xFBA5CDF6U, 0x162C429FU}},
		{{0x753B9371U, 0x2F682343U, 0x5F1F9CD7U, 0x29CAB45AU, 0xB245DB96U, 0x571623ABU, 0x3FD79999U, 0xC507DB09U},
			{0xAF036C32U, 0x4E2EF652U, 0x05018E5CU, 0x86F0CC78U, 0xAB8BE350U, 0xC10A73D4U, 0x7E826327U, 0x6519B397U}},
		{{0x9C053DF7U, 0xE8CB5EEFU, 0xB300EA6FU, 0x8DE25B37U, 0xC849CFFBU, 0xDB03FA92U, 0xE84169BBU, 0x242E43A7U},
			{0xDD6F958EU, 0xE4FA51F4U, 0xF4445A8DU, 0x6925A77FU, 0xE90D8949U, 0xE6E72A50U, 0x2B1F6390U, 0xC66648E3U}},
		{{0x173E460CU, 0xB2AB1957U, 0x30704590U, 0x1BBBCE75U, 0xDB1C7162U, 0xC0A90DBDU, 0x15CDD65DU, 0x505E399EU},
			{0x57797AB7U, 0x68434DCBU, 0x6A2CA8E8U, 0x60AD35BAU, 0xDE3336C1U, 0x4BFDB1E0U, 0xD8B39015U, 0xBBEF99EBU}},
		{{0x1711EBECU, 0x6C3B96F3U, 0xCE98FDC4U, 0x2DA40F1FU, 0x57B4411FU, 0xB99774D3U, 0x15B65BB6U, 0x87C8BDF4U},
			{0xC2EEF12DU, 0xDA3A89E3U, 0x3C7471F3U, 0xDE95BB9BU, 0xD812C594U, 0x600F225BU, 0x2B75A56BU, 0x54907C5DU}},
		{{0x8DB60E35U, 0xA93CC5F0U, 0xFA833319U, 0x743E3CD6U, 0xF81683C9U, 0x7DAD5C41U, 0x9C34107EU, 0x70C1E7D9U},
			{0xA6BE0907U, 0x0EDC4A39U, 0x86D0B7D3U, 0x36D47035U, 0x272BFA60U, 0x8C76DA03U, 0x0F08A414U, 0x0B4A07EAU}},
		{{0x45C1DD53U, 0x699E4D29U, 0x231DEBB5U, 0xCADC5898U, 0xA77F00E0U, 0xDF49FCC7U, 0xA73E5A0EU, 0x93057BBFU},
			{0x027A4CD1U, 0x2F8B7ECDU, 0xC614011AU, 0x114734B3U, 0x67677C68U, 0xE7A01DB7U, 0x7E273F4FU, 0x89D9BE5EU}},
		{{0x089808EFU, 0xD225CB2EU, 0xD59E4107U, 0xF1F7A27DU, 0x8211B9C9U, 0x53AFC761U, 0xE6819159U, 0x0361BC67U},
			{0x7F071426U, 0x2A865D0BU, 0xE7072567U, 0x6A3C1810U, 0x0D6BCABDU, 0x3E3BCA1EU, 0x408591BCU, 0xA1B02BC1U}},
		{{0x31FBA239U, 0xE0DEEE59U, 0x98BD91D1U, 0xF47424D3U, 0x071A3C1DU, 0x0F8886F4U, 0xA819233BU, 0x3F7D41E8U},
			{0xCF6EB998U, 0x708623C2U, 0x609A287FU, 0x86BB49AFU, 0x63C90762U, 0x942BB249U, 0x55A9654BU, 0x0EF6EEA5U}},
		{{0x36F5DEFEU, 0x5F6D2D72U, 0x56F99176U, 0xFA9922DCU, 0xF78CE0C7U, 0x6C8C5ECEU, 0xBE09B55EU, 0x7B44589DU},
			{0x9EA83770U, 0xE11B3BCAU, 0x2AB71547U, 0xD7FA2C7FU, 0x2A1DDCC0U, 0x2A3DD6FAU, 0x5A7B7707U, 0x09ACB430U}},
		{{0x649D4E57U, 0x4ADD4A2EU, 0x1917526EU, 0xCD53A2B0U, 0x20B44AC4U, 0xC5262330U, 0xBAA2C31DU, 0x4028746AU},
			{0x64291D4CU, 0x51318390U, 0xEE5AD909U, 0xBF48F151U, 0x7B185681U, 0xCCE57F59U, 0x4854D442U, 0x7C3AC1B0U}},
		{{0xC093C171U, 0x65587DC3U, 0x24F42B65U, 0xAE7ACB24U, 0x955996CBU, 0x5A338ADBU, 0x6051F91BU, 0xC8E65675U},
			{0x28B8D0B1U, 0x66711FBAU, 0xB6C10A90U, 0x15D74137U, 0x3A232A80U, 0x70CDD7EBU, 0x6191ED24U, 0xC9E2F07FU}},
		{{0xF79588C0U, 0xA80D1DB6U, 0xB55768CCU, 0xFA52FC69U, 0x7F54438AU, 0x0B4DF1AEU, 0xF9B46A4FU, 0x0CADD1A7U},
			{0x1803DD6FU, 0xB40EA6B3U, 0x55EAAE35U, 0x488E4FA5U, 0x382E4E16U, 0x9F047D55U, 0x2F6E0C98U, 0xC9B5B7E0U}},
		{{0x95762649U, 0x6B1BD2D3U, 0xC7AEA3F6U, 0xA9604EE7U, 0x6DC6F896U, 0x3646FF27U, 0x2860BAD1U, 0x9BF0E7F5U},
			{0x7CB44B92U, 0x2D92C821U, 0xAEA9C182U, 0xA2F5CE63U, 0x9154A5FDU, 0xD0A2AFB1U, 0x95801DA6U, 0x482E474CU}},
		{{0xB611C24BU, 0xC19972D0U, 0x60A8F351U, 0x1D468E65U, 0x7BCF6421U, 0xEB758069U, 0x88FBC491U, 0xEC9DD0EEU},
			{0x956C2E32U, 0x5B59D2BFU, 0xDCDDF94EU, 0x73DC6864U, 0xBCEE7665U, 0xFD5E2321U, 0x5E9A06C4U, 0xA7B4F8EFU}},
		{{0x7280F855U, 0xFBA918DDU, 0x8BAEC688U, 0xBBAAC260U, 0x33400F42U, 0xA3B3F00FU, 0x66F2E6E4U, 0x3D2DBA29U},
			{0x98509375U, 0xB6F71A94U, 0xCEA423CCU, 0x8F33031FU, 0x4807E6FBU, 0x009B8DD0U, 0x5CDB954CU, 0x5163CFE5U}},
		{{0xCF41C6E8U, 0x03CC8F17U, 0x037B925CU, 0xF1F03C2AU, 0x66D2427CU, 0xC39C19CCU, 0x7B6C18E4U, 0x823D24BAU},
			{0x901F0B4FU, 0x32EF9013U, 0xF8941C2EU, 0x684360F1U, 0x2C28092EU, 0x0EBAFF52U, 0x256C932FU, 0x7891E4E3U}},
		{{0xAC445E3DU, 0x51264319U, 0x8EA74381U, 0x553432E7U, 0x67E9C50AU, 0xE6EEAA69U, 0x62E628C7U, 0x27CED284U},
			{0x7A4AFA57U, 0x3F96D375U, 0xE484C150U, 0xDE0A14C3U, 0x38BD9923U, 0x364A24EBU, 0xE5177422U, 0x1DF18DA0U}},
		{{0xD8D38A9BU, 0x174E8F82U, 0xE7DE1391U, 0x2E97C600U, 0xA1C175DDU, 0xC5709850U, 0x32AE5035U, 0x969041A0U},
			{0x76A2086BU, 0xCBFD533BU, 0xD7C2E8FEU, 0xD6BBA71BU, 0x099DFB67U, 0xB2D58EE6U, 0x064A85D9U, 0x3A8B342DU}},
		{{0x522F9BE3U, 0x3BC07649U, 0xDF1F49A8U, 0x690C075BU, 0x3854EC42U, 0x80E1AEE8U, 0x17689DC7U, 0x2A7DBF44U},
			{0x3FAF4078U, 0xC004FC0EU, 0xDF11862CU, 0xB2F02E9EU, 0xA0A1B7B3U, 0xF10A5E0FU, 0x8936EC80U, 0x30ACA623U}},
		{{0x02F40D9AU, 0xF83CBF05U, 0x2C318A4DU, 0x4681C468U, 0x0E9C2674U, 0x98575618U, 0x1847092EU, 0xBE79D046U},
			{0x78BD01E0U, 0xAF1E480AU, 0x72A51DB9U, 0x6DD359E4U, 0xE3AFBAB6U, 0x62CE3821U, 0x17733199U, 0xC5CEE5B6U}},
		{{0x6FFD9FBBU, 0xE08B30D4U, 0x36C610B7U, 0x6E5BC699U, 0x9CE262CFU, 0xF343CFF2U, 0x68B914C1U, 0xCA2E4E35U},
			{0x16DE36C5U, 0x011D64C0U, 0x42E2B829U, 0xE0B10FDDU, 0x6685AAF8U, 0x78942981U, 0x230EDE97U, 0xE7511708U}},
		{{0x3B922BF8U, 0x671ED8FCU, 0x4C29B133U, 0xE4D8C0A0U, 0x3B6E99C4U, 0x87EB1239U, 0x8793BEBAU, 0xAFF3974CU},
			{0x2C18DF9BU, 0x03749405U, 0x91007139U, 0xC5C3A293U, 0xE37A0B95U, 0x6A77234FU, 0xB661C96BU, 0x02C29A21U}},
		{{0x141ECF61U, 0xC3AAF1D6U, 0x3BB22F53U, 0x9195509EU, 0x22D51357U, 0x29597404U, 0x537BED60U, 0x1B083822U},
			{0xE07289F0U, 0xCD7D6E35U, 0x6DD86EFFU, 0x1F94C48CU, 0xEB0F9CFAU, 0xC8BB1F82U, 0x1B2EB97DU, 0x9EE0B7E6U}},
		{{0x34D74E31U, 0x5A52FE2EU, 0x3BF79AB6U, 0xA352C310U, 0xABFEEB8FU, 0x97FF6C5AU, 0xF5C97305U, 0xBFBE8FEFU},
			{0xA7904608U, 0xD6081CE6U, 0xC4FCA249U, 0x1F812F3AU, 0xB9E5E200U, 0x9B24BC9AU, 0x38012EE8U, 0x91022C67U}},
		{{0x30A713A1U, 0xE83D9C5DU, 0x84EF0F93U, 0x4876E3F0U, 0xC1FBF928U, 0xC9777029U, 0xBCE7D2A4U, 0xEF7A6BB3U},
			{0xDFA2A659U, 0xB8067228U, 0xD877A48FU, 0xD5CD3398U, 0x025D0F3FU, 0xBEA4FD8FU, 0x2EAE7C2BU, 0xD67D2E35U}},
		{{0xCC5F4394U, 0x184DE7D7U, 0x4536E142U, 0xB5551B5CU, 0xD34AA60AU, 0x2E89B212U, 0xF50051D5U, 0x14A96FEAU},
			{0x0D12BB0BU, 0x4E21EF74U, 0x60B9677EU, 0xC522F020U, 0x2DF7731DU, 0x8B12E467U, 0x7B326D31U, 0x39F80382U}},
		{{0x39024A94U, 0xDFB8630CU, 0x97319452U, 0xAACB96A8U, 0xEDA3867CU, 0xD68A3961U, 0x77C4FFCAU, 0x0C58E2B0U},
			{0x4DA919FAU, 0x3D545D63U, 0xF15E2289U, 0xEF79B69AU, 0x808BAB10U, 0x54BC3D3DU, 0x45F82C37U, 0xC8AB3007U}},
		{{0x7C4A658AU, 0xC12738B6U, 0x40E72182U, 0xB3C47639U, 0x8798E44FU, 0x3B77BE46U, 0x17A7F85FU, 0xDC047DF2U},
			{0x5E59D92DU, 0x2439D4C5U, 0xE8E64D8DU, 0xCEDCA475U, 0x87CA9B16U, 0xA724CD0DU, 0xA5540DFEU, 0x35E4FD59U}},
	},
	{
		{{0x3A29467AU, 0x9894344FU, 0xC51EBA6DU, 0xDE81E949U, 0xA5E5C2F2U, 0xDAEA066BU, 0x08C8C7B3U, 0x3FC8A614U},
			{0x06D0DE9FU, 0x7ADFF88FU, 0x3B75CE0AU, 0xBBC11CF5U, 0xFBBC87D5U, 0x9FBB7ACCU, 0x7BADFDE2U, 0xA1458E26U}},
		{{0xE039C256U, 0x1CB43668U, 0x7C17FD5DU, 0x5F26FB8BU, 0x79AA062BU, 0xEEE426AFU, 0xD78FBF04U, 0x072002D0U},
			{0xE84FB7E3U, 0x4C9CA237U, 0x0C82133DU, 0xB401D8A1U, 0x6D7E4181U, 0xAAA52592U, 0x73DBB152U, 0xE9430833U}},
		{{0x6EE7C983U, 0x2F5FAD1EU, 0xB41328F5U, 0xEB0F9D7CU, 0x1D78D5F7U, 0x9BA68B44U, 0x35BC726FU, 0xA06B3B9EU},
			{0x593E1FF1U, 0xA2550255U, 0xDFBEC115U, 0x552DD43DU, 0xBBA8F046U, 0x2C48A7ABU, 0xAD0BF133U, 0xD4FC56A3U}},
		{{0xBE24319AU, 0xF92DDA31U, 0xE095A8E7U, 0x03F7D28BU, 0x98782185U, 0xA52FE840U, 0x29C24DBCU, 0x276DDAFEU},
			{0x1D7A64EBU, 0x80CD5496U, 0x7F1DBE42U, 0xE4360889U, 0x8438D2D5U, 0x2F81A877U, 0x85169036U, 0x7E4D52A8U}},
		{{0xBA04B5D1U, 0x62F21CEFU, 0x224C7352U, 0x9A442707U, 0x33C6171FU, 0xBF07966CU, 0x1E0816B0U, 0xDB7BA891U},
			{0x033745A9U, 0x306FEA59U, 0xC0A78F67U, 0x2AACF7E0U, 0xAD251BF9U, 0xB5AA3883U, 0x26BD7086U, 0x345AEDE9U}},
		{{0x1D59715DU, 0x19E3D5B1U, 0xD788983EU, 0xC7EAA762U, 0xABF1F248U, 0xE5A730B0U, 0xFAE3FD83U, 0xFBAB8084U},
			{0x53765B2FU, 0x65E50D21U, 0xFA127F3DU, 0xBDD4E083U, 0x397B1B10U, 0x9CF3C074U, 0xB1B59FD3U, 0x59F8090CU}},
		{{0x98119F10U, 0xDC1DE17DU, 0x488C36A6U, 0x74353C5DU, 0x3D8E23DFU, 0x14AAF33AU, 0x78BAF593U, 0x31E075C0U},
			{0x46D1CA3CU, 0x0F7CA03AU, 0x47B660C7U, 0x99C5E3ACU, 0x88FE2E59U, 0x70D02413U, 0x2A7EC005U, 0x2E9A6BE1U}},
		{{0x615FAA8FU, 0x7B15FD9DU, 0x968554EDU, 0x8FA1EB40U, 0x7AA44882U, 0x7BB4447EU, 0x029FFF32U, 0x2BB2D0D1U},
			{0x6CAA6D2FU, 0x075E2A64U, 0x22E7351BU, 0x8EB879DEU, 0x9A506C62U, 0xBCD5624EU, 0xA87E24DCU, 0x218EAEF0U}},
		{{0x241FBD6FU, 0xAC449695U, 0x081C1223U, 0x67C9B170U, 0xB56AAC6FU, 0x16868F21U, 0xF8BCB721U, 0x34BD8FA3U},
			{0xB6691C76U, 0x06B6BD33U, 0x381A7973U, 0x6C924766U, 0xA54078DBU, 0x6A12444CU, 0x6D1051CCU, 0xD02E91A9U}},
		{{0x44DDFA35U, 0x37E56847U, 0xDAB3F747U, 0x9CCFC5C5U, 0x1EE96CF4U, 0x9AC1DF3FU, 0x3B480B8FU, 0x0C0571A1U},
			{0x4B3A7B3CU, 0x2FBEB3D5U, 0x5DCDBB99U, 0x35C03669U, 0xB2415B3AU, 0x52A0F5DCU, 0x4413ED9AU, 0xD57759B4U}},
		{{0x0B33D3F8U, 0x077379C0U, 0x7064E409U, 0x421883C6U, 0x6C29C8F6U, 0x2D0873D7U, 0xD274C0C8U, 0xBFA433A3U},
			{0x23A5891EU, 0x56DC778FU, 0x35E2DE04U, 0xD663BF65U, 0x5DB517CEU, 0x488FDB48U, 0x19B226C2U, 0x00BBA55EU}},
		{{0x3D30A2C5U, 0x1FE647D8U, 0xF78A81DCU, 0x0857F77EU, 0x131A4A9BU, 0x11D5A334U, 0x29D393F5U, 0xC0A94AF9U},
			{0xDAA6EC1AU, 0xBC3A5C0BU, 0x88D2D7EDU, 0xBA9FE493U, 0xBB614797U, 0xBB4335B4U, 0x72F83533U, 0x991C4D68U}},
		{{0x8A058FB6U, 0xEDBBEEE7U, 0xFB09121AU, 0xB9D19DDCU, 0xD34DDDCEU, 0xA41BB45BU, 0x00964BC4U, 0x2DBC80B9U},
			{0x1D6CB654U, 0x4ED9137DU, 0x483D01C5U, 0x1B9016DBU, 0x6528E22EU, 0x5FC501BCU, 0x6CAD646BU, 0xB2D2F881U}},
		{{0xD2F01CB3U, 0x53258C28U, 0xD75DB0B1U, 0x93D6EAA3U, 0xE87D0DB4U, 0x419A2B0DU, 0xD8FE8493U, 0xA1E48F03U},
			{0xC508B23AU, 0xF747FAF6U, 0x35D53549U, 0xF137571AU, 0xFCF9B838U, 0x9F5E58E2U, 0xA7FD3CF5U, 0xC7186CEEU}},
		{{0x286BAD39U, 0x5E76FB2FU, 0x9DCAD1E2U, 0xBAD9EFE3U, 0xEDC7E904U, 0x60E75190U, 0x0FECB5A5U, 0x6A6F063EU},
			{0xAED8ACC3U, 0x5150ED85U, 0x6D20AF6CU, 0xB56CCFBCU, 0x2C69DBFAU, 0x7E0D1E98U, 0x7C7E10A9U, 0xABF5628AU}},
		{{0xE978A1D3U, 0x77B868CEU, 0x7AB92D04U, 0xE3A68B33U, 0x87A5B862U, 0x51029794U, 0x3A61D41DU, 0x5F0606C3U},
			{0x6F9326F1U, 0x2814BE27U, 0xC6FE3C2EU, 0x2F521C14U, 0xACDF7351U, 0x17464D7DU, 0x777F7E44U, 0x10F5F9D3U}},
		{{0x7408A2ABU, 0x1D216419U, 0x5928916AU, 0xAE55D518U, 0xF3165EEAU, 0xDF75684AU, 0xD84EEF59U, 0x538364D5U},
			{0x70563B1AU, 0xB54E2015U, 0x6B4CEFFFU, 0x74D9BBA7U, 0x7A0682DCU, 0xFCBECBD8U, 0xF193116CU, 0x0E00A402U}},
		{{0x269FB37DU, 0xCE8E616BU, 0x7DE62DE5U, 0xAAF73804U, 0x4FDD4153U, 0xABA11175U, 0x3770B49BU, 0x515759BAU},
			{0xAA423A61U, 0x8B09EBF8U, 0xCD41FB92U, 0x592245A1U, 0x9B4C8936U, 0x1CBA8EC1U, 0xAF36710EU, 0xA87E91E3U}},
		{{0x849FC416U, 0x65F68985U, 0xCDBAA73CU, 0x3C03A934U, 0xBFCB6647U, 0x112F311BU, 0xDE4E93CDU, 0x69C11340U},
			{0x66DB537BU, 0xBD2458B9U, 0x885B07E7U, 0xF974B018U, 0x70C8D332U, 0x5DB145A5U, 0x549B837BU, 0x30FDD0D1U}},
		{{0x3D34A2E3U, 0x1FD84CE4U, 0xB43B5D61U, 0xEE3759CEU, 0x619186C7U, 0x895BC78CU, 0xCBB9725AU, 0xF19C3809U},
			{0xDE744B1FU, 0xC0BE21AAU, 0x60F8056BU, 0xA7D222B0U, 0xB23EFE11U, 0x74BE6157U, 0x0CD68253U, 0x6FAB2B4FU}},
		{{0x512358B4U, 0x3E5C1D73U, 0x30BB99C9U, 0xCB5742B2U, 0x3C2D031AU, 0x4A2E2FA8U, 0xFB9878B8U, 0x371BC92BU},
			{0x8275656CU, 0x1EA71F9CU, 0x1C0300A1U, 0x14F794A2U, 0x26EA54E5U, 0x08EAE798U, 0x171A54C6U, 0xCF5854E5U}},
		{{0x4BF1D725U, 0xAD33EA5FU, 0x4F6C950FU, 0x9C1D8EE2U, 0xA377AF06U, 0x544EE78AU, 0x94A113E1U, 0x54F489BBU},
			{0x992FB7E8U, 0x8F11D634U, 0xA2A44347U, 0x0169A7AAU, 0x95020E00U, 0x1D49D4AFU, 0xE08E120BU, 0x95945722U}},
		{{0xB7BA3886U, 0x280AFBB3U, 0x368934A8U, 0x08803A3EU, 0x31F671ABU, 0xF980DF65U, 0x1A724791U, 0x90894AEAU},
			{0x8D1DA350U, 0x545B66A9U, 0x411353A5U, 0x9DF4FBBFU, 0xA398088AU, 0x1552743CU, 0xB82D5717U, 0xD1C14CDEU}},
		{{0xA4D32282U, 0xB6E33878U, 0x48020AE7U, 0xE36E029DU, 0x37A9B750U, 0xE05847FBU, 0xB29E3819U, 0xF876812CU},
			{0xD23A17F0U, 0x84AD138EU, 0xF0B3950EU, 0x6D7B4480U, 0x2FD67AE0U, 0xDFA8AEF4U, 0x52333AF6U, 0x8D3EEA24U}},
		{{0xF5C5EC83U, 0xB28D3AFDU, 0x91049FADU, 0x8D6AF6C1U, 0xFFBE1E1AU, 0x417964FFU, 0xF51C790AU, 0xBACE9EEAU},
			{0xB20F2979U, 0x42022236U, 0x765D3801U, 0x6B05B729U, 0x6D6DE3E7U, 0xBE0EE200U, 0x1E01AF3AU, 0xB96ED501U}},
		{{0xB15D5ACCU, 0x0D052075U, 0xBD815BC4U, 0xC6D9C79FU, 0xDFA36CF2U, 0x8DCAFD88U, 0x38AA9070U, 0x908CCBE2U},
			{0xBA35AFCEU, 0x638722C4U, 0xFD6ABF0BU, 0x5A3DA8B0U, 0xC9C335C1U, 0x2DCE252CU, 0x65AA799BU, 0x84E7F0DEU}},
		{{0xE0EDBC62U, 0xEF8762ECU, 0x852773FBU, 0x33449828U, 0xC3AE3885U, 0x2C9B90F3U, 0x731E56B2U, 0xD8191812U},
			{0x736831F0U, 0x205D7E95U, 0xD641C15DU, 0xC3818D48U, 0xF43E157CU, 0xC6B63839U, 0x36AD51F0U, 0x55160447U}},
		{{0xB99A72CBU, 0x2101A522U, 0x87618016U, 0x06DE6E67U, 0xE6F3653EU, 0x5FF8C7CDU, 0xC7A6754AU, 0x0A821AB5U},
			{0x7CB0B5A2U, 0x7E3FA52BU, 0xC9048790U, 0xA7FB121CU, 0x06CE053AU, 0x1A725020U, 0x04E929B0U, 0xB490A31FU}},
		{{0xBC407E6EU, 0x70BB7719U, 0xD84CEB41U, 0x231328EFU, 0xC104BB20U, 0x8BCA6A1FU, 0x280B9071U, 0xD6F4E425U},
			{0x92896A82U, 0xB41B95A2U, 0xFA34DF67U, 0x735CF435U, 0xD9D6D769U, 0xBC331A08U, 0x2682747EU, 0x57978605U}},
		{{0x62DD61ADU, 0xE17BE47DU, 0x6BE01371U, 0x781A961CU, 0xDAE3CBBAU, 0x1063BFD3U, 0x7F73C9BAU, 0x35647406U},
			{0x2736A129U, 0xF50E957BU, 0xED13F256U, 0xA6313702U, 0x3A19FCC5U, 0x9436EE65U, 0xE7A4C8B6U, 0xCF2BDB29U}},
		{{0x87F3B8BEU, 0x698AF742U, 0xD1A1591DU, 0x4F5D9D1AU, 0x0FE4ACE1U, 0x540FAC3CU, 0xC6894A7DU, 0x83A69B24U},
			{0xAD6FEB46U, 0x935C07EEU, 0x7FF325FAU, 0xE02CBD88U, 0xBCC6380BU, 0xE8F08C9DU, 0xA6E045CEU, 0x9C7FF40FU}},
		{{0xC5F95CD8U, 0xB06B1244U, 0xF4AB95F4U, 0xDA8C8AF0U, 0xB9E5836DU, 0x1BAE59C2U, 0x3ACFFFFCU, 0x07D51E7EU},
			{0xC2CCBCDAU, 0x01E15E6AU, 0x8528C3E0U, 0x3BC1923FU, 0xA49FEAD4U, 0x43324577U, 0x2AA7A711U, 0x61A1B884U}},
	},
	{
		{{0xB0E63D34U, 0x4FE7EE31U, 0xA9E54FABU, 0xF4600572U, 0xD5E7B5A4U, 0xC0493334U, 0x06D54831U, 0x8589FB92U},
			{0x6583553AU, 0xAA70F5CCU, 0xE25649E5U, 0x0879094AU, 0x10044652U, 0xCC904507U, 0x02541C4FU, 0xEBB0696DU}},
		{{0xA2DEE7A6U, 0x758C1A3EU, 0x734B2284U, 0xDCDE2F3CU, 0x4EABA6ADU, 0xABA445D2U, 0x76CEE0A7U, 0x35AAF668U},
			{0xE5AA049AU, 0x7E0B04A9U, 0x91103E84U, 0xE74083ADU, 0x40AFECC3U, 0xBEB183CEU, 0xEA043F7AU, 0x6B89DE9FU}},
		{{0x99375235U, 0xB99F0E03U, 0xB9917970U, 0x7614C847U, 0x524EC067U, 0xFEC93CE9U, 0x9B122520U, 0xE40E7BF8U},
			{0xEE4C4774U, 0xB5670631U, 0x3B04914CU, 0x6F03847AU, 0xDC9DD226U, 0xC96E9429U, 0x8C57C1F8U, 0x43489B6CU}},
		{{0xFE67BA66U, 0x0E299D23U, 0x93CF2F34U, 0x91450760U, 0x97FCF913U, 0xF45B5EA9U, 0x8BD7DDDAU, 0x5BE00843U},
			{0xD53FF04DU, 0x358C3E05U, 0x5DE91EF7U, 0xBF7CCDC3U, 0xB69EC1A0U, 0xAD684DBFU, 0x801FD997U, 0x367E7CF2U}},
		{{0xCC2338FBU, 0x46FFD227U, 0x90E26153U, 0x89FF6FA9U, 0x331A0076U, 0xBE570779U, 0x06E1F3AFU, 0x43D241C5U},
			{0xDE9B62A3U, 0xFDCDB97DU, 0xA0AE30EAU, 0x6A06E984U, 0x4FBDDF7DU, 0xC9BF1680U, 0xD36163C4U, 0x170471A2U}},
		{{0x3113655EU, 0xFF5BA8AEU, 0x57B83180U, 0xFA2C6E2BU, 0x77E0EABEU, 0x1C482719U, 0x337FEA97U, 0xF9F3C555U},
			{0xA42581CBU, 0x340F7022U, 0x18F710E3U, 0xE1DE0BC2U, 0xF62E5AA8U, 0xEE640ADEU, 0x49428940U, 0x16B23891U}},
		{{0x55950CC3U, 0x361619E4U, 0x56B66BB8U, 0xC71D665CU, 0xAFAC6D84U, 0xEA034B34U, 0xE5E4C7E3U, 0xA987F832U},
			{0x7A79A6A7U, 0xA0742772U, 0xE26D6C23U, 0x56E5D017U, 0x38167E10U, 0x7E50B976U, 0xE88AA84EU, 0xAA6C81EFU}},
		{{0xB0DC8595U, 0x0CA1F3B7U, 0x9F1D9F2EU, 0x27DE4608U, 0xBADD82A7U, 0x1AF3BF39U, 0x65862448U, 0x79356A79U},
			{0xF5F9A052U, 0xC0602345U, 0x139A42F9U, 0x1A8B0F89U, 0x844D40FCU, 0xB53EEE42U, 0x4E5B6368U, 0x93B0BFE5U}},
		{{0x4D325BBFU, 0x473959D7U, 0x8D6114B9U, 0x2A61BEECU, 0x924BE2EEU, 0x25672A94U, 0xF2C23D0CU, 0xA48595DBU},
			{0x6A221838U, 0xE476848BU, 0x35C1B673U, 0xE743E69AU, 0xD8468503U, 0x2AB42499U, 0xE9E90BA7U, 0x62AA0054U}},
		{{0xBC482911U, 0x358D13F1U, 0xB7FA7F26U, 0x685D1971U, 0x2BE1AEE4U, 0x3E67A51DU, 0x98D114A9U, 0xE0418509U},
			{0x4E052561U, 0x59639F60U, 0x155D0818U, 0x32075C49U, 0x67B64B1CU, 0x2AA2343BU, 0x67F53E6AU, 0x1B445E29U}},
		{{0x73A904E0U, 0xBDFB2717U, 0x28888D73U, 0x7CE1E40BU, 0xEAA97D1BU, 0x2E7E35F6U, 0xA9AFA097U, 0xD061772AU},
			{0x7A1F7C59U, 0x434AC7C4U, 0xE79B7B9AU, 0x6E21124AU, 0xBB22ECC7U, 0x055ACFF3U, 0x84C858D3U, 0x8BFD7AC9U}},
		{{0xC024789CU, 0x5434DD02U, 0x41B57BFCU, 0x90DCA9EAU, 0x243398DFU, 0x8AA898E2U, 0x894A94BBU, 0xF607C834U},
			{0xC2C99B76U, 0xBB07BE97U, 0x18C29302U, 0x6576BA67U, 0xE703A88CU, 0x3D79EFCCU, 0xB6A0D106U, 0xF259CED7U}},
		{{0x9F1F68ADU, 0x2FD57DF5U, 0xB06470C8U, 0x5DDCC6DBU, 0xA9B47307U, 0x801B6451U, 0x76551BF4U, 0x6B51C8E3U},
			{0xD44E1DA9U, 0xEF0BD1F7U, 0x4D4E600CU, 0x714BCB1DU, 0x0C6540C7U, 0xC57BB9E4U, 0x327CC644U, 0x71BD1EC2U}},
		{{0xCFD84F0AU, 0x00CD33B5U, 0x4E6B0DDDU, 0xCFA568F7U, 0x2D0F48F4U, 0x1C694EDBU, 0xFEFF7DD8U, 0x2747C7CCU},
			{0xAC8C24B2U, 0xCEDAECADU, 0x0742A5E5U, 0xDB29DE3FU, 0x3090296DU, 0xE35D8FBBU, 0xB11FB54AU, 0x788CABF7U}},
		{{0x7F4DD81FU, 0x9A52CF7EU, 0x5E69C05EU, 0xA0132BE1U, 0x2A0F4D72U, 0x90DAB747U, 0x312D6706U, 0xC142F911U},
			{0x8261998BU, 0xE8D3631FU, 0x615C1C94U, 0xF0F42FAEU, 0xAEC3FA5DU, 0x2F4E948CU, 0xA374101EU, 0x242AE7A8U}},
		{{0xC8DE610BU, 0x0F893A5DU, 0x67E223CEU, 0xE8C515FBU, 0x4EAD6DC5U, 0x7774BFA6U, 0x925C728FU, 0x89D20F95U},
			{0x098583CEU, 0x7A1E0966U, 0x93F2A7D7U, 0xA2EEDB94U, 0x4C304D4AU, 0x1B282097U, 0xC077282DU, 0x0842E3DAU}},
		{{0xD088BE52U, 0x1FA878CAU, 0xA9E1E656U, 0x89C2CB07U, 0x219D62DBU, 0x385BC5C3U, 0x5FDA2752U, 0xD82B676BU},
			{0xE304EAFCU, 0x2449DC9EU, 0x632F4EA2U, 0x1E9E7991U, 0xCDD5E0B9U, 0x3036E061U, 0x830825BCU, 0x75A6F6FFU}},
		{{0x81F65E9BU, 0x2E5B2604U, 0x4901F837U, 0x480156C0U, 0xB857B733U, 0x557F86ABU, 0x735B4411U, 0x88E3ED0EU},
			{0x2A33732EU, 0xC337680DU, 0x31C9C11FU, 0xA599BFCBU, 0xA95201C4U, 0xB282F851U, 0x854DDF95U, 0xD342DA8AU}},
		{{0x449DEDB4U, 0xB10FCDDCU, 0xD1244ACFU, 0x2C890042U, 0xC7FC7017U, 0x9B3072CAU, 0x9CE8063FU, 0x1ACDA685U},
			{0x7F51E2F5U, 0xD243313CU, 0xD73D9578U, 0x52A3F1A4U, 0x64F0CE6EU, 0xDA785B7AU, 0x442A4C2DU, 0x2E766315U}},
		{{0x3B9E2D7BU, 0xE4D972A3U, 0xC48218FFU, 0x7CC60B27U, 0x84149D91U, 0x8FC70838U, 0x2F461ECCU, 0x5C04346FU},
			{0x614650A9U, 0xEBE9FDF2U, 0xC1F666ACU, 0x5E35B537U, 0x88BABC83U, 0x645613D1U, 0xC5E1C93EU, 0x88CACE3AU}},
		{{0x151F111AU, 0x94F9B004U, 0x07DBC5FAU, 0xC7A5035BU, 0x609E49D7U, 0x53958EA7U, 0x9013F4C0U, 0x0526B4D7U},
			{0x593E2FBDU, 0x66DE5EBBU, 0x4C2E0C37U, 0x6E7CF8B4U, 0x8C983E78U, 0x6F72FC8BU, 0x2348F9D7U, 0x6FAB9B63U}},
		{{0xEB70AC59U, 0x58D02E81U, 0x4417D8F7U, 0xF522769BU, 0x077274FFU, 0x9F3063D5U, 0x340FE8ACU, 0xF5AC6F4FU},
			{0xB50914BAU, 0xCE72D9D1U, 0xB7BC255CU, 0xB3835984U, 0x7CA5038FU, 0x145D3FA7U, 0xAD8FAB13U, 0x7ACDA3C6U}},
		{{0x6A3D8468U, 0xC748A352U, 0x27E38032U, 0x3FAB4799U, 0xFA430CE7U, 0x91AD3629U, 0x71614C44U, 0xC5AF0B2CU},
			{0x0C211611U, 0xCEDE3FA5U, 0x02338083U, 0x6E6889BAU, 0x77F0FE32U, 0xEE0A1959U, 0x0F4BBC5AU, 0x01EA905DU}},
		{{0x3DE92E23U, 0x209CA375U, 0x5FBBB6E3U, 0xCCB03CC8U, 0xD7B1487EU, 0xCCB90F03U, 0xC710941FU, 0xFA9C2A38U},
			{0x6724CEEDU, 0x756C3823U, 0x192D0323U, 0x3A902258U, 0xEA5E038EU, 0xB150E519U, 0xC7427591U, 0xDCBA2865U}},
		{{0x8193DB48U, 0x12CFB25EU, 0x3BEA708CU, 0xDDB4AE63U, 0xF181F821U, 0xDAAE102EU, 0x24A089D9U, 0x9D9D9230U},
			{0xA0876AEAU, 0x71C4122DU, 0xBBE19C09U, 0x1A63EA3BU, 0x016F8D0CU, 0x3B898076U, 0xAEA6B713U, 0xA5CCCC5DU}},
		{{0x06F6E97DU, 0x510E8EE3U, 0xB00EAA8CU, 0x684A8FC5U, 0xB93FBF33U, 0x15313579U, 0xF66B1723U, 0xE67F5FA6U},
			{0xCE86748CU, 0x815881F6U, 0xEAD58B10U, 0xC1CED318U, 0xF2F33393U, 0x8662775BU, 0x7D836FF2U, 0x7AC0C904U}},
		{{0x4A8E2F61U, 0xC3F22BAFU, 0x176DA6A6U, 0x77D29EDEU, 0x1607DA63U, 0x40A55F21U, 0x1452E391U, 0x858B3856U},
			{0xFE1B3C56U, 0x0DD3C267U, 0x7D55227AU, 0x66C04BDDU, 0xE6404E09U, 0xFBD2FE55U, 0xEA9CFCBCU, 0x5981CF49U}},
		{{0x78890732U, 0xE549237FU, 0x53FCB4D9U, 0xC443BEF9U, 0xEB3480D6U, 0x9884D8A6U, 0x3048B186U, 0x8A35B6A1U},
			{0x65E9A90AU, 0xB4E44716U, 0x653006C0U, 0x45BF380DU, 0x4FE9AE3BU, 0x8F3F820DU, 0x979A3B71U, 0x244A35A0U}},
		{{0xAEA870AFU, 0xAE46A902U, 0x7CBEDC99U, 0xA9B9FCF5U, 0x79B7E793U, 0x74F2CA3FU, 0x1DBEEB28U, 0xADB8F223U},
			{0x6764DF85U, 0x6302060EU, 0x57EBD554U, 0x363320D2U, 0x798D22E1U, 0xD9FD573EU, 0xEBB67DEDU, 0x285F85F5U}},
		{{0x8AEB55C9U, 0x0AACD613U, 0xD86885F0U, 0x79791DA4U, 0x44B05F23U, 0x165E8267U, 0x284548EDU, 0x9EE5F5E8U},
			{0x85B661B8U, 0x9FD548CCU, 0x89C58689U, 0x257037C0U, 0xF9290CB2U, 0x9B47306FU, 0x0677ECF4U, 0x56BA2EEBU}},
		{{0x11CAA2B5U, 0xD86B3292U, 0x39337BD1U, 0x2A26258EU, 0x79C8C291U, 0x4DC5A9B5U, 0x741942E6U, 0x16443D87U},
			{0xF811400CU, 0x6BC9A2F8U, 0x9EEB4E0EU, 0x819C6935U, 0xCE0C214BU, 0xE1BE7273U, 0x84B61581U, 0x429AFB81U}},
		{{0x74CD06FFU, 0xA1010E9DU, 0xACA3EEACU, 0x9C17C7DFU, 0x8063AA2BU, 0x74C86CD3U, 0x734614FFU, 0x8595C4B3U},
			{0x990F62CCU, 0xA3DE00CAU, 0xCA0C3BE5U, 0xD9BED213U, 0xDF8CE9F5U, 0x7886078AU, 0x5CD44444U, 0xDDB27CE3U}},
	},
	{
		{{0x26EE8382U, 0x9C7C581DU, 0x359D638EU, 0xCF17DCC5U, 0xB728AE3DU, 0xEE8273ABU, 0xF821F047U, 0x1D112926U},
			{0x50491A74U, 0x11498477U, 0xFDE0DFB9U, 0x687FA761U, 0x7EA435ABU, 0x2C258022U, 0x91CE7E3FU, 0x6B8BDB94U}},
		{{0x53FB2B56U, 0xB23A03A5U, 0x4E057F78U, 0x6CE141E7U, 0x89E490D9U, 0x796525C3U, 0xA31A7E75U, 0x0BC95725U},
			{0x1220FD06U, 0x1EC56791U, 0x408B0BD6U, 0x716E3A3CU, 0xE8EBEBA9U, 0x31CD6BF7U, 0xBEE6B670U, 0xA7326CA6U}},
		{{0x99F241D7U, 0x60953556U, 0x001A349DU, 0xEE4ADBD7U, 0xAA89E491U, 0x0B35BF6AU, 0x136F7546U, 0x7F0076F4U},
			{0x9264DA3DU, 0xD19A18BAU, 0x62A7A28BU, 0x6EB2D2CDU, 0x8761C971U, 0xCDBA941FU, 0xA3BE4A5DU, 0x1550518BU}},
		{{0xCF7D62D2U, 0x20D3C982U, 0x23BA8150U, 0x1F36E29DU, 0x92763F9EU, 0x48AE0BF0U, 0x1D3A7007U, 0x7A527E6BU},
			{0x581A85E3U, 0xB4A89097U, 0xDC158BE5U, 0x1F1A520FU, 0x167D726EU, 0xF98DB37DU, 0x1113E862U, 0x8802786EU}},
		{{0x6BCEFC18U, 0xC3C39896U, 0x18636E00U, 0xB754B343U, 0xF53B1991U, 0x6FB6A168U, 0xB84C2FE5U, 0x87181B55U},
			{0x2721BC8CU, 0x1686C910U, 0x95030E2AU, 0xC6490660U, 0x97DF55DAU, 0x18FDEB2FU, 0x7C27D231U, 0x10D52CFCU}},
		{{0x118731B9U, 0x2A01E09CU, 0xCD393CD8U, 0xB6C46182U, 0x7508E328U, 0x5ED7DD65U, 0x681DA8FAU, 0x6402CA1BU},
			{0xCE9F272DU, 0x603ABE86U, 0x29167C9CU, 0x9363435CU, 0xC45A2A42U, 0x4814F7C1U, 0x9A22CACDU, 0x14656222U}},
		{{0x323B470CU, 0xB4526431U, 0xD536E418U, 0x40CD4E1AU, 0x01933BC0U, 0x430FDD3DU, 0x07649023U, 0x3D3E6DDEU},
			{0x2E9523B1U, 0x4B0564EFU, 0x9079BC4FU, 0x8C0D3105U, 0x837D3D58U, 0x496C6967U, 0x89123B5FU, 0x3A79F660U}},
		{{0x36F09AB0U, 0xEFB2149EU, 0x4A10BB5BU, 0x03F163CAU, 0x06E20998U, 0xD0297045U, 0x1B5A3BABU, 0x56F0AF00U},
			{0x70880E0DU, 0x7AF4CFECU, 0xBE3D913FU, 0x7332A66FU, 0x7ECEB4BDU, 0x32E6C84AU, 0x9C228F55U, 0xEDC4A79AU}},
		{{0xA32F699AU, 0x2999149EU, 0x72186170U, 0x6D6C8E11U, 0x45546E52U, 0xAD74494FU, 0x89EFE7FEU, 0x2B3CB539U},
			{0xE42FB031U, 0xB9A2E60EU, 0x670E4823U, 0xF858FD0DU, 0x492C636DU, 0xEBCAAB7EU, 0xD32C4670U, 0x40E072FCU}},
		{{0xB2344E1DU, 0x457A6A66U, 0x8F37DCFEU, 0xDEC81F2AU, 0xAB40F9D5U, 0x61D5F83EU, 0xF1DF043CU, 0x5CA82776U},
			{0xF846677CU, 0x2174681EU, 0x516D1628U, 0x7C241F4FU, 0x1F01374FU, 0xF54994C3U, 0xDF0F210CU, 0x253C8367U}},
		{{0x20E91820U, 0xC94DBEEBU, 0x62B641E7U, 0x19AAC204U, 0x8B49CF50U, 0xC22834F0U, 0x8E5D5A6DU, 0x47E8C74BU},
			{0xF42ACB6AU, 0x78160CDCU, 0x3A3568B9U, 0x7A536475U, 0x6CD1EB71U, 0x4A28D547U, 0x8C8FBC11U, 0x0360BC3FU}},
		{{0xF4C6B6ECU, 0xF6E894D1U, 0x18B3CD9BU, 0x526B0827U, 0x12117FBFU, 0x73F952A8U, 0x11945BF5U, 0x2BE864B0U},
			{0x42099B64U, 0x86F18EA5U, 0x07548CE2U, 0x2770B28AU, 0x295C1C9CU, 0x97390F28U, 0xCB5206C3U, 0x672E6A43U}},
		{{0x8EBADAF8U, 0x66502B73U, 0xF9A04C07U, 0x27BAFE8EU, 0x1BF6AE04U, 0x74DA432FU, 0x278D403BU, 0x271D8268U},
			{0x93471B57U, 0x018B91ACU, 0xB276C51FU, 0x01096869U, 0x6DC57DD2U, 0x5B79C101U, 0x806C80A5U, 0xB623345EU}},
		{{0xE9D72088U, 0x89D24349U, 0x3E9CF6E0U, 0xD5317A03U, 0x73C8F8EAU, 0x5BC61A9DU, 0xF10F5A3DU, 0x48F9C2C8U},
			{0x086B9507U, 0x472414DFU, 0xAE549B92U, 0x79818CDFU, 0x62A415BFU, 0x3D24A77AU, 0xD3B22976U, 0xB92DF59FU}},
		{{0xE71FCF44U, 0x80450F8EU, 0xDB0A9986U, 0x2763DDFDU, 0x9668BCF2U, 0x8C288C7AU, 0x0392E2F6U, 0xD7D09B35U},
			{0x6506DD7AU, 0x0A3D5482U, 0xCDCE9D4FU, 0x9B43DAC1U, 0x458B63B8U, 0x8D154F61U, 0x129C973BU, 0x77BDA4D0U}},
		{{0xC55C4496U, 0xC37C7DD0U, 0x25BBABD2U, 0xA6A96357U, 0xADD7F363U, 0x5B7E63F2U, 0x2E73F1DFU, 0x9DCE3782U},
			{0xB2B91F71U, 0xE1E5A16AU, 0x5BA0163CU, 0xE4489823U, 0xF6E515ADU, 0xF2759C32U, 0x8615EECFU, 0xA5E2F1F8U}},
		{{0xEBA6ABCEU, 0x0B6C0D19U, 0x649EEEE4U, 0x6CAAC445U, 0xB465E10EU, 0x59B4F283U, 0xF729212DU, 0xD76704F2U},
			{0x70D1EE92U, 0x8D4E7383U, 0xEA6C1EB5U, 0xFBCAC28BU, 0x4EF28E05U, 0x2C84218BU, 0x7E6C6E0DU, 0x2C52F7D0U}},
		{{0x0FE09616U, 0xD8134CF0U, 0xE48C8CC3U, 0x4A31E59AU, 0x5FB87B82U, 0x5C0AE566U, 0xB2BD26A7U, 0xDC2EF15AU},
			{0x5B781765U, 0x63EBAEF5U, 0x5339585EU, 0x4F6CC83CU, 0xABFC78E4U, 0xD08AE201U, 0x1FBE2A56U, 0x98E7EE9AU}},
		{{0x0E1489A2U, 0x0A4897DDU, 0xE93D987FU, 0xC09F8736U, 0xEA79A437U, 0x427A00B8U, 0xAF89E9FAU, 0x3E2B39E4U},
			{0x7E8138F1U, 0x451C2D2FU, 0x37148BB0U, 0x08CDE411U, 0x0D50E541U, 0x016968C7U, 0xDD471291U, 0x2BDCEEE1U}},
		{{0x47C64367U, 0xCACCE2C8U, 0x45AF4EC0U, 0x6A496B9FU, 0x6034042CU, 0x2A0836F3U, 0x0B6C62EAU, 0x14A1F390U},
			{0x3EF1F540U, 0xE7FA9363U, 0x72A76D93U, 0xD323B30AU, 0x0FEAE451U, 0xFFEEC8B5U, 0xBD04EF87U, 0x4EAFC172U}},
		{{0x6C484007U, 0x3BDB1E1BU, 0xE6BE0202U, 0xE110D5A1U, 0x15665AAEU, 0x1C24E1AEU, 0x7C9C9D27U, 0xFA0EF689U},
			{0x9D22B607U, 0x01A0662AU, 0x6722F147U, 0x18C364CEU, 0x7521F74CU, 0x0446146DU, 0x9FA8ABB8U, 0x39777A4EU}},
		{{0x8DEAE427U, 0x36A7B30CU, 0xB62E583EU, 0xB4AC5F5AU, 0xDF0A39A9U, 0xACEF9FA2U, 0x5D659039U, 0xC929A604U},
			{0xFC262F7EU, 0xE14D9D6EU, 0x05538D9DU, 0x15E6D62DU, 0xC488F9E0U, 0xEE42A77EU, 0x892C8A42U, 0xAE836365U}},
		{{0x1AF533FDU, 0x90ABDD1BU, 0x750F0ACBU, 0x7C3D2576U, 0xC76CC9C8U, 0xFA0AC55AU, 0x5275AA05U, 0xC3B4302EU},
			{0xEF2DC19EU, 0xE2CBB31DU, 0x3806357BU, 0x5F3DB751U, 0xF509F98EU, 0x6474DF00U, 0x28EBBD89U, 0x9BA75F1EU}},
		{{0xABDED551U, 0x74519BE7U, 0xC8B74410U, 0x03D358B8U, 0x0E10D9A9U, 0x4D00B10BU, 0x28DA52B7U, 0x6392B0B1U},
			{0x0B75C904U, 0x6744A298U, 0xA8F7F96CU, 0xC305B0AEU, 0x182CF932U, 0x042E421DU, 0x9E4636CAU, 0xF6FC5D50U}},
		{{0x5FD676DFU, 0x47CB1FE0U, 0x9BA8960BU, 0x69C64291U, 0x0165DE6DU, 0x40D02306U, 0xD6B8B29AU, 0x783BF44EU},
			{0x6ED098BDU, 0xC84E19FBU, 0xFFBE6123U, 0x601F09F7U, 0xA0E24A3AU, 0x87AE89C5U, 0x5E05AC2AU, 0x07864E9CU}},
		{{0x392C5E00U, 0x850F9EFDU, 0xE2511BDEU, 0xC29F667FU, 0x8431298FU, 0xF5CF406DU, 0x79C0D05DU, 0xF90B10C8U},
			{0x0038F012U, 0xFB3E9B1DU, 0x0A8C9799U, 0x84C04E7AU, 0x96C8E986U, 0xB76102D4U, 0x176DA675U, 0xDEA63B13U}},
		{{0xDDF55369U, 0x2FAFC2EFU, 0x24AC63B9U, 0x70BFF06FU, 0x6E926ADDU, 0x1E1A3742U, 0xFDFA18CFU, 0x773537ADU},
			{0x5984B552U, 0xD211EA63U, 0x8C1AED24U, 0xB17EED4DU, 0x140B8B67U, 0x5DE9DE74U, 0x768BFF57U, 0x742501C8U}},
		{{0xB3E59B89U, 0xE4435A51U, 0x4133A1C9U, 0x13613955U, 0x440BEE59U, 0x87F46973U, 0x00C401E4U, 0x714710F8U},
			{0xD6C446C9U, 0xC0CF4BCEU, 0x6C4D5368U, 0xE0AA7FD6U, 0xFC68FC37U, 0xDE5D811AU, 0xB7C2A057U, 0x61FEBD72U}},
		{{0xBE4725E8U, 0x90FF2B91U, 0x5E81001EU, 0x710ABFF6U, 0xC5EF04F3U, 0x15EB3476U, 0x3C0DA2B7U, 0xCCDAB51BU},
			{0x2CC0652BU, 0x883840A5U, 0xF5E4A856U, 0xD1FC7D9DU, 0x070FFC88U, 0xEBBC3953U, 0x91EFEDC1U, 0x340F947DU}},
		{{0x6DBD11CFU, 0x1EDDBEBBU, 0xC619E203U, 0x8297AA45U, 0x962BD2A6U, 0x6354826FU, 0xFA12EDC7U, 0xBA3F3F67U},
			{0xFC7AD88DU, 0x25220F1DU, 0x8683C801U, 0x5D059F81U, 0x2D385764U, 0x0577F26EU, 0xA453E80DU, 0xA574C646U}},
		{{0xB8F4E30CU, 0x89D16C71U, 0xC63DFA29U, 0x9E2DABFBU, 0xDFDE5CEBU, 0x6033065EU, 0x0F3C45C6U, 0x072B1D1FU},
			{0xB8D429ECU, 0x0CD0BC2AU, 0xC2471F89U, 0xE747438CU, 0x319D679EU, 0x131CE856U, 0x87B24EBAU, 0x7520A228U}},
		{{0xD64CC78CU, 0x795847C9U, 0x9B6CB27BU, 0x6C50621BU, 0xDF8022ABU, 0x07099BF8U, 0xC04EDA1DU, 0x48F862EBU},
			{0xE1603C16U, 0xD12732EDU, 0x5C9A9450U, 0x19A80E0FU, 0xB429B4FCU, 0xE2257F54U, 0x45460515U, 0x66D3B2C6U}},
	},
	{
		{{0x453CADD6U, 0x8DE2B7BCU, 0xBC0BC1F8U, 0x203900A7U, 0xA6ABD3AFU, 0xBCD86E47U, 0x8502EFFBU, 0x911CAC12U},
			{0xEC965469U, 0x2D550242U, 0x29E0017EU, 0x0E9F7692U, 0x65979885U, 0x633F078FU, 0x4CF751EFU, 0xFB87D449U}},
		{{0xD551EE10U, 0x6066E2A2U, 0x727E09A6U, 0x87A8F1D8U, 0x2C01148DU, 0x00D08BABU, 0x424F33FEU, 0x6DA8E4F1U},
			{0xCF9A4E71U, 0x466D17F0U, 0x3BF5CB19U, 0xFF502010U, 0xD062ECC0U, 0xDCCF97D8U, 0x81D80AC4U, 0x80C0D9AFU}},
		{{0x1D7AADABU, 0x1A0445FFU, 0xD5F6A67CU, 0x65D38260U, 0x91CFB26FU, 0x6E62FB08U, 0x5C7D91D6U, 0xEF1E0FA5U},
			{0x33DB72CDU, 0x47E7C7BAU, 0xFA7C74B2U, 0x017CBC09U, 0xF50A503CU, 0x3C931590U, 0x616BAA42U, 0xCAC54F60U}},
		{{0x1BF4581CU, 0x98857CEBU, 0xACA7B166U, 0xE635E186U, 0x659722ACU, 0x278DDD22U, 0x1DB68007U, 0xA0903C4CU},
			{0x48F21402U, 0x366E4589U, 0xB96ABDA2U, 0x31B49C14U, 0xE0403190U, 0x329C4B09U, 0xD29F43FEU, 0x97197CA3U}},
		{{0x4B07E2B1U, 0x7173DD5DU, 0x8D9EA221U, 0xD144C4CBU, 0x1105AB14U, 0xE8B04EA4U, 0xFE80D8F1U, 0x92DDA542U},
			{0xCF03DCE6U, 0xE9982FA8U, 0x1A22CFFCU, 0x8B5EA965U, 0x3FAD88C4U, 0xF7F4EA7FU, 0x6A5BA95CU, 0x62DB773EU}},
		{{0x820357C7U, 0x18BD3FB4U, 0x6F1458ADU, 0x992039AEU, 0x25B44AA1U, 0x9A1DF3C5U, 0xED3D5281U, 0x2D780357U},
			{0xC77AD4D4U, 0x58CF7E4DU, 0xF9DF4FC4U, 0xD49A7998U, 0x1D71205EU, 0x4465A8B5U, 0x649254AAU, 0xA0EE0EA6U}},
		{{0x9C92B235U, 0x4BAAE6E8U, 0x6B3993A1U, 0xA73BBD0EU, 0x693DD031U, 0xD06D60ECU, 0x7156881CU, 0x03CAB91BU},
			{0x1DB3574BU, 0xD615862FU, 0x64BB061AU, 0x485B0185U, 0xA0181E06U, 0x27434988U, 0xC1C0C757U, 0x2CD61AD4U}},
		{{0xF3480D4AU, 0x03E2DE1CU, 0xBC8ACF1AU, 0xF0D8EDC7U, 0x68295A9CU, 0xF23E3303U, 0xC546A97DU, 0xFADD5F68U},
			{0x96F8ACB1U, 0x895597ADU, 0x671BDAE2U, 0xBDDD49D5U, 0x21DD43F4U, 0x16FCD528U, 0x6619141AU, 0xA5A45412U}},
		{{0x030D86A0U, 0xC85C34D3U, 0x213CE95EU, 0xF14B2E80U, 0xF07E6D7FU, 0xCE3EED9BU, 0xA3A3EC79U, 0x476C3E21U},
			{0xCADEA5D3U, 0xB4EC11F2U, 0xCCA936AAU, 0xD1AD5F12U, 0x34E61C7DU, 0x1724609EU, 0x2FD67BA2U, 0xCC520DF3U}},
		{{0xA9A17F2AU, 0x6BFBE2A8U, 0x03D95017U, 0x1CAC2F60U, 0x8EA2B48CU, 0x38C06257U, 0xCC3CC38AU, 0x21CA4D5CU},
			{0x67452091U, 0xFF067A54U, 0x139D462CU, 0x63BFDF5DU, 0x1450006FU, 0x221376A1U, 0x332A9AECU, 0xC81AFE5EU}},
		{{0xBAFEA141U, 0x11A09A99U, 0x19D41640U, 0x7FE0414BU, 0xF3B609D1U, 0xD66B072AU, 0xBC5554D2U, 0x27F7DE34U},
			{0xBC517B45U, 0xD66529AFU, 0x12D18D9FU, 0x8BE43521U, 0x4E0DEFD7U, 0x942192E1U, 0x90C0AF1EU, 0xB465871FU}},
		{{0x439F29CFU, 0xFA32C79FU, 0x4DD82A3BU, 0x7BF321C0U, 0xEAA2C1B1U, 0xFF127F54U, 0xF35E9618U, 0xA8365F2DU},
			{0x4D0EF8DDU, 0x852D2902U, 0x59228C4AU, 0x395CE2C1U, 0x215AFED3U, 0xB69F44E8U, 0xB27458E3U, 0x16C1F898U}},
		{{0xF33F25BCU, 0x170F87E0U, 0xC339C098U, 0x24DCB667U, 0xAB073EAEU, 0xBF1702A4U, 0x238CFB44U, 0xADA6919CU},
			{0xDDEE6375U, 0x53008511U, 0xB8DB60ADU, 0xDB92FA85U, 0xA421210EU, 0x50B6A366U, 0x4C37558FU, 0xDC7BF8EBU}},
		{{0x2E4F257EU, 0xE47BA108U, 0x35689D7CU, 0xCF0EE2DFU, 0x321BA0D0U, 0x8B8FC38EU, 0x0F745E8BU, 0x9470C64CU},
			{0xD65FA22FU, 0xA73887F5U, 0xC2A7EFBEU, 0xA581F89BU, 0xEEE4C98AU, 0x835A0BA6U, 0xA3291A71U, 0x86E183E9U}},
		{{0x89E4043BU, 0xFB5487B0U, 0x09799BD2U, 0x4DE49DEFU, 0xB3E760BEU, 0x9DA870C0U, 0x89EE1539U, 0x5E4E1DD3U},
			{0x915705DBU, 0x1B3849FAU, 0x5EAC0E81U, 0x7CE5E194U, 0xB00D3F5CU, 0x7C1772A0U, 0x6C00B5A1U, 0x54792676U}},
		{{0xC360E25AU, 0x8CE9B6BFU, 0x075A1A78U, 0xE6425195U, 0x481732F4U, 0x9DC756A8U, 0x5432B57AU, 0x83C0440FU},
			{0xD720281FU, 0xC670B3F1U, 0xD135E051U, 0x2205910EU, 0xDB052BE7U, 0xDED14B0EU, 0xC568EA39U, 0x697B3D27U}},
		{{0x1AF6714BU, 0x2E3A6CF1U, 0x3C13B96FU, 0x770F8EA6U, 0x4C8CFF95U, 0x98C242FBU, 0x95A0BE91U, 0x67EC9A0CU},
			{0xEB8EE7CFU, 0xEEF0335AU, 0x3371C424U, 0x63F34CE7U, 0x31EDE505U, 0x980B3995U, 0x9B3F3619U, 0x7CE83AFEU}},
		{{0x795E4A1CU, 0xB3F1BD2EU, 0xA1CDCA89U, 0x85D3187EU, 0x3541683DU, 0x15E44E3CU, 0x80ED4067U, 0x2A8C239CU},
			{0xBFC508EDU, 0xBDE6025AU, 0x3BF2C5EDU, 0xB1631E31U, 0xE7D9A112U, 0xB2CB3B3BU, 0x7C7838CCU, 0x0554C14FU}},
		{{0xAA88E0BFU, 0x1BE6B727U, 0x64E83507U, 0xD764C2BAU, 0xBAD7EB86U, 0x4ABCF397U, 0x7920B74FU, 0xB2FD1CBFU},
			{0xF13D032BU, 0x65E8915BU, 0x19FBD622U, 0x9D264ABBU, 0x2F48A2B4U, 0x2F62AF79U, 0x8619BAECU, 0x22A9B05FU}},
		{{0xDC453233U, 0xDEF29005U, 0x2FAC4BCFU, 0xC208C47AU, 0xAC3D55ACU, 0x6057A3FEU, 0x902C1207U, 0x1723725DU},
			{0x33EB0FECU, 0x9C31C627U, 0xBB3C63BBU, 0x4913CCDBU, 0x07305838U, 0x113E542BU, 0x310C2D97U, 0x9D48E72AU}},
		{{0xB8316B58U, 0xC1D52754U, 0x811FAB60U, 0x9435A342U, 0x6102C935U, 0xE126C376U, 0x3E25292EU, 0x7A4F1595U},
			{0x032CAD59U, 0x1BC3E7C3U, 0xFE2A1CB6U, 0x4B2D7A81U, 0xE08BA6CBU, 0xA80BF4E2U, 0x8CF90268U, 0xB7FCC9B2U}},
		{{0x51288296U, 0xA2E2D1A7U, 0xF66DDBB0U, 0xBACA527BU, 0x80313CD4U, 0x409B418FU, 0x873C6A8BU, 0x2B4B1AE8U},
			{0x2A93295FU, 0xB8E95EC7U, 0x2E5A795FU, 0x0EF65090U, 0x2F876AFAU, 0x165AC888U, 0x25C1E203U, 0x90CA87D9U}},
		{{0x93CE7936U, 0xBC128DA7U, 0x39BE9DF9U, 0x3CC69AD6U, 0xECB6D37CU, 0x6965991FU, 0xB8B5FFA3U, 0x64E001BFU},
			{0x9334010DU, 0x5D610ABFU, 0xDFDA3F0CU, 0x718FEEB0U, 0x030540D7U, 0x5B2B1EA8U, 0xF4B4D337U, 0x59F22F73U}},
		{{0xD9BBEB3DU, 0x54424EC4U, 0xD7B2921CU, 0x34CEAFE3U, 0x296D37C5U, 0x5E68022EU, 0x359F16B0U, 0xA28E0A2BU},
			{0xBC3F9D73U, 0xFDD82DD9U, 0xBAF3E1FFU, 0x6939A8F9U, 0x31736DC4U, 0x55CFF45CU, 0x7892E8E7U, 0x910F5642U}},
		{{0xAAD0042CU, 0xDF35BF05U, 0x28DA6ACCU, 0x2925EC70U, 0xE1AA3F5CU, 0x822AA804U, 0x3D348E63U, 0xB5EDEC7DU},
			{0xB4F6B2CFU, 0x03362830U, 0x096BBA2AU, 0x08BFCB0DU, 0x9FEC3F04U, 0x8AFDE464U, 0x1C434E17U, 0xFB402E4FU}},
		{{0x8ACEC326U, 0xB6C46C9DU, 0x296CB8C0U, 0xACF5583DU, 0xCF077208U, 0x2552CAC6U, 0x0DA03DD6U, 0x5261EF83U},
			{0x5D0046B4U, 0xF6A7EE30U, 0xCB0A3E85U, 0x24865C96U, 0x8BDF7A89U, 0x71599144U, 0xF8E42383U, 0x221D5CDBU}},
		{{0x3547DC09U, 0x951DAAF4U, 0xD4AEACD4U, 0xB982D50BU, 0x459F1156U, 0xDCC9942BU, 0xFA45B272U, 0x8067B1E2U},
			{0xD6A3FBB7U, 0xE2FBD00CU, 0xCA742D37U, 0x46FC24DDU, 0x7B26FBDDU, 0x66454476U, 0x2FD8F67CU, 0x3FA6A361U}},
		{{0xDFE39260U, 0xDE09B349U, 0x73549093U, 0x984612F7U, 0x67853B02U, 0x7CEDE281U, 0x29D17703U, 0x7D809BB4U},
			{0x2756C4F0U, 0x450B6BFBU, 0x93F02B80U, 0xC59FF9BAU, 0x20AD9561U, 0x3E695457U, 0x3331E2C7U, 0x0C7CF0BEU}},
		{{0xCA9C4803U, 0x42727C9BU, 0x29DCDA5EU, 0x7C140346U, 0xBA21F617U, 0x00ECAB39U, 0xF0BAEFC1U, 0xB52BB196U},
			{0x73AC1C74U, 0x56D503DEU, 0x539C9D2CU, 0x082DCE0FU, 0xFA3C9587U, 0xF7770A8AU, 0x595C7E7DU, 0x96895A7AU}},
		{{0x6EFAFB47U, 0x29DB69D2U, 0xEE5E7429U, 0x04B9E9F2U, 0x88E90203U, 0x91F21D38U, 0x7ADFA615U, 0xCF3F8E79U},
			{0x61EBE737U, 0x89F9121CU, 0x06BA03BDU, 0x87596906U, 0x9778FEB7U, 0x1AC27A72U, 0x34726018U, 0xE018723CU}},
		{{0xFC70937EU, 0x7C42CF86U, 0xA1118F05U, 0x5BF83375U, 0x39E9BF98U, 0x11C05413U, 0xACFA08F9U, 0x4AA2F304U},
			{0xDA8B6FB3U, 0xD6614D1AU, 0x5B05AD0BU, 0x92733B77U, 0x3015DD66U, 0xCF8ED5F1U, 0xD8150A32U, 0x1BADEF18U}},
		{{0xFB3FF9EDU, 0x2E599B9AU, 0x17F6515CU, 0x28C2E0ABU, 0x474DA449U, 0x1CBEE4FDU, 0x4F364452U, 0x071279A4U},
			{0x01FBE855U, 0x97ABFF66U, 0x5FDA51C4U, 0x3EE394E8U, 0x67597C0BU, 0x190385F6U, 0xA27EE34BU, 0x6E9FCCC6U}},
	},
	{
		{{0xDDA492F8U, 0x3BC77ADEU, 0x78297205U, 0xC11A3AEAU, 0x34931B4CU, 0x5E89A3E7U, 0x9F5694BBU, 0x17512E2EU},
			{0x177BF8B6U, 0x5DC349F3U, 0x08C7FF3EU, 0x232EA4BAU, 0xF511145DU, 0x9C4F9D16U, 0x33B379C3U, 0xCCF109A3U}},
		{{0x80EB24A9U, 0x60E28570U, 0x488E0CFDU, 0x7BEDFB4DU, 0xC259CDB8U, 0x721EBBD7U, 0xBC6390A9U, 0x0B0DA855U},
			{0xDE314C70U, 0x2B4D04DBU, 0x6C32E846U, 0xCDBF1FBCU, 0xB162FC9EU, 0x33833EABU, 0xB0DD3AB7U, 0x9939B48BU}},
		{{0x97C3DFB9U, 0xC42B8AB1U, 0xCF168154U, 0x55A549B0U, 0xC1B50692U, 0xAD6748E7U, 0x6FC5CBCBU, 0x2775780FU},
			{0xE1C9D7C8U, 0x4EAB80B8U, 0x3FDBCD56U, 0x8C69DAE1U, 0x9969EACEU, 0x47E6B4FBU, 0xA705CB5AU, 0x002F1085U}},
		{{0x711B0EB9U, 0x96892C1FU, 0x780AB954U, 0xB905F2C8U, 0xA20792DBU, 0xACE26309U, 0x0684E126U, 0xEC8AC9B3U},
			{0xB40A2447U, 0x486AD8B6U, 0x9FE3FB24U, 0x60121FC1U, 0x1A8E3B3FU, 0x5626FCCFU, 0x6AD1F394U, 0x4E568622U}},
		{{0x3037BF52U, 0x2BFB4318U, 0x78C725D7U, 0xB61E6DB5U, 0xBBB3E5D7U, 0x8EFD4060U, 0xDBAC488EU, 0x2E014701U},
			{0x360AA449U, 0xAC75CF9AU, 0x79634D08U, 0xB70CFD05U, 0xFFFB15EFU, 0xA591536DU, 0xD07C106CU, 0xB2C37582U}},
		{{0x236F4A98U, 0x5CFBBB22U, 0x066800BBU, 0x0B0C59E9U, 0x5A9A7774U, 0x4AC69A8FU, 0xD6BEC948U, 0x2B33F804U},
			{0x32E6C466U, 0xB3729295U, 0x4E599C73U, 0x68956D0FU, 0x155C31CCU, 0xA47A249FU, 0xE1CE284EU, 0x24D80F0DU}},
		{{0x6457D188U, 0xF347A70DU, 0x8B7A388BU, 0x86EDA86BU, 0x0CCD6013U, 0xB7CDFF06U, 0xD0053FB2U, 0xBEB1B6C7U},
			{0x99240A9FU, 0x0B022387U, 0x776189B2U, 0x1BBB384FU, 0x9066193AU, 0x8695E71EU, 0x06FFAC7EU, 0x2EB50097U}},
		{{0x4A8A3D62U, 0x5A4B46C6U, 0x247743D2U, 0x8469C4D0U, 0x88F7E433U, 0x2BB3A13DU, 0x01BE5849U, 0x62B23A10U},
			{0xA63D1A4CU, 0xE83596B4U, 0x7D183F3EU, 0x454E7FEAU, 0x17AFB01CU, 0x643FCE61U, 0x1C4C3638U, 0x4E65E5E6U}},
		{{0xA35FCD5FU, 0x4065508DU, 0x495CCAEBU, 0x8965DF8CU, 0x12E1A962U, 0x0F2DA850U, 0xC1CF1CC4U, 0xEE471B94U},
			{0x0A08FB75U, 0xCEF19BC8U, 0x81DE3591U, 0x704958F5U, 0x3AEF4F88U, 0x2867F8B2U, 0xEA9F9A5FU, 0x8D749384U}},
		{{0xDC09508BU, 0xB7E830E3U, 0x74317655U, 0xFAF6D2CFU, 0xDF690355U, 0x72606CEBU, 0xD0C3DED6U, 0x48BB92B3U},
			{0x5C7CF892U, 0x65B75484U, 0xD5D5F01FU, 0xF6CD7AC9U, 0x96401D69U, 0xC2C30A59U, 0xED921878U, 0x91268650U}},
		{{0x8D2668D5U, 0xE38B5FF9U, 0x7AD81965U, 0x0715281AU, 0x03C6CE11U, 0x1BC8FC7CU, 0x8B650436U, 0xCBBEE6E2U},
			{0x0CDB9808U, 0x06B00FE8U, 0xFE3ED315U, 0x17D6E066U, 0x4D0B5018U, 0x2E9D38C6U, 0x844DCAEFU, 0xAB8BFD56U}},
		{{0x6ADD8545U, 0xE5DB7717U, 0x72C49B66U, 0x1B71CB66U, 0x68421D77U, 0xD8560739U, 0x83E3AFEAU, 0x03840FE8U},
			{0x1EC69977U, 0xB391DAD5U, 0x307F6726U, 0xAE243FB9U, 0xE8CA160CU, 0xC88AC87BU, 0x4CE355F4U, 0x5174CCEDU}},
		{{0x53A4F566U, 0xD4F9497DU, 0x97B56810U, 0x89734664U, 0x0494A621U, 0xF8E1DA74U, 0x8D011C68U, 0x82546A93U},
			{0xC61AC162U, 0x1F3ACB19U, 0xABAD0D3EU, 0x52F8FA9CU, 0xB4B7EA43U, 0x15356523U, 0xAE608125U, 0x5A16AD61U}},
		{{0xFF81578EU, 0x752067F8U, 0x9045447DU, 0x78622150U, 0x0505AA6FU, 0xC0C22FCFU, 0x6BED1C77U, 0x1030F0A6U},
			{0x1F0BD739U, 0x31F29F15U, 0xE6DEBE85U, 0x2D7989C7U, 0x8E677E98U, 0x5C070E72U, 0x06E81FD5U, 0x0A817BD3U}},
		{{0x7FE02299U, 0x0F816A72U, 0x294F3319U, 0x6335CCC2U, 0x4745C5BEU, 0x3820179FU, 0x922F066EU, 0xE647B782U},
			{0x02CAFB8AU, 0xC22E49DEU, 0xFCC2ECCCU, 0x299BC2FFU, 0x6E0E8282U, 0x9A8FEEA2U, 0xFE893205U, 0xA627278BU}},
		{{0xCBC613E5U, 0xC1E17EB6U, 0x497EA61CU, 0x33131D55U, 0xAF7EDED5U, 0x2F69D39EU, 0xDE6AF11BU, 0x73C2F434U},
			{0xA4A375FAU, 0x4CA52493U, 0xB833C5C2U, 0x5F06787CU, 0x3E6E71CFU, 0x814E091FU, 0x8B746666U, 0x76451F57U}},
		{{0xB533E92AU, 0x6E57C18CU, 0x55BFB5DEU, 0x339BCAFEU, 0x01EEA2EBU, 0xA1EA8B9CU, 0xF4F8A7D6U, 0x6023B4F5U},
			{0x52B54E42U, 0x5E52E4AEU, 0x84BF70DCU, 0x1CBA55E0U, 0x3F06A48DU, 0x22097ABAU, 0xE90BBFA9U, 0x5513633FU}},
		{{0xE1539388U, 0x01C7E082U, 0x759A9C6BU, 0xFD286F30U, 0x176BACFBU, 0x94581041U, 0x3BC3DE53U, 0xE580F07CU},
			{0x884D772FU, 0xDCDB6F75U, 0x40BB9D4FU, 0xD75C3BB8U, 0xDB083011U, 0xDC6C2E4EU, 0xCD9C298DU, 0xE18789A2U}},
		{{0xFFA0CE82U, 0xA5F2101CU, 0x4B343440U, 0x7C6D36E5U, 0x0C74A303U, 0x82528D29U, 0x04D4AB17U, 0xD083A8C2U},
			{0x76001E0DU, 0xCFF14EDDU, 0xC9662EC7U, 0xC911C202U, 0x810278C6U, 0xDB34FB98U, 0x5EE4E368U, 0xA1B4250EU}},
		{{0x95FE1347U, 0x5EE6AB84U, 0x6F24503CU, 0xAB0F6C39U, 0x4486DD6BU, 0x807E3FFBU, 0x8002FEF5U, 0xF00B6C74U},
			{0xA7862999U, 0x48BFF9A6U, 0xBED89E26U, 0x85E5A06CU, 0x3D8419EBU, 0x86D311AFU, 0x34733F16U, 0x24F3AD78U}},
		{{0x5A6FA2AAU, 0x9CACEE5EU, 0x75D4E623U, 0x0686D783U, 0x0B28185DU, 0x3F728D0AU, 0xDD3CED6FU, 0x7912B060U},
			{0xF014CC5AU, 0x8D3129FAU, 0xD7395AEAU, 0x321DDE5CU, 0x6B0FBAABU, 0x9607B2D6U, 0x07AFBD99U, 0xBC5911AEU}},
		{{0x11820D44U, 0x5E205513U, 0x86C4473AU, 0x0C651BCCU, 0x9BD80EEFU, 0x1D230C2BU, 0x07515BE5U, 0x042C4A12U},
			{0xBFE9E284U, 0x42517CA0U, 0x2369827AU, 0xE8F60578U, 0x1638699DU, 0x184F04F0U, 0xF2BC6D05U, 0x174618EDU}},
		{{0x651CF177U, 0x7C3778D5U, 0xD852BD0FU, 0x1B685555U, 0xF3461FF8U, 0x4A03F682U, 0x9B12CA7BU, 0xC1098C35U},
			{0x5D983401U, 0x6A0553D2U, 0x3DC687B0U, 0xE0C0768FU, 0x344B732EU, 0x7C44A33EU, 0x64B70A02U, 0x5EB171C3U}},
		{{0x6C68D687U, 0x5E3E03FCU, 0x1FF052C7U, 0x3E732C3DU, 0x6ED16E7AU, 0xF2D0EFA6U, 0xB65BB746U, 0x63D92B26U},
			{0xDD44867CU, 0xFFCD82BAU, 0xF8C081B8U, 0xA71B4A9EU, 0x736C8785U, 0x6C1676A7U, 0x9D8932D0U, 0xBE2C0616U}},
		{{0xB50939F2U, 0xD1638849U, 0xBA90858EU, 0xFC33692CU, 0x2FA6008EU, 0x2B4A0A91U, 0x97A33940U, 0xC00190C7U},
			{0xD62D3C10U, 0x8AFF14FDU, 0x571989C1U, 0x98C64D09U, 0x00E5FEBAU, 0x8224EA28U, 0xF9A9C5C1U, 0x913CB90CU}},
		{{0x9ECA1C9FU, 0x7BFA1A4BU, 0x8CE5E535U, 0x960BC1DCU, 0x17EEC30AU, 0xE267D9F3U, 0x6C257D38U, 0x06FB89EFU},
			{0xD364A26DU, 0x2328999AU, 0x26EAAB58U, 0x69B794CBU, 0xB85BA596U, 0xAD28AB1FU, 0x56D0AA94U, 0x05DCBFF3U}},
		{{0xA3A1A602U, 0x14D79E80U, 0x22C3D6AFU, 0xFC4F185EU, 0xB7F667C8U, 0x232FA56BU, 0x8F3EEAF8U, 0x49D0BC91U},
			{0x5870E248U, 0xE89151B9U, 0x3D4409ABU, 0x70AB0E70U, 0x800783E8U, 0x22D8E910U, 0xA2AC7762U, 0x9B2C7BB2U}},
		{{0x2BCFFBC4U, 0x53376D28U, 0x06EADB7AU, 0x708817A7U, 0xCD35AE69U, 0x6FF50E05U, 0x74BC7FDEU, 0x63B5FB75U},
			{0xE7FE08C4U, 0x71C9E953U, 0xF583CA18U, 0xB4D8BFD4U, 0x45E81C5CU, 0xDE8D7882U, 0xE0474138U, 0xA5F5E93CU}},
		{{0xF0831932U, 0xD4D75F4BU, 0x77FE8CC9U, 0x5E770AC4U, 0x862E72A2U, 0x52B5E748U, 0x501D35FEU, 0xE9A45482U},
			{0x4A9AB187U, 0x8A93E742U, 0xE88CA017U, 0x5A72506DU, 0x01EB2DEFU, 0xE680DCB2U, 0xBA68209DU, 0xDC5AA4E6U}},
		{{0x293C9F31U, 0x426C160FU, 0xE864D7A7U, 0x8EB56333U, 0x3EBBBA30U, 0xBE116402U, 0x2FD5A302U, 0x64C2BAE3U},
			{0x265AFF7BU, 0x800601E1U, 0x66FD4B14U, 0x52D8A880U, 0x46075A9CU, 0x5ABA20E7U, 0x7E1234C6U, 0xDAA32BF8U}},
		{{0xC4562FC8U, 0x457497A5U, 0xF3E2BFF8U, 0x44FD8E8AU, 0x49C97D59U, 0x19234935U, 0x4036BBE4U, 0xDAE30756U},
			{0x49ADA0EDU, 0xF1377851U, 0x80EF87AAU, 0xC6D362C5U, 0x30A55C6AU, 0xC5974312U, 0x15EC5A37U, 0x568407E5U}},
		{{0x694DB7E0U, 0x80F9BDEFU, 0xB9FCDDC6U, 0xEDCA8787U, 0x03B8DCE1U, 0x51981C34U, 0x70E10BA1U, 0x4274DCF1U},
			{0x6DEF6D1AU, 0xF72743B8U, 0xEBDB1866U, 0xD25B1670U, 0x050C6F58U, 0xC4491E8CU, 0x87FBD7F5U, 0x2BE2B2ABU}},
	},
	{
		{{0xD111F8ECU, 0x3E0E5C9DU, 0xB7C4E760U, 0xBCC33F8DU, 0xBD392A51U, 0x702F9A91U, 0xC132E92DU, 0x7DA4A795U},
			{0x0BB1151BU, 0x1A0B0AE3U, 0x02E32251U, 0x54FEBAC8U, 0x694E9E78U, 0xEA3A5082U, 0xE4FE40B8U, 0xE58FFEC1U}},
		{{0x29C4120BU, 0xFBB8349DU, 0xC0D0D915U, 0x9F94391FU, 0x5410BA51U, 0xC4074FA7U, 0x150A5911U, 0xA66ADBF6U},
			{0x34BFCA38U, 0xC164543CU, 0xB9E1CCFCU, 0xE0F27560U, 0xE820219CU, 0x99DA0F53U, 0xC6B4997AU, 0xE8234498U}},
		{{0x516E19E4U, 0x7B23C513U, 0xC5C4D593U, 0x56E2E847U, 0x5CE71EF6U, 0x9F727D73U, 0xF79A44C5U, 0x5B6304A6U},
			{0x3AB7E433U, 0x6638A736U, 0xFE742F83U, 0x1ADEA470U, 0x5B7FC19FU, 0xE054B854U, 0xBA1D0698U, 0xF935381AU}},
		{{0x918E4936U, 0xB5504F9DU, 0xB2513982U, 0x65035EF6U, 0x6F4D9CB9U, 0x0553A0C2U, 0xBEA85509U, 0x6CB10D56U},
			{0xA242DA11U, 0x48D957B7U, 0x672B7268U, 0x16A4D3DDU, 0x8502A96BU, 0x3D7E637CU, 0x730D463BU, 0x27C7032BU}},
		{{0x5846426FU, 0x55366B7DU, 0x247D441DU, 0xE7D09E89U, 0x736FBF48U, 0x510B404DU, 0xE784BD7DU, 0x7FA003D0U},
			{0x17FD9596U, 0x25F7614FU, 0x35CB98DBU, 0x49E0E0A1U, 0x2E83A76AU, 0x2C65957BU, 0xCDDBE0F8U, 0x5D40DA8DU}},
		{{0xA595939DU, 0x37F68BB4U, 0x28740217U, 0x03556479U, 0x84AD7612U, 0x8E740E7CU, 0x9044695FU, 0xD89BC843U},
			{0x85A9184DU, 0xF7F3DA5DU, 0x9FC0B074U, 0x562563BBU, 0xF88A888EU, 0x06D2E6AAU, 0x161FBE7CU, 0x612D8643U}},
		{{0x54530BB2U, 0x9FB3BBA3U, 0xCB0869EAU, 0xBDE3EF77U, 0x0B431163U, 0x89BC9046U, 0xE4819A35U, 0x4D03D7D2U},
			{0x43B6A782U, 0x33AE4F9EU, 0x9C88A686U, 0x216DB307U, 0x00FFEDD9U, 0x91DD88E0U, 0x12BD4840U, 0xB280DA9FU}},
		{{0x3E538CD7U, 0x458F8691U, 0x8E08AD53U, 0xA7001F6CU, 0xBF5D15FFU, 0x52B8C6E6U, 0x011215DDU, 0x548234A4U},
			{0x3D5B4045U, 0xFF5A9D2DU, 0x4A904190U, 0xB0FFEEB6U, 0x48607F8BU, 0x55A3ACA4U, 0x30A0672AU, 0x8CBD665CU}},
		{{0xF37F5937U, 0xA37F3573U, 0xD1E4FCA5U, 0xEB0F6C7DU, 0xAC8AB0FCU, 0x2965A554U, 0x274676ACU, 0x17FBF56CU},
			{0xACF7D720U, 0x2E2F6BD9U, 0x10224766U, 0x41FC8F88U, 0x85D53BEFU, 0x517A14B3U, 0x7D76A7D1U, 0xDAE327A5U}},
		{{0x1F5F82DCU, 0x515D5C89U, 0x6361079EU, 0x9A7F67D7U, 0x11A35330U, 0xA8DA81E3U, 0x4B18BE1BU, 0xE44990C4U},
			{0xAF103E59U, 0xC7D5ED95U, 0x8DAC9261U, 0xECE8ABA7U, 0x9394B8D3U, 0xBE82B099U, 0x16ADFE83U, 0x6830F09AU}},
		{{0x94D7D9B1U, 0x43C41AC1U, 0xC82E7F17U, 0x5BAFDD82U, 0x5FDA0FCAU, 0xDF0614C1U, 0xA8AE37ADU, 0x74B043A7U},
			{0x9E71734CU, 0x3BA6AFA1U, 0x9C450F2EU, 0x15D5437EU, 0x67E242B1U, 0x4A5883FEU, 0x2C1953C2U, 0x5143BDC2U}},
		{{0x6B53F5F9U, 0xA2A9CE7CU, 0x1B176D99U, 0x64246595U, 0xB95C081BU, 0xB1298D36U, 0x1D9A9EE6U, 0x53505BB8U},
			{0xF2BA70B0U, 0x3F6F9E61U, 0x8AFAD453U, 0xD07E16C9U, 0xE7EB4A6AU, 0x9F1694BBU, 0x3CB0BC8EU, 0xDFEBCED9U}},
		{{0xB1F3390BU, 0xC676D7F2U, 0xA5B61272U, 0x9F7A1B8CU, 0xC2E127A9U, 0x4EBEBFC9U, 0x5DD997BFU, 0x4602500CU},
			{0x4711230FU, 0x7F09771CU, 0x020F09C1U, 0x058EB37CU, 0xFEE5E38BU, 0xAB693D4BU, 0x4653CBC0U, 0x9289EB1FU}},
		{{0x1770F5A7U, 0xA44D2B39U, 0x0E44EB82U, 0xE4D4D791U, 0x3F69712AU, 0x42E69D1EU, 0xAC6A820EU, 0xBF11C4D6U},
			{0x42C4224CU, 0xB5E7F3E5U, 0x449D941CU, 0xD6B4E81CU, 0x5450E878U, 0x5D72BD16U, 0xEE25AC54U, 0x6A61E28AU}},
		{{0xAB952578U, 0x54DA9DC7U, 0x26E84D0BU, 0xB5423DF2U, 0x9B872042U, 0xA8B64EEBU, 0x5990F6DFU, 0xAC205782U},
			{0x21F4C77AU, 0x4FF696EBU, 0xAAB273AFU, 0x1A79C3E4U, 0x9436B3F1U, 0x29BC922EU, 0xD6D9A27AU, 0xFF807EF8U}},
		{{0x33F6746CU, 0xC7F3A8F8U, 0xFEA990CAU, 0x21E46F65U, 0xCADDB0A9U, 0x915FD5C5U, 0x78614555U, 0xBD41F016U},
			{0x426FFB58U, 0x346F4434U, 0x14DBC204U, 0x80559436U, 0x5A969B7FU, 0xF3DD20FEU, 0xE899A39AU, 0x9D59E956U}},
		{{0xD06F56C0U, 0xE4CA688FU, 0xDF027972U, 0xA48AF70DU, 0x5E9A609DU, 0x691F0F04U, 0xEE61270EU, 0xA9DD82CDU},
			{0xA0EF18D3U, 0x8903CA63U, 0x3D6CA3BDU, 0x9FB7EE35U, 0xABF47D03U, 0xA7B4A09CU, 0x1C67DE8EU, 0x4CDADA01U}},
		{{0x74921592U, 0xF9A05637U, 0xB9BB9D31U, 0xB4F1261DU, 0x4E9C5459U, 0x551429B7U, 0x6EA71F53U, 0xBE182E6FU},
			{0xDFC50573U, 0xD3A3B07CU, 0x62BE8D44U, 0x9BA1AFDAU, 0x52AB65D3U, 0x9BCFD2CBU, 0xA9571802U, 0xDF11D547U}},
		{{0xE038A675U, 0xAC127DC1U, 0x8C5C6320U, 0x729DEFF3U, 0xA90D2C53U, 0xB7DF8FD4U, 0x681E7CD3U, 0x9B74B0ECU},
			{0xDAB407E5U, 0x5CB5A623U, 0x76B340C6U, 0xCDBD3615U, 0x7D28392CU, 0xA184415AU, 0xE96F7830U, 0xC184C1D8U}},
		{{0x5E43FC61U, 0xB189B684U, 0xE0D3AB57U, 0xF3282375U, 0xB1181DA8U, 0x4FA34B67U, 0x99EE52B8U, 0x621ED0B2U},
			{0xAD990676U, 0x9B178DE1U, 0x56D54065U, 0xD51DE67BU, 0x7538C201U, 0x2A2C27C4U, 0x38A40F5CU, 0x33856EC8U}},
		{{0x2F7E85C3U, 0x86A9303BU, 0x71988F9BU, 0x5FCE4621U, 0xC138ACB5U, 0x5B935BF6U, 0x25661212U, 0x30EA7D67U},
			{0xE51AB9A2U, 0xEF1EB5F4U, 0xAE067C78U, 0x0587C98AU, 0x77CA9CA6U, 0xB3CE1B3CU, 0x54B5F057U, 0x2A553D4DU}},
		{{0xCD21AB3DU, 0x89E468B2U, 0xC393D392U, 0xE504F022U, 0xA5013AF9U, 0xAB21E1D4U, 0xC2C28ACBU, 0xE3283F78U},
			{0x226BF99FU, 0xF38B35F6U, 0x0E291E69U, 0xE8354274U, 0xB20C162DU, 0x61673A15U, 0xB04FBDBEU, 0xC101DC75U}},
		{{0x0B1894A0U, 0x2C7156E1U, 0xD81C68C0U, 0x92034001U, 0xC8B115B5U, 0xED225D00U, 0x83B907F2U, 0x237F9C22U},
			{0x4470E2C0U, 0x0EA2F32FU, 0x58BE4E95U, 0xB725F7C1U, 0xB1AE5463U, 0x0F1DCAFAU, 0x1BA2FC04U, 0x59ED5187U}},
		{{0x06DDD657U, 0x35DBBEE2U, 0x2FF3A96DU, 0xE7CBDD11U, 0x076BE758U, 0x88381968U, 0x08C91F5DU, 0x2D737E72U},
			{0x86EC3776U, 0x5F83AB62U, 0x945FA7A1U, 0x98AA649DU, 0x72EF0933U, 0xF477EC37U, 0x098C17B1U, 0x66F52B1EU}},
		{{0xC9520711U, 0xD1B0CCDEU, 0x3C8B84BFU, 0x55A9E4EDU, 0xA1FEF314U, 0x9426BD39U, 0x6EB93F2BU, 0x4F5F638EU},
			{0x2BF9341BU, 0xBA2A1ED3U, 0x4D42D5A9U, 0xD63C1321U, 0x316DC7C5U, 0xD2964A89U, 0xCA511851U, 0xD1759606U}},
		{{0xCFE57BBDU, 0xB12EC10EU, 0x35A0C2B5U, 0x82C7B656U, 0x161C67BDU, 0xDDC7D5CDU, 0xAE3A32CCU, 0xE32E8985U},
			{0xD11A5529U, 0x7ABA9444U, 0x2427FA1AU, 0xE964ED02U, 0x24A1770AU, 0x1528392DU, 0x12C72FCDU, 0xA152CE2CU}},
		{{0xF8C51187U, 0xEDF69FEAU, 0x741E4DA7U, 0x05BB67ECU, 0x08114345U, 0x47DF0F32U, 0xBB9792B1U, 0x56FACB07U},
			{0x8F6229E4U, 0xF3E007E9U, 0x526FBA0FU, 0x62D103F4U, 0xB0339D79U, 0x4F33BEF7U, 0xB59BFEC1U, 0x9841357BU}},
		{{0xE28EF5BAU, 0xAE1E0B67U, 0xCB18E169U, 0x2C9A4699U, 0x1E6BBD20U, 0x0ECD0E33U, 0xAF5E81D2U, 0x571B360EU},
			{0x101C1D45U, 0xCD9FEA58U, 0x18880452U, 0x6651788EU, 0x1F8DD446U, 0xA9972635U, 0xE37281D0U, 0x44BED022U}},
		{{0x60DBAC1FU, 0x830E6EEAU, 0xDA06A2F7U, 0x23D8C484U, 0x50CA535BU, 0x896714B0U, 0xEBD97A9BU, 0xDC8D3644U},
			{0xB12177B4U, 0x106EF9FAU, 0x534D5D9CU, 0xF79BF464U, 0xA6AB360BU, 0x2537A349U, 0xA00C744FU, 0xC7C54253U}},
		{{0xFACF69D4U, 0xF0F82DE5U, 0x4775344CU, 0x363B7E76U, 0xB2E36D04U, 0x6894F312U, 0x11D1C9A5U, 0x3C6CB4FEU},
			{0x4008E1F2U, 0x85D9C339U, 0x249F326CU, 0x5E9A85EAU, 0x678C5E06U, 0xDC35C60AU, 0x9F86FBA9U, 0xC08B944FU}},
		{{0x68754AB0U, 0x24D661D1U, 0x6F429A76U, 0x801FCE1DU, 0xA58CE769U, 0xC068A85FU, 0x5D5ECA2BU, 0xEDC35C54U},
			{0xA3F660D1U, 0xEA31276FU, 0xB8FC7167U, 0xA0184EBEU, 0x1D8DB0AEU, 0x0F20F21AU, 0x56C35E12U, 0xD96D095FU}},
		{{0xB733AA5FU, 0x3C2F0BA9U, 0xF05AF235U, 0xDECE47CBU, 0xA2AC82A5U, 0xF8E3F715U, 0x2203F18AU, 0xC97BA641U},
			{0x09C11060U, 0xC3AF5504U, 0x46AF512DU, 0x56EA2C05U, 0xF3F28146U, 0xFAC28DAFU, 0x959EF494U, 0x87FAB43AU}},
	},
	{
		{{0xD4C5105FU, 0x09891641U, 0x6D7FBD65U, 0x1AE80F8EU, 0xBEE6BDB0U, 0x9D67225FU, 0x7FC4D860U, 0x3B433B59U},
			{0x93E85638U, 0x44E66DB6U, 0xE3E9862FU, 0xF7B59252U, 0x665C32ECU, 0xDB785157U, 0xAE362F50U, 0x702FEFD7U}},
		{{0x0FEFB0C3U, 0x3754475DU, 0x46D7C35DU, 0xD48FB56BU, 0x363798A4U, 0xA070B633U, 0x8FDB98E6U, 0xAE89F3D2U},
			{0x6363D14CU, 0x970B89C8U, 0x67ABD27DU, 0x89817521U, 0x44D5A021U, 0x9BF7D474U, 0xCAC72AEEU, 0xB3083BAFU}},
		{{0xBE949A44U, 0x389741DEU, 0x546A4FA5U, 0x638E9388U, 0xA0047BDCU, 0x3FE6419CU, 0xAAEA57CAU, 0x7047F648U},
			{0x41FBAB17U, 0x54E48A90U, 0x576BDBA2U, 0xDA8E0B28U, 0xC72AFDDCU, 0xE807EEBCU, 0xF42577BFU, 0x07D3336DU}},
		{{0xBFE20925U, 0x62A8C244U, 0x8FDCE867U, 0x91C19AC3U, 0xDD387063U, 0x5A96A5D5U, 0x21D324F6U, 0x61D587D4U},
			{0xA37173EAU, 0xE87673A2U, 0x53778B65U, 0x23848008U, 0x05BAB43EU, 0x10F8441EU, 0x4621EFBEU, 0xFA11FE12U}},
		{{0x81685D7BU, 0x047B772EU, 0xBF34A976U, 0x23F27D81U, 0x915F48EFU, 0xC27608E2U, 0xA521D5C3U, 0x3B0B43FAU},
			{0x63CA7284U, 0x7613FB26U, 0x1D4DB837U, 0x7F5729B4U, 0x583B526BU, 0x87B14898U, 0xBBADD3D1U, 0x00B732A6U}},
		{{0x2048E396U, 0x8E02F426U, 0x383D9DE4U, 0x436B50B6U, 0x471E85ADU, 0xF78D3481U, 0xD005C8D6U, 0x8B01EA6AU},
			{0x97015C07U, 0xD3C7AFEEU, 0x4E3BA2AEU, 0x46CDF1A9U, 0x83D3A1D2U, 0x7A42E501U, 0xB541DFF4U, 0xD54B5268U}},
		{{0x4E23E9BCU, 0x3F24CF30U, 0x126E3624U, 0x4387F816U, 0x3B0B6D61U, 0x26A46A03U, 0x8B2D777CU, 0xAF1BC845U},
			{0x527DE79CU, 0x25C401BAU, 0x4261BBB6U, 0x0E1346D4U, 0x287B4BC7U, 0x4B96C44BU, 0x5254562FU, 0x658493C7U}},
		{{0xB8A24A20U, 0x23F949FEU, 0xF52CA53FU, 0x17EBFED1U, 0xBCFB4853U, 0x9B691BBEU, 0x6278A05DU, 0x5617FF6BU},
			{0xE3C99EBDU, 0x241B34C5U, 0x1784156AU, 0xFC64242EU, 0x695D67DFU, 0x4206482FU, 0xEE27C011U, 0xB967CE0EU}},
		{{0x21C80B5DU, 0x65DB3751U, 0xA31ECCA0U, 0x2E7A563CU, 0x5238A07EU, 0xE56FFC4EU, 0x32CED854U, 0x3D6C2966U},
			{0xAF70B885U, 0xE99D7D1AU, 0x2D686459U, 0xAFC3BAD9U, 0x0CC8BA5BU, 0x9C78BF46U, 0x18955AA3U, 0x5A439519U}},
		{{0x5FE4E314U, 0xF8B517A8U, 0xFCB8906FU, 0xE60234D0U, 0xF2061B23U, 0xFFE542ACU, 0x6B4CB59CU, 0x287E191FU},
			{0x09D877D8U, 0x21857DDCU, 0x14678941U, 0x1C23478CU, 0xB6E05EA4U, 0xBBF0C056U, 0xB01594FEU, 0x82DA4B53U}},
		{{0xFADB8608U, 0xF7526791U, 0x7B74CDF6U, 0x049E832DU, 0xC2B90A34U, 0xA43581CCU, 0x9360B10CU, 0x73639EB8U},
			{0xE1E4A71BU, 0x4FBA331FU, 0x8072F919U, 0x6FFD6B93U, 0x65679032U, 0x6E53271CU, 0xF14272CEU, 0x67206444U}},
		{{0xB2335834U, 0xC0F734A3U, 0x90EF6860U, 0x9526205AU, 0x04E2BB0DU, 0xCB8BE717U, 0x02F383FAU, 0x2418871EU},
			{0x4082C157U, 0xD7177681U, 0x29C20073U, 0xCC914AD0U, 0xE587E728U, 0xF186C1EBU, 0x61BCD5FDU, 0x6FDB3C22U}},
		{{0xF2F9F8E9U, 0x30D014A6U, 0x4FEC49D2U, 0x963ECE23U, 0x9605A8D9U, 0x862025C5U, 0x19F8929AU, 0x39874445U},
			{0x12BF476AU, 0x01B6FF65U, 0x09CF7D91U, 0x598A64D8U, 0x93BE56CAU, 0xD7EC7749U, 0xCBB33615U, 0x10899785U}},
		{{0x02EEE3ADU, 0xB8A092FDU, 0x30145270U, 0xA86B3D35U, 0x8512B675U, 0x323D98C6U, 0x62EBB40FU, 0x4B8BC785U},
			{0x413F9CDEU, 0x7D301F54U, 0x2BAB5664U, 0xA5E4FB4FU, 0x1CBFEC23U, 0x1D2B252DU, 0xE177120DU, 0xFCD576BBU}},
		{{0x83731A34U, 0x04427D3EU, 0xED836E8EU, 0x2BB9028EU, 0xB612CA7CU, 0xB36ACFF8U, 0xD3D9C73AU, 0xB88FE5EFU},
			{0xEDEA4EB3U, 0xBE2A6BC6U, 0x488EEC77U, 0x43B93133U, 0xB17106E1U, 0xF41FF566U, 0x654EFA32U, 0x469E9172U}},
		{{0x41C23FA3U, 0xB4480F04U, 0xC1989A2EU, 0xB4712EB0U, 0x93A29CA7U, 0x3CCBBA0FU, 0xD619428CU, 0x6E205C14U},
			{0xB3641686U, 0x90DB7957U, 0x45AC8B4EU, 0x0432691DU, 0xF64E0350U, 0x07A759ACU, 0x9C972517U, 0x0514D89CU}},
		{{0xA8E67FC3U, 0x1701147FU, 0xAB2085BEU, 0x9E2E0B8BU, 0xAC284E57U, 0xD5651824U, 0x74893664U, 0x890D4325U},
			{0xC55E68A3U, 0x8A7C5E6EU, 0x4339C85AU, 0xBF12E90BU, 0xF922B655U, 0x31846B85U, 0x0BF4D700U, 0x9A54CE4DU}},
		{{0xF1A14295U, 0xD7F4E83AU, 0xB285D4F9U, 0x916F955CU, 0x99FFDABAU, 0xE57BB0E0U, 0xEAB0D152U, 0x28A43034U},
			{0xB8A9CEF8U, 0x0A36FFA2U, 0xB9EC051AU, 0x5517407EU, 0xEA68E672U, 0x9C796096U, 0xFB3C77FBU, 0x853DB5FBU}},
		{{0xE864A51AU, 0x21474BA9U, 0x6E8A1B8BU, 0x6C267699U, 0x94120A28U, 0x7C823626U, 0x8383A5DBU, 0xE61E9A48U},
			{0x9F84216DU, 0x7DD75003U, 0xAD43CD85U, 0xAB020D07U, 0xDA12C659U, 0x9437AE48U, 0xE65452ADU, 0x6449C2EBU}},
		{{0x2CF9D7C1U, 0xCC7C4C1CU, 0xEE95E5ABU, 0x1320886AU, 0xBEAE170CU, 0xBB7B9056U, 0xDBC0D662U, 0xC8A5B250U},
			{0xC11D2303U, 0x4ED81432U, 0x1F03769FU, 0x7DA66912U, 0x84539828U, 0x3AC7A5FDU, 0x3BCCDD02U, 0x14DADA94U}},
		{{0x7EF6B0D1U, 0x8B84C321U, 0x7C933F22U, 0x52A9477AU, 0xFD440B82U, 0x5EF6728AU, 0x6CE4BD5EU, 0x5C3BD859U},
			{0xF22C2D3EU, 0x918B80F5U, 0xB7BB6CC5U, 0x368D5040U, 0x2695A11CU, 0xB66142A1U, 0xEB19EA70U, 0x60AC583AU}},
		{{0x0EAB2437U, 0x317CBB98U, 0x5E2654C8U, 0x8CC08C55U, 0xE6D8307FU, 0xFE2D6520U, 0x57428993U, 0xE9F147F3U},
			{0xD2FD6CF1U, 0x5F9C7D14U, 0x2D4FCBB0U, 0xA3ECD064U, 0x8E7341F7U, 0xAD83FEF0U, 0x3A63115CU, 0x643F23A0U}},
		{{0xE65AB743U, 0xD38A78ABU, 0x35EDC89CU, 0xBF7C75B1U, 0x530DF568U, 0x3DD8752EU, 0xE308C682U, 0xF85C4A76U},
			{0xE68ACF37U, 0x4C9955B2U, 0xAB32AF85U, 0xA544DF3DU, 0xA25CF493U, 0x4B8EC3F5U, 0x1A622FEBU, 0x4D8F2764U}},
		{{0xF0DCBC49U, 0x7BB4F7AAU, 0x70BBB45BU, 0x7DE551F9U, 0x9F2CA2E5U, 0xCFD0F3E4U, 0x1F5C76EFU, 0xECE58709U},
			{0x167D79AEU, 0x32920EDDU, 0xFA7D7EC1U, 0x039DF8A2U, 0xBB30AF91U, 0xF46206C0U, 0x22676B59U, 0x1FF5E2F5U}},
		{{0x6EA51D66U, 0x11F4A039U, 0x807D7A26U, 0x506C1445U, 0x755A9B24U, 0x60DA5705U, 0x1F1A319EU, 0x8FC8CC32U},
			{0x9433D67DU, 0x83642D4DU, 0x6A7DD296U, 0x7FA5CB8FU, 0x9B7BDE07U, 0x576591DBU, 0x419716FBU, 0x13173D25U}},
		{{0xD5B340FFU, 0xEA30599DU, 0xB0FE76C5U, 0xFC6B5297U, 0xAB8F5ADCU, 0x1C6968C8U, 0x901C928DU, 0xF723C7F5U},
			{0x9773D402U, 0x4203C321U, 0x1B51DD47U, 0xDF7C6AA3U, 0x552BE23CU, 0x3D49E37AU, 0x0B5A6E87U, 0x57FEBEE8U}},
		{{0x7BD8E739U, 0xC5ECBEE4U, 0xAE63BF75U, 0x79D44994U, 0x38FB8923U, 0x168BD00FU, 0xD0533130U, 0x75D48EE4U},
			{0xDB5CDF33U, 0x554F77AAU, 0x3C696769U, 0x3396E896U, 0xD3FD674EU, 0x2FDDDBF2U, 0x99D0E3E5U, 0xBBB8F6EEU}},
		{{0xCBAE2F70U, 0x51B90651U, 0x93AAA8EBU, 0xEFC4BC05U, 0xDD1DF499U, 0x8ECD8689U, 0x22F367A5U, 0x1AEE99A8U},
			{0xAE8274C5U, 0x95D485B9U, 0x7D30B39CU, 0x6C14D445U, 0xBCC1EF81U, 0xBAFEA90BU, 0xA459A2EDU, 0x7C5F317AU}},
		{{0x4EF44227U, 0x01211075U, 0xDC20F496U, 0xA17BED6EU, 0x819853CDU, 0x0CDFE424U, 0xF71E2CE7U, 0x13793298U},
			{0xDBBE307BU, 0x3C1F3078U, 0x76EE9936U, 0x6DD1C20EU, 0x423CAA20U, 0x23EE4B57U, 0x8EFB840EU, 0x4AC3793BU}},
		{{0xED1F8CA0U, 0x934438EBU, 0x4EBB25A2U, 0x3E546658U, 0xC069896FU, 0xC415AF0EU, 0x9A5AA43DU, 0xC13EDDB0U},
			{0xD49EB8F6U, 0x7A04204FU, 0xD74F1670U, 0xD0D5BDFCU, 0x56FC0558U, 0x3697E286U, 0x01CEBADEU, 0x10207371U}},
		{{0x0647A82BU, 0x5F87E690U, 0x8F40054FU, 0x908E0ED4U, 0x79853803U, 0xA9F633D4U, 0x4A28B252U, 0x8ED13C9AU},
			{0x1F460F64U, 0x3E2EF676U, 0x36D06336U, 0x53930B9BU, 0x8FC4979BU, 0x347073ACU, 0x5ECD5597U, 0x84380E0EU}},
		{{0xC4FE3C39U, 0xE3B22C6BU, 0x6C7BEBDFU, 0xBA4A8153U, 0x25693459U, 0xF23AB6B7U, 0x14922B11U, 0x53BC3770U},
			{0x5AFC60DBU, 0x4645C8ABU, 0x20B9F2A3U, 0xAA022355U, 0xCE0FC507U, 0x52A2954CU, 0x7CE1C2E7U, 0x8C2731BBU}},
	},
	{
		{{0xE48FB889U, 0x6A7091C2U, 0x7B8A9D06U, 0x26882C13U, 0x1B82A0E2U, 0xA2498663U, 0x3518152DU, 0x844ED736U},
			{0xD86E27C7U, 0x282F476FU, 0x04AFEFDCU, 0xA04EDACAU, 0x6119E34DU, 0x8B256EBCU, 0x0787D78BU, 0x56A413E9U}},
		{{0x5A74BE50U, 0x82EE061DU, 0xDEA16FF5U, 0xE41781C4U, 0x99BFC8A2U, 0xE0B0C81EU, 0x0B547E2DU, 0x624F4D69U},
			{0xBDCC9AE4U, 0x3A83545DU, 0x409B1E8EU, 0x2573DBB6U, 0xA6C93539U, 0x482960C4U, 0x5AE18798U, 0xF01059ADU}},
		{{0x4D559D96U, 0x38151E27U, 0xB8DB6C01U, 0x4F18C0D3U, 0x6F9921AFU, 0x49A3AA83U, 0x8C046029U, 0xDBEAB27BU},
			{0x7040BF3BU, 0x242B9EAAU, 0x1614B091U, 0x39C479E5U, 0x0E4BAF5DU, 0x338EDE2BU, 0xF0A53945U, 0x5BB192B7U}},
		{{0x3112795FU, 0x715C9F97U, 0x984E6EE1U, 0xE8244437U, 0xECB66BCDU, 0x55CB4858U, 0xABAFFBEEU, 0x7C136735U},
			{0x5DBEC38EU, 0x54661595U, 0x388AD153U, 0x51C0782CU, 0xC6E0952FU, 0x9BA4C53AU, 0x1B21DFA8U, 0x27E6782AU}},
		{{0xEC5D7F65U, 0x7D89C251U, 0x90394087U, 0x0C8F5616U, 0xF0691AB3U, 0x609E1CFCU, 0xE9B20B21U, 0x2A0300BFU},
			{0xB114FAF4U, 0xBF532FADU, 0x521BF5D1U, 0x328FC0B9U, 0x3BFC36DEU, 0xBD51F93CU, 0x7A4E5F60U, 0xD989050EU}},
		{{0x4ED2DBC2U, 0x682F903DU, 0x7C3B2D83U, 0x0EBA59C8U, 0x9C7E9335U, 0x8E9DC84DU, 0x0EB226D7U, 0x5F9B21B0U},
			{0xAF267BAEU, 0xE33BD394U, 0xBE2E15AEU, 0xAA86CC25U, 0x6A8EC500U, 0x4F0BF67DU, 0xF9630658U, 0x5846AA44U}},
		{{0xE7E0C278U, 0x6786BA38U, 0x588B2E6FU, 0x09BF87CEU, 0x465FEE3AU, 0x723B7022U, 0x64682394U, 0x08B84114U},
			{0x29E64629U, 0x0EB52CE0U, 0xCCA78E43U, 0xADB60E8FU, 0xB654A991U, 0x20DD7062U, 0xC69A6FE5U, 0x4281D428U}},
		{{0xE2C2BF15U, 0xFEB09740U, 0xA9E99704U, 0x627A2205U, 0xC2FBC565U, 0xEC8D73D0U, 0xC20C8DE8U, 0x223EED8FU},
			{0xA8363B49U, 0x1EE32583U, 0xC9C2B0A6U, 0x1A0B6CB9U, 0x90DBC85CU, 0x49F7C3D2U, 0x1EF4C1ACU, 0xA8DFBB97U}},
		{{0xC01E2EE1U, 0x5C257CA3U, 0x27C36961U, 0x1FB43A14U, 0x3472F324U, 0xD594A7CBU, 0x660ABE10U, 0xC15EC024U},
			{0x6B614CEDU, 0xB176D449U, 0x62DBB885U, 0x0B04734DU, 0x36DDB587U, 0x2CB753C6U, 0x14CD340CU, 0x9A1C80E6U}},
		{{0x65C7C2ABU, 0xAFB34D4CU, 0xE2C5EA84U, 0x1D4610E7U, 0x973C4AB5U, 0x893F6D1BU, 0x945BA5C4U, 0xA3CDD7E9U},
			{0x064417EEU, 0x60514983U, 0xAD6BDF2BU, 0x1459B23CU, 0x5CF726C3U, 0x23B2C341U, 0x32D6354AU, 0x3A829635U}},
		{{0xC06FE7CDU, 0xE9F65696U, 0x9AFD3A15U, 0x51063057U, 0x185360EDU, 0x3DCDACA6U, 0xC1853D2FU, 0x2741703DU},
			{0x1A33F1A0U, 0xBD8AD84AU, 0xC35CB07CU, 0x5F6C698CU, 0x6561E6B9U, 0x212BD119U, 0x617B4FD7U, 0xF149CD7EU}},
		{{0xAB192C18U, 0x294F901FU, 0x7030164FU, 0xEC5FCBFEU, 0xE2246BA6U, 0xE2E2FCB7U, 0x221A1A0CU, 0x1E7C88B3U},
			{0xC92D88C5U, 0x72C7DD93U, 0x1106FB59U, 0x41C2148EU, 0xA0F60F14U, 0x547DD4F5U, 0x63960F31U, 0xED9B52B2U}},
		{{0x30E82BF8U, 0x1CE3C9C5U, 0x0DBB772AU, 0x4D662542U, 0xD9C17214U, 0x19E25A60U, 0x7722FA55U, 0x13BCF84CU},
			{0xF89EF7A7U, 0x228ACA0EU, 0xFD3ED455U, 0x03D64E2FU, 0xDDE6C904U, 0xF1C390F5U, 0x7678E18AU, 0x731452A6U}},
		{{0xB0A5B358U, 0x6C8349EBU, 0x9E7E2ED6U, 0xB154C5C2U, 0xEDA462DBU, 0xCAD5ECCFU, 0x2DE66B69U, 0xF2D6DBE4U},
			{0x8665E5B2U, 0x426AEDF3U, 0x7B7F5723U, 0x488A8513U, 0x8BCBB386U, 0x15CC43B3U, 0xD791D879U, 0x27AD0AF3U}},
		{{0xA0632CBAU, 0x3C006E61U, 0x45B35CCDU, 0x920D9248U, 0x7C5C7F65U, 0x4B3379FBU, 0xB05E050BU, 0x526CDF10U},
			{0xD21BF1AEU, 0x3188E936U, 0x624BBD2FU, 0xB3E07B39U, 0x1367A541U, 0x7B9BFCF3U, 0x8A367927U, 0x039F8EC8U}},
		{{0x846E364FU, 0xC16C236EU, 0xDEA50CA0U, 0x7F33527CU, 0x0926B86DU, 0xC4810775U, 0x0598E70CU, 0x6C2A3609U},
			{0xF024E924U, 0xA6755E52U, 0x9DB4AFCAU, 0xE0FA07A4U, 0x66831790U, 0x15C3CE7DU, 0xA6CBB0D6U, 0x5B4EF350U}},
		{{0x436982F4U, 0x348504E0U, 0xD8E3EC79U, 0xC94905EEU, 0x3509179EU, 0xB92CFDCBU, 0xF9E6D914U, 0x245266D0U},
			{0xAD316955U, 0x8BAA50D0U, 0xCA227F60U, 0x77235C79U, 0x51E5F9D8U, 0xF2C927C9U, 0xE679940FU, 0xEBBF8C30U}},
		{{0xB6205969U, 0x2C4AAFC4U, 0xF6C7854FU, 0x42563F02U, 0x1D983B48U, 0x016ACED5U, 0x99949755U, 0xFEB356D8U},
			{0xD1A39BD7U, 0x8C2A2C81U, 0xE6934AE9U, 0x8F44340FU, 0x447904DAU, 0x148CF91CU, 0x0F51A926U, 0x7340185FU}},
		{{0xCEAC6990U, 0xE4E95F66U, 0xBE6C16CEU, 0x17DC1D16U, 0x45AD0CBEU, 0x2967A055U, 0x716F7EB6U, 0xDD0E2F97U},
			{0x2DC33B91U, 0x338B7FF3U, 0x2FE976DEU, 0xDCF6AEF5U, 0x43193F6EU, 0xF51CF71CU, 0xE8C077E3U, 0x15E444C4U}},
		{{0x7409AB46U, 0x2F8F00FBU, 0x80E289B2U, 0x057E78E6U, 0xA888E5D1U, 0x03E5022CU, 0x9DEDE4E2U, 0x3C87111AU},
			{0x7809460BU, 0x5B9B0E1CU, 0x71C9ABC7U, 0xE751C852U, 0xC7CC1DC9U, 0x8B944E28U, 0x1D3CFA08U, 0x4F201FFAU}},
		{{0x0F9FC049U, 0x6078FE2DU, 0x40F6D11AU, 0xD99D9750U, 0x0854C0B7U, 0x87AE9A97U, 0x9302FB79U, 0xF4CEB09CU},
			{0x2C32A83FU, 0x502F0168U, 0xB1685024U, 0x1E352771U, 0x66792B19U, 0x970DF6F2U, 0x9C8D87FDU, 0xF507D0BBU}},
		{{0x3E6721CEU, 0x02FC905CU, 0xD0B3674CU, 0xD52D70DAU, 0x18810DA4U, 0x5DC2E5CAU, 0x5C69DD99U, 0xA984B273U},
			{0x84DE5CA4U, 0x63B92527U, 0xC852DEC4U, 0x2F1C9872U, 0xC2E3DE09U, 0x18B03593U, 0x9813DC2FU, 0x19D70B01U}},
		{{0x426338B2U, 0x154E40CEU, 0x96AA88C9U, 0x7B2CB000U, 0xAD51F925U, 0xD5C901FCU, 0x7ED0EE10U, 0x5ABD216CU},
			{0xF87DE164U, 0x73C3D557U, 0xE139516DU, 0x693AD1DCU, 0x3EBD547AU, 0xB4767B3AU, 0x20F4A982U, 0xB8B3C24CU}},
		{{0xA6DC1D29U, 0x42806B2DU, 0xF871E144U, 0xD3030009U, 0xAAF49276U, 0xA1FEB333U, 0xC70BC04BU, 0xB5583B9EU},
			{0x95695F20U, 0x1DB0BE78U, 0x89D012B5U, 0xFC841811U, 0x05F61643U, 0x6409F272U, 0xD5883128U, 0x40D34174U}},
		{{0x08567C7BU, 0x64FBA0CDU, 0xA2CBFB54U, 0xC9EA590DU, 0x136D0D73U, 0x666F7716U, 0x38F2A30DU, 0x2CA09648U},
			{0x0F4E0CA9U, 0x7FA54524U, 0xC1BEB84BU, 0xEF3301A8U, 0xBC62B92AU, 0x45CB930EU, 0x9BB6CBEAU, 0x964AC705U}},
		{{0x67419833U, 0xD79196F5U, 0x863B7B08U, 0x6059E252U, 0x1C56700CU, 0x84DA1817U, 0xB28D3EC4U, 0x5758EE56U},
			{0x013B0EA6U, 0x7DA2771DU, 0x54C5E9B9U, 0xFDDF524BU, 0x24305D80U, 0x7DF4FAF8U, 0x3A97763FU, 0x58F5C1BFU}},
		{{0x81F5261FU, 0xEAF671CCU, 0xBCFE83EFU, 0x7D083506U, 0x3188536EU, 0x94CDC50BU, 0x24DD3ECDU, 0x410B2C41U},
			{0x0205520CU, 0x57CB99CCU, 0x5F06446DU, 0x23F3A268U, 0x49A04B17U, 0xB2B27E43U, 0x81785A12U, 0xABB266F3U}},
		{{0x7C696042U, 0xA5AF37F1U, 0x4A2538DEU, 0xD4CBA22CU, 0x9EA42600U, 0x211CB995U, 0x7B069889U, 0xCD105F41U},
			{0xDDB81E74U, 0xB1E1CF19U, 0x5157B8CAU, 0x472F2D89U, 0xEE9DB885U, 0x086FB008U, 0x0F26D131U, 0x365CD570U}},
		{{0x66B7FE5AU, 0x00A7BA5DU, 0x05FD5D56U, 0x818674ACU, 0x04145A57U, 0x688FB03CU, 0x97D5832CU, 0x76C16588U},
			{0x1245ABA7U, 0xA0F0DCD8U, 0x1847F6E9U, 0xDD077CAAU, 0x0D34ADD0U, 0xF9035314U, 0x48B73DEDU, 0x22E37C11U}},
		{{0xA2BE7053U, 0x284B02BBU, 0x7AB9A6D6U, 0xDCBBF7C6U, 0x20F7A530U, 0x4425559CU, 0x188767C8U, 0x961F2DFAU},
			{0x70DC80C4U, 0xE2FD9435U, 0xF0784120U, 0x104D6B63U, 0x53567122U, 0x7F592BC1U, 0xF688AD77U, 0xF6BC1246U}},
		{{0xB70AB006U, 0xFDFE436BU, 0x18991A1DU, 0x57E7D119U, 0x34D4C0B0U, 0x3A544228U, 0x32B58404U, 0x26091DD4U},
			{0x272AF899U, 0x8B116DFCU, 0x34118777U, 0x51F8DC87U, 0xDFA7F0BCU, 0xC0F0A340U, 0x56AD97DDU, 0x22C5A5F6U}},
		{{0x0F15DDE9U, 0x05214C05U, 0x0D5F2B82U, 0xA47A76A8U, 0x62E82B62U, 0xBB254D30U, 0x3EC955EEU, 0x11A05FE0U},
			{0x9D529B36U, 0x7EAFF46EU, 0x8F9E3DF6U, 0x55AB1301U, 0x99317698U, 0xC463E371U, 0xCCDA47ADU, 0xFD251438U}},
	},
	{
		{{0xDBFB894EU, 0xE13122F3U, 0xCE274B18U, 0xBE9B79F6U, 0xCA58AADFU, 0x85A49DE5U, 0x11487351U, 0x24957758U},
			{0xBB939099U, 0x111DEF61U, 0x26D13694U, 0x1D6A974AU, 0xD3FC253BU, 0x4474B4CEU, 0x4C5DB15EU, 0x3A1485E6U}},
		{{0x1ED66F18U, 0xEBDE86ECU, 0xD61FCE43U, 0x225D906BU, 0xE8BED74DU, 0x5CAB07D6U, 0x27855AB7U, 0x16E4617FU},
			{0xB2FBC3DDU, 0x6568AADDU, 0x8AEDDF5BU, 0xEDB5484FU, 0x6DCF2FADU, 0x878F20E8U, 0x615F5699U, 0x3516497CU}},
		{{0x707BACE2U, 0x5158AEE8U, 0xF86D1C56U, 0x458D14C6U, 0xC1B9BEE2U, 0x15EBF15CU, 0x0F379CC0U, 0xA015DF66U},
			{0x202ED161U, 0xB24CEBA3U, 0x204B3DF0U, 0x4558F687U, 0xBE264C04U, 0x890E8EEDU, 0x90DE8BB7U, 0xB5B78710U}},
		{{0xFA181E69U, 0xEF0A3FECU, 0x30D69A98U, 0x9EA02F81U, 0x66EAB95DU, 0xB2E9CF8EU, 0x24720021U, 0x520F2BEBU},
			{0x1DF84361U, 0x621C540AU, 0x71FA6D5DU, 0x12037721U, 0x0FF5F6FFU, 0x6E3C7B51U, 0xABB2BEF3U, 0x817A069BU}},
		{{0x9781CD05U, 0x7E2B2F11U, 0x7EAFA12BU, 0x77A8C2E2U, 0xA381385EU, 0x78FDD03CU, 0x15AB85ADU, 0xAB3B54BBU},
			{0xCF1C8AD4U, 0x48BE55AAU, 0x528ABC81U, 0x57A60C58U, 0x4A6893B3U, 0xF8AFB5FEU, 0x9A66CCCBU, 0xBDD179CFU}},
		{{0x656C09B1U, 0xF14F7D77U, 0x29A9DF00U, 0x4B40AC95U, 0x14103833U, 0xE9DC4882U, 0x421745C7U, 0x4C633233U},
			{0x75C20369U, 0xD22FCCC5U, 0x89370C36U, 0x47F242A5U, 0x4EDAECCFU, 0x1E8C16AEU, 0x4FCF78C4U, 0xAD8EABB0U}},
		{{0x9EC598CFU, 0x3DE605BAU, 0x4D3029AEU, 0x1933D3AEU, 0x9B140516U, 0x6BF2FABDU, 0x59A7D01CU, 0x712DFC55U},
			{0xD2576366U, 0xFF3EAAE0U, 0x48701CF8U, 0x36E407F9U, 0xB41F4BD4U, 0xEDE21D89U, 0x666EEFA9U, 0xC5292F5CU}},
		{{0xB294CDA6U, 0x83572FB6U, 0xB9039F34U, 0x6CE9BF75U, 0x095CBB21U, 0x20E012F0U, 0xD063F0DAU, 0xA0AECC1BU},
			{0xF02909E5U, 0x57C21C3AU, 0x48CE9CDCU, 0xC7D59ECFU, 0x8AE336F8U, 0x2732B844U, 0x3F4F85F4U, 0x056E3723U}},
		{{0xEF78A852U, 0xF2B75D21U, 0xDD31A900U, 0xBA38CD34U, 0x58FFE18AU, 0x72B3A686U, 0xBFD95745U, 0x7464190CU},
			{0x77ED6E81U, 0x406E5321U, 0xDE535EABU, 0x1AF0975BU, 0x60C54C82U, 0x66BA22C7U, 0xB00A2FE0U, 0x88E3B1CEU}},
		{{0xF0337B15U, 0x55B7F977U, 0x0E94973AU, 0x3BC872A3U, 0x770DEEA0U, 0x624AD983U, 0x13A5EFDBU, 0xCAAB3364U},
			{0x7A0D4247U, 0x391DD002U, 0xF312AED5U, 0x39590D5DU, 0x351365ACU, 0x532802C9U, 0x78A2E22AU, 0xDD2E8245U}},
		{{0x2EBEE687U, 0x98C6A6A5U, 0x56C1C731U, 0xCDF65BFAU, 0x72DEF210U, 0x48E81327U, 0x8083B5A5U, 0x4EA11941U},
			{0xFFEBB525U, 0x3FDCEA4FU, 0xFB50BF72U, 0x55AAEA19U, 0x2A85B40CU, 0x5FBEDC0AU, 0xBF44F29FU, 0x0D6FD954U}},
		{{0x89E800CAU, 0x8A10B531U, 0x145208FDU, 0x50FE0C17U, 0xB714BA37U, 0x9E43C0D3U, 0x34189ACCU, 0x427D200EU},
			{0xE616E2C0U, 0x05DEE24FU, 0xEE1854C1U, 0x9C25F4C8U, 0x8F342A73U, 0x4D3222A5U, 0xA027C952U, 0x0807804FU}},
		{{0x2E8F326FU, 0xBABFB7F8U, 0x5625A519U, 0xED9CAC22U, 0x0EDAE0A9U, 0xF1109C1AU, 0x58521259U, 0x45F80A98U},
			{0x5AB71F44U, 0x37A44B07U, 0x4A21161BU, 0x21699EB6U, 0x56FE67EEU, 0xB523FDDFU, 0x20B9F72EU, 0x9F5C3A21U}},
		{{0x50D26E73U, 0xBA414A33U, 0x75F72688U, 0x45694494U, 0xB1550F82U, 0xD482A6E3U, 0x43166D7EU, 0xDE7FF7E6U},
			{0x9C94222AU, 0xAD97C668U, 0x72FA9840U, 0x90A5922DU, 0x32E6AA5FU, 0x371886BDU, 0x7F5E0D44U, 0xF1BD4F67U}},
		{{0xFBA319C5U, 0x058EB276U, 0x7F7FA54AU, 0xD33A9112U, 0x932A2DABU, 0xF060C1B4U, 0x79C7D9BFU, 0xCE3A224EU},
			{0x0BA92823U, 0x6FB0388CU, 0x69787881U, 0x8D31738AU, 0x03CD00B7U, 0x2D86EB02U, 0x2B69911BU, 0x4E6E4451U}},
		{{0x4F0D56F3U, 0xC222653AU, 0xCA28B805U, 0x961E4047U, 0x4A73434BU, 0x2C03F8B0U, 0xAB712A19U, 0x4C966787U},
			{0x864FEE42U, 0xCC196C42U, 0x5B0ECE5CU, 0xC1BE93DAU, 0xC131C159U, 0xA87D9F22U, 0xDCE45655U, 0x2BB6D593U}},
		{{0x4C894042U, 0xEC955AA9U, 0xF22F92EDU, 0x9D32179AU, 0xFA286508U, 0x5E020FF0U, 0x239B1CDAU, 0x4649863AU},
			{0x11F1458FU, 0xA5711B92U, 0xDE9B356DU, 0x7DD493ECU, 0x80AD8194U, 0xE4F90682U, 0xFE309773U, 0x81867AC1U}},
		{{0xAD78913CU, 0xE9DD96FEU, 0x86EEB7B5U, 0x325EB514U, 0xA193B08EU, 0x85747461U, 0x5ADC3541U, 0xF5840DAAU},
			{0xDB369FDAU, 0xC11D0C44U, 0xAD759205U, 0x3AB14AD9U, 0x038FAFA2U, 0x533F9A3DU, 0xFDE3F704U, 0xFDDF6553U}},
		{{0x2915A4C6U, 0xBEAF6990U, 0x37C31C11U, 0xD5DBC04DU, 0x281FCBC8U, 0xA7A72ABAU, 0x3F4AE621U, 0xA178F28DU},
			{0x9B8D0895U, 0x23DDDC76U, 0x93B206D0U, 0x88AED784U, 0x0E32A4E4U, 0x6EE61A09U, 0x262F03F4U, 0x1D482E3BU}},
		{{0xB809B7CEU, 0x22C49EC9U, 0xE2C72C2CU, 0x8A41486BU, 0xFEA0BF36U, 0x813B9420U, 0xA66DAC69U, 0xB3D36EE9U},
			{0x328CC987U, 0x6FDDC08AU, 0x3A326461U, 0x0A3BCD2CU, 0xD810DBBAU, 0x7103C49DU, 0x4B78A4C4U, 0xF9D81A28U}},
		{{0xDD180B99U, 0xFED1D8E8U, 0xD33A3949U, 0xDD8C333FU, 0xB9B72399U, 0xCDDFDF2DU, 0x8C785526U, 0xADA6E53EU},
			{0xC1BDE1B4U, 0xA0DFBFEDU, 0x2477D54EU, 0xC7436B81U, 0xE73245E8U, 0x27ECD641U, 0xE097CC90U, 0xB68F77F1U}},
		{{0x2B625C66U, 0x1AA3621EU, 0xA9EAE50FU, 0x48DC5DAEU, 0x7D52A158U, 0x5706ACC2U, 0xA991A25CU, 0x0A1551A2U},
			{0x970DB4EBU, 0x4654046AU, 0x35FF7E4BU, 0x2BBE4D4DU, 0x18A62FB9U, 0xD9856AE7U, 0x10A7D38EU, 0xACA01604U}},
		{{0x7A76DB89U, 0x6BA0BBEBU, 0x13352AF5U, 0x1BC5C3BDU, 0xDD44BD08U, 0xB83EFE18U, 0x8DD82449U, 0x4BD6BEA7U},
			{0xDAF9D90EU, 0x4A973124U, 0x3332D84CU, 0x6EDB890CU, 0x9BBB841BU, 0xC23E39E6U, 0x07AE3E6DU, 0xC38F3545U}},
		{{0xE4D55941U, 0x3DE865ADU, 0x30384087U, 0xDEDAFA5EU, 0x4EF18B9BU, 0x6F414ABBU, 0xFAEE5268U, 0x9EE9EA42U},
			{0x37A55A4AU, 0x260FAA16U, 0x015F93B9U, 0xEB19A514U, 0x9E9C3598U, 0x51D7EBD2U, 0x1932178EU, 0x523FC56DU}},
		{{0x9ACFF1C8U, 0x9FC6DD08U, 0x9B25B60DU, 0x20E8AC2FU, 0xD4D95C4CU, 0x222930ABU, 0x15B2507BU, 0x1E77B04EU},
			{0x2D9CDAEBU, 0x7A6B8819U, 0x3197793AU, 0xF15D4D18U, 0x1CED4B92U, 0x38702A72U, 0x37EA9334U, 0x948D92B0U}},
		{{0x16F39D1DU, 0xDAF89FA3U, 0x60286F51U, 0x4FDFECA3U, 0x79053AD2U, 0x1D37C5E9U, 0x1958FA40U, 0xDEA70E30U},
			{0x251FE67CU, 0xD00A96EFU, 0xEB94BE74U, 0xD8C01A2BU, 0x0CFD4B75U, 0x0E2A4438U, 0x85BDF22CU, 0x871BC7B2U}},
		{{0x3C8622F4U, 0x9FFF9428U, 0x8C468440U, 0xB76E328FU, 0x31AE0F70U, 0x60C5E197U, 0xEC729CBCU, 0xF86DD177U},
			{0xF3F497A2U, 0x21813530U, 0x5920FEE7U, 0x7F3192C1U, 0xE1C51EE5U, 0x0E0F0C31U, 0x22F4DD10U, 0xF336CD73U}},
		{{0xB98FE684U, 0x501D070CU, 0x124A1458U, 0xD60FBE9AU, 0x92BC6B3FU, 0xA45761C8U, 0xFE6F27CBU, 0xF5384858U},
			{0xB59E763BU, 0x4B0271F7U, 0x5B5A8E5EU, 0x3D4606A9U, 0x05A48292U, 0x1EDA5D9BU, 0xE6FEC446U, 0xDA7731D0U}},
		{{0xEB18FF20U, 0x277B5177U, 0x28F06D62U, 0x48002E98U, 0x0E506D8DU, 0xECE8D6C3U, 0xCD9FF963U, 0x5CDE0A58U},
			{0x4E3BAA0EU, 0x3B97CDB7U, 0x631238F9U, 0x50560C0BU, 0xCF79793DU, 0xE1C31B35U, 0x355E2178U, 0x95D12F14U}},
		{{0x2F428837U, 0x3D21B9C3U, 0x0F3402BFU, 0x73C96B1EU, 0x424FF39EU, 0x6CF7BFC9U, 0xF6D0D696U, 0xCA2DA459U},
			{0x3BB8154EU, 0x3CF1D69DU, 0x5430EDB4U, 0xC2429B16U, 0x15D0D375U, 0xD3C6478AU, 0x7DE4376BU, 0x5E33067FU}},
		{{0xCB205962U, 0x378C305DU, 0x3D04599AU, 0xE1409F9DU, 0x8057C1B2U, 0x84ECBA27U, 0xA2BD80B1U, 0xCC92ACE7U},
			{0x4CC4C760U, 0xCB5311DBU, 0x466D8EFEU, 0x18F0CE63U, 0x087249EEU, 0x0DA0EB1BU, 0x56FBDEF3U, 0x7D47E3FBU}},
		{{0x90D45871U, 0xA3E33693U, 0x06166D8DU, 0xE9764040U, 0x89A90403U, 0xB5C33682U, 0x72F1D637U, 0x4BD17983U},
			{0xD5D2C53AU, 0xA616679EU, 0xFDCF3B87U, 0x5EC4BCD8U, 0xB66A694EU, 0xAE6D7613U, 0xE3FC27E5U, 0x7460FC76U}},
	},
	{
		{{0xC63C4962U, 0x80531FE1U, 0x981FDB25U, 0x50541E89U, 0xFD4C2B6BU, 0xDC1291A1U, 0xA6DF4FCAU, 0xC0693A17U},
			{0x0117F203U, 0xB2C4604EU, 0x0A99B8D0U, 0x245F1963U, 0xC6212C44U, 0xAEDC20AAU, 0x520F52A8U, 0xB1ED4E56U}},
		{{0x700A1ACDU, 0xB5560FB6U, 0xFD999681U, 0xE823FD73U, 0x6CB4E1BAU, 0xDA915D1FU, 0x6EBE00A3U, 0x0D030118U},
			{0x89FCA8CDU, 0x744FB0C9U, 0xF9DA0E0BU, 0x970D01DBU, 0x7931D76FU, 0x0AD8C564U, 0xF659B96AU, 0xB15737BFU}},
		{{0x6BDF22DAU, 0x18F37A9CU, 0x90DC82DFU, 0xEFBC432FU, 0x5D703651U, 0xC52CEF8EU, 0xD99881A5U, 0x82887BA0U},
			{0xB920EC1DU, 0x7CEC9DDAU, 0xEC3E8D3BU, 0xD0D7E8C3U, 0x4CA88747U, 0x445BC395U, 0x9FD53535U, 0xEDEAA2E0U}},
		{{0xCE53C2D0U, 0xA12B384EU, 0x5E4606DAU, 0x779D897DU, 0x73EC12B0U, 0xA53E47B0U, 0x5756F1ADU, 0x462DBBBAU},
			{0xCAFE37B6U, 0x69FE09F2U, 0xECCE2E17U, 0x273D1EBFU, 0x3CF607FDU, 0x8AC1D538U, 0x12E10C25U, 0x8035F7FFU}},
		{{0x296C9005U, 0xB7D4CC0FU, 0x7B0AEBDBU, 0x4B9094FAU, 0xC00EC8D4U, 0xE1BF10F1U, 0xD667C101U, 0xD807B1C4U},
			{0xBE713383U, 0xA9412CDFU, 0x81142BA1U, 0x435E063EU, 0xAF0A6BDCU, 0x984C15ECU, 0x92A3DAB9U, 0x592C2460U}},
		{{0x2093C22AU, 0xCA442D5AU, 0xD5703AEDU, 0xEBD0BD31U, 0x653287B6U, 0x308F2AFDU, 0x0D1BC8BAU, 0x9BB88BACU},
			{0x75C1E3B2U, 0xFBAF8538U, 0xCA11447CU, 0xBD2AC950U, 0xEA5C4C8DU, 0x286D816CU, 0x28DC3208U, 0xDC3AA800U}},
		{{0x16E23E9DU, 0x93656900U, 0xA7CC41E1U, 0xCB220C6BU, 0x69D6245CU, 0xB36B20C3U, 0xB62E9A6AU, 0x2D63C348U},
			{0xCDC0BCB5U, 0xA3473E19U, 0x8F601B98U, 0x70F18B3FU, 0xCDE346E4U, 0x8AD7A2C7U, 0xBD3AAA64U, 0xAE9F6EC3U}},
		{{0x7E6C5520U, 0x854D34C7U, 0xDCB9EA58U, 0xC27DF9EFU, 0xD686666DU, 0x405F2369U, 0x0417AA85U, 0x29D1FEBFU},
			{0x93470AFEU, 0x9846819EU, 0xE2A27F9EU, 0x3E6A9669U, 0xE31E6504U, 0x24D008A2U, 0x9CB7680AU, 0xDBA7CECFU}},
		{{0x3274C7E1U, 0x03022350U, 0x4C4B6C26U, 0x61EE8C93U, 0x199389CEU, 0x3C4397E3U, 0x488757CEU, 0xE0082600U},
			{0x06B4DAFBU, 0xAAC3A2DFU, 0xDDFF5B6AU, 0x45AF0700U, 0x8C1D9FA0U, 0x0A597424U, 0x391FC68BU, 0x1640087DU}},
		{{0xD07FA53DU, 0x26A43E41U, 0x74E35BC5U, 0x3154A78AU, 0xE0DA2F8CU, 0x7B768924U, 0x23613F9AU, 0xBA964A2BU},
			{0xBA1D16C4U, 0x5A548D35U, 0xFB54D057U, 0x2E1BFED1U, 0xBC640205U, 0xFF992136U, 0x8156DF29U, 0xF39CB914U}},
		{{0x4E5548BDU, 0xF4873FCFU, 0x03CE57F0U, 0x8725DA3FU, 0xCA953258U, 0xD82F5C95U, 0x7CF0747EU, 0xAC647F12U},
			{0x2D570BD5U, 0xFF2038B0U, 0xA13AE03FU, 0xB0C2A767U, 0xE9932D16U, 0xEBAA27CDU, 0x1234E901U, 0xA686E3FCU}},
		{{0x99B444ADU, 0xC913E646U, 0xC40504C5U, 0xDDFCE99DU, 0xD42E53DBU, 0x58482A99U, 0xD1AFF537U, 0x9AAF2C25U},
			{0x2664CF67U, 0xEE90F796U, 0xF1393E2BU, 0x74AB5C99U, 0xE6225BB0U, 0xFAD0FAEAU, 0x2D63DD6CU, 0xC355648CU}},
		{{0x63261ECCU, 0x9F80435EU, 0x4337D6C9U, 0x6302A62EU, 0xCA4958A0U, 0x91916A49U, 0x3149D5D3U, 0x55495899U},
			{0x9F91DE3CU, 0x378D020BU, 0x4DD25170U, 0x47B839A3U, 0x38B7F258U, 0x28258541U, 0x437E7DECU, 0xEA5B14F7U}},
		{{0x1D91CF9DU, 0xE4E31D27U, 0xB377B20AU, 0xCB35D4FDU, 0x055E1327U, 0x74DE1E45U, 0x28703E75U, 0x3298E31BU},
			{0xDE013339U, 0x55087237U, 0x23D101C6U, 0x32CBF301U, 0xE8AAB0DCU, 0xC70DBA22U, 0x3D155BB9U, 0x4A52623DU}},
		{{0xB0018F44U, 0x74F08736U, 0xB446D0F5U, 0xF4A03417U, 0xA40CA6B2U, 0x66A4AA2FU, 0xBADB60EDU, 0x215679F0U},
			{0x323E4EEFU, 0x3871195AU, 0x20952B16U, 0x8F0940C3U, 0x879D5F7DU, 0xFE8DAC62U, 0xC1A6E875U, 0x649CB623U}},
		{{0x338D6E43U, 0xECAFF541U, 0x4541D5CCU, 0x56F7DD73U, 0x96BC88CAU, 0xB5D426DEU, 0x9ED3A2C3U, 0x48D94F6BU},
			{0x2EF8279CU, 0x6354A3BBU, 0x0B1867F2U, 0xD575465BU, 0x95225151U, 0xEF99B0FFU, 0xF94500D8U, 0xF3E19D88U}},
		{{0x133EC108U, 0xA26A9087U, 0x2712BDC0U, 0x5DC5699FU, 0xD14224A9U, 0x96903F4DU, 0x29E47B80U, 0x3DA59924U},
			{0xF9DBBA5AU, 0xB717712FU, 0x756391C9U, 0x9E52004BU, 0xCC9D219CU, 0xE669A11DU, 0xD1D6C07DU, 0x3B6E6B84U}},
		{{0xC85DCF57U, 0xDBF435ACU, 0xC88F5415U, 0x61745658U, 0x17C55807U, 0x26367E9AU, 0xCA90C56FU, 0x22D077A5U},
			{0xA2E04E76U, 0xFBF72258U, 0x6E06E405U, 0xBA965D3EU, 0xE3E6F954U, 0x5724D06FU, 0x81251A74U, 0x3E47D475U}},
		{{0x676FEADBU, 0x5FEEC06AU, 0x9D69F322U, 0xFC449BC5U, 0x7CDA8895U, 0x1D8D7B5EU, 0x1A3314A7U, 0x5ED54DC1U},
			{0x6DE889C0U, 0x1A11D2AEU, 0x4CED2BD9U, 0xB2A97972U, 0x306A5EF6U, 0x6ECF6989U, 0x8CC8A249U, 0x1611D57BU}},
		{{0xE0FB82F7U, 0xB8BA0151U, 0xD5668AC2U, 0x0D160726U, 0x14D711B0U, 0x622BA258U, 0x7F3FE2F2U, 0x6ADDF557U},
			{0x6B9C9435U, 0x2B831E1CU, 0xB73826BDU, 0xCE3A060AU, 0x1C240F89U, 0x93FA11C1U, 0x956E303AU, 0x4F9CC8D8U}},
		{{0x007CBF87U, 0x2D9942BAU, 0xDF3FC926U, 0x4E62BCE6U, 0xE4560AFFU, 0xE7EEE5B0U, 0x7CB009B7U, 0xE51963BBU},
			{0xE29B37DDU, 0xAA5118CEU, 0x47263903U, 0x5CD84A47U, 0x620055D8U, 0x3050CAA6U, 0x6C4B1E3DU, 0x7EF576A7U}},
		{{0x641F82C9U, 0x4B9331F6U, 0xDFFEC756U, 0xD97C7C54U, 0x1A9158ABU, 0xF5EE6D1FU, 0x85C3DA7FU, 0x054493A3U},
			{0xEB7D96DFU, 0xA57A05F5U, 0xE4473A39U, 0xA3AFD447U, 0x88E16D55U, 0x42A4D9C4U, 0xF5F876AEU, 0x83E144F5U}},
		{{0xE6008FF1U, 0x9026A4DDU, 0x1C8CD96CU, 0x49E995ADU, 0x503E589BU, 0x80722E73U, 0x84C2BC26U, 0x05BCBCE1U},
			{0xD4682C2CU, 0x255F9ABBU, 0xF084D456U, 0xC42BCFC2U, 0x641C0767U, 0xA0EAE9B0U, 0x864C9A2DU, 0x1B45632DU}},
		{{0xE32DD620U, 0x92A83268U, 0x627849A2U, 0x913EC99FU, 0x2C378882U, 0xEDD8FDFAU, 0xEE6F8CFEU, 0xAF96F33EU},
			{0xDC3FA8A5U, 0xC06737E5U, 0xB0B03A1DU, 0x236BB531U, 0x89F037B0U, 0x33E59F29U, 0xD9A12A53U, 0x13F9B5A7U}},
		{{0x6AE024E0U, 0xCF25793BU, 0x84B5C4B0U, 0x1B6607B4U, 0x3F1624C8U, 0x9579FA90U, 0x68BD57E8U, 0x37FB65BEU},
			{0xFC39C203U, 0xD693A55EU, 0xC87252E9U, 0x4E267AC4U, 0x9F899413U, 0xB8D78BB0U, 0x0B3B8508U, 0xE4C01407U}},
		{{0x59029AA6U, 0x50D8AE95U, 0x5A4DB2EDU, 0xD74E292CU, 0x848F373DU, 0x0B9C3355U, 0xAC45AB38U, 0xEC018DB6U},
			{0x69CC53A8U, 0x1F446902U, 0x1A879864U, 0x8C4B628DU, 0x4B13475EU, 0x1C743D28U, 0x73DE19F6U, 0xBF4A9338U}},
		{{0xBC3F3553U, 0x662906E5U, 0x31459684U, 0xDE38D535U, 0x34F7280DU, 0x8F46A8C6U, 0x3D24198EU, 0xAAF91B87U},
			{0x5F9B117EU, 0xECD5EE11U, 0x50AE8DDAU, 0xCE00FFBEU, 0x7710A9AEU, 0x263A3D4EU, 0xF26BA74FU, 0x0FF3F721U}},
		{{0xF0CEFA69U, 0x4A8A4F47U, 0xA4546866U, 0xDC8E4CBAU, 0x23F603C1U, 0x359BA69BU, 0x187B7AC5U, 0xDAB4D601U},
			{0xC1EBC8D9U, 0xA6CA4337U, 0x52B4074BU, 0x9FA65854U, 0x902FB733U, 0x1A4B4F81U, 0xA525DEAAU, 0xD2BB5D7AU}},
		{{0xE6B3577AU, 0xCC287AC2U, 0xF612003BU, 0xD7528CA7U, 0x2C1400B8U, 0x8AFDB6F1U, 0x46A2DD8DU, 0x103A2ED3U},
			{0x2EE21339U, 0xC8F8C54DU, 0x355A2D20U, 0x8F011B92U, 0x1346F2ACU, 0x81C6FC9FU, 0x05A6D24BU, 0xDB6042F0U}},
		{{0xF81F9567U, 0xEB2E92D5U, 0x4D698470U, 0x54CB95EAU, 0xE04C81EBU, 0x5F2ACB28U, 0xF8CEEC64U, 0x1C1EBFC4U},
			{0x06E07423U, 0x8F799FACU, 0x37FA0C85U, 0x72225F99U, 0x34F4DB44U, 0xB0CD8616U, 0x752C9091U, 0x5EC36159U}},
		{{0x0DA4F996U, 0xFC90E363U, 0xAA6D6FE4U, 0x8CECA49DU, 0xBDFC619BU, 0x1084AFFDU, 0xC1140B04U, 0x2029F672U},
			{0x136F3E5EU, 0x606EC25FU, 0x02224C4AU, 0x6D24149BU, 0xCFDFCF4CU, 0xABB0F142U, 0xFAB1A0EDU, 0xE40D0419U}},
		{{0x51EFB310U, 0x0D0DF6CEU, 0x958DF5BEU, 0xCB5B2EB4U, 0x36158E59U, 0xD6459E29U, 0x1466E336U, 0x82AAE2B9U},
			{0x411AA636U, 0xFB658A39U, 0xD4C0A933U, 0x7152ECC5U, 0x49F026B7U, 0xF10C758AU, 0xCB09311FU, 0xF4837F97U}},
	},
	{
		{{0x626332D5U, 0x994F523AU, 0x5561BB44U, 0x7BC38833U, 0x3D845EA2U, 0x005ED4B0U, 0xC2A1F08AU, 0xD39D3EE1U},
			{0xE7676B0DU, 0x6561FDD3U, 0xFB706017U, 0x620E35FFU, 0xF264F9A8U, 0x36CE424FU, 0xDA2681F7U, 0xC4C3419FU}},
		{{0x9BB81648U, 0x00F83176U, 0x653120D0U, 0xD69EB485U, 0x4CCABC62U, 0xD17D75F4U, 0xB749FCB1U, 0x34A07F82U},
			{0xBBFB5554U, 0x2C3AF787U, 0x62E283F8U, 0xB06ED4D0U, 0xA19213A0U, 0x5722889FU, 0xDCF3C7B4U, 0x162B085EU}},
		{{0xEB300F7AU, 0x36D90DDAU, 0xEDB5E801U, 0x9DCF7DFCU, 0x74D5244CU, 0x645CB268U, 0x348E3AA2U, 0xA127EE79U},
			{0x575F1DBBU, 0x488ACC53U, 0x80E6161EU, 0x95037E85U, 0x292650D0U, 0x57E59283U, 0x14938216U, 0xABE67D99U}},
		{{0x7189E71FU, 0x32670D2FU, 0x5ECF91E7U, 0xC6438748U, 0xDB757A21U, 0x15758E57U, 0x290A9CE5U, 0x427D09F8U},
			{0x38384A7AU, 0x846A308FU, 0xB0732B99U, 0xAAC3ACB4U, 0x17845819U, 0x9E941009U, 0xA7CE5E03U, 0x95CBA111U}},
		{{0x7378058EU, 0xEB81AA37U, 0x04411154U, 0x41C746A1U, 0xFB828AC7U, 0xA10C73BCU, 0x9D972B29U, 0x6439BE91U},
			{0x43A2FBADU, 0x4BF3B4B0U, 0x82B5E840U, 0x39E6DADFU, 0x6397BD4CU, 0x4F716408U, 0x7F1EECCBU, 0x0F7DE568U}},
		{{0xF37EC3C3U, 0xDB332A73U, 0xDD59EBA0U, 0xC65259BDU, 0xDB4D3257U, 0x2291709CU, 0xBD389390U, 0x9A793B25U},
			{0xE43756F0U, 0xF39FE34BU, 0x9AFB56C9U, 0x2F76BDCEU, 0x61208B27U, 0x9F37867AU, 0x089972C3U, 0xEA1D4307U}},
		{{0x8A429F4FU, 0xD0A74487U, 0xDB516609U, 0x0649712BU, 0xE769B5DFU, 0xB826BA57U, 0x1FC7AAF2U, 0x82335DF2U},
			{0x5C93D995U, 0x2389F067U, 0x68677BE6U, 0x59AC367AU, 0x21D9951BU, 0xA77985FFU, 0x85011CCEU, 0x038956FBU}},
		{{0xAACA5E9BU, 0x97B7851AU, 0x56713B97U, 0x518AA521U, 0x150A61F6U, 0x3357E8C7U, 0xEC2C2B69U, 0x7842E7E2U},
			{0x6868A548U, 0x8DFFAF65U, 0xE068FC81U, 0xD963BD82U, 0x65917733U, 0x64DA5C8BU, 0x7B247328U, 0x927090FFU}},
		{{0x2F6D0D97U, 0xD6FFDB94U, 0x443B9373U, 0x05C3EE41U, 0xFFD36DB6U, 0xB2E541EBU, 0xCE1DCC3EU, 0xB7415A96U},
			{0x163AA2F6U, 0xE383682EU, 0x2F3AF218U, 0x46FEBDD4U, 0xBAFDBADBU, 0x90A0507EU, 0xCE52E21AU, 0x4CA8AB4DU}},
		{{0x1B7CFB73U, 0xA3F0832EU, 0x3EC354C9U, 0x7A8AFE52U, 0x378EADCAU, 0xAE91C97EU, 0xAC3B32BBU, 0x7449C599U},
			{0x0B1C4655U, 0xA619C371U, 0xF79DA87EU, 0x692E4C6AU, 0xDE38D96AU, 0xFF3F5D86U, 0x1C08C0ECU, 0xC5320F42U}},
		{{0x8FEC5DECU, 0x92A6F2BCU, 0x84D6786CU, 0xA71383FFU, 0xDBFFA084U, 0x87588C06U, 0x6857E715U, 0x0D85F5CAU},
			{0xB6C774D4U, 0xE87311B3U, 0x4C3521A8U, 0x672357C8U, 0x5B29FE0FU, 0xE5FE7461U, 0x5B7158CDU, 0x02BC5110U}},
		{{0xA105FC8EU, 0x37A01E48U, 0x289BA48CU, 0x769D754AU, 0xD51C2180U, 0xC08C6FE1U, 0xB7BD1387U, 0xB032DD33U},
			{0x020B0AA6U, 0x953826DBU, 0x0664C73CU, 0x05137E80U, 0x660CF95DU, 0xC66302C4U, 0xB2CEF28AU, 0x99004E11U}},
		{{0x4F973536U, 0x824F5B28U, 0xD35B04EAU, 0xB43E299EU, 0x4DA03089U, 0xC72C88F7U, 0x45A2E42CU, 0x8269D57AU},
			{0x6607B38EU, 0x7C1E63FCU, 0x29390B0CU, 0xE89E2AAFU, 0x1BEE2869U, 0xC7C740DAU, 0xAF3FB974U, 0x8556F6FCU}},
		{{0xA4B6BED1U, 0x1A0A3995U, 0x97095C54U, 0x2DAB5795U, 0x2AA73CE9U, 0x06C6A1FFU, 0x4DE438A7U, 0xADD0A54BU},
			{0xFCA906CDU, 0x160B6B1AU, 0x29DE10DDU, 0x25FC6016U, 0xD3633DA3U, 0x348E9C99U, 0x158A4D5AU, 0x1FE3F746U}},
		{{0x8BE85C1DU, 0xC253EDC8U, 0x3CA09CB6U, 0xDD3D0E48U, 0x9AE3055AU, 0xB997F687U, 0x07431DBFU, 0x0C929AD0U},
			{0x84D2DB42U, 0xCEF16215U, 0x078828CDU, 0xB50DF3EFU, 0x6DBD4B66U, 0x4589DA9DU, 0xD99C2B04U, 0xBC4FD2E3U}},
		{{0xD298C241U, 0x214BC9A7U, 0x56807CFDU, 0xE3B697BAU, 0x4564EADBU, 0xEF1C7802U, 0xB48149C5U, 0xDDE8CDCFU},
			{0x5A4D2604U, 0x946BF0A7U, 0x6C1538AFU, 0x27154D7FU, 0xDE5B1FCCU, 0x95CC9230U, 0x66864F82U, 0xD88519E9U}},
		{{0x6286BC77U, 0x9901A9EAU, 0x69794DB0U, 0x249DFE58U, 0xBBA6CD21U, 0xC4370BBDU, 0x21FC5E6BU, 0x718F8131U},
			{0x22C78B61U, 0x9CDFEDBDU, 0xD9D43D71U, 0x4B313EECU, 0x19BB1B22U, 0x4144031FU, 0x07A33158U, 0x974973ABU}},
		{{0x06366526U, 0x67AADEF4U, 0xAE535D96U, 0xD7D53019U, 0xE3A2EBC6U, 0x72FADBA7U, 0x75269D16U, 0xA32313A5U},
			{0xB50D922EU, 0x97FA1A69U, 0xCA202B45U, 0x4C6E28CFU, 0x68100B91U, 0xB7BD1100U, 0x73C96A5DU, 0xE02E418DU}},
		{{0x8E805546U, 0xFA9E6EDCU, 0x82639840U, 0xC0E0E678U, 0xB7BE643DU, 0x430858A4U, 0x18CF5F1EU, 0x1D422414U},
			{0x9FEF49AFU, 0x05990C62U, 0x5EC31D32U, 0x4846E0CDU, 0xBABF85D4U, 0x46DB47A8U, 0xAA759F7FU, 0x5F66C9F1U}},
		{{0x96EA6CA1U, 0x1013E4F7U, 0x1F792871U, 0x567CDC2AU, 0x5C658D45U, 0xADB72870U, 0xCE600E98U, 0xF7C1FF4AU},
			{0x4B6CAD39U, 0xA1BA8657U, 0xBA20B428U, 0x3D58D634U, 0xA2E6FDFBU, 0xC0011CDEU, 0x7B18960DU, 0xA832367AU}},
		{{0x50521507U, 0xB7392C8FU, 0xE5EF2E9DU, 0xACB3914BU, 0xEA446F85U, 0x9A70B178U, 0x98D8C3EEU, 0xBD4C43A6U},
			{0x844C0177U, 0xA973BBE5U, 0x062AB3EAU, 0x299B274DU, 0x856ADAAFU, 0x26BA0E7CU, 0x765CB2B8U, 0x139B9194U}},
		{{0xBD9FD387U, 0x7B21E79BU, 0x241C0C71U, 0xB48F769AU, 0x8B725A93U, 0x83E36836U, 0x1F5B96E1U, 0xEF9D4F55U},
			{0x2A9910A0U, 0xC67139A4U, 0x4E095E76U, 0x71E1C8A2U, 0x2719B8F2U, 0x212F7F36U, 0x00FA1217U, 0x9F75EB3FU}},
		{{0x343E6DB6U, 0x4E118E6EU, 0x25B6993FU, 0x98BD5559U, 0xB32EFA85U, 0xB40DD514U, 0x7A24E3A1U, 0x7E305580U},
			{0x775857C3U, 0x7DCC9550U, 0x2C9BC1B0U, 0x05631112U, 0x02A5DCE9U, 0x6EAE85D5U, 0x34EB4172U, 0xE53FC9AAU}},
		{{0x0E4938F7U, 0x47618C9FU, 0xDC83719EU, 0x58D47D69U, 0xF41A64CCU, 0xD74C1A23U, 0xB5829F66U, 0x5D28E068U},
			{0x210466F6U, 0xD8D37529U, 0xC6A64EF8U, 0x2AF1152FU, 0x19CE6A7AU, 0x55D4485CU, 0xF648E2D7U, 0x6D0BD2F5U}},
		{{0xF89DB521U, 0xF02D6AB1U, 0x650CEDC6U, 0x46F41AFCU, 0x1C8ADF71U, 0xB1BC7396U, 0x7EBDB1B9U, 0xD2147FCBU},
			{0xC1080363U, 0xCAAF0EF7U, 0xD95C09C5U, 0xF90B1AF3U, 0xF6F44883U, 0x7AAFBFD4U, 0x8A8D9B6DU, 0x9B64E087U}},
		{{0xBD356AE5U, 0xEEFC9CE8U, 0x2ED25AF4U, 0x3D98A6C0U, 0x6319D884U, 0x3173F564U, 0xCA6C4F16U, 0x2B2DED64U},
			{0xCE6DFCD0U, 0xE27B19E5U, 0xA0D887CAU, 0xA369BC5FU, 0x07463710U, 0x59C2606EU, 0xF3C6E74EU, 0x15C1112AU}},
		{{0x7E7A13A0U, 0x4ABA3000U, 0x89BBAAF5U, 0xF483BB47U, 0x9FFD273FU, 0x7C0D50F6U, 0xF4A4D692U, 0x7E63C191U},
			{0x42F2D6E6U, 0x8BDA3440U, 0x938B72C6U, 0xD7CFCDC2U, 0x6F6E54E9U, 0xD28AFBD2U, 0xC28B3FE5U, 0xD40423B6U}},
		{{0xF416448DU, 0x1ECC032AU, 0xEC76D971U, 0x4A7E8C10U, 0xB90B6EAEU, 0x854F9805U, 0x4BED0594U, 0xFD0B1532U},
			{0xD98B5CA3U, 0x89F71848U, 0xF039B3EFU, 0xD01FE5FCU, 0x627BDA2EU, 0x4481332EU, 0xA5073E41U, 0xE67CECD7U}},
		{{0x8A9CECCDU, 0x2E691646U, 0x053A6DA1U, 0xCC92EBCCU, 0x783A6B64U, 0xA80076B8U, 0xA5992FA2U, 0x42D0E8A0U},
			{0x7C56EC30U, 0xD9C71C53U, 0x6B6BC769U, 0x388B6A96U, 0xD3BF9FC7U, 0xA0C233ABU, 0x2FC45369U, 0xD0F55BD0U}},
		{{0x3292EEF9U, 0xA72C3302U, 0x9F8C1116U, 0x0F5A4036U, 0x3E96A791U, 0x429E6EF0U, 0xF3843939U, 0x60EB6181U},
			{0x902518D3U, 0xAF49F083U, 0xB9E8390BU, 0xFE65C013U, 0xEC4D34A4U, 0x7AB97CB3U, 0x8B4F853DU, 0x72427A08U}},
		{{0x2EFEAD1FU, 0x3883FC68U, 0xFC4D8D68U, 0xDD7224A1U, 0x9F1DAFDDU, 0x5C4E844CU, 0x15119B7DU, 0x7F40D18EU},
			{0xB7C268EBU, 0x79C6D14CU, 0xC2AE89E1U, 0x65B4C855U, 0x7CB0D9A2U, 0x3508BB99U, 0x2EC64A5BU, 0xBC2C635BU}},
		{{0x7CB1282CU, 0xB828DD1AU, 0xBE46973AU, 0xA08D7626U, 0xE708D6B2U, 0x6BAF8D40U, 0x4DAEB3F3U, 0x72571FA1U},
			{0xF22DFD98U, 0x85B1732FU, 0x0087108DU, 0x87AB01A7U, 0x5988207AU, 0xAAAAFEA8U, 0x69F00755U, 0xCCC832F8U}},
	},
	{
		{{0xCA8D9D1AU, 0x488F1185U, 0xD987DED2U, 0xADF2C77DU, 0x60C46124U, 0x5F3039F0U, 0x71E095F4U, 0xE5D70B75U},
			{0x6260E70FU, 0x82D58650U, 0xF750D105U, 0x39D75EA7U, 0x75BAC364U, 0x8CF3D0B1U, 0x21D01329U, 0xF3A7564DU}},
		{{0x3FCD3EFCU, 0xB24AA43EU, 0xB8088E9AU, 0xDD26C034U, 0xBD3D46EAU, 0xA5EF4DC9U, 0x8A4C6A6FU, 0xA2F99D58U},
			{0x2F1DA46CU, 0xDDABD355U, 0x1AFACDD1U, 0x72C3F8CEU, 0x92D40578U, 0xD90C4EEEU, 0xCA623B94U, 0xD28BB41FU}},
		{{0xE7417CE1U, 0x242792D2U, 0x970EE7F5U, 0xFF42BC71U, 0x5C67A41EU, 0x1FF4DC6DU, 0x20882A58U, 0x77709B7BU},
			{0xBE217F2CU, 0x3554731DU, 0x5BB72177U, 0x2AF2A8CDU, 0x591DD059U, 0x58EEE769U, 0x4BBA6477U, 0xBB2930C9U}},
		{{0xF176F2C0U, 0x1E6ADDDAU, 0xE2572658U, 0x01CA4604U, 0x85342FFBU, 0x0A404DEDU, 0x441838D6U, 0x8CF60F96U},
			{0xC9071C4AU, 0x9BBC691CU, 0x34442803U, 0xFD588744U, 0x809C0D81U, 0x97101C85U, 0x8C456F7FU, 0xA7FB754CU}},
		{{0xAF71013FU, 0x6AF7A1D5U, 0x0BEDC946U, 0xE68216E5U, 0xD27370A0U, 0xF4CBA30BU, 0x870421CCU, 0x7981AFBFU},
			{0x9449F0E1U, 0x02496A67U, 0x0A47EDAEU, 0x86CFC4BEU, 0xB1FECA22U, 0x3073C936U, 0x03F8F8FBU, 0xF5694612U}},
		{{0x5BDE48F8U, 0xBCADD671U, 0x2189BC7DU, 0xC9703873U, 0xC709EE8AU, 0x5D45299EU, 0x845AAFF8U, 0xD1287EE2U},
			{0xDB1DBF1FU, 0x7D1F8874U, 0x990C88D6U, 0xEA46588BU, 0x84368313U, 0x60BA649AU, 0x60D543AEU, 0xD5FDCBCEU}},
		{{0x9890272DU, 0xCF3DE995U, 0x3E713A10U, 0x75F3432AU, 0xE28227B8U, 0x5E13479FU, 0xFEFACDC8U, 0xB8561EA9U},
			{0x8332AAFDU, 0xA6A297A0U, 0x73809B62U, 0x9B0D8BB5U, 0x0C63036FU, 0xD2FA1CFDU, 0xBD64BDA8U, 0x7A16EB55U}},
		{{0x2AC13E27U, 0xF7E48E8AU, 0x4EB1A9F5U, 0x4494F6DFU, 0x981F0A62U, 0xEDBF84EBU, 0x536438F0U, 0x49BADC32U},
			{0x004F7571U, 0x50BEA541U, 0xDF1C94EEU, 0xBAC67D10U, 0xB727BC31U, 0x253D73A1U, 0x30686E28U, 0xB3D01CF2U}},
		{{0x306A5A3BU, 0xA40BC039U, 0x96783A1BU, 0x4E0A41FDU, 0x0253CDD4U, 0xA1E8D39AU, 0xC7388638U, 0x6480BE26U},
			{0x2285F382U, 0xEE365E1DU, 0xEC0B5C36U, 0x188D8D8FU, 0x1F0F4D82U, 0x34EF1A48U, 0xA487D29AU, 0x1A8F43E1U}},
		{{0x3902DDA5U, 0xA5A8147CU, 0xFE6973B4U, 0x35D2F706U, 0xC257457EU, 0x5AC2EFCFU, 0x8700611BU, 0x933F48D4U},
			{0x4912BEB2U, 0xC365AF88U, 0x162EDF94U, 0x7F5A4DE6U, 0x0C32F34BU, 0xC646BA7CU, 0xB2091074U, 0x632C6AF3U}},
		{{0x9BB26F5FU, 0x10F6A333U, 0x044D85B6U, 0x1E85DB8EU, 0x94197E54U, 0xC3697A08U, 0xA7CB4EA8U, 0x65E18CC0U},
			{0xA471FE6EU, 0xA38C4F50U, 0x2F13439CU, 0xF031747AU, 0xC007318BU, 0x53C4A6BAU, 0x1DECCB3DU, 0xA8DA3EE5U}},
		{{0x5CA48F3FU, 0xBFC01ADFU, 0xE22A9B84U, 0x64352F06U, 0xC1099E4AU, 0xCEE54DA1U, 0xFA1B89C0U, 0xBBDA54E8U},
			{0x6F6E55FBU, 0x166A3DF5U, 0x20176F88U, 0x1CA44A24U, 0xDFB7B5FFU, 0x936AFD88U, 0x8611D4A0U, 0xE34C2437U}},
		{{0x3E554892U, 0x5F24416DU, 0x430E2A45U, 0x8413B53DU, 0x9032A2A0U, 0x99C56AEEU, 0xEEC367B1U, 0x09432BF6U},
			{0xDAF0ECC1U, 0x552850C6U, 0x5BC92048U, 0x49EBCE55U, 0x54811307U, 0xDFB66BA6U, 0x6F298597U, 0x1B84F797U}},
		{{0x70F8D5A4U, 0xD5B5D9EBU, 0xD7BBB228U, 0x375ADDE7U, 0x0C1C0B32U, 0x31E88B86U, 0x173EDBAAU, 0xD1F568C4U},
			{0x5459DF02U, 0x1592FC83U, 0x0FCD9A7EU, 0x2BEAC0FBU, 0x1B473B0AU, 0xB0A6FDB8U, 0x0FE8FC48U, 0xE3224C6FU}},
		{{0x5777E189U, 0xA1A5C845U, 0x456F2829U, 0xCC10BEE0U, 0xDA762BD5U, 0x8AD95C56U, 0xE9D91DA8U, 0x152E2214U},
			{0x7CB23C74U, 0x975B0E72U, 0xA90C66DFU, 0xFD5D7670U, 0x225FFC53U, 0xB5B5B8ADU, 0xFADED2AEU, 0xAB6DFF73U}},
		{{0x6D3549CFU, 0xD433E50FU, 0xFACD665EU, 0x6F33696FU, 0xCE11FCB4U, 0x695BFDACU, 0xAF7C9860U, 0x810EE252U},
			{0x7159BB2CU, 0x65450FE1U, 0x758B357BU, 0xF7DFBEBEU, 0xD69FEA72U, 0x2B057E74U, 0x92731745U, 0xD485717AU}},
		{{0xB376D7EFU, 0x8D6D7684U, 0x48D5DA81U, 0x3DBF02ACU, 0x1B89139CU, 0xFAA5385AU, 0x6820A7CEU, 0x504DCB85U},
			{0xE61A9D26U, 0xC0982145U, 0xAC5D25AFU, 0xF35C6C32U, 0x4E27B3C2U, 0xAA3BA267U, 0x9F6C7AC5U, 0x2E69A3A0U}},
		{{0xF30B86CFU, 0x906A5C1DU, 0x4D07EF87U, 0xB16F66FCU, 0xD4012261U, 0xA975C2DAU, 0x0FBC361EU, 0xE69748E6U},
			{0x2D9900C7U, 0xA2A03536U, 0x7CF6AA0FU, 0x1F2A3CE1U, 0xA1E33887U, 0x80D5443AU, 0x5B47B4DFU, 0x6ADA248BU}},
		{{0xDD3C721AU, 0x1F9FBB08U, 0x46B2229CU, 0x93A1F97EU, 0x31BA7EFBU, 0x4EE5AD46U, 0xF3AE10A3U, 0x6BAA5CA5U},
			{0x746C0204U, 0x7D81FC3EU, 0x2B9A060BU, 0x9ECC90F0U, 0x7B688CA7U, 0xDB58162FU, 0xF554C1DFU, 0xF4772A99U}},
		{{0x67DC4BF4U, 0xEDB24E7CU, 0xAA4A827BU, 0xCBE4C743U, 0xFACFF82BU, 0x229472F5U, 0xCF2C4A9BU, 0x2CEFBB82U},
			{0x59367FF1U, 0x386E06B8U, 0xA3CDAF75U, 0x32245978U, 0x9807B198U, 0x2DBDD36DU, 0xB78511E9U, 0x437495E7U}},
		{{0x77DDA727U, 0x34166E65U, 0x3EAAAACFU, 0xB6A4A3C1U, 0x9D2C6240U, 0x9CCD49C2U, 0xA42BA163U, 0xC2E17F3DU},
			{0x7C6D2133U, 0x91F9EB5CU, 0xE6A97606U, 0x85CEBD2AU, 0x65B00DFBU, 0x806E35BDU, 0xB9392A82U, 0x9E9F7906U}},
		{{0x4D0D2B3BU, 0x239F298AU, 0xDBB207F1U, 0x6C9760CFU, 0xD4F92EEBU, 0xC8BF203FU, 0x7EA74E9BU, 0x290B2AE4U},
			{0x163A7D3DU, 0x1FA69337U, 0x87EFA414U, 0xD0295EE8U, 0xF9F8273FU, 0x54844037U, 0xE341AB58U, 0x3046A862U}},
		{{0x38C6FC0BU, 0xFB9FE953U, 0xAC9579C8U, 0xE494E2E8U, 0x69D7CA8BU, 0xC424EF6FU, 0x4FB857ECU, 0x630E5215U},
			{0x42E2DF48U, 0xF013112BU, 0x625204BFU, 0xEFADC908U, 0x1163B0CEU, 0x7D8BB16CU, 0xB7146889U, 0xDF5147E3U}},
		{{0xA2BF75ADU, 0x5B378B05U, 0x25DA1E92U, 0xFE374B66U, 0xFF766712U, 0xFB4C8100U, 0xCBC84660U, 0xBC606380U},
			{0x6C10ADE4U, 0x27266EC9U, 0x7AB6ECA7U, 0xB46AC2B5U, 0xBB28E800U, 0xFDC673D7U, 0x23C0E3FEU, 0xB5645F20U}},
		{{0x30562B28U, 0x76430E5FU, 0x36EAD806U, 0x6741CA10U, 0x937F1293U, 0xBF6E5031U, 0x22299AF0U, 0x32C3096EU},
			{0x2145DD22U, 0xD6A3B161U, 0xD75E8633U, 0x6C499057U, 0x39F1C2BDU, 0xA5997651U, 0x6B1FABF5U, 0x3B900C6DU}},
		{{0xE7437C63U, 0xE8296816U, 0x76164C11U, 0x38A7C0D2U, 0x9C29840EU, 0x1F1095F9U, 0x57B9093FU, 0x1912B9B3U},
			{0xF839C817U, 0xFE09D504U, 0xBDDD4BDDU, 0x1F64FB3BU, 0xDB044534U, 0xEF42ED5BU, 0xB4E821C8U, 0x1560DD95U}},
		{{0x70B9524EU, 0xDE39AF50U, 0xADD1C868U, 0x796995E9U, 0x329A4CC9U, 0x9790B828U, 0x5B62AE64U, 0x1EEBA2B7U},
			{0xD7E3C12FU, 0x617BD3F6U, 0xDF336421U, 0xDB7E711CU, 0xD78907CFU, 0x7DFC0937U, 0x841A8BD5U, 0x88937A99U}},
		{{0x5D0A41BAU, 0xB9A5C24DU, 0xB66C861EU, 0x58298402U, 0x4C71CDFCU, 0x99DB6EF8U, 0xE6364CD9U, 0x69E2AAAAU},
			{0x648BC7D9U, 0x4BF09418U, 0xEB713C6FU, 0x5AB3C2E9U, 0x0C6E52C2U, 0x6A75D558U, 0xE5600012U, 0x462B8A24U}},
		{{0xFE82858EU, 0xCA544208U, 0x3EC21A90U, 0x51A3AF4AU, 0xC27614D4U, 0x63C19E63U, 0xE005E739U, 0x32088C95U},
			{0x944A8D00U, 0x7C5025F9U, 0x9A942A48U, 0x8F98E37DU, 0x535C45E7U, 0x53357351U, 0x44891F80U, 0xFE41F11CU}},
		{{0x5DA2C390U, 0x20F9E19CU, 0xDABD6D8AU, 0x1F69E62FU, 0x27AABB65U, 0x1B9EB62EU, 0x3DBBBBB5U, 0xBB098337U},
			{0x823632DAU, 0x7D3B88C9U, 0xA759E7DEU, 0x6C8974F3U, 0x3D52876CU, 0x49657808U, 0xE045CDD8U, 0xB56473BCU}},
		{{0x0053E747U, 0x5DE57E0EU, 0x561C8A53U, 0x04D36592U, 0xCA7F2EADU, 0x6A06D378U, 0x14F859DBU, 0xB3615620U},
			{0x1419F8F8U, 0x4EB19117U, 0x603B9932U, 0xD0BF4525U, 0x9DA15898U, 0xFC3E45CDU, 0x79328D14U, 0x5EE89F71U}},
		{{0xEE36860CU, 0x896C42E8U, 0x4113C22DU, 0xDAF04DFDU, 0x44104213U, 0x1ADBB7B7U, 0x1FD394EAU, 0xE5FD5FA1U},
			{0x1A4E0551U, 0x68235D94U, 0x18D10151U, 0x6772CFBEU, 0x09984523U, 0x276071E3U, 0x5A56BA98U, 0xE4E879DEU}},
	},
	{
		{{0x285B9491U, 0xAAAFAFB0U, 0x1E4C705EU, 0x01A0BE88U, 0x2AD9CAABU, 0xFF1D4F5DU, 0xC37A233FU, 0x6E349A4AU},
			{0x4A1C6A16U, 0xCF1C1246U, 0x29383260U, 0xD99E6B66U, 0x5F6D5471U, 0xEA3D4366U, 0xFF8CC89BU, 0x36974D04U}},
		{{0x8F929057U, 0x27F29E14U, 0xC0C853DFU, 0x7A64AE06U, 0x58E9C5CEU, 0x256CD183U, 0xDED092A5U, 0x9D9CCE82U},
			{0x6E93B7C7U, 0xCC6E5979U, 0x31BB9E27U, 0xE1E47092U, 0xAA9E29A0U, 0xB70B3083U, 0x3785E644U, 0xBF181A75U}},
		{{0x5C0A3F1EU, 0x8ED6E8C8U, 0x7C87C37FU, 0xBCAD2492U, 0x9EE3B78DU, 0xFDFB62BBU, 0xCBCEBA46U, 0xEBA8E477U},
			{0xEEAEDE4BU, 0x37D38CB0U, 0x7976DEB6U, 0x0BC498E8U, 0x6B6147FBU, 0xB2944C04U, 0xF71F9609U, 0x8B123F35U}},
		{{0x1402B9D0U, 0xD3B3A13FU, 0x2C7BC863U, 0x573441C3U, 0x578C3E6EU, 0x4B301EC4U, 0x0ADAF57EU, 0xC26FC9C4U},
			{0x7493CEA3U, 0x96E71BFDU, 0x1AF81456U, 0xD05D4B3FU, 0x6A8C608FU, 0xDACA2A8AU, 0x0725B276U, 0x53EF07F6U}},
		{{0xC7435978U, 0xBAE023F0U, 0x20E30E19U, 0xB152C888U, 0xE3FA6FAFU, 0x9C241645U, 0x84823E60U, 0x735D95C1U},
			{0x03955317U, 0x03197573U, 0xF03B4995U, 0x0B4B02A9U, 0x70274600U, 0x076BF559U, 0xAAF57508U, 0x32C5CC53U}},
		{{0xD5C7C5D2U, 0x0318DBFDU, 0x072B342DU, 0xB38F8DA7U, 0x7B8DE38AU, 0x3569BDDCU, 0xA1C94842U, 0xF25B5887U},
			{0x2946AD60U, 0xB2D5B284U, 0xE9D1707EU, 0x854F29ADU, 0x2C6A4509U, 0xAA5159DCU, 0x57189837U, 0x899F94C0U}},
		{{0x49CE89E7U, 0x27F536E0U, 0xCC890CB5U, 0x18908539U, 0xD83C2AA1U, 0x308909ABU, 0x1AB73BD3U, 0xECD3142BU},
			{0xB3F5AB84U, 0x6A85BF59U, 0xF2BEA4C6U, 0x3C320A68U, 0x6DA4541FU, 0xAD8DC538U, 0xB7C41186U, 0xEAF34EB0U}},
		{{0x46AC49D2U, 0xA6B5C9D6U, 0x83137AA9U, 0x42C77C0BU, 0x68225A38U, 0x24D000FCU, 0x2FE1E907U, 0x0F63CFC8U},
			{0xC6441F95U, 0x22D1B01BU, 0xEC8E448FU, 0x7D38F719U, 0x787FB1BAU, 0x9B33FA5FU, 0x190158DFU, 0x94DCFDA1U}},
		{{0x490A1ACAU, 0x63C79326U, 0x41526B02U, 0xCB64DD9CU, 0xA2979258U, 0xBB772591U, 0x48D97846U, 0x3F582970U},
			{0x7C213BA7U, 0xD66B70D1U, 0xE8A0CED4U, 0xC28FEBB5U, 0xC10338C1U, 0x6B911831U, 0xBF0126F3U, 0x0D54E389U}},
		{{0xB483689BU, 0x40242EFEU, 0x513AC262U, 0x2575D3F6U, 0x0CA6DB72U, 0xF30037C8U, 0x98864BE2U, 0xC9FCCE82U},
			{0x0149362DU, 0x84A112FFU, 0x1C4AE971U, 0x95E57582U, 0x945CF86CU, 0x1FA4B1A8U, 0x0B024A2FU, 0x4525A734U}},
		{{0xC905D85FU, 0xCAEAD1C2U, 0x0733AE57U, 0xE9D7F790U, 0xF07CDD94U, 0x24C9A65CU, 0xA4B55931U, 0x7389359CU},
			{0x367E45F7U, 0xF58709B7U, 0xCB7E7ADCU, 0x1F203067U, 0xC7B72818U, 0x82444BFFU, 0xBAAC8033U, 0x07303B35U}},
		{{0x526F09FDU, 0x057FED45U, 0x8128240AU, 0xE8A4F10CU, 0xFF2BFD8DU, 0x9332EFC4U, 0xBD35AA31U, 0x214E77A0U},
			{0x14FAA40EU, 0x32896D73U, 0x01E5F186U, 0x767867ECU, 0x17A1813EU, 0xC9ADF8F1U, 0x54741795U, 0xCB6CDA78U}},
		{{0x01DAE185U, 0xB7B4D001U, 0x9B7A94BCU, 0x45434E0BU, 0xFBD8CB0BU, 0xF54339AFU, 0xE98EF49EU, 0xDCC4569EU},
			{0x09A51299U, 0x7789318AU, 0xB2B025D8U, 0x81B4D206U, 0xFAE85792U, 0xF64AA418U, 0xACD7BAF7U, 0x3E50258FU}},
		{{0xA19FD868U, 0xC072EBD3U, 0xDB8DDD3BU, 0x612E481CU, 0x1A64D852U, 0xB4E1D754U, 0xC4C6C4ABU, 0x00EF95ACU},
			{0xAA0A6C46U, 0x1536D2EDU, 0x43774790U, 0x61294086U, 0x343FDA10U, 0x54AF25E8U, 0xFD25D6F2U, 0x9FF9D98DU}},
		{{0x5579BEA4U, 0x4CD296DFU, 0x5CEEDAF1U, 0x10E35AC8U, 0xE3BCC5B1U, 0x04C4C5FDU, 0x89412CF9U, 0x95F9EE8AU},
			{0x82B6EB0FU, 0x2C9459EEU, 0x95C2AADDU, 0x2E845765U, 0xD327FCFEU, 0x774A84AEU, 0x0368D476U, 0xD8C93722U}},
		{{0x296C36EFU, 0x211CDE10U, 0x82C4DA77U, 0x7EE89672U, 0xA57836DAU, 0xB617D270U, 0x9CB7560BU, 0xF0CD9C31U},
			{0xE455FE90U, 0x01FDCBF7U, 0x7E7334F3U, 0x3FB53CBBU, 0x4E7DE4ECU, 0x781E2EA4U, 0x0B384FD0U, 0x8ADAB3ADU}},
		{{0xBBBAB3B8U, 0x60E690F2U, 0x8B04816BU, 0x4851F8AEU, 0x9C92E4D2U, 0xC72046ABU, 0x7CF3136BU, 0x518C74A1U},
			{0xF9877D4CU, 0xFF4EB50AU, 0xA919CABBU, 0x14578D90U, 0xAC5EB2B6U, 0x8218F8C4U, 0x542016E4U, 0xA3CCC547U}},
		{{0x1EEA7B85U, 0xE33EA76CU, 0x92D4F85EU, 0x2352B461U, 0xAFE115BBU, 0xF101D334U, 0x889175A3U, 0xFABC1294U},
			{0x5233F925U, 0x7F6BCDC0U, 0xE77FEC55U, 0xE0A802DBU, 0x8069B659U, 0xBDB47B75U, 0xF98FBD74U, 0x1C5E12DEU}},
		{{0x89D8DDBBU, 0x656C4658U, 0x70F38EE8U, 0x8830B26EU, 0xDE1212B0U, 0x4320FD5CU, 0xE4A2EDB2U, 0xC34F30CFU},
			{0x56AB64B8U, 0xABB131A3U, 0xD99C5D26U, 0x7F77F0CCU, 0xBF981D94U, 0x66856A37U, 0x738BD76EU, 0x19E76D09U}},
		{{0x53B618C0U, 0x1C6BD47DU, 0x6A227923U, 0xC424F46CU, 0xDD92D964U, 0x7303FFDEU, 0x71B5ABF2U, 0xE9712878U},
			{0xF815561DU, 0x8F48A632U, 0xD3C055D1U, 0x85F48FF5U, 0x7525684FU, 0x222A1427U, 0x67360CC3U, 0xD0D841A0U}},
		{{0xF2C34A99U, 0x860C44B1U, 0xBF5855ACU, 0x3B00ACA4U, 0xFAAF37BEU, 0xABF6AAA0U, 0x2A53EC08U, 0x65F43682U},
			{0xA11B12E1U, 0x1D9A5801U, 0xE20ED475U, 0x78A7AB2CU, 0x9A41E0D5U, 0x0DE1067EU, 0x305023EAU, 0x30473F5FU}},
		{{0xF97F68C6U, 0xDBB7B352U, 0x0B02CF58U, 0x0C773B50U, 0x3C1F96D9U, 0xEA2E4821U, 0xEEE01815U, 0xFFB357B0U},
			{0xE0F28039U, 0xB9C924CDU, 0x46A3FBE4U, 0x0B36C95AU, 0x5E46DB6CU, 0x1FAAAEA4U, 0x1928AAFFU, 0xCAE575C3U}},
		{{0x70CBB96CU, 0x263C962AU, 0xBCD124A9U, 0xE034362AU, 0x3C2AE58DU, 0xF120DB28U, 0xFEF6D507U, 0xB9A38D49U},
			{0x1FF140FDU, 0xB1FD2A82U, 0x20AEE7E0U, 0xBD162F30U, 0xCB251949U, 0x4E17A5D4U, 0x4F7E1C3DU, 0x2AEBCB83U}},
		{{0x599FF0F9U, 0x01778A2BU, 0x8104FC6BU, 0x68A923D7U, 0xDA694FF3U, 0x5BFA44DFU, 0xF7667F12U, 0x4F7199DBU},
			{0xE46F2A79U, 0xC06D8FF6U, 0xE9F8131DU, 0x08B5DEADU, 0xABB4CE7CU, 0x02519A59U, 0xB42AEC3EU, 0xC4F710BCU}},
		{{0xC0C22719U, 0xD8BFD3CAU, 0xC9CA151EU, 0xC60209E4U, 0xD9A1A69CU, 0x7A744AB5U, 0x14937F8FU, 0x6DE5048BU},
			{0xE115AC04U, 0x171938D8U, 0x1C6B16D2U, 0x7DF70940U, 0x7F8E94E7U, 0xA6AEB663U, 0x2A2CF094U, 0xC130388EU}},
		{{0x786F337CU, 0xCDB6719DU, 0xE704397DU, 0xD9C01CD2U, 0x555C2FEFU, 0x0F4A3F20U, 0x7C0AF223U, 0x00452509U},
			{0x84DB8E76U, 0x54A58047U, 0x93C8AA06U, 0x3BACF1AAU, 0xF7919422U, 0x11CA957CU, 0x78CDAA40U, 0x50641053U}},
		{{0x6C67A775U, 0x9F6EB731U, 0xEFC5D0B1U, 0xCB10471AU, 0xE1B806B2U, 0xB433750CU, 0x57B1AE7EU, 0x19C5714DU},
			{0xED03FD3FU, 0xC0DC8B7BU, 0x31BC194EU, 0xDD03344FU, 0x8C6320B5U, 0xA66C52A7U, 0xD0B6FD93U, 0x8BC82CE3U}},
		{{0x0E0B040DU, 0xB228A90FU, 0x45FF897FU, 0xBAF02D82U, 0x00FA6122U, 0x2AAC79E6U, 0x8E36F557U, 0x24828817U},
			{0x113EC356U, 0xB9521D31U, 0x15EFF1F8U, 0x9E48861EU, 0xE0D41715U, 0x2AA1D412U, 0x53F131B8U, 0x71F86203U}},
		{{0x6F73C51EU, 0x6D2A483DU, 0xEA0DC2DDU, 0xA4CB2412U, 0x1EB917FFU, 0x50663C41U, 0xEADE299EU, 0x3D3A74CFU},
			{0x4A7A9202U, 0x29B3990FU, 0xA7B15C3DU, 0xA9BCCF59U, 0xA5DF9208U, 0x66A3CCDCU, 0x43F2F929U, 0x48027C14U}},
		{{0x098CAFB4U, 0xE044A3BBU, 0x60D48CAFU, 0x27ED2310U, 0x3A31B84DU, 0x542B5675U, 0xFCDDBED7U, 0xCBF3DD50U},
			{0x41B1D830U, 0x25031F16U, 0xCB0C1E27U, 0xA7EC851DU, 0xB5AE75DBU, 0xAC1C8FE0U, 0x08C52120U, 0xB24C7557U}},
		{{0xD607039EU, 0x1FBB0E71U, 0xCD3A4546U, 0x2B70E215U, 0x53324091U, 0x32D2F01DU, 0x180AB19BU, 0xB796FF08U},
			{0x3C57C4AAU, 0x32D87A86U, 0xB7C49A27U, 0x2AED9CAFU, 0x31630D98U, 0x9FB35EACU, 0x5C3E20A3U, 0x338E8CDFU}},
		{{0x4ED80940U, 0x3014368BU, 0x7A6FCEDDU, 0x67E6D056U, 0xCA97579FU, 0x7C208C49U, 0xA23597F6U, 0xFE3D7A81U},
			{0x7E096AE2U, 0x5E203202U, 0x24B39366U, 0xB1F3E1E7U, 0x2FDCDFFCU, 0x26DA26F3U, 0x6097BE83U, 0x79422F1DU}},
	},
	{
		{{0x9DB3B381U, 0x263A2CFBU, 0xD4DF0A4BU, 0x9C3A2DEEU, 0x7D04E61FU, 0x728D06E9U, 0x42449325U, 0x8B1ADFBCU},
			{0x7E053A1BU, 0x6EC1D939U, 0x66DAF707U, 0xEE2BE5C7U, 0x810AC7ABU, 0x80BA1E14U, 0xF530F174U, 0xDD2AE778U}},
		{{0x205B9D8BU, 0x0435D97AU, 0x056756D4U, 0x6EB8F064U, 0xB6F8210EU, 0xD5E88A8BU, 0xEC9FD9EAU, 0x070EF12DU},
			{0x3BCC876AU, 0x4D849505U, 0xA7404CE3U, 0x12A75338U, 0xB8A1DB5EU, 0xD22B49E1U, 0x14BFA5ADU, 0xEC1F2051U}},
		{{0xB6828F36U, 0xADBAEB79U, 0x01BD5B9EU, 0x9D7A0258U, 0x1E844B0CU, 0xEDA01E0DU, 0x887EDFC9U, 0x4B625175U},
			{0x9669B621U, 0x14109FDDU, 0xF6F87B98U, 0x88A2CA56U, 0x170DF6BCU, 0xFE2EB788U, 0xFFA473F9U, 0x0CEA06F4U}},
		{{0xC4E83D33U, 0x43ED81B5U, 0x5EFD488BU, 0xD9F35879U, 0x9DEB4D0FU, 0x164A620FU, 0xAC6A7394U, 0xC6927BDBU},
			{0x9F9E0F03U, 0x45C28DF7U, 0xFCD7E1A9U, 0x2868661EU, 0xFFA348F1U, 0x7CF4E8D0U, 0x398538E0U, 0x6BD4C284U}},
		{{0x289A8619U, 0x2618A091U, 0x6671B173U, 0xEF796E60U, 0x9090C632U, 0x664E46E5U, 0x1E66F8FBU, 0xA38062D4U},
			{0x0573274EU, 0x6C744A20U, 0xA9271394U, 0xD07B67E4U, 0x6BDC0E20U, 0x391223B2U, 0xEB0A05A7U, 0xBE2D93F1U}},
		{{0x3F36D141U, 0xF23E2E53U, 0x4DFCA442U, 0xE84BB3D4U, 0x6B7C023AU, 0xB804A48DU, 0x76431C3BU, 0x1E16A8FAU},
			{0xDDD472E0U, 0x1B5452ADU, 0x0D1EE127U, 0x7D405EE7U, 0xFFA27599U, 0x50FC6F1DU, 0xBF391B35U, 0x351AC53CU}},
		{{0x4444896BU, 0x7EFA14B8U, 0xF94027FBU, 0x64974D2FU, 0xDE84487DU, 0xEFDCD0E8U, 0x2B48989BU, 0x8C45B260U},
			{0xD8463487U, 0xA8FCBBC2U, 0x3FBC476CU, 0xD1B2B3F7U, 0xC8F443C0U, 0x21D005B7U, 0x40C0139CU, 0x518F2E67U}},
		{{0x06D75FC1U, 0x56036E8CU, 0x3249A89FU, 0x2DCF7BB7U, 0xE245E7DDU, 0x81DD1D3DU, 0xEBD6E2A7U, 0xF578DC4BU},
			{0xDF2CE7A0U, 0x4C028903U, 0x9C39AFACU, 0xAEE36288U, 0x146404ABU, 0xDC847C31U, 0xA4E97818U, 0x6304C0D8U}},
		{{0xA91F6791U, 0xAE51DCA2U, 0x9BAA9EFCU, 0x2ABE4190U, 0x559C7AC1U, 0xD9D2E2F4U, 0xFC9F773AU, 0xE82F4B51U},
			{0x4073E81CU, 0xA7713027U, 0xFBB596FCU, 0xC0276FACU, 0xA684F70CU, 0x1D819FC9U, 0xC9F7B1E0U, 0x29B47FDDU}},
		{{0x459B1940U, 0x358DE103U, 0x5B013E93U, 0xEC881C59U, 0x49532AD3U, 0x51574C93U, 0xB37B46DEU, 0x2DB1D445U},
			{0xDF239FD8U, 0xC6445B87U, 0x151D24EEU, 0xC718AF75U, 0xF43C6259U, 0xAEA1C4A4U, 0x70BE02F7U, 0x40C0E5D7U}},
		{{0x721B33F2U, 0x6A4590F4U, 0xFEDF04EAU, 0x2124F1FBU, 0x9745EFE7U, 0xF8E53CDEU, 0x65F046D9U, 0xE7E10432U},
			{0xE4D0C7E6U, 0xC3FCA28EU, 0x87253B1BU, 0x847E339AU, 0x3743E643U, 0x9B595348U, 0x4FD12FC5U, 0xCB6A0A0BU}},
		{{0x27D02DCCU, 0xFB6836C3U, 0x7A68BCC2U, 0x5AD00982U, 0x005E912DU, 0x1B24B44CU, 0x811FDCFEU, 0xCC83D20FU},
			{0x666FBA0CU, 0x36527EC1U, 0x14754635U, 0x69948197U, 0x556DA9C2U, 0xFCDCB1A8U, 0x81A732B2U, 0xA5934267U}},
		{{0xA714181DU, 0xEC1214EDU, 0x6067B341U, 0x609AC13BU, 0xA545DF1FU, 0xFF4B4C97U, 0x34D2076BU, 0xA1240501U},
			{0x1409CA97U, 0x6EFA0C23U, 0x20638C43U, 0x254CC1A8U, 0xDCFB46CDU, 0xD4E363AFU, 0x03942A27U, 0x62C2ADC3U}},
		{{0x56E46483U, 0xC67B9DF0U, 0x63736356U, 0xA55ABB20U, 0xC551BC52U, 0xAB93C098U, 0xB15FE64BU, 0x382B49F9U},
			{0x4DFF8D47U, 0x9EC221ADU, 0x437DF4D6U, 0x79CAF615U, 0xBB456509U, 0x5F13DC64U, 0x191F0714U, 0xE4C589D9U}},
		{{0x3FD40E09U, 0x27B6A8ABU, 0x77313EA9U, 0xE455842EU, 0x1F55988BU, 0x8B51D1E2U, 0x062BBBFCU, 0x5716DD73U},
			{0x4E8BF3DEU, 0x633C11E5U, 0x1B85BE3BU, 0x9A0E77B6U, 0x0911CCA6U, 0x56510729U, 0xEFA6590FU, 0x27E76495U}},
		{{0x070D3AABU, 0xE4AC8B33U, 0x9A2CD5E5U, 0x2643672BU, 0x1CFC9173U, 0x52EFF79BU, 0x90A7C13FU, 0x665CA49BU},
			{0xB3EFB998U, 0x5A8DDA59U, 0x052F1341U, 0x8A5B922DU, 0x3CF9A530U, 0xAE9EBBABU, 0xF56DA4D7U, 0x35986E7BU}},
		{{0xFF3513CCU, 0x3A636B5CU, 0x3198F7DDU, 0xBB0CF8BAU, 0x41F16F86U, 0xB8D40522U, 0xDE13A7BFU, 0x760575D8U},
			{0x9F7AA181U, 0x36F74E16U, 0xF509ED1CU, 0x163A3ECFU, 0x3C40A491U, 0x6AEAD61FU, 0xDFE8FCAAU, 0x158C95FCU}},
		{{0x13CDA46FU, 0xA3991B6EU, 0x342FAED0U, 0x79482415U, 0x666B5970U, 0xF3BA5BDEU, 0xB26AB6DDU, 0x1D52E6BCU},
			{0x8608DD3DU, 0x768BA1E7U, 0xEA076586U, 0x4930DB2AU, 0xE7DC1AFAU, 0xD9575714U, 0xF7C58817U, 0x1FC7BF7DU}},
		{{0xD9EEE96CU, 0x6B47ACCDU, 0xE58CEC37U, 0x0CA277FBU, 0xE702C42AU, 0x113FE413U, 0xC47CBE51U, 0xDD1764EEU},
			{0x7B3ED739U, 0x041E7CDEU, 0x5CE9E1C0U, 0x50CB7459U, 0x2925B212U, 0x35568513U, 0x001B081CU, 0x7CFF95C4U}},
		{{0x8088B454U, 0x63EE4CBDU, 0x9A9E0C8AU, 0xDB7F32F7U, 0x6B2447CBU, 0xB377D418U, 0xD370219BU, 0xE3E982AAU},
			{0xC2A2A593U, 0x06CCC1E4U, 0x0773F24FU, 0x72C36865U, 0x95859423U, 0xA13B4DA7U, 0x75040C8FU, 0x8BBF1D33U}},
		{{0xDA50C991U, 0x726F0973U, 0x822D6EE2U, 0x48AFCD5BU, 0x20FD7771U, 0xE5FC718BU, 0xFD0807A1U, 0xB9E8E77DU},
			{0x99A7703DU, 0x7F5E0F44U, 0x618E36F3U, 0x6972930EU, 0x23807BBEU, 0x2B7C77B8U, 0xCB27FF50U, 0xE5B82405U}},
		{{0xBD379062U, 0xBA8B8BE3U, 0x2DCE4A92U, 0xD64B7A1DU, 0xB2952E37U, 0x040A73C5U, 0xD438AECAU, 0x0A9E252EU},
			{0xC39D3BCBU, 0xDD43956BU, 0xB32B2D63U, 0x1A31CA00U, 0x5C417A18U, 0xD67133B8U, 0x2EF442C8U, 0xD08E4790U}},
		{{0x255C0980U, 0x98CB1AE9U, 0x2B4A739FU, 0x4BD86381U, 0x1E4A45A1U, 0x5A5C31E1U, 0x9CB0DB2FU, 0x1E5D55FEU},
			{0x8FF5CC29U, 0x74661B06U, 0x0EB8A4F4U, 0x026B389FU, 0x58848C24U, 0x536B21A4U, 0x81DC72B0U, 0x2E5BF8ECU}},
		{{0xAD886AACU, 0x03C187D0U, 0xB771B645U, 0x5C16878AU, 0xC74045ABU, 0xB07DFC6FU, 0x7800CAEDU, 0x2C6360BFU},
			{0xB9C972A3U, 0x24295BB5U, 0x7C9A6DBAU, 0xC9E6F88EU, 0x92A79AA6U, 0x90FFBF24U, 0x41C26AC2U, 0xDE29D50AU}},
		{{0xD309CBE6U, 0x9F0AF483U, 0xE0BCED4FU, 0x5B020D8AU, 0xB38023E3U, 0x606E986DU, 0x1ABC6933U, 0xAD8F2C9DU},
			{0xE7400E93U, 0x19292E1DU, 0x52BE5E4DU, 0xFE3E18A9U, 0x2E0680BFU, 0xE8E9771DU, 0xC54DB063U, 0x8C5BEC98U}},
		{{0x74A55D1FU, 0x2AF9662AU, 0x046F66D8U, 0xE3FBF28FU, 0xD4DC4794U, 0xA3A72AB4U, 0x5C7C2DD8U, 0x09779F45U},
			{0xC3D19D8DU, 0xD893BDAFU, 0x57D6A6DFU, 0xD5A75094U, 0x952E6255U, 0x8CF8FEF9U, 0xDA9A8AFFU, 0x3DA67CFBU}},
		{{0x2C160DCDU, 0x4C23F62AU, 0x8F90EAEFU, 0x34E6C5E3U, 0xA9A65D5AU, 0x35865519U, 0x8FD38A3DU, 0x07C48AAEU},
			{0x50068527U, 0xB7E7AEDAU, 0x1C90936AU, 0x2C09EF23U, 0xE879324CU, 0x31ECFEB6U, 0xFB0EC938U, 0xA0871F6BU}},
		{{0xD84D835DU, 0xB1F0FB68U, 0x861DC1E6U, 0xC90CAF39U, 0x7594F8D7U, 0x12E5B046U, 0x65012B92U, 0x26897AE2U},
			{0xA4D6755DU, 0xBCF68A08U, 0x0991FBDAU, 0x403EE41CU, 0x3BBF17E8U, 0x733E343EU, 0x679B3D65U, 0xD2C7980DU}},
		{{0xD2E11305U, 0x33056232U, 0xF3C07A6FU, 0x966BE492U, 0xBB15509DU, 0x6A8878FFU, 0x0A9B59A4U, 0xFF221101U},
			{0xABE30129U, 0x6C9F564AU, 0x336E64CFU, 0xC6F2C940U, 0x8B0C8022U, 0x0FE75262U, 0x6AE8DB87U, 0xBE0267E9U}},
		{{0x93BC042BU, 0x22E192F1U, 0xB237C458U, 0xF085B534U, 0x832C4168U, 0xA0D192BDU, 0xBDF6271DU, 0x7A76E9E3U},
			{0xB88911B5U, 0x52A882FAU, 0xB4DB0EB5U, 0xC85345E4U, 0x81A7C3FFU, 0xA3BE02A6U, 0xF0EC0469U, 0x51889C8CU}},
		{{0xA5E829E5U, 0x9D031369U, 0x1607AA41U, 0xCBB4C6FCU, 0x241D84C1U, 0x75AC59A6U, 0x8829E0EEU, 0xC043F2BFU},
			{0x8EA5E185U, 0x82A38F75U, 0xD87CBD9FU, 0x8BDA40B9U, 0x2D8FC601U, 0x9E65E75EU, 0xA35690B3U, 0x3D515F74U}},
		{{0xDA79E5ACU, 0x534ACF4FU, 0x8630215FU, 0x68B83B3AU, 0xD085756EU, 0x5C748B2EU, 0xE5D37CB2U, 0xB0317258U},
			{0xC5CCC2C4U, 0x6735841AU, 0x3D9D5069U, 0x7D7DC96BU, 0xFD1754BDU, 0xA147E410U, 0xD399DDD5U, 0x65296E94U}},
	},
	{
		{{0xB30CFB3AU, 0xD7E0C4CDU, 0x6C9DB4C8U, 0x6D09B8C1U, 0x07C8D9DFU, 0x40BA1A42U, 0x1C52C66DU, 0x6FD495F7U},
			{0x275264DAU, 0xFB0E169FU, 0xE57D8362U, 0x80C2B746U, 0x49AD7222U, 0xEDD987F7U, 0x4398EC7BU, 0xFDC229AFU}},
		{{0x52666A58U, 0xB0D1ED84U, 0xE6A9C3C2U, 0x4BCB6E00U, 0x26906408U, 0x3C57411CU, 0x13556400U, 0xCFC20755U},
			{0x5294DBA3U, 0xA08B1C50U, 0x8B7DD31EU, 0xA30BA286U, 0x991ECA74U, 0xD70BA90EU, 0xE762C2B9U, 0x094E142CU}},
		{{0xAC7F13EFU, 0x88EA439BU, 0x8D9A7D14U, 0x65AA143FU, 0x20CB2F1AU, 0xFFE0CF2DU, 0x381C6AD1U, 0x847B7BF1U},
			{0x8AC80B4DU, 0x56F5B814U, 0x35CEAFF2U, 0x041B4418U, 0xCDA5FCEFU, 0xDE9088C0U, 0xE083B8CEU, 0xE668519BU}},
		{{0x979F3925U, 0xB81D783EU, 0xAF4C89A7U, 0x1EFD130AU, 0xFD1BF7FAU, 0x525C2144U, 0x1B265A9EU, 0x4B296904U},
			{0xB9DB65B6U, 0xED8E9634U, 0x03599D8AU, 0x35C82E32U, 0x403563F3U, 0xDAA7A54FU, 0x022C38ABU, 0x9DF088ADU}},
		{{0x456260EEU, 0x1C695AC1U, 0x4D783693U, 0x4E3ACEDFU, 0x11674A8FU, 0xDAFD5259U, 0x6C7B22F9U, 0x21846D40U},
			{0x17891F55U, 0x783D1CFCU, 0xD74D0475U, 0x2A173C34U, 0xB699FA20U, 0x3AFDBD7FU, 0xAC829F62U, 0x79248FB6U}},
		{{0xBB3FD30AU, 0xE5CFB066U, 0xEFF0354EU, 0x429169DAU, 0x3524E36CU, 0x809CF852U, 0x0155BE1DU, 0x136F4FB3U},
			{0x1FBBA712U, 0x4826AF01U, 0x506BA1A1U, 0x6EF0F0B4U, 0x77AEA73EU, 0xD9928B31U, 0x5EAA244EU, 0xE2BF6AF2U}},
		{{0x1AC81DB2U, 0x1828363AU, 0x48820666U, 0x752A22B3U, 0x3D32AB6AU, 0xCFC00003U, 0xD96A3CB1U, 0x2AD677E1U},
			{0xC8233011U, 0xA7E3E672U, 0x5E4303B7U, 0x2C65E87EU, 0xC6DF04CBU, 0x1834F71BU, 0x3CEDA834U, 0x32F8772CU}},
		{{0x4237B64BU, 0x8D084F12U, 0xE3ECFD07U, 0x688EBE99U, 0xF6845DD8U, 0x57B8A70CU, 0x5DA4A325U, 0x808FC59CU},
			{0xA3585862U, 0xA9032B2BU, 0xEDF29386U, 0xB66825D5U, 0x431EC29BU, 0xB5A5A8DBU, 0x3A1E8DC8U, 0xBB143A98U}},
		{{0xCFE9D1D9U, 0x5B356A07U, 0x306F48DDU, 0xD4BA683AU, 0x2C6437C1U, 0x3B6AE7B5U, 0x54B64FD4U, 0xF9C0C1A1U},
			{0xED5452D0U, 0x90660DBAU, 0x2850530FU, 0x423F3E95U, 0x47274D81U, 0x1432A206U, 0x7DB00574U, 0xCCEBF3F8U}},
		{{0x12AE381BU, 0x35EE94CEU, 0x86CCDA90U, 0x3A7F176CU, 0x4606EACAU, 0xC63A657EU, 0x43CD04DFU, 0x9AE5A380U},
			{0xED251B46U, 0x9BEC8D15U, 0xCACA5E64U, 0x1F5D6D30U, 0x9FF20F07U, 0x347B3B35U, 0xF7E4B286U, 0x4D65F034U}},
		{{0x06C82996U, 0xD89F81F6U, 0x15C592FCU, 0x4F735288U, 0xCE49A8C6U, 0x8C0C03A1U, 0xB9F25907U, 0xE04DFFE0U},
			{0x4AF7AB4BU, 0x22662150U, 0xF5A35C4CU, 0x9E21FFF6U, 0x5A1E9198U, 0x071D4484U, 0x4109FC11U, 0x0811955CU}},
		{{0xF111661EU, 0x9E93BA24U, 0xB105EB04U, 0xEDCED484U, 0xF424B578U, 0x96DC9BA1U, 0xE83E9069U, 0xBF8F66B7U},
			{0xD7ED8216U, 0x872D4DF4U, 0x8E2CBECFU, 0xBF07F377U, 0x98E73754U, 0x4281D899U, 0x8AAB8708U, 0xFEC85FBBU}},
		{{0x4511395BU, 0xD328411DU, 0xE4CDF8DEU, 0x3150C079U, 0x5934BCD0U, 0x224BE7C4U, 0x4358C9AEU, 0x9D977175U},
			{0x2230DB4DU, 0xDBB1BB41U, 0x0D8E31DCU, 0x168E84BDU, 0x1C115FD2U, 0xA61B4F34U, 0x5888C28FU, 0xC775FA15U}},
		{{0xA5BA5B0BU, 0x9A3C0DEEU, 0x42D05299U, 0xE6A116CEU, 0xE9B02D42U, 0xAE9775FEU, 0xA1545CB6U, 0x72B05200U},
			{0x31A3B4EAU, 0xBC506F7DU, 0x8BBD9B32U, 0xE5893078U, 0xE4B12A97U, 0xC8BC5F37U, 0x4A73B671U, 0x6B000C06U}},
		{{0x17DE5F8AU, 0xF3C6925CU, 0xF34991D5U, 0xA6CB4B95U, 0x7DD50566U, 0xA8BF97F0U, 0x0B91A09EU, 0x2C8D55E5U},
			{0x3AD7E720U, 0x6ADCC2EDU, 0x0093EC5AU, 0x734A2348U, 0x43CB36AFU, 0xFA1D8FBEU, 0xA4A8A7E4U, 0xDC87B81CU}},
		{{0x765FA7D0U, 0x13B5BF22U, 0x1D6A5370U, 0x59805BF0U, 0x4280DB98U, 0x67A5E29DU, 0x776B1CE3U, 0x4F53916FU},
			{0x33DDF626U, 0x714FF61FU, 0xA085D103U, 0x4206238EU, 0xE5809EE3U, 0x1C50D4B7U, 0x85F8EB1DU, 0x999F450DU}},
		{{0xA239F325U, 0x5F3904B1U, 0x1A58AD90U, 0xD026A6F7U, 0xD6B824EDU, 0x43542736U, 0x4A9364B8U, 0x0841A775U},
			{0xCFEB1DE9U, 0x7597CB41U, 0xBF580A4FU, 0x20252B7AU, 0x17C48E20U, 0x37729281U, 0xC6F5A071U, 0xDADB1C28U}},
		{{0xE4C79E9BU, 0x658A6051U, 0xC66A9FEAU, 0x1394CB73U, 0xC6BE7B23U, 0x27F31ED5U, 0x5AA6F8FEU, 0xF4C88F36U},
			{0x4AAA499EU, 0x0FB0721FU, 0xE3FB2A6BU, 0x68B3A7D5U, 0x3A92851DU, 0xA788097DU, 0xE96F4913U, 0x060E7F8AU}},
		{{0x88DBFDC1U, 0xF1FA0CE2U, 0xD2F8DD08U, 0x3C397480U, 0x4EDB95F0U, 0x0EF10A8BU, 0x3247E556U, 0x4558BC75U},
			{0x0FC04FA4U, 0x765CEF5FU, 0xD66D3D75U, 0x729F2CE6U, 0xB433F066U, 0x6D35275DU, 0x364E597EU, 0x31D95C27U}},
		{{0x1A3A93BCU, 0x82EEBE73U, 0xA21ADC1AU, 0x42BBF465U, 0xEF030EFDU, 0xC10B6FA4U, 0x87B097BBU, 0x247AA4C7U},
			{0xF60C77DAU, 0x8B8DC632U, 0xC223523EU, 0x6FFBC26AU, 0x344579CFU, 0xA4F6FF11U, 0x980250F6U, 0x5825653CU}},
		{{0xCC1F398BU, 0x88EAEF9AU, 0xF4217E95U, 0x85189A25U, 0xB968FCEFU, 0x9424F5F5U, 0xD0072228U, 0xC05D8AF9U},
			{0x49A1B22AU, 0x0B36FA8CU, 0xF1115FCEU, 0xE61C3657U, 0x4262433FU, 0x06CDF0C0U, 0x9EC820DCU, 0x9D8AC52DU}},
		{{0xBC1AA2B9U, 0xB2DD097EU, 0x37A0333AU, 0x07889393U, 0x37A0DB38U, 0x1CF55E71U, 0x792C1613U, 0x2648487FU},
			{0x3FCEF261U, 0xDAD01336U, 0x0EABF129U, 0x6239C81DU, 0x9D276BE2U, 0x8EE761DEU, 0x1EDA6AD3U, 0x406A7A34U}},
		{{0xD5026A07U, 0x017310ACU, 0xE793281CU, 0x3526C954U, 0x7600AC51U, 0x416B7BC5U, 0xD42B44A7U, 0x09678952U},
			{0xB6049FB1U, 0xABDA3FB7U, 0xDFADEF7BU, 0x3CB0A659U, 0x1B8B0C0DU, 0x58793172U, 0x4E9D611BU, 0xFE73476EU}},
		{{0x4A493B31U, 0x4BF367BAU, 0x9BF7F026U, 0x54F20A52U, 0x9795914BU, 0xB696E062U, 0x8BF236ACU, 0xCDDAB96DU},
			{0xED25EA13U, 0x4FF2C70AU, 0x81CBBBE7U, 0xFA1D09EBU, 0x468544C5U, 0x88FC8C87U, 0x696B3317U, 0x847A670DU}},
		{{0x45519A59U, 0x8410AFE2U, 0xBC30D774U, 0x9A9739AFU, 0xD8F44A88U, 0x6633DE03U, 0x505DDB37U, 0xD56A9BB3U},
			{0x46815E14U, 0x66667C07U, 0x884493BBU, 0x2228F8EDU, 0x17AB4882U, 0x23CC561AU, 0x521A1BCEU, 0x99830759U}},
		{{0x64BCB626U, 0xF133421EU, 0x26DEE0B5U, 0xAEA638C8U, 0xB310346CU, 0xD6E7680BU, 0xD5D4CED3U, 0xE06F4097U},
			{0x7512A30BU, 0x09961452U, 0xE589A59AU, 0xF3D867FDU, 0x52D0C180U, 0x2E73254FU, 0x333C74ACU, 0x9063D8A3U}},
		{{0xE2EE6F7AU, 0x12142744U, 0x6521603FU, 0x63389D10U, 0x9E9C813AU, 0xA1CD82C7U, 0x5AE342EBU, 0xC109641CU},
			{0x04BB06E9U, 0x3C85FB30U, 0xC212F17FU, 0x1FED441CU, 0x82F61A53U, 0x1656DFACU, 0xCED98F5FU, 0x88EC7A30U}},
		{{0xD314E7BCU, 0xEDA6C595U, 0x467899EDU, 0x2EE7464BU, 0x0A1ED5D3U, 0x1CEF423CU, 0x69CC7613U, 0x217E76EAU},
			{0xE7CDA917U, 0x27CCCE1FU, 0x8A893F16U, 0x12D8016BU, 0x9FC74F6BU, 0xBCD6DE84U, 0xF3144E61U, 0xFA5817E2U}},
		{{0x9BC55ECEU, 0x0B8939B5U, 0xCBAA70FFU, 0xB164B33BU, 0x3F2AB791U, 0xAF6B010FU, 0x7B52CB37U, 0x98B767BAU},
			{0xFCF86541U, 0xBD0DF380U, 0x64A1014AU, 0x5194F354U, 0x4C35F625U, 0x42C1F22EU, 0xF7BBF51BU, 0x9A70F3E2U}},
		{{0x0821EE4CU, 0x1F354164U, 0x0BC61992U, 0x1583EAB4U, 0x1D72879FU, 0x7490CAF6U, 0xF76AE7B2U, 0x998AD9F3U},
			{0xA41157F7U, 0x1E181950U, 0xE8DA3A7EU, 0xA9D7E1E6U, 0x8426B95FU, 0x963784EBU, 0x542E2A10U, 0x0EE4ED6EU}},
		{{0x9612FD83U, 0xBC4D35B8U, 0x5C4005E9U, 0xF477CA50U, 0xA87EECD1U, 0xB762203DU, 0x38082586U, 0x68AC9B22U},
			{0xCC783591U, 0x6696D659U, 0xD36352B4U, 0x254643DDU, 0x9DAD1D69U, 0xCDE370D9U, 0x62715DFAU, 0x9D7AF26CU}},
		{{0xAC751E7BU, 0xB79D4CC5U, 0xFD4211BDU, 0x93F96472U, 0xC8DE4FC6U, 0x8C72D3D2U, 0xDF44F064U, 0x7B69CBF5U},
			{0xF4BF94E1U, 0x3DA90CA2U, 0xF12894E2U, 0x1A5325F8U, 0x7917D60BU, 0x0A437F6CU, 0x96C9CB5DU, 0x9BE70486U}},
	},
	{
		{{0xE1337C26U, 0x949C9976U, 0xD73D68E5U, 0x6FAADEBDU, 0xF1B768D9U, 0x9E158614U, 0x9CC4F069U, 0x22DFA557U},
			{0xBE93C6D6U, 0xCCD6DA17U, 0xA504F5B9U, 0x24866C61U, 0x8D694DA1U, 0x2121353CU, 0x0140B8C6U, 0x1C6CA580U}},
		{{0xD4B79BB8U, 0xF1604A7DU, 0x52C878C8U, 0xAEE806FBU, 0x8D47B8E8U, 0x34144F11U, 0x949F9054U, 0x72EDF52BU},
			{0x2127015AU, 0xEBFCA84EU, 0x9CB7CEF3U, 0x9051D0C0U, 0x296DEEC8U, 0x86E8FE58U, 0x41010D74U, 0x33B28188U}},
		{{0x9AED9F40U, 0xBD5660EDU, 0x532A8C99U, 0x70CA6AD1U, 0x95C371EAU, 0xC4978BFBU, 0x7003109DU, 0xE5464D0DU},
			{0xD9E535EFU, 0x1AF32FDFU, 0x98C9185BU, 0xABF57EA7U, 0x12B42488U, 0xED7A7417U, 0xE97286FAU, 0x8E0296A7U}},
		{{0x171B445FU, 0x01079383U, 0x8131AD4CU, 0x9BCF21E3U, 0xC93987E8U, 0x8CDFE205U, 0xC92E8C8FU, 0xE63F4152U},
			{0x30ADD43DU, 0x729462A9U, 0xC980F05AU, 0x62EBB143U, 0x3B06E968U, 0x4F3954E5U, 0x242CF6B1U, 0xFE1D75ADU}},
		{{0x1F017D5EU, 0x8B57416EU, 0x7674E99BU, 0x37533396U, 0xE8F488A0U, 0x6E6D94C0U, 0xDC16F95EU, 0xB93A787AU},
			{0xDCC99CCCU, 0xC3AC51A2U, 0x9AA47C1DU, 0xC134B413U, 0xAFDFD8D5U, 0xF28FCDAFU, 0x10B831EDU, 0x0D57BD8EU}},
		{{0xF0BCFC46U, 0x9276FBCCU, 0xB5CFFEE6U, 0x3A822ACEU, 0xC75D915BU, 0x328ED2FEU, 0xC359476CU, 0xA145C113U},
			{0x8BE17BCDU, 0xF61A8153U, 0xAA6C3D8FU, 0x01E867C3U, 0x6516C82FU, 0x5634E15DU, 0x6948B9B0U, 0xC1437BD2U}},
		{{0x6C19D4C7U, 0xD2FCD200U, 0xE1B1E976U, 0xA0F3C437U, 0x94F237E8U, 0xF0545FF6U, 0xC0BF8BB1U, 0xDD10EC3FU},
			{0xAC7CD3E1U, 0x4F89696CU, 0x5F24BFE6U, 0xED3714ECU, 0x5FAF7706U, 0x363EB1D8U, 0xC027CC32U, 0xFCBD604DU}},
		{{0xAF8685C8U, 0x5F95C6C7U, 0x2F8F01AAU, 0xD4C1C8CEU, 0x2574692AU, 0xC44BBE32U, 0xD4A4A068U, 0xB8003478U},
			{0x2ECA3CDBU, 0x7C8FC6E5U, 0xEC04D399U, 0xEA1DB16BU, 0x8F2BC5CFU, 0xB05BC82EU, 0xF44793D2U, 0x763D517FU}},
		{{0xC355363BU, 0x16CE8EDDU, 0xF8820D6EU, 0x4AF2F70FU, 0x7661A508U, 0xCB7ED4D2U, 0xDD195472U, 0x41D3444EU},
			{0x38DA9649U, 0x17FEA2B4U, 0xAEB4A200U, 0x9BF69356U, 0x6AB19C3DU, 0xA13B5F91U, 0xDC9360A6U, 0xC0519C14U}},
		{{0x2E42E171U, 0xC2571AE9U, 0xED41CCF9U, 0xCB31AB63U, 0xB5C8854FU, 0x37F3C576U, 0xC62392A1U, 0x66E5191BU},
			{0x6CD5683BU, 0x71565A1CU, 0x606FE689U, 0x484B0283U, 0x67E2FDA6U, 0xF3A25D67U, 0x8A65C0A4U, 0x87BA21DEU}},
		{{0xA70684D1U, 0xDE74E49CU, 0x33E80C3DU, 0x3AE87661U, 0x16A5C34DU, 0x5984A2A9U, 0xB8298C35U, 0x09A83ECCU},
			{0xAA4CA4C0U, 0x9A19867CU, 0xB375B8FFU, 0x02085610U, 0xF70396DCU, 0xF296328BU, 0xDE6FAE63U, 0x9C9DDC4CU}},
		{{0x08BD98D0U, 0x4451C1B8U, 0x6575F240U, 0x644B1CD4U, 0x7375D270U, 0x6907EB33U, 0xFA2286BDU, 0x56C8BEBDU},
			{0xC4632B46U, 0xC713D2ACU, 0xAFD60242U, 0x17DA427AU, 0xC95C7546U, 0x313065B7U, 0xBF17A3DEU, 0xF8239898U}},
		{{0x0B083B6EU, 0x94683D26U, 0x06F6A54DU, 0x0A3752EBU, 0x752074DDU, 0x48BEDC23U, 0x3E822593U, 0x637622FCU},
			{0x6BE55D3BU, 0xEA000513U, 0x324D006DU, 0x9F5E12F4U, 0x64FC0270U, 0x529486A9U, 0x923399E6U, 0x09BA0D0CU}},
		{{0x3A977080U, 0x36385847U, 0x0C6A6AB6U, 0x4CF8E1B8U, 0x0482261EU, 0x919A5C6CU, 0xE5CE4806U, 0x517A9AD0U},
			{0x056AA7AAU, 0x2792D40CU, 0xE56C61B0U, 0x4C7C6ADAU, 0xA4B19E0CU, 0xF19CB178U, 0xE4BA267FU, 0x046D5C4FU}},
		{{0x121550B3U, 0xD3E926ABU, 0xC147CE84U, 0xE4975E4AU, 0x5EFF722AU, 0x7A8BE0F9U, 0x6FD4F2A0U, 0x71E4702CU},
			{0x3CB7B280U, 0x13B92ACFU, 0x28272D73U, 0xC588716DU, 0xDAA9FE5CU, 0x862C7BF3U, 0xE2A79E42U, 0x78C008F2U}},
		{{0x4C830320U, 0xF3B7963FU, 0x903203E3U, 0x842C7AA0U, 0xE7327AFBU, 0xAF22CA0AU, 0x967609B6U, 0x38E13092U},
			{0x757558F1U, 0x73B8FB62U, 0xF7ECA8C1U, 0x3CC3E831U, 0xF6331627U, 0xE4174474U, 0xC3C40234U, 0xA77989CAU}},
		{{0xF536FA1FU, 0xED5832C5U, 0x928244A4U, 0xE16F3F55U, 0xBF5BE190U, 0xF43A2621U, 0xCA2B6B2BU, 0xF7D672C3U},
			{0x827A5B83U, 0x64F86245U, 0x00E97F72U, 0xC1A109F5U, 0xA47327BBU, 0xC259785CU, 0x7F6A62B6U, 0xDAF109E9U}},
		{{0x57565120U, 0x88ABDF18U, 0xF25F2BF1U, 0xBF34BC72U, 0x6283EA40U, 0x0C216A22U, 0x072E18E4U, 0x573D2046U},
			{0x11BE8136U, 0x11110F6AU, 0xD6E4861BU, 0x10F32A84U, 0xEE297531U, 0x3EEDDEE2U, 0xD3404269U, 0xB3F37F99U}},
		{{0x1CC1D43AU, 0xCEA3F5E9U, 0x6A233AF4U, 0x624ACADBU, 0xD0EFE7C2U, 0xC9DF18A9U, 0x79BA79F3U, 0xFE0D0BE8U},
			{0x522FF5EAU, 0xC74C5A56U, 0x6C7D514EU, 0x4AC379F0U, 0xD70EA29FU, 0x64921404U, 0x0269F270U, 0x443EE591U}},
		{{0x44A081E0U, 0xE5FD17A1U, 0xB70E296AU, 0xD797FB7DU, 0x481F719CU, 0x2B472B30U, 0xFE6F8C52U, 0x0E632A98U},
			{0xC5F0C284U, 0x89CCD116U, 0x2D987C62U, 0xF51088AFU, 0x4C2DE6CFU, 0x2A2BCCDAU, 0xF679F0F9U, 0x810F9EFEU}},
		{{0xA61EA539U, 0x3874F443U, 0xC206FEDFU, 0x90A3A311U, 0x0FBD8785U, 0x962A7B5BU, 0x58C31C8BU, 0xFC37E970U},
			{0x5F1A1048U, 0xCDEB5538U, 0x8CCD6255U, 0x5A205122U, 0x9C4F1B8BU, 0x9762D496U, 0xD52F05DEU, 0x213D8803U}},
		{{0xE54C73F6U, 0x7C64377BU, 0x5A4EFBC0U, 0x65BFFE04U, 0x36F58541U, 0xD0D23063U, 0x25CDBDF0U, 0x54D6066FU},
			{0x5CF86D5BU, 0x685F2D63U, 0xF12EF6E5U, 0x8E51E9C1U, 0xCB346D82U, 0xA6AF042DU, 0x0073816FU, 0x37955079U}},
		{{0x13C5F7F4U, 0xC89CD3A7U, 0xAC352EEDU, 0x0D9CB54EU, 0x33B34788U, 0x462E7AEEU, 0x7C998D9AU, 0x831AF143U},
			{0x11E04F87U, 0xED8802C9U, 0x1938D969U, 0x1CA1A00BU, 0x7BBB9310U, 0x52805BB4U, 0x31C16410U, 0xCAA3CDE4U}},
		{{0x7FFE4B3EU, 0xB0F394B9U, 0xE5FA5D21U, 0x0B691D21U, 0x9DFBBC75U, 0xB0BD7747U, 0xFAF78B00U, 0xD2830FDAU},
			{0x52434F57U, 0xF78C249CU, 0x98096DABU, 0x4B1F7545U, 0x8FF8C0B3U, 0x73BF6F94U, 0x454E134CU, 0x34AEF03DU}},
		{{0x390BC059U, 0x2EB856D5U, 0x041312DFU, 0xC0EABD5FU, 0x8636D67BU, 0x7EEF45DFU, 0xDFEA7FB5U, 0x6909E81FU},
			{0x31DA7737U, 0x628E8C53U, 0x755B55BCU, 0x1B2F8BE3U, 0x137841D7U, 0x35BA0512U, 0x317CE57DU, 0x59550359U}},
		{{0xF5D16DC9U, 0xB251D407U, 0x4C72CC1CU, 0x541FAAAFU, 0xE58173CCU, 0xD28170ACU, 0x7B0C1B5AU, 0x1CC057C5U},
			{0x21062374U, 0x04B274E6U, 0xE2CB8C79U, 0xEFACCAA7U, 0x24EA9495U, 0xC466C3ECU, 0x67EF7C15U, 0xC3516EF3U}},
		{{0x45575C1CU, 0x34EF003BU, 0x49C2FE0CU, 0xDEB3E7A0U, 0xF7149C63U, 0x048EC01DU, 0xC79A986CU, 0x203869B9U},
			{0x6C1E80EFU, 0xCF7C4083U, 0x8E294447U, 0x210E17D5U, 0x1212601CU, 0x2B507D2EU, 0x5A17E279U, 0x98EDD3FAU}},
		{{0xB7AC7EC5U, 0xF8D151F4U, 0xE50DA7D5U, 0xD6CEB95AU, 0xDC3A0EB8U, 0xA1B492B0U, 0xB3DD2863U, 0x75157B69U},
			{0xC5413D62U, 0xE2C4C74EU, 0xBC5FC4C7U, 0xBE329FF7U, 0x60FA9DDAU, 0x835A2AEAU, 0x7445CB87U, 0xF117F5ADU}},
		{{0xE91D691DU, 0x9BF42636U, 0x8FC07BE4U, 0x0BCC3242U, 0x69E9AA90U, 0x5B205CAEU, 0x399CF75EU, 0x6F69722BU},
			{0x79424235U, 0x3DB059F6U, 0xA2205463U, 0x6B98B404U, 0x6F60F451U, 0x68CAF5E4U, 0xAD08939EU, 0xE8F1FC66U}},
		{{0x6346B21FU, 0x36661BD4U, 0x3CB69DF0U, 0xDE6FB01DU, 0xA884B40AU, 0x7D05A0E4U, 0xEF3D4ABFU, 0xD92569D4U},
			{0xE6B261F8U, 0x1C2BD7E1U, 0xC74DDBEFU, 0x0503B0E5U, 0xE09A4C37U, 0x6A361A39U, 0xE7FF8473U, 0x7FD57508U}},
		{{0xC776EDF8U, 0x1939FD67U, 0xCB5C848AU, 0xD0847C70U, 0x5ADE03D1U, 0x4FF55391U, 0xCFA9823EU, 0x8FB54D83U},
			{0xF10D4E04U, 0xB308146EU, 0xB6CB2A36U, 0x14A691B3U, 0xC620657FU, 0x2F419B93U, 0xD3E1DA7FU, 0x4DB7AAA2U}},
		{{0xB0166F7AU, 0xAE8317F4U, 0xCEEC74E6U, 0xFBD3E3F7U, 0xE0874BFDU, 0xFDB516ACU, 0xC681F3A3U, 0x3D846019U},
			{0x7C1620B0U, 0x0B12EE5CU, 0x2B63C501U, 0xBA68B4DDU, 0x6668C51EU, 0xAC03CD32U, 0x4E0BCB5BU, 0x2A6279F7U}},
	},
	{
		{{0x8F5FCDA8U, 0xFD8E139FU, 0xBDEE5BFDU, 0xF3E558C4U, 0xE33F9F77U, 0xD76CBAF4U, 0x71771969U, 0x3A4C97A4U},
			{0xF6DCE6A7U, 0xDA27E84BU, 0x13E6C2D1U, 0xFF373D96U, 0xD759A6E9U, 0xF115193CU, 0x63D2262CU, 0x3F9B7025U}},
		{{0x1A335CC8U, 0x8C318491U, 0x6A5913E4U, 0x563459BAU, 0xC7B32919U, 0x1B920D61U, 0xA02425ADU, 0x805AB8B6U},
			{0x8D006086U, 0x2AC512DAU, 0xBCF5C0FDU, 0x6CA4846AU, 0xAC2138D7U, 0xAFEA51D8U, 0x344CD443U, 0xCB647545U}},
		{{0xCDEDCA85U, 0x9F1B2466U, 0x1A09538CU, 0x140BB710U, 0x5E11115DU, 0xAC8AE851U, 0x6F03F59EU, 0x0D63FF67U},
			{0x7D234AFBU, 0x755E5551U, 0x7E208FC1U, 0x61C2DB4EU, 0xF28A4B5DU, 0xAA9859CEU, 0x34AF030FU, 0xBDD6D4FCU}},
		{{0x53544774U, 0x511053E4U, 0x3ADBA2BCU, 0x834D0ECCU, 0xBAE371F5U, 0x4215D7F7U, 0x6C8663BCU, 0xFCFD57BFU},
			{0xD6901B1DU, 0xDED2383DU, 0xB5587DC3U, 0x3B49FBB4U, 0x07625F62U, 0xFD44A08DU, 0x9DE9B762U, 0x3EE4D65BU}},
		{{0x717815DEU, 0x5A994B6EU, 0xA7E131D1U, 0xD995C7A0U, 0x26C023AAU, 0xC8B46DF2U, 0x702AFCEDU, 0x8CFD094DU},
			{0xCED6A886U, 0x7BC743CDU, 0x1FCABE75U, 0xB7D70EC4U, 0xDDAC9390U, 0x2A6C9E47U, 0x9310AA90U, 0x72069425U}},
		{{0x5464D0EBU, 0xD17E80F5U, 0x67A613A7U, 0x89D3E1A7U, 0xC8C97DADU, 0x77791260U, 0xE4F0CBE7U, 0xEC2FF21FU},
			{0xE9E6BC10U, 0xED984AC2U, 0x77CBA305U, 0xE3C53DE8U, 0x83624FDCU, 0x9BBAF9B2U, 0x1485C0ECU, 0x5E9451CDU}},
		{{0xB1761EC8U, 0x1F13756DU, 0xA4B97E55U, 0xE53C8B98U, 0x4096CC28U, 0xB2AEE3F8U, 0x920F1A8DU, 0x48C361A0U},
			{0x8C31190AU, 0xA98B672DU, 0x001855D4U, 0x7BC1E7D1U, 0xBF3F4B2AU, 0x242CFB07U, 0x32A28BC4U, 0x9BF44A3FU}},
		{{0x0D63D1FAU, 0x64E5137DU, 0x02A9D89FU, 0x658FC052U, 0x50436309U, 0x48894874U, 0xD598DA61U, 0xE9AE30F8U},
			{0x818BAF91U, 0x2ED710D1U, 0x8B6A0C20U, 0xE27E9E06U, 0x1C1A6B44U, 0x1E28DCFBU, 0xD6AC57DCU, 0x883ACB64U}},
		{{0x42E176A5U, 0x9982E2ACU, 0xE2782B64U, 0x324EBA46U, 0xE18350F5U, 0x3D8CAAAFU, 0xF5D674CAU, 0xF3D82AF2U},
			{0x56600D1EU, 0xC2090FEDU, 0x5950DE07U, 0x4548E0EFU, 0x765A4FEBU, 0xB2F0023FU, 0x39F16790U, 0xB3031033U}},
		{{0x61A3C8B3U, 0xA692781DU, 0x32876D0EU, 0x08BC3854U, 0x28027B03U, 0xBECF05FBU, 0xA4B1E12FU, 0x636C687DU},
			{0x07217C58U, 0x00E3003DU, 0x5E01B2A3U, 0x613BA937U, 0x881DE16EU, 0xA58C8405U, 0x14F8F48BU, 0xC653C430U}},
		{{0xD6A0D0F9U, 0xBC1C6897U, 0x3B0D7F55U, 0xD8E0EA0EU, 0xB85B7AADU, 0xB35BAA92U, 0x674E48F4U, 0x2BECD1B7U},
			{0x6D7A9AC2U, 0xE2D7F78DU, 0xF99C95D0U, 0xF5074262U, 0x89F611E9U, 0x4852470AU, 0x92869DECU, 0xF7AA9119U}},
		{{0x4E6DAAE2U, 0xED7F2E77U, 0x9E0A19BCU, 0x7B3AE0E3U, 0x91AE677EU, 0xD3293F8AU, 0x45C8611FU, 0xD363B0CBU},
			{0x309AE93BU, 0xBE1D1CCFU, 0x3920CAE1U, 0xA3F80BE7U, 0x498EDF01U, 0xAAACBA74U, 0xB2F5AC90U, 0x1E6D2A4AU}},
		{{0x233550F1U, 0x60C5F03FU, 0x925AFD2EU, 0xD4D09411U, 0xD258E5A6U, 0xA95B65C3U, 0x9F902C6AU, 0x1A19CFB5U},
			{0xF5AD5C68U, 0xB486013AU, 0x979638F3U, 0xA2506776U, 0xA38E0B28U, 0x1232B4D0U, 0xD36A7B4FU, 0xA64784B8U}},
		{{0x0266A696U, 0x7FCFA19EU, 0x92C3FB4BU, 0x5E1F64FDU, 0x506D19DFU, 0x6D954911U, 0x697A3CA1U, 0x9F989FE1U},
			{0x2327A87DU, 0x7E488D8CU, 0x037DA317U, 0xA543CE28U, 0xF93C5518U, 0xEA071D76U, 0x220A6D3BU, 0x585FFD48U}},
		{{0xE7D70E03U, 0x5655179DU, 0x72A84570U, 0x3E780C5CU, 0x1D50029CU, 0xC102B4CBU, 0xF075E839U, 0x3E71BDD5U},
			{0xB498B822U, 0x6460F4F0U, 0x6D4B8DA5U, 0x2682E06CU, 0x96A740D4U, 0x4EAE53C9U, 0x6389702CU, 0xC19D8BEFU}},
		{{0xC2C6FF70U, 0x8735728DU, 0xC5DC2235U, 0x79D6122FU, 0x19E277F9U, 0x23F5D003U, 0xDDED8CC7U, 0x7EE84E25U},
			{0x63CD880AU, 0x91A8AFB0U, 0x3574AF60U, 0x3F3EA7C6U, 0x02DE7F42U, 0x0CFCDC84U, 0xB31AA152U, 0x62D0792FU}},
		{{0xEE3B1655U, 0x959A47B2U, 0xEC883D5BU, 0xC799B9DDU, 0xB7933804U, 0x2DC09F80U, 0x3D2D3DB8U, 0xAE69E888U},
			{0x25E70AF4U, 0xC15D5E2FU, 0x05040085U, 0x875FD9CEU, 0x6B5A38F2U, 0x2850E8D0U, 0x9ABEB0DAU, 0x15227F35U}},
		{{0xE0E523F2U, 0x650F1037U, 0x9583013BU, 0x4438AB43U, 0xEFC0905EU, 0x034268FBU, 0x0C06776BU, 0x7B284BA2U},
			{0x1B6C1133U, 0x02B949C4U, 0x194BEF4FU, 0x7C3B8D47U, 0x0E7E0535U, 0x5FE15B00U, 0x28B126B4U, 0xC3266674U}},
		{{0xE0921144U, 0xF8B99342U, 0xB5033E2CU, 0xF14FC6F1U, 0xDCDACF54U, 0x7DFB3760U, 0xD88D7BA5U, 0xD25A0A31U},
			{0x68F74977U, 0x4DED2FCBU, 0x9A764007U, 0xF1884765U, 0xF2DCF4C7U, 0x879DB169U, 0xD16DF96AU, 0x744D75D5U}},
		{{0xBECCEFB5U, 0x40FDF5AAU, 0x3621D7C7U, 0xCF56EDE9U, 0x52B576C1U, 0xB632A9CEU, 0x9A6F6027U, 0xD3403AE8U},
			{0xE8785A64U, 0x660A050DU, 0x9682652EU, 0x10F3D647U, 0x4FBCBE02U, 0x78B25EDFU, 0xB4F9315DU, 0xC9710FDEU}},
		{{0x1E0235F9U, 0x0F88009AU, 0x4820B8A1U, 0x2FED4027U, 0x86081140U, 0xBE72B7ACU, 0x601163E3U, 0xD4162672U},
			{0x750C71EAU, 0xF71EA3ADU, 0xAFDC8BE3U, 0x02347140U, 0xC65AA66BU, 0xA5E66F29U, 0x07398FC8U, 0xF3C7EC64U}},
		{{0x179938A2U, 0x14096763U, 0x1C1CB877U, 0x4FBA0E71U, 0x7CCF7CCFU, 0xDA6F2A2FU, 0x091BDE65U, 0x91241A4EU},
			{0x1E71FCD8U, 0xCC2856C3U, 0x12441CC3U, 0xC0B87E7CU, 0xE5F224AAU, 0x3DD1681EU, 0xAD7308EAU, 0x30AED6F6U}},
		{{0x28B53E22U, 0xD4B8B017U, 0x0F7B7C71U, 0xE394D948U, 0xB21CAFDFU, 0xE21F2368U, 0x86CC7833U, 0xC911FAB6U},
			{0x39D1CCD7U, 0x0F61F6FDU, 0x248D90A9U, 0xE216EB8BU, 0xFC22D20DU, 0xA5058F44U, 0x57C69628U, 0x91269692U}},
		{{0x8A5807CEU, 0x8E1B4E43U, 0xE4109A7EU, 0xAD283893U, 0xAFD59DDAU, 0xC30CC9CBU, 0x3D8D8093U, 0xF65F36C6U},
			{0xA60D32B2U, 0xDF31469EU, 0x3E8191C8U, 0xEE93DF4BU, 0x355BDEB5U, 0x9C1017C5U, 0x8616AA28U, 0xD2623185U}},
		{{0xA448ED10U, 0x38ED4F64U, 0xC4EFB78BU, 0x81EB03A8U, 0x91323B52U, 0xBFD91B5CU, 0xB6BEFF2EU, 0xED882B33U},
			{0x6722D7A1U, 0xD0FB4551U, 0x949FE8ABU, 0x6F91441BU, 0x3AC181A6U, 0x63A44A99U, 0x950B6B74U, 0xF4A62B5FU}},
		{{0xE801A2CFU, 0x22614446U, 0x2E478CDFU, 0xFA3A2027U, 0x98C650B3U, 0x102A0C9AU, 0x4873FF70U, 0xC5009398U},
			{0xFAA16D01U, 0x87EC8606U, 0x9EDD4D8BU, 0x0FC12794U, 0x6F6BD460U, 0xE7A97A00U, 0x5EBEFF59U, 0xF69CD130U}},
		{{0x62B5A228U, 0x6209D186U, 0xD4408B26U, 0xB85D7DAAU, 0x8EB1B300U, 0x7E48110FU, 0x0464AAABU, 0x66783CD2U},
			{0x0F8BA061U, 0x2DF68B25U, 0xB2A08AEBU, 0x97E0C461U, 0xBD640D38U, 0x6F8F6F0EU, 0x41475DA6U, 0x993322E1U}},
		{{0x3245980EU, 0xD655ADE7U, 0x81067200U, 0xA6F59657U, 0xDB136BE1U, 0xE4FC23BEU, 0xAF13D879U, 0x9F246CDCU},
			{0xF961AC0EU, 0xC2B93117U, 0xEBDB9E1AU, 0xC8A741B5U, 0x6C693BD1U, 0x82EDE246U, 0x3DD1701EU, 0xFCDE6B4FU}},
		{{0xCAA4646FU, 0x1F804E00U, 0x70944924U, 0x8643DC88U, 0x73F86DE9U, 0xA37F1CA2U, 0x28889898U, 0xA3199F92U},
			{0x0C1E4ADFU, 0xC273BA58U, 0x65BC82F0U, 0x0F0D38AFU, 0xF8A6CD3BU, 0xD8B28AB5U, 0x75894D8EU, 0xEEA6E085U}},
		{{0x0EC93215U, 0x4642B998U, 0x299D349FU, 0xB719170AU, 0xBC36B5BAU, 0xB32C162BU, 0x4BD23CA2U, 0x06357385U},
			{0xDFF68115U, 0xFF416292U, 0x4BB5DB99U, 0xB7A150E3U, 0xA3C13D55U, 0xB97A2028U, 0xE5424506U, 0x86F406C1U}},
		{{0xB9CD95CFU, 0xFAB0C1B9U, 0x11A9AE73U, 0x3685ABB3U, 0xA996A9A3U, 0x02973EAFU, 0x2934571DU, 0xFF6F9BAFU},
			{0x257C40E8U, 0xE4AB8121U, 0xD92D30B1U, 0x09AD28E4U, 0x09E4B582U, 0x7C51A035U, 0xC35B120FU, 0x60BB01F8U}},
		{{0xDEC31A21U, 0xB02C83F9U, 0x6AD9D573U, 0x988C8B23U, 0xA57BE365U, 0x53E983AEU, 0x646F834EU, 0xE968734DU},
			{0x5DA6309BU, 0x9137EA8FU, 0xC1F1CE16U, 0x10F3A624U, 0xCA440921U, 0x782A9EA2U, 0x5B46F1B5U, 0xDF94739EU}},
	},
	{
		{{0xF4F8B16AU, 0x56F8410EU, 0xC47B266AU, 0x97241AFEU, 0x6D9C87C1U, 0x0A406B8EU, 0xCD42AB1BU, 0x803F3E02U},
			{0x04DBEC69U, 0x7F0309A8U, 0x3BBAD05FU, 0xA83B85F7U, 0xAD8E197FU, 0xC6097273U, 0x5067ADC1U, 0xC097440EU}},
		{{0xB311898CU, 0x3F747FA0U, 0xCD0EAC65U, 0xE2A272E4U, 0xF914D0BCU, 0x4BBA5851U, 0xC4A43EE3U, 0x7A1A9660U},
			{0xA1C8CDE9U, 0xE5A367CEU, 0x7271ABE3U, 0x9D958BA9U, 0x3D1615CDU, 0xF3FF7EB6U, 0xF5AE20B0U, 0xA2280DCEU}},
		{{0x3794F8DCU, 0x266344A4U, 0x483C5C36U, 0xDCCA923AU, 0x3F9D10A0U, 0x2D6B6BBFU, 0x81D9BDF3U, 0xB320C5CAU},
			{0x47B50A95U, 0x620E28FFU, 0xCEF03371U, 0x933E3B01U, 0x99100153U, 0xF081BF85U, 0xC3A8C8D6U, 0x183BE9A0U}},
		{{0x41DCA566U, 0xB6C185C3U, 0xD8622AA3U, 0x7DE7FEDAU, 0x901B6DFBU, 0x99E84D92U, 0x7C4AD288U, 0x30A02B0EU},
			{0x2FD3CF36U, 0xC7C81DAAU, 0xDF89E59FU, 0xD1319547U, 0xCD496733U, 0xB2BE8184U, 0x93D3412BU, 0xD5F449EBU}},
		{{0xE085116BU, 0x25470FABU, 0x87285310U, 0x04A43375U, 0xE2BFD52FU, 0x4E39187EU, 0x7D9EBC74U, 0x36166B44U},
			{0xFD4B322CU, 0x92AD433CU, 0xBA79AB51U, 0x726AA817U, 0xC1DB15EBU, 0xF96EACD8U, 0x0476BE63U, 0xFAF71E91U}},
		{{0xC97E6516U, 0xD74E9BDAU, 0xC230F49EU, 0x88779360U, 0x1E74EA49U, 0xA6EC1DE3U, 0x3FB645A2U, 0x581DCEE5U},
			{0x8F483F14U, 0xBAEF2391U, 0xD137D13BU, 0x6D2DDDFCU, 0xD2743A42U, 0x54CDE50EU, 0xE4D97E67U, 0x89A34FC5U}},
		{{0x49DEE168U, 0x72CFD2E9U, 0x3E2AF239U, 0x1AE05223U, 0x1D94066AU, 0x009E75BEU, 0x38ABF413U, 0x6CCA31C7U},
			{0x9BC49908U, 0xB50BD61DU, 0xF5E2BC1EU, 0x4A9B4A8CU, 0x946F83ACU, 0xEB6CC5F7U, 0xEBFFAB28U, 0x27DA93FCU}},
		{{0x4CD8F64CU, 0xC492EC64U, 0x279D7B51U, 0x58A2D790U, 0x1FC75256U, 0x0CED1FC5U, 0x8F433017U, 0x3E658AEDU},
			{0x05DA59EBU, 0x0B61942EU, 0x0DDC3722U, 0xBA3D60A3U, 0x742E7F87U, 0x7C311CD1U, 0xF6B01B6EU, 0x6473FFEEU}},
		{{0x76257C51U, 0x3CE519EFU, 0x18D477E7U, 0x6F5818D3U, 0x7963EDC0U, 0xAB022E03U, 0x8BD1F5F3U, 0xF0403A89U},
			{0x496033CAU, 0xE43B8DA0U, 0xA1CFDD72U, 0x0994E10EU, 0xBA73C0E2U, 0xB1EC6D20U, 0xB6BCFAD1U, 0x0329C9ECU}},
		{{0x2C84BD9DU, 0xF1FF42A1U, 0x390C674AU, 0x751F3EC4U, 0x01E5E0CAU, 0x27BB36F7U, 0x5CAF6692U, 0x65DFFF51U},
			{0xCD7BBD3FU, 0x5DF579C4U, 0x85591205U, 0xEF8FB297U, 0xE47AC732U, 0x1DED7203U, 0xCD1C331AU, 0xA93DC45CU}},
		{{0x3318D2D4U, 0xBDEC338EU, 0xBE8DE963U, 0x733DD7BBU, 0xA2C47EBDU, 0x61BCC3BAU, 0x35EFCBDEU, 0xA821AD19U},
			{0x024CDD5CU, 0x91AC668CU, 0xC1CDFA49U, 0x7BA558E4U, 0x908FB4DAU, 0x491D4CE0U, 0xF685BDE8U, 0x7BA869F9U}},
		{{0x81F41C78U, 0x7B2A0BCBU, 0x1FD240E1U, 0x5C522C85U, 0xDF5CE3F6U, 0xCE512E68U, 0xB6D5EE13U, 0xA7D4B952U},
			{0x31AD7EAFU, 0x8CDC0A8BU, 0x1B915E20U, 0x165E8675U, 0x5D6477F4U, 0x8E8C269BU, 0x44421B91U, 0xD28D5ADEU}},
		{{0x79F464BAU, 0xED1B5EC2U, 0x47D72E26U, 0x2D65E42CU, 0x9E67F926U, 0x8198E574U, 0x34747E44U, 0x41066738U},
			{0xE37E5447U, 0x4637ACC1U, 0xF3E15822U, 0x02CBC9ECU, 0x805AA83CU, 0x58A8E98EU, 0x5595E800U, 0x73FACD6EU}},
		{{0x32A92318U, 0x197CFDB3U, 0x25AC87B6U, 0x9EBEA841U, 0xA3510C7AU, 0x4CD805F7U, 0xE06E428EU, 0x24DF999AU},
			{0x4D71459CU, 0xD54DD5DCU, 0x20B8A03CU, 0x1484324FU, 0x3174B927U, 0x7924F2D9U, 0xF93ADE50U, 0x42B8ACBFU}},
		{{0x38330507U, 0x468FF803U, 0x4037A53EU, 0x06F34DDFU, 0x8D6993A4U, 0x70CD1A40U, 0x43E5C022U, 0xF85A1597U},
			{0xC125A67DU, 0x396FC9C2U, 0x1064BFCBU, 0x03B7BEBFU, 0xA9806DCBU, 0x7C444592U, 0x4487CD54U, 0x1B02614BU}},
		{{0x692AC542U, 0x8303604FU, 0x227B91D3U, 0xF079FFE1U, 0x15AAF9BDU, 0x19F63E63U, 0xF1F344FBU, 0xF99EE565U},
			{0xD6219199U, 0x8A1D661FU, 0xD48CE41CU, 0x8C883BC6U, 0x3C74D904U, 0x1065118FU, 0x0FAF8B1BU, 0x713889EEU}},
		{{0x0DE21BB6U, 0xB47B60F7U, 0xDCD836CAU, 0x64ACAE4FU, 0xC744CE63U, 0x3375EA6DU, 0xB047955BU, 0xB764265FU},
			{0x9841C2C3U, 0xC68A5D4CU, 0xCF454F60U, 0x60E98FD7U, 0x756AEA0CU, 0xC701FBE2U, 0xAAB21C79U, 0x09C8885EU}},
		{{0x91D1BDCFU, 0xCA1359EFU, 0xF3592586U, 0x6A082157U, 0x3951951CU, 0xD9AEA594U, 0xA2B7E706U, 0x57ABEF24U},
			{0x2E2EB1A2U, 0x3FA5721EU, 0x516ACE98U, 0x3C68EEACU, 0xC28782DFU, 0xFFA79D47U, 0x4E16577BU, 0xBDD69F63U}},
		{{0x69D2D46CU, 0x45BB8108U, 0x68C8365AU, 0xE47C8B39U, 0x267551BDU, 0xF3B87663U, 0x5B67547AU, 0x1590768FU},
			{0xFB2ED3FFU, 0x371C1DB2U, 0x17A59440U, 0xE3166919U, 0xDF242C14U, 0x03C0D178U, 0xED862AC1U, 0x40C93FCEU}},
		{{0xC5BB84AFU, 0x402B7960U, 0xBCC8A639U, 0xCF29C7DCU, 0x478F7C6DU, 0xFAF19DFFU, 0x3337BD22U, 0x71306AE4U},
			{0xBF599B7AU, 0xEF7C5505U, 0x9C4691A8U, 0xE09E159EU, 0x74CEB119U, 0xD403E818U, 0x5211A98DU, 0x5325E702U}},
		{{0x2BC982D6U, 0x1286DA69U, 0x7BDAE7E3U, 0x5F6D80F2U, 0xA6F064FBU, 0x3D9C5647U, 0xD74C1540U, 0xFDC8E6A1U},
			{0xD68B135AU, 0x97DA48C6U, 0xD66DBFFFU, 0xC2097979U, 0xEA20531DU, 0x0296ADB9U, 0x4AB2C8F0U, 0xA333730DU}},
		{{0x7A251933U, 0xAF97122BU, 0xC1233345U, 0x36C7349CU, 0x73F400B0U, 0x5687DE88U, 0x707595AFU, 0x922847A3U},
			{0x7FF6DEC1U, 0xB7E01858U, 0x2FC191CBU, 0x6E283ECEU, 0x1C20DC56U, 0x78C2EF8BU, 0x452ED2DCU, 0x51E6535EU}},
		{{0x29847FEDU, 0x0EB35654U, 0x0A673DD0U, 0xFDC14286U, 0x8B62DD0BU, 0x721B3627U, 0x711A5771U, 0x105A293EU},
			{0x7F761927U, 0xDF001CCEU, 0x11D04C7DU, 0xF7B681B0U, 0xA3AC1996U, 0x16DFF792U, 0x0FC4AE30U, 0x580C120BU}},
		{{0x960EB8C7U, 0xC035F697U, 0xE2DE04D3U, 0xF1599F2CU, 0xD2AD9228U, 0x892450F8U, 0xB829C1ABU, 0x7D48129BU},
			{0x3A50AFC9U, 0x24D785E1U, 0x63A96EE0U, 0x2745BA27U, 0x3BFB6D7BU, 0x95653401U, 0x1BAD2A42U, 0x53620267U}},
		{{0x7EE8D0BCU, 0x31EA3D4FU, 0x0F42C3DCU, 0x3832F22AU, 0x1A87A2F4U, 0xC661061AU, 0x4B45576BU, 0x0978C9F6U},
			{0x6DFB5FD2U, 0xB7ABAC3CU, 0xB7E01B90U, 0x27F36A00U, 0xE9429E36U, 0x68F733CDU, 0xDCBFE8CBU, 0x953A4681U}},
		{{0x4103C2E3U, 0xE396FF24U, 0x1B06ADE7U, 0x4133561CU, 0x65D0A734U, 0xE120B9ACU, 0x927919D9U, 0x576F6F07U},
			{0x691F955AU, 0xA0CFC846U, 0xA6449D65U, 0x3D2E2BC0U, 0x9767ED9BU, 0x7BA541B8U, 0xDC9215C7U, 0xD1B21B04U}},
		{{0x67FE1EAFU, 0xBFB7C410U, 0x6929A785U, 0xA2073C6AU, 0xA75FDB79U, 0x6F2536F4U, 0x809BCA69U, 0x859AD26DU},
			{0x3B197E7BU, 0x06F2C069U, 0x8EC0A573U, 0x656AD9F4U, 0x9A4D0262U, 0xE7C7901FU, 0xB938602BU, 0xBEC29443U}},
		{{0x0F0073A4U, 0xD00397FCU, 0x6F8D675FU, 0x5B668FA4U, 0x1522108CU, 0x14374AC9U, 0x0283E42EU, 0x92EFA7D1U},
			{0x0B6D024AU, 0x673E6DF9U, 0x57581F26U, 0x05F914D4U, 0x67DF8C12U, 0xF5C85162U, 0xE06C2462U, 0x1197F1B4U}},
		{{0xDD9C90C1U, 0x6E2D1CB3U, 0x7990579EU, 0x28F82D5AU, 0x06226195U, 0x90E189CDU, 0x19B0DC74U, 0xBD2939DFU},
			{0xC0917177U, 0x18B18505U, 0x3117D9C4U, 0xEED5470DU, 0x6C893CA0U, 0x39EF92EBU, 0x44A41940U, 0x4533EF82U}},
		{{0x2D2D7595U, 0x62AC853CU, 0x598FAD54U, 0x4883DAB7U, 0x6D32D7A4U, 0xBBF7F5D1U, 0xFD1DD881U, 0x95FB4F2DU},
			{0x545DC580U, 0xE239AEF2U, 0x4D1E39B9U, 0x4609A70AU, 0x338EBBB2U, 0x61D3B33EU, 0x15BD5461U, 0x06051DC2U}},
		{{0x34943DDAU, 0xCAEE9DECU, 0x8B4B6782U, 0x8E50E98EU, 0x91EA3A1FU, 0x24358EA5U, 0xA9E1C194U, 0x71C4C827U},
			{0x09BB7A94U, 0xA38BAA5DU, 0x57B58F9CU, 0xFB4AB4C0U, 0x24E0EE19U, 0x4A01065EU, 0x07B877BFU, 0xB9CF8051U}},
		{{0x81A1B3BEU, 0x972B3F8FU, 0xCE2764A0U, 0x4F3CE145U, 0x28C4F5F7U, 0xE2D0F1CCU, 0xC7F3985BU, 0xDEEE0C0DU},
			{0xD39E25C3U, 0x7DF4ADC0U, 0xC467A080U, 0x40619820U, 0x61CF5A58U, 0x440EBC93U, 0x422AD600U, 0x527729A6U}},
	},
	{
		{{0x3F73F449U, 0xEFB26A75U, 0x8D44FC79U, 0x1D1C94F8U, 0x3BC0DC4DU, 0x49F0FBC5U, 0x3698A0D0U, 0xB747EA0BU},
			{0x228D291EU, 0x5218C3FEU, 0x43C129D6U, 0x35B804B5U, 0xD1ACC516U, 0xFAC859B8U, 0x95D6E668U, 0x6C10697DU}},
		{{0xCB452FDBU, 0x6E30251AU, 0x50F30650U, 0x31EE6965U, 0x933548D9U, 0xB0B3E508U, 0xF4B0EF5BU, 0xB8949A4FU},
			{0x3C88F3BDU, 0x208B8326U, 0xDB1D9989U, 0xAB147C30U, 0x44D4DF03U, 0xED6515FDU, 0xE72EB0C5U, 0x17A12F75U}},
		{{0x28E3FE89U, 0x7A6CBBE0U, 0xC5AAC0EBU, 0xE7E1FEE4U, 0x697E5140U, 0x7F47EDA5U, 0xB454921FU, 0x4F450137U},
			{0x95CD8185U, 0xDB625F84U, 0xCDB2E583U, 0x74BE0BA1U, 0xDD5E6DE4U, 0xAEE4FD7CU, 0xE8101739U, 0x4251437DU}},
		{{0x81FDAD90U, 0x25914F78U, 0x0D2CF6ABU, 0xCF638F56U, 0xCC054DE5U, 0xB90BC03FU, 0x18B06350U, 0x932811A7U},
			{0x9BBD11FFU, 0x2F00B330U, 0xB4044974U, 0x76108A6FU, 0xA851D266U, 0x801BB9E0U, 0xBF8990C1U, 0x0DD099BEU}},
		{{0x517D7061U, 0x115EB20AU, 0x6C2DF683U, 0x77FE3433U, 0xCDC6FC67U, 0x6870DDC7U, 0x0B87DE83U, 0xB1610588U},
			{0xD9C4DDBEU, 0x343584CAU, 0x3D754BE2U, 0xB3164F1CU, 0xC1E6C894U, 0x0731ED3AU, 0x4F6B904CU, 0x26327DECU}},
		{{0xC61C3855U, 0x29267BAEU, 0x58C1FD3BU, 0xEBFF429DU, 0x8C0B93B8U, 0x22D886C0U, 0x2DDB8953U, 0xCA5E00B2U},
			{0xC3FED8B7U, 0xCF330117U, 0x819C01F6U, 0xD49AC6FAU, 0x3C0FBD54U, 0x6DDAA6BDU, 0x8049A2CFU, 0x91743068U}},
		{{0x7672765AU, 0x0A6A063CU, 0x0547B9BFU, 0x37A3CE64U, 0x98B1A633U, 0x42C099C8U, 0x05EE6961U, 0xB5AB800DU},
			{0x11A5ACD6U, 0xF1963F59U, 0x46201063U, 0xBAEE6157U, 0xA596210AU, 0x36D9A649U, 0x1BA7138CU, 0xAED04363U}},
		{{0x58D6CD46U, 0x14C6DD8AU, 0x8E6634D2U, 0x9CB633B5U, 0xF81BC328U, 0xC1305047U, 0x26A177E5U, 0x12EDE0E2U},
			{0x065A6F4FU, 0x332CCA62U, 0x67BE487BU, 0xC3A47ECDU, 0x0F47ED1CU, 0x741EB187U, 0xE7598B14U, 0x99E66E58U}},
		{{0xF51FE76EU, 0x36822876U, 0x11D62589U, 0x8A6811CCU, 0x46225718U, 0xC3FC7E65U, 0xC82FDBCDU, 0xB7DF2C9FU},
			{0xDD7B205BU, 0x3B1D4E52U, 0x47A2E414U, 0xB6959478U, 0xEFA91148U, 0x05E4D793U, 0xFD2E9675U, 0xB47ED446U}},
		{{0xEBF3232FU, 0x8F0ED0E2U, 0xC52A2EDDU, 0xFFF80F9EU, 0x75B55FDBU, 0xAD9AB433U, 0xE42E0C11U, 0x73CA7820U},
			{0xE6251B46U, 0x6DACE0A0U, 0x4C0D932DU, 0x89BC6B5CU, 0x095DA19AU, 0x3438CD77U, 0x8D48BDFBU, 0x2F24A939U}},
		{{0x5541B892U, 0x1D5DC451U, 0xFC9D9E54U, 0xB186EE41U, 0xD5BF610DU, 0x9D9F345EU, 0xF6ACCA9FU, 0x3E7BA65DU},
			{0xA8369486U, 0x9DDA787AU, 0x8EB5BA53U, 0x09F9DAB7U, 0xD6481BC3U, 0x5AFB2033U, 0xAFA62104U, 0x76F4CE30U}},
		{{0x7B0AC93DU, 0xEBD6A677U, 0x78F5E0D7U, 0xA6E37B0DU, 0x76F5492BU, 0x2516C096U, 0x9AC05F3AU, 0x1E4BF888U},
			{0x4DF0BA2BU, 0xCDB42CE0U, 0x5062341BU, 0x935D5CFDU, 0x82ACAC20U, 0x8A303333U, 0x5198B00EU, 0x429438C4U}},
		{{0x5A1F8E24U, 0x3F99183CU, 0x9DD255F0U, 0xFDB118FAU, 0xC27F62A6U, 0xB9B18B90U, 0x396EC191U, 0xE8F732F7U},
			{0x0BE786ABU, 0x524A2D91U, 0x0AC5A0F5U, 0x5D32ADEFU, 0x9725F694U, 0x9B53D4D6U, 0x0510BA89U, 0x032A76C6U}},
		{{0x5758B11CU, 0xA49B5D59U, 0xC8654F40U, 0x0B852893U, 0x52379447U, 0xB63EF6F4U, 0x105E690CU, 0xD4957D29U},
			{0x646559B0U, 0x7D484363U, 0x49788A8EU, 0xF4A8273CU, 0x34CE54A9U, 0xEE406CB8U, 0xF86FDA9BU, 0x1E1C260FU}},
		{{0x0E954750U, 0x9DBD7974U, 0x64F9D2C6U, 0x0121DE88U, 0xD985232EU, 0x2E597B42U, 0x53451777U, 0x55B6C3C5U},
			{0x519CB9FBU, 0xBB53E547U, 0x8428600DU, 0xF134019FU, 0xE081791AU, 0x5A473176U, 0x35FB0C08U, 0x2F3E2263U}},
		{{0x67E573E0U, 0xFB2838BEU, 0x4084C44BU, 0x05891DB9U, 0x96C1C2C5U, 0x91311373U, 0xD958444BU, 0x6AEBFA3FU},
			{0xE56E55C1U, 0xAC9CDCE9U, 0x2CAA46D0U, 0x7148CED3U, 0xB61FE8EBU, 0x2E10C7EFU, 0xFF97CF4DU, 0x9FD835DAU}},
		{{0x431D99DDU, 0x9BEDA18DU, 0xF3D5CCE1U, 0xF7690B3DU, 0xB7326EC9U, 0x97FB656DU, 0x8C95739CU, 0xC1B27144U},
			{0x9C21E298U, 0x65ECEA89U, 0x37355734U, 0xD0E57291U, 0x2165EB3DU, 0x80BD7C2BU, 0xDCC0F1C0U, 0xDF1E16E7U}},
		{{0x0C07C832U, 0x97E58FADU, 0x41C3439BU, 0x73EE50A4U, 0x8E1F0E20U, 0x230643A4U, 0xCEEBC6A3U, 0x533C7F8BU},
			{0x7163E1B5U, 0x4DA647B3U, 0x410B26FAU, 0x1A650D4CU, 0xDDE8FDFBU, 0x0DA53A64U, 0x88D80C73U, 0x0CE786DFU}},
		{{0x238F0ACAU, 0x19CF9227U, 0xABAC4CFDU, 0x6386ADD4U, 0x5E5CDE7FU, 0x17B6C4A0U, 0xC9AA5607U, 0x172B5758U},
			{0x5F01E78CU, 0x0FA265C5U, 0xDC124D1EU, 0x1FB2FDFBU, 0x9BF223F8U, 0xCF238D3CU, 0x0394BB6BU, 0x3C5C2C8DU}},
		{{0xC1770616U, 0x6C626F56U, 0x09DA9A2DU, 0x5351909EU, 0xA3730E45U, 0xE58E6825U, 0x03EF0A79U, 0x9D8C8BC0U},
			{0x056BECFDU, 0x543F78B6U, 0xA090B36DU, 0x33F13253U, 0x794432F9U, 0x82AD4997U, 0x4721F502U, 0x1386493CU}},
		{{0xD49ED714U, 0xDCC413F1U, 0x6AC2B4D8U, 0x18D3D627U, 0x5347BCF8U, 0x0F157A45U, 0x2694C944U, 0x4A13F412U},
			{0x397700DDU, 0xE3ABBF7CU, 0x6C4EEF39U, 0x72A88A91U, 0x4606479CU, 0xB149F8DBU, 0x54C2D3B3U, 0xFF44B1ABU}},
		{{0x4B833D09U, 0x8875AC36U, 0xF0ED5C9BU, 0xCAC97712U, 0x0281520DU, 0x7AF55D8FU, 0x46936237U, 0x06F7473BU},
			{0xFE6F84D6U, 0x8A5BCA51U, 0x84274FA7U, 0x764B6F4BU, 0xB964C01DU, 0xFA3091DCU, 0x0A3AB846U, 0x6D1F26F6U}},
		{{0x8AC0CFF0U, 0x0D0BF55FU, 0xC150EB54U, 0xD9598882U, 0x51C293D0U, 0x22A4A72CU, 0x643C198AU, 0xF86C57F6U},
			{0x20395710U, 0x97AB91B0U, 0x1970DBC0U, 0x9AE1716CU, 0xCCE53DF8U, 0x5B7A2BA2U, 0xFC85D64CU, 0xB2799A99U}},
		{{0x5ABEA82AU, 0x3794EEFAU, 0x93FE62D4U, 0x8DC611B9U, 0x281EF606U, 0x69F1AF37U, 0x39839E69U, 0x6AF546C8U},
			{0xC977EC23U, 0x625578C7U, 0xBD5C0576U, 0xA8DE294CU, 0x7CD1A4C0U, 0xE2DDAF0FU, 0x4F95F4D4U, 0x8243FC70U}},
		{{0x50E71812U, 0x94C5ABDAU, 0x03BB6A7CU, 0x02947435U, 0x798FBF14U, 0x02A153ABU, 0x7A2F284EU, 0xF8EF26C8U},
			{0x05F99EDCU, 0x863C925DU, 0x409B35DDU, 0x976D81E6U, 0xDCE99170U, 0xEF3A5A99U, 0x53131DE6U, 0xAABC80ECU}},
		{{0xC940B335U, 0x19417C64U, 0xAF6E97E9U, 0x51454EF5U, 0xED16309CU, 0x763C9BACU, 0x81464804U, 0xE26D174DU},
			{0x35197497U, 0xA05A4286U, 0xADEDB109U, 0xA410FA71U, 0xDA95F76EU, 0x7219CAB7U, 0xBE88D11FU, 0x74C323E7U}},
		{{0xB2DB103CU, 0xE1BB91D6U, 0x92E2C2E3U, 0xBE593DB1U, 0xB45E25C1U, 0x53F949CAU, 0x0A6E2F23U, 0x6A39E616U},
			{0x1357D70AU, 0x0213E26EU, 0x8E623E9CU, 0x73741C1AU, 0x8D9399B2U, 0x54DFA9BAU, 0x0C598C32U, 0x86310C40U}},
		{{0xB008733AU, 0xE566F400U, 0x512E1F57U, 0xCBA0697DU, 0x40509CD0U, 0x9537C2B2U, 0x57353D8CU, 0x5F989C69U},
			{0x4C3C2B2FU, 0x7DBEC972U, 0xFF031FA8U, 0x90E02FA8U, 0xCFD5D11FU, 0xF4D15C53U, 0x48314DFCU, 0xB3404FAEU}},
		{{0xB4CA5FEFU, 0xB6F0BBA3U, 0x0FD19008U, 0x4919FCE2U, 0x1BD12ADCU, 0x18B4D18DU, 0xC81C8E9CU, 0xB22F3A88U},
			{0xCC7C2949U, 0x86F5B12CU, 0x05DE987FU, 0xA2F61AD8U, 0xED727970U, 0x69742172U, 0xD7434EC7U, 0x3E9F2C8EU}},
		{{0x212C52B4U, 0xD1490EF8U, 0x00B75A7BU, 0x5B2FFDEAU, 0xBF958BA1U, 0xF2C7B23EU, 0x696CBAAAU, 0x43B42039U},
			{0x02BE3496U, 0x1F5BDE94U, 0x39EFA5C4U, 0x3ABE9D6BU, 0x47077E82U, 0x2A207FDEU, 0x65862928U, 0x3BC374FCU}},
		{{0x540604C4U, 0x35D40E1DU, 0x3A486FEDU, 0x16A4B33AU, 0xEE43A4A1U, 0x9170496CU, 0xAD948AAFU, 0x174ADBE1U},
			{0x5451DF99U, 0x8A47A30AU, 0x9E1791A1U, 0x7CCABDD1U, 0xECFCF12AU, 0x7112B53AU, 0xFAB5C6D2U, 0x561EB395U}},
		{{0x081E9387U, 0xA36DA109U, 0x8C935828U, 0xFB9780D7U, 0xE540B015U, 0xD5940332U, 0xE0F466FAU, 0xC9D7B51BU},
			{0xD6D9F671U, 0xFAADCD41U, 0xB1A2AC17U, 0xBA6C1E28U, 0xED201E5FU, 0x066A7833U, 0xF90F462BU, 0x19D99719U}},
	},
	{
		{{0x060B5F61U, 0xF431F462U, 0x7BD057C2U, 0xA56F46B4U, 0x47E1BF65U, 0x348DCA6CU, 0x41BCF1FFU, 0x9A38783EU},
			{0xDA710718U, 0x7A5D33A9U, 0x2E0AEAF6U, 0x5A779987U, 0x2D29D187U, 0xCA87314DU, 0xC687D733U, 0xFA0EDC3EU}},
		{{0xCB198AC7U, 0x1C894849U, 0x0F264665U, 0xA884A93DU, 0x9B200678U, 0x2DA964EFU, 0x009834E6U, 0x3C351B87U},
			{0xE2C4B44BU, 0xAFB2EF9FU, 0x3326790CU, 0x580F6C47U, 0x0B02264AU, 0xB8480521U, 0x42A194E2U, 0x8BA6F9E2U}},
		{{0x5EB03C0EU, 0x499B6AB6U, 0x72BC3FDEU, 0xF19B7954U, 0x6E3A80D2U, 0xA86B5B9CU, 0x6D42819FU, 0xE4377508U},
			{0xBB3EE8A3U, 0xC1663650U, 0xB132075FU, 0x75EB14FCU, 0x7AD834F6U, 0xA8CCC906U, 0xE6E92FFDU, 0xEA6A2474U}},
		{{0xD3C095F1U, 0x39D934ABU, 0xE4B76D71U, 0x04B261BEU, 0xE73E6984U, 0x1D2E6970U, 0x5E5FCB11U, 0x879FB23BU},
			{0xDFD75490U, 0x11506C72U, 0x61BCF1C1U, 0x3A97D085U, 0xBF5E7007U, 0x43201D82U, 0x798232A7U, 0x7F0AC52FU}},
		{{0x4B049136U, 0xCB4D20EEU, 0x356A4613U, 0x8B63BF12U, 0x70E08128U, 0x1221AEF6U, 0x4ACB6B16U, 0xE62D8C51U},
			{0x379E7896U, 0x71F64A67U, 0xCAFD7FA5U, 0xB25237A2U, 0x3841BA6AU, 0xF077BD98U, 0x3CD16E7EU, 0xC4AC0244U}},
		{{0x319D7682U, 0xB25101FBU, 0x0A982FEEU, 0xB0293129U, 0x0261B344U, 0x51C1C9B9U, 0xBFD371FAU, 0x0E008C5BU},
			{0x0278CA33U, 0xD866DD1CU, 0xE5AA53B1U, 0x666F76A6U, 0x6013A2CFU, 0xE5CFB779U, 0xA3521836U, 0x1D3A1AADU}},
		{{0x50F75F9CU, 0x3C5604FFU, 0x7E752B22U, 0x1D8EDDF3U, 0x3C9A1118U, 0x0EF074DDU, 0xCCB86D7BU, 0xD0FFC172U},
			{0x037D90F2U, 0xABD1ECE3U, 0x6055856CU, 0xE3F307D6U, 0x7E4C6DAFU, 0x422F9328U, 0x334879A0U, 0x902AAC66U}},
		{{0x567193ECU, 0x76B4131AU, 0xE5F6E70BU, 0xAF3C305AU, 0x031EEBDDU, 0x9587BD39U, 0x71BBE831U, 0x5709DEF8U},
			{0x0EB2B669U, 0x57059983U, 0x875B7029U, 0x4D80CE1BU, 0x0364AC16U, 0x838A7DA8U, 0xBE1C83ABU, 0x2F431D23U}},
		{{0xB940C71EU, 0x8E52874CU, 0xDB5F4B3AU, 0x211935A9U, 0x301B1DC3U, 0x94350492U, 0x29958620U, 0x33D2646DU},
			{0xEF911404U, 0x16B0D64BU, 0x9A3C5EF4U, 0x9D1F25EAU, 0x4A352C78U, 0x20F200EBU, 0x4BD0B428U, 0x43929F2CU}},
		{{0x38235D4EU, 0xE7812766U, 0x496E3298U, 0x1C62BD67U, 0x3F175BC8U, 0x8378660CU, 0x17AFDD4DU, 0x4D04E189U},
			{0x85A8068CU, 0x32A81601U, 0x92B29A85U, 0xDB58E4E1U, 0xC70D8A3BU, 0xE8A65B86U, 0x98A0403BU, 0x5F0E6F4EU}},
		{{0xE82C9F9EU, 0xD44636E6U, 0xC33A1043U, 0x711DB87CU, 0xAA8AEC05U, 0x6F431263U, 0x2744A4AAU, 0x43FF120DU},
			{0xAE77779BU, 0xD3BD892FU, 0x8CDC9F82U, 0xF0FE0CC9U, 0xF1C5B1BCU, 0xCA5F7FE6U, 0x44929A72U, 0xCC63A682U}},
		{{0x3F894AE0U, 0x2C2492B7U, 0xB75F18CEU, 0xF59DF3E5U, 0x8F53CAD0U, 0x7CB740D2U, 0xC4F01294U, 0x3EB585FBU},
			{0x32C7F717U, 0x17DA0C86U, 0xAF943F4CU, 0xEB8C795BU, 0xF67C51D2U, 0x4EE23FB5U, 0x68889949U, 0xEF187575U}},
		{{0xB38DFF6FU, 0x2834DA3EU, 0xEA636BE8U, 0xBE012C52U, 0x61DD37F8U, 0x292D238CU, 0x8F8142DBU, 0x0E54523FU},
			{0x036A05D8U, 0xE31EB436U, 0x1E93C0FFU, 0x83E3CDFFU, 0x50821DDFU, 0x3FD2FE0FU, 0xFF9EB33BU, 0xC8E19B0DU}},
		{{0xE822F0D0U, 0x3EA011A4U, 0x5A8704F8U, 0xBC647AD1U, 0x50C6820FU, 0xBB315B35U, 0xB7E76BECU, 0x863DEC3DU},
			{0xF017BFC7U, 0x01FF5D3AU, 0x976B8229U, 0x20054439U, 0x0BBD0D3BU, 0x067FCA37U, 0x7F5E3D0FU, 0xF63DDE64U}},
		{{0x5E9CA895U, 0x147D9052U, 0x972072DFU, 0x2F4DD31EU, 0xE6C6755CU, 0xA16FDA8EU, 0xCF196558U, 0xC66826FFU},
			{0x0CF43895U, 0x1F1A76A3U, 0x83C3097BU, 0xA9D604E0U, 0x66390E0EU, 0xE1908309U, 0xB3C85EFFU, 0xA50BF753U}},
		{{0xADF7CCCFU, 0x75D9BC15U, 0xDFA1E1B0U, 0x81A3E5D6U, 0x249BC17EU, 0x8C39E444U, 0x8EA7FD43U, 0xF37DCCB2U},
			{0x907FBA12U, 0xDA654873U, 0x4A372904U, 0x35DAA6DAU, 0x6283A6C5U, 0x0564CFC6U, 0x4A9395BFU, 0xD09FA4F6U}},
		{{0x6F568431U, 0x0D64F9A7U, 0x02F8898CU, 0xF848C27CU, 0x260B5BD5U, 0xF418ADE1U, 0x6973DEE8U, 0xC1F3E323U},
			{0x26C185DDU, 0x46E9319CU, 0x546F0AC4U, 0x6D85B7D8U, 0x247F9D57U, 0x427965F2U, 0xB0035F48U, 0xB519B636U}},
		{{0x6AA39DFFU, 0xB510B3B5U, 0x9F8E4D8CU, 0x59B43DA2U, 0x9E4C4B9FU, 0xA8CE31FDU, 0xC1303C01U, 0x0E20BE26U},
			{0xE8EE47C9U, 0x18187182U, 0x7DB98101U, 0xD9687CDBU, 0xA1E14FF6U, 0x7A520E4DU, 0x8836D572U, 0x429808BAU}},
		{{0xDDA9E5C6U, 0x682AC1E5U, 0xCAA9FC95U, 0x4E0D3C72U, 0x772BEA44U, 0x17FAAADEU, 0xAB0009C8U, 0x5EF8428CU},
			{0x460FF016U, 0xCC4CE47AU, 0x725281CBU, 0xDA6D12BFU, 0x0223AAD2U, 0x44C67848U, 0x36256E28U, 0x6E342AFAU}},
		{{0x6D16768EU, 0x174D4699U, 0x628BF217U, 0x9FC4FF6AU, 0x154E490DU, 0x77705A94U, 0x8D2D997AU, 0x9D96DD28U},
			{0xCE5D72C4U, 0x77E2D9D8U, 0xC11C714FU, 0x9D06C5A4U, 0x79E4A03EU, 0x02AA5136U, 0x030FF28BU, 0x1386B3C2U}},
		{{0x8BCEC9C2U, 0xB86186B6U, 0x680B9F06U, 0x7CF24DF9U, 0xC0D29281U, 0xC46B45EAU, 0x07B10E12U, 0xFFF42BC5U},
			{0x4D289427U, 0x12263C40U, 0xB4848EC4U, 0x3D5F1899U, 0xD040800CU, 0x11F97010U, 0x300FEB20U, 0xB4C5F529U}},
		{{0xEA40DC3AU, 0x26A42D69U, 0xAECC018FU, 0xDC84AD22U, 0x3270F04AU, 0x25C36C7BU, 0x50FA72EDU, 0x46BA6D47U},
			{0x93E58A8EU, 0x6C37D1C5U, 0x120C088CU, 0xA2394731U, 0xCB6E86DAU, 0xC3BE4263U, 0x7126D038U, 0x2C417D36U}},
		{{0xB07159D0U, 0x9D3D116DU, 0xC1896210U, 0xAE07A67FU, 0xBB961579U, 0x8FC84D87U, 0x1C1F8DD6U, 0x30009E49U},
			{0xE3132819U, 0x8A8CAF22U, 0xF23AB4FFU, 0xCFFA197CU, 0x205DD687U, 0x58103A44U, 0x0DED67A2U, 0x57B796C3U}},
		{{0x440E2229U, 0xCCA523BBU, 0x73EF4D04U, 0x324673A2U, 0x3E11EC39U, 0xAF3ADF34U, 0xDC5968D3U, 0x6136D7F1U},
			{0xB053A927U, 0x7A7B2899U, 0xAE067ECDU, 0x3EAA2661U, 0x02779CD9U, 0x8549B9C8U, 0xC53385EAU, 0x061D7940U}},
		{{0xB3E93CE7U, 0xD7D27A89U, 0x5D3A2C1BU, 0xF7B5A875U, 0x255B218AU, 0xB29E68A0U, 0x8AF76754U, 0xB533837EU},
			{0x579FAB2EU, 0xD1B05A73U, 0xECD74385U, 0xB41055A1U, 0x445E9115U, 0xB2369274U, 0xF520274EU, 0x2972A7C4U}},
		{{0xAAA2902BU, 0xE07141FCU, 0xE4F69AD3U, 0x539AD799U, 0x813F9FFDU, 0xA6453F94U, 0x375BC2F7U, 0xC58D3C48U},
			{0x5DC64E96U, 0xB3326FADU, 0xB240E354U, 0x3AAFCAA9U, 0xACA1E7A9U, 0x1D1B0903U, 0x1211B8A0U, 0x4CEB9767U}},
		{{0xC81710A0U, 0x5E942E79U, 0x27CCADD4U, 0x557E4A36U, 0x4BCF6D0CU, 0x72A2BC56U, 0x26D7B80CU, 0x09EE5F43U},
			{0xD4292F19U, 0x6B70DBE9U, 0x63F16B18U, 0x56F74C26U, 0x35FBB42AU, 0xC23DB0F7U, 0x6AE10040U, 0xB606BDF6U}},
		{{0x87032D58U, 0x1EB4DE46U, 0x5E2C79E0U, 0xC54F3D83U, 0x5D04EF23U, 0x07818DF4U, 0x673D41B4U, 0x55FAA9C8U},
			{0x89B95355U, 0xCED64F6FU, 0xB7415C84U, 0x4860D2EAU, 0x050EBAD3U, 0x5FDB9BD2U, 0x6685A5BFU, 0xDB53E0CCU}},
		{{0x8B1EA7B3U, 0x9A61D2A0U, 0xAE8B1485U, 0xD495AB63U, 0x87052F99U, 0x38740F84U, 0xB2974EEAU, 0x178EBE5BU},
			{0x5B36D17FU, 0x030BBCCAU, 0xAAF86EEAU, 0xB5E4CCE3U, 0x68F8E9E0U, 0xB51A0220U, 0x09EB3E75U, 0xA4348796U}},
		{{0xABFAE1CAU, 0x919FCA5FU, 0x1A21459BU, 0x937AFAACU, 0x1F66A4D2U, 0x9E0CA91CU, 0x23EC1331U, 0x194CC7F3U},
			{0x8AA11690U, 0xAD25143AU, 0x09B59E08U, 0xBE40AD8DU, 0xE750860AU, 0x37D60D9BU, 0xC6BF434CU, 0x6C53B008U}},
		{{0x1D3EC517U, 0xA661A0D0U, 0x512321AEU, 0x98744652U, 0xECA92598U, 0x084CA591U, 0x1DCB3FEBU, 0xA9BB9DC9U},
			{0x78B4C240U, 0x14C54355U, 0x610CAFDCU, 0x5ED62A3BU, 0x1B38846BU, 0x07512F37U, 0xB0E38161U, 0x571BB70AU}},
		{{0xEB6B242DU, 0x832D7080U, 0x3B71E246U, 0xD30BD023U, 0xBE31139DU, 0x7027991BU, 0x462E4E53U, 0x68797E91U},
			{0x6B4E185AU, 0x423FE20AU, 0x42D9B707U, 0x82F2C67EU, 0x4CF7811BU, 0x25C81768U, 0x045BB95DU, 0xBD53005EU}},
	},
	{
		{{0x9D8E68FDU, 0xE5F649BEU, 0x1B044320U, 0xDB0F0533U, 0xE0C33398U, 0xF6FDE9B3U, 0x66C8CFAEU, 0x92F4209BU},
			{0x1A739D4BU, 0xE9D1AFCCU, 0xA28AB8DEU, 0x09AEA75FU, 0xEAC6F1D0U, 0x14375FB5U, 0x708F7AA5U, 0x6420B560U}},
		{{0x6254DC41U, 0x9EAE499CU, 0x7A837E7EU, 0x7E293924U, 0x090524A7U, 0x74AEC08CU, 0x8D6F55F2U, 0xF82B9219U},
			{0x1402CEC5U, 0x493C962EU, 0xFA2F30E7U, 0x9F17CA17U, 0xE9B879CBU, 0xBCD783E8U, 0x5A6F145FU, 0xEA3D8C14U}},
		{{0x5E0DEE6EU, 0xDEDE15E7U, 0xDC628AA2U, 0x74F24872U, 0x7861BB93U, 0xD3E9C4FEU, 0x6187B2E0U, 0x56D4822AU},
			{0xC59826F9U, 0xB66417CFU, 0x2408169EU, 0xCA260969U, 0xC79EF885U, 0xEDF69D06U, 0xDC7D138FU, 0x00031F8AU}},
		{{0x0EBCF726U, 0x103C46E6U, 0x6231470EU, 0x4482B831U, 0x487C2109U, 0x6F6DFACAU, 0x62E666EFU, 0x2E0ACE97U},
			{0x1F8D1F42U, 0x3246A9D3U, 0x574944D2U, 0x1B1E83F1U, 0xA57F334BU, 0x13DFA63AU, 0x9F025D81U, 0x0CF8DAEDU}},
		{{0x00EE11C1U, 0x30D78EA8U, 0xB5E3DD75U, 0xEB053CD4U, 0xD58C43C5U, 0x9B65B13EU, 0xBD151663U, 0xC3AD49BDU},
			{0xB6427990U, 0x99FD8E41U, 0x707EAE1EU, 0x12CF15BDU, 0x1AABB71EU, 0x29AD4F1BU, 0x07545D0EU, 0x5143E74DU}},
		{{0xC88BDEE1U, 0x30266336U, 0x5876767CU, 0x25F29306U, 0xC6731996U, 0x9C078571U, 0xED552951U, 0xC88690B2U},
			{0x852705B4U, 0x274F2C2DU, 0x4E09552DU, 0xB0BF8D44U, 0x986575D1U, 0x7628BEEBU, 0x7F864651U, 0x407BE238U}},
		{{0xA639FC6BU, 0x0E5E3049U, 0x86003625U, 0xE75C35D9U, 0x5DCC1646U, 0x0CF35BD8U, 0x6C26273AU, 0x8BCACED2U},
			{0xB5536742U, 0xE22ECF1DU, 0x1A9E068BU, 0x013DD897U, 0x8A7909C5U, 0x17F411CBU, 0x861DD506U, 0x5757AC98U}},
		{{0x1E935ABBU, 0x85DE1F0DU, 0x154DE37AU, 0xDEFD10B4U, 0x369CEBB5U, 0xB8D9E392U, 0x761324BEU, 0x54D5EF9BU},
			{0x74F17E26U, 0x4D6341BAU, 0x78C1DDE4U, 0xC0A0E3C8U, 0x87D918FDU, 0xA6D77581U, 0x02CA3A13U, 0x66876015U}},
		{{0xF36658F0U, 0xC7313E9CU, 0x71F8057EU, 0xC433EF1CU, 0x1B6A835AU, 0x85326246U, 0x7C86394CU, 0xC8F05398U},
			{0xE983C4A1U, 0xFF398CDFU, 0x03B7B931U, 0xBF5E8162U, 0xB7B9045BU, 0x93193C46U, 0xA4A6E46BU, 0x1E4EBF5DU}},
		{{0x43A24FE7U, 0xF9942A60U, 0xFFB3492BU, 0x29C1191EU, 0x902FDE05U, 0x9F662449U, 0x6713C32DU, 0xC792A7ACU},
			{0xB737982CU, 0x2FD88AD8U, 0xA21E60E3U, 0x7E3A0319U, 0x7383591AU, 0x09B0DE44U, 0x8310A456U, 0x6DF141EEU}},
		{{0xE6D6F471U, 0xAEC1A039U, 0x1198D12EU, 0x14B2BA0FU, 0x3AEEE5ACU, 0xEBC1A160U, 0xE0B964CEU, 0x401F4836U},
			{0x4FD03F66U, 0x2EE43796U, 0xDD8F3F12U, 0x3FDB4E49U, 0x29380F18U, 0x6EF267F6U, 0x8DA64D16U, 0x3E8E9670U}},
		{{0x207674F1U, 0xBC19180CU, 0x33AE8FDBU, 0x112E09A7U, 0x6AAEB71EU, 0x99667554U, 0xE101B1C7U, 0x79432AF1U},
			{0xDE2DDEC6U, 0xD5EB558FU, 0x5357753FU, 0x81392D1FU, 0x3AE1158AU, 0xA7A76B97U, 0x4A899991U, 0x416FBBFFU}},
		{{0x0D4A9DCFU, 0x9E65FDFDU, 0x944DDF12U, 0x7BC29E48U, 0x3C856866U, 0xBC1A92D9U, 0x6E98DFE2U, 0x273C6905U},
			{0xCDFAA6B8U, 0x69FCE418U, 0x5061C69FU, 0x606BD823U, 0x6AF75E27U, 0x42D495A0U, 0x6D873A1FU, 0x8ED3D505U}},
		{{0x6AB25B6AU, 0xAF552841U, 0x2B1A4523U, 0xC6C0FFC7U, 0x21C99E03U, 0xAB18827BU, 0x9034691BU, 0x060E8648U},
			{0x93C7F398U, 0x5207F90FU, 0x82F8D10BU, 0x9F4A96CBU, 0x3AD0F9E3U, 0xDD71CD79U, 0xFC3A54F5U, 0x84F435D2U}},
		{{0x8E33787FU, 0x4B03C55BU, 0xA6384673U, 0xEF42F975U, 0x5051B9F0U, 0xFF7304F7U, 0x741C87C2U, 0x18ACA1DCU},
			{0x2D4BFE80U, 0x56F120A7U, 0x053E732CU, 0xFD823B3DU, 0x7537CA16U, 0x11BCCFE4U, 0x1B5A996BU, 0xDF6C9C74U}},
		{{0x904FC3FAU, 0xEE7332C7U, 0xC7E3636AU, 0x14A23F45U, 0xF091D9AAU, 0xC38659C3U, 0xB12D8540U, 0x4A995E5DU},
			{0xF3A5598AU, 0x20A53BECU, 0xB1EAA995U, 0x56534B17U, 0xBF04E03CU, 0x9ED3DCA4U, 0xD8D56268U, 0x716C563AU}},
		{{0x1D6178E7U, 0x27BA77A4U, 0x68A1FF8EU, 0xE4C80C40U, 0x0A13F63DU, 0x75011099U, 0xA61D46F3U, 0x7BF33521U},
			{0x10B365BBU, 0x0AFF218EU, 0x0FD7EA75U, 0x81021804U, 0xA4B3A925U, 0x05A3FD8AU, 0x9B3DB4E6U, 0xB829E75FU}},
		{{0x4D53E5FBU, 0x6BDC75A5U, 0xD52717E3U, 0x04A5DC02U, 0xE9A42EC2U, 0x86AF502FU, 0x2630E382U, 0x8867E8FBU},
			{0xBEC9889BU, 0xBF845C6EU, 0xCB47C98DU, 0x54F491F2U, 0x790C2A12U, 0xA3091FBAU, 0xC20F708BU, 0xD7F6FD78U}},
		{{0xACDE5E17U, 0xA569AC30U, 0x6852B4D7U, 0xD0F996D0U, 0x4609AE54U, 0xE51D4BB5U, 0x0DAED061U, 0x3FA37D17U},
			{0x34B8FB41U, 0x62A88684U, 0x9EFB64F1U, 0x99A2ACBDU, 0x6448E1F2U, 0xB75C1A5EU, 0x42B5A069U, 0xFA99951AU}},
		{{0x2F3B26E7U, 0x6D956E89U, 0xDA875247U, 0xF4709860U, 0x2482DDA3U, 0x3AD15179U, 0x017D82F0U, 0xD64110E3U},
			{0xFAD414E4U, 0x14928D2CU, 0x2ED02B24U, 0x2B155F58U, 0xCB821BF1U, 0x481A141BU, 0x4F81F5DAU, 0x12E3C770U}},
		{{0x9FFF8381U, 0xE49C5DE5U, 0x5BBEC894U, 0x11053232U, 0x454D88C4U, 0xA0D051CCU, 0x1F8E531BU, 0x4F6DB89CU},
			{0xCA563A44U, 0x34FE3FD6U, 0x58DA8AB9U, 0x7F5C2215U, 0x9474F0A1U, 0x8445016DU, 0xCB7D8A0AU, 0x17D34D61U}},
		{{0x1C474019U, 0x8E9D3910U, 0xD52CEEFBU, 0xCAFF2629U, 0xC1622C2BU, 0xF9CF3E32U, 0xE9071A05U, 0xD4B95E3CU},
			{0x1594438CU, 0xFBBCA61FU, 0x04AADEDFU, 0x1EB6E6A6U, 0x68E14940U, 0x853027F4U, 0xDFABDA9CU, 0x221D322AU}},
		{{0xB7CB179AU, 0xED8EA9F6U, 0xB7934DCCU, 0xDC7B764DU, 0x5E09180DU, 0xFCB13940U, 0xB47DC2DDU, 0x6629A6BFU},
			{0x9F5A915EU, 0xBFC55E4EU, 0x6204441EU, 0xB1DB9D37U, 0x930C5F53U, 0xF82D68CFU, 0xCBB605B1U, 0x17D3A142U}},
		{{0x308780F2U, 0xDD5944EAU, 0x3845F5E4U, 0xDC8DE761U, 0x7624D7A3U, 0x6BEABA7DU, 0x304DF11EU, 0x1E709AFDU},
			{0x02170456U, 0x95364376U, 0xC8F94B64U, 0xBF204B3AU, 0x5680CA68U, 0x4E53AF7CU, 0xE0C67574U, 0x0526074AU}},
		{{0xECD92AF6U, 0x95D8CEF8U, 0x6CD1745AU, 0xE6B9FA7AU, 0xA325C3E4U, 0x3D546D3DU, 0x9AE93AAEU, 0x1F57691DU},
			{0x9D2E1A33U, 0xE891F3FEU, 0xAC063D35U, 0xD430093FU, 0x5513A327U, 0xEDA59B12U, 0x5536F18FU, 0xDC2134F3U}},
		{{0x5C210286U, 0xAA51FE2CU, 0x1CAB658CU, 0x3F68AAEEU, 0xF9357292U, 0x5A23A00BU, 0x7EFDABEDU, 0x9A626F39U},
			{0x199D78E3U, 0xFE2B3BF3U, 0x71BBC345U, 0xB7A2AF77U, 0x1E59802CU, 0x3D19827AU, 0xB487A51CU, 0x823BBC15U}},
		{{0x99D0A422U, 0x856139F2U, 0xF456C6FBU, 0x9AC3DF65U, 0x701F8BD6U, 0xADDF65C6U, 0x3758DF87U, 0x149F321EU},
			{0x721B7EBAU, 0xB1ECF714U, 0x31A3312AU, 0xE17DF098U, 0xD5C4D581U, 0xDB2FD6ECU, 0x8FCEA1B3U, 0xFD02996FU}},
		{{0x7882F14FU, 0xE29FA63EU, 0x07C6CADCU, 0xC9F6DC35U, 0xB882BED0U, 0x46F22D6FU, 0xD118E52CU, 0x1A45755BU},
			{0x7C4608CFU, 0x9F2C7C27U, 0x568012C2U, 0x7CCBDF32U, 0x61729B0EU, 0xFCB0AEDDU, 0xF7D75DBFU, 0x7CA2CA9EU}},
		{{0x6F640F62U, 0xF58FECB1U, 0x39F51946U, 0xE274B92BU, 0x6288AF44U, 0x7F4DFC04U, 0xEAC329E5U, 0x0A91F32AU},
			{0xD6AABA31U, 0x43AD274BU, 0x0F6884F9U, 0x719A1640U, 0xDAF91E20U, 0x685D29F6U, 0x27E49D52U, 0x5EC1CC33U}},
		{{0x3B54A059U, 0x38F4DE96U, 0xEFBCFDB3U, 0x0E0015E5U, 0x4DBB8DA6U, 0x177D23D9U, 0x97A617ADU, 0x98724AA2U},
			{0xFDB6558EU, 0x30F0885BU, 0xC7899A96U, 0xF9F7A28AU, 0x872DC112U, 0xD2AE8AC8U, 0x73C3C459U, 0xFA0642CAU}},
		{{0xE7DFC8D6U, 0x15296981U, 0x1FB5B94AU, 0x67CD4450U, 0x0EDDFD37U, 0x0EC71CF1U, 0x9A8EDDC7U, 0xC7E5EEB3U},
			{0x81D95028U, 0x02AC8E3DU, 0x70B0E35DU, 0x0088F172U, 0xE1881FE3U, 0xEC041FABU, 0xD99E7FAAU, 0x62CF71B8U}},
		{{0xE0F222C2U, 0x5043DEA7U, 0x72E65142U, 0x309D42ACU, 0x9216CD30U, 0x94FE9DDDU, 0x0F87FEECU, 0xD6539C7DU},
			{0x432AC7D7U, 0x03C5A57CU, 0x327FDA10U, 0x72692CF0U, 0x280698DEU, 0xEC28C85FU, 0x7EC283B1U, 0x2331FB46U}},
	},
	{
		{{0xE457A477U, 0xA0158EEAU, 0xEE6DDC05U, 0xD19857DBU, 0x18C41671U, 0xB3265224U, 0x3C2C0D58U, 0x3FFDFC7EU},
			{0x26EE7CDAU, 0x3A3A5254U, 0xDF02C3A8U, 0x341B0869U, 0x723BBFC8U, 0xA023BF42U, 0x14452691U, 0x3D15002AU}},
		{{0x85EDFA30U, 0x5EF7324CU, 0x87D4F3DAU, 0x25976554U, 0xDCB50C86U, 0x352F5BC0U, 0x4832A96CU, 0x8F6927B0U},
			{0x55F2F94CU, 0xD08EE1BAU, 0x344B45FAU, 0x6A996F99U, 0xA8AA455DU, 0xE133CB8DU, 0x758DC1F7U, 0x5D0721ECU}},
		{{0x262A3539U, 0xF3CAE7E9U, 0x6670D59EU, 0x78A49D1DU, 0xC1C5E1B9U, 0x37DE0F63U, 0x69CB7C1CU, 0x3072C30CU},
			{0x77C850E6U, 0x1D278A52U, 0x1F6A3DE6U, 0x84F15F8FU, 0x592CA7ADU, 0x46A8BB45U, 0xE4D424B8U, 0x1912E3EEU}},
		{{0x79E5FB67U, 0x6BA7A920U, 0x70AA725EU, 0xE1331FEBU, 0x7DF5D837U, 0x5080CCF5U, 0x7FF72E21U, 0xE4CAE01DU},
			{0x0412A77DU, 0xD9243EE6U, 0xDF449025U, 0x06FF7CACU, 0x23EF5A31U, 0xBE75F7CDU, 0x0DDEF7A8U, 0xBC957822U}},
		{{0x365E668BU, 0xDC988086U, 0xAABDA5FBU, 0xADA8DCDAU, 0x255F1FBEU, 0xBC146B4CU, 0xCF34CFC3U, 0x9CFCDE29U},
			{0x7E85D1E4U, 0xACBB453EU, 0xF92358B5U, 0x9CA09679U, 0x240823FFU, 0x15FC2D96U, 0x0C11D11EU, 0x8D65ADF7U}},
		{{0xB0CE1C55U, 0x8CF7230CU, 0x0BBFB607U, 0x5B534D05U, 0x0E16363BU, 0xEE1EF113U, 0xB4999E82U, 0x27E0AA7AU},
			{0x79362C41U, 0xCE1DAC2DU, 0x91BB6CB0U, 0x67920C90U, 0x2223DF24U, 0x1E648D63U, 0xE32E8F28U, 0x0F7D9EEFU}},
		{{0x0296F4FDU, 0x775557F1U, 0xEA51B436U, 0x1DCA76A3U, 0xFB950805U, 0xF3E98F60U, 0x831CF7F1U, 0x31FF32EAU},
			{0x8D2C714BU, 0x643E7BF1U, 0x2E9D2ACAU, 0x64B5C339U, 0x6ADC2D23U, 0xA9FD9CCCU, 0xCC721B9BU, 0xFC2397ECU}},
		{{0xFA833834U, 0x6943F39AU, 0xA6328562U, 0x22951722U, 0x4170FC10U, 0x81D63DD5U, 0xAECC2E6DU, 0x9F5FA58FU},
			{0xE77D9A3BU, 0xB66C8725U, 0x6384EBE0U, 0x11235CEAU, 0x5845E24AU, 0x06A8C118U, 0xEBD093B1U, 0x0137B286U}},
		{{0xB48EC57DU, 0xF031182DU, 0x04B233B9U, 0x515D32F8U, 0x093AAD26U, 0x06BBB1D4U, 0x0D83D1ECU, 0x88A142FEU},
			{0x245C73F8U, 0x3B95C099U, 0x52EDCD32U, 0xB126D4AFU, 0x8FCB52E6U, 0xF8022C1EU, 0x0106D339U, 0x5A51AC4CU}},
		{{0x44ACE150U, 0xC589E1CEU, 0x4381E97CU, 0xE0F8D3D9U, 0x62C5A4B8U, 0x59E99B11U, 0xFD0EC9F9U, 0x90D262F7U},
			{0x283E13C9U, 0xFBC854C9U, 0xAEDC7085U, 0x2D04FDE7U, 0x47DCBECBU, 0x057D7765U, 0x9A76FA5FU, 0x8DBDF591U}},
		{{0x7C64A054U, 0xB7F70A1AU, 0x9DB43E79U, 0x0DC1C0DFU, 0x51FE63D6U, 0x6D0A4AE2U, 0x7F0C8ABFU, 0xE0D5E332U},
			{0x2B7ECEE8U, 0xFF550036U, 0x5D055008U, 0x3EA0E6F7U, 0xF24AC84FU, 0x30DEB62FU, 0x5D7116B7U, 0x936969FDU}},
		{{0x0DE1E578U, 0xD0150695U, 0xE9F72BC6U, 0x2E1463E7U, 0x1B39ECA5U, 0xFFA68441U, 0x7C037F2FU, 0x673C8530U},
			{0x747F91DAU, 0xD0D6A600U, 0xC9CB78E9U, 0xB08D43E1U, 0x27B5CEF5U, 0x0FC0C644U, 0xA60A2FD6U, 0x5C1D160AU}},
		{{0x2617CF7FU, 0x02DA7612U, 0xEEE35260U, 0xD6E25D4EU, 0xFD3533E9U, 0xB2FA5B0AU, 0xB9126F88U, 0xE76BB7B0U},
			{0x88856866U, 0x692E6A99U, 0x49DB65CAU, 0x3FDF394FU, 0x22D8D606U, 0x25296991U, 0x3DD7C4CFU, 0xE815BFBFU}},
		{{0x28C8E13BU, 0xF98CAE53U, 0xB2EDDCD1U, 0x375F10C4U, 0x5CCE06ADU, 0xD4EB8B7FU, 0x80A2E1EFU, 0xB4669F45U},
			{0x5BBD8699U, 0xD593F9D0U, 0xE7976D13U, 0x5528A4C9U, 0x1C7E28D3U, 0x3923E095U, 0x3F6BB577U, 0xB9293790U}},
		{{0x4D844E7FU, 0x69C984EDU, 0x4A2E8A82U, 0xD354B217U, 0xFB2C4136U, 0x25BD4ADDU, 0x144B26E1U, 0xF72DF4DEU},
			{0xE6101AFDU, 0xD0AA9DB0U, 0xE49BD1B8U, 0x4445EFAAU, 0x331593B2U, 0x5DC54EEEU, 0x094BF10BU, 0xFA35E3B9U}},
		{{0xC42BD6D2U, 0xDB567D6AU, 0xBB1F96AEU, 0x6DF86468U, 0x4843B28EU, 0x0EFE5B1AU, 0x6379B240U, 0x961BBB05U},
			{0x70A6A26BU, 0xB6CAF5F0U, 0x328E6E39U, 0x70686C0DU, 0x895FC8D3U, 0x80DA06CFU, 0xB363FDC9U, 0x804D8810U}},
		{{0x3EA089C3U, 0x660A0F89U, 0xC9009B09U, 0xA25823AAU, 0xA681F5E5U, 0xB2262D7BU, 0x3413863AU, 0x4FC30C8CU},
			{0xC32059F7U, 0x691544B7U, 0xB21C6134U, 0xF65CF276U, 0x5104DABAU, 0xE3A96B2AU, 0xA43EE42FU, 0xBB08D109U}},
		{{0x207F1670U, 0xBE22877BU, 0x4E615291U, 0x9B0DD188U, 0x97A3C2BFU, 0x625AE8DCU, 0x439B86E8U, 0x08584EF7U},
			{0xDCD898FFU, 0xDE7190A5U, 0x2058EE3DU, 0x26286C40U, 0x5F87B1C1U, 0x3DB0B217U, 0x102A6DB5U, 0xCC334771U}},
		{{0xF9916861U, 0x85A52D69U, 0xDA4FA813U, 0x595469A4U, 0x3338502FU, 0x1DD7786EU, 0x53963AC5U, 0x34B8EF28U},
			{0x1A891B25U, 0xC0F019F8U, 0x4F4BD775U, 0xB619970CU, 0xBE19F681U, 0x8C2A5AF3U, 0x98EC1728U, 0x9463DB04U}},
		{{0x2F770FB1U, 0xD99DE954U, 0x4CD7535EU, 0x97C1C620U, 0x3F09CEFCU, 0xD3B6C448U, 0x5A63B4F8U, 0xD725AF15U},
			{0xC01E20ECU, 0x0C95D24FU, 0x9AE7121FU, 0xDFD37494U, 0xEC77B7ECU, 0x7D6DDB72U, 0x0353A4AEU, 0xFE079D3BU}},
		{{0x01F39EABU, 0xEB62C278U, 0x0AB3A4AAU, 0x27DE3934U, 0xA982CA8DU, 0xFBD17520U, 0xE4BDC6EDU, 0x58817EC2U},
			{0x31C6AC13U, 0x312D78DEU, 0x09202EA6U, 0x9483BF76U, 0x22C6D8E1U, 0xF64AB8B6U, 0xE580DE74U, 0xDDDF589CU}},
		{{0x2E6AC8D2U, 0x3066E70AU, 0x106E5C05U, 0x9C6B5A43U, 0xEDE59B8CU, 0x52D3C6F5U, 0xFCCEC9AEU, 0x30D6A5C3U},
			{0x4FC0A9EFU, 0xEDEC7C22U, 0x95C16CEDU, 0x190FF083U, 0x94DE0FDEU, 0xBE12EC8FU, 0x852D3433U, 0x0D131AB8U}},
		{{0xEE98A92AU, 0xE0FA3336U, 0x66A4D745U, 0x7D80EEEFU, 0xBA0119D3U, 0xB612531BU, 0xB351FE15U, 0x86E770C1U},
			{0x82D5A397U, 0xAFBAD6F8U, 0x0DBF0110U, 0x1E5F1CB8U, 0x9F79063DU, 0x25138AC0U, 0x2746A156U, 0x089ED22FU}},
		{{0x85701291U, 0x42ACE07EU, 0x194061A8U, 0x94793ED9U, 0xD7F4A485U, 0x30E83ED6U, 0xF9EEFF4DU, 0x9EEC7269U},
			{0x0C9D8005U, 0x90ACBA59U, 0x1E79B9D1U, 0x5FECA458U, 0x1D506A1EU, 0x8FBE5427U, 0x2439CFA7U, 0xA32B2C8EU}},
		{{0x7D8B8DDEU, 0x198D1B5DU, 0x8DAB37FBU, 0xF32C1107U, 0x42B93874U, 0xF15FCB6DU, 0x41F94F84U, 0x91DDB74FU},
			{0x271524B2U, 0x6A64540AU, 0x758B5A64U, 0x950A0C12U, 0x3DCE9580U, 0xF9F23793U, 0x2CF8CE32U, 0xC8EDD0ABU}},
		{{0x73DD0B4EU, 0x1671C173U, 0x44A054C6U, 0x37A28214U, 0x4E8B53F1U, 0x81760A1BU, 0xF9F93B9EU, 0xA6C04224U},
			{0xCF671E3CU, 0x18784B34U, 0xCDA9B994U, 0x81BBECD2U, 0xB2AB3848U, 0x38831979U, 0xF2E03C2DU, 0xEF54FEB7U}},
		{{0xAE1046B7U, 0xEFC6357EU, 0x612932E4U, 0xE6704929U, 0xB1355B17U, 0xA20305D4U, 0x58B4A156U, 0x88A9136AU},
			{0xB4D275ECU, 0xBC379985U, 0x6EAF338BU, 0x718B9131U, 0xD152A509U, 0x61229A7AU, 0x45157AE9U, 0x1109F7C4U}},
		{{0xFB8088FAU, 0xCF197CA7U, 0x4DDC96C5U, 0x01427247U, 0x30777176U, 0xA2D2550AU, 0x4D0CF71DU, 0x53469898U},
			{0x3A2AAAC6U, 0x6CE937B8U, 0x5AF38D9BU, 0xE9F91DC3U, 0xC8BF2899U, 0x2598AD83U, 0xB5536C16U, 0x8E706AC9U}},
		{{0x0DF85C2CU, 0x2BDE4214U, 0x058A7A63U, 0x4FB839F4U, 0x47F51231U, 0x7C10572AU, 0x1989824EU, 0x87882623U},
			{0x16E1564AU, 0xA8293D20U, 0x18C04576U, 0xCB11C0F8U, 0x9740C631U, 0x83B91E7DU, 0xCBFFCEA0U, 0xBDCB23D0U}},
		{{0xF688DC98U, 0x40DC7495U, 0x124C4AFCU, 0x26490CD7U, 0x1F18775CU, 0xE651EC84U, 0xB4FDAF4AU, 0x393EA6C3U},
			{0x7F338E0DU, 0x1E1F3343U, 0x6053E7B5U, 0x39FB832BU, 0x619E14D5U, 0x46E702DAU, 0xCDEEF6E0U, 0x859CACD1U}},
		{{0x9094BFC8U, 0x64BDFD2AU, 0x0FC54D1EU, 0x8558ACC6U, 0xAF27721EU, 0x3992848FU, 0xA14CD009U, 0x7A8FCBDAU},
			{0x00A4B9C2U, 0x6DE61209U, 0x20CF8F28U, 0xBD192B1BU, 0x68D9BE83U, 0x2356B901U, 0x4A49A48AU, 0xCE1E7A94U}},
		{{0x4462007DU, 0x63B99CE7U, 0x4CB5F5B7U, 0xB8AB48A5U, 0xF55EDDE7U, 0x9EC673D2U, 0x8CFAEFDAU, 0xD1567F74U},
			{0x0887BCECU, 0x46381B6BU, 0xE178F3C2U, 0x694497CEU, 0x1E6266CBU, 0x5E6525E3U, 0x697D6413U, 0x5931DE26U}},
	},
	{
		{{0x1A93507AU, 0x142B5502U, 0x8D3C06CFU, 0xB4CD1187U, 0x91EC3F40U, 0xDF70E76AU, 0x4E7553C2U, 0x484E81ADU},
			{0x272E9D6EU, 0x830F87B5U, 0xC6FF514AU, 0xEA1C93E5U, 0xC4192A8EU, 0x67CC2ADCU, 0x42F4535AU, 0xC77E27E2U}},
		{{0xD0C05199U, 0x8CDA9CF2U, 0xFAE78454U, 0x502FBC22U, 0xF572A182U, 0xC0BDA9DFU, 0x6158B372U, 0x5F9B71B8U},
			{0x2B82DD07U, 0xE0F33A59U, 0x9523032EU, 0x76302735U, 0xC4505A32U, 0x7FE1A721U, 0xF796409FU, 0x7B6E3E82U}},
		{{0xEA37BA9EU, 0xB4C66356U, 0x0AFFF55DU, 0x1ADC8415U, 0x596CC862U, 0xF0080EF9U, 0x6D647AB6U, 0x756C85B8U},
			{0x1DB9C215U, 0xC9DB94AAU, 0x2013B1A5U, 0x2DD36DB1U, 0x4286C903U, 0xDE6AC61CU, 0xC76CF884U, 0x3FD32F88U}},
		{{0x35D0B34AU, 0xE3417BC0U, 0x8327C0A7U, 0x440B386BU, 0xAC0362D1U, 0x8FB7262DU, 0xE0CDF943U, 0x2C41114CU},
			{0xAD95A0B1U, 0x2BA5CEF1U, 0x67D54362U, 0xC09B37A8U, 0x01E486C9U, 0x26D6CDD2U, 0x42FF9297U, 0x20477ABFU}},
		{{0x11E9468DU, 0x31CA82ECU, 0x1CA05FA0U, 0xCF5D0EB6U, 0xAA962E73U, 0x49BAA305U, 0x4015E456U, 0xAD2B61B9U},
			{0x6C213835U, 0x6D2B8E5FU, 0x48F74763U, 0x0EF11C2BU, 0xC18BA768U, 0xA8CD7B5EU, 0x157ECCECU, 0x73C84DEFU}},
		{{0x51581E7DU, 0x13546AF6U, 0x39C7DB2EU, 0x0CE20B87U, 0xD9127C46U, 0xFAB1E2EDU, 0x6F35E6A8U, 0xBA9A1DC4U},
			{0x80690E7BU, 0x1B69666FU, 0x648890A0U, 0xD6530E3DU, 0x99C23E00U, 0x37BD4CB1U, 0xB7BA7A00U, 0xE7274E2CU}},
		{{0x6757243AU, 0x9FAC50B6U, 0x23F32472U, 0x8F417961U, 0xB372CBF4U, 0xEB367A56U, 0xB7799203U, 0xBE37E15CU},
			{0xDC4033DDU, 0x1B521FDFU, 0xAE8D8D7FU, 0x21F410EDU, 0xBDDC7547U, 0xBE6AF24EU, 0x6E18A74DU, 0x9965AE84U}},
		{{0x292A9287U, 0xA004DCB3U, 0x77B092C7U, 0xDDC15CF6U, 0x806C0605U, 0x083A8464U, 0x3DB997B0U, 0x4A68DF70U},
			{0x05BF7DD0U, 0x9C134E45U, 0x8CCF7F8CU, 0xA4E63D39U, 0x41B5F8AFU, 0xA6E6517FU, 0xAD7BC1CCU, 0xAA8B9342U}},
		{{0x16895AC1U, 0x6AA9B0CDU, 0xF28E4C37U, 0xADDCD353U, 0x6F90AE0AU, 0xFF473ABDU, 0x318A148EU, 0x76482409U},
			{0xCA192721U, 0xC5EB5ECCU, 0xFBD222AEU, 0x58542527U, 0x81B50D94U, 0x594852A9U, 0xE26A8CBAU, 0xA01F4E03U}},
		{{0xC2E0F94AU, 0xE11DC5F5U, 0x71986CC7U, 0x1FB6FA4EU, 0xA5B38D02U, 0x0FFC1996U, 0x9385403FU, 0x0E06268EU},
			{0xD01A6195U, 0x93D11F09U, 0x5D466517U, 0x05EB9640U, 0x77ED5ADFU, 0x63A885CCU, 0x35A0EA72U, 0xD507DC25U}},
		{{0xA94FC338U, 0x68E7AD81U, 0x5A224D9DU, 0x316C704BU, 0x4F26595FU, 0xE34FA938U, 0x98961836U, 0x86171FE9U},
			{0x3927496CU, 0x98991BC4U, 0xC68761D7U, 0xCE6FDB5AU, 0xB29E96D6U, 0x0A24FEFCU, 0xE5AC66A3U, 0xC72DFFA6U}},
		{{0x1E706AD9U, 0x126F35B5U, 0xC3A9EBDFU, 0xB99CEBB4U, 0xBF608D90U, 0xA75389AFU, 0xC6C89858U, 0x76113C4FU},
			{0x97E2B5AAU, 0x80DE8EB0U, 0x63B91304U, 0x7E1022CCU, 0x6CCC066CU, 0x3BDAB605U, 0xB2EDF900U, 0x33CBB144U}},
		{{0x8AE08A5BU, 0xB483143AU, 0xE60B2BA6U, 0x4E278FA1U, 0x317842FBU, 0x24B31C25U, 0x90CD3808U, 0xD4E4CF7CU},
			{0x695EF878U, 0x5CDF4D86U, 0x599A3AE8U, 0x362AAB50U, 0xB35844FCU, 0x22E00076U, 0xC8E71A04U, 0xA6876EB1U}},
		{{0xCE720DD9U, 0x73344BFFU, 0xFE3BE6A1U, 0x62A616C0U, 0x41EC162AU, 0x304117BCU, 0x3E13670DU, 0x79BEB1F6U},
			{0x68903A6DU, 0xCCAA3FC5U, 0xF531FEAFU, 0x999B57ACU, 0xDF173055U, 0xAB6395D7U, 0xFC72F80FU, 0x7B7F1D97U}},
		{{0xA6284AE6U, 0x489A91D9U, 0x69AD866BU, 0x47E6D431U, 0x39177F97U, 0x93E5E533U, 0x2C59EB80U, 0x235D2C8AU},
			{0x94E9C546U, 0xEDDE6977U, 0xD5934383U, 0xF94275BCU, 0xEC824653U, 0xAC2F71BFU, 0x17D03D8AU, 0x14520967U}},
		{{0x7AF715D2U, 0xC4176471U, 0xD0134A96U, 0xE2F7F594U, 0xA41EC956U, 0x2C1873EFU, 0x77821304U, 0xE4E7B4F6U},
			{0x88D5374AU, 0xE5C8FF97U, 0x80823D5BU, 0x2B915E63U, 0xB2EE8FE2U, 0xEA6BC755U, 0xE7112651U, 0x6657624CU}},
		{{0x8ACB4915U, 0xFD30B3ACU, 0xE1004B60U, 0x8C2218BFU, 0x4DC25DCCU, 0x80A64CFEU, 0x95D0B9DAU, 0x0506F26EU},
			{0x41C3EF37U, 0xABAA94FDU, 0x89BCEF26U, 0x2366D29DU, 0x4BE4EA63U, 0x6BD0E78FU, 0x2E21331FU, 0x0686F35FU}},
		{{0x0590D9CEU, 0xCB0FC7F3U, 0xEA0AD53BU, 0xC022C3D9U, 0x84BA2933U, 0xA9C429B3U, 0x9DB892CFU, 0xFCE65236U},
			{0x1F518D52U, 0x48702862U, 0x10383132U, 0x25DF7D1EU, 0xAA36795BU, 0x3F170EBDU, 0x34957E47U, 0xA931884FU}},
		{{0x5833F14AU, 0xDC39FBEAU, 0x88D50F33U, 0xB010A3C1U, 0x76F5752CU, 0xCD6145BCU, 0x7E12DE77U, 0x113B2521U},
			{0x041839A5U, 0x62417866U, 0x0EF309D7U, 0x95CA58CBU, 0xA2D02249U, 0x6D02CC9DU, 0xB8FD3ABBU, 0x8745B54BU}},
		{{0xDACE5ACAU, 0x157AF101U, 0x11A6A267U, 0xC4FDBCF2U, 0xC49C8609U, 0xDADDF340U, 0xE9604A65U, 0x97E49F52U},
			{0x937E2AD5U, 0x9BE8E790U, 0x326E17F1U, 0x846E2508U, 0x0BBBC0DCU, 0x3F38007AU, 0xB11E16D6U, 0xCF03603FU}},
		{{0x4ED3BCFEU, 0x0589150AU, 0x6CD80CB9U, 0xF462B65CU, 0x29531C5DU, 0x3412ADA8U, 0x2F14A675U, 0x90E969E7U},
			{0xC7B95B4CU, 0x486C8906U, 0xBCB4780CU, 0x5A67A94CU, 0xD22DF985U, 0xDE611513U, 0x481BE00CU, 0xBAB4869AU}},
		{{0xB8D98F1FU, 0x2FEAA4C5U, 0x41050250U, 0x7C09029CU, 0x1B56132FU, 0xD4FA4277U, 0xDA1235E5U, 0xECB257F1U},
			{0x6A46AEAFU, 0x617E2158U, 0xD4653EAEU, 0x65EFF300U, 0x03562A01U, 0xF67A13ADU, 0x70C77027U, 0x957FFA87U}},
		{{0x46C11C2FU, 0x89F2C490U, 0xD7D50818U, 0xBDBC06D6U, 0x82BE51E2U, 0x13DFC160U, 0xC1719895U, 0x710B3AF6U},
			{0x61DD8475U, 0x0BD54643U, 0x4544E029U, 0xA18A8ED3U, 0xDC3FBB7DU, 0xE11AD2CFU, 0x79E8788AU, 0xB177D79BU}},
		{{0x7442F1D5U, 0xD6F800E0U, 0x66E0E3ABU, 0x475607D1U, 0xB7C64047U, 0x82807F16U, 0xA749883DU, 0x8858E1E3U},
			{0x8231EE10U, 0x5859120BU, 0x638A1ECEU, 0x1B80E7EBU, 0xC6AA73A4U, 0xCB72525AU, 0x844423ACU, 0xA7CDEA3DU}},
		{{0x6B80ED3EU, 0x863A8DB0U, 0x75D3FA13U, 0x19A747E3U, 0x69C8F701U, 0x5A35CF2EU, 0xF8E5BBE9U, 0x769F0413U},
			{0x1D64E56AU, 0x3B6D36C0U, 0x456A9896U, 0xB9D92B32U, 0xCF8E9CDAU, 0x0D47CE70U, 0x6C019864U, 0x19E3355EU}},
		{{0x025123EDU, 0x7F101AACU, 0x93AD0606U, 0xF16E93EFU, 0x46CF85D1U, 0x89FE8948U, 0xF78E910EU, 0xE31D0CCBU},
			{0xD561F678U, 0xBCABAB1CU, 0x87C92833U, 0x7331E5C8U, 0x0E72F68DU, 0x6338AD26U, 0x35DB05C3U, 0x800C053EU}},
		{{0xA1B06B08U, 0x81E2EB76U, 0x8D7E82C9U, 0x81AE5578U, 0x48F78A96U, 0x03EC3E38U, 0x81A39B01U, 0x1BB4F753U},
			{0xEBEE8A26U, 0x424EB01CU, 0xD4AE8F2CU, 0x1311F7F5U, 0xAF8C01F1U, 0x153AB076U, 0x5E02C177U, 0x2EC94C83U}},
		{{0xF8AE7C38U, 0x5ED0C007U, 0x3D740192U, 0x6DB07A5CU, 0x5FE36DB3U, 0xBE5E9C2AU, 0x76E95046U, 0xD5B9D57AU},
			{0x8EBA20F2U, 0x54AC32E7U, 0x71B9A352U, 0xEF11CA8FU, 0xFF98A658U, 0x305E373EU, 0x823EB667U, 0xFFE5A100U}},
		{{0xDC8CEECFU, 0x46B7C800U, 0x815994A5U, 0xD6E49C2DU, 0xBB6256EAU, 0x6B7814FCU, 0x4A6E1022U, 0x7E8F51FCU},
			{0xCADE2038U, 0xF9805383U, 0x7454FBEAU, 0x9F762F31U, 0x65388068U, 0x5ABA0C29U, 0x721CB251U, 0xA27561FAU}},
		{{0x945E32CFU, 0x5C144938U, 0x5A8291A6U, 0x9E997E75U, 0xFC6E07D6U, 0x0570E846U, 0x1E74447DU, 0xE2681364U},
			{0x721FF2E2U, 0xBF1710CEU, 0xF814E83DU, 0xEA450819U, 0xED697AD2U, 0x27F0A70BU, 0x086B3F36U, 0x90369899U}},
		{{0xDB46CFDBU, 0xE9FF40FCU, 0x5E7E94C4U, 0x1B526715U, 0x9700B3BFU, 0xB8986BC5U, 0x0C8C3128U, 0xC98CAF59U},
			{0x301BBBEBU, 0xD1FB015DU, 0xBA2FD1A9U, 0x18E64F28U, 0xC0365B70U, 0x9212787EU, 0x98386C04U, 0xC64B51D0U}},
		{{0xE51732D2U, 0x57477B11U, 0x2538FC0EU, 0xDFD6EB28U, 0x3B39EEC5U, 0x5C43B0CCU, 0xCB36CC57U, 0x6AF12778U},
			{0x06C425AEU, 0x70B0852DU, 0x5C221B9BU, 0x6DF92F8CU, 0xCE826D9CU, 0x6C8D4F9EU, 0xB49359C3U, 0xF59ABA7BU}},
	},
	{
		{{0x421D3AA4U, 0xC37E2C2EU, 0xE84FA840U, 0xF926407CU, 0x1454E41CU, 0x18ABC03DU, 0x3F7AF644U, 0x26605ECDU},
			{0xD6A5EABFU, 0x242341A6U, 0x216B668EU, 0x1EDB84F4U, 0x04010102U, 0xD836EDB8U, 0x945E1D8CU, 0x5B337CE7U}},
		{{0xD23DDC82U, 0x4C076B86U, 0x7E0143F0U, 0x03FD344CU, 0x317AF2C5U, 0xA95362FFU, 0xE18B7A4FU, 0x0ADD3DB7U},
			{0x8260E01BU, 0x9C673E3FU, 0x54A1CC91U, 0xFBEB49E5U, 0x92F2E433U, 0x91351BF2U, 0x851141EBU, 0xC755E7ECU}},
		{{0xDA9F3804U, 0x349AE368U, 0xA164349CU, 0x470F07FEU, 0x8562BAA5U, 0xD52F4CC9U, 0x2B290DF3U, 0xC74A9E86U},
			{0x43471A24U, 0xD3A1AA35U, 0xB8194511U, 0x239446BEU, 0x81DCD44DU, 0xBEC2DD00U, 0xC42AC82DU, 0xCA3D7F0FU}},
		{{0xF23206D5U, 0x2BF5DB47U, 0x1D260152U, 0x2F6D3420U, 0x3F8FF89AU, 0x17B87653U, 0x378FA458U, 0x5157C30CU},
			{0x2D4FB936U, 0x7517C5C5U, 0xE6518CDCU, 0xEF22F7ACU, 0xBF847A64U, 0xDEB483E6U, 0x92E0FA89U, 0xF5084558U}},
		{{0x9B583160U, 0xB418C2A6U, 0xB4E59194U, 0xBE74FCD4U, 0x3C83E3FFU, 0xF178EEAAU, 0xE296F29BU, 0xE051F895U},
			{0x06CEB84AU, 0xD0235238U, 0xE111FE6BU, 0x5ACE48CEU, 0x1C045545U, 0x40E43A49U, 0xDD522146U, 0xF3FA86DDU}},
		{{0x908EC5B5U, 0x959616FAU, 0xA01AB12DU, 0x882D661DU, 0x4382AE8AU, 0xC49F6082U, 0x5D133F5EU, 0x5CDF92EBU},
			{0x5EF6C9C1U, 0x98CECC42U, 0x664D84EEU, 0xB52D6682U, 0x6F25B8C4U, 0x9E285ED8U, 0x48DEBE88U, 0xEB80CDC7U}},
		{{0xEC222BA0U, 0x2D9794C1U, 0x523E5D48U, 0xC3DFF42FU, 0x0FE4846BU, 0x4A7CD570U, 0xFF135174U, 0xEFC5B113U},
			{0xC6B05E85U, 0x2630B25BU, 0x654CD077U, 0x0A6D3029U, 0x32D8B89DU, 0xB4F1F54FU, 0x1627FC27U, 0xDE3BAFF2U}},
		{{0xDF7304D4U, 0xAB9659D8U, 0xFF210E8EU, 0xB71BCF1BU, 0xD73FBD60U, 0xA9A2438BU, 0x5D11B4DEU, 0x4595CD1FU},
			{0x4835859DU, 0x9C0D329AU, 0x7DBB6E56U, 0x4A0F0D2DU, 0xDF928A4EU, 0xC6038E5EU, 0x8F5AD154U, 0xC9429621U}},
		{{0xA4A2DF3EU, 0xB883B83BU, 0x44E5A363U, 0x045B7CC2U, 0x4E0D96DEU, 0xA42BD773U, 0x8D93C165U, 0xB9257547U},
			{0x73C8138EU, 0xE8F90126U, 0x607D84BFU, 0x5A8EE74DU, 0x49EA4363U, 0x1BECBB50U, 0x5ADA3286U, 0x1D4B6114U}},
		{{0xAA093B15U, 0xEBB678B5U, 0xD3E2B40CU, 0x0EACDF44U, 0x2089199FU, 0xBC4223C4U, 0x490A06A4U, 0x0E252BB4U},
			{0xCC2C5DF7U, 0x1E6479B5U, 0xBA94328AU, 0x8B6922D2U, 0x218B948CU, 0x4278CCE7U, 0xE6064F39U, 0x947E995CU}},
		{{0xF1D96994U, 0xCDF32D65U, 0xB75B2B18U, 0x8BB3D8F3U, 0xCB307798U, 0x5A95D2A3U, 0xCB15A8B5U, 0xDF8629CCU},
			{0x548C4926U, 0x375BDCBEU, 0x3C25B3A6U, 0x94AD58C6U, 0x8FAC4888U, 0xE94E0D52U, 0x69BA5BE3U, 0x9CBE7746U}},
		{{0xA70C6EC4U, 0x08A33840U, 0xE0311195U, 0x9E8819F7U, 0x708AB202U, 0xED209D96U, 0xCE943A27U, 0x10D7C4E7U},
			{0xA29B49A1U, 0x372FB317U, 0x46627D1FU, 0x57A67FB3U, 0x7CDF39ECU, 0xF912561EU, 0x6F7C8F17U, 0xFA3CE6F2U}},
		{{0x782FEDC1U, 0x04C16DE7U, 0x093AE7C4U, 0xFEE2C11AU, 0x3DDE90B1U, 0x357A7D85U, 0xCE6923DCU, 0x68136AF2U},
			{0x8E864536U, 0x0AAA9B44U, 0xFEAA1C2FU, 0x16B53452U, 0x5946D955U, 0xE8F494D1U, 0x3B1569E3U, 0xB5311651U}},
		{{0xBE51E3E7U, 0xDDEBFD7DU, 0x7F026831U, 0x0B25FC40U, 0xACE45FD1U, 0x4F3BAD3BU, 0x706809A7U, 0x8CB332BAU},
			{0xD6B93FCAU, 0x40E160B1U, 0x8B28BDEDU, 0x85368EDFU, 0x90B4C2FDU, 0x266F0A8CU, 0xFFAAD24FU, 0xAAD987F6U}},
		{{0x4E1B623BU, 0x9F310D42U, 0x816266A5U, 0xF045749BU, 0xA0DB7827U, 0x944FD751U, 0x681D7259U, 0x80120DA6U},
			{0x31A9C588U, 0x00CDD20DU, 0x97AE4BF1U, 0x7BF2ABD3U, 0x6B08C06AU, 0xF75A2290U, 0x4A12DC8BU, 0x0FA3E584U}},
		{{0xF23F2D92U, 0x91213462U, 0x60B94078U, 0x6CAB71BDU, 0x176CDE20U, 0x6BDD0A63U, 0xEE4D54BCU, 0x54C9B20CU},
			{0x9F2AC02FU, 0x3CD2D8AAU, 0x206EEDB0U, 0x03F8E617U, 0x93086434U, 0xC7F68E16U, 0x92DD3DB9U, 0x831469C5U}},
		{{0x69BA2241U, 0xF35E2CFEU, 0x8CF4D5BDU, 0x95446CE0U, 0xB8DB4F92U, 0xDCBA1BCDU, 0x5970D958U, 0x9679AE8EU},
			{0x40D5B94BU, 0x959CB445U, 0x33A31FD2U, 0xAD567814U, 0x1B002BC1U, 0xC7D4C3D1U, 0x8AC853E3U, 0x59A281CCU}},
		{{0xDD28B1CDU, 0xFD75AEC0U, 0x7A374DC2U, 0xC7120205U, 0x08F0622FU, 0xAB6A2BE4U, 0x12268B58U, 0xCB4AD0A1U},
			{0xF5193A94U, 0x34F8ED7CU, 0x1C459C2BU, 0xBACD167EU, 0x57BCE274U, 0x24CC6254U, 0x2D4060ECU, 0xF47164A8U}},
		{{0xE2AC751BU, 0x0F5D6E5AU, 0xD44D4569U, 0xC609B3F3U, 0x0B964C33U, 0x38C4AC80U, 0xC143C505U, 0xDEF9451BU},
			{0x394D7586U, 0x981F9295U, 0xD058A6D1U, 0x4C0D1E9BU, 0x07E8803DU, 0x76A4CF1CU, 0x4DDD01D6U, 0x2B5F7633U}},
		{{0x653F3C5FU, 0xFE7D7465U, 0xF040FEB1U, 0x283DD45EU, 0xF3B7EDFEU, 0x91FE599BU, 0x80379311U, 0x5FF039ADU},
			{0x4E96FA49U, 0xBF76995BU, 0xA3E25094U, 0x2640B6B2U, 0xC1C83F74U, 0x8B096341U, 0xFA560AC3U, 0xD2BEC884U}},
		{{0xB9F31405U, 0x096B576BU, 0x62B02B5EU, 0x40FC2287U, 0xE62F6118U, 0x42B2BDBBU, 0x7303491AU, 0x628D80F7U},
			{0x8F33BE96U, 0x897ED8FDU, 0x48498D0AU, 0x4D5669CAU, 0xE99C9DEFU, 0xF74C401AU, 0x6544B85AU, 0x7938EB5BU}},
		{{0xE7F21288U, 0x430BD312U, 0x8794E333U, 0x7381A725U, 0xB253D2FCU, 0x945D2F8BU, 0xBEA3FF9EU, 0x79593585U},
			{0x8DAF6006U, 0xB0C3F67FU, 0x19A6D877U, 0x7848D085U, 0x62211B4FU, 0x6E38701BU, 0x0506396DU, 0xAF07F06EU}},
		{{0x91FAB8FFU, 0xE59AC88DU, 0x3F7C96EDU, 0x2F5E1C0EU, 0xB4085079U, 0xFFF28A16U, 0x94E0C09FU, 0x8D765F9EU},
			{0xA00337BEU, 0xD2A53ECEU, 0x4AFAD088U, 0x98215DBDU, 0xA9238920U, 0xA32B6FA9U, 0x64D9ED2AU, 0xE1658015U}},
		{{0x8F981354U, 0x8521DF24U, 0x3588A259U, 0x587E23ECU, 0xD7A0992CU, 0xCBEDF281U, 0x38961407U, 0x06930A55U},
			{0xBE5BBE21U, 0x09320DEBU, 0x2491817FU, 0xA7FFA5B5U, 0x09065160U, 0xE6C8B4D9U, 0xFFF6D2A9U, 0xAC4F3992U}},
		{{0x567B9C76U, 0x5C5DC8F5U, 0x96D19AC6U, 0xAAE0CCBEU, 0xCF26A25FU, 0xD471F8A8U, 0x37365208U, 0x1DF9704AU},
			{0xA145DA05U, 0xABBC541BU, 0xF5B7D8AFU, 0x9D43323DU, 0xF1E253DDU, 0xA3AFB092U, 0xDBCB36CFU, 0xC4A7EB79U}},
		{{0xA3AA9123U, 0x2E4D6F15U, 0x384DD342U, 0x33FF9C8CU, 0x8F2D1B0CU, 0xB0168617U, 0xBD6D0562U, 0x66AED87DU},
			{0x4EA466E8U, 0x403176ACU, 0x1E10BE7BU, 0x154D8F0CU, 0x58D1A44BU, 0x5F75F776U, 0x33A53905U, 0xC9B29810U}},
		{{0xA47FB101U, 0x56BD73F5U, 0xFBBF59FBU, 0x36258684U, 0x864C842BU, 0x43C8DD38U, 0xF54E8703U, 0xF1466592U},
			{0xD10678C5U, 0x1137C392U, 0xF0D5918AU, 0x86A882DEU, 0x2D1033D0U, 0x8EE1D24DU, 0xE376E926U, 0x649CE162U}},
		{{0xCC53DA66U, 0x2E4EB2A3U, 0xF17A9B4EU, 0x04708A71U, 0x0DE05B2CU, 0xDBFDC7B2U, 0x4907A201U, 0x4CDC9AEEU},
			{0x6C475566U, 0xE5CC8DFCU, 0x47BE1691U, 0x2B83CBFBU, 0x4C05C3FDU, 0x695833A7U, 0x43B0DEB0U, 0xEE938A72U}},
		{{0x3F428F0FU, 0x07862577U, 0x4C3DED1FU, 0x9B63DBA9U, 0x356751BDU, 0x852AAE44U, 0x3B2F1C80U, 0xE2EC4911U},
			{0x73C420FBU, 0xEDB0F354U, 0x0BC255C3U, 0xD663CCABU, 0xCFAE46A9U, 0x1C3E015DU, 0x1F187D84U, 0x98558999U}},
		{{0xB78B3D1AU, 0x2CD34F1EU, 0x5FF84C0EU, 0x1713FAC6U, 0xC29CEC60U, 0xDEE9FAC9U, 0xB27AA552U, 0x53917BFDU},
			{0xEE64129FU, 0x896F534DU, 0xDBEB1EE0U, 0x76A523F2U, 0xD2591127U, 0xE1C13309U, 0xAD4CF66CU, 0x876F1D57U}},
		{{0xB576A3A9U, 0xC632C789U, 0x690DD7C8U, 0xCFC021F2U, 0xEB84AD6DU, 0xCF55EA32U, 0x72059566U, 0x6170B72BU},
			{0xCFA5F228U, 0xFBA05610U, 0x894CBF1AU, 0xC1B3DD15U, 0x314FF436U, 0xC6C524F0U, 0x07A1FFDDU, 0xB27E0C61U}},
		{{0x3AE9C1BDU, 0x7AA7A158U, 0xE37CE240U, 0xE0AF6D98U, 0x28AB38B4U, 0xE54342D9U, 0x0A1C98CAU, 0xE8B75007U},
			{0xE02358F2U, 0xEFCE86AFU, 0xEA921228U, 0x31B8B856U, 0x0A1C67FCU, 0x052A1912U, 0xE3AEAD59U, 0xB4069EA4U}},
	},
	{
		{{0x558DF019U, 0x9F51439EU, 0xAC712B27U, 0x230DA4BAU, 0x55185A24U, 0x518919E3U, 0x84B78F50U, 0x4DCEFCDDU},
			{0xA47D4C5AU, 0xA7D90FB2U, 0xB30E009EU, 0x55AC9ABFU, 0x74EED273U, 0xFD2FC359U, 0xDBEA8FAFU, 0xB72D824CU}},
		{{0xEF7D9289U, 0x549DB2B5U, 0x197F015AU, 0x2480D4A8U, 0xC40493B6U, 0x61D5590BU, 0x6F780331U, 0x3A55B52EU},
			{0x309EADB0U, 0x40EB8115U, 0x92E5C625U, 0xDEA7DE5AU, 0xCC6A3D5AU, 0x64D631F0U, 0x93E8DD61U, 0x9D5E9D7CU}},
		{{0x04C82BDDU, 0x1B7A588DU, 0xF8319DFDU, 0x68005534U, 0xD8EB9580U, 0xDE8A55B5U, 0x8D5BCA81U, 0x5EA886DAU},
			{0x252A0B4DU, 0xE8530A01U, 0x35EAA0A1U, 0x1BFFB4FEU, 0xD8E99563U, 0x2AD828B1U, 0x95F9CD87U, 0x7DE96EF5U}},
		{{0x1E84E0E5U, 0x19686041U, 0xAEA34C93U, 0xA5DB84D3U, 0x7073A732U, 0xF9D5BB19U, 0x6BCFD7C0U, 0xB8D2FE56U},
			{0xF3EB82FAU, 0x45775F36U, 0xFDFF8B58U, 0x8CB20CCCU, 0x8374C110U, 0x1659B65FU, 0x330C789AU, 0xB8B4A422U}},
		{{0x7EA973DCU, 0x745741E5U, 0x20888F2EU, 0x5C00CA70U, 0x45FD9CF1U, 0x7CDCE3CFU, 0x5507F872U, 0x8A741EF1U},
			{0x196B4CECU, 0x47C51C2FU, 0xC97EA618U, 0x70D08E43U, 0x15B18A2BU, 0x930DA15CU, 0x2F610514U, 0x33B6C678U}},
		{{0xAEDBAE9FU, 0xC925FF87U, 0x36880A54U, 0x7DAF0EB9U, 0x9C4D0E71U, 0x9284DDF5U, 0x316F8CF5U, 0x1581CF93U},
			{0x3AC1F452U, 0x3EECA887U, 0xFB6AEFFEU, 0xB417FCE9U, 0xEEFB8DC3U, 0xA5918046U, 0x02209400U, 0x73D318ACU}},
		{{0x9A85788BU, 0x6BA535DAU, 0xBD0626D4U, 0xD21F03AEU, 0xE873DC64U, 0x099F8C47U, 0x018EC97EU, 0xCDA8564DU},
			{0xDE92C68CU, 0x3E8D7A5CU, 0x73323CC4U, 0x78E035A1U, 0xF880FF7CU, 0x3EF26275U, 0x273EEDAAU, 0xA4EE3DFFU}},
		{{0xAF2EBC2FU, 0xC4F4CDA3U, 0xCB4EFE24U, 0xA0AF843DU, 0x9CCD10B1U, 0x53B857C1U, 0x914D3E04U, 0xDDC9D1EBU},
			{0x62771DEBU, 0x7BDEC8BBU, 0x91C5AA81U, 0x829277AAU, 0x832391AEU, 0x7AF18DD6U, 0xC71A84CAU, 0x1740F316U}},
		{{0xA56D73EDU, 0xBA9E5C88U, 0x2CA054D3U, 0x6C24F771U, 0x083BEAE1U, 0x4A37C235U, 0x6483E9FDU, 0x04A883B2U},
			{0xE27C2C5DU, 0x0C63F3AEU, 0xAE4671F1U, 0x0E1DA88DU, 0x5995E1DBU, 0xA577E8E2U, 0x6ED6066AU, 0xBFC4B1B1U}},
		{{0xE12B31F8U, 0xDD4A12D8U, 0x177736E6U, 0x577E29BCU, 0xA88935E8U, 0x2353722BU, 0x015F286DU, 0xCA1D3729U},
			{0x39A3E035U, 0x86C7B6A2U, 0xD3B03A9FU, 0x6E5250BFU, 0xFD0D536EU, 0x79D98930U, 0xFA0C3832U, 0x8C4CBBABU}},
		{{0xA43B2339U, 0x169B38C9U, 0x1732BFABU, 0x884308D9U, 0x8FF202DDU, 0xE4B593A2U, 0x1E65376CU, 0xAF51D11FU},
			{0x741525FFU, 0x6EC648DEU, 0x9FF4C628U, 0xF93CBD36U, 0xB1129C79U, 0xC76DF9EFU, 0xB7A67294U, 0x31A5F2E2U}},
		{{0xCAB91F1EU, 0x2D500910U, 0x4D1CD216U, 0xBEDD9E44U, 0xEDD02252U, 0xD634B74FU, 0x1258617AU, 0xBD60F8E1U},
			{0x9E05614AU, 0xD8C7537BU, 0xE7AF5FC5U, 0xFD26C766U, 0x582BD926U, 0x0660B581U, 0xACF07FC8U, 0x87019244U}},
		{{0xBADCFE8EU, 0x2C3B7322U, 0xC5E25A04U, 0x6E0616FAU, 0x3DA6E4A2U, 0x0A3C1275U, 0x077BCA01U, 0xE46C957EU},
			{0xDA4BE64BU, 0xB46CA4E3U, 0x8E75EE78U, 0xA59BDA66U, 0xA4DE98F2U, 0x41835184U, 0x4ED6A568U, 0x6EFB1F92U}},
		{{0xAF64ECB6U, 0xAFA26CCFU, 0x4BD72775U, 0xE6054F97U, 0x140F695AU, 0xBBCBAB5BU, 0xE348EFDEU, 0xBC71B4A4U},
			{0xCC96D963U, 0xFC2E52BEU, 0x5E5D9018U, 0x150ABF5FU, 0x04568771U, 0xBD182FA6U, 0x70339F83U, 0x35B4C061U}},
		{{0x11370605U, 0x4741B9B3U, 0x5D09B355U, 0x47FA72F7U, 0x7A144C6AU, 0x391A71ACU, 0x98B6E3CAU, 0x0808C0F4U},
			{0x7FE53900U, 0x7EAED9EFU, 0xE5A830BAU, 0xF157A2A5U, 0x27974AFCU, 0xD13EC091U, 0x0B87997DU, 0x78D710A7U}},
		{{0xEEAF8C49U, 0x8928E99AU, 0x6E24D728U, 0xEE7AA73DU, 0xE72B156CU, 0x4C5007C2U, 0xED408A1DU, 0x5FCF57C5U},
			{0xB6057604U, 0x9F719E39U, 0xC2868BBFU, 0x7D343C01U, 0x7E103E2DU, 0x2CCA254BU, 0xF131BEA2U, 0xE6EB38A9U}},
		{{0xCD201911U, 0x27E1D3ECU, 0xAD72C0EBU, 0xB1119A70U, 0x6AB57FFBU, 0xF8B3E3AFU, 0x5B92C42BU, 0x23C1685BU},
			{0xD08D7AAFU, 0x2C27B7B9U, 0x189A591CU, 0x0F660DC3U, 0xADC843CAU, 0x7BCAA102U, 0x1AB27652U, 0xDED38BB4U}},
		{{0x5F40FF52U, 0xC624A04EU, 0xFCD2914AU, 0x3611D7CFU, 0x1FD3BFD6U, 0xB7E8B42BU, 0xFA85063AU, 0x6CDE40FDU},
			{0x178B7E5BU, 0x7811C449U, 0x2972CC13U, 0x4CB60931U, 0x33B46135U, 0xF579125EU, 0x88A4E56EU, 0xCA102EF7U}},
		{{0x5DEF0B84U, 0x96BD677FU, 0x97DE99B9U, 0xE96FA87BU, 0x4EBE1553U, 0x5DD3FEC1U, 0x7E4275CDU, 0x315743E6U},
			{0xB1B48323U, 0x81F13125U, 0x4D498E75U, 0xC4AFB1DDU, 0x3F15DAD9U, 0x84568E7DU, 0xA3AE73B8U, 0xD8E3A61BU}},
		{{0x0A981B0DU, 0x0BA4E352U, 0xBD1A41A4U, 0x1C354CB3U, 0xDF9FAB9CU, 0x1AABAA3AU, 0x53C418D5U, 0x0701A7D1U},
			{0xDCF2B921U, 0xDD1A7CEFU, 0xBCF48061U, 0x6CEEF0B3U, 0xDE25CCE6U, 0x1083B598U, 0xE90A5E34U, 0x890A54C7U}},
		{{0x1C02CAF4U, 0xA62BB442U, 0xDB627B5AU, 0x6A74481DU, 0x2C6BF52DU, 0x1D5625F6U, 0x73B246A0U, 0x1FC5FD4CU},
			{0x1731813DU, 0x3F6DFC62U, 0xE58854BEU, 0x8322DF79U, 0xFA8B2EE4U, 0xE51438B2U, 0x2D4ACDA0U, 0xBE737848U}},
		{{0x40AC1807U, 0xC5359566U, 0x84DA0B1EU, 0xD4C1E566U, 0xE0B82421U, 0xC4B33F97U, 0x7B41BE00U, 0xD0BD2317U},
			{0x147B72E1U, 0x53A4B42EU, 0xF777104CU, 0xF8D39F5FU, 0xD3FB530DU, 0x36E64E64U, 0x56074FDDU, 0xA7A6BA67U}},
		{{0x1ECA7C71U, 0x1B658FE3U, 0xE4ADDAB8U, 0x20945214U, 0x11F9C299U, 0x7D4E5D3FU, 0x2F845004U, 0xD7F62AE7U},
			{0xE22A1E92U, 0x417E6D6AU, 0xCA4C7141U, 0x1AB67F85U, 0x279AB5EDU, 0x44B2D9C0U, 0xFA57CE11U, 0x2D0BF0B8U}},
		{{0x4F6D01B1U, 0x405718DBU, 0x8F11E8A0U, 0xE73C6BC2U, 0xA0591A3BU, 0xAC11BB8CU, 0x0ACC4531U, 0x12D09A5AU},
			{0xE7DE13F4U, 0xCBF174EEU, 0x044FD682U, 0x177E2BE6U, 0x1C48AF70U, 0x65F574CBU, 0x9961CB7CU, 0xCE596692U}},
		{{0x10F6BAE9U, 0x64836BFCU, 0x0A087608U, 0x6BD5616EU, 0x2F0B7807U, 0xCFD5C463U, 0x61A08578U, 0x05682712U},
			{0x630F2CCDU, 0x30303777U, 0xC2E2AB40U, 0x9EFDA732U, 0x6B0F9592U, 0xCA95B1C5U, 0xD0F2F2D8U, 0xF78FB23EU}},
		{{0xBC6FAB9FU, 0x989FE84EU, 0xC80F6474U, 0xE70CE6B1U, 0x3B02A1BCU, 0xBE9FF305U, 0x99C0AFD3U, 0x12EF4866U},
			{0xE3411A26U, 0x22D957F9U, 0x7B485B98U, 0x0B41D881U, 0x4AE20119U, 0x820E56D0U, 0x328528E0U, 0x81E3D01FU}},
		{{0xBE827C8AU, 0xD47DD477U, 0xEC10E44DU, 0xEE4A69E7U, 0x130ED77CU, 0xAF236038U, 0x804C65F0U, 0xF2045CCEU},
			{0x2A4B70DBU, 0xFB871903U, 0xB33C9FF5U, 0xFF36B3CCU, 0x1FD2783DU, 0x4C37F2E6U, 0x910071D6U, 0xE5117EDEU}},
		{{0x048752A1U, 0xC59EED6CU, 0xA01341B4U, 0x41F2702EU, 0x9DC6B092U, 0x6E35903BU, 0x1F5B5B23U, 0x4291ABA8U},
			{0xA653D61DU, 0x8173AA70U, 0x4F2EB51EU, 0xD1B648D4U, 0x5AB93F8FU, 0x31B7CE06U, 0x99E2F4FEU, 0xA55408EEU}},
		{{0xDADC4404U, 0x1BC4FA8BU, 0xDAA12EE3U, 0x0EDB9534U, 0xA5F7289CU, 0x084481B6U, 0x9D8FB3D2U, 0x7F42461DU},
			{0x12293C70U, 0xF93F1D32U, 0x6BB73EA3U, 0xC1470659U, 0xDE339CADU, 0xF80834AFU, 0x81F22953U, 0x99DCFC00U}},
		{{0x85E34160U, 0x1FA4ED09U, 0x7A03CDE2U, 0xA26D7DC3U, 0xFA84DF2DU, 0x1DAC0848U, 0x1B697108U, 0x5E9A28D6U},
			{0x14EA0EA1U, 0xA88004D9U, 0x3FFE5520U, 0xA8D15428U, 0x639B139CU, 0x4F422DAEU, 0xD4B5A861U, 0xEEDCCC0DU}},
		{{0xD7748ECDU, 0x541D1636U, 0x7B865C2EU, 0x385AABF0U, 0xE1DCE431U, 0xD2C2F9ECU, 0x8B95E052U, 0xFF160325U},
			{0x7A33077AU, 0x0CDE4C3FU, 0x12E41F97U, 0x675BDD56U, 0x71F5A6F1U, 0xC35181AEU, 0xAE753EF8U, 0xD55600C8U}},
		{{0x8BE762B4U, 0xB33E624FU, 0x058E3413U, 0x2A9EE4D1U, 0x67D805FAU, 0x968E6369U, 0x7DB8BFD7U, 0x9848949BU},
			{0xD23A8417U, 0x5308D7E5U, 0xF3E29DA5U, 0x892F3B1DU, 0x3DEE471FU, 0xC95C139EU, 0xD757E089U, 0x8631594DU}},
	},
	{
		{{0x1F095615U, 0x1083E2EAU, 0x14E68C33U, 0x0A28AD77U, 0x3D8818BEU, 0x6BFC0252U, 0xF35850CDU, 0xB585113AU},
			{0x30DF8AA1U, 0x7D935F0BU, 0x4AB7E3ACU, 0xADDDA07CU, 0x552F00CBU, 0x92C34299U, 0x2909DF6CU, 0xC33ED1DEU}},
		{{0x3E07113CU, 0x2DC40D48U, 0x7D8B63AEU, 0x6E4A5D39U, 0x79684C2BU, 0x5582A94BU, 0x622DA26CU, 0x932B33D4U},
			{0x0DBBF08DU, 0xF534F651U, 0x64C23A52U, 0x211D07C9U, 0xEE5BDC9BU, 0x0EEECE0FU, 0xF7015558U, 0xDF178168U}},
		{{0x83CDD60EU, 0xABE7905AU, 0xA1170184U, 0x50602FB5U, 0xB023642AU, 0x689886CDU, 0xA6E1FB00U, 0xD568D090U},
			{0x0259217FU, 0x5B1922C7U, 0xC43141E4U, 0x93831CD9U, 0x0C95F86EU, 0xDFCA3587U, 0x568AE828U, 0xDEC2057AU}},
		{{0x913CC16DU, 0x568F8925U, 0xE1A26F5AU, 0x18BC5B6DU, 0xF5F499AEU, 0xDFA413BEU, 0xC3F0AE84U, 0xF8835DECU},
			{0x65A40AB0U, 0xB6E60BD8U, 0x194B377EU, 0x65596439U, 0x92084A69U, 0xBCD85625U, 0x4F23EDE0U, 0x5CE433B9U}},
		{{0x42E06189U, 0x860D523DU, 0x4E3AFF13U, 0xBF077941U, 0xC1B20650U, 0x0B616DCAU, 0x2131300DU, 0xE66DD6D1U},
			{0xFF99ABDEU, 0xD4A0FD67U, 0xC7AAC50DU, 0xC9903550U, 0x7C46B2D7U, 0x022ECF8BU, 0x3ABF92AFU, 0x3333B1E8U}},
		{{0x84D6365DU, 0xC0DA65E7U, 0x8F759FB8U, 0xBCB7443FU, 0x7AE81930U, 0x35C712B1U, 0x4C6E08ABU, 0x80428DFFU},
			{0xA4FAF843U, 0xF19DAFEFU, 0xFFA9855FU, 0xCED8538DU, 0xBE3AC7CEU, 0x20AC409CU, 0x882DA71EU, 0x358C1FB6U}},
		{{0xBE42A582U, 0xEFECDEF7U, 0x65046BE6U, 0xD3FC6080U, 0x09E8DBA9U, 0xC9AF13C8U, 0x641491FFU, 0x1E6C9847U},
			{0xD30C31F7U, 0x3B574925U, 0xAC2A2122U, 0xB7EB72BAU, 0xEF0859E7U, 0x776A0DACU, 0x21900942U, 0x06FEC314U}},
		{{0x7E50122BU, 0x324794B0U, 0x4AF07CA5U, 0xDD744F8BU, 0xD63FC97BU, 0x30A12F08U, 0x76626D9DU, 0x39650F1AU},
			{0x1FA38477U, 0x101B47F7U, 0xD4DC124FU, 0x3D815F19U, 0xB26EB58AU, 0x1569AE95U, 0x95FB1887U, 0xC3CDE188U}},
		{{0xF4737F21U, 0x7EC62FBBU, 0x6209F5ACU, 0xD8DBA5ABU, 0xA5F9ADBEU, 0x24B5D7A9U, 0xA61DC768U, 0x707D28F7U},
			{0xCAA999EAU, 0x7711460BU, 0x1C92E4CCU, 0xBA7B174DU, 0x18D4BF2DU, 0x3C4BAB66U, 0xEB8BD279U, 0xB8F0C980U}},
		{{0x790691BFU, 0x9D658932U, 0x06B736AEU, 0xED610589U, 0xC0D63B6EU, 0x712C2F04U, 0xC63D488FU, 0x5CF06FD5U},
			{0xD9588E41U, 0x97363FACU, 0x2B93257EU, 0x1F9BF762U, 0x667ACACEU, 0xA9D1FFC4U, 0x0A061ECFU, 0x1CF4A1AAU}},
		{{0xC0519A23U, 0x28D675B2U, 0x4F6952E3U, 0x9EBF94FEU, 0xA2294A8AU, 0xF28BB767U, 0xFE0AF3F5U, 0x85512B4DU},
			{0x99B16A0DU, 0x18958BA8U, 0xBA7548A7U, 0x95C2430CU, 0xA16BE615U, 0xB30D1B10U, 0x85BFB74CU, 0xE3EBBB97U}},
		{{0xB2E63645U, 0x07B53F5EU, 0x84C84232U, 0xBE57E547U, 0x7214D5CFU, 0xD779C216U, 0x029A3ACAU, 0x617969CDU},
			{0x8A7017A0U, 0xD17668CDU, 0xBE9B7EE8U, 0x77B4D19AU, 0x9C161776U, 0x58FD0E93U, 0xD5968A72U, 0xA8C4F4EFU}},
		{{0xD2FDCA23U, 0x81EEB865U, 0xCC8EF895U, 0x5A15EE08U, 0x01905614U, 0x768FA10AU, 0x880EE19BU, 0xEFF5B8EFU},
			{0xCB1C8A0EU, 0xF0C0CABBU, 0xB8C838F9U, 0x2E1EE9CDU, 0x8A4A14C0U, 0x0587D8B8U, 0x2FF698E5U, 0xF6F27896U}},
		{{0xBF44DA80U, 0x519D34B3U, 0x5AB32E66U, 0x283834F9U, 0x6278A000U, 0x6E608797U, 0x627312F6U, 0x1E62960EU},
			{0xE6901C55U, 0x9B87B27BU, 0x24FDBC1FU, 0x80E78538U, 0x2FACC27DU, 0xBBBC0951U, 0xAC143B5AU, 0x06394239U}},
		{{0x9E2FCE99U, 0x9C4B646EU, 0x1E80857FU, 0x68A21081U, 0x3643B52AU, 0x06D54E44U, 0x0D8EB843U, 0xDE8D6D63U},
			{0x42146A0AU, 0x70321563U, 0x5EAA3622U, 0x8BA826F2U, 0x86138787U, 0x227A58BDU, 0x10281D37U, 0x43B6C03CU}},
		{{0x2F41DEFFU, 0x02B37A95U, 0xE63B89B7U, 0x0E44A59AU, 0x143FF951U, 0x673257DCU, 0xD752BAF4U, 0x19C02205U},
			{0xC4B7D692U, 0x46C23069U, 0xFD1502ACU, 0x2E6392C3U, 0x1B220846U, 0x6057B1A2U, 0x0C1B5B63U, 0xE51FF946U}},
		{{0xF02FC0F0U, 0x7ACA2632U, 0xC7F01C86U, 0xB92B337DU, 0x5AFBDC7DU, 0x624BC4BFU, 0x4DE21A5EU, 0x812B07BCU},
			{0x0B2090CCU, 0x29D13724U, 0x5A1B2132U, 0x0403C509U, 0x0E35E015U, 0x1DCA34D5U, 0x3BBBB66FU, 0xF085ED7DU}},
		{{0x2EAE5735U, 0xBEC86686U, 0xF9B6F03EU, 0x580501F2U, 0x990E74C2U, 0x8BFF2063U, 0x9F40C840U, 0xFADC4E3DU},
			{0x32EB6F2AU, 0x0357D3A0U, 0x0DF1C98AU, 0xE318B22EU, 0x502ADD38U, 0xBB9A2D8DU, 0x4A84CE6AU, 0x6F7E957AU}},
		{{0xF781E865U, 0xC27B98F9U, 0x994E1345U, 0x51E1F692U, 0xE19361EEU, 0x0807D516U, 0xFB998AEFU, 0x13885CEFU},
			{0x2F0F8A17U, 0xD223D5E9U, 0xE8D20280U, 0x48672010U, 0x237EAC98U, 0x6F02FD60U, 0x9ADA7EE7U, 0xCC51BFADU}},
		{{0x3D1F3648U, 0x0BE78D67U, 0x26F82644U, 0xB170AEBFU, 0x11AAA6F5U, 0x9D88B5AFU, 0x40930EB2U, 0x57444EB2U},
			{0x4AD92906U, 0xD0964A76U, 0xBFF87E5FU, 0x4CA05DE3U, 0x0B869084U, 0x1141A6C8U, 0x4ADA948DU, 0x3183FCA3U}},
		{{0x1E09701DU, 0x2756BCDDU, 0x90D45C80U, 0x94E31DB9U, 0x8566E584U, 0xB9E856A9U, 0xAB10E3F3U, 0x4F87D9DEU},
			{0x3DED9CB2U, 0x166ECB37U, 0x3F653D3EU, 0xFD14C707U, 0x92AEC425U, 0x105D049BU, 0x09A42E11U, 0x7F657E49U}},
		{{0xA5D609A1U, 0xC380A39BU, 0x24C10ECBU, 0x6C711E77U, 0xB922D070U, 0xE8D53CC6U, 0x0AB57D84U, 0xEAC37B81U},
			{0xA770CAA7U, 0xE260C978U, 0xAA71F4B5U, 0xDBF26129U, 0x489A8E30U, 0xE2EED9B6U, 0xEB3F75FEU, 0x488FD27FU}},
		{{0x6A159594U, 0xEA649007U, 0x1F97CE52U, 0x3E424D6BU, 0x185E8CCBU, 0xAC6DF30AU, 0x517747BFU, 0xAD56EC80U},
			{0x4391FE93U, 0xF0935CCFU, 0x03811D40U, 0x866B260FU, 0x9F7B9ABEU, 0x792047B9U, 0x8EE42D84U, 0xB1600BC8U}},
		{{0x7CA37123U, 0xDD584592U, 0x088BBDD5U, 0x903F1311U, 0xA2C2272EU, 0xDCDECF65U, 0xD61F6FE0U, 0x9E356E26U},
			{0x54480DC0U, 0xEEAD9F9DU, 0x1446BE5AU, 0x91CAA140U, 0xC4C075D1U, 0x9C66CC8DU, 0xBC85C9B8U, 0x5E529A62U}},
		{{0x7768A85FU, 0x2D97B3DBU, 0x4287E038U, 0x2B78F633U, 0x6F892BB1U, 0x86C94767U, 0xC0A9C200U, 0x920BFB1AU},
			{0x332041B2U, 0x4292F6ECU, 0xC9989D54U, 0xA30BB937U, 0xC6D5879EU, 0x39F941EBU, 0xDFDBB187U, 0x76A450FCU}},
		{{0x9C29A890U, 0x5FB793C3U, 0x87A811B1U, 0xB0A03BFDU, 0x12F128D3U, 0xB0249E49U, 0x5AED3EDEU, 0x107B3A13U},
			{0x2034D932U, 0x98E19956U, 0x0DC7D71CU, 0xD8CEC771U, 0xB231E0B2U, 0xE7563713U, 0xAC968C02U, 0x6284D285U}},
		{{0xEE430DB6U, 0x31256089U, 0xF6836F56U, 0xAECE9BD8U, 0xFB85A046U, 0x484CFC4BU, 0x1599B2B9U, 0xEE1E3E2CU},
			{0x3D122EAFU, 0x7E3C3890U, 0xC770556CU, 0xAA940CE0U, 0x1B08FAE8U, 0x4802D663U, 0x7F69F8BAU, 0xB08A8580U}},
		{{0x05411EAEU, 0x70ED0A04U, 0x16494C66U, 0x60DEB08FU, 0x133797BBU, 0x8CF20FC6U, 0x0C6BC310U, 0x3E30F4F5U},
			{0x749C46C7U, 0x1A677C29U, 0xF11E981CU, 0xFE1D93F4U, 0x2E3E688BU, 0x937303D8U, 0xA6AA9E85U, 0x01AEF5A7U}},
		{{0xB959B920U, 0x4902F495U, 0xFCA2D885U, 0x13B0FDBDU, 0xB6A2F0FAU, 0x41CBD9E7U, 0x56430B87U, 0xF9BDF110U},
			{0x954D19B9U, 0xD705A223U, 0x972A4FDEU, 0x74D0FC5CU, 0x912977EAU, 0xCBCBFED6U, 0xCC59A5AFU, 0x870611FDU}},
		{{0xBB302F57U, 0xBA7219ABU, 0xFAB32730U, 0x28CE0059U, 0xA8F54322U, 0xFD26DCA0U, 0xB26BBDCFU, 0x69A90D6BU},
			{0x8949638BU, 0xE95DD3BCU, 0x922B6A2DU, 0x76E1A4F1U, 0xD5872CFDU, 0x99F73CB1U, 0xDB32A3CEU, 0x752B149AU}},
		{{0x4089236AU, 0xF4F19BD0U, 0x313D0E0BU, 0x3B206C12U, 0x03FEAEB2U, 0x73E70DF3U, 0x9BD1EFE0U, 0x09DBA0EBU},
			{0xFC4E5305U, 0x4C7FD532U, 0xE93D787AU, 0xD792FFEDU, 0xE4245010U, 0xC72DC4E2U, 0x0466BBBDU, 0xE7E0D47DU}},
		{{0x566C5C43U, 0x6E85CB51U, 0x3597F046U, 0xCFF9C919U, 0x4994D94AU, 0x9354E90CU, 0x2147927DU, 0xE0A39332U},
			{0x0DC1EB2BU, 0x8427FAC1U, 0x2FF319FAU, 0x88CFD8C2U, 0x01965274U, 0xE2D4E684U, 0x67AAA746U, 0xFA2E067DU}},
	},
	{
		{{0x3E5F9F11U, 0xB6D92A7FU, 0xD6CB3B8EU, 0x9AFE153AU, 0xDDF800BDU, 0x4D1A6DD7U, 0xCAF17E19U, 0xF6C13CC0U},
			{0x325FC3EEU, 0x15F6C58EU, 0xA31DC3B2U, 0x71095400U, 0xAFA3D3E7U, 0x168E7C07U, 0x94C7AE2DU, 0x3F8417A1U}},
		{{0x319540C3U, 0x2842589BU, 0xA283D6F8U, 0x18490F59U, 0xDAAE9FCBU, 0xA2731F84U, 0xC3683BA0U, 0x3DB6D960U},
			{0x14611069U, 0xC85C63BBU, 0x0788BF05U, 0xB19436AFU, 0x347460D2U, 0x905459DFU, 0xE11A7DB1U, 0x73F6E094U}},
		{{0xC31B9C38U, 0x7B85BB91U, 0x48EF57B5U, 0x0C5AA90BU, 0xAF3BAB6FU, 0xDEDEB169U, 0x2D373685U, 0xE610AD73U},
			{0x02BA8E15U, 0xF13870DFU, 0x8CA7F771U, 0x0337EDB6U, 0xB62C036CU, 0xE4ACF747U, 0xB6B94E81U, 0xD921D576U}},
		{{0xEE3C76CBU, 0xF306A3C8U, 0xD32A1F6EU, 0x3CF11623U, 0x6863E956U, 0xE6D5AB64U, 0x5C005C26U, 0x3B8A4CBEU},
			{0x9CE6BB27U, 0xDCD529A5U, 0x04D4B16FU, 0xC4AFAA52U, 0x7923798DU, 0xB0624A26U, 0x6B307FABU, 0x85E56DF6U}},
		{{0x859DD614U, 0x3A3E5334U, 0x18D0C8EEU, 0x9C475B5BU, 0x07CD51D5U, 0x63080D1FU, 0xB88B4326U, 0xC9C0D0A6U},
			{0xC234296FU, 0x1AC98691U, 0x94887FB6U, 0x2A0A83A4U, 0x0CEA9CF2U, 0x56511427U, 0xA24802F5U, 0x5230A6E8U}},
		{{0xBCE913AFU, 0xAD0FC73DU, 0x458A07CBU, 0x909E587BU, 0xD4F00C8AU, 0x1300DA84U, 0xB54466ACU, 0x425CD048U},
			{0x90E9D8BFU, 0xB59CB9BEU, 0x3E431B0EU, 0x991616DBU, 0x531AECFFU, 0xD3AA117AU, 0x59F4DC3BU, 0x91AF92D3U}},
		{{0x20445C36U, 0x7A3EE207U, 0x59877174U, 0x71D1AC82U, 0x949F73E9U, 0x0FC539F7U, 0x982E3081U, 0xD05CF3D7U},
			{0x7B1C7129U, 0x8758E20BU, 0x569E61F2U, 0xFFADCC20U, 0x59544C2DU, 0xB05D3A2FU, 0x9FFF5E53U, 0xBE16F5C1U}},
		{{0x4E4CA463U, 0xB2330FEFU, 0x3566CC63U, 0xBCEF7287U, 0xCF780900U, 0xD161D2CAU, 0x5B54827DU, 0x135DC539U},
			{0x27BF1BC6U, 0x638F052EU, 0x07DFA06CU, 0x10A224F0U, 0x6D3321DAU, 0xE973586DU, 0x26152C8FU, 0x8B0C5738U}},
		{{0xB9556098U, 0x7043178BU, 0x801C3886U, 0x4090A1DFU, 0x9B67B912U, 0x759800FFU, 0x232620C8U, 0x3E5C0304U},
			{0x70DCEECAU, 0x4B9D3C4BU, 0x181F648EU, 0xBB2D3C15U, 0x6E33345CU, 0xF981D837U, 0x0CF2297AU, 0xB626289BU}},
		{{0x32BE5E0FU, 0x9DC74CBDU, 0x17A01375U, 0x7475BCB7U, 0x50D872B1U, 0x438477C9U, 0xFFE1D63DU, 0xCEC67879U},
			{0xD8578C70U, 0x9B006014U, 0x78BB6B8BU, 0xC9AD99A8U, 0x11FB3806U, 0x6799008EU, 0xCD44CAB3U, 0xCFE81435U}},
		{{0x9EF2D2E4U, 0x113FFEC1U, 0xD5A0EA7FU, 0x1BF6767EU, 0x03714C0AU, 0x57FFF75EU, 0x0A23E9EEU, 0xA23C422EU},
			{0x540F83AFU, 0xDD5F6B2DU, 0x55EA46A7U, 0xC2C2C27EU, 0x672A1208U, 0xEB6B4246U, 0xAE634F7AU, 0xD13599F7U}},
		{{0x9884AAF7U, 0x89689595U, 0x07B348A6U, 0xB1959BE3U, 0x3C147C87U, 0x96250E57U, 0xDD0C61F8U, 0xAE0EFB3AU},
			{0xCA8C325EU, 0xED00745EU, 0xECFF3F70U, 0x3C911696U, 0x319AD41DU, 0x73ACBC65U, 0xF0B1C7EFU, 0x7B01A020U}},
		{{0x9D79046EU, 0xAF89790DU, 0x6CEE0976U, 0x4D650F2DU, 0x43071ECAU, 0xA3935D9AU, 0x283B0BFEU, 0x66FCD2C9U},
			{0x696605F1U, 0x0E665EB5U, 0xA54CD38DU, 0xE77E5D07U, 0x43D950CFU, 0x90EE050AU, 0xD32E69B5U, 0x86DDEBDAU}},
		{{0x3A8631E8U, 0xD2EDB89BU, 0x7A213746U, 0x8DE855DEU, 0xB00C5F11U, 0xB2056CB7U, 0x2C9B85E4U, 0xDEAEFBD0U},
			{0xD150892DU, 0x03F39A8DU, 0x218B7985U, 0x37B84686U, 0xB7375F1AU, 0x36296DD8U, 0xB78E898EU, 0x472CD4B1U}},
		{{0x308FBD93U, 0xEB45AE53U, 0x02C36FDAU, 0x46CD5A2EU, 0xBAA48385U, 0x6A3D4E90U, 0x9DBE9960U, 0xDD55E62EU},
			{0x2A81EDE7U, 0xA1406AA0U, 0xF9274EA7U, 0x6860DD14U, 0x80414F86U, 0xCFDCB0C2U, 0x22F94327U, 0xFF410B10U}},
		{{0x23A5D896U, 0x9910BA6BU, 0x7FE4364EU, 0x1FE19E35U, 0x9A33C677U, 0x6E1DA8C3U, 0x29FD9FD0U, 0x15B4488BU},
			{0x1A1F22BFU, 0x1F439254U, 0xAB8163E8U, 0x920A8A70U, 0x07E5658EU, 0x3FD1B249U, 0xB6EC839BU, 0xF2C4F79CU}},
		{{0xB44A3F84U, 0x17D55DE3U, 0x17C6C690U, 0xACB2F344U, 0x10232390U, 0x32088168U, 0x6C733BF7U, 0xF2E8A61FU},
			{0x9C2D7652U, 0xA774AAB6U, 0xED95C5BCU, 0xFB5307E3U, 0x4981F110U, 0xA05C73C2U, 0xA39458C9U, 0x1BAAE31CU}},
		{{0xC55D2D8BU, 0xCE1DB2BBU, 0xF4F6CA56U, 0x41D58BB7U, 0x8F877614U, 0x7650B680U, 0xF4C349EDU, 0x905E16BAU},
			{0xF661ACACU, 0xED415140U, 0xCB2270AFU, 0x3B8784F0U, 0x8A402CBAU, 0x3BC280ACU, 0x0937921AU, 0xD53F7146U}},
		{{0x78341730U, 0x7F1ED86CU, 0xB525E248U, 0x8EF5BEB8U, 0xB74FBF38U, 0xBBC489FDU, 0x91A0B382U, 0x38A92A0EU},
			{0x22433CCFU, 0x7A77BA3FU, 0xA29F05A9U, 0xDE8362D6U, 0x61189AFCU, 0x7F6A30EAU, 0x59EF114FU, 0x693B5505U}},
		{{0x224C08DCU, 0x262143B5U, 0x81B50C91U, 0x2BBB09B4U, 0xACA8C84FU, 0xC16ED709U, 0xB2850CA8U, 0xA6210D9DU},
			{0x09CB54D6U, 0x6D8DF67AU, 0x500919A4U, 0x91EEF6E0U, 0x0F132857U, 0x90F61381U, 0xF8D5028BU, 0x9ACEDE47U}},
		{{0xCED806B8U, 0x071A2FA8U, 0x697F1478U, 0x222E6134U, 0xABFCDBBFU, 0xDC16FD5DU, 0x121B53B8U, 0x44912EBFU},
			{0x2496C27CU, 0xAC943674U, 0x1FFC26B0U, 0x8EA3176CU, 0x13DEBF2CU, 0xB6E224ACU, 0xF372A832U, 0x524CC235U}},
		{{0x3567962FU, 0x7E98367DU, 0x8188BFFBU, 0x379ED61FU, 0xFAF130A1U, 0x73BBA348U, 0x904ED734U, 0x6C1F75E1U},
			{0x3B4A79FCU, 0x18956642U, 0x54EF4493U, 0xF20BC83DU, 0x9111ECA1U, 0x836D425DU, 0x009A8DCFU, 0xE5B5C318U}},
		{{0xDA85D534U, 0x2771A5BDU, 0xFF980EEAU, 0x53E78C1FU, 0x900385E7U, 0xADF1CF84U, 0xC9387B62U, 0x7D3B14F6U},
			{0xCB8F2BD2U, 0x170E74B0U, 0x827FA993U, 0x2D50B486U, 0xF6F32BABU, 0xCDBE8C9AU, 0xC3B93AB8U, 0x55E906B0U}},
		{{0x1416A6A5U, 0x84CEA069U, 0x43EF881CU, 0x8F860C79U, 0x38038A5DU, 0x41311F8AU, 0xFC612067U, 0xE78C2EC0U},
			{0x5AD73581U, 0x494D2E81U, 0x59604097U, 0xB4CC9E00U, 0xF3612CBAU, 0xFF558AECU, 0x9E36C39EU, 0x35BEEF7AU}},
		{{0x36BA06EEU, 0x324EC0CCU, 0x3DD2CC0CU, 0xFACE3115U, 0xF333E91FU, 0xB364F3BEU, 0x28E832B0U, 0xEF8AFF73U},
			{0x2D05841BU, 0x1E9BAD04U, 0x356A21E2U, 0x42F0E3DFU, 0x4ADD627EU, 0xA3270BCBU, 0xD322E711U, 0xB09A8158U}},
		{{0x66926E04U, 0x323F8ECDU, 0x8110C1BAU, 0x0001E38FU, 0xFC6A7F07U, 0x8DBCAC12U, 0x0CEC0827U, 0xD65E1D58U},
			{0xBE76CA2DU, 0xD2CD4141U, 0xE892F33AU, 0x7895CF5CU, 0x367139D2U, 0x956D230DU, 0xD012C4C1U, 0xA91ABD3EU}},
		{{0x6295D426U, 0x28FF779DU, 0x3FA3AD7BU, 0x0C4F6AC7U, 0x8B8E2604U, 0xEC44D054U, 0x8B0050E1U, 0x9B32A66DU},
			{0xF0476CE2U, 0x1F943366U, 0xA602C7B4U, 0x7554D953U, 0x524F2809U, 0xBE35ACA6U, 0xFD4EDBEAU, 0xB6881229U}},
		{{0xDE673629U, 0x45E21446U, 0x703C2D21U, 0x57F7AA1EU, 0x98C868C7U, 0xA0E99B7FU, 0x8B641676U, 0x4E42F66DU},
			{0x91077896U, 0x602884DCU, 0xC2C9885BU, 0xA0D690CFU, 0x3B9A5187U, 0xFEB4DA33U, 0x153C87EEU, 0x5F789598U}},
		{{0x15F09690U, 0xB782DCE7U, 0x2DFC0FC9U, 0x508B9B12U, 0x65D89FC6U, 0x9015AB4BU, 0xD6D5BB0FU, 0x5E79DAB7U},
			{0x6C775AA2U, 0x64F021F0U, 0x37C7ECA1U, 0xDF09D8CCU, 0xEF2FA506U, 0x9A761367U, 0x5B81EEC6U, 0xED4CA476U}},
		{{0x67B0867CU, 0x3B837119U, 0x9D364520U, 0x8D5E0D08U, 0xD930F0E3U, 0x52DCCC1EU, 0xBF20BBAFU, 0xEFBBCEC7U},
			{0x0263AD10U, 0x99CFFCABU, 0xFCD18F8AU, 0xD8199E6DU, 0xE9F10617U, 0x64E2773FU, 0x08704848U, 0x0079E8E1U}},
		{{0x5C2F342BU, 0xBB9CCE4DU, 0xB52D7AAEU, 0xBF80907AU, 0x2161BCD0U, 0x97F3D3CDU, 0x0962744DU, 0xB25B0834U},
			{0x6C3A1DDAU, 0xC5B18EA5U, 0x06C92317U, 0xFE4EC7EBU, 0xAD1C4AFEU, 0xB787B890U, 0x0EDE801AU, 0xDCCD9A92U}},
		{{0x76497EE8U, 0x8B5C619CU, 0xC717370EU, 0x5D2B0AC6U, 0x4FCF68E1U, 0x98204CB6U, 0x62BC6792U, 0x0BDEC211U},
			{0xA63B1011U, 0x6973CCEFU, 0xE0DE1AC5U, 0xF9E3FA97U, 0x3D0E0C8BU, 0x5EFB693EU, 0xD2D4FCB4U, 0x037248E9U}},
	},
	{
		{{0x1EC34F9EU, 0x80802DC9U, 0x33810603U, 0xD8772D35U, 0x530CB4F3U, 0x3F06D66CU, 0xC475C129U, 0x7BE5ED0DU},
			{0x31E82B10U, 0xCB9E3C19U, 0xC9FF6B4CU, 0xC63D2857U, 0x92A1B45EU, 0xB92118C6U, 0x7285BBCAU, 0x0AEC4414U}},
		{{0x1E29A3EFU, 0xFC189AE7U, 0x4C93302EU, 0xCBE906F0U, 0xCEAAE10EU, 0xD0107914U, 0xB68E19F8U, 0xB7A23F34U},
			{0xEFD2119DU, 0xE9D875C2U, 0xFCADC9C8U, 0x03198C6EU, 0x4DA17113U, 0x65591BF6U, 0x3D443038U, 0x3CF0BBF8U}},
		{{0x2B724759U, 0xAE485BB7U, 0xB2D4C63AU, 0x945353E1U, 0xDE7D6F2CU, 0x82159D07U, 0x4EC5B109U, 0x389CAEF3U},
			{0xDB65EF14U, 0x4A8EBB53U, 0xDD99DE43U, 0x2DC2CB7EU, 0x83F2405FU, 0x816FA3EDU, 0xC14208A3U, 0x73429BB9U}},
		{{0xB01E6E27U, 0xB618D590U, 0xE180B2DCU, 0x047E2CCDU, 0x04AEA4A9U, 0xD1B299B5U, 0x9FA403A4U, 0x412C9E1EU},
			{0x79407552U, 0x88D28A36U, 0xF332B8E3U, 0x49C50136U, 0xE668DE19U, 0x3A1B6FCCU, 0x75122B97U, 0x178851BCU}},
		{{0xFB85FA4CU, 0xB1E13752U, 0x383C8CE9U, 0xD61257CEU, 0xD2F74DAEU, 0xD43DA670U, 0xBF846BBBU, 0xA35AA23FU},
			{0x4421FC83U, 0x5E74235DU, 0xC363473BU, 0xF6DF8EE0U, 0x3C4AA158U, 0x34D7F52AU, 0x9BC6D22EU, 0x50D05AABU}},
		{{0xA64785F4U, 0x8C56E735U, 0x5F29CD07U, 0xBC56637BU, 0x3EE35067U, 0x53B2BB80U, 0xDC919270U, 0x50235A0FU},
			{0xF2C4AA65U, 0x191AB6D8U, 0x8396023BU, 0xC3475831U, 0xF0F805BAU, 0x80400BA5U, 0x5EC0F80FU, 0x8881065BU}},
		{{0xCC1B5E83U, 0xC370E522U, 0x860B8BFBU, 0xDE2D4AD1U, 0x67B256DFU, 0xAD364DF0U, 0xE0138997U, 0x8F12502EU},
			{0x7783920AU, 0x503FA0DCU, 0xC0BC866AU, 0xE80014ADU, 0xD3064BA6U, 0x3F89B744U, 0xCBA5DBA5U, 0x03511DCDU}},
		{{0x95A7B1A2U, 0x197DD46DU, 0x3C6341FBU, 0x9C4E7AD6U, 0x484C2ECEU, 0x426ECA29U, 0xDE7F4F8AU, 0x9211E489U},
			{0xC78EF1F4U, 0x14997F6EU, 0x06574586U, 0x2B2C0910U, 0x1C3EEDE8U, 0x17286A6EU, 0x0F60E018U, 0x25F92E47U}},
		{{0x31890A36U, 0x805C5646U, 0x57FEEA5BU, 0x703EF600U, 0xAF3C3030U, 0x389F747CU, 0x54DD3739U, 0xE0E5DAEBU},
			{0xC9C9F155U, 0xFE24A4C3U, 0xB5393962U, 0x7E4BF176U, 0xAF20BF29U, 0x37183DE2U, 0xF95A8C3BU, 0x4A1BD7B5U}},
		{{0x46191D3DU, 0xA83B9699U, 0x7B87F257U, 0x281FC8DDU, 0x54107588U, 0xB18E2C13U, 0x9B2BAFE8U, 0x6372DEF7U},
			{0x0D8972CAU, 0xDAF4BB48U, 0x56167A3FU, 0x3F2DD4B7U, 0x84310CF4U, 0x1EACE32DU, 0xE42700AAU, 0xE3BCEFAFU}},
		{{0xD785E73DU, 0x5FE5691EU, 0x2EA60467U, 0xA5DB5AB6U, 0xDFC6514AU, 0x02E23D41U, 0xE03C3665U, 0x35E8048EU},
			{0x1ADAA0F8U, 0x3F8B118FU, 0x84CE1A5AU, 0x28EC3B45U, 0x2C6646B8U, 0xE8CACC6EU, 0xDBD0E40FU, 0x1343D185U}},
		{{0xCAAA358CU, 0xE5D7F844U, 0x9924182AU, 0x1A1DB7E4U, 0x9C875D9AU, 0xD64CD42DU, 0x042EEEC8U, 0xB37B515FU},
			{0x7B165FBEU, 0x4D4DD409U, 0xE206EFF3U, 0xFC322ED9U, 0x59B7E17EU, 0x7DEE4102U, 0x8236CA00U, 0x55A481C0U}},
		{{0xC23FC975U, 0x8C885312U, 0x05D6297BU, 0x15715806U, 0xF78EDD39U, 0xA078868EU, 0x03C45E52U, 0x956B31E0U},
			{0xFF7B33A6U, 0x470275D5U, 0x0C7E673FU, 0xC8D5DC3AU, 0x7E2F2598U, 0x419227B4U, 0x4C14A975U, 0x8B37B634U}},
		{{0x8B11888CU, 0xD0667ED6U, 0x803E25DCU, 0x5E0E8C3EU, 0xB987A24AU, 0x34E5D0DCU, 0xAE920323U, 0x9F40AC3BU},
			{0x34E0F63AU, 0x5463DE95U, 0x6B6328F9U, 0xA128BF92U, 0xDA64F1B7U, 0x491CCD7CU, 0xC47BDE35U, 0x7EF1EC27U}},
		{{0xA36A2737U, 0xA857240FU, 0x63621BC1U, 0x35DC1366U, 0xD4FB6897U, 0x7A3A6453U, 0xC929319DU, 0x80F1A439U},
			{0xF8CB0BA0U, 0xFC18274BU, 0x8078C5EBU, 0xB0B53766U, 0x1E01D0EFU, 0xFB0D4924U, 0x372AB09CU, 0x50D7C67DU}},
		{{0x3AEAC968U, 0xB4E370AFU, 0xC4B63266U, 0xE4F7FEE9U, 0xE3AC5664U, 0xB4ACD4C2U, 0xCEB38CBFU, 0xF8910BD2U},
			{0xC9C0726EU, 0x1C3AE50CU, 0xD97B40BFU, 0x15309569U, 0xFD5A5A1BU, 0x70884B7FU, 0xEF8314CDU, 0x3890896AU}},
		{{0xA5618C93U, 0x58E1515CU, 0x77D942D1U, 0xE665432BU, 0xB6F767A8U, 0xB32181BFU, 0x3A604110U, 0x753794E8U},
			{0xE8C0DBCCU, 0x09AFEB7CU, 0x598673A3U, 0x31E02613U, 0x7D46DB00U, 0x5D98E557U, 0x9D985B28U, 0xFC21FB8CU}},
		{{0xB0843E0BU, 0xC9040116U, 0x69B04531U, 0x53B1B3A8U, 0x85D7D830U, 0xDD1649F0U, 0xCB7427E8U, 0xBB3BCC87U},
			{0xC93DCE83U, 0x77261100U, 0xA1922A2AU, 0x7E79DA61U, 0xF3149CE8U, 0x587A2B02U, 0xDE92EC83U, 0x147E1384U}},
		{{0xAF077F30U, 0x484C83D3U, 0x0658B53AU, 0xEA78F844U, 0x027AEC53U, 0x912076C2U, 0x93C8177DU, 0xF34714E3U},
			{0xC2376C84U, 0x37EF5D15U, 0x3D1AA783U, 0x8315B659U, 0xEF852A90U, 0x3A75C484U, 0x16086BD4U, 0x0BA0C58AU}},
		{{0x529A6D48U, 0x29688D7AU, 0xC2F19203U, 0x9C7F250DU, 0x682E2DF9U, 0x123042FBU, 0xAD8121BCU, 0x2B7587E7U},
			{0xE0182A65U, 0x30FC0233U, 0xE3E1128AU, 0xB82ECF87U, 0x93FB098FU, 0x71682861U, 0x85E9E6A7U, 0x043E21AEU}},
		{{0x66C834EAU, 0xAB5B49D6U, 0x47414287U, 0x3BE43E18U, 0x219A2A47U, 0xF40FB859U, 0xCC58DF3CU, 0x0E6559E9U},
			{0x0C6615B4U, 0xFE1DFE8EU, 0x56459D70U, 0x14ABC8FDU, 0x05DE0386U, 0x7BE0FA8EU, 0xE9035C7CU, 0x8E63EF68U}},
		{{0x53B31E91U, 0x116401B4U, 0x4436B4D8U, 0x0CBA7AD4U, 0x107AFD66U, 0x9151F9A0U, 0x1F0EE4C4U, 0xAFACA8D0U},
			{0x9EE9761CU, 0x75FE5C1DU, 0xF0C0588FU, 0x3497A16BU, 0x0304804CU, 0x3EE2BEBDU, 0xC2C990B9U, 0xA8FB9A60U}},
		{{0x39251114U, 0xD14D32FEU, 0xCAC73366U, 0x36BF25BCU, 0xDBA7495CU, 0xC9562C66U, 0x46AD348BU, 0x324D301BU},
			{0xD670407EU, 0x9F46620CU, 0xE3733A01U, 0x0EA8D4F1U, 0xB0C324E0U, 0xD396D532U, 0x03C317CDU, 0x5B211A0EU}},
		{{0x5FFE7B37U, 0x090D7D20U, 0x1747D2DAU, 0x3B7F3EFBU, 0xB54FC519U, 0xA2CB525FU, 0xF66A971EU, 0x6E220932U},
			{0xB486D440U, 0xDDC160DFU, 0x3FE13465U, 0x7FCFEC46U, 0x76E4C151U, 0x83DA7E4EU, 0xD8D302B5U, 0xD6FA48A1U}},
		{{0x5872CD88U, 0xC6304F26U, 0x278B90A1U, 0x806C1D3CU, 0xCAF0BC1CU, 0x3553E725U, 0xBB9D8D5CU, 0xFF59E603U},
			{0x7A0B85DDU, 0xA4550F32U, 0x93ECC217U, 0xDEC5720AU, 0x69D62213U, 0x0B88B741U, 0x5B365955U, 0x7212F245U}},
		{{0xB5CAE787U, 0x20764111U, 0x1DFD3124U, 0x13CB7F58U, 0x1175AEFBU, 0x2DCA77DAU, 0xFFAAE775U, 0xEB75466BU},
			{0xDB6CFF32U, 0x74D76F3BU, 0x61FCDA9AU, 0x7440F37AU, 0xB525028BU, 0x1BB3AC92U, 0xA1975F29U, 0x20FBF8F7U}},
		{{0xDF83097FU, 0x982692E1U, 0x554B0800U, 0x28738F6CU, 0xA2CE2F2FU, 0xDC703717U, 0x40814194U, 0x7913B93CU},
			{0x1FE89636U, 0x04924593U, 0xF78834A6U, 0x7B98443FU, 0x5114A5A1U, 0x11C6AB01U, 0xFFBA5F4CU, 0x60DEB383U}},
		{{0x01A982E6U, 0x4CAA54C6U, 0x3491CD26U, 0x1DD35E11U, 0x7CBD6B05U, 0x973C315FU, 0x52494724U, 0xCAB00775U},
			{0x6565E15AU, 0x04659B1FU, 0x8C8FB026U, 0xBF30F529U, 0xA8A0DE37U, 0xFC21641BU, 0xFA5E5114U, 0xE9C7A366U}},
		{{0x52F03AD8U, 0xDB849CA5U, 0x024E35C0U, 0xC7E8DBE9U, 0xCFC3C789U, 0xA1A2BBACU, 0x9C26F262U, 0xBF733E7DU},
			{0xB8444823U, 0x882FFBF5U, 0x6BF8483BU, 0xB7224E88U, 0x65BEF640U, 0x53023B8BU, 0xD4D5F8CDU, 0xAABFEC91U}},
		{{0x079EA1BDU, 0xA40E1510U, 0xD05D5D26U, 0x1AD9ADDCU, 0x13E68D4FU, 0xDB3F2EABU, 0x640F803FU, 0x1CFF1AE2U},
			{0xD4CEE117U, 0xE0E7B749U, 0x4036D909U, 0x8E9F275BU, 0x8F4D4C38U, 0xCE34E31DU, 0xD75130FCU, 0x22B37F69U}},
		{{0xB4014604U, 0x83E0F1FDU, 0x89415078U, 0xA8CE9919U, 0x41792EFEU, 0x82375B75U, 0x97D4515BU, 0x4F59BF5CU},
			{0x923A277DU, 0xAC4F324FU, 0x650F3406U, 0xD9BC9B7DU, 0x8A39BC51U, 0xC6FA87D1U, 0x5CCC108FU, 0x82588530U}},
		{{0x82E4C634U, 0x5CED3C9FU, 0x3A4464F8U, 0x8EFB8314U, 0x7A1DCA25U, 0xE706381BU, 0x5A2A412BU, 0x6CD15A3CU},
			{0xBFCD8FB5U, 0x9347A8FDU, 0x6E54CD22U, 0x31DB2EEFU, 0xF8D8932FU, 0xC4AEB11EU, 0x344411AFU, 0x11E7C1EDU}},
	},
	{
		{{0x43228D83U, 0xAB41B43AU, 0x4AD63F99U, 0x24AE1C30U, 0x46A51229U, 0x8E525F1AU, 0xCD26D2B4U, 0x14AF860FU},
			{0x3F714AA1U, 0xD6BAEF61U, 0xEB78795EU, 0xF51865ADU, 0xE6A9D694U, 0xD3E21FCEU, 0x8A37B527U, 0x82CEB1DDU}},
		{{0x55DBD4B3U, 0xDB09E873U, 0x6639BBB1U, 0x1F879928U, 0x1C651962U, 0xB83E47E5U, 0xC43FB574U, 0xD4EF0FB6U},
			{0xF1BFB12AU, 0x27D3B9D8U, 0x6E5E8B72U, 0x6AB877E8U, 0x157B9014U, 0x8EEBDC9DU, 0x3AA5CB64U, 0x4C211005U}},
		{{0x7DDAE64BU, 0xF7F1D007U, 0x67DEFDC4U, 0x21A3774CU, 0x95CE1424U, 0x1B464BADU, 0xDE96CCF0U, 0x8254012BU},
			{0x84517A34U, 0x06FCAE8FU, 0x0B0EA1D2U, 0x160113EAU, 0x93E4A3D0U, 0x07F0D49CU, 0x31814D6FU, 0x830CD056U}},
		{{0x6D55D6A4U, 0xC52D8D8BU, 0xBE58E8F9U, 0xC4130FB3U, 0xE1275627U, 0x5F55C345U, 0x117042D3U, 0xB881A03CU},
			{0x3238D301U, 0x00A970A5U, 0x12A2C4F1U, 0x40D7CF24U, 0xD770EA74U, 0xACE4A2F5U, 0xE96940B2U, 0x36A2E587U}},
		{{0x6859A677U, 0x8069E9B9U, 0x07D9FD10U, 0x649A49F8U, 0x0B89BEAEU, 0x5928254CU, 0xE32C3228U, 0xD64FF5DFU},
			{0xD3EF0355U, 0xD3D19C2BU, 0xA12F22C5U, 0x15E3DA65U, 0xFDC22E65U, 0xCA4044B3U, 0x95310851U, 0x78296F23U}},
		{{0x63106C5AU, 0x71F75463U, 0x60F37957U, 0x4A9BA533U, 0x30F7FC89U, 0x9F6E772CU, 0x1AD4525EU, 0xE2A83A35U},
			{0x4047FC33U, 0xA8B6DA64U, 0x5E839BAEU, 0xDFF306B7U, 0x212F3378U, 0x3AF37CB8U, 0x21D15B12U, 0x10389042U}},
		{{0x3594917AU, 0xBE4AE568U, 0xA04BF81EU, 0xEF7C1C47U, 0x046D91A0U, 0xA1DC3612U, 0xFB11B338U, 0x3EEE37AFU},
			{0xD03D8F51U, 0x7E90278FU, 0x4FA183C6U, 0x3045A6DAU, 0x91CD16A9U, 0xB39E5733U, 0xE54E9411U, 0xC748A504U}},
		{{0x23C25370U, 0xD4C773A7U, 0x0B932DA3U, 0xDC7F4793U, 0xC14179CEU, 0xC570E9F7U, 0x2CA31422U, 0x24A62CEBU},
			{0xCDDA9395U, 0x9F79A669U, 0x13E0E9ACU, 0x4A10812EU, 0xB0DDDD59U, 0xF260AE53U, 0xDB7269FEU, 0xCB9EED67U}},
		{{0x107F7BACU, 0xAB6A1E13U, 0x972091F5U, 0x83A8BC57U, 0xF6DCBA41U, 0x3C65B454U, 0x6ABC431DU, 0xD7606FF9U},
			{0x9BD09971U, 0xA3AF9C18U, 0x276BAD63U, 0x6DDD3BBFU, 0xAB4F0816U, 0xD2ABA9BEU, 0x151581EDU, 0x8F13063CU}},
		{{0x2C23464EU, 0xD31C5E8EU, 0x50CFBDE7U, 0x5BCC382FU, 0xA93C3D9BU, 0x6CEE3D8DU, 0x09EE62ACU, 0xBEE29489U},
			{0x10742B84U, 0x4848D59CU, 0xE35E9C84U, 0x2486796FU, 0xCD8F391AU, 0x1A1D9570U, 0x3EEDB743U, 0x839AA091U}},
		{{0x378200B1U, 0xD9183F74U, 0x762F5605U, 0xE5EA1645U, 0x7BD6290FU, 0x78B42E2FU, 0x07FA0899U, 0xA0BDFCCCU},
			{0xDACDA629U, 0x2F92EA52U, 0x48DE27E2U, 0x810B4E6CU, 0xD9D1250DU, 0x013D8587U, 0xDD5141D5U, 0xC153D519U}},
		{{0x85AE12C3U, 0xAC177EB9U, 0x6CF76537U, 0x8E6CB5CCU, 0xF265F9E3U, 0x134ABB19U, 0x1BA3F55DU, 0xC37309B7U},
			{0x392D564BU, 0x570833B4U, 0xD8C22F00U, 0xAA273A27U, 0x6006773AU, 0x9BA6B627U, 0x0A16C092U, 0x2156C94FU}},
		{{0x64E8344DU, 0xF773535AU, 0xD0DBABE6U, 0xB8486A33U, 0xB578862DU, 0x43C2DF99U, 0x1A39820EU, 0xCEAD29A1U},
			{0x63134D63U, 0x3E5466FEU, 0xDF43A104U, 0xC37EA88FU, 0xBBAACB5AU, 0x3B34AC34U, 0xBC20BE5AU, 0x8281C240U}},
		{{0x1F2E166FU, 0x0B136851U, 0x94C4CF6CU, 0x9E614C68U, 0x22981446U, 0x09A65766U, 0x402CD6B0U, 0x2F6CEC6CU},
			{0xF5948CC4U, 0xB7E42695U, 0xD9B80C50U, 0x39A370C8U, 0xEB22C9CCU, 0xD9A0ACDBU, 0x0E0E07A5U, 0x2D99F773U}},
		{{0xC679D9F9U, 0x6B669496U, 0xE78F0830U, 0x3B741F36U, 0xEB3F9E53U, 0xF99D4857U, 0x76F7D4AEU, 0x41BE5942U},
			{0xC09A112BU, 0x75F44D57U, 0x8475EEB7U, 0xA5139FD6U, 0xC6BC9DF6U, 0xA4560CD5U, 0x50845434U, 0x8CE2C4CFU}},
		{{0xB48D4168U, 0x09800DC1U, 0xBFEE87A2U, 0xA740B282U, 0xC94A547AU, 0x80C6B75DU, 0x099C1985U, 0x8CB622F0U},
			{0x1467E05DU, 0xE6C78963U, 0x22FD3064U, 0x027B6588U, 0xC2FDB68CU, 0xE14735E2U, 0x7D853158U, 0xFD286994U}},
		{{0x35767730U, 0x0DA4D7A1U, 0x47F1522CU, 0x3062DE71U, 0xC79EF7BEU, 0xA03CE343U, 0x2040ADF8U, 0xAF5D5A38U},
			{0x9CC6A18BU, 0xA0BC544CU, 0x935F7861U, 0xED2987C8U, 0x4BD78013U, 0x879810D9U, 0xF1A78FE1U, 0xBBBE174AU}},
		{{0x5A35325FU, 0x2D4F00E6U, 0x8879BDF7U, 0x48A4F167U, 0x6C5FFBEDU, 0x2976561CU, 0x6487D2D7U, 0x3F19540DU},
			{0x5EA8C27EU, 0x7C1C2A88U, 0x9D1FD509U, 0x48F8EA38U, 0x3E65BE45U, 0x436B4381U, 0x60B06F2CU, 0x9B474327U}},
		{{0xDD91271CU, 0x4D726E8DU, 0xA177DBF0U, 0x15D87956U, 0x6A7E668AU, 0xC3AC54BBU, 0x03EB76DFU, 0xF3C65736U},
			{0x08D0D859U, 0xF231ECA1U, 0x98FC2CB7U, 0x7C78D5FDU, 0xAAB174E5U, 0x18574D1EU, 0xC2DDE43AU, 0xD8D7FF03U}},
		{{0x6EEE4444U, 0xBF24D728U, 0x3343C17BU, 0x4B881141U, 0xDC0B7E7EU, 0x92CE2758U, 0xE9A92CD1U, 0x0D29D7F7U},
			{0x713BEE91U, 0x60B035DBU, 0x40536FE8U, 0xF090078EU, 0x9BEBE704U, 0x008ECA09U, 0x199E9A25U, 0x9BF246B1U}},
		{{0x371255C4U, 0xA0E4637AU, 0x0406F3ACU, 0x322B388AU, 0x7B952F51U, 0xFB1C0FD7U, 0x400D59C8U, 0x5BE0906CU},
			{0xA100D000U, 0xA6712CE6U, 0x4BABC754U, 0x1B77D034U, 0xC3F0CC11U, 0x423921E1U, 0xE6AD4522U, 0x7A99158BU}},
		{{0x35FD50B7U, 0x6807619CU, 0xD27D9B31U, 0x00B9632DU, 0xE61DED94U, 0xBE2A876DU, 0xD5D7A399U, 0xCDD8DC5FU},
			{0x2D54C8A5U, 0xECA46623U, 0x15894DCCU, 0x8468C6FBU, 0x09669250U, 0x7CA82855U, 0x6F455F69U, 0x88942E18U}},
		{{0xEB199970U, 0xECC34407U, 0xFC4EFE76U, 0x32FD6E96U, 0xC49F6FEDU, 0xC747038FU, 0x11B567BCU, 0x1E84ECF8U},
			{0x90595DE8U, 0x7C47E72CU, 0x89A35A81U, 0x28D7396DU, 0xE9B18255U, 0xA68AFD7AU, 0x2EC174EDU, 0x97D86665U}},
		{{0xFF84F957U, 0xD9CE9363U, 0x749B21A0U, 0x27195DDFU, 0xE948D437U, 0xA0D0F61DU, 0xD750DB6DU, 0x0949E270U},
			{0x0F9D74D5U, 0x0429A041U, 0x511D7E91U, 0x192A6D0FU, 0xF37E3E5BU, 0x711F4AB5U, 0x377E7606U, 0x651B9686U}},
		{{0x16EBFC32U, 0x501B86EEU, 0xD4B5215EU, 0xAB12F402U, 0xCFFAB871U, 0x8D7CDB18U, 0x0CE836C3U, 0xEAC35C20U},
			{0x2FA94684U, 0xE77924BBU, 0x199EB8A0U, 0xAE26E6E5U, 0x1AB8FA72U, 0xAD8BCF84U, 0x3FA6A4BFU, 0x2D3FB681U}},
		{{0x32C9C4E3U, 0xF70FF7A1U, 0x095D572EU, 0x45BCA040U, 0xA7C3FD7AU, 0x6BB5C6FBU, 0xF89380A5U, 0xBFC3AF57U},
			{0x53151F5DU, 0xDAA43E2DU, 0x210A0EFEU, 0x83A7BFBFU, 0x9A2FF755U, 0x3719EE23U, 0xE736E0C7U, 0x36C28134U}},
		{{0xBAB07B68U, 0x9D98E4FAU, 0x3D001566U, 0x5CEFC84FU, 0xD85DA744U, 0x6AF704FDU, 0xF5155997U, 0xAB30F6C8U},
			{0xA02F4807U, 0x1E1B0997U, 0x89366AA4U, 0x38769211U, 0xDD6F746FU, 0x46A3964BU, 0x7E12CAA1U, 0x55EBD179U}},
		{{0xAB667CDCU, 0x07383F61U, 0x19455CB8U, 0x44C4F2F5U, 0x3B01BCE1U, 0x18D19416U, 0xB61AE93DU, 0x78A333ACU},
			{0xE71735F4U, 0x28C79F99U, 0x11AF8992U, 0xE186014FU, 0x1EEA5FDFU, 0x5BD6F93DU, 0x863E71E6U, 0x9CEEBD47U}},
		{{0x0F46C635U, 0x090A0422U, 0xA04DE3F5U, 0xC7EAC842U, 0x8990D4B2U, 0x45B69D4CU, 0xB8E0CDC6U, 0x032AEB50U},
			{0x4EE3F307U, 0x02CE332AU, 0x5043980FU, 0x3C80C154U, 0xCBD5287CU, 0xC774838BU, 0x4A37D0AEU, 0x05266107U}},
		{{0x333D2E74U, 0x7E0ADD38U, 0xA8FD3E6BU, 0x20CBA1BAU, 0xA969429FU, 0x51C4ECC1U, 0x04AC749AU, 0xCDF4763EU},
			{0x14CADA98U, 0xFF5F3044U, 0x26816A23U, 0x5C469220U, 0xBC83C978U, 0x1B4DE08EU, 0x2DA85B41U, 0x68CE92BDU}},
		{{0xC67460F5U, 0xC05F97EAU, 0x43EEAE0BU, 0xF71FC73FU, 0x8C1F8FC4U, 0xC4A8D30AU, 0xF7A10EC8U, 0xBB690944U},
			{0x759B9B81U, 0xC09F28CAU, 0x9D8FC498U, 0x2D050A28U, 0xD5F0DD68U, 0xD2027363U, 0x992AC2EEU, 0x046372B2U}},
		{{0x80397946U, 0x424B06A6U, 0xDE62F94DU, 0xD46758C3U, 0x5CA2C838U, 0xE575B73AU, 0xCD110FFCU, 0xE20BB6D6U},
			{0x4C92DA7DU, 0xD30A99B1U, 0x289B77FEU, 0x7118C224U, 0x49AEA3C1U, 0x8A73BD2BU, 0xBC1AD4D0U, 0x11D83099U}},
	},
	{
		{{0x10C341E4U, 0x14EFCA5CU, 0x04295D58U, 0xCFDDF812U, 0xBF6B3EC5U, 0x109BCFA3U, 0x1D165F9CU, 0x5B6D5185U},
			{0xA9B1150FU, 0x29B0F7B7U, 0x9A241B5DU, 0xAB458711U, 0xF94AC313U, 0xBBBCA8BBU, 0x433B1B17U, 0x6AA37CFBU}},
		{{0x1AB98DF0U, 0xEE8B49B0U, 0xF59A9427U, 0xECBDEAB5U, 0x548C6A63U, 0xBB05EFFAU, 0xDB9344EFU, 0x7EFC4617U},
			{0x357E0678U, 0x4F4444F2U, 0x72103A20U, 0xD4B9F5F7U, 0xB9777DB0U, 0x4F0D7397U, 0x8288F5DFU, 0x7FF6E1D2U}},
		{{0x2D34AB45U, 0xB0AABD66U, 0x68BD2982U, 0x26325281U, 0x05BFA4BDU, 0xDAFE95A1U, 0x36D55FCCU, 0x15DB716FU},
			{0x227D1799U, 0x6EEEC56EU, 0xCA4AA2ABU, 0x4296D668U, 0xF970855CU, 0x5F3B0F6CU, 0x710534F1U, 0x18989294U}},
		{{0xC20BDAEFU, 0xADC1D269U, 0x1E9FE09AU, 0x1CC0E8FCU, 0x49DCC275U, 0xDFF17382U, 0x4DF920A8U, 0x0D1200BCU},
			{0x422C76ABU, 0x7C19ABA2U, 0x942923E8U, 0x50A987BEU, 0x3DFFC278U, 0x783052C6U, 0x7BA347B6U, 0xB9D8A7AEU}},
		{{0x25B68701U, 0x1648E258U, 0x6472E0C0U, 0x3F3F4464U, 0xE67FCAD6U, 0xB9ED706EU, 0x2CFE75B8U, 0xFEBCF0F1U},
			{0x70CE9626U, 0x87CC5F95U, 0x33113B92U, 0xC382894EU, 0xED803FBBU, 0x23F28472U, 0x457C3133U, 0x3F18928FU}},
		{{0xA1B0CB79U, 0x2381C29FU, 0xB39F556AU, 0x178792A5U, 0x70C511FEU, 0x0C61FA60U, 0x9B5DC8DEU, 0x216D5D34U},
			{0xF1E61E5DU, 0x8831F3E6U, 0x3BB0252AU, 0x9E1CE114U, 0x911EAC20U, 0x119DE0C0U, 0x5D60FF83U, 0x7C0748D9U}},
		{{0x9BA32FF3U, 0xD6A6C477U, 0xB87A33F7U, 0xF86DF258U, 0x01D65E71U, 0xF4BA1EC7U, 0x7EC7BA6FU, 0x2BE422A7U},
			{0x5DB951E1U, 0x7AC04DC6U, 0x7CDDCEE9U, 0x5A9F169AU, 0xF672F868U, 0x0C6D73FEU, 0x0D5E4C0AU, 0x7C4E626AU}},
		{{0xFFBE7B04U, 0x115EF28EU, 0x064E537EU, 0x08418611U, 0x5B4C5CE0U, 0x281C0634U, 0x65F6F606U, 0x69063C2FU},
			{0x1A7886BEU, 0x3C641F6EU, 0x949E15ACU, 0x6230B27AU, 0x04F43938U, 0x70AEFC30U, 0xE43BEA4CU, 0xD686A28AU}},
		{{0x00E7197CU, 0x119450F0U, 0x0D17AB85U, 0x02193CD8U, 0xA0ABF962U, 0xEFC24AA1U, 0x992E78AAU, 0x1104BAAFU},
			{0xCE343CFCU, 0xA92D4D7FU, 0xE26E7273U, 0xF16AE61FU, 0x7513AC4AU, 0x199D4991U, 0xF470F26EU, 0xDA626E6FU}},
		{{0x1CF8EE2CU, 0xDC7F33FDU, 0x280B3C62U, 0xD0DD833FU, 0x51DF7842U, 0x3E7ABC45U, 0xA87F250BU, 0xCFFFF689U},
			{0x4C5A5995U, 0xADB1E61AU, 0x77352114U, 0x9E71BA54U, 0xEB6BE2FCU, 0xBB19B791U, 0x39F3B1C1U, 0x95002696U}},
		{{0xF6A2BFFBU, 0xB17BC45AU, 0xA42A0B96U, 0xCB7D475AU, 0x498718BBU, 0x9FBD042AU, 0x9FABB05DU, 0x316CDC16U},
			{0xDBF732DEU, 0x1C951FACU, 0x277AE3CAU, 0x6566A5E7U, 0xCD5991B0U, 0xE4EF03EDU, 0x50E81F85U, 0x574410BBU}},
		{{0x95B360B5U, 0x4C77975CU, 0x6A619674U, 0x2187A050U, 0x677762DDU, 0xE7B9ADB6U, 0x42FF74C9U, 0x73EC4879U},
			{0xBA8E1453U, 0x77277DA2U, 0x89A08B6CU, 0xA2F6A467U, 0x1264DB01U, 0x3D94E808U, 0xA9601858U, 0xB6EA656EU}},
		{{0xDB76F8BCU, 0x283BF73EU, 0x3968BBE8U, 0x727CBDA5U, 0xD9D6ABC2U, 0x8FE97294U, 0x197B1C0EU, 0x67666287U},
			{0x93CE3DDEU, 0xEF990847U, 0x70AE5E90U, 0xE5298E97U, 0xBEA31DE8U, 0xC52CE14DU, 0xDD70842EU, 0x08325AC4U}},
		{{0x1C8F3608U, 0x038846D6U, 0xC1EAB9A3U, 0x367A8216U, 0x15A859C4U, 0xA787F539U, 0x211D6BC0U, 0xBB299297U},
			{0xE7ACF3E0U, 0x3AE25A29U, 0x536FB744U, 0x57D56A4BU, 0x62A77B1EU, 0x79688B35U, 0xB31DFED7U, 0xD8F7533CU}},
		{{0x66EF3F6BU, 0xCB0302B0U, 0x748D011AU, 0x8B7FD53DU, 0xEB79C2C0U, 0xAC8EC0ECU, 0x18DBDB70U, 0x2A901844U},
			{0xB6E63D06U, 0xB2779937U, 0x5F1BCC97U, 0x9E8B4A0FU, 0x9C96ECE0U, 0x83BDF6AEU, 0x86AA7DB1U, 0x9EE09A0AU}},
		{{0xF4ADA85EU, 0x09E9B691U, 0x03C2DC7EU, 0x4B049A09U, 0x48A973F5U, 0x58CDCEDEU, 0x49DAF23CU, 0xCD772E72U},
			{0x6DFAA07BU, 0x86945C4DU, 0xC0C91A19U, 0xD68488B4U, 0xAAE9C88AU, 0x80DC8B01U, 0xD7E0167CU, 0x6CF7E196U}},
		{{0x5C93EB04U, 0xBA8AD904U, 0x08C3F291U, 0x8378F7D0U, 0xEC84634BU, 0x0C2EBDF9U, 0x84867322U, 0x80499C42U},
			{0xE683D6DAU, 0xDF9D6C77U, 0x1F332C0EU, 0x1BB0158DU, 0x1B98A5DAU, 0x40104714U, 0xD89F94B9U, 0xB11071BBU}},
		{{0x7A5ABEB3U, 0xFBC505DEU, 0xE103BC87U, 0x44C6FB76U, 0x6ED845D8U, 0x80DA6C79U, 0x14C98574U, 0x2693849AU},
			{0x7BAF4C81U, 0xBAA65E56U, 0xA075B130U, 0x724A6B4AU, 0x2E4A99B0U, 0x34C9F080U, 0x1BF450B2U, 0xDC452C18U}},
		{{0x873C80D9U, 0x357C8B9BU, 0x3497427BU, 0x319EDAFFU, 0x2CAB7D2CU, 0x343FCCF6U, 0x897A8DE5U, 0xCCB34CDCU},
			{0x0596A85EU, 0x5EE5F018U, 0xF889F879U, 0x3EF8D801U, 0xD82892DBU, 0xA24377E8U, 0x2B5A2D86U, 0x4870B638U}},
		{{0x0A130473U, 0xEBC88D2CU, 0x3808AAF7U, 0x337FA97AU, 0xD5B027BAU, 0xE491984DU, 0x8C004F7BU, 0x08D1BD31U},
			{0xFB8E4E49U, 0x5139358AU, 0x6462CFC4U, 0x7DD9922CU, 0xF5755910U, 0x9AE57070U, 0x5779C85CU, 0xB9F4043BU}},
		{{0x6B480B48U, 0x995C4197U, 0xAF413B1BU, 0xF81E22E5U, 0x57DC4791U, 0x554F2451U, 0x17BBD826U, 0xE9CFF65FU},
			{0x71603B68U, 0x6E5CD19DU, 0x10762FA1U, 0x8CC6C5DCU, 0xD06A9DD6U, 0xA43E99A5U, 0x887F2E73U, 0x0CA71DB3U}},
		{{0xEB056DF3U, 0x7BF8855EU, 0x99C89B0AU, 0x12FF7A0DU, 0x65BC4D51U, 0xD5293D7AU, 0xC979B041U, 0xC27B8201U},
			{0xEB91640CU, 0x7BCE7877U, 0xE9011B62U, 0xF84F8D90U, 0xC107B2C6U, 0x59F76C8DU, 0xC2D1795DU, 0xBA43BB66U}},
		{{0xBDE511C2U, 0x9F471017U, 0x05BB5058U, 0xC56E7798U, 0x408898EAU, 0xB281E3F1U, 0x82738438U, 0xDB2B0413U},
			{0x2F209D1CU, 0x510237DAU, 0xD0942DF7U, 0xE57ACF1FU, 0xED63AFFDU, 0x7E36F094U, 0x45E4241AU, 0x0379B76EU}},
		{{0x131DC69EU, 0xAA8B9B8BU, 0x51DEB5F2U, 0x39FF5353U, 0x7C5AEF71U, 0xC420C272U, 0xC730F579U, 0xD3F1C1EEU},
			{0x07A26F4DU, 0xA0030074U, 0xD11D54F0U, 0x2D3F33FCU, 0x75E559A9U, 0x22AA5236U, 0x7BE61CBDU, 0x9A550560U}},
		{{0x14904AC1U, 0x096745CBU, 0xCFB6CCC6U, 0xCD9F0F99U, 0xCC37EE69U, 0x6D215C79U, 0x4EB87816U, 0xE13B0FF7U},
			{0x8E63567DU, 0xB5EFB639U, 0x62355850U, 0x928346DEU, 0x1A38D780U, 0x8CB09C4EU, 0x9EBCFFEEU, 0x0356B509U}},
		{{0x7F3F7600U, 0xCD95100BU, 0x56FB2959U, 0xDEF5C611U, 0x76890987U, 0x22EBF9BDU, 0x9A0AA9E6U, 0x14786B0DU},
			{0x1490651EU, 0xB3A950C0U, 0x43A0E8CEU, 0xAA9B33FDU, 0xEB1D3CE7U, 0x76A292F3U, 0x984BAD56U, 0x6F1CFD83U}},
		{{0x7BB24905U, 0xBF2AFDD0U, 0x93AC0428U, 0x7D0A9DF0U, 0x32F4E521U, 0x158FFC8CU, 0x99EF8B42U, 0x3C2889BCU},
			{0x4105F864U, 0xF40B1316U, 0x03B10BE6U, 0xEF782CC3U, 0x77C448ACU, 0x6B902E01U, 0xB2DC2127U, 0xF1009D1AU}},
		{{0xB2513D48U, 0xED146E57U, 0x7B953986U, 0x91FC85C6U, 0xB1DA1ED9U, 0xFF2023D0U, 0xC7896C82U, 0x5DD58751U},
			{0xB804058DU, 0x70605CD9U, 0x5877CD8FU, 0xCFB64E18U, 0xA3D65231U, 0x4A8CDC79U, 0xAB1D5E16U, 0x156E8FF5U}},
		{{0x0D56B9EBU, 0x910CFA91U, 0x2B6CB240U, 0xF2836DA0U, 0xE502D043U, 0x978209BFU, 0x6B6843BFU, 0x82D08FB7U},
			{0x97AB426FU, 0x09702F32U, 0x6356FCEFU, 0x04669BB9U, 0x20DB8499U, 0xC97E03C3U, 0x60236705U, 0xD941875AU}},
		{{0x6887D69DU, 0x6F5A8411U, 0xC6F5FF94U, 0x9F62F195U, 0x09C3CFBCU, 0x0121BBC1U, 0x2E31E5F0U, 0x9F28100DU},
			{0xF0D7AFE6U, 0x2254DB28U, 0x6F183303U, 0x764E7EB0U, 0x96CA1379U, 0xED732F5AU, 0xB246D3D6U, 0x8848BE9DU}},
		{{0x5D36656BU, 0x4ACF5626U, 0x79E1DC5AU, 0x56D6253CU, 0x7E4345ECU, 0x43355144U, 0x3199068BU, 0xB67F06F3U},
			{0x88EE80DBU, 0x61AACB0AU, 0x64AC89D8U, 0xEFFFEEC0U, 0x6A31D253U, 0x3DB8A0B7U, 0x5042F355U, 0x3B2A9B1AU}},
		{{0xEE9343C8U, 0xFE73CAECU, 0xC313DCFCU, 0x1D0F03C6U, 0xEF88FC84U, 0xE29BCAB5U, 0xAEFD799EU, 0x028C579AU},
			{0xEE74AE63U, 0x4F9B082EU, 0xEA499914U, 0x8B377A3BU, 0x653E934BU, 0xBBFECD83U, 0x27E0955BU, 0x7DFEDE99U}},
	},
	{
		{{0x5A463486U, 0x97575F51U, 0x306EAA96U, 0x3CF990BCU, 0xFE851FE2U, 0xBBFD37EEU, 0x0347D5D8U, 0x98075A38U},
			{0x087DEF74U, 0xD799F5A9U, 0x1BA1609CU, 0x07365F7AU, 0x76A88396U, 0xE6A39CA6U, 0x39FB04CAU, 0xAB11ED8DU}},
		{{0x76B69D34U, 0x6EF95F96U, 0xF6DBD7FDU, 0x02733B46U, 0x30BD392CU, 0x61972F96U, 0xBC3F6738U, 0x54F90CC1U},
			{0x4B28D694U, 0xE3B0A9DCU, 0xFDE61847U, 0xF0990A40U, 0x497A281CU, 0x32286266U, 0x70752537U, 0xD11FDAAAU}},
		{{0x7472F50CU, 0xE5E3A9F7U, 0xBCC62D7BU, 0xF0E73FECU, 0xC9AACEB9U, 0x1EE0E5B5U, 0x85F1FA2EU, 0xC154B18EU},
			{0x5F9B0C7FU, 0x761E88DEU, 0x0680A7F4U, 0x4C674094U, 0xEA61F5B1U, 0x5956DD9FU, 0x6B353A07U, 0x69C12800U}},
		{{0x3BD44493U, 0x8D95F8E8U, 0x92FA57E5U, 0x8459BA63U, 0xCCDD4D2BU, 0xA5FEA017U, 0x720E296CU, 0xE58D9A77U},
			{0x0D664B7EU, 0x4C37741EU, 0xB31559DBU, 0xEAB4DF92U, 0xFBD0504AU, 0xCE616B89U, 0xF55A71F2U, 0xDA3EDBAAU}},
		{{0xED0EA091U, 0xD25B309CU, 0x7B977CD7U, 0x44DF9F7AU, 0x47D7F9E5U, 0xD251DBE7U, 0x40707975U, 0xA2AA1F02U},
			{0xFE390CE8U, 0xCD62DEF2U, 0xD629B055U, 0x202DB5E4U, 0x3CCBC105U, 0xC487C447U, 0xF6437166U, 0x619DAEC9U}},
		{{0xD71F92F7U, 0x69F60AC6U, 0x595B7FEFU, 0x8F950B66U, 0xBDA55FE6U, 0x8B7A5EBEU, 0xE810319FU, 0x91515073U},
			{0xE7F4A8F7U, 0x3BC09561U, 0x1B407699U, 0x35F9B4D9U, 0x3E58641DU, 0xABA67B80U, 0xABC2E61FU, 0x6FFD4BEBU}},
		{{0x5368A3D0U, 0x9F0CB613U, 0x490B6545U, 0x91A5A661U, 0xA625A22DU, 0x5CA62732U, 0x0FDBEE86U, 0x652056E1U},
			{0x02899C61U, 0xF165384AU, 0x385F9328U, 0xA2981927U, 0xDC9F5C63U, 0x2D897ABFU, 0x9F48330AU, 0x283379EAU}},
		{{0x66C83175U, 0x225D9104U, 0x1393B947U, 0xB3601BF5U, 0xDFA1DC5FU, 0x530C10EAU, 0x3E045CF5U, 0x11ADE47CU},
			{0x3AB055BCU, 0x556B53C1U, 0xE20037A1U, 0x7E4C52A2U, 0x970108B9U, 0xD298F3F2U, 0xDE027B02U, 0x7D3F261BU}},
		{{0x9BF0B55AU, 0xB473E735U, 0xB65EEC02U, 0x08FF4B5EU, 0x7AD74DF9U, 0x7E45E2A3U, 0x6BBF191CU, 0xDDD397E7U},
			{0xDE7703F8U, 0x8C92A35FU, 0x049C4F5FU, 0xF4785802U, 0x2676E1A2U, 0xA9BC86F1U, 0x4548B967U, 0xA2C7DA8EU}},
		{{0x5A4144E0U, 0x690815F1U, 0x5D923ACFU, 0xE2293801U, 0xA9FA2767U, 0x8A15BD73U, 0xD2AF259FU, 0xB7906A34U},
			{0x8E4A4146U, 0xD416AEF8U, 0xB79F22E6U, 0xFE6BA604U, 0x73575CCDU, 0xAC724FDDU, 0xB53F69ADU, 0x968DF54BU}},
		{{0xA875FDC2U, 0x0F3698A4U, 0x91B919C9U, 0x10AFC3ECU, 0xFA2068D1U, 0x2F1FAF33U, 0x2D439404U, 0xA3A85B91U},
			{0xF66DB407U, 0x3A622EADU, 0x98B8AD8CU, 0x7CC7B295U, 0x538FB0D1U, 0x78C7EA7CU, 0xF8123BB3U, 0xBBDF3A12U}},
		{{0x332B78A9U, 0xFC484E3BU, 0x09CA2996U, 0x0B60C723U, 0xBA95DEBCU, 0x5CBB5E7DU, 0xB3619E31U, 0x7304C2ECU},
			{0x71AD1762U, 0xE79AED16U, 0x82185905U, 0x05D55877U, 0xB20E3391U, 0x10CCC33CU, 0x8B0AECCEU, 0x44C596BCU}},
		{{0xF53139F3U, 0xE767E269U, 0x7B162577U, 0x1CFC2DA2U, 0x71624055U, 0x31442E1AU, 0x094C7B28U, 0x99729FBEU},
			{0xED80410CU, 0x6A536961U, 0x37B49861U, 0xDA1B75B4U, 0x77A82D71U, 0xD0AE2F91U, 0x437C160CU, 0xF598B747U}},
		{{0x72C95A4FU, 0x40E2992DU, 0x93FE76FFU, 0x83A1A46BU, 0xEF35C9DDU, 0x710D42C5U, 0xC6562BD9U, 0x7FFBB9F5U},
			{0x403EB751U, 0x0DD0D68EU, 0x54DC2422U, 0x574D2D90U, 0xF8B44B04U, 0xA90C6195U, 0x0BD7728BU, 0x10DAB1CAU}},
		{{0x1171C31EU, 0xB1AB6D56U, 0x0AA77791U, 0xFF5479ABU, 0xD6C9C858U, 0xD0BCE8ABU, 0x9DE531DBU, 0xD35AB2B2U},
			{0x17E889BAU, 0xF739BDBDU, 0x6AC44639U, 0x50BEA93BU, 0xA69569F4U, 0x8A399661U, 0x043F1173U, 0x72C6C999U}},
		{{0xFC73E042U, 0x5A6B96F5U, 0xE53760B2U, 0x3D02D2B0U, 0x380626A9U, 0x53A35409U, 0x539E7DB2U, 0x669980E2U},
			{0x7A7B0038U, 0xB7B5C8D9U, 0x1CFBA555U, 0xDD73406AU, 0x272EF5C4U, 0x169FCDF4U, 0xD7BBA10CU, 0xFF06AE90U}},
		{{0xF6F67604U, 0xF7DF7DE6U, 0x8A925A9DU, 0x6BA7EBCDU, 0xEF0457A0U, 0x0A908049U, 0xFFB1ED64U, 0x0F7919D8U},
			{0x41A3BB40U, 0xA4F6E54FU, 0x93C22067U, 0x400243A1U, 0x2076413CU, 0xE4D2B4D8U, 0x93308E54U, 0xD5F9EFE3U}},
		{{0x886B48B9U, 0xD1CE02B0U, 0xE5339020U, 0x2FD0FC85U, 0xF87BC53DU, 0x2C73527CU, 0xD7129674U, 0x94390518U},
			{0x260A1134U, 0xAE0AD814U, 0x9542D1EFU, 0x70CA8C09U, 0xA8ACA5DAU, 0x5FA1D7D4U, 0xBE91F62EU, 0x33CDDBD9U}},
		{{0xA523F63FU, 0xDAC48E18U, 0xB2AD5777U, 0x3186653EU, 0x7BE7A7EDU, 0xC9E99342U, 0x0B2E84DAU, 0x22360D61U},
			{0x979CE258U, 0x1190A9A0U, 0xD3832926U, 0xF9E875F3U, 0xCC592B2FU, 0x38462039U, 0x15A1318EU, 0xE5463F33U}},
		{{0x94784F54U, 0x1B1F4FC9U, 0x47DA4E3BU, 0x59B9F95DU, 0x0D253003U, 0x3318C585U, 0x9776462FU, 0x5DC0CBC7U},
			{0xBFB42D52U, 0x6875D030U, 0x8C40B03AU, 0x10E0B532U, 0xF7EEC471U, 0xDDBB33C9U, 0x5D698FF2U, 0x35CB8684U}},
		{{0x31816299U, 0xEBEACE49U, 0xCA1B6FB4U, 0x05F04B9AU, 0xEBB62BC4U, 0xB5E94346U, 0x2DF78D3FU, 0xC752D77EU},
			{0x728E7F5BU, 0xC0B45FF3U, 0x70C2B812U, 0x303229F7U, 0xA957AE6AU, 0xA3831D10U, 0xBB55AF1EU, 0xFA620759U}},
		{{0xABA19201U, 0x5D819DB1U, 0xC7E96BAEU, 0xD62BA642U, 0x3D218C30U, 0xF2DDC2A9U, 0x81CE2CF8U, 0xF2B654B9U},
			{0xF557DA7FU, 0x122B4170U, 0x05CA7973U, 0x30E09F60U, 0x13FA9895U, 0x746478B0U, 0x8DBC49E1U, 0xCFF608E1U}},
		{{0x0555A23CU, 0x68278335U, 0x108FE179U, 0x0F722C21U, 0xBE05B1B6U, 0xEA8BF2BFU, 0xE180DDBAU, 0x36E99010U},
			{0x55C248D9U, 0x38C2FC97U, 0x6BB950D0U, 0x12D2C032U, 0xB470C36AU, 0xDA685117U, 0x700AA61AU, 0xD1ADEF11U}},
		{{0x2F40F053U, 0xDF4ACA6AU, 0xC6E0EA5FU, 0x5D9F2592U, 0xCC21B8AAU, 0x341D75C5U, 0x1D5FEA71U, 0x7579CBBDU},
			{0xD0B83674U, 0x60E54197U, 0xF494A853U, 0x126E994DU, 0xAEA22EA3U, 0xF770A4EBU, 0x9E772B19U, 0xE003DD5EU}},
		{{0x4B1156AFU, 0xFFE3600EU, 0x6BBAF1E1U, 0xFC20E218U, 0xCBE594D0U, 0x34DA738FU, 0xB6CB6440U, 0x121CCBCAU},
			{0x2B62193EU, 0x38B018DCU, 0x7415A42AU, 0xE44D23FAU, 0xB1DAC463U, 0x700A2B6BU, 0xCA1EF367U, 0xA60E3788U}},
		{{0xDDDD6659U, 0x5666054BU, 0x20E7D0A0U, 0xA8A17590U, 0x37AC362EU, 0x5B0D7C80U, 0xC0B2C58DU, 0x29268190U},
			{0xD9E5AD53U, 0x7FBD9AEFU, 0x3A14A909U, 0x9DE6D1F9U, 0x3315BC01U, 0x6C5199F2U, 0x1CC7E2BFU, 0x33A6B276U}},
		{{0x2C6B9710U, 0x2F26BA7AU, 0x9A8D00E1U, 0x39F6234FU, 0xD02B7F81U, 0x3F2BCCE0U, 0xD1C5BC5CU, 0xD46F1A25U},
			{0xEC294094U, 0x3CB52353U, 0xF229CAECU, 0x7D448416U, 0x1C45C168U, 0xC3D8933FU, 0x8E19EAA8U, 0x79E8C681U}},
		{{0xC06A229EU, 0x34D8192BU, 0xCE7C6438U, 0xD44EBE29U, 0x2D0407B4U, 0xD3835BE7U, 0x54AF357AU, 0x97A20DA4U},
			{0x7054ADDBU, 0xF8AE5B78U, 0xB55BB1BAU, 0x8B01F12EU, 0x19380AF2U, 0x45677F56U, 0xDA4D4E31U, 0x81FF3404U}},
		{{0x1BD05FD1U, 0xD55307AEU, 0x6361378EU, 0x3698338CU, 0x7D6F7BA8U, 0xBC1F33F3U, 0xBD196689U, 0xF3DE614AU},
			{0x2DBBCD10U, 0x6E6FB62EU, 0x328C0531U, 0x083995A2U, 0x523F1958U, 0xD9FD96BEU, 0xDA98B55BU, 0xC837BB3AU}},
		{{0x33A85C1FU, 0x817D9D30U, 0x93F28AE5U, 0xF78768A7U, 0xED5FF632U, 0xC90350D3U, 0x5FD3AAE6U, 0x00381E58U},
			{0x491485B5U, 0xF314B0F5U, 0xC702376BU, 0xBC8562E9U, 0xFC915929U, 0xA7F50C06U, 0x77A8BD00U, 0xEF3D7BB3U}},
		{{0x34A3AEB8U, 0xB8F01D71U, 0xF0F494A8U, 0xD1D75AE0U, 0x370BF979U, 0x11766948U, 0x98392E0CU, 0x321537ABU},
			{0x6C5EDACEU, 0xD2FFD43EU, 0x91AC65CFU, 0xAAC0694AU, 0xCA5E4326U, 0x05193F2EU, 0xF65595DAU, 0x436DFE92U}},
		{{0x2D6D2261U, 0x30DBDB03U, 0x0A712D66U, 0x9C2CC5EAU, 0x91BE6C9BU, 0x04096F3CU, 0x0AAB7E15U, 0x0410F050U},
			{0xF6831D44U, 0x6ACD71DBU, 0x732F1B08U, 0x6E118CECU, 0xA4E928F8U, 0x942EF8CCU, 0x42577CCBU, 0xB9395357U}},
	},
	{
		{{0x4A6B4D7BU, 0xAA74F081U, 0xD0D22F33U, 0x17459308U, 0x396D5B88U, 0x230E642FU, 0x5B70D9B5U, 0x59925E8EU},
			{0xE988E8C6U, 0x85DB3608U, 0x3D5D11F0U, 0xC8482150U, 0xFAD7CBE0U, 0x286792D8U, 0xEE1DA897U, 0x68D954EEU}},
		{{0xC2429516U, 0x9149DA66U, 0x223D4474U, 0x76773E7EU, 0xF1E55871U, 0xFC15000FU, 0x6C7398CEU, 0xD7CFBCACU},
			{0x9FEDAF54U, 0xB3DBF81CU, 0xF74F0986U, 0x20623564U, 0x23C3B500U, 0xA9366C28U, 0xE639EFA5U, 0x0CB31D9EU}},
		{{0x29C7E0E6U, 0x8B659676U, 0x738308AEU, 0x88FAF8A2U, 0xF96E7621U, 0x90B97DB7U, 0xEF1F4BE4U, 0x52102D49U},
			{0x7C031E27U, 0xB37222DAU, 0x2FF0F1E6U, 0xA46618F2U, 0xA9BE360CU, 0xF853C6FBU, 0x055A9B24U, 0x9CC02E8CU}},
		{{0x2E4C53F8U, 0xE021A079U, 0x7370173FU, 0x0AF8A6C2U, 0x72A95AC1U, 0x22F2B415U, 0xDB19ED3AU, 0xCB550D5AU},
			{0x1D6B4C3BU, 0x6518B416U, 0xE5945205U, 0xC19C459AU, 0x94E88A9FU, 0x3FDEA6AAU, 0x384A77C1U, 0xA3FE44EEU}},
		{{0xBD79A507U, 0x2BE21857U, 0xDDF73DF8U, 0xC0998677U, 0xE10C705BU, 0xD01EB81CU, 0xCDAF5044U, 0x6BBB345DU},
			{0x5FFBE536U, 0x585818ADU, 0x7B9D49BCU, 0xD48F9DF3U, 0xF68591AEU, 0xC9B90499U, 0x87BC73CCU, 0x1C4DAB45U}},
		{{0x721B4A9CU, 0xFB4AB5F0U, 0x4CE9AA8CU, 0x5F9B4E47U, 0xD0224ACDU, 0x12BCD4C1U, 0x326DD07EU, 0xC1AD6AABU},
			{0x19058AFAU, 0x6139FF3CU, 0x261010F0U, 0x7F4F3653U, 0x4BFAB0AFU, 0x33480A5CU, 0x8260E2B2U, 0xD0C05BF4U}},
		{{0x63452D63U, 0x4259177CU, 0x0FFEB89CU, 0xAC2B4571U, 0x7607C930U, 0x4ADEBFDEU, 0xCE82B0A4U, 0x6BBC01F0U},
			{0x32F28816U, 0xB275B966U, 0x02C56554U, 0x076A3100U, 0xD818C1B6U, 0xDB580306U, 0x4A2272B1U, 0x3C0DF0E4U}},
		{{0x31C2BB5DU, 0x33CAC5DEU, 0x76963CB5U, 0xE75581C4U, 0x5231A36BU, 0x0583EE4FU, 0x007C69F0U, 0xEE03F7DCU},
			{0x7CB8AFE6U, 0x9A675C58U, 0x0D58463AU, 0xA377EDD2U, 0x7A984D83U, 0x5CE62F14U, 0x8513F201U, 0x16EA2A3BU}},
		{{0x3D1F7A0AU, 0x5404D6B0U, 0xDC5BC9CDU, 0xD0E1AC0AU, 0xD7F31B40U, 0x3CBBD5C6U, 0xDAC2BE1EU, 0xAB2999BFU},
			{0xF10B70B6U, 0x2CAEA454U, 0x3A018F54U, 0x5BB626EEU, 0x067D17E7U, 0xF6EF3B60U, 0x05189520U, 0x98860E8BU}},
		{{0xC1F89A66U, 0x8851B053U, 0xE76FC448U, 0x1921D0D3U, 0xFDE37207U, 0xF34A74C9U, 0xF2D855D7U, 0x5D54E7D1U},
			{0xC31C208CU, 0xBCC29F8BU, 0xE4C84762U, 0x3E5659C1U, 0x4621CA67U, 0xDD181262U, 0xC4F85F5BU, 0x875A1A98U}},
		{{0xC15B8AD4U, 0x55EEAD68U, 0xE1DA0823U, 0x411831D8U, 0x0C24400DU, 0x1D073FEEU, 0x124B8586U, 0xCC0E0E09U},
			{0xD6DD3187U, 0xD76A6D25U, 0x563953FBU, 0x6C0FEF64U, 0x45CE6D30U, 0x907C02BAU, 0x3CE4206CU, 0xE1EF7D6AU}},
		{{0x1B341BE8U, 0x7944000AU, 0x8677EF5AU, 0x99F625E9U, 0xB42F7128U, 0xA74EBB2AU, 0xFA90A6E5U, 0x9EC5986AU},
			{0xDD704BAEU, 0xC6E29BBCU, 0xDEA1A1D0U, 0x093B816AU, 0xCE4FDD17U, 0x936E8446U, 0x467229ACU, 0x028E3789U}},
		{{0x2194F68EU, 0xE2CB0F82U, 0xFEAB884AU, 0xDD1F31A3U, 0x1A643132U, 0x37DBB7D8U, 0xCADA5C3AU, 0x6BF781E8U},
			{0x535D37DBU, 0x7B0631A4U, 0x86B653BDU, 0x3C2DC850U, 0x30E5AC4BU, 0x2ABED5E3U, 0x5F2CD850U, 0xC21E639CU}},
		{{0x4D7762DEU, 0x93E0F468U, 0xE92EDD2FU, 0x4572F6EFU, 0x81B2DCAEU, 0xDAF1F799U, 0xD7344C4FU, 0xB52F729BU},
			{0xE16D553FU, 0xDE5823A6U, 0x66C224F4U, 0xF4AB4B7CU, 0x48FE7FFBU, 0xF420533DU, 0x5B4AE60BU, 0x57CC98AAU}},
		{{0xC6F08B4DU, 0xEF87A2E7U, 0x1D18D268U, 0xB0EBCACFU, 0x9C7D5451U, 0x634F0EBDU, 0xDE066A30U, 0xA3318B9CU},
			{0x2580268EU, 0x9CE3785EU, 0x3343D8B4U, 0x811B59AFU, 0x9B21BC4FU, 0xDA42FF93U, 0xB1C3B6E6U, 0x62C86FCDU}},
		{{0x241507A2U, 0x6243E9B8U, 0x2B237781U, 0x68AB873FU, 0x5526ADF7U, 0x0E53B515U, 0xDF40FA2EU, 0xAC542701U},
			{0x686808E7U, 0x9EE929C6U, 0x176C5288U, 0x44977CAAU, 0x867C9C46U, 0x1375FD2BU, 0xCDB2E6D2U, 0xB1395E94U}},
		{{0x51EBCC10U, 0x064E4C0AU, 0x3E3F6C8AU, 0x3AE613CDU, 0x12DC7AFDU, 0x22167590U, 0x3A66DD49U, 0xEBA5CACFU},
			{0x22967FC0U, 0x55B1C690U, 0x2FD357F4U, 0x72BE687EU, 0xB7F233DFU, 0x2B6F7193U, 0x9078B30FU, 0x6D84F95EU}},
		{{0x13026EBAU, 0xD18D9AC9U, 0x75D17721U, 0x4869F89BU, 0xDBA41125U, 0x47ADE759U, 0x0B363C3EU, 0x78BCBC9FU},
			{0xD7C49530U, 0x8AF5F5BCU, 0xC54F6AE8U, 0xA23A1BC9U, 0x97226C39U, 0xC2627C8AU, 0xD090AE98U, 0xD25EDB99U}},
		{{0x3204DB4BU, 0x46E638CAU, 0x13E262D2U, 0x461AB99CU, 0xECC5CBB9U, 0x9C6FF7AEU, 0x2CCD0FD8U, 0x84930680U},
			{0x04D52B6BU, 0xB2DE05E0U, 0x11D07055U, 0x867DFC33U, 0x09AA9778U, 0xB7E6E04CU, 0x0E202CF3U, 0x7DE92541U}},
		{{0xCDCBE0B1U, 0xFC0FE5C0U, 0xF42B9AC5U, 0x5F0C8DD5U, 0x33333262U, 0x30CC28A4U, 0x5A027ADFU, 0x51D1FE2FU},
			{0xF13BFC44U, 0xF8ED01E0U, 0x6924632CU, 0x97D8A877U, 0x6265BB60U, 0x82D469E7U, 0xBAEB6E5EU, 0xC1A9D1E8U}},
		{{0xF101AE08U, 0xA98EB54CU, 0x75626D64U, 0x6F2D3845U, 0x49121970U, 0x87599623U, 0xBF2A30CAU, 0x8B3D8E81U},
			{0x09F83428U, 0xD038EA25U, 0xD28FAB4AU, 0x16F121F1U, 0x6331E644U, 0xA29BAB45U, 0x15B243C0U, 0x902C8621U}},
		{{0x285A299DU, 0x2D9699E8U, 0xE8D88555U, 0x889A2A14U, 0xF53F77A5U, 0x37F34B6EU, 0x43585CE7U, 0x1AF0AD89U},
			{0x31AD76C1U, 0xBD9BFB7CU, 0xBDC78883U, 0x46FABC6BU, 0x354685FDU, 0x585D1433U, 0x8E95B326U, 0x932A053AU}},
		{{0x930CFE0DU, 0xEB27D06EU, 0xA523543EU, 0x6F28F816U, 0x0EDF92F1U, 0xA53434FDU, 0xBCE3B4B5U, 0x257ED189U},
			{0x07C7D4A4U, 0x23752F3CU, 0x69428A37U, 0xBC53663DU, 0x7D25B711U, 0x0BDBFAEEU, 0x185C6B3CU, 0x2E5DD8C6U}},
		{{0x54B606FEU, 0x042716A5U, 0x462FE09CU, 0x28BD0E80U, 0x94E1ED7FU, 0xE42D366EU, 0xCB60306CU, 0x0E026A68U},
			{0x2E34B36EU, 0xAF6481E2U, 0x40C27DBEU, 0x00188F0BU, 0x5729930CU, 0x06F6D879U, 0xE85CAEACU, 0x4ABC2A44U}},
		{{0x99D239AAU, 0x3AA1DC21U, 0xFE97B917U, 0x93FBA620U, 0xD1BFFC7CU, 0x79605ABAU, 0xF825F76AU, 0x420A57B1U},
			{0xE72E0681U, 0x2F39F031U, 0x46451E72U, 0xBA3FB168U, 0x4A51956CU, 0xC12A3879U, 0x6EB87560U, 0xD1606D19U}},
		{{0xDC8EBDCAU, 0x5997B48EU, 0x6CAF1919U, 0x40A63093U, 0xDD666C80U, 0x738C6CB5U, 0xE388AF11U, 0xB9B7168FU},
			{0xC35284B8U, 0xE5DC4190U, 0xD953B8BBU, 0x47621096U, 0xB3882CA5U, 0xAD5E7286U, 0x4743DCBAU, 0xC7045E5FU}},
		{{0xBCE1AA49U, 0x76769D43U, 0x329FAF12U, 0xCD56DAAFU, 0x5B3AA4F5U, 0x82DF8E94U, 0xF3048891U, 0xCA76B0D4U},
			{0x66A0C0C1U, 0xEB0B06DEU, 0x3AF2C53BU, 0xE82127EEU, 0x0E3B9A9AU, 0x36ADA9EDU, 0xFCE9A485U, 0xFD48451CU}},
		{{0xEFB28650U, 0x00A20DAAU, 0xE4D91E47U, 0x2F5E84C1U, 0x2E291764U, 0x5E95DE2CU, 0x7510D5A7U, 0x8572EB6AU},
			{0x3847B8CBU, 0xF55178BEU, 0x41E1A311U, 0xD87CB375U, 0x6A5CB6F2U, 0x83F7441AU, 0x8E5B6D6AU, 0x44142E50U}},
		{{0xF1B41111U, 0x6CD3A374U, 0xFFD063A5U, 0x4859171AU, 0xAE033768U, 0xF12511C8U, 0x0C1CB1D1U, 0xF066990FU},
			{0x2C53FED4U, 0xF1657B91U, 0x4248567FU, 0x356A7624U, 0x6D4D6202U, 0x09869F90U, 0x94322808U, 0x19A13CA7U}},
		{{0xB78AFE42U, 0xA2B3A247U, 0x18C6995DU, 0xC39E32D2U, 0xCB6D70AAU, 0x3677C300U, 0xB76EE0A8U, 0x151524D2U},
			{0x699926E0U, 0x71D606B8U, 0x8F68F279U, 0x998FD251U, 0x53467468U, 0xCA4AA262U, 0x50E72837U, 0x4067C166U}},
		{{0xF18A7F19U, 0x2B10A48FU, 0xFD1688CAU, 0x65397A81U, 0x1C96011EU, 0xD87D4351U, 0x6246C4FDU, 0x1FD9D0F6U},
			{0x935434A6U, 0xCA255733U, 0x2020AF00U, 0x8B95E568U, 0x14C80343U, 0x2B59403AU, 0xF4E31580U, 0x1CC1659FU}},
		{{0xEB9FBBEEU, 0x97545F47U, 0x58E5BCC4U, 0x95917B89U, 0x05C7F749U, 0x92135EC6U, 0x6B44C4AAU, 0x48FD6542U},
			{0xF2BEB176U, 0x0719B6CCU, 0x9C348E8FU, 0x9F978538U, 0xC43C9C60U, 0x2E5FB742U, 0x79B10E73U, 0x9BAE786EU}},
	},
	{
		{{0x6286B2CFU, 0x7C0F9F1CU, 0x9FC3BDA9U, 0x546294FBU, 0xFDBE0F99U, 0x125F452EU, 0x5DFDCE13U, 0x7AA11FCEU},
			{0x9BEB92D9U, 0x8FCB312AU, 0xB6C7B8FEU, 0x328880B5U, 0x45042D16U, 0xF5BDDD5BU, 0xE02EF7A8U, 0xBC7E1A23U}},
		{{0x874031E8U, 0xC466A8F0U, 0x98E0FC79U, 0x5BB46A31U, 0xDA6F088DU, 0xCE491CF2U, 0x9EDA1D60U, 0x787CC2D0U},
			{0xA68D9512U, 0x88F46B51U, 0x21909741U, 0xDEAB3798U, 0xAF297AF6U, 0x19CDCAFAU, 0x46FA0F42U, 0x97CD6DC5U}},
		{{0x2B2146ACU, 0x82A3EFD1U, 0x75B73278U, 0x1CECA6FEU, 0x7FD3E96EU, 0xDB4FFD73U, 0xF771B621U, 0x8A82779DU},
			{0x1C2A0A37U, 0xB81BD243U, 0x14382709U, 0xEBFC01E0U, 0xA1077D02U, 0x7D2CEAB2U, 0xD709BC16U, 0x1D030684U}},
		{{0x802D8D16U, 0x9F65C8FCU, 0x0FCAB9F0U, 0xD972E087U, 0xCC5BA7B8U, 0xFC9632DBU, 0x2DD5C388U, 0x3FBBF784U},
			{0x83B73926U, 0x44D5ED92U, 0x7F7F175CU, 0x6AA32FE5U, 0x7B541738U, 0xEDA213CFU, 0xC2497B2FU, 0x16F57069U}},
		{{0xDD3E29C5U, 0xFAB43F93U, 0x99B7766CU, 0xC8E0D00EU, 0x589614D1U, 0xA5590211U, 0x31EB477BU, 0x69C2C2C2U},
			{0xAA1B47B0U, 0xE21A51FDU, 0x1B8683BAU, 0x91442DB2U, 0x24DDD553U, 0x4BFCDA3AU, 0x156AACCCU, 0xF03169A9U}},
		{{0x54C5B38AU, 0x7ECC088DU, 0x869977EEU, 0xD51ACD1CU, 0xFF625734U, 0xA56ACFDBU, 0x8C151542U, 0x4A01B002U},
			{0x620ADFFCU, 0xD6C80D77U, 0x1AA44119U, 0xD8BF8605U, 0x21B9AF3BU, 0xA18DCA59U, 0x2D5D5D92U, 0x9ADFABCEU}},
		{{0x795034B7U, 0xA4A91C4AU, 0xF36F18A3U, 0xACCE5687U, 0x5B1E3CE3U, 0x08321DDBU, 0xAB6369EDU, 0x795C7565U},
			{0x37AFB37FU, 0x487D42CFU, 0x0ACE8E90U, 0x057459FCU, 0xF4D8AC18U, 0x0359C4CCU, 0x818E0937U, 0x0D84B8D2U}},
		{{0xE323FE2AU, 0x88DBF571U, 0x89081B0FU, 0x1FCE5D43U, 0x6D053B84U, 0xF94CF853U, 0x00233CAFU, 0x95C5550DU},
			{0xD39A394FU, 0x0AFB5C85U, 0x465031A5U, 0x4BADB9FDU, 0x974FABA7U, 0x1AE7AFAEU, 0x53CC5C75U, 0xB5281147U}},
		{{0xC3971D69U, 0x8BAD1AE6U, 0xD34F516EU, 0x078708E8U, 0xA57A2F5FU, 0x6B4898E8U, 0xF614AC17U, 0x69D4E15CU},
			{0x6A34FAD4U, 0x6C4C01F6U, 0x8EB093EAU, 0x3D59CD37U, 0xEB85750FU, 0x86A1C339U, 0x89BC5B82U, 0x0D2AA93FU}},
		{{0x681C6043U, 0x2246FDA4U, 0x0C30C938U, 0xD7B988EEU, 0xA64BDFDDU, 0x7D30C88DU, 0x89196603U, 0x40822B8EU},
			{0x703261FAU, 0xEAA4EBEDU, 0x3A302811U, 0x3D6741BDU, 0x51E087F0U, 0xA1744385U, 0x90F3F673U, 0x4E3F9E19U}},
		{{0x668F1110U, 0x5E092C4AU, 0x15B4E717U, 0x41253BCAU, 0x0D5BEC01U, 0x27AFCBEBU, 0x4B9E9A3CU, 0x78C7F11CU},
			{0x676A44D0U, 0xFB01FFE5U, 0x6111BE75U, 0x62A464BDU, 0x1CA3C99FU, 0xD41DA73FU, 0xED68AD95U, 0x51AA4DD6U}},
		{{0xABC75D15U, 0x09CD0E95U, 0xEE8ADA07U, 0xF3DBB481U, 0x8A1D3610U, 0x481D44EDU, 0x992CF119U, 0x7DE20FE6U},
			{0x8F6687CDU, 0x4569A59EU, 0xA90CD3F9U, 0xE6E7AD0EU, 0xD947E31AU, 0x9C0161CFU, 0x3811770DU, 0x3277C7BEU}},
		{{0x79933F3BU, 0x647E205DU, 0x68C40917U, 0x7224EC92U, 0x16C12323U, 0x3E58ABD7U, 0xBEC709A6U, 0x3DF6CE24U},
			{0xEC60CDF6U, 0x214C5762U, 0xE2699CFCU, 0x18663827U, 0x78878188U, 0xCAACAB58U, 0x6AE09FC4U, 0xE07A6C61U}},
		{{0x706045FFU, 0xACBA163BU, 0x6D0E0D19U, 0xB124481AU, 0xD7202AE7U, 0x388102E6U, 0x1FC01DB2U, 0x1E533289U},
			{0x6A8C51B3U, 0xB7211F51U, 0x8AFB2C61U, 0xDAFDCF24U, 0x4D124DCFU, 0xD48A6C55U, 0x31552F71U, 0xF21E391CU}},
		{{0xC4C0E23AU, 0x81386532U, 0xB738C9DCU, 0x3C63EDBAU, 0x4174D3ADU, 0xF5EB5D08U, 0x16F563A3U, 0x28A80E18U},
			{0xB72ACE3CU, 0xCFF439ADU, 0xAAB70BDCU, 0x4E76B153U, 0xC77ABDC2U, 0x78C0D21BU, 0xB9CBAAB4U, 0xA508C7C4U}},
		{{0xBC3CDB11U, 0xD79BBE93U, 0x173C8B27U, 0x259935E7U, 0xC6BD33D6U, 0x43BA75FAU, 0x765FE535U, 0x89B4927CU},
			{0x7A79D11EU, 0xCC5FB136U, 0x93A52126U, 0xA99C1C95U, 0xCB178888U, 0xBE3A10DEU, 0x5487EAE9U, 0x43EF0F71U}},
		{{0x6AD7616AU, 0x2CFE0533U, 0x20A2CD0DU, 0xCB37AB40U, 0x6521A441U, 0xBFFF9B26U, 0xD64455E7U, 0x5E32C250U},
			{0x001B4B95U, 0xADA1FB2FU, 0xE9BA4FD7U, 0x7587B15BU, 0x8329F96FU, 0xA34F8541U, 0x731CB904U, 0xC62F247EU}},
		{{0x4C3E3392U, 0xFEF95616U, 0x95FCA932U, 0x1A549FC9U, 0x3DB36462U, 0x1BD12D71U, 0x0C9F637BU, 0xF2755A4CU},
			{0x15FA1703U, 0xA4897D67U, 0x3444BCF7U, 0xDED71DC2U, 0xCF4EFE79U, 0xE8D41B09U, 0xC2006471U, 0xB5A47B45U}},
		{{0xE9ACB2D3U, 0x91C5A815U, 0xC10E1C39U, 0x14F020B9U, 0xE5A6D4BDU, 0x0A6E9921U, 0xFA46283DU, 0x9A084984U},
			{0x06D278EBU, 0xED44F288U, 0x7FB36412U, 0xBE381AEBU, 0x831FC6D2U, 0xC411AEB9U, 0x86A1BFAAU, 0x7C7DE274U}},
		{{0x7D950027U, 0x1AFBF3E1U, 0x71A038A5U, 0x4B89E70AU, 0x0466855CU, 0x29DF9898U, 0xD46C9001U, 0x50A3574FU},
			{0xC16C93B9U, 0x9C952065U, 0x67CAA4EBU, 0xC3FCF9E4U, 0x06405B60U, 0x21DA3568U, 0x43EAB4AAU, 0xCAE5105FU}},
		{{0x185AC0A1U, 0x5A027720U, 0x166F6289U, 0xF8F9BC23U, 0x9645DAC2U, 0xD157A3A1U, 0x94E83F41U, 0x7BA4E228U},
			{0x47BE2D41U, 0x37254AACU, 0x662EFCE7U, 0xB0341B39U, 0x1FE725DDU, 0xFD876B3DU, 0x930D44DAU, 0xFE05A7E2U}},
		{{0x40472A03U, 0xE118C872U, 0xAEAB57CAU, 0x4C6C2FACU, 0x43F429C4U, 0x4D512F2DU, 0xC7DF9BA2U, 0x03401EF0U},
			{0x0D38EE98U, 0xECF2E1CBU, 0x22CAD42DU, 0x44D7205DU, 0x1A456DB8U, 0xD39B2F47U, 0xE4CEC6A7U, 0x356F0F7CU}},
		{{0x5FA2F7E7U, 0xD3E044B3U, 0x33B1D256U, 0xFD702E36U, 0x30695AC9U, 0x7FDBE03FU, 0x88074020U, 0x70FA3709U},
			{0xB35EEE89U, 0x2D6D32D5U, 0xA10C3F28U, 0x982B59D3U, 0xF5B99D72U, 0x176E8DA9U, 0xE0A2B535U, 0xEF9221F9U}},
		{{0x1E3D7446U, 0x08B6055FU, 0xC1CD1E2EU, 0xBB9148FBU, 0x15AE2116U, 0xCE5E4C18U, 0xCF478FA8U, 0x6B05FB29U},
			{0xB9C9D7B9U, 0x57512488U, 0x1E9F6C6EU, 0xA7D6D67DU, 0xF8F1C21AU, 0x4A9E9C0BU, 0x47EA190DU, 0x029A50C3U}},
		{{0xF716FD28U, 0x3E31C1FAU, 0xB565E64EU, 0x3B836D9EU, 0x32C87559U, 0x7E34CA16U, 0xAA1811C5U, 0xA543CB2DU},
			{0xA561B1F8U, 0x02B8F9AAU, 0x555DB0B4U, 0x42AE64D1U, 0xF8B47C8FU, 0x45BD2198U, 0xAA8A0505U, 0x7627E520U}},
		{{0xA6A3CB29U, 0x346822A2U, 0x9EBF7B26U, 0xE665C2CEU, 0x1A47D496U, 0xF87F0FC2U, 0x8BB52C0BU, 0xAE75798DU},
			{0x3E56F22BU, 0x2DB1D658U, 0xC6950683U, 0x007BEDA0U, 0xAF89FD40U, 0xF96FFFC6U, 0x31631D12U, 0xF184B682U}},
		{{0x6E9DF8ABU, 0x7A62006BU, 0x7D77F416U, 0x154EF358U, 0x0373C434U, 0x216A4B21U, 0x565CFC4BU, 0x8AF13545U},
			{0xA103BEFCU, 0xA82BB5D0U, 0xBA493460U, 0xD483E4C2U, 0x670D0749U, 0x42FD5DB9U, 0xD7B944EEU, 0x7D2AEC32U}},
		{{0x8E868B17U, 0x908D2210U, 0x5226A7E9U, 0x6E1B052CU, 0xB9FB3276U, 0x21D05FE9U, 0xD34EC626U, 0xED8A583AU},
			{0x1DC500C5U, 0xDC02B5C7U, 0xE5DEF15BU, 0x3C16EBA1U, 0x61BDD24BU, 0x4B732E67U, 0xAF0667F9U, 0xEAC1942AU}},
		{{0x1E45DBD9U, 0x39ED2F13U, 0x37FD28F7U, 0xD7278B3BU, 0x0B723C54U, 0xB0F67426U, 0xF369E73DU, 0xA9BB3556U},
			{0xB52FFCDCU, 0xC2613B5EU, 0xD659EAF1U, 0x30D4DCFBU, 0x2C5E49E3U, 0x3DE2C21AU, 0xEFA0CA09U, 0xDC8B6970U}},
		{{0x6B393EDBU, 0x3BB28BD0U, 0x12712307U, 0xCF588C85U, 0x43597BACU, 0x91FA652FU, 0x381C397FU, 0xC5A4596BU},
			{0xAA97733CU, 0xAD6E4746U, 0x9E7F2D09U, 0x39B3BD8EU, 0x8151922CU, 0xAC7CE651U, 0x55C9FEFBU, 0x3AEAEEA3U}},
		{{0x9779D560U, 0xD971C912U, 0xF8B38AD0U, 0x83112A91U, 0xFC20056CU, 0x76D07B62U, 0xF28E068DU, 0xE249C00AU},
			{0x5545CF64U, 0xAE0AE62FU, 0x74FFA8B5U, 0xB6B4B4FDU, 0x6545BE72U, 0xE7924D00U, 0x19CE8DC7U, 0xD6409022U}},
		{{0xDC2932BBU, 0xA240E75FU, 0xDEACD939U, 0xF8F69E81U, 0xF886C205U, 0x6853C334U, 0x17B7888FU, 0x36F2E21FU},
			{0x3E2C8C97U, 0x1BF901B2U, 0xB72050F7U, 0x1EC021AEU, 0xDEF16F43U, 0x55ADED39U, 0x9D74BC53U, 0xF8AE913CU}},
	},
	{
		{{0x823E643FU, 0xE235DC4AU, 0x83C96BE1U, 0x63874879U, 0xA376C60BU, 0x8F683767U, 0x092F9254U, 0x75BDE5D5U},
			{0x0A672F73U, 0x628171E7U, 0xD327FDA3U, 0x348C72B0U, 0xA0508E38U, 0xFDC6FBCBU, 0x44BF87A2U, 0x642B1870U}},
		{{0x439974B3U, 0x0D917D6DU, 0xD68E0B4EU, 0x5C0CBB75U, 0x4CADDCC0U, 0xC2A005B1U, 0x29766A26U, 0x4E66E146U},
			{0x71535ADAU, 0x9711A859U, 0x0F6E8E40U, 0x9B2FF71AU, 0x8552E871U, 0x219112F5U, 0xD530F8E6U, 0x5DEBEAF3U}},
		{{0xD393BE8EU, 0xCC2EDBABU, 0x84581A57U, 0xC8CC2ED8U, 0x4BBEFBB1U, 0x2B65EB88U, 0xAEFEA1B2U, 0x915F3A45U},
			{0xFDECA358U, 0x08E58E6AU, 0x8CA70356U, 0xF1DAD115U, 0x03C6FE0AU, 0x90E4FFA1U, 0x87629A2FU, 0xB25E3BDDU}},
		{{0xD4F4E970U, 0x8306AD4BU, 0x05A8C25BU, 0x3118E937U, 0xBDC8C9E3U, 0x9CDDED3CU, 0x7C1A5725U, 0x2E1C3A6BU},
			{0x73ACF0A1U, 0x4CD326B4U, 0xF21A3175U, 0xA6BFDA97U, 0x1E00DA12U, 0x4F64BCA2U, 0xBBD27529U, 0x17B50465U}},
		{{0x2C32C63CU, 0x62273AABU, 0xEDE9E56EU, 0xCDEA1273U, 0xBCB285B3U, 0x437B5CC1U, 0xA8796B9BU, 0xA304FB42U},
			{0xF328655EU, 0x3CEA25DDU, 0x737A5B56U, 0x0B39149BU, 0x04D5F5F7U, 0xED47BC62U, 0x6C0595C8U, 0x0E452DF7U}},
		{{0x62DC5DE3U, 0x8B9906D7U, 0xFB42C0B9U, 0x46B9A973U, 0x0DC64D3EU, 0xF5EFEC37U, 0x8799AE68U, 0x6BE9A238U},
			{0x43313EC3U, 0xD568EBFAU, 0x82C067CAU, 0x7A77B27CU, 0x75E271B3U, 0xB273C20EU, 0x8450F025U, 0xCE33C82EU}},
		{{0x9CF3CCEBU, 0x5C54710FU, 0x0ACADCE4U, 0x2C7B4959U, 0x4F2BA7C2U, 0xDFE180ACU, 0x8F73F34FU, 0xFB24390DU},
			{0x9F04B9FEU, 0xA4363A96U, 0x8D137414U, 0x74B7BA49U, 0x3A5359A8U, 0xFDEED62DU, 0xE98C4FCDU, 0x62B0269CU}},
		{{0x624274F3U, 0xEB0BDA0BU, 0xD2FDE546U, 0x2F08FB7CU, 0xCFCE9855U, 0x28F2A39BU, 0x27D545ABU, 0xDEEE6E54U},
			{0x1D975C57U, 0x3FD487C7U, 0xE5297A43U, 0xBD6CC4FDU, 0xAC251A34U, 0x656815A6U, 0x293AFA05U, 0x2AF06F9AU}},
		{{0x2A2327E1U, 0x80207CD4U, 0xCEDFCDD1U, 0x8527834AU, 0x052A6FB1U, 0xE647FE09U, 0xAD2C3900U, 0xAEBBE677U},
			{0x57357603U, 0x53A9A486U, 0x9030A6CBU, 0xF9BA6B61U, 0xD828192CU, 0x0CCCBCE6U, 0xE5D13A67U, 0xC3E1E793U}},
		{{0x26D8BF66U, 0xDCD41611U, 0x9D7D385EU, 0x2A84DD4AU, 0x16BB71ABU, 0xB915B0D4U, 0x80E305CDU, 0xFF29F933U},
			{0x30770012U, 0x9C7707C9U, 0x467DC0E3U, 0x717654FEU, 0xCA5299F3U, 0x06CEB05AU, 0x3574FAD3U, 0xB2CE26A2U}},
		{{0x1C601DE9U, 0x68883050U, 0xB14758D3U, 0x73843C49U, 0x744127B9U, 0xB8B8481EU, 0x415578CBU, 0x635449CBU},
			{0xA1FDDE87U, 0x25682440U, 0xF92C8D04U, 0x369D8885U, 0x1FE324CCU, 0x5024708FU, 0x8816EA43U, 0x573A0F63U}},
		{{0xDE1CDBCCU, 0xCB7EC446U, 0x8442F587U, 0x4232E9CCU, 0xBA79DF51U, 0xC3348119U, 0x93FBF9F4U, 0xC3201210U},
			{0xF52DF449U, 0x1B5DE336U, 0x62AF4F3AU, 0xE55994A2U, 0xD61715FCU, 0xC0D1ADAFU, 0x04371F05U, 0xB9B180CBU}},
		{{0x34343F50U, 0xB0EF2F37U, 0x988B77F0U, 0x26E2C134U, 0x8800716BU, 0xBC697028U, 0x079F6EB5U, 0xC78780BDU},
			{0x4D5894B0U, 0x74CA26BFU, 0xC9F66C28U, 0xE0F73448U, 0x83D68A72U, 0xC0482C7CU, 0x5FA52771U, 0x3DB085F4U}},
		{{0x564AB06DU, 0x429A3BF2U, 0xA3663E43U, 0xB85ED0FCU, 0xB7A8242FU, 0xAC688EECU, 0xA62E9418U, 0x58508D37U},
			{0x98F13D28U, 0x25A73A99U, 0xE4D0F472U, 0xD0E126BAU, 0x3A8DAD74U, 0xDDD62646U, 0xF5475178U, 0x6B68806CU}},
		{{0xE83EE5ADU, 0x07DE0942U, 0x46964B26U, 0xD8F0F547U, 0xA72D872FU, 0x4A087F8AU, 0x6CBA2AA3U, 0x272355EBU},
			{0x9918C063U, 0xC68FA97EU, 0x15B10B94U, 0x12DE28FBU, 0xBE9F8FF5U, 0xBC3A6E7DU, 0x699E1B6EU, 0x8BEBB2D8U}},
		{{0xA3EDA6B0U, 0xED791EE6U, 0x6E152C0AU, 0x9D9043BFU, 0xF22C97ADU, 0x4294D133U, 0x9F74C19FU, 0xDC19EBD5U},
			{0x4A35961EU, 0x367D8C20U, 0x46B81FA8U, 0x3FF7AF74U, 0xDD7EEE86U, 0xC912AC8FU, 0x76DD1571U, 0xF38B0EFDU}},
		{{0xC6F2EE9CU, 0x78F456B4U, 0xA8E74A1AU, 0x768763A6U, 0xDAF69CB6U, 0x4F504957U, 0x1F34D07DU, 0x4249101BU},
			{0xC936ABE9U, 0xEE05924CU, 0x5F379CEEU, 0xC3BFC88DU, 0xBBF54D66U, 0x86070A2BU, 0xAE429F1CU, 0x7D0EF525U}},
		{{0x70A70F31U, 0xA5A2A5CAU, 0x53A51A4FU, 0x2B4A1AEEU, 0xFAB619A9U, 0xDAAF0E05U, 0xCA727AACU, 0x53BF733CU},
			{0x2A1C2C29U, 0x4D4A7A44U, 0x8714650CU, 0x27C4F326U, 0xD1E14F93U, 0xA43AF401U, 0x79EF1752U, 0x31A619B5U}},
		{{0xECC85026U, 0x63EEDAB0U, 0x24120329U, 0x1D9E24F9U, 0x4C916E09U, 0x55FC0F62U, 0x7A86D45FU, 0x0EC1F6ADU},
			{0x95F79183U, 0x83D65FC4U, 0xDC6F30A2U, 0x738AA909U, 0xA37FA5CCU, 0xB0671858U, 0x68DCAC11U, 0x6FD064B6U}},
		{{0x9070F596U, 0x70EB4DA3U, 0xDC378541U, 0x33064D88U, 0x49899686U, 0xBA8137BFU, 0x05C8B180U, 0x1571E854U},
			{0xFFE21909U, 0x843CB441U, 0x1C7F4FD2U, 0xBDFFBEE3U, 0xAEFB4BD1U, 0xBB7BDFDDU, 0x0E5FBE5DU, 0x1C397021U}},
		{{0x317BBE46U, 0xCB65DEBCU, 0x9FECC243U, 0x250A8FB5U, 0x7A5A4231U, 0xE864D7E7U, 0x819E3112U, 0xF767F728U},
			{0x0ABCBA47U, 0x23EE4233U, 0xEF2DB90BU, 0x6909F2E0U, 0xDEB56070U, 0x88F20C70U, 0xD773F024U, 0x343E29B9U}},
		{{0xA0B461C4U, 0x6D94219AU, 0xC85CEF86U, 0x0F5F2D68U, 0x06ED763BU, 0x1D550CD2U, 0xF563633BU, 0x54EDE445U},
			{0x12BBA8BAU, 0xCB8F73B8U, 0xCD21403EU, 0x92DA1699U, 0xBAA68D8EU, 0x0228AC8DU, 0xE8D76ECAU, 0xD2B45C62U}},
		{{0x2B50482EU, 0x75B85589U, 0xA7F426B9U, 0x5B4BC678U, 0x96B0338AU, 0xE8E7F51EU, 0x8CF1BD2AU, 0xE98F2F51U},
			{0x37A9614DU, 0x81C16FCFU, 0xF95E22B4U, 0xE8FBBD4AU, 0x1E6635B0U, 0x44D313C2U, 0xC4628A03U, 0x77C9FFB6U}},
		{{0x5C4B2FDCU, 0xEC47D0EFU, 0x9FEFD44CU, 0x178E31D0U, 0x3C157109U, 0xF9EF8DA9U, 0x6C1F898BU, 0x12E7F153U},
			{0xBB87441BU, 0x146B67F8U, 0xDBE355E1U, 0xE75690D0U, 0x3795EF99U, 0x032E1F65U, 0x58480729U, 0x6FEBC9E9U}},
		{{0xAC7EC62CU, 0x62BA1C8FU, 0x73ED4AE6U, 0xC60F07C5U, 0xF83BB48EU, 0xFD5DDDECU, 0xF5EDCE16U, 0x49454DDFU},
			{0x60AD920CU, 0xC7A94724U, 0x48393597U, 0x9B22DA38U, 0xD9F0B705U, 0xE36CC768U, 0xA7B632C9U, 0x780D14EEU}},
		{{0x6E6C16C8U, 0x6CDED9E1U, 0xEEB2DDC2U, 0x36460BA6U, 0x10A45729U, 0x23B5FD8FU, 0x462B1B99U, 0xAC3C479FU},
			{0x4E6BC15BU, 0xCA9049FCU, 0x90A612D3U, 0x327ED1B5U, 0x10B5D97EU, 0x76A1DDAFU, 0xCB7A2538U, 0xA36C3906U}},
		{{0x0D3C3CBFU, 0xC716D981U, 0x1DFEFD9FU, 0x4C2F5B0BU, 0x5792DBF7U, 0x50468BD5U, 0x93929E8FU, 0x49FD0A84U},
			{0x60E9801FU, 0x68BC629EU, 0x38CD1FA8U, 0x935B118EU, 0x293FE6F1U, 0xD4417460U, 0xE92E3B71U, 0xE886815DU}},
		{{0x94303F77U, 0xC6BF7D28U, 0x1518CEE3U, 0x3604B927U, 0x9BDF267EU, 0x0747FFFCU, 0x5BCEDB65U, 0xEEE0618EU},
			{0xF6DC087CU, 0xE33DA39FU, 0xB48AAE28U, 0x3A68220CU, 0xE7DD4491U, 0x91DFFE4AU, 0x4BCA5BF9U, 0x48C22DEEU}},
		{{0xDB69584CU, 0x6B4A6169U, 0x909DDAEBU, 0x90F391E4U, 0xF99184EAU, 0xD2909C2CU, 0x93C25C0CU, 0xD8CD6A32U},
			{0xDA844A99U, 0xBCF40D97U, 0x01482D12U, 0xED664260U, 0x682F1BA8U, 0xC46D714EU, 0x1964BE57U, 0xEF79E704U}},
		{{0x82177EA6U, 0xEB89FFD9U, 0xB1615F8AU, 0x736B6368U, 0x6663BCDEU, 0x95C63910U, 0x334207FAU, 0x2E0FEE03U},
			{0xDE6EAE4BU, 0xF336AC50U, 0x1DECC020U, 0xA200D829U, 0xDF066586U, 0x6632289BU, 0xD2344553U, 0x522E5C0DU}},
		{{0xAD80446AU, 0x819B07CAU, 0x39794853U, 0x26A106CDU, 0x46AD48C6U, 0x73463A64U, 0x3F3A24BEU, 0xD7EE76CAU},
			{0xFFF150B0U, 0x2F350DE5U, 0x0E9B25E2U, 0xD2EF244CU, 0xB8AF66B2U, 0x257B1CD0U, 0xA143F5F2U, 0xF9771078U}},
		{{0x3E146C35U, 0x3A07FFD6U, 0xA8165BCDU, 0x7632AAF1U, 0xF96C999FU, 0x18661DB2U, 0x7EE20DA6U, 0xAC7EC731U},
			{0x832C9668U, 0xB89F8713U, 0x5D5D8099U, 0x994B3766U, 0x64808DE9U, 0xE755FE51U, 0x4FF080ACU, 0x04496564U}},
	},
};

#if defined(ECDSAP256_NATIVE_64)

/*! \brief One P-256 Montgomery residue, least significant word first. */
typedef uint64_t ecdsap256_native_fe[4U];

/*! \brief One P-256 Jacobian point over the native Montgomery representation. */
typedef struct
{
	/*! \brief Montgomery projective X coordinate. */
	ecdsap256_native_fe x;
	/*! \brief Montgomery projective Y coordinate. */
	ecdsap256_native_fe y;
	/*! \brief Montgomery projective Z coordinate, zero for infinity. */
	ecdsap256_native_fe z;
} ecdsap256_native_point;

/*! \brief P-256 field modulus as four little-endian words. */
static const uint64_t ECDSAP256_NATIVE_PRIME[4U] = {
	UINT64_C(0xFFFFFFFFFFFFFFFF), UINT64_C(0x00000000FFFFFFFF), UINT64_C(0x0000000000000000), UINT64_C(0xFFFFFFFF00000001)};

/*! \brief The Montgomery representation of field identity. */
static const uint64_t ECDSAP256_NATIVE_ONE[4U] = {
	UINT64_C(0x0000000000000001), UINT64_C(0xFFFFFFFF00000000), UINT64_C(0xFFFFFFFFFFFFFFFF), UINT64_C(0x00000000FFFFFFFE)};

static void ecdsap256_native_load(ecdsap256_native_fe output, const uint32_t input[8U])
{
	/* convert QSC's eight 32-bit words to a four-word native residue */
	size_t i;

	for (i = 0U; i < 4U; ++i)
	{
		output[i] = (uint64_t)input[2U * i] | ((uint64_t)input[2U * i + 1U] << 32U);
	}
}

static void ecdsap256_native_store(uint32_t output[8U], const ecdsap256_native_fe input)
{
	/* convert four native words to QSC's eight-word representation */
	size_t i;

	for (i = 0U; i < 4U; ++i)
	{
		output[2U * i] = (uint32_t)input[i];
		output[2U * i + 1U] = (uint32_t)(input[i] >> 32U);
	}
}

static uint64_t ecdsap256_native_is_zero(const ecdsap256_native_fe input)
{
	/* return whether a native Montgomery element equals zero */
	uint64_t bits;

	bits = input[0U] | input[1U] | input[2U] | input[3U];

	return (uint64_t)(1U ^ ((bits | (UINT64_C(0) - bits)) >> 63U));
}

static void ecdsap256_native_copy(ecdsap256_native_fe output, const ecdsap256_native_fe input)
{
	/* copy one Montgomery residue using four fixed native assignments */
	output[0U] = input[0U];
	output[1U] = input[1U];
	output[2U] = input[2U];
	output[3U] = input[3U];
}

static void ecdsap256_native_choose(ecdsap256_native_fe result, const ecdsap256_native_fe a, const ecdsap256_native_fe b, uint64_t select)
{
	/* constant-time conditional assignment of a field element */
	uint64_t mask;
	size_t i;

	mask = UINT64_C(0) - select;

	for (i = 0U; i < 4U; ++i)
	{
		result[i] = (a[i] & mask) | (b[i] & ~mask);
	}
}

static void ecdsap256_native_add(ecdsap256_native_fe output, const ecdsap256_native_fe a, const ecdsap256_native_fe b)
{
	/* add two canonical native P-256 field elements modulo p */
	uint64_t sum[4U] = { 0U };
	uint64_t reduced[4U] = { 0U };
	uint64_t carry;
	uint64_t borrow;
	uint64_t mask;
	size_t i;

	carry = 0U;

	for (i = 0U; i < 4U; ++i)
	{
		sum[i] = ecdsap256_word_add(a[i], b[i], &carry);
	}

	borrow = 0U;

	for (i = 0U; i < 4U; ++i)
	{
		reduced[i] = ecdsap256_word_sub(sum[i], ECDSAP256_NATIVE_PRIME[i], &borrow);
	}

	mask = UINT64_C(0) - (carry | (borrow ^ 1U));

	for (i = 0U; i < 4U; ++i)
	{
		output[i] = (reduced[i] & mask) | (sum[i] & ~mask);
	}

	qsc_memutils_secure_erase(sum, sizeof(sum));
	qsc_memutils_secure_erase(reduced, sizeof(reduced));
}

static void ecdsap256_native_sub(ecdsap256_native_fe output, const ecdsap256_native_fe a, const ecdsap256_native_fe b)
{
	/* subtract two canonical native P-256 field elements modulo p */
	uint64_t difference[4U] = { 0U };
	uint64_t borrow;
	uint64_t carry;
	uint64_t mask;
	size_t i;

	borrow = 0U;

	for (i = 0U; i < 4U; ++i)
	{
		difference[i] = ecdsap256_word_sub(a[i], b[i], &borrow);
	}

	mask = UINT64_C(0) - borrow;
	carry = 0U;

	for (i = 0U; i < 4U; ++i)
	{
		output[i] = ecdsap256_word_add(difference[i], (ECDSAP256_NATIVE_PRIME[i] & mask), &carry);
	}
}

static inline void ecdsap256_native_comba_acc_product(uint64_t accumulator[3U], uint64_t low, uint64_t high)
{
#if QSC_ECDSAP256_USE_ASM && defined(ECDSAP256_X64) && !defined(_MSC_VER) && (defined(__GNUC__) || defined(__clang__))
	uint64_t w0;
	uint64_t w1;
	uint64_t w2;

	w0 = accumulator[0U];
	w1 = accumulator[1U];
	w2 = accumulator[2U];
	__asm__("addq %[low], %[w0]\n\t"
			"adcq %[high], %[w1]\n\t"
			"adcq $0, %[w2]"
			: [w0] "+&r"(w0), [w1] "+&r"(w1), [w2] "+&r"(w2)
			: [low] "r"(low), [high] "r"(high)
			: "cc");
	accumulator[0U] = w0;
	accumulator[1U] = w1;
	accumulator[2U] = w2;
#elif defined(ECDSAP256_X64_INTRINSICS)
	unsigned long long w0;
	unsigned long long w1;
	uint64_t w2;
	unsigned char carry;

	carry = _addcarry_u64(0U, accumulator[0U], low, &w0);
	carry = _addcarry_u64(carry, accumulator[1U], high, &w1);
	w2 = accumulator[2U] + (uint64_t)carry;
	accumulator[0U] = (uint64_t)w0;
	accumulator[1U] = (uint64_t)w1;
	accumulator[2U] = w2;
#else
	uint64_t carry;

	carry = 0U;
	accumulator[0U] = ecdsap256_word_add(accumulator[0U], low, &carry);
	accumulator[1U] = ecdsap256_word_add(accumulator[1U], high, &carry);
	accumulator[2U] += carry;
#endif
}

static inline void ecdsap256_native_comba_acc(uint64_t accumulator[3U], uint64_t a, uint64_t b)
{
	uint64_t low;
	uint64_t high;

	low = ecdsap256_word_multiply(a, b, &high);
	ecdsap256_native_comba_acc_product(accumulator, low, high);
}

static inline uint64_t ecdsap256_native_comba_extract(uint64_t accumulator[3U])
{
	uint64_t result;

	result = accumulator[0U];
	accumulator[0U] = accumulator[1U];
	accumulator[1U] = accumulator[2U];
	accumulator[2U] = 0U;

	return result;
}

static inline void ecdsap256_native_comba_double(uint64_t accumulator[3U], uint64_t a, uint64_t b)
{
	uint64_t low;
	uint64_t high;

	low = ecdsap256_word_multiply(a, b, &high);
	ecdsap256_native_comba_acc_product(accumulator, low, high);
	ecdsap256_native_comba_acc_product(accumulator, low, high);
}

static inline void ecdsap256_native_comba_add(uint64_t accumulator[3U], uint64_t word)
{
	ecdsap256_native_comba_acc_product(accumulator, word, 0U);
}

static inline uint64_t ecdsap256_native_order_step(uint64_t accumulator[3U])
{
	uint64_t multiplier;

	multiplier = accumulator[0U] * UINT64_C(0xCCD1C8AAEE00BC4F);
	ecdsap256_native_comba_acc(accumulator, multiplier, UINT64_C(0xF3B9CAC2FC632551));
	(void)ecdsap256_native_comba_extract(accumulator);

	return multiplier;
}

static void ecdsap256_native_comba_mul_base(uint64_t* ECDSAP256_RESTRICT result, const ecdsap256_native_fe a, const ecdsap256_native_fe b)
{
	uint64_t* accumulator;

	accumulator = result + 12U;
	accumulator[0U] = 0U;
	accumulator[1U] = 0U;
	accumulator[2U] = 0U;
	ecdsap256_native_comba_acc(accumulator, a[0U], b[0U]);
	result[0U] = ecdsap256_native_comba_extract(accumulator);
	ecdsap256_native_comba_acc(accumulator, a[0U], b[1U]);
	ecdsap256_native_comba_acc(accumulator, a[1U], b[0U]);
	result[1U] = ecdsap256_native_comba_extract(accumulator);
	ecdsap256_native_comba_acc(accumulator, a[0U], b[2U]);
	ecdsap256_native_comba_acc(accumulator, a[1U], b[1U]);
	ecdsap256_native_comba_acc(accumulator, a[2U], b[0U]);
	result[2U] = ecdsap256_native_comba_extract(accumulator);
	ecdsap256_native_comba_acc(accumulator, a[0U], b[3U]);
	ecdsap256_native_comba_acc(accumulator, a[1U], b[2U]);
	ecdsap256_native_comba_acc(accumulator, a[2U], b[1U]);
	ecdsap256_native_comba_acc(accumulator, a[3U], b[0U]);
	result[3U] = ecdsap256_native_comba_extract(accumulator);
	ecdsap256_native_comba_acc(accumulator, a[1U], b[3U]);
	ecdsap256_native_comba_acc(accumulator, a[2U], b[2U]);
	ecdsap256_native_comba_acc(accumulator, a[3U], b[1U]);
	result[4U] = ecdsap256_native_comba_extract(accumulator);
	ecdsap256_native_comba_acc(accumulator, a[2U], b[3U]);
	ecdsap256_native_comba_acc(accumulator, a[3U], b[2U]);
	result[5U] = ecdsap256_native_comba_extract(accumulator);
	ecdsap256_native_comba_acc(accumulator, a[3U], b[3U]);
	result[6U] = ecdsap256_native_comba_extract(accumulator);
	result[7U] = ecdsap256_native_comba_extract(accumulator);
}

#if defined(ECDSAP256_BMI2_KERNEL)

static ECDSAP256_TARGET_BMI2 void ecdsap256_native_comba_mul_bmi2(uint64_t* ECDSAP256_RESTRICT result, const ecdsap256_native_fe a, const ecdsap256_native_fe b)
{
	uint64_t* accumulator;
	uint64_t low;

	unsigned long long high;

	accumulator = result + 12U;
	accumulator[0U] = 0U;
	accumulator[1U] = 0U;
	accumulator[2U] = 0U;
	low = (uint64_t)_mulx_u64(a[0U], b[0U], &high);
	ecdsap256_native_comba_acc_product(accumulator, low, (uint64_t)high);
	result[0U] = ecdsap256_native_comba_extract(accumulator);
	low = (uint64_t)_mulx_u64(a[0U], b[1U], &high);
	ecdsap256_native_comba_acc_product(accumulator, low, (uint64_t)high);
	low = (uint64_t)_mulx_u64(a[1U], b[0U], &high);
	ecdsap256_native_comba_acc_product(accumulator, low, (uint64_t)high);
	result[1U] = ecdsap256_native_comba_extract(accumulator);
	low = (uint64_t)_mulx_u64(a[0U], b[2U], &high);
	ecdsap256_native_comba_acc_product(accumulator, low, (uint64_t)high);
	low = (uint64_t)_mulx_u64(a[1U], b[1U], &high);
	ecdsap256_native_comba_acc_product(accumulator, low, (uint64_t)high);
	low = (uint64_t)_mulx_u64(a[2U], b[0U], &high);
	ecdsap256_native_comba_acc_product(accumulator, low, (uint64_t)high);
	result[2U] = ecdsap256_native_comba_extract(accumulator);
	low = (uint64_t)_mulx_u64(a[0U], b[3U], &high);
	ecdsap256_native_comba_acc_product(accumulator, low, (uint64_t)high);
	low = (uint64_t)_mulx_u64(a[1U], b[2U], &high);
	ecdsap256_native_comba_acc_product(accumulator, low, (uint64_t)high);
	low = (uint64_t)_mulx_u64(a[2U], b[1U], &high);
	ecdsap256_native_comba_acc_product(accumulator, low, (uint64_t)high);
	low = (uint64_t)_mulx_u64(a[3U], b[0U], &high);
	ecdsap256_native_comba_acc_product(accumulator, low, (uint64_t)high);
	result[3U] = ecdsap256_native_comba_extract(accumulator);
	low = (uint64_t)_mulx_u64(a[1U], b[3U], &high);
	ecdsap256_native_comba_acc_product(accumulator, low, (uint64_t)high);
	low = (uint64_t)_mulx_u64(a[2U], b[2U], &high);
	ecdsap256_native_comba_acc_product(accumulator, low, (uint64_t)high);
	low = (uint64_t)_mulx_u64(a[3U], b[1U], &high);
	ecdsap256_native_comba_acc_product(accumulator, low, (uint64_t)high);
	result[4U] = ecdsap256_native_comba_extract(accumulator);
	low = (uint64_t)_mulx_u64(a[2U], b[3U], &high);
	ecdsap256_native_comba_acc_product(accumulator, low, (uint64_t)high);
	low = (uint64_t)_mulx_u64(a[3U], b[2U], &high);
	ecdsap256_native_comba_acc_product(accumulator, low, (uint64_t)high);
	result[5U] = ecdsap256_native_comba_extract(accumulator);
	low = (uint64_t)_mulx_u64(a[3U], b[3U], &high);
	ecdsap256_native_comba_acc_product(accumulator, low, (uint64_t)high);
	result[6U] = ecdsap256_native_comba_extract(accumulator);
	result[7U] = ecdsap256_native_comba_extract(accumulator);
}
#endif

static void ecdsap256_native_comba_mul(uint64_t result[15U], const ecdsap256_native_fe a, const ecdsap256_native_fe b)
{
#if defined(ECDSAP256_BMI2_KERNEL)
	if ((ecdsap256_optional_features() & 1U) != 0U)
	{
		ecdsap256_native_comba_mul_bmi2(result, a, b);
	}
	else
#endif
	{
		ecdsap256_native_comba_mul_base(result, a, b);
	}
}

static void ecdsap256_native_comba_square_base(uint64_t* ECDSAP256_RESTRICT result, const ecdsap256_native_fe a)
{
	uint64_t* accumulator;

	accumulator = result + 12U;
	accumulator[0U] = 0U;
	accumulator[1U] = 0U;
	accumulator[2U] = 0U;
	ecdsap256_native_comba_acc(accumulator, a[0U], a[0U]);
	result[0U] = ecdsap256_native_comba_extract(accumulator);
	ecdsap256_native_comba_double(accumulator, a[0U], a[1U]);
	result[1U] = ecdsap256_native_comba_extract(accumulator);
	ecdsap256_native_comba_double(accumulator, a[0U], a[2U]);
	ecdsap256_native_comba_acc(accumulator, a[1U], a[1U]);
	result[2U] = ecdsap256_native_comba_extract(accumulator);
	ecdsap256_native_comba_double(accumulator, a[0U], a[3U]);
	ecdsap256_native_comba_double(accumulator, a[1U], a[2U]);
	result[3U] = ecdsap256_native_comba_extract(accumulator);
	ecdsap256_native_comba_double(accumulator, a[1U], a[3U]);
	ecdsap256_native_comba_acc(accumulator, a[2U], a[2U]);
	result[4U] = ecdsap256_native_comba_extract(accumulator);
	ecdsap256_native_comba_double(accumulator, a[2U], a[3U]);
	result[5U] = ecdsap256_native_comba_extract(accumulator);
	ecdsap256_native_comba_acc(accumulator, a[3U], a[3U]);
	result[6U] = ecdsap256_native_comba_extract(accumulator);
	result[7U] = ecdsap256_native_comba_extract(accumulator);
}

#if defined(ECDSAP256_BMI2_KERNEL)

static ECDSAP256_TARGET_BMI2 void ecdsap256_native_comba_square_bmi2(uint64_t* ECDSAP256_RESTRICT result, const ecdsap256_native_fe a)
{
	uint64_t* accumulator;
	uint64_t low;

	unsigned long long high;

	accumulator = result + 12U;
	accumulator[0U] = 0U;
	accumulator[1U] = 0U;
	accumulator[2U] = 0U;
	low = (uint64_t)_mulx_u64(a[0U], a[0U], &high);
	ecdsap256_native_comba_acc_product(accumulator, low, (uint64_t)high);
	result[0U] = ecdsap256_native_comba_extract(accumulator);
	low = (uint64_t)_mulx_u64(a[0U], a[1U], &high);
	ecdsap256_native_comba_acc_product(accumulator, low, (uint64_t)high);
	ecdsap256_native_comba_acc_product(accumulator, low, (uint64_t)high);
	result[1U] = ecdsap256_native_comba_extract(accumulator);
	low = (uint64_t)_mulx_u64(a[0U], a[2U], &high);
	ecdsap256_native_comba_acc_product(accumulator, low, (uint64_t)high);
	ecdsap256_native_comba_acc_product(accumulator, low, (uint64_t)high);
	low = (uint64_t)_mulx_u64(a[1U], a[1U], &high);
	ecdsap256_native_comba_acc_product(accumulator, low, (uint64_t)high);
	result[2U] = ecdsap256_native_comba_extract(accumulator);
	low = (uint64_t)_mulx_u64(a[0U], a[3U], &high);
	ecdsap256_native_comba_acc_product(accumulator, low, (uint64_t)high);
	ecdsap256_native_comba_acc_product(accumulator, low, (uint64_t)high);
	low = (uint64_t)_mulx_u64(a[1U], a[2U], &high);
	ecdsap256_native_comba_acc_product(accumulator, low, (uint64_t)high);
	ecdsap256_native_comba_acc_product(accumulator, low, (uint64_t)high);
	result[3U] = ecdsap256_native_comba_extract(accumulator);
	low = (uint64_t)_mulx_u64(a[1U], a[3U], &high);
	ecdsap256_native_comba_acc_product(accumulator, low, (uint64_t)high);
	ecdsap256_native_comba_acc_product(accumulator, low, (uint64_t)high);
	low = (uint64_t)_mulx_u64(a[2U], a[2U], &high);
	ecdsap256_native_comba_acc_product(accumulator, low, (uint64_t)high);
	result[4U] = ecdsap256_native_comba_extract(accumulator);
	low = (uint64_t)_mulx_u64(a[2U], a[3U], &high);
	ecdsap256_native_comba_acc_product(accumulator, low, (uint64_t)high);
	ecdsap256_native_comba_acc_product(accumulator, low, (uint64_t)high);
	result[5U] = ecdsap256_native_comba_extract(accumulator);
	low = (uint64_t)_mulx_u64(a[3U], a[3U], &high);
	ecdsap256_native_comba_acc_product(accumulator, low, (uint64_t)high);
	result[6U] = ecdsap256_native_comba_extract(accumulator);
	result[7U] = ecdsap256_native_comba_extract(accumulator);
}
#endif

static void ecdsap256_native_comba_square(uint64_t result[15U], const ecdsap256_native_fe a)
{
#if defined(ECDSAP256_BMI2_KERNEL)
	if ((ecdsap256_optional_features() & 1U) != 0U)
	{
		ecdsap256_native_comba_square_bmi2(result, a);
	}
	else
#endif
	{
		ecdsap256_native_comba_square_base(result, a);
	}
}

static void ecdsap256_native_reduce(ecdsap256_native_fe output, uint64_t scratch[15U])
{
	/* reduce eight product words using specialized P-256 Montgomery formula */
	uint64_t* words;
	uint64_t* reduced;
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

		words[i + 1U] = ecdsap256_word_add(words[i + 1U], q0, &carry);
		words[i + 2U] = ecdsap256_word_add(words[i + 2U], q1, &carry);
		words[i + 3U] = ecdsap256_word_add(words[i + 3U], q2, &carry);
		words[i + 4U] = ecdsap256_word_add(words[i + 4U], q3, &carry);
		pending = carry;
	}

	borrow = 0U;

	for (i = 0U; i < 4U; ++i)
	{
		reduced[i] = ecdsap256_word_sub(words[i + 4U], ECDSAP256_NATIVE_PRIME[i], &borrow);
	}

	mask = UINT64_C(0) - (borrow & (pending ^ 1U));

	for (i = 0U; i < 4U; ++i)
	{
		selected = (words[i + 4U] & mask) | (reduced[i] & ~mask);
		output[i] = selected;
	}
}

static void ecdsap256_native_mul(ecdsap256_native_fe output, const ecdsap256_native_fe a, const ecdsap256_native_fe b, uint64_t scratch[15U])
{
	/* multiply two Montgomery-native P-256 field elements */
	ecdsap256_native_comba_mul(scratch, a, b);
	ecdsap256_native_reduce(output, scratch);
}

static void ecdsap256_native_square(ecdsap256_native_fe output, const ecdsap256_native_fe a, uint64_t scratch[15U])
{
	/* square one native P-256 Montgomery element */
	ecdsap256_native_comba_square(scratch, a);
	ecdsap256_native_reduce(output, scratch);
}

static void ecdsap256_native_square_n(ecdsap256_native_fe value, size_t rounds, uint64_t scratch[15U])
{
	/* apply a fixed number of native field squarings */
	size_t i;

	for (i = 0U; i < rounds; ++i)
	{
		ecdsap256_native_square(value, value, scratch);
	}
}

static void ecdsap256_native_inverse_square(ecdsap256_native_fe output, const ecdsap256_native_fe z, uint64_t scratch[15U])
{
	/* compute Z^-2 fixed P-256 p-3 addition chain */
	ecdsap256_native_fe t[2U] = {{ 0U }};
	ecdsap256_native_fe r = { 0U };

	ecdsap256_native_square(r, z, scratch);
	ecdsap256_native_mul(r, r, z, scratch);
	ecdsap256_native_square(r, r, scratch);
	ecdsap256_native_mul(r, r, z, scratch);
	ecdsap256_native_copy(t[0U], r);
	ecdsap256_native_square_n(t[0U], 3U, scratch);
	ecdsap256_native_mul(t[0U], t[0U], r, scratch);
	ecdsap256_native_copy(t[1U], t[0U]);
	ecdsap256_native_square_n(t[1U], 6U, scratch);
	ecdsap256_native_mul(t[0U], t[0U], t[1U], scratch);
	ecdsap256_native_square_n(t[0U], 3U, scratch);
	ecdsap256_native_mul(r, r, t[0U], scratch);
	ecdsap256_native_square(t[0U], r, scratch);
	ecdsap256_native_mul(t[0U], t[0U], z, scratch);
	ecdsap256_native_copy(t[1U], t[0U]);
	ecdsap256_native_square_n(t[1U], 16U, scratch);
	ecdsap256_native_mul(t[0U], t[0U], t[1U], scratch);
	ecdsap256_native_square_n(t[0U], 15U, scratch);
	ecdsap256_native_mul(r, r, t[0U], scratch);
	ecdsap256_native_square_n(t[0U], 17U, scratch);
	ecdsap256_native_mul(t[0U], t[0U], z, scratch);
	ecdsap256_native_square_n(t[0U], 143U, scratch);
	ecdsap256_native_mul(t[0U], t[0U], r, scratch);
	ecdsap256_native_square_n(t[0U], 47U, scratch);
	ecdsap256_native_mul(r, r, t[0U], scratch);
	ecdsap256_native_square_n(r, 2U, scratch);
	ecdsap256_native_copy(output, r);

	qsc_memutils_secure_erase(t, sizeof(t));
	qsc_memutils_secure_erase(r, sizeof(r));
}

static void ecdsap256_native_point_choose(ecdsap256_native_point* output, const ecdsap256_native_point* a, const ecdsap256_native_point* b, uint64_t select)
{
	/* select one native projective point in constant time */
	ecdsap256_native_choose(output->x, a->x, b->x, select);
	ecdsap256_native_choose(output->y, a->y, b->y, select);
	ecdsap256_native_choose(output->z, a->z, b->z, select);
}

static void ecdsap256_native_double_generator(ecdsap256_native_point* output, const ecdsap256_native_point* input, uint64_t scratch[15U])
{
	ecdsap256_native_fe delta;
	ecdsap256_native_fe gamma;
	ecdsap256_native_fe beta;
	ecdsap256_native_fe alpha;
	ecdsap256_native_fe temp;
	ecdsap256_native_fe tx;
	ecdsap256_native_fe ty;
	ecdsap256_native_fe tz;

	ecdsap256_native_square(delta, input->z, scratch);
	ecdsap256_native_square(gamma, input->y, scratch);
	ecdsap256_native_mul(beta, input->x, gamma, scratch);
	ecdsap256_native_sub(alpha, input->x, delta);
	ecdsap256_native_add(temp, input->x, delta);
	ecdsap256_native_mul(alpha, alpha, temp, scratch);
	ecdsap256_native_add(temp, alpha, alpha);
	ecdsap256_native_add(alpha, temp, alpha);

	ecdsap256_native_square(tx, alpha, scratch);
	ecdsap256_native_add(temp, beta, beta);
	ecdsap256_native_add(temp, temp, temp);
	ecdsap256_native_add(temp, temp, temp);
	ecdsap256_native_sub(tx, tx, temp);

	ecdsap256_native_add(tz, input->y, input->z);
	ecdsap256_native_square(tz, tz, scratch);
	ecdsap256_native_sub(tz, tz, gamma);
	ecdsap256_native_sub(tz, tz, delta);

	ecdsap256_native_add(temp, beta, beta);
	ecdsap256_native_add(temp, temp, temp);
	ecdsap256_native_sub(temp, temp, tx);
	ecdsap256_native_mul(ty, alpha, temp, scratch);
	ecdsap256_native_square(temp, gamma, scratch);
	ecdsap256_native_add(temp, temp, temp);
	ecdsap256_native_add(temp, temp, temp);
	ecdsap256_native_add(temp, temp, temp);
	ecdsap256_native_sub(ty, ty, temp);

	ecdsap256_native_copy(output->x, tx);
	ecdsap256_native_copy(output->y, ty);
	ecdsap256_native_copy(output->z, tz);

	qsc_memutils_secure_erase(delta, sizeof(delta));
	qsc_memutils_secure_erase(gamma, sizeof(gamma));
	qsc_memutils_secure_erase(beta, sizeof(beta));
	qsc_memutils_secure_erase(alpha, sizeof(alpha));
	qsc_memutils_secure_erase(temp, sizeof(temp));
	qsc_memutils_secure_erase(tx, sizeof(tx));
	qsc_memutils_secure_erase(ty, sizeof(ty));
	qsc_memutils_secure_erase(tz, sizeof(tz));
}

/*! \brief Reusable native-width Jacobian mixed-add workspace.
 * \note Owned by one scalar multiplication and securely erased at its completion.
 */
typedef struct
{
	/*! \brief Projective Z square. */
	ecdsap256_native_fe zz;
	/*! \brief Second X scaled by first Z square. */
	ecdsap256_native_fe u;
	/*! \brief Second Y scaled by first Z cube. */
	ecdsap256_native_fe s;
	/*! \brief Jacobian X coordinate difference. */
	ecdsap256_native_fe h;
	/*! \brief Jacobian Y coordinate difference. */
	ecdsap256_native_fe delta;
	/*! \brief Square of X difference. */
	ecdsap256_native_fe hh;
	/*! \brief Cube of X difference. */
	ecdsap256_native_fe hhh;
	/*! \brief First X times squared X difference. */
	ecdsap256_native_fe v;
	/*! \brief Temporary intermediate field value. */
	ecdsap256_native_fe tmp;
	/*! \brief Candidate sum point before constant-time infinity selection. */
	ecdsap256_native_point added;
} ecdsap256_native_window_workspace;

static void ecdsap256_native_add_generator(ecdsap256_native_point* output, const ecdsap256_native_point* first, const ecdsap256_native_point* second, ecdsap256_native_window_workspace* work, uint64_t scratch[15U], bool check_exception)
{
	ecdsap256_native_point doubled;
	uint64_t eqpt;
	uint64_t finf;
	uint64_t sinf;

	ecdsap256_native_square(work->zz, first->z, scratch);
	ecdsap256_native_mul(work->u, second->x, work->zz, scratch);
	ecdsap256_native_mul(work->s, second->y, first->z, scratch);
	ecdsap256_native_mul(work->s, work->s, work->zz, scratch);
	ecdsap256_native_sub(work->h, work->u, first->x);
	ecdsap256_native_sub(work->delta, work->s, first->y);
	ecdsap256_native_square(work->hh, work->h, scratch);
	ecdsap256_native_mul(work->hhh, work->h, work->hh, scratch);
	ecdsap256_native_mul(work->v, first->x, work->hh, scratch);
	ecdsap256_native_square(work->added.x, work->delta, scratch);
	ecdsap256_native_sub(work->added.x, work->added.x, work->hhh);
	ecdsap256_native_add(work->tmp, work->v, work->v);
	ecdsap256_native_sub(work->added.x, work->added.x, work->tmp);
	ecdsap256_native_sub(work->tmp, work->v, work->added.x);
	ecdsap256_native_mul(work->added.y, work->delta, work->tmp, scratch);
	ecdsap256_native_mul(work->tmp, first->y, work->hhh, scratch);
	ecdsap256_native_sub(work->added.y, work->added.y, work->tmp);
	ecdsap256_native_mul(work->added.z, first->z, work->h, scratch);

	finf = ecdsap256_native_is_zero(first->z);
	sinf = ecdsap256_native_is_zero(second->z);
	/* Select the exceptional equal-point result without secret-dependent control flow. */
	if (check_exception)
	{
		eqpt = (finf ^ 1U) & (sinf ^ 1U) & ecdsap256_native_is_zero(work->h) & ecdsap256_native_is_zero(work->delta);
		ecdsap256_native_double_generator(&doubled, first, scratch);
		ecdsap256_native_point_choose(&work->added, &doubled, &work->added, eqpt);
		qsc_memutils_secure_erase(&doubled, sizeof(doubled));
	}

	ecdsap256_native_point_choose(&work->added, first, &work->added, sinf);
	ecdsap256_native_point_choose(&work->added, second, &work->added, finf);
	*output = work->added;
}

static inline void ecdsap256_select_scalar(uint64_t x[4U], uint64_t y[4U], const uint32_t row[32U][2U][8U], uint32_t magnitude)
{
	uint32_t difference;
	uint32_t equal;
	uint64_t mask;
	size_t i;
	size_t j;

	for (i = 0U; i < 4U; ++i)
	{
		x[i] = 0U;
		y[i] = 0U;
	}

	for (j = 0U; j < 32U; ++j)
	{
		difference = (uint32_t)(j + 1U) ^ magnitude;
		equal = 1U ^ ((difference | (0U - difference)) >> 31U);
		mask = UINT64_C(0) - (uint64_t)equal;

		for (i = 0U; i < 4U; ++i)
		{
			x[i] |= ((uint64_t)row[j][0U][2U * i] | ((uint64_t)row[j][0U][2U * i + 1U] << 32U)) & mask;
			y[i] |= ((uint64_t)row[j][1U][2U * i] | ((uint64_t)row[j][1U][2U * i + 1U] << 32U)) & mask;
		}
	}
}

#if defined(ECDSAP256_X64) && QSC_ECDSAP256_USE_SIMD

static void ecdsap256_select_sse2(uint64_t x[4U], uint64_t y[4U], const uint32_t row[32U][2U][8U], uint32_t magnitude)
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
		x1 = _mm_or_si128(x1, _mm_and_si128(mask, _mm_loadu_si128((const __m128i*)(const void*)&row[j][0U][4U])));
		y0 = _mm_or_si128(y0, _mm_and_si128(mask, _mm_loadu_si128((const __m128i*)(const void*)&row[j][1U][0U])));
		y1 = _mm_or_si128(y1, _mm_and_si128(mask, _mm_loadu_si128((const __m128i*)(const void*)&row[j][1U][4U])));
	}

	_mm_storeu_si128((__m128i*)(void*)&x[0U], x0);
	_mm_storeu_si128((__m128i*)(void*)&x[2U], x1);
	_mm_storeu_si128((__m128i*)(void*)&y[0U], y0);
	_mm_storeu_si128((__m128i*)(void*)&y[2U], y1);
}
#endif

#if defined(ECDSAP256_AVX2_KERNEL)

static ECDSAP256_TARGET_AVX2 void ecdsap256_select_avx2(uint64_t x[4U], uint64_t y[4U], const uint32_t row[32U][2U][8U], uint32_t magnitude)
{
	__m256i vx;
	__m256i vy;
	__m256i digit;
	__m256i mask;
	size_t j;

	vx = _mm256_setzero_si256();
	vy = _mm256_setzero_si256();
	digit = _mm256_set1_epi32((int32_t)magnitude);

	for (j = 0U; j < 32U; ++j)
	{
		mask = _mm256_cmpeq_epi32(digit, _mm256_set1_epi32((int32_t)(j + 1U)));
		vx = _mm256_or_si256(vx, _mm256_and_si256(mask, _mm256_loadu_si256((const __m256i*)(const void*)&row[j][0U][0U])));
		vy = _mm256_or_si256(vy, _mm256_and_si256(mask, _mm256_loadu_si256((const __m256i*)(const void*)&row[j][1U][0U])));
	}

	_mm256_storeu_si256((__m256i*)(void*)x, vx);
	_mm256_storeu_si256((__m256i*)(void*)y, vy);
	_mm256_zeroupper();
}
#endif

static void ecdsap256_native_generator(ecdsap256_jac_t* output, const uint32_t scalar[10U], const ecdsap256_field factors[4U])
{
	uint64_t scratch[15U] = { 0U };
	ecdsap256_native_window_workspace work;
	ecdsap256_native_point accumulator;
	ecdsap256_native_point selected;
	ecdsap256_native_point added;
	ecdsap256_native_fe negative_y;
	ecdsap256_native_fe zero = { 0U };
	ecdsap256_native_fe factor;
	ecdsap256_native_fe square;
	ecdsap256_native_fe cube;
	uint32_t magnitude;
	uint32_t sign;
	uint64_t mask;
#if defined(ECDSAP256_AVX2_KERNEL)
	bool avx2;
#endif
	size_t i;
	size_t w;

	qsc_memutils_clear(&work, sizeof(work));
#if defined(ECDSAP256_AVX2_KERNEL)
	avx2 = (ecdsap256_optional_features() & 2U) != 0U;
#endif
	/* A previous Booth prefix has absolute value at most
	 * 32 * (64^i - 1) / 63. For i <= 41, adding or subtracting a
	 * nonzero digit of magnitude at least 64^i gives a nonzero integer
	 * with absolute value below the P-256 subgroup order. Thus the
	 * equal-point exception is impossible in windows 1..41, even after
	 * reducing a blinded scalar modulo the subgroup order. Windows
	 * 42..48 retain unconditional, masked exceptional-case doubling.
	 * The window index is public and the predicate cannot leak a scalar.
	 */
	for (i = 0U; i < 49U; ++i)
	{
		magnitude = ecdsap256_booth_digit(scalar, i, &sign);
		mask = (uint64_t)0U - (uint64_t)((magnitude | (0U - magnitude)) >> 31U);

		for (w = 0U; w < 4U; ++w)
		{
			selected.z[w] = ECDSAP256_NATIVE_ONE[w] & mask;
		}

#if defined(ECDSAP256_AVX2_KERNEL)
		if (avx2)
		{
			ecdsap256_select_avx2(selected.x, selected.y, ECDSAP256_GENERATOR_TABLE[i], magnitude);
		}
		else
#endif
		{
#if defined(ECDSAP256_X64) && QSC_ECDSAP256_USE_SIMD
			ecdsap256_select_sse2(selected.x, selected.y, ECDSAP256_GENERATOR_TABLE[i], magnitude);
#else
			ecdsap256_select_scalar(selected.x, selected.y, ECDSAP256_GENERATOR_TABLE[i], magnitude);
#endif
		}

		ecdsap256_native_sub(negative_y, zero, selected.y);
		ecdsap256_native_choose(selected.y, negative_y, selected.y, sign);

		if (i == 0U)
		{
			accumulator = selected;
		}
		else
		{
			ecdsap256_native_add_generator(&added, &accumulator, &selected, &work, scratch, i >= 42U);
			accumulator = added;
		}

		if (i < 4U)
		{
			ecdsap256_native_load(factor, factors[i]);
			ecdsap256_native_square(square, factor, scratch);
			ecdsap256_native_mul(cube, square, factor, scratch);
			ecdsap256_native_mul(accumulator.x, accumulator.x, square, scratch);
			ecdsap256_native_mul(accumulator.y, accumulator.y, cube, scratch);
			ecdsap256_native_mul(accumulator.z, accumulator.z, factor, scratch);
		}
	}

	ecdsap256_native_store(output->X, accumulator.x);
	ecdsap256_native_store(output->Y, accumulator.y);
	ecdsap256_native_store(output->Z, accumulator.z);
	qsc_memutils_secure_erase(&accumulator, sizeof(accumulator));
	qsc_memutils_secure_erase(&selected, sizeof(selected));
	qsc_memutils_secure_erase(&added, sizeof(added));
	qsc_memutils_secure_erase(&work, sizeof(work));
	qsc_memutils_secure_erase(negative_y, sizeof(negative_y));
	qsc_memutils_secure_erase(factor, sizeof(factor));
	qsc_memutils_secure_erase(square, sizeof(square));
	qsc_memutils_secure_erase(cube, sizeof(cube));
	qsc_memutils_secure_erase(scratch, sizeof(scratch));
}

static void ecdsap256_native_affine_x(ecdsap256_field output, const ecdsap256_jac_t* point)
{
	/* compute affine X for one non-infinity P-256 native Montgomery point */
	uint64_t scratch[15U] = { 0U };
	ecdsap256_native_fe x = { 0U };
	ecdsap256_native_fe z = { 0U };
	ecdsap256_native_fe inverse2 = { 0U };
	ecdsap256_native_fe product = { 0U };

	ecdsap256_native_load(x, point->X);
	ecdsap256_native_load(z, point->Z);
	ecdsap256_native_inverse_square(inverse2, z, scratch);
	ecdsap256_native_mul(product, x, inverse2, scratch);
	ecdsap256_native_mul(product, product, (const uint64_t[4U]){1U, 0U, 0U, 0U}, scratch);
	ecdsap256_native_store(output, product);
	qsc_memutils_secure_erase(x, sizeof(x));
	qsc_memutils_secure_erase(z, sizeof(z));
	qsc_memutils_secure_erase(inverse2, sizeof(inverse2));
	qsc_memutils_secure_erase(product, sizeof(product));
	qsc_memutils_secure_erase(scratch, sizeof(scratch));
}

static const uint64_t ECDSAP256_NATIVE_ORDER[4U] = {
	/* P-256 subgroup modulus, little-endian four-word representation */
	UINT64_C(0xF3B9CAC2FC632551), UINT64_C(0xBCE6FAADA7179E84), UINT64_C(0xFFFFFFFFFFFFFFFF), UINT64_C(0xFFFFFFFF00000000)};

static const uint64_t ECDSAP256_NATIVE_ORDER_R2[4U] = {
	/* R-squared modulo the P-256 subgroup order for native Montgomery encoding */
	UINT64_C(0x83244C95BE79EEA2), UINT64_C(0x4699799C49BD6FA6), UINT64_C(0x2845B2392B6BEC59), UINT64_C(0x66E12D94F3D95620)};

static void ecdsap256_native_order_reduce(ecdsap256_native_fe output, uint64_t scratch[15U])
{
	uint64_t* accumulator;
	uint64_t* ws;
	uint64_t reduced[4U];
	uint64_t carry;
	uint64_t borrow;
	uint64_t mask;
	size_t i;

	ws = scratch + 8U;
	accumulator = scratch + 12U;
	accumulator[0U] = 0U;
	accumulator[1U] = 0U;
	accumulator[2U] = 0U;
	ecdsap256_native_comba_add(accumulator, scratch[0U]);
	ws[0U] = ecdsap256_native_order_step(accumulator);
	ecdsap256_native_comba_acc(accumulator, ws[0U], ECDSAP256_NATIVE_ORDER[1U]);
	ecdsap256_native_comba_add(accumulator, scratch[1U]);
	ws[1U] = ecdsap256_native_order_step(accumulator);
	ecdsap256_native_comba_acc(accumulator, ws[0U], ECDSAP256_NATIVE_ORDER[2U]);
	ecdsap256_native_comba_acc(accumulator, ws[1U], ECDSAP256_NATIVE_ORDER[1U]);
	ecdsap256_native_comba_add(accumulator, scratch[2U]);
	ws[2U] = ecdsap256_native_order_step(accumulator);
	ecdsap256_native_comba_acc(accumulator, ws[0U], ECDSAP256_NATIVE_ORDER[3U]);
	ecdsap256_native_comba_acc(accumulator, ws[1U], ECDSAP256_NATIVE_ORDER[2U]);
	ecdsap256_native_comba_acc(accumulator, ws[2U], ECDSAP256_NATIVE_ORDER[1U]);
	ecdsap256_native_comba_add(accumulator, scratch[3U]);
	ws[3U] = ecdsap256_native_order_step(accumulator);
	ecdsap256_native_comba_acc(accumulator, ws[1U], ECDSAP256_NATIVE_ORDER[3U]);
	ecdsap256_native_comba_acc(accumulator, ws[2U], ECDSAP256_NATIVE_ORDER[2U]);
	ecdsap256_native_comba_acc(accumulator, ws[3U], ECDSAP256_NATIVE_ORDER[1U]);
	ecdsap256_native_comba_add(accumulator, scratch[4U]);
	ws[0U] = ecdsap256_native_comba_extract(accumulator);
	ecdsap256_native_comba_acc(accumulator, ws[2U], ECDSAP256_NATIVE_ORDER[3U]);
	ecdsap256_native_comba_acc(accumulator, ws[3U], ECDSAP256_NATIVE_ORDER[2U]);
	ecdsap256_native_comba_add(accumulator, scratch[5U]);
	ws[1U] = ecdsap256_native_comba_extract(accumulator);
	ecdsap256_native_comba_acc(accumulator, ws[3U], ECDSAP256_NATIVE_ORDER[3U]);
	ecdsap256_native_comba_add(accumulator, scratch[6U]);
	ws[2U] = ecdsap256_native_comba_extract(accumulator);
	ecdsap256_native_comba_add(accumulator, scratch[7U]);
	ws[3U] = ecdsap256_native_comba_extract(accumulator);
	carry = ecdsap256_native_comba_extract(accumulator);
	borrow = 0U;

	for (i = 0U; i < 4U; ++i)
	{
		reduced[i] = ecdsap256_word_sub(ws[i], ECDSAP256_NATIVE_ORDER[i], &borrow);
	}

	mask = UINT64_C(0) - (borrow & (carry ^ 1U));

	for (i = 0U; i < 4U; ++i)
	{
		output[i] = reduced[i] ^ (mask & (ws[i] ^ reduced[i]));
	}

	qsc_memutils_secure_erase(reduced, sizeof(reduced));
}

static void ecdsap256_native_order_mul(ecdsap256_native_fe output, const ecdsap256_native_fe a, const ecdsap256_native_fe b, uint64_t scratch[15U])
{
	ecdsap256_native_comba_mul(scratch, a, b);
	ecdsap256_native_order_reduce(output, scratch);
}

static void ecdsap256_native_scalar_product(uint32_t output[8U], const uint32_t a[8U], const uint32_t b[8U])
{
	ecdsap256_native_fe left;
	ecdsap256_native_fe right;
	ecdsap256_native_fe result;
	uint64_t scratch[15U];

	ecdsap256_native_load(left, a);
	ecdsap256_native_load(right, b);
	ecdsap256_native_order_mul(result, left, ECDSAP256_NATIVE_ORDER_R2, scratch);
	ecdsap256_native_order_mul(result, result, right, scratch);
	ecdsap256_native_store(output, result);
	qsc_memutils_secure_erase(left, sizeof(left));
	qsc_memutils_secure_erase(right, sizeof(right));
	qsc_memutils_secure_erase(result, sizeof(result));
	qsc_memutils_secure_erase(scratch, sizeof(scratch));
}

static void ecdsap256_native_order_add(ecdsap256_native_fe output, const ecdsap256_native_fe a, const ecdsap256_native_fe b)
{
	/* add canonical native Montgomery scalars modulo the subgroup order */
	uint64_t sum[4U] = { 0U };
	uint64_t reduced[4U] = { 0U };
	uint64_t carry;
	uint64_t borrow;
	uint64_t mask;
	size_t i;

	carry = 0U;

	for (i = 0U; i < 4U; ++i)
	{
		sum[i] = ecdsap256_word_add(a[i], b[i], &carry);
	}

	borrow = 0U;

	for (i = 0U; i < 4U; ++i)
	{
		reduced[i] = ecdsap256_word_sub(sum[i], ECDSAP256_NATIVE_ORDER[i], &borrow);
	}

	mask = UINT64_C(0) - (carry | (borrow ^ 1U));

	for (i = 0U; i < 4U; ++i)
	{
		output[i] = (reduced[i] & mask) | (sum[i] & ~mask);
	}

	qsc_memutils_secure_erase(sum, sizeof(sum));
	qsc_memutils_secure_erase(reduced, sizeof(reduced));
}

static void ecdsap256_native_order_square_n(ecdsap256_native_fe value, size_t rounds, uint64_t scratch[15U])
{
	/* square one order residue for a fixed number of Montgomery rounds */
	size_t i;

	for (i = 0U; i < rounds; ++i)
	{
		ecdsap256_native_comba_square(scratch, value);
		ecdsap256_native_order_reduce(value, scratch);
	}
}

static void ecdsap256_native_order_inverse(ecdsap256_native_fe output, const ecdsap256_native_fe a, uint64_t scratch[15U])
{
	/* P-256 order inversion addition chain in persistent native representation */
	ecdsap256_native_fe t[15U] = {{ 0U }};
	ecdsap256_native_fe z = { 0U };

	ecdsap256_native_order_mul(t[1U], a, a, scratch);
	ecdsap256_native_order_mul(t[5U], t[1U], t[1U], scratch);
	ecdsap256_native_order_mul(t[2U], t[5U], a, scratch);
	ecdsap256_native_order_mul(t[10U], t[2U], a, scratch);
	ecdsap256_native_order_mul(t[3U], t[2U], t[5U], scratch);
	ecdsap256_native_order_mul(z, t[10U], t[3U], scratch);
	ecdsap256_native_order_mul(t[9U], t[3U], t[3U], scratch);
	ecdsap256_native_order_mul(t[4U], t[10U], z, scratch);
	ecdsap256_native_order_mul(t[0U], t[10U], t[9U], scratch);
	ecdsap256_native_order_mul(t[13U], t[0U], t[1U], scratch);
	ecdsap256_native_order_mul(t[8U], t[13U], t[4U], scratch);
	ecdsap256_native_order_mul(t[4U], t[3U], t[8U], scratch);
	ecdsap256_native_order_mul(t[7U], t[2U], t[4U], scratch);
	ecdsap256_native_order_mul(t[2U], t[1U], t[7U], scratch);
	ecdsap256_native_order_mul(t[6U], t[7U], t[9U], scratch);
	ecdsap256_native_order_mul(t[3U], t[6U], t[9U], scratch);
	ecdsap256_native_order_mul(t[1U], t[1U], t[3U], scratch);
	ecdsap256_native_order_mul(t[12U], t[3U], t[9U], scratch);
	ecdsap256_native_order_mul(t[5U], t[5U], t[12U], scratch);
	ecdsap256_native_order_mul(t[11U], t[10U], t[5U], scratch);
	ecdsap256_native_order_mul(t[0U], t[0U], t[11U], scratch);
	ecdsap256_native_order_mul(t[9U], t[9U], t[0U], scratch);
	ecdsap256_native_order_mul(t[10U], t[10U], t[9U], scratch);
	ecdsap256_native_order_mul(t[4U], t[4U], t[10U], scratch);
	ecdsap256_native_order_mul(t[13U], t[13U], t[4U], scratch);
	ecdsap256_native_copy(t[14U], t[13U]);
	ecdsap256_native_order_square_n(t[14U], 8U, scratch);
	ecdsap256_native_order_mul(t[13U], t[13U], t[14U], scratch);
	ecdsap256_native_copy(t[14U], t[13U]);
	ecdsap256_native_order_square_n(t[14U], 16U, scratch);
	ecdsap256_native_order_mul(t[14U], t[14U], t[13U], scratch);
	ecdsap256_native_order_square_n(t[14U], 48U, scratch);
	ecdsap256_native_order_mul(t[14U], t[14U], t[13U], scratch);
	ecdsap256_native_order_square_n(t[14U], 16U, scratch);
	ecdsap256_native_order_mul(t[14U], t[14U], t[13U], scratch);
	ecdsap256_native_order_square_n(t[14U], 16U, scratch);
	ecdsap256_native_order_mul(t[14U], t[14U], t[13U], scratch);
	ecdsap256_native_order_square_n(t[14U], 16U, scratch);
	ecdsap256_native_order_mul(t[13U], t[13U], t[14U], scratch);
	ecdsap256_native_order_square_n(t[13U], 6U, scratch);
	ecdsap256_native_order_mul(t[13U], t[13U], t[8U], scratch);
	ecdsap256_native_order_square_n(t[13U], 9U, scratch);
	ecdsap256_native_order_mul(t[12U], t[12U], t[13U], scratch);
	ecdsap256_native_order_square_n(t[12U], 8U, scratch);
	ecdsap256_native_order_mul(t[11U], t[11U], t[12U], scratch);
	ecdsap256_native_order_square_n(t[11U], 9U, scratch);
	ecdsap256_native_order_mul(t[10U], t[10U], t[11U], scratch);
	ecdsap256_native_order_square_n(t[10U], 8U, scratch);
	ecdsap256_native_order_mul(t[9U], t[9U], t[10U], scratch);
	ecdsap256_native_order_square_n(t[9U], 9U, scratch);
	ecdsap256_native_order_mul(t[8U], t[8U], t[9U], scratch);
	ecdsap256_native_order_square_n(t[8U], 8U, scratch);
	ecdsap256_native_order_mul(t[7U], t[7U], t[8U], scratch);
	ecdsap256_native_order_square_n(t[7U], 11U, scratch);
	ecdsap256_native_order_mul(t[6U], t[6U], t[7U], scratch);
	ecdsap256_native_order_square_n(t[6U], 9U, scratch);
	ecdsap256_native_order_mul(t[5U], t[5U], t[6U], scratch);
	ecdsap256_native_order_square_n(t[5U], 10U, scratch);
	ecdsap256_native_order_mul(t[4U], t[4U], t[5U], scratch);
	ecdsap256_native_order_square_n(t[4U], 8U, scratch);
	ecdsap256_native_order_mul(t[3U], t[3U], t[4U], scratch);
	ecdsap256_native_order_square_n(t[3U], 7U, scratch);
	ecdsap256_native_order_mul(t[2U], t[2U], t[3U], scratch);
	ecdsap256_native_order_square_n(t[2U], 10U, scratch);
	ecdsap256_native_order_mul(t[1U], t[1U], t[2U], scratch);
	ecdsap256_native_order_square_n(t[1U], 10U, scratch);
	ecdsap256_native_order_mul(t[0U], t[0U], t[1U], scratch);
	ecdsap256_native_order_square_n(t[0U], 6U, scratch);
	ecdsap256_native_order_mul(z, z, t[0U], scratch);
	ecdsap256_native_copy(output, z);

	qsc_memutils_secure_erase(t, sizeof(t));
	qsc_memutils_secure_erase(z, sizeof(z));
}

static bool ecdsap256_native_sign_scalar(uint32_t output[8U], const uint32_t nonce[8U], const uint32_t private_scalar[8U], const uint32_t signature_r[8U], const uint32_t message_scalar[8U])
{
	/* calculate QSC's independently blinded P-256 signature scalar natively */
	uint64_t scratch[15U] = { 0U };
	uint8_t rmsk[32U] = { 0U };
	uint32_t mask[8U] = { 0U };
	ecdsap256_native_fe masking = { 0U };
	ecdsap256_native_fe nonce_mont = { 0U };
	ecdsap256_native_fe private_mont = { 0U };
	ecdsap256_native_fe hash_mont = { 0U };
	ecdsap256_native_fe r_mont = { 0U };
	ecdsap256_native_fe inverse = { 0U };
	ecdsap256_native_fe sum = { 0U };
	ecdsap256_native_fe result = { 0U };
	ecdsap256_native_fe canonical = { 0U };
	ecdsap256_native_fe one = {1U, 0U, 0U, 0U};
	bool ok;

	ok = qsc_csp_generate(rmsk, sizeof(rmsk));

	if (ok)
	{
		ecdsap256_sc_from_bytes_reduce(mask, rmsk);
		mask[0U] |= ecdsap256_field_is_zero(mask);
		ecdsap256_native_load(canonical, mask);
		ecdsap256_native_order_mul(masking, canonical, ECDSAP256_NATIVE_ORDER_R2, scratch);
		ecdsap256_native_load(canonical, nonce);
		ecdsap256_native_order_mul(nonce_mont, canonical, ECDSAP256_NATIVE_ORDER_R2, scratch);
		ecdsap256_native_load(canonical, private_scalar);
		ecdsap256_native_order_mul(private_mont, canonical, ECDSAP256_NATIVE_ORDER_R2, scratch);
		ecdsap256_native_load(canonical, message_scalar);
		ecdsap256_native_order_mul(hash_mont, canonical, ECDSAP256_NATIVE_ORDER_R2, scratch);
		ecdsap256_native_load(canonical, signature_r);
		ecdsap256_native_order_mul(r_mont, canonical, ECDSAP256_NATIVE_ORDER_R2, scratch);

		ecdsap256_native_order_mul(nonce_mont, nonce_mont, masking, scratch);
		ecdsap256_native_order_inverse(inverse, nonce_mont, scratch);
		ecdsap256_native_order_mul(private_mont, private_mont, masking, scratch);
		ecdsap256_native_order_mul(private_mont, private_mont, r_mont, scratch);
		ecdsap256_native_order_mul(hash_mont, hash_mont, masking, scratch);
		ecdsap256_native_order_add(sum, private_mont, hash_mont);
		ecdsap256_native_order_mul(result, inverse, sum, scratch);
		ecdsap256_native_order_mul(result, result, one, scratch);
		ecdsap256_native_store(output, result);
	}

	qsc_memutils_secure_erase(rmsk, sizeof(rmsk));
	qsc_memutils_secure_erase(mask, sizeof(mask));
	qsc_memutils_secure_erase(masking, sizeof(masking));
	qsc_memutils_secure_erase(nonce_mont, sizeof(nonce_mont));
	qsc_memutils_secure_erase(private_mont, sizeof(private_mont));
	qsc_memutils_secure_erase(hash_mont, sizeof(hash_mont));
	qsc_memutils_secure_erase(r_mont, sizeof(r_mont));
	qsc_memutils_secure_erase(inverse, sizeof(inverse));
	qsc_memutils_secure_erase(sum, sizeof(sum));
	qsc_memutils_secure_erase(result, sizeof(result));
	qsc_memutils_secure_erase(canonical, sizeof(canonical));
	qsc_memutils_secure_erase(scratch, sizeof(scratch));

	return ok;
}

#endif /* native-width signing point backend */

/*! \brief Bound exceptional cases in signed radix-64 fixed-base multiplication.
 * \details Each lower-order Booth digit has magnitude at most 32, so the
 * sum preceding window i has absolute magnitude strictly less than
 * 32 * 64^i / 63. A nonzero contribution at window i has absolute
 * magnitude at least 64^i. For windows i <= 41, the absolute value of
 * their sum or difference is nonzero and strictly below the P-256 group
 * order. Equal-point doubling is therefore impossible, even modulo the
 * group order. Windows 42 through 48 require masked exceptional-case
 * selection. Window indices are public; secret digits never control the
 * exceptional-case branch. Infinity inputs always use masked selection.
 */
#if !defined(ECDSAP256_NATIVE_64)

static void ecdsap256_add_mixed_booth(ecdsap256_jac_t* R, const ecdsap256_jac_t* P, const ecdsap256_jac_t* Q, bool check_exception)
{
	ecdsap256_field z1z1 = { 0U };
	ecdsap256_field u2 = { 0U };
	ecdsap256_field s2 = { 0U };
	ecdsap256_field h = { 0U };
	ecdsap256_field delta = { 0U };
	ecdsap256_field hh = { 0U };
	ecdsap256_field hhh = { 0U };
	ecdsap256_field v = { 0U };
	ecdsap256_field temp = { 0U };
	ecdsap256_jac_t sum;
	ecdsap256_jac_t doubled;
	uint32_t eqpt;
	uint32_t pinf;
	uint32_t qinf;

	ecdsap256_fe_sqr(z1z1, P->Z);
	ecdsap256_fe_mul(u2, Q->X, z1z1);
	ecdsap256_fe_mul(s2, Q->Y, P->Z);
	ecdsap256_fe_mul(s2, s2, z1z1);
	ecdsap256_fe_sub(h, u2, P->X);
	ecdsap256_fe_sub(delta, s2, P->Y);
	ecdsap256_fe_sqr(hh, h);
	ecdsap256_fe_mul(hhh, h, hh);
	ecdsap256_fe_mul(v, P->X, hh);
	ecdsap256_fe_sqr(sum.X, delta);
	ecdsap256_fe_sub(sum.X, sum.X, hhh);
	ecdsap256_fe_add(temp, v, v);
	ecdsap256_fe_sub(sum.X, sum.X, temp);
	ecdsap256_fe_sub(temp, v, sum.X);
	ecdsap256_fe_mul(sum.Y, delta, temp);
	ecdsap256_fe_mul(temp, P->Y, hhh);
	ecdsap256_fe_sub(sum.Y, sum.Y, temp);
	ecdsap256_fe_mul(sum.Z, P->Z, h);

	pinf = ecdsap256_is_infinity(P);
	qinf = ecdsap256_is_infinity(Q);

	if (check_exception)
	{
		eqpt = (pinf ^ 1U) & (qinf ^ 1U) & ecdsap256_field_is_zero(h) & ecdsap256_field_is_zero(delta);
		ecdsap256_dbl(&doubled, P);
		ecdsap256_jac_ct_select(&sum, eqpt, &doubled, &sum);
		qsc_memutils_secure_erase(&doubled, sizeof(doubled));
	}

	ecdsap256_jac_ct_select(&sum, qinf, P, &sum);
	ecdsap256_jac_ct_select(&sum, pinf, Q, &sum);
	*R = sum;

	qsc_memutils_secure_erase(z1z1, sizeof(z1z1));
	qsc_memutils_secure_erase(u2, sizeof(u2));
	qsc_memutils_secure_erase(s2, sizeof(s2));
	qsc_memutils_secure_erase(h, sizeof(h));
	qsc_memutils_secure_erase(delta, sizeof(delta));
	qsc_memutils_secure_erase(hh, sizeof(hh));
	qsc_memutils_secure_erase(hhh, sizeof(hhh));
	qsc_memutils_secure_erase(v, sizeof(v));
	qsc_memutils_secure_erase(temp, sizeof(temp));
	qsc_memutils_secure_erase(&sum, sizeof(sum));
}
#endif

#if !defined(ECDSAP256_NATIVE_64)

static void ecdsap256_portable_generator(ecdsap256_jac_t* output, const uint32_t scalar[10U], const ecdsap256_field factors[4U])
{
	ecdsap256_jac_t accumulator;
	ecdsap256_jac_t selected;
	ecdsap256_jac_t added;
	ecdsap256_field negative_y;
	ecdsap256_field zero = { 0U };
	ecdsap256_field factor;
	ecdsap256_field square;
	ecdsap256_field cube;
	uint32_t magnitude;
	uint32_t sign;
	uint32_t difference;
	uint32_t equal;
	uint32_t mask;
	size_t i;
	size_t j;
	size_t w;

	/* A previous Booth prefix has absolute value at most
	 * 32 * (64^i - 1) / 63. For i <= 41, adding or subtracting a
	 * nonzero digit of magnitude at least 64^i gives a nonzero integer
	 * with absolute value below the P-256 subgroup order. Thus the
	 * equal-point exception is impossible in windows 1..41, even after
	 * reducing a blinded scalar modulo the subgroup order. Windows
	 * 42..48 retain unconditional, masked exceptional-case doubling.
	 * The window index is public and the predicate cannot leak a scalar.
	 */
	for (i = 0U; i < 49U; ++i)
	{
		magnitude = ecdsap256_booth_digit(scalar, i, &sign);
		mask = (uint32_t)0U - (uint32_t)((magnitude | (0U - magnitude)) >> 31U);

		for (w = 0U; w < 8U; ++w)
		{
			selected.X[w] = 0U;
			selected.Y[w] = 0U;
			selected.Z[w] = ECDSAP256_MONT_ONE[w] & mask;
		}

		for (j = 0U; j < 32U; ++j)
		{
			difference = (uint32_t)(j + 1U) ^ magnitude;
			equal = 1U ^ ((difference | (0U - difference)) >> 31U);
			mask = (uint32_t)0U - (uint32_t)equal;

			for (w = 0U; w < 8U; ++w)
			{
				selected.X[w] |= ECDSAP256_GENERATOR_TABLE[i][j][0U][w] & mask;
				selected.Y[w] |= ECDSAP256_GENERATOR_TABLE[i][j][1U][w] & mask;
			}
		}

		ecdsap256_fe_sub(negative_y, zero, selected.Y);
		ecdsap256_field_ct_select(selected.Y, sign, negative_y, selected.Y);

		if (i == 0U)
		{
			accumulator = selected;
		}
		else
		{
			ecdsap256_add_mixed_booth(&added, &accumulator, &selected, i >= 42U);
			accumulator = added;
		}

		if (i < 4U)
		{
			ecdsap256_field_copy(factor, factors[i]);
			ecdsap256_fe_sqr(square, factor);
			ecdsap256_fe_mul(cube, square, factor);
			ecdsap256_fe_mul(accumulator.X, accumulator.X, square);
			ecdsap256_fe_mul(accumulator.Y, accumulator.Y, cube);
			ecdsap256_fe_mul(accumulator.Z, accumulator.Z, factor);
		}
	}

	*output = accumulator;
	qsc_memutils_secure_erase(&accumulator, sizeof(accumulator));
	qsc_memutils_secure_erase(&selected, sizeof(selected));
	qsc_memutils_secure_erase(&added, sizeof(added));
	qsc_memutils_secure_erase(negative_y, sizeof(negative_y));
	qsc_memutils_secure_erase(factor, sizeof(factor));
	qsc_memutils_secure_erase(square, sizeof(square));
	qsc_memutils_secure_erase(cube, sizeof(cube));
}
#endif

static void ecdsap256_scalar_mult_generator(ecdsap256_jac_t* R, const uint32_t k[8U])
{
	uint32_t scalar[10U];
	ecdsap256_field factors[4U];

	if (ecdsap256_generator_blinding(scalar, factors, k))
	{
#if defined(ECDSAP256_NATIVE_64)
		ecdsap256_native_generator(R, scalar, factors);
#else
		ecdsap256_portable_generator(R, scalar, factors);
#endif
	}
	else
	{
		ecdsap256_set_infinity(R);
	}

	qsc_memutils_secure_erase(scalar, sizeof(scalar));
	qsc_memutils_secure_erase(factors, sizeof(factors));
}

static void ecdsap256_scalar_mult(ecdsap256_jac_t* R, const ecdsap256_aff_t* P, const uint32_t k[8U], bool fixed_generator)
{
	/* multiply a curve point by a scalar with a constant-time four-bit window */
	ecdsap256_jac_t table[16U];
	ecdsap256_aff_t encoded;
	ecdsap256_jac_t accumulator;
	ecdsap256_jac_t doubled;
	ecdsap256_jac_t selected;
	ecdsap256_jac_t added;
	uint32_t digit;
	uint32_t match;
	uint32_t difference;
	size_t i;
	size_t j;
	size_t round;

	if (fixed_generator == true)
	{
		ecdsap256_scalar_mult_generator(R, k);

		return;
	}

	ecdsap256_set_infinity(&table[0U]);

	ecdsap256_field_mont_encode(encoded.X, P->X);
	ecdsap256_field_mont_encode(encoded.Y, P->Y);
	ecdsap256_aff_to_jac(&table[1U], &encoded);

	for (i = 2U; i < 16U; ++i)
	{
		ecdsap256_add(&table[i], &table[i - 1U], &table[1U]);
	}

	ecdsap256_set_infinity(&accumulator);

	for (i = 64U; i > 0U; --i)
	{
		for (round = 0U; round < 4U; ++round)
		{
			ecdsap256_dbl(&doubled, &accumulator);
			accumulator = doubled;
		}

		digit = (k[(i - 1U) / 8U] >> (((uint32_t)((i - 1U) % 8U)) * 4U)) & 15U;
		ecdsap256_set_infinity(&selected);

		for (j = 0U; j < 16U; ++j)
		{
			difference = ((uint32_t)j ^ digit);
			match = (uint32_t)(1U ^ ((difference | (0U - difference)) >> 31U));
			ecdsap256_jac_ct_select(&selected, match, &table[j], &selected);
		}

		ecdsap256_add(&added, &accumulator, &selected);
		accumulator = added;
	}

	*R = accumulator;

	qsc_memutils_secure_erase(&encoded, sizeof(encoded));
	qsc_memutils_secure_erase(table, sizeof(table));
	qsc_memutils_secure_erase(&accumulator, sizeof(accumulator));
	qsc_memutils_secure_erase(&doubled, sizeof(doubled));
	qsc_memutils_secure_erase(&selected, sizeof(selected));
	qsc_memutils_secure_erase(&added, sizeof(added));
}

#if defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)

static void ecdsap256_double_scalar_mult(ecdsap256_jac_t* R, const ecdsap256_aff_t* Q, const uint32_t u1[8U], const uint32_t u2[8U], const qsc_ecdsap256_verify_context* context)
{
	/* joint scalar multiplication u1*G + u2*Q with one shared doubling chain */
	(void)context;
	ecdsap256_jac_t generator_table[16U];
	ecdsap256_jac_t point_table[16U];
	ecdsap256_jac_t accumulator;
	ecdsap256_jac_t doubled;
	ecdsap256_jac_t selected_generator;
	ecdsap256_jac_t selected_point;
	ecdsap256_jac_t added;
	ecdsap256_aff_t encoded;
	uint32_t fdgt;
	uint32_t sdgt;
	uint32_t difference;
	uint32_t mtf1;
	uint32_t mts2;
	size_t i;
	size_t j;
	size_t round;

	ecdsap256_set_infinity(&generator_table[0U]);
	ecdsap256_set_infinity(&point_table[0U]);
	ecdsap256_field_mont_encode(encoded.X, Q->X);
	ecdsap256_field_mont_encode(encoded.Y, Q->Y);
	ecdsap256_aff_to_jac(&point_table[1U], &encoded);

	for (i = 1U; i < 16U; ++i)
	{
		ecdsap256_field_copy(generator_table[i].X, ECDSAP256_GENERATOR_MONT[i][0U]);
		ecdsap256_field_copy(generator_table[i].Y, ECDSAP256_GENERATOR_MONT[i][1U]);
		ecdsap256_field_one(generator_table[i].Z);
	}

	for (i = 2U; i < 16U; ++i)
	{
		ecdsap256_add(&point_table[i], &point_table[i - 1U], &point_table[1U]);
	}

	ecdsap256_set_infinity(&accumulator);

	for (i = 64U; i > 0U; --i)
	{
		for (round = 0U; round < 4U; ++round)
		{
			ecdsap256_dbl(&doubled, &accumulator);
			accumulator = doubled;
		}

		fdgt = (u1[(i - 1U) / 8U] >> (((uint32_t)((i - 1U) % 8U)) * 4U)) & 15U;
		sdgt = (u2[(i - 1U) / 8U] >> (((uint32_t)((i - 1U) % 8U)) * 4U)) & 15U;
		ecdsap256_set_infinity(&selected_generator);
		ecdsap256_set_infinity(&selected_point);

		for (j = 0U; j < 16U; ++j)
		{
			difference = ((uint32_t)j ^ fdgt);
			mtf1 = (uint32_t)(1U ^ ((difference | (0U - difference)) >> 31U));
			difference = ((uint32_t)j ^ sdgt);
			mts2 = (uint32_t)(1U ^ ((difference | (0U - difference)) >> 31U));
			ecdsap256_jac_ct_select(&selected_generator, mtf1, &generator_table[j], &selected_generator);
			ecdsap256_jac_ct_select(&selected_point, mts2, &point_table[j], &selected_point);
		}

		ecdsap256_add_mixed(&added, &accumulator, &selected_generator);
		ecdsap256_add(&accumulator, &added, &selected_point);
	}

	*R = accumulator;
	qsc_memutils_secure_erase(generator_table, sizeof(generator_table));
	qsc_memutils_secure_erase(point_table, sizeof(point_table));
	qsc_memutils_secure_erase(&accumulator, sizeof(accumulator));
	qsc_memutils_secure_erase(&doubled, sizeof(doubled));
	qsc_memutils_secure_erase(&selected_generator, sizeof(selected_generator));
	qsc_memutils_secure_erase(&selected_point, sizeof(selected_point));
	qsc_memutils_secure_erase(&added, sizeof(added));
	qsc_memutils_secure_erase(&encoded, sizeof(encoded));
}
#else

#if !defined(ECDSAP256_NATIVE_64)

static void ecdsap256_add_public(ecdsap256_jac_t* result, const ecdsap256_jac_t* first, const ecdsap256_jac_t* second)
{
	/* affine-compatible Jacobian addition, restricted to public verification operands */
	ecdsap256_field z1z1;
	ecdsap256_field z2z2;
	ecdsap256_field u1;
	ecdsap256_field u2;
	ecdsap256_field s1;
	ecdsap256_field s2;
	ecdsap256_field h;
	ecdsap256_field r2;
	ecdsap256_field i;
	ecdsap256_field j;
	ecdsap256_field v;
	ecdsap256_field tmp;
	ecdsap256_jac_t candidate;

	if (ecdsap256_is_infinity(first) != 0U)
	{
		*result = *second;
	}
	else if (ecdsap256_is_infinity(second) != 0U)
	{
		*result = *first;
	}
	else
	{
		ecdsap256_fe_sqr(z1z1, first->Z);
		ecdsap256_fe_sqr(z2z2, second->Z);
		ecdsap256_fe_mul(u1, first->X, z2z2);
		ecdsap256_fe_mul(u2, second->X, z1z1);
		ecdsap256_fe_mul(s1, first->Y, second->Z);
		ecdsap256_fe_mul(s1, s1, z2z2);
		ecdsap256_fe_mul(s2, second->Y, first->Z);
		ecdsap256_fe_mul(s2, s2, z1z1);
		ecdsap256_fe_sub(h, u2, u1);
		ecdsap256_fe_sub(r2, s2, s1);

		if (ecdsap256_field_is_zero(h) != 0U)
		{
			if (ecdsap256_field_is_zero(r2) != 0U)
			{
				ecdsap256_dbl(result, first);
			}
			else
			{
				ecdsap256_set_infinity(result);
			}
		}
		else
		{
			ecdsap256_fe_mul_small(r2, r2, 2U);
			ecdsap256_fe_mul_small(i, h, 2U);
			ecdsap256_fe_sqr(i, i);
			ecdsap256_fe_mul(j, h, i);
			ecdsap256_fe_mul(v, u1, i);
			ecdsap256_fe_sqr(candidate.X, r2);
			ecdsap256_fe_sub(candidate.X, candidate.X, j);
			ecdsap256_fe_sub(candidate.X, candidate.X, v);
			ecdsap256_fe_sub(candidate.X, candidate.X, v);
			ecdsap256_fe_sub(tmp, v, candidate.X);
			ecdsap256_fe_mul(candidate.Y, r2, tmp);
			ecdsap256_fe_mul(tmp, s1, j);
			ecdsap256_fe_mul_small(tmp, tmp, 2U);
			ecdsap256_fe_sub(candidate.Y, candidate.Y, tmp);
			ecdsap256_fe_add(candidate.Z, first->Z, second->Z);
			ecdsap256_fe_sqr(candidate.Z, candidate.Z);
			ecdsap256_fe_sub(candidate.Z, candidate.Z, z1z1);
			ecdsap256_fe_sub(candidate.Z, candidate.Z, z2z2);
			ecdsap256_fe_mul(candidate.Z, candidate.Z, h);
			*result = candidate;
		}
	}
}

#endif

static void ecdsap256_recode_public(int8_t digits[257U], const uint32_t scalar[8U])
{
	/* convert a public scalar to width-five nonadjacent form */
	uint32_t value[9U] = { 0U };
	uint64_t carry;
	uint32_t borrow;
	uint32_t old;
	int32_t digit;
	uint32_t topbit;
	size_t i;
	size_t j;

	for (j = 0U; j < 8U; ++j)
	{
		value[j] = scalar[j];
	}

	for (i = 0U; i < 257U; ++i)
	{
		digit = 0;

		if ((value[0U] & 1U) != 0U)
		{
			digit = (int32_t)(value[0U] & 31U);

			if (digit > 15)
			{
				digit -= 32;
			}

			if (digit > 0)
			{
				borrow = (uint32_t)digit;

				for (j = 0U; j < 9U; ++j)
				{
					old = value[j];
					value[j] -= borrow;
					borrow = (uint32_t)(old < borrow);
				}
			}
			else
			{
				carry = (uint64_t)(-digit);

				for (j = 0U; j < 9U; ++j)
				{
					carry += value[j];
					value[j] = (uint32_t)carry;
					carry >>= 32U;
				}
			}
		}

		digits[i] = (int8_t)digit;
		topbit = 0U;

		for (j = 9U; j > 0U; --j)
		{
			old = value[j - 1U];
			value[j - 1U] = (old >> 1U) | (topbit << 31U);
			topbit = old & 1U;
		}
	}

	qsc_memutils_secure_erase(value, sizeof(value));
}

#if !defined(ECDSAP256_NATIVE_64)

static void ecdsap256_negate_public(ecdsap256_jac_t* output, const ecdsap256_jac_t* input)
{
	/* negate the Y coordinate of a public Jacobian point */
	ecdsap256_field zero = { 0U };
	ecdsap256_jac_t tmp;

	tmp = *input;
	ecdsap256_fe_sub(tmp.Y, zero, tmp.Y);
	*output = tmp;
}

static void ecdsap256_batch_affine_public(ecdsap256_jac_t table[8U])
{
	/* calculate u1 G + u2 Q with public-only signed-window recoding */
	ecdsap256_field prefix[8U];
	ecdsap256_field inverse;
	ecdsap256_field zinverse;
	ecdsap256_field zinverse2;
	ecdsap256_field zinverse3;
	size_t i;

	ecdsap256_field_copy(prefix[0U], table[0U].Z);

	for (i = 1U; i < 8U; ++i)
	{
		ecdsap256_fe_mul(prefix[i], prefix[i - 1U], table[i].Z);
	}

	ecdsap256_fe_inv(inverse, prefix[7U]);

	for (i = 8U; i > 0U; --i)
	{
		if (i == 1U)
		{
			ecdsap256_field_copy(zinverse, inverse);
		}
		else
		{
			ecdsap256_fe_mul(zinverse, inverse, prefix[i - 2U]);
			ecdsap256_fe_mul(inverse, inverse, table[i - 1U].Z);
		}

		ecdsap256_fe_sqr(zinverse2, zinverse);
		ecdsap256_fe_mul(zinverse3, zinverse2, zinverse);
		ecdsap256_fe_mul(table[i - 1U].X, table[i - 1U].X, zinverse2);
		ecdsap256_fe_mul(table[i - 1U].Y, table[i - 1U].Y, zinverse3);
		ecdsap256_field_one(table[i - 1U].Z);
	}

	qsc_memutils_secure_erase(prefix, sizeof(prefix));
	qsc_memutils_secure_erase(inverse, sizeof(inverse));
	qsc_memutils_secure_erase(zinverse, sizeof(zinverse));
	qsc_memutils_secure_erase(zinverse2, sizeof(zinverse2));
	qsc_memutils_secure_erase(zinverse3, sizeof(zinverse3));
}

#endif

#if defined(ECDSAP256_NATIVE_64)

/*! \typedef ecdsap256_public_fe64
 * \brief Four-word Montgomery field element; public verification data only.
 */
typedef uint64_t ecdsap256_public_fe64[4U];

/*! \def ECDSAP256_PUBLIC_ADD_WORD
 * \brief Public addition adapter, honoring the legacy intrinsic-disable switch.
 */
/*! \def ECDSAP256_PUBLIC_SUB_WORD
 * \brief Public subtraction adapter, honoring the legacy intrinsic-disable switch.
 */
#if defined(QSC_ECDSA_DISABLE_PUBLIC_CARRY_INTRINSICS)
#define ECDSAP256_PUBLIC_ADD_WORD ecdsap256_word_add_c
#define ECDSAP256_PUBLIC_SUB_WORD ecdsap256_word_sub_c
#else
#define ECDSAP256_PUBLIC_ADD_WORD ecdsap256_word_add
#define ECDSAP256_PUBLIC_SUB_WORD ecdsap256_word_sub
#endif

static inline void ecdsap256_public_add64(ecdsap256_public_fe64 output, const ecdsap256_public_fe64 left, const ecdsap256_public_fe64 right)
{
	uint64_t t[4U];
	uint64_t reduced[4U];
	uint64_t carry;
	uint64_t borrow;
	uint64_t mask;
	size_t i;

	carry = 0U;

	for (i = 0U; i < 4U; ++i)
	{
		t[i] = ECDSAP256_PUBLIC_ADD_WORD(left[i], right[i], &carry);
	}

	borrow = 0U;

	for (i = 0U; i < 4U; ++i)
	{
		reduced[i] = ECDSAP256_PUBLIC_SUB_WORD(t[i], ECDSAP256_P64[i], &borrow);
	}

	mask = (uint64_t)0U - (uint64_t)(carry | (borrow ^ 1U));

	for (i = 0U; i < 4U; ++i)
	{
		output[i] = (reduced[i] & mask) | (t[i] & ~mask);
	}
}

static inline void ecdsap256_public_sub64(ecdsap256_public_fe64 output, const ecdsap256_public_fe64 left, const ecdsap256_public_fe64 right)
{
	/* constant-time canonical field subtraction in native-width limbs */
	uint64_t t[4U];
	uint64_t borrow;
	uint64_t carry;
	uint64_t mask;
	size_t i;

	borrow = 0U;

	for (i = 0U; i < 4U; ++i)
	{
		t[i] = ECDSAP256_PUBLIC_SUB_WORD(left[i], right[i], &borrow);
	}

	mask = (uint64_t)0U - borrow;
	carry = 0U;

	for (i = 0U; i < 4U; ++i)
	{
		output[i] = ECDSAP256_PUBLIC_ADD_WORD(t[i], (ECDSAP256_P64[i] & mask), &carry);
	}
}

static inline void ecdsap256_public_mul64(ecdsap256_public_fe64 output, const ecdsap256_public_fe64 left, const ecdsap256_public_fe64 right)
{
	uint64_t scratch[15U];

	ecdsap256_native_mul(output, left, right, scratch);
}

static inline void ecdsap256_public_square64(ecdsap256_public_fe64 output, const ecdsap256_public_fe64 left)
{
	uint64_t scratch[15U];

	ecdsap256_native_square(output, left, scratch);
}

static inline void ecdsap256_public_half64(ecdsap256_public_fe64 output, const ecdsap256_public_fe64 input)
{
	/* divide canonical public P-256 field residue by two modulo p */
	uint64_t t[4U];
	uint64_t mask;
	uint64_t carry;
	uint64_t top;
	size_t i;

	mask = (uint64_t)0U - (input[0U] & 1U);
	carry = 0U;

	for (i = 0U; i < 4U; ++i)
	{
		t[i] = ecdsap256_word_add(input[i], (ECDSAP256_P64[i] & mask), &carry);
	}

	top = carry;

	for (i = 4U; i > 0U; --i)
	{
		output[i - 1U] = (t[i - 1U] >> 1U) | (top << 63U);
		top = t[i - 1U] & 1U;
	}
}

#endif

#if !defined(ECDSAP256_NATIVE_64)

static void ecdsap256_add_public_mixed(ecdsap256_jac_t* output, const ecdsap256_jac_t* first, const ecdsap256_jac_t* second)
{
#if defined(ECDSAP256_NATIVE_64)
	ecdsap256_add_public_mixed_native(output, first, second);
#else

	ecdsap256_field zz;
	ecdsap256_field u;
	ecdsap256_field v;
	ecdsap256_field h;
	ecdsap256_field r;
	ecdsap256_field i;
	ecdsap256_field j;
	ecdsap256_field x;
	ecdsap256_field scratch;
	ecdsap256_jac_t result;

	if (ecdsap256_is_infinity(first) != 0U)
	{
		*output = *second;
	}
	else if (ecdsap256_is_infinity(second) != 0U)
	{
		*output = *first;
	}
	else
	{
		ecdsap256_fe_sqr(zz, first->Z);
		ecdsap256_fe_mul(u, second->X, zz);
		ecdsap256_fe_mul(v, second->Y, first->Z);
		ecdsap256_fe_mul(v, v, zz);
		ecdsap256_fe_sub(h, u, first->X);
		ecdsap256_fe_sub(r, v, first->Y);

		if (ecdsap256_field_is_zero(h) != 0U)
		{
			if (ecdsap256_field_is_zero(r) != 0U)
			{
				ecdsap256_dbl(output, first);
			}
			else
			{
				ecdsap256_set_infinity(output);
			}
		}
		else
		{
			ecdsap256_fe_mul_small(r, r, 2U);
			ecdsap256_fe_mul_small(i, h, 2U);
			ecdsap256_fe_sqr(i, i);
			ecdsap256_fe_mul(j, h, i);
			ecdsap256_fe_mul(u, first->X, i);
			ecdsap256_fe_sqr(result.X, r);
			ecdsap256_fe_sub(result.X, result.X, j);
			ecdsap256_fe_sub(result.X, result.X, u);
			ecdsap256_fe_sub(result.X, result.X, u);
			ecdsap256_fe_sub(x, u, result.X);
			ecdsap256_fe_mul(result.Y, r, x);
			ecdsap256_fe_mul(scratch, first->Y, j);
			ecdsap256_fe_mul_small(scratch, scratch, 2U);
			ecdsap256_fe_sub(result.Y, result.Y, scratch);
			ecdsap256_fe_mul(result.Z, first->Z, h);
			ecdsap256_fe_mul_small(result.Z, result.Z, 2U);
			*output = result;
		}
	}
#endif
}
#endif

#if !defined(ECDSAP256_NATIVE_64)

static void ecdsap256_half_public(ecdsap256_field output, const ecdsap256_field value)
{
	/* halve a Montgomery field residue modulo the public curve prime */
	uint32_t tmp[8U];
	uint64_t carry;
	uint64_t v;
	uint32_t high;
	uint32_t mask;
	size_t i;

	carry = 0U;
	mask = (uint32_t)(0U - (value[0U] & 1U));

	for (i = 0U; i < 8U; ++i)
	{
		v = (uint64_t)value[i] + (uint64_t)(ECDSAP256_P[i] & mask) + carry;
		tmp[i] = (uint32_t)v;
		carry = v >> 32U;
	}

	high = (uint32_t)carry;

	for (i = 8U; i > 0U; --i)
	{
		output[i - 1U] = (tmp[i - 1U] >> 1U) | (high << 31U);
		high = tmp[i - 1U] & 1U;
	}

	qsc_memutils_secure_erase(tmp, sizeof(tmp));
}

#endif

#if !defined(ECDSAP256_NATIVE_64)

static void ecdsap256_double_n_public(ecdsap256_jac_t* output, const ecdsap256_jac_t* point, size_t rounds)
{
	/* apply grouped point doubling for the a=-3 curve */
#if defined(ECDSAP256_NATIVE_64)
	ecdsap256_double_n_public_native(output, point, rounds);
#else

	ecdsap256_jac_t result;
	ecdsap256_field ny;
	ecdsap256_field w;
	ecdsap256_field ny2;
	ecdsap256_field ny4;
	ecdsap256_field t1;
	ecdsap256_field t2;
	ecdsap256_field tmp;

	result = *point;
	ecdsap256_fe_add(ny, point->Y, point->Y);
	ecdsap256_fe_sqr(w, point->Z);
	ecdsap256_fe_sqr(w, w);

	while (rounds > 0U)
	{
		ecdsap256_fe_sqr(ny2, ny);
		ecdsap256_fe_sqr(ny4, ny2);
		ecdsap256_fe_sqr(t1, result.X);
		ecdsap256_fe_sub(t1, t1, w);
		ecdsap256_fe_mul_small(t1, t1, 3U);
		ecdsap256_fe_mul(t2, result.X, ny2);
		ecdsap256_fe_sqr(result.X, t1);
		ecdsap256_fe_add(tmp, t2, t2);
		ecdsap256_fe_sub(result.X, result.X, tmp);
		ecdsap256_fe_mul(result.Z, result.Z, ny);
		ecdsap256_fe_sub(tmp, t2, result.X);
		ecdsap256_fe_mul(tmp, t1, tmp);
		ecdsap256_fe_add(tmp, tmp, tmp);
		ecdsap256_fe_sub(ny, tmp, ny4);
		--rounds;

		if (rounds > 0U)
		{
			ecdsap256_fe_mul(w, w, ny4);
		}
	}

	ecdsap256_half_public(result.Y, ny);
	*output = result;
	qsc_memutils_secure_erase(&result, sizeof(result));
	qsc_memutils_secure_erase(ny, sizeof(ny));
	qsc_memutils_secure_erase(w, sizeof(w));
	qsc_memutils_secure_erase(ny2, sizeof(ny2));
	qsc_memutils_secure_erase(ny4, sizeof(ny4));
	qsc_memutils_secure_erase(t1, sizeof(t1));
	qsc_memutils_secure_erase(t2, sizeof(t2));
	qsc_memutils_secure_erase(tmp, sizeof(tmp));
#endif
}

#endif /* portable verification grouped doubling */

#if defined(ECDSAP256_NATIVE_64) && !defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)
/*! brief Public verifier subgroup order in four little-endian 64-bit limbs. */
static const uint64_t ECDSAP256_VERIFY_ORDER_N64[4U] = {
	UINT64_C(0xF3B9CAC2FC632551), UINT64_C(0xBCE6FAADA7179E84), UINT64_C(0xFFFFFFFFFFFFFFFF), UINT64_C(0xFFFFFFFF00000000)};

static int32_t ecdsap256_verify_order_compare64(const uint64_t left[4U], const uint64_t right[4U])
{
	/* compare two public 256-bit order residues in four native limbs */
	int32_t result;
	size_t i;

	result = 0;

	for (i = 4U; i > 0U; --i)
	{
		if (left[i - 1U] != right[i - 1U])
		{
			result = (left[i - 1U] > right[i - 1U]) ? 1 : -1;
			break;
		}
	}

	return result;
}

static void ecdsap256_verify_order_sub64(uint64_t left[4U], const uint64_t right[4U])
{
	/* subtract a public 256-bit integer in place without modular reduction */
	uint64_t borrow;
	size_t i;

	borrow = 0U;

	for (i = 0U; i < 4U; ++i)
	{
		left[i] = ecdsap256_word_sub(left[i], right[i], &borrow);
	}
}

static void ecdsap256_verify_order_modsub64(uint64_t left[4U], const uint64_t right[4U])
{
	/* subtract public canonical P-256 order residues modulo n */
	uint64_t borrow;
	uint64_t carry;
	size_t i;

	borrow = 0U;

	for (i = 0U; i < 4U; ++i)
	{
		left[i] = ecdsap256_word_sub(left[i], right[i], &borrow);
	}

	if (borrow != 0U)
	{
		carry = 0U;

		for (i = 0U; i < 4U; ++i)
		{
			left[i] = ecdsap256_word_add(left[i], ECDSAP256_VERIFY_ORDER_N64[i], &carry);
		}
	}
}

static void ecdsap256_verify_order_half64(uint64_t value[4U])
{
	/* halve a public canonical order residue modulo n */
	uint64_t carry;
	uint64_t high;
	uint64_t next;
	size_t i;

	carry = 0U;

	if ((value[0U] & 1U) != 0U)
	{
		for (i = 0U; i < 4U; ++i)
		{
			value[i] = ecdsap256_word_add(value[i], ECDSAP256_VERIFY_ORDER_N64[i], &carry);
		}
	}

	high = carry;

	for (i = 4U; i > 0U; --i)
	{
		next = value[i - 1U] & 1U;
		value[i - 1U] = (value[i - 1U] >> 1U) | (high << 63U);
		high = next;
	}
}

static void ecdsap256_sc_inv_public(uint32_t output[8U], const uint32_t input[8U])
{
	/* invert a nonzero public subgroup scalar using native-width binary GCD */
	uint64_t u[4U] = { 0U };
	uint64_t v[4U] = { 0U };
	uint64_t x1[4U] = { 0U };
	uint64_t x2[4U] = { 0U };
	uint64_t zero[4U] = { 0U };
	uint64_t one[4U] = {1U, 0U, 0U, 0U};
	uint64_t* selected;
	size_t i;
	size_t count;
	bool valid;

	for (i = 0U; i < 4U; ++i)
	{
		u[i] = (uint64_t)input[2U * i] | ((uint64_t)input[2U * i + 1U] << 32U);
		v[i] = ECDSAP256_VERIFY_ORDER_N64[i];
	}

	x1[0U] = 1U;
	valid = (ecdsap256_verify_order_compare64(u, zero) > 0) && (ecdsap256_verify_order_compare64(u, v) < 0);
	count = 0U;

	while (valid && (count < 1024U))
	{
		if ((ecdsap256_verify_order_compare64(u, one) == 0) || (ecdsap256_verify_order_compare64(v, one) == 0))
		{
			break;
		}
		else if ((u[0U] & 1U) == 0U)
		{
			ecdsap256_verify_order_half64(u);
			ecdsap256_verify_order_half64(x1);
		}
		else if ((v[0U] & 1U) == 0U)
		{
			ecdsap256_verify_order_half64(v);
			ecdsap256_verify_order_half64(x2);
		}
		else if (ecdsap256_verify_order_compare64(u, v) >= 0)
		{
			ecdsap256_verify_order_sub64(u, v);
			ecdsap256_verify_order_modsub64(x1, x2);
		}
		else
		{
			ecdsap256_verify_order_sub64(v, u);
			ecdsap256_verify_order_modsub64(x2, x1);
		}

		++count;
	}

	selected = zero;

	if (valid && (ecdsap256_verify_order_compare64(u, one) == 0))
	{
		selected = x1;
	}
	else if (valid && (ecdsap256_verify_order_compare64(v, one) == 0))
	{
		selected = x2;
	}

	for (i = 0U; i < 4U; ++i)
	{
		output[2U * i] = (uint32_t)selected[i];
		output[2U * i + 1U] = (uint32_t)(selected[i] >> 32U);
	}

	qsc_memutils_secure_erase(u, sizeof(u));
	qsc_memutils_secure_erase(v, sizeof(v));
	qsc_memutils_secure_erase(x1, sizeof(x1));
	qsc_memutils_secure_erase(x2, sizeof(x2));
	qsc_memutils_secure_erase(zero, sizeof(zero));
	qsc_memutils_secure_erase(one, sizeof(one));
}
#else

static int32_t ecdsap256_sc_public_256_cmp(const uint32_t a[8U], const uint32_t b[8U])
{
	/* compare two canonical subgroup residues from public verification data */
	int32_t relation;
	size_t i;

	relation = 0;

	for (i = 8U; i > 0U; --i)
	{
		if (a[i - 1U] > b[i - 1U])
		{
			relation = 1;
			break;
		}
		else if (a[i - 1U] < b[i - 1U])
		{
			relation = -1;
			break;
		}
	}

	return relation;
}

static void ecdsap256_sc_public_256_sub(uint32_t a[8U], const uint32_t b[8U])
{
	/* subtract two public scalars in place modulo 2^256 */
	uint64_t tmp;
	uint64_t borrow;
	size_t i;

	borrow = 0U;

	for (i = 0U; i < 8U; ++i)
	{
		tmp = (uint64_t)a[i] - b[i] - borrow;
		a[i] = (uint32_t)tmp;
		borrow = tmp >> 63U;
	}
}

static void ecdsap256_sc_public_256_mod_sub(uint32_t a[8U], const uint32_t b[8U])
{
	/* subtract two public residues modulo the subgroup order */
	uint64_t t;
	uint64_t borrow;
	uint64_t carry;
	size_t i;

	borrow = 0U;

	for (i = 0U; i < 8U; ++i)
	{
		t = (uint64_t)a[i] - b[i] - borrow;
		a[i] = (uint32_t)t;
		borrow = t >> 63U;
	}

	if (borrow != 0U)
	{
		carry = 0U;

		for (i = 0U; i < 8U; ++i)
		{
			t = (uint64_t)a[i] + ECDSAP256_N[i] + carry;
			a[i] = (uint32_t)t;
			carry = t >> 32U;
		}
	}
}

static void ecdsap256_sc_public_256_half(uint32_t a[8U])
{
	/* divide a public canonical residue by two modulo the order */
	uint64_t t;
	uint64_t carry;
	uint32_t high;
	size_t i;

	carry = 0U;

	if ((a[0U] & 1U) != 0U)
	{
		for (i = 0U; i < 8U; ++i)
		{
			t = (uint64_t)a[i] + ECDSAP256_N[i] + carry;
			a[i] = (uint32_t)t;
			carry = t >> 32U;
		}
	}

	high = (uint32_t)carry;

	for (i = 8U; i > 0U; --i)
	{
		t = a[i - 1U];
		a[i - 1U] = (uint32_t)(t >> 1U) | (high << 31U);
		high = (uint32_t)t & 1U;
	}
}

static void ecdsap256_sc_inv_public(uint32_t r[8U], const uint32_t a[8U])
{
	/* binary extended Euclidean inversion for public ECDSA verification scalars only */
	uint32_t u[8U] = { 0U };
	uint32_t v[8U] = { 0U };
	uint32_t x1[8U] = { 0U };
	uint32_t x2[8U] = { 0U };
	uint32_t zero[8U] = { 0U };
	size_t i;
	size_t steps;
	bool valid;

	ecdsap256_sc_copy(u, a);
	ecdsap256_sc_copy(v, ECDSAP256_N);
	x1[0U] = 1U;
	valid = (ecdsap256_sc_public_256_cmp(a, zero) > 0) && (ecdsap256_sc_public_256_cmp(a, ECDSAP256_N) < 0);
	steps = 0U;

	while (valid && steps < 1024U)
	{
		if (u[0U] == 1U)
		{
			valid = true;

			for (i = 1U; i < 8U; ++i)
			{
				if (u[i] != 0U)
				{
					valid = false;
				}
			}

			if (valid)
			{
				break;
			}
		}

		if (v[0U] == 1U)
		{
			valid = true;

			for (i = 1U; i < 8U; ++i)
			{
				if (v[i] != 0U)
				{
					valid = false;
				}
			}

			if (valid)
			{
				break;
			}
		}

		valid = true;

		if ((u[0U] & 1U) == 0U)
		{
			ecdsap256_sc_public_256_half(u); /* u even: ordinary shift, no modulus carry */
			ecdsap256_sc_public_256_half(x1);
		}
		else if ((v[0U] & 1U) == 0U)
		{
			ecdsap256_sc_public_256_half(v);
			ecdsap256_sc_public_256_half(x2);
		}
		else if (ecdsap256_sc_public_256_cmp(u, v) >= 0)
		{
			ecdsap256_sc_public_256_sub(u, v);
			ecdsap256_sc_public_256_mod_sub(x1, x2);
		}
		else
		{
			ecdsap256_sc_public_256_sub(v, u);
			ecdsap256_sc_public_256_mod_sub(x2, x1);
		}

		++steps;
	}

	/* input validation normally guarantees gcd(a,n)=1. */
	if (valid && u[0U] == 1U)
	{
		valid = true;

		for (i = 1U; i < 8U; ++i)
		{
			if (u[i] != 0U)
			{
				valid = false;
			}
		}

		if (valid)
		{
			ecdsap256_sc_copy(r, x1);
		}
	}
	else if (valid && v[0U] == 1U)
	{
		valid = true;

		for (i = 1U; i < 8U; ++i)
		{
			if (v[i] != 0U)
			{
				valid = false;
			}
		}

		if (valid)
		{
			ecdsap256_sc_copy(r, x2);
		}
	}
	else
	{
		valid = false;
	}

	if (!valid)
	{
		ecdsap256_sc_copy(r, zero);
	}

	qsc_memutils_secure_erase(u, sizeof(u));
	qsc_memutils_secure_erase(v, sizeof(v));
	qsc_memutils_secure_erase(x1, sizeof(x1));
	qsc_memutils_secure_erase(x2, sizeof(x2));
	qsc_memutils_secure_erase(zero, sizeof(zero));
}

#endif

#if !defined(ECDSAP256_NATIVE_64)

static void ecdsap256_joint_public_wnaf(ecdsap256_jac_t* output, const ecdsap256_aff_t* Q, const uint32_t first[8U], const uint32_t second[8U])
{
	ecdsap256_aff_t encoded;
	ecdsap256_jac_t table_q[8U];
	ecdsap256_jac_t twice_q;
	ecdsap256_jac_t accumulator;
	ecdsap256_jac_t doubled;
	ecdsap256_jac_t added;
	ecdsap256_jac_t negative;
	int8_t dq[257U];
	int32_t q;
	size_t i;
	size_t pending;
	uint32_t scalar[10U] = { 0U };
	uint32_t magnitude;
	uint32_t sign;
	ecdsap256_jac_t selected;

	ecdsap256_field_mont_encode(encoded.X, Q->X);
	ecdsap256_field_mont_encode(encoded.Y, Q->Y);
	ecdsap256_aff_to_jac(&table_q[0U], &encoded);
	ecdsap256_dbl(&twice_q, &table_q[0U]);

	for (i = 1U; i < 8U; ++i)
	{
		ecdsap256_add_public(&table_q[i], &table_q[i - 1U], &twice_q);
	}

	ecdsap256_batch_affine_public(table_q);

	ecdsap256_recode_public(dq, second);
	ecdsap256_set_infinity(&accumulator);

	pending = 0U;

	for (i = 257U; i > 0U; --i)
	{
		++pending;
		q = (int32_t)dq[i - 1U];

		if (q != 0)
		{
			if (ecdsap256_is_infinity(&accumulator) == 0U)
			{
				ecdsap256_double_n_public(&doubled, &accumulator, pending);
				accumulator = doubled;
			}

			pending = 0U;
		}

		if (q > 0)
		{
			ecdsap256_add_public_mixed(&added, &accumulator, &table_q[((uint32_t)q - 1U) / 2U]);
			accumulator = added;
		}
		else if (q < 0)
		{
			ecdsap256_negate_public(&negative, &table_q[((uint32_t)(-q) - 1U) / 2U]);
			ecdsap256_add_public_mixed(&added, &accumulator, &negative);
			accumulator = added;
		}
	}

	if ((pending > 0U) && (ecdsap256_is_infinity(&accumulator) == 0U))
	{
		ecdsap256_double_n_public(&doubled, &accumulator, pending);
		accumulator = doubled;
	}

	for (i = 0U; i < 8U; ++i)
	{
		scalar[i] = first[i];
	}

	for (i = 0U; i < 43U; ++i)
	{
		magnitude = ecdsap256_booth_digit(scalar, i, &sign);

		if (magnitude != 0U)
		{
			ecdsap256_field_copy(selected.X, ECDSAP256_GENERATOR_TABLE[i][magnitude - 1U][0U]);
			ecdsap256_field_copy(selected.Y, ECDSAP256_GENERATOR_TABLE[i][magnitude - 1U][1U]);
			ecdsap256_field_copy(selected.Z, ECDSAP256_MONT_ONE);

			if (sign != 0U)
			{
				ecdsap256_negate_public(&negative, &selected);
				selected = negative;
			}

			ecdsap256_add_public_mixed(&added, &accumulator, &selected);
			accumulator = added;
		}
	}

	*output = accumulator;
	qsc_memutils_secure_erase(&encoded, sizeof(encoded));
	qsc_memutils_secure_erase(table_q, sizeof(table_q));
	qsc_memutils_secure_erase(&twice_q, sizeof(twice_q));
	qsc_memutils_secure_erase(&accumulator, sizeof(accumulator));
	qsc_memutils_secure_erase(&doubled, sizeof(doubled));
	qsc_memutils_secure_erase(&added, sizeof(added));
	qsc_memutils_secure_erase(scalar, sizeof(scalar));
	qsc_memutils_secure_erase(&selected, sizeof(selected));
	qsc_memutils_secure_erase(&negative, sizeof(negative));
	qsc_memutils_secure_erase(dq, sizeof(dq));
}

#endif

#if defined(ECDSAP256_NATIVE_64)

static void ecdsap256_verify_public_add_generator(ecdsap256_native_point* output, const ecdsap256_native_point* first, const ecdsap256_native_point* second, ecdsap256_native_window_workspace* work)
{
	/* add one public affine point using the native mixed-Jacobian formula */
	uint64_t finf;
	uint64_t sinf;

	ecdsap256_public_square64(work->zz, first->z);
	ecdsap256_public_mul64(work->u, second->x, work->zz);
	ecdsap256_public_mul64(work->s, second->y, first->z);
	ecdsap256_public_mul64(work->s, work->s, work->zz);
	ecdsap256_public_sub64(work->h, work->u, first->x);
	ecdsap256_public_sub64(work->delta, work->s, first->y);
	ecdsap256_public_square64(work->hh, work->h);
	ecdsap256_public_mul64(work->hhh, work->h, work->hh);
	ecdsap256_public_mul64(work->v, first->x, work->hh);
	ecdsap256_public_square64(work->added.x, work->delta);
	ecdsap256_public_sub64(work->added.x, work->added.x, work->hhh);
	ecdsap256_public_add64(work->tmp, work->v, work->v);
	ecdsap256_public_sub64(work->added.x, work->added.x, work->tmp);
	ecdsap256_public_sub64(work->tmp, work->v, work->added.x);
	ecdsap256_public_mul64(work->added.y, work->delta, work->tmp);
	ecdsap256_public_mul64(work->tmp, first->y, work->hhh);
	ecdsap256_public_sub64(work->added.y, work->added.y, work->tmp);
	ecdsap256_public_mul64(work->added.z, first->z, work->h);

	finf = ecdsap256_native_is_zero(first->z);
	sinf = ecdsap256_native_is_zero(second->z);
	ecdsap256_native_point_choose(&work->added, first, &work->added, sinf);
	ecdsap256_native_point_choose(&work->added, second, &work->added, finf);
	*output = work->added;
}

static void ecdsap256_verify_public_square_n(ecdsap256_native_fe value, size_t count)
{
	/* square a native public field element the specified number of times */
	size_t i;

	for (i = 0U; i < count; ++i)
	{
		ecdsap256_public_square64(value, value);
	}
}

static void ecdsap256_verify_inverse_square(ecdsap256_native_fe output, const ecdsap256_native_fe z)
{
	/* compute inverse-square of a nonzero public field element */
	ecdsap256_native_fe t[2U] = {{ 0U }};
	ecdsap256_native_fe r = { 0U };

	ecdsap256_public_square64(r, z);
	ecdsap256_public_mul64(r, r, z);
	ecdsap256_public_square64(r, r);
	ecdsap256_public_mul64(r, r, z);
	ecdsap256_native_copy(t[0U], r);
	ecdsap256_verify_public_square_n(t[0U], 3U);
	ecdsap256_public_mul64(t[0U], t[0U], r);
	ecdsap256_native_copy(t[1U], t[0U]);
	ecdsap256_verify_public_square_n(t[1U], 6U);
	ecdsap256_public_mul64(t[0U], t[0U], t[1U]);
	ecdsap256_verify_public_square_n(t[0U], 3U);
	ecdsap256_public_mul64(r, r, t[0U]);
	ecdsap256_public_square64(t[0U], r);
	ecdsap256_public_mul64(t[0U], t[0U], z);
	ecdsap256_native_copy(t[1U], t[0U]);
	ecdsap256_verify_public_square_n(t[1U], 16U);
	ecdsap256_public_mul64(t[0U], t[0U], t[1U]);
	ecdsap256_verify_public_square_n(t[0U], 15U);
	ecdsap256_public_mul64(r, r, t[0U]);
	ecdsap256_verify_public_square_n(t[0U], 17U);
	ecdsap256_public_mul64(t[0U], t[0U], z);
	ecdsap256_verify_public_square_n(t[0U], 143U);
	ecdsap256_public_mul64(t[0U], t[0U], r);
	ecdsap256_verify_public_square_n(t[0U], 47U);
	ecdsap256_public_mul64(r, r, t[0U]);
	ecdsap256_verify_public_square_n(r, 2U);
	ecdsap256_native_copy(output, r);

	qsc_memutils_secure_erase(t, sizeof(t));
	qsc_memutils_secure_erase(r, sizeof(r));
}

static void ecdsap256_verify_native_batch(ecdsap256_native_point table[8U])
{
	/* normalize eight projective public odd multiples with one inversion */
	ecdsap256_native_fe prefix[8U] = {{ 0U }};
	ecdsap256_native_fe inverse = { 0U };
	ecdsap256_native_fe invsquared = { 0U };
	ecdsap256_native_fe zinv = { 0U };
	ecdsap256_native_fe z2 = { 0U };
	ecdsap256_native_fe z3 = { 0U };
	size_t i;

	ecdsap256_native_copy(prefix[0U], table[0U].z);

	for (i = 1U; i < 8U; ++i)
	{
		ecdsap256_public_mul64(prefix[i], prefix[i - 1U], table[i].z);
	}

	ecdsap256_verify_inverse_square(invsquared, prefix[7U]);
	ecdsap256_public_mul64(inverse, invsquared, prefix[7U]);

	for (i = 8U; i > 0U; --i)
	{
		if (i == 1U)
		{
			ecdsap256_native_copy(zinv, inverse);
		}
		else
		{
			ecdsap256_public_mul64(zinv, inverse, prefix[i - 2U]);
			ecdsap256_public_mul64(inverse, inverse, table[i - 1U].z);
		}

		ecdsap256_public_square64(z2, zinv);
		ecdsap256_public_mul64(z3, z2, zinv);
		ecdsap256_public_mul64(table[i - 1U].x, table[i - 1U].x, z2);
		ecdsap256_public_mul64(table[i - 1U].y, table[i - 1U].y, z3);
		ecdsap256_native_copy(table[i - 1U].z, ECDSAP256_NATIVE_ONE);
	}

	qsc_memutils_secure_erase(prefix, sizeof(prefix));
	qsc_memutils_secure_erase(inverse, sizeof(inverse));
	qsc_memutils_secure_erase(invsquared, sizeof(invsquared));
	qsc_memutils_secure_erase(zinv, sizeof(zinv));
	qsc_memutils_secure_erase(z2, sizeof(z2));
	qsc_memutils_secure_erase(z3, sizeof(z3));
}

static void ecdsap256_verify_native_double_n(ecdsap256_native_point* output, const ecdsap256_native_point* input, size_t rounds)
{
	/* apply grouped a=-3 doubling to a public native Jacobian point */
	ecdsap256_native_fe x = { 0U };
	ecdsap256_native_fe z = { 0U };
	ecdsap256_native_fe ny = { 0U };
	ecdsap256_native_fe w = { 0U };
	ecdsap256_native_fe ny2 = { 0U };
	ecdsap256_native_fe ny4 = { 0U };
	ecdsap256_native_fe t1 = { 0U };
	ecdsap256_native_fe t2 = { 0U };
	ecdsap256_native_fe tmp = { 0U };
	size_t remaining;

	*output = *input;

	if ((rounds != 0U) && (ecdsap256_native_is_zero(input->z) == 0U))
	{
		ecdsap256_native_copy(x, input->x);
		ecdsap256_native_copy(z, input->z);
		ecdsap256_public_add64(ny, input->y, input->y);
		ecdsap256_public_square64(w, z);
		ecdsap256_public_square64(w, w);
		remaining = rounds;

		while (remaining != 0U)
		{
			ecdsap256_public_square64(ny2, ny);
			ecdsap256_public_square64(ny4, ny2);
			ecdsap256_public_square64(t1, x);
			ecdsap256_public_sub64(t1, t1, w);
			ecdsap256_public_add64(tmp, t1, t1);
			ecdsap256_public_add64(t1, tmp, t1);
			ecdsap256_public_mul64(t2, x, ny2);
			ecdsap256_public_square64(x, t1);
			ecdsap256_public_add64(tmp, t2, t2);
			ecdsap256_public_sub64(x, x, tmp);
			ecdsap256_public_mul64(z, z, ny);
			ecdsap256_public_sub64(tmp, t2, x);
			ecdsap256_public_mul64(tmp, t1, tmp);
			ecdsap256_public_add64(tmp, tmp, tmp);
			ecdsap256_public_sub64(ny, tmp, ny4);
			--remaining;

			if (remaining != 0U)
			{
				ecdsap256_public_mul64(w, w, ny4);
			}
		}

		/* The grouped formula maintains ny=2Y; halve modulo p. */
		ecdsap256_public_half64(output->y, ny);
		ecdsap256_native_copy(output->x, x);
		ecdsap256_native_copy(output->z, z);
	}
}

static void ecdsap256_verify_native_add_mixed(ecdsap256_native_point* output, const ecdsap256_native_point* first, const ecdsap256_native_point* second, ecdsap256_native_window_workspace* work)
{
	/* add a public affine point using native mixed addition with exceptional cases */
	uint64_t same;
	uint64_t inverse;
	uint64_t finf;
	uint64_t sinf;
	ecdsap256_native_point original;

	original = *first;
	finf = ecdsap256_native_is_zero(original.z);
	sinf = ecdsap256_native_is_zero(second->z);
	ecdsap256_verify_public_add_generator(output, first, second, work);
	same = ecdsap256_native_is_zero(work->h) & ecdsap256_native_is_zero(work->delta);
	inverse = ecdsap256_native_is_zero(work->h) & (same ^ 1U);

	if ((finf == 0U) && (sinf == 0U))
	{
		if (same != 0U)
		{
			ecdsap256_verify_native_double_n(output, &original, 1U);
		}
		else if (inverse != 0U)
		{
			qsc_memutils_clear(output, sizeof(*output));
			ecdsap256_native_copy(output->y, ECDSAP256_NATIVE_ONE);
		}
	}
}

static void ecdsap256_verify_native_add_projective(ecdsap256_native_point* output, const ecdsap256_native_point* first, const ecdsap256_native_point* second)
{
	/* compute u1*G+u2*Q with persistent 4x64 native Montgomery points */
	ecdsap256_native_fe z1z1 = { 0U };
	ecdsap256_native_fe z2z2 = { 0U };
	ecdsap256_native_fe u1 = { 0U };
	ecdsap256_native_fe u2 = { 0U };
	ecdsap256_native_fe s1 = { 0U };
	ecdsap256_native_fe s2 = { 0U };
	ecdsap256_native_fe h = { 0U };
	ecdsap256_native_fe r = { 0U };
	ecdsap256_native_fe t = { 0U };
	ecdsap256_native_fe i = { 0U };
	ecdsap256_native_fe j = { 0U };
	ecdsap256_native_fe v = { 0U };
	ecdsap256_native_point result;

	ecdsap256_public_square64(z1z1, first->z);
	ecdsap256_public_square64(z2z2, second->z);
	ecdsap256_public_mul64(u1, first->x, z2z2);
	ecdsap256_public_mul64(u2, second->x, z1z1);
	ecdsap256_public_mul64(s1, first->y, second->z);
	ecdsap256_public_mul64(s1, s1, z2z2);
	ecdsap256_public_mul64(s2, second->y, first->z);
	ecdsap256_public_mul64(s2, s2, z1z1);
	ecdsap256_public_sub64(h, u2, u1);
	ecdsap256_public_sub64(r, s2, s1);
	ecdsap256_public_add64(r, r, r);
	ecdsap256_public_add64(t, h, h);
	ecdsap256_public_square64(i, t);
	ecdsap256_public_mul64(j, h, i);
	ecdsap256_public_mul64(v, u1, i);
	ecdsap256_public_mul64(result.x, r, r);
	ecdsap256_public_sub64(result.x, result.x, j);
	ecdsap256_public_add64(t, v, v);
	ecdsap256_public_sub64(result.x, result.x, t);
	ecdsap256_public_sub64(t, v, result.x);
	ecdsap256_public_mul64(result.y, r, t);
	ecdsap256_public_mul64(t, s1, j);
	ecdsap256_public_add64(t, t, t);
	ecdsap256_public_sub64(result.y, result.y, t);
	ecdsap256_public_add64(t, first->z, second->z);
	ecdsap256_public_square64(t, t);
	ecdsap256_public_sub64(t, t, z1z1);
	ecdsap256_public_sub64(t, t, z2z2);
	ecdsap256_public_mul64(result.z, t, h);
	*output = result;
}

static void ecdsap256_verify_native_add_generator(ecdsap256_native_point* accumulator, const uint32_t first[8U])
{
	ecdsap256_native_point selected;
	ecdsap256_native_window_workspace work = { 0 };
	ecdsap256_native_fe zero = { 0U };
	uint32_t scalar[10U] = { 0U };
	uint32_t magnitude;
	uint32_t sign;
	size_t i;

	for (i = 0U; i < 8U; ++i)
	{
		scalar[i] = first[i];
	}

	for (i = 0U; i < 43U; ++i)
	{
		magnitude = ecdsap256_booth_digit(scalar, i, &sign);

		if (magnitude != 0U)
		{
			ecdsap256_native_load(selected.x, ECDSAP256_GENERATOR_TABLE[i][magnitude - 1U][0U]);
			ecdsap256_native_load(selected.y, ECDSAP256_GENERATOR_TABLE[i][magnitude - 1U][1U]);
			ecdsap256_native_copy(selected.z, ECDSAP256_NATIVE_ONE);

			if (sign != 0U)
			{
				ecdsap256_public_sub64(selected.y, zero, selected.y);
			}

			ecdsap256_verify_native_add_mixed(accumulator, accumulator, &selected, &work);
		}
	}
}

static void ecdsap256_verify_native_joint(ecdsap256_jac_t* output, const ecdsap256_aff_t* public_point, const uint32_t first[8U], const uint32_t second[8U], const qsc_ecdsap256_verify_context* context)
{
	ecdsap256_aff_t encoded = {{ 0U }, { 0U }};
	ecdsap256_native_point twice_q;
	ecdsap256_native_point qpoint;
	ecdsap256_native_fe zero = { 0U };
	ecdsap256_native_point qnative[8U];
	ecdsap256_native_point accumulator;
	ecdsap256_native_point selected;
	ecdsap256_native_window_workspace work;
	int8_t qd[257U];
	int32_t q;
	size_t i;
	size_t pending;

	qsc_memutils_clear(&accumulator, sizeof(accumulator));
	qsc_memutils_clear(&work, sizeof(work));
	ecdsap256_native_copy(accumulator.y, ECDSAP256_NATIVE_ONE);

	if (context == NULL)
	{
		ecdsap256_field_mont_encode(encoded.X, public_point->X);
		ecdsap256_field_mont_encode(encoded.Y, public_point->Y);
		ecdsap256_native_load(qpoint.x, encoded.X);
		ecdsap256_native_load(qpoint.y, encoded.Y);
		ecdsap256_native_copy(qpoint.z, ECDSAP256_NATIVE_ONE);
		qnative[0U] = qpoint;
		ecdsap256_verify_native_double_n(&twice_q, &qpoint, 1U);

		for (i = 1U; i < 8U; ++i)
		{
			ecdsap256_verify_native_add_projective(&qnative[i], &qnative[i - 1U], &twice_q);
		}
	}
	else
	{
		for (i = 0U; i < 8U; ++i)
		{
			ecdsap256_native_load(qnative[i].x, context->odd_montgomery[i][0U]);
			ecdsap256_native_load(qnative[i].y, context->odd_montgomery[i][1U]);
			ecdsap256_native_copy(qnative[i].z, ECDSAP256_NATIVE_ONE);
		}
	}

	if (context == NULL)
	{
		ecdsap256_verify_native_batch(qnative);
	}

	ecdsap256_recode_public(qd, second);
	pending = 0U;

	for (i = 257U; i > 0U; --i)
	{
		++pending;
		q = (int32_t)qd[i - 1U];

		if (q != 0)
		{
			if (ecdsap256_native_is_zero(accumulator.z) == 0U)
			{
				ecdsap256_verify_native_double_n(&accumulator, &accumulator, pending);
			}

			pending = 0U;
		}

		if (q != 0)
		{
			selected = qnative[((uint32_t)((q < 0) ? -q : q) - 1U) / 2U];

			if (q < 0)
			{
				ecdsap256_public_sub64(selected.y, zero, selected.y);
			}

			ecdsap256_verify_native_add_mixed(&accumulator, &accumulator, &selected, &work);
		}
	}

	if ((pending > 0U) && (ecdsap256_native_is_zero(accumulator.z) == 0U))
	{
		ecdsap256_verify_native_double_n(&accumulator, &accumulator, pending);
	}

	ecdsap256_verify_native_add_generator(&accumulator, first);

	ecdsap256_native_store(output->X, accumulator.x);
	ecdsap256_native_store(output->Y, accumulator.y);
	ecdsap256_native_store(output->Z, accumulator.z);
	qsc_memutils_secure_erase(&encoded, sizeof(encoded));
	qsc_memutils_secure_erase(&twice_q, sizeof(twice_q));
	qsc_memutils_secure_erase(&qpoint, sizeof(qpoint));
	qsc_memutils_secure_erase(zero, sizeof(zero));
	qsc_memutils_secure_erase(qnative, sizeof(qnative));
	qsc_memutils_secure_erase(&accumulator, sizeof(accumulator));
	qsc_memutils_secure_erase(&selected, sizeof(selected));
	qsc_memutils_secure_erase(&work, sizeof(work));
	qsc_memutils_secure_erase(qd, sizeof(qd));
}
#endif

#if defined(ECDSAP256_NATIVE_64) && !defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)

static void ecdsap256_verify_native_batch_variable(ecdsap256_native_point* points, size_t count)
{
	/* batch-convert public Jacobian points to Montgomery affine form */
	ecdsap256_native_fe prefix[256U];
	ecdsap256_native_fe inverse = { 0U };
	ecdsap256_native_fe inverse_squared = { 0U };
	ecdsap256_native_fe zinv = { 0U };
	ecdsap256_native_fe z2 = { 0U };
	ecdsap256_native_fe z3 = { 0U };
	size_t i;

	ecdsap256_native_copy(prefix[0U], ECDSAP256_NATIVE_ONE);

	for (i = 0U; i < count; ++i)
	{
		if (i != 0U)
		{
			ecdsap256_native_copy(prefix[i], prefix[i - 1U]);
		}

		if (ecdsap256_native_is_zero(points[i].z) == 0U)
		{
			ecdsap256_public_mul64(prefix[i], prefix[i], points[i].z);
		}
	}

	if (count != 0U)
	{
		ecdsap256_verify_inverse_square(inverse_squared, prefix[count - 1U]);
		ecdsap256_public_mul64(inverse, inverse_squared, prefix[count - 1U]);

		for (i = count; i > 0U; --i)
		{
			if (ecdsap256_native_is_zero(points[i - 1U].z) == 0U)
			{
				if (i == 1U)
				{
					ecdsap256_native_copy(zinv, inverse);
				}
				else
				{
					ecdsap256_public_mul64(zinv, inverse, prefix[i - 2U]);
				}

				ecdsap256_public_mul64(inverse, inverse, points[i - 1U].z);
				ecdsap256_public_square64(z2, zinv);
				ecdsap256_public_mul64(z3, z2, zinv);
				ecdsap256_public_mul64(points[i - 1U].x, points[i - 1U].x, z2);
				ecdsap256_public_mul64(points[i - 1U].y, points[i - 1U].y, z3);
				ecdsap256_native_copy(points[i - 1U].z, ECDSAP256_NATIVE_ONE);
			}
		}
	}

	qsc_memutils_secure_erase(prefix, sizeof(prefix));
	qsc_memutils_secure_erase(inverse, sizeof(inverse));
	qsc_memutils_secure_erase(inverse_squared, sizeof(inverse_squared));
	qsc_memutils_secure_erase(zinv, sizeof(zinv));
	qsc_memutils_secure_erase(z2, sizeof(z2));
	qsc_memutils_secure_erase(z3, sizeof(z3));
}

static void ecdsap256_verify_native_joint_prepare(qsc_ecdsap256_joint_verify_context* context)
{
	/* compute a validated-key joint affine table once per context */
	ecdsap256_native_point multiples_g[16U];
	ecdsap256_native_point multiples_q[16U];
	ecdsap256_native_point combined[256U];
	ecdsap256_native_window_workspace work;
	size_t i;
	size_t j;
	size_t k;

	qsc_memutils_clear(multiples_g, sizeof(multiples_g));
	qsc_memutils_clear(multiples_q, sizeof(multiples_q));
	qsc_memutils_clear(combined, sizeof(combined));
	qsc_memutils_clear(&work, sizeof(work));
	ecdsap256_native_copy(multiples_g[0U].y, ECDSAP256_NATIVE_ONE);
	ecdsap256_native_copy(multiples_q[0U].y, ECDSAP256_NATIVE_ONE);

	for (i = 1U; i < 16U; ++i)
	{
		ecdsap256_native_load(multiples_g[i].x, ECDSAP256_GENERATOR_MONT[i][0U]);
		ecdsap256_native_load(multiples_g[i].y, ECDSAP256_GENERATOR_MONT[i][1U]);
		ecdsap256_native_copy(multiples_g[i].z, ECDSAP256_NATIVE_ONE);
	}

	ecdsap256_native_load(multiples_q[1U].x, context->base.odd_montgomery[0U][0U]);
	ecdsap256_native_load(multiples_q[1U].y, context->base.odd_montgomery[0U][1U]);
	ecdsap256_native_copy(multiples_q[1U].z, ECDSAP256_NATIVE_ONE);

	for (i = 2U; i < 16U; ++i)
	{
		ecdsap256_verify_native_add_mixed(&multiples_q[i], &multiples_q[i - 1U], &multiples_q[1U], &work);
	}

	ecdsap256_verify_native_batch_variable(multiples_q, 16U);

	for (i = 0U; i < 16U; ++i)
	{
		for (j = 0U; j < 16U; ++j)
		{
			k = (i << 4U) | j;

			if (i == 0U)
			{
				combined[k] = multiples_q[j];
			}
			else if (j == 0U)
			{
				combined[k] = multiples_g[i];
			}
			else
			{
				ecdsap256_verify_native_add_mixed(&combined[k], &multiples_g[i], &multiples_q[j], &work);
			}
		}
	}

	ecdsap256_verify_native_batch_variable(combined, 256U);

	for (k = 0U; k < 256U; ++k)
	{
		context->joint_infinity[k] = (uint8_t)ecdsap256_native_is_zero(combined[k].z);
		ecdsap256_native_copy(context->joint_montgomery[k][0U], combined[k].x);
		ecdsap256_native_copy(context->joint_montgomery[k][1U], combined[k].y);
	}

	qsc_memutils_secure_erase(multiples_g, sizeof(multiples_g));
	qsc_memutils_secure_erase(multiples_q, sizeof(multiples_q));
	qsc_memutils_secure_erase(combined, sizeof(combined));
	qsc_memutils_secure_erase(&work, sizeof(work));
}

static void ecdsap256_verify_native_joint_window(ecdsap256_jac_t* output, const uint32_t first[8U], const uint32_t second[8U], const qsc_ecdsap256_joint_verify_context* context)
{
	/* verify a public double scalar using a cached radix-16 joint table */
	ecdsap256_native_point accumulator;
	ecdsap256_native_point selected;
	ecdsap256_native_window_workspace work;
	size_t i;
	size_t word;
	uint32_t shift;
	uint32_t dgig;
	uint32_t dgiq;
	size_t index;

	qsc_memutils_clear(&accumulator, sizeof(accumulator));
	qsc_memutils_clear(&work, sizeof(work));
	ecdsap256_native_copy(accumulator.y, ECDSAP256_NATIVE_ONE);

	for (i = 64U; i > 0U; --i)
	{
		word = (i - 1U) / 8U;
		shift = (uint32_t)(((i - 1U) % 8U) * 4U);
		dgig = (first[word] >> shift) & 15U;
		dgiq = (second[word] >> shift) & 15U;
		index = (size_t)((dgig << 4U) | dgiq);

		if (ecdsap256_native_is_zero(accumulator.z) == 0U)
		{
			ecdsap256_verify_native_double_n(&accumulator, &accumulator, 4U);
		}

		if ((index != 0U) && (context->joint_infinity[index] == 0U))
		{
			ecdsap256_native_copy(selected.x, context->joint_montgomery[index][0U]);
			ecdsap256_native_copy(selected.y, context->joint_montgomery[index][1U]);
			ecdsap256_native_copy(selected.z, ECDSAP256_NATIVE_ONE);

			if (ecdsap256_native_is_zero(accumulator.z) != 0U)
			{
				accumulator = selected;
			}
			else
			{
				ecdsap256_verify_native_add_mixed(&accumulator, &accumulator, &selected, &work);
			}
		}
	}

	ecdsap256_native_store(output->X, accumulator.x);
	ecdsap256_native_store(output->Y, accumulator.y);
	ecdsap256_native_store(output->Z, accumulator.z);
	qsc_memutils_secure_erase(&accumulator, sizeof(accumulator));
	qsc_memutils_secure_erase(&selected, sizeof(selected));
	qsc_memutils_secure_erase(&work, sizeof(work));
}
#endif /* native public joint-window engine */

static void ecdsap256_double_scalar_mult(ecdsap256_jac_t* output, const ecdsap256_aff_t* public_point, const uint32_t first[8U], const uint32_t second[8U], const qsc_ecdsap256_verify_context* context)
{
#if defined(ECDSAP256_NATIVE_64)
	ecdsap256_verify_native_joint(output, public_point, first, second, context);
#else
	(void)context;
	ecdsap256_joint_public_wnaf(output, public_point, first, second);
#endif
}
#endif

#if !defined(ECDSAP256_NATIVE_64)

static void ecdsap256_fe_square_n(ecdsap256_field value, size_t count)
{
	/* apply a public, fixed number of P-256 field squarings */
	size_t i;

	for (i = 0U; i < count; ++i)
	{
		ecdsap256_fe_sqr(value, value);
	}
}
#endif

#if !defined(ECDSAP256_NATIVE_64)

static void ecdsap256_fe_inv_squared(ecdsap256_field r, const ecdsap256_field a)
{
	/* compute Z^-2 over the P-256 field using addition chain */
	ecdsap256_field t[2U] = {{ 0U }};
	ecdsap256_field z = { 0U };

	ecdsap256_fe_mul(z, a, a);
	ecdsap256_fe_mul(z, z, a);
	ecdsap256_fe_mul(z, z, z);
	ecdsap256_fe_mul(z, z, a);
	ecdsap256_field_copy(t[0U], z);
	ecdsap256_fe_square_n(t[0U], 3U);
	ecdsap256_fe_mul(t[0U], t[0U], z);
	ecdsap256_field_copy(t[1U], t[0U]);
	ecdsap256_fe_square_n(t[1U], 6U);
	ecdsap256_fe_mul(t[0U], t[0U], t[1U]);
	ecdsap256_fe_square_n(t[0U], 3U);
	ecdsap256_fe_mul(z, z, t[0U]);
	ecdsap256_fe_mul(t[0U], z, z);
	ecdsap256_fe_mul(t[0U], t[0U], a);
	ecdsap256_field_copy(t[1U], t[0U]);
	ecdsap256_fe_square_n(t[1U], 16U);
	ecdsap256_fe_mul(t[0U], t[0U], t[1U]);
	ecdsap256_fe_square_n(t[0U], 15U);
	ecdsap256_fe_mul(z, z, t[0U]);
	ecdsap256_fe_square_n(t[0U], 17U);
	ecdsap256_fe_mul(t[0U], t[0U], a);
	ecdsap256_fe_square_n(t[0U], 143U);
	ecdsap256_fe_mul(t[0U], t[0U], z);
	ecdsap256_fe_square_n(t[0U], 47U);
	ecdsap256_fe_mul(z, z, t[0U]);
	ecdsap256_fe_square_n(z, 2U);

	ecdsap256_field_copy(r, z);
	qsc_memutils_secure_erase(t, sizeof(t));
	qsc_memutils_secure_erase(z, sizeof(z));
}
#endif

static void ecdsap256_jac_x_to_aff(ecdsap256_field output, const ecdsap256_jac_t* point)
{
	/* recover only the affine X coordinate for an ECDSA generator multiple */
#if defined(ECDSAP256_NATIVE_64)
	ecdsap256_native_affine_x(output, point);
#else
	ecdsap256_field zinvsquared = { 0U };

	ecdsap256_fe_inv_squared(zinvsquared, point->Z);
	ecdsap256_fe_mul(output, point->X, zinvsquared);
	ecdsap256_field_mont_decode(output, output);
	qsc_memutils_secure_erase(zinvsquared, sizeof(zinvsquared));
#endif
}

static bool ecdsap256_jac_to_aff(ecdsap256_aff_t* R, const ecdsap256_jac_t* P)
{
	/* convert Jacobian to affine: (X:Y:Z) -> (X/Z^2, Y/Z^3) */
	ecdsap256_field zinv, zinv2, zinv3;

	if (ecdsap256_is_infinity(P))
	{
		return false;
	}

	ecdsap256_fe_inv(zinv, P->Z);
	ecdsap256_fe_sqr(zinv2, zinv);
	ecdsap256_fe_mul(zinv3, zinv2, zinv);

	ecdsap256_fe_mul(R->X, P->X, zinv2);
	ecdsap256_fe_mul(R->Y, P->Y, zinv3);

	ecdsap256_field_mont_decode(R->X, R->X);
	ecdsap256_field_mont_decode(R->Y, R->Y);

	return true;
}

static bool ecdsap256_point_is_on_curve(const ecdsap256_aff_t* Q)
{
	/* verify that a public key point lies on the curve.
     * checks the Weierstrass equation:  Y^2 = X^3 - 3X + b  (mod p)
     * and that the point is not the identity. */
	ecdsap256_field y2, x3, ax, rhs;
	ecdsap256_field xmont;
	ecdsap256_field ymont;
	ecdsap256_field bmont;

	ecdsap256_field_mont_encode(xmont, Q->X);
	ecdsap256_field_mont_encode(ymont, Q->Y);
	ecdsap256_field_mont_encode(bmont, ECDSAP256_B);

	/* y^2 mod p */
	ecdsap256_fe_sqr(y2, ymont);

	/* x^3 mod p */
	ecdsap256_fe_sqr(x3, xmont);
	ecdsap256_fe_mul(x3, x3, xmont);

	/* -3*x mod p (a = -3) */
	ecdsap256_fe_mul_small(ax, xmont, 3U);
	ecdsap256_fe_sub(rhs, x3, ax);

	/* rhs = x^3 - 3x + b */
	ecdsap256_fe_add(rhs, rhs, bmont);

	return (ecdsap256_field_cmp(y2, rhs) == 0);
}

/* RFC 6979 deterministic k generation */

static void ecdsap256_rfc6979_bits2octets_p256(uint8_t out[32U], const uint8_t hash_be[32U])
{
	uint32_t z[8U] = { 0U };

	QSC_ASSERT(out != NULL);
	QSC_ASSERT(hash_be != NULL);

	/*
     * RFC 6979 bits2octets(h1):
     *   z1 = bits2int(h1)
     *   z2 = z1 mod q
     *   return int2octets(z2)
     *
     * for P-256 with SHA-256, h1 is already 256 bits, so bits2int()
     * is simply the 32-byte big-endian integer represented by hash_be.
     */
	ecdsap256_sc_from_bytes_reduce(z, hash_be);
	ecdsap256_field_to_bytes(out, z);

	qsc_memutils_secure_erase(z, sizeof(z));
}

static void ecdsap256_rfc6979_generate_k(uint32_t k_out[8U], const uint8_t priv_be[32U], const uint8_t h1_be[32U])
{
	/* Generate a deterministic nonce k in [1, n-1] from privkey and message hash,
     * per RFC 6979 Section 3.2 using HMAC-SHA256.
     *
     * RFC 6979 requires bits2octets(h1), not raw h1, in the HMAC input. */

	size_t i;

	QSC_ASSERT(k_out != NULL);
	QSC_ASSERT(priv_be != NULL);
	QSC_ASSERT(h1_be != NULL);

	uint8_t V[32U] = { 0U };
	uint8_t K[32U] = { 0U };
	uint8_t bh[32U] = { 0U };
	uint8_t blob[65U] = { 0U };
	uint8_t T[32U] = { 0U };
	uint8_t msg[97U] = { 0U };
	uint8_t mac[32U] = { 0U };

	ecdsap256_rfc6979_bits2octets_p256(bh, h1_be);

	/* V = 0x01 repeated 32 times */
	for (i = 0U; i < 32U; ++i)
	{
		V[i] = 0x01U;
	}

	/* K = 0x00 repeated 32 times */
	for (i = 0U; i < 32U; ++i)
	{
		K[i] = 0x00U;
	}

	/* K = HMAC(K, V || 0x00 || int2octets(x) || bits2octets(h1)) */
	blob[0U] = 0x00U;
	qsc_memutils_copy((blob + 1U), priv_be, 32U);
	qsc_memutils_copy((blob + 33U), bh, 32U);

	qsc_memutils_copy(msg, V, 32U);
	qsc_memutils_copy((msg + 32U), blob, 65U);
	qsc_hmac256_compute(mac, msg, sizeof(msg), K, sizeof(K));
	qsc_memutils_copy(K, mac, 32U);

	/* V = HMAC(K, V) */
	qsc_hmac256_compute(mac, V, sizeof(V), K, sizeof(K));
	qsc_memutils_copy(V, mac, 32U);

	/* K = HMAC(K, V || 0x01 || int2octets(x) || bits2octets(h1)) */
	blob[0U] = 0x01U;

	qsc_memutils_copy(msg, V, 32U);
	qsc_memutils_copy((msg + 32U), blob, 65U);
	qsc_hmac256_compute(mac, msg, sizeof(msg), K, sizeof(K));
	qsc_memutils_copy(K, mac, 32U);

	/* V = HMAC(K, V) */
	qsc_hmac256_compute(mac, V, sizeof(V), K, sizeof(K));
	qsc_memutils_copy(V, mac, 32U);

	/* generate candidate k values until one is in [1, n-1] */
	for (;;)
	{
		qsc_hmac256_compute(T, V, sizeof(V), K, sizeof(K));
		qsc_memutils_copy(V, T, 32U);

		ecdsap256_field_from_bytes(k_out, T);

		if ((ecdsap256_field_is_zero(k_out) == false) && (ecdsap256_field_cmp(k_out, ECDSAP256_N) < 0))
		{
			break;
		}

		qsc_memutils_copy(msg, V, sizeof(V));
		msg[sizeof(V)] = 0U;
		qsc_hmac256_compute(mac, msg, sizeof(V) + 1U, K, sizeof(K));
		qsc_memutils_copy(K, mac, 32U);

		qsc_hmac256_compute(mac, V, sizeof(V), K, sizeof(K));
		qsc_memutils_copy(V, mac, 32U);
	}

	qsc_memutils_secure_erase(V, sizeof(V));
	qsc_memutils_secure_erase(K, sizeof(K));
	qsc_memutils_secure_erase(bh, sizeof(bh));
	qsc_memutils_secure_erase(blob, sizeof(blob));
	qsc_memutils_secure_erase(T, sizeof(T));
	qsc_memutils_secure_erase(msg, sizeof(msg));
	qsc_memutils_secure_erase(mac, sizeof(mac));
}

static void ecdsap256_sc_from_bytes(uint32_t r[8U], const uint8_t s[32U])
{
	int32_t i;
	int32_t j;

	for (i = 0, j = 28; i < 8; ++i, j -= 4)
	{
		r[i] = ((uint32_t)s[j] << 24) | ((uint32_t)s[j + 1U] << 16) | ((uint32_t)s[j + 2U] << 8) | ((uint32_t)s[j + 3U]);
	}
}

/* Public API */

int32_t qsc_ecdsap256_publickey_from_privatekey(uint8_t* publickey, const uint8_t* privatekey)
{
	ecdsap256_aff_t G;
	ecdsap256_aff_t Q;
	ecdsap256_jac_t R;
	uint32_t d[8U] = { 0U };
	int32_t ret;

	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(privatekey != NULL);

	ret = -1;

	/* decode the raw 32-byte scalar */
	ecdsap256_sc_from_bytes(d, privatekey);

	/* reject zero */
	if (ecdsap256_field_is_zero(d) != 0U)
	{
		ret = -2;
	}

	/* reject d >= n */
	else if (ecdsap256_field_cmp(d, ECDSAP256_N) >= 0)
	{
		ret = -3;
	}
	else
	{
		/* initialize the P-256 base point */
		ecdsap256_field_copy(G.X, ECDSAP256_GX);
		ecdsap256_field_copy(G.Y, ECDSAP256_GY);

		/* compute R = dG */
		ecdsap256_scalar_mult(&R, &G, d, true);

		/* reject infinity */
		if (ecdsap256_is_infinity(&R) != 0U)
		{
			ret = -4;
		}

		/* convert to affine */
		else if (ecdsap256_jac_to_aff(&Q, &R) != true)
		{
			ret = -5;
		}
		else
		{
			/* serialize public key as Qx || Qy */
			ecdsap256_field_to_bytes(publickey, Q.X);
			ecdsap256_field_to_bytes(publickey + 32U, Q.Y);
			ret = 0;
		}
	}

	qsc_memutils_secure_erase(d, sizeof(d));
	qsc_memutils_secure_erase(&R, sizeof(R));
	qsc_memutils_secure_erase(&Q, sizeof(Q));
	qsc_memutils_secure_erase(&G, sizeof(G));

	return ret;
}

int32_t qsc_ecdsap256_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed)
{
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(privatekey != NULL);
	QSC_ASSERT(seed != NULL);

	uint8_t hash[32U] = { 0U };
	uint32_t d[8U] = { 0U };
	ecdsap256_aff_t Q;
	ecdsap256_jac_t Q_jac;
	ecdsap256_aff_t G_init;
	int32_t ret;

	ret = -1;

	/* clear outputs on entry */
	qsc_memutils_clear(publickey, EC_NISTP256_PUBLICKEY_SIZE);
	qsc_memutils_clear(privatekey, EC_NISTP256_PRIVATEKEY_SIZE);

	/* derive private scalar: d = SHA-256(seed) mod n */
	qsc_sha256_compute(hash, seed, EC_NISTP256_SEED_SIZE);
	ecdsap256_sc_from_bytes_reduce(d, hash);

	/* reject d == 0 instead of silently substituting d = 1 */
	if (ecdsap256_field_is_zero(d))
	{
		ret = -2;
	}
	else
	{
		/* Q = d * G */
		ecdsap256_field_copy((uint32_t*)G_init.X, ECDSAP256_GX);
		ecdsap256_field_copy((uint32_t*)G_init.Y, ECDSAP256_GY);

		ecdsap256_scalar_mult(&Q_jac, &G_init, d, true);

		if (ecdsap256_jac_to_aff(&Q, &Q_jac) != true)
		{
			ret = -3;
		}
		else
		{
			/* public key: Qx || Qy (big-endian, 32 bytes each) */
			ecdsap256_field_to_bytes(publickey, Q.X);
			ecdsap256_field_to_bytes(publickey + 32U, Q.Y);

			/* private key: seed[32] || pubkey[64] */
			qsc_memutils_copy(privatekey, seed, EC_NISTP256_SEED_SIZE);
			qsc_memutils_copy(privatekey + 32U, publickey, EC_NISTP256_PUBLICKEY_SIZE);

			ret = 0;
		}
	}

	qsc_memutils_secure_erase(hash, sizeof(hash));
	qsc_memutils_secure_erase(d, sizeof(d));
	qsc_memutils_secure_erase(&Q, sizeof(Q));
	qsc_memutils_secure_erase(&Q_jac, sizeof(Q_jac));
	qsc_memutils_secure_erase(&G_init, sizeof(G_init));

	return ret;
}

bool qsc_ecdsap256_privatekey_validate(const uint8_t* privatekey)
{
	QSC_ASSERT(privatekey != NULL);

	uint8_t publickey[EC_NISTP256_PUBLICKEY_SIZE] = { 0U };
	uint8_t reconstructed[EC_NISTP256_PRIVATEKEY_SIZE] = { 0U };
	bool result;

	result = false;

	if (qsc_ecdsap256_keypair(publickey, reconstructed, privatekey) == 0)
	{
		result = qsc_memutils_are_equal(publickey, privatekey + EC_NISTP256_SEED_SIZE, EC_NISTP256_PUBLICKEY_SIZE);
	}

	qsc_memutils_secure_erase(publickey, sizeof(publickey));
	qsc_memutils_secure_erase(reconstructed, sizeof(reconstructed));

	return result;
}

static bool ecdsap256_sign_scalar_blinded(uint32_t output[8U], const uint32_t nonce[8U], const uint32_t private_scalar[8U], const uint32_t signature_r[8U], const uint32_t message_scalar[8U])
{
	/* calculate a blinded ECDSA P-256 signature scalar */
#if defined(ECDSAP256_NATIVE_64)
	return ecdsap256_native_sign_scalar(output, nonce, private_scalar, signature_r, message_scalar);
#else

	uint8_t rmsk[32U] = { 0U };
	uint32_t mask[8U] = { 0U };
	uint32_t mskm[8U] = { 0U };
	uint32_t nncm[8U] = { 0U };
	uint32_t pvmn[8U] = { 0U };
	uint32_t dgmt[8U] = { 0U };
	uint32_t rmnt[8U] = { 0U };
	uint32_t invm[8U] = { 0U };
	uint32_t smnt[8U] = { 0U };
	uint32_t rsmt[8U] = { 0U };
	bool result;

	result = qsc_csp_generate(rmsk, sizeof(rmsk));

	if (result)
	{
		ecdsap256_sc_from_bytes_reduce(mask, rmsk);
		mask[0U] |= ecdsap256_field_is_zero(mask);

		ecdsap256_sc_mont_encode(mskm, mask);
		ecdsap256_sc_mont_encode(nncm, nonce);
		ecdsap256_sc_mont_encode(pvmn, private_scalar);
		ecdsap256_sc_mont_encode(dgmt, message_scalar);
		ecdsap256_sc_mont_encode(rmnt, signature_r);

		ecdsap256_sc_mont_mul(nncm, nncm, mskm);
		ecdsap256_sc_inv_mont(invm, nncm);
		ecdsap256_sc_mont_mul(pvmn, pvmn, mskm);
		ecdsap256_sc_mont_mul(pvmn, pvmn, rmnt);
		ecdsap256_sc_mont_mul(dgmt, dgmt, mskm);
		ecdsap256_sc_add(smnt, pvmn, dgmt);
		ecdsap256_sc_mont_mul(rsmt, invm, smnt);
		ecdsap256_sc_mont_decode(output, rsmt);
	}

	qsc_memutils_secure_erase(rmsk, sizeof(rmsk));
	qsc_memutils_secure_erase(mask, sizeof(mask));
	qsc_memutils_secure_erase(mskm, sizeof(mskm));
	qsc_memutils_secure_erase(nncm, sizeof(nncm));
	qsc_memutils_secure_erase(pvmn, sizeof(pvmn));
	qsc_memutils_secure_erase(dgmt, sizeof(dgmt));
	qsc_memutils_secure_erase(rmnt, sizeof(rmnt));
	qsc_memutils_secure_erase(invm, sizeof(invm));
	qsc_memutils_secure_erase(smnt, sizeof(smnt));
	qsc_memutils_secure_erase(rsmt, sizeof(rsmt));

	return result;
#endif
}

int32_t qsc_ecdsap256_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey)
{
	uint8_t hash[32U] = { 0U };
	uint8_t dbe[32U] = { 0U };
	uint8_t dhash[32U] = { 0U };
	uint32_t d[8U] = { 0U };
	uint32_t k[8U] = { 0U };
	uint32_t r[8U] = { 0U };
	uint32_t s[8U] = { 0U };
	uint32_t e[8U] = { 0U };
	ecdsap256_aff_t kG;
	ecdsap256_jac_t kG_jac;
	ecdsap256_aff_t G;
	int32_t res;

	QSC_ASSERT(signedmsg != NULL);
	QSC_ASSERT(smsglen != NULL);
	QSC_ASSERT(message != NULL);
	QSC_ASSERT(privatekey != NULL);

	res = -1;

	if (msglen <= (SIZE_MAX - EC_NISTP256_SIGNATURE_SIZE))
	{
		/* hash the message with SHA-256 */
		qsc_sha256_compute(hash, message, msglen);

		/* derive private scalar by hashing the private key and reducing */
		qsc_sha256_compute(dhash, privatekey, EC_NISTP256_SEED_SIZE);
		ecdsap256_sc_from_bytes_reduce(d, dhash);

		if (ecdsap256_field_is_zero(d))
		{
			res = -2;
		}
		else if (ecdsap256_field_cmp(d, ECDSAP256_N) < 0)
		{
			/* load message hash as scalar e */
			ecdsap256_sc_from_bytes_reduce(e, hash);

			/* reconstruct the private scalar bytes in big-endian for RFC 6979 */
			ecdsap256_field_to_bytes(dbe, d);

			/* generate deterministic k using RFC 6979 */
			ecdsap256_rfc6979_generate_k(k, dbe, hash);

			/* R = k * G */
			ecdsap256_field_copy((uint32_t*)G.X, ECDSAP256_GX);
			ecdsap256_field_copy((uint32_t*)G.Y, ECDSAP256_GY);

			ecdsap256_scalar_mult(&kG_jac, &G, k, true);
			ecdsap256_jac_x_to_aff(kG.X, &kG_jac);

			/* r = kG.x mod n */
			ecdsap256_field_copy(r, kG.X);
			ecdsap256_field_cond_sub(r, ECDSAP256_N);

			if (!ecdsap256_field_is_zero(r))
			{
				/* independent scalar blinding; fail closed on RNG error. */
				if (!ecdsap256_sign_scalar_blinded(s, k, d, r, e))
				{
					res = -3;
				}
				else if (!ecdsap256_field_is_zero(s))
				{
					ecdsap256_field_to_bytes(signedmsg, r);
					ecdsap256_field_to_bytes(signedmsg + 32U, s);
					qsc_memutils_copy(signedmsg + EC_NISTP256_SIGNATURE_SIZE, message, msglen);
					*smsglen = EC_NISTP256_SIGNATURE_SIZE + msglen;
					res = 0;
				}
			}
		}
	}

	qsc_memutils_secure_erase(hash, sizeof(hash));
	qsc_memutils_secure_erase(dhash, sizeof(dhash));
	qsc_memutils_secure_erase(dbe, sizeof(dbe));
	qsc_memutils_secure_erase(d, sizeof(d));
	qsc_memutils_secure_erase(k, sizeof(k));
	qsc_memutils_secure_erase(r, sizeof(r));
	qsc_memutils_secure_erase(s, sizeof(s));
	qsc_memutils_secure_erase(e, sizeof(e));
	qsc_memutils_secure_erase(&kG, sizeof(kG));
	qsc_memutils_secure_erase(&kG_jac, sizeof(kG_jac));
	qsc_memutils_secure_erase(&G, sizeof(G));

	if (res != 0)
	{
		/* The caller must supply a nonoverlapping msglen + 64-byte output.
		 * Exclude wrapped sizes from the failure-buffer clearing operation.
		 */
		if (msglen <= (SIZE_MAX - EC_NISTP256_SIGNATURE_SIZE))
		{
			qsc_memutils_clear(signedmsg, EC_NISTP256_SIGNATURE_SIZE + msglen);
		}

		*smsglen = 0U;
	}

	return res;
}

int32_t qsc_ecdsap256_sign_scalar(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey)
{
	uint8_t hash[32U] = { 0U };
	uint8_t dbe[32U] = { 0U };
	uint8_t dhash[32U] = { 0U };
	uint32_t d[8U] = { 0U };
	uint32_t k[8U] = { 0U };
	uint32_t r[8U] = { 0U };
	uint32_t s[8U] = { 0U };
	uint32_t e[8U] = { 0U };
	ecdsap256_aff_t kG;
	ecdsap256_jac_t kG_jac;
	ecdsap256_aff_t G;
	int32_t res;

	QSC_ASSERT(signedmsg != NULL);
	QSC_ASSERT(smsglen != NULL);
	QSC_ASSERT(message != NULL);
	QSC_ASSERT(privatekey != NULL);

	res = -1;

	if (msglen <= (SIZE_MAX - EC_NISTP256_SIGNATURE_SIZE))
	{
		/* hash the message with SHA-256 */
		qsc_sha256_compute(hash, message, msglen);

		/* derive private scalar exactly as in qsc_ecdsap256_keypair() */
		ecdsap256_sc_from_bytes(d, privatekey);

		if (ecdsap256_field_is_zero(d))
		{
			res = -2;
		}
		else if (ecdsap256_field_cmp(d, ECDSAP256_N) < 0)
		{
			/* load message hash as scalar e */
			ecdsap256_sc_from_bytes_reduce(e, hash);

			/* reconstruct the private scalar bytes in big-endian for RFC 6979 */
			ecdsap256_field_to_bytes(dbe, d);

			/* generate deterministic k using RFC 6979 */
			ecdsap256_rfc6979_generate_k(k, dbe, hash);

			/* R = k * G */
			ecdsap256_field_copy((uint32_t*)G.X, ECDSAP256_GX);
			ecdsap256_field_copy((uint32_t*)G.Y, ECDSAP256_GY);

			ecdsap256_scalar_mult(&kG_jac, &G, k, true);
			ecdsap256_jac_x_to_aff(kG.X, &kG_jac);

			/* r = kG.x mod n */
			ecdsap256_field_copy(r, kG.X);
			ecdsap256_field_cond_sub(r, ECDSAP256_N);

			if (!ecdsap256_field_is_zero(r))
			{
				/* independent scalar blinding; fail closed on RNG error. */
				if (!ecdsap256_sign_scalar_blinded(s, k, d, r, e))
				{
					res = -3;
				}
				else if (!ecdsap256_field_is_zero(s))
				{
					ecdsap256_field_to_bytes(signedmsg, r);
					ecdsap256_field_to_bytes(signedmsg + 32U, s);
					qsc_memutils_copy(signedmsg + EC_NISTP256_SIGNATURE_SIZE, message, msglen);
					*smsglen = EC_NISTP256_SIGNATURE_SIZE + msglen;
					res = 0;
				}
			}
		}
	}

	qsc_memutils_secure_erase(hash, sizeof(hash));
	qsc_memutils_secure_erase(dhash, sizeof(dhash));
	qsc_memutils_secure_erase(dbe, sizeof(dbe));
	qsc_memutils_secure_erase(d, sizeof(d));
	qsc_memutils_secure_erase(k, sizeof(k));
	qsc_memutils_secure_erase(r, sizeof(r));
	qsc_memutils_secure_erase(s, sizeof(s));
	qsc_memutils_secure_erase(e, sizeof(e));
	qsc_memutils_secure_erase(&kG, sizeof(kG));
	qsc_memutils_secure_erase(&kG_jac, sizeof(kG_jac));
	qsc_memutils_secure_erase(&G, sizeof(G));

	if (res != 0)
	{
		/* The caller must supply a nonoverlapping msglen + 64-byte output.
		 * Exclude wrapped sizes from the failure-buffer clearing operation.
		 */
		if (msglen <= (SIZE_MAX - EC_NISTP256_SIGNATURE_SIZE))
		{
			qsc_memutils_clear(signedmsg, EC_NISTP256_SIGNATURE_SIZE + msglen);
		}

		*smsglen = 0U;
	}

	return res;
}

static bool ecdsap256_verify_projective_x(const ecdsap256_jac_t* point, const uint32_t r[8U])
{
	/* compare the public signature r with the X coordinate of a Jacobian point */
	static const uint32_t ECDSAP256_P_MINUS_N[8U] = {0x039CDAAEU, 0x0C46353DU, 0x58E8617BU, 0x43190553U, 0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U};
	ecdsap256_field z_squared = { 0U };
	ecdsap256_field canonical = { 0U };
	ecdsap256_field encoded = { 0U };
	ecdsap256_field expected = { 0U };
	bool result;

	result = false;

	if (ecdsap256_is_infinity(point) == 0U)
	{
		ecdsap256_fe_sqr(z_squared, point->Z);
		ecdsap256_field_mont_encode(encoded, r);
		ecdsap256_fe_mul(expected, encoded, z_squared);
		result = (ecdsap256_field_cmp(point->X, expected) == 0);

		if ((result == false) && (ecdsap256_field_cmp(r, ECDSAP256_P_MINUS_N) < 0))
		{
			ecdsap256_fe_add(canonical, r, ECDSAP256_N);
			ecdsap256_field_mont_encode(encoded, canonical);
			ecdsap256_fe_mul(expected, encoded, z_squared);
			result = (ecdsap256_field_cmp(point->X, expected) == 0);
		}
	}

	qsc_memutils_secure_erase(z_squared, sizeof(z_squared));
	qsc_memutils_secure_erase(canonical, sizeof(canonical));
	qsc_memutils_secure_erase(encoded, sizeof(encoded));
	qsc_memutils_secure_erase(expected, sizeof(expected));

	return result;
}

bool qsc_ecdsap256_verify_context_initialize(qsc_ecdsap256_verify_context* context, const uint8_t* publickey)
{
	ecdsap256_aff_t Q = {{ 0U }, { 0U }};
	bool result;

	result = false;

	if (context != NULL)
	{
		qsc_memutils_clear(context, sizeof(*context));

		if (publickey != NULL)
		{
			ecdsap256_field_from_bytes(Q.X, publickey);
			ecdsap256_field_from_bytes(Q.Y, publickey + 32U);

			if ((ecdsap256_field_cmp(Q.X, ECDSAP256_P) < 0) && (ecdsap256_field_cmp(Q.Y, ECDSAP256_P) < 0) && ecdsap256_point_is_on_curve(&Q))
			{
#if defined(ECDSAP256_NATIVE_64) && !defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)
				ecdsap256_aff_t encoded = {{ 0U }, { 0U }};
				ecdsap256_native_point points[8U];
				ecdsap256_native_point doubled;
				size_t i;

				ecdsap256_field_mont_encode(encoded.X, Q.X);
				ecdsap256_field_mont_encode(encoded.Y, Q.Y);
				ecdsap256_native_load(points[0U].x, encoded.X);
				ecdsap256_native_load(points[0U].y, encoded.Y);
				ecdsap256_native_copy(points[0U].z, ECDSAP256_NATIVE_ONE);
				ecdsap256_verify_native_double_n(&doubled, &points[0U], 1U);

				for (i = 1U; i < 8U; ++i)
				{
					ecdsap256_verify_native_add_projective(&points[i], &points[i - 1U], &doubled);
				}

				ecdsap256_verify_native_batch(points);

				for (i = 0U; i < 8U; ++i)
				{
					ecdsap256_native_store(context->odd_montgomery[i][0U], points[i].x);
					ecdsap256_native_store(context->odd_montgomery[i][1U], points[i].y);
				}

				qsc_memutils_secure_erase(&encoded, sizeof(encoded));
				qsc_memutils_secure_erase(points, sizeof(points));
				qsc_memutils_secure_erase(&doubled, sizeof(doubled));
#endif
				qsc_memutils_copy(context->publickey, publickey, EC_NISTP256_PUBLICKEY_SIZE);
				context->initialized = true;
				result = true;
			}
		}
	}

	qsc_memutils_secure_erase(&Q, sizeof(Q));

	return result;
}

void qsc_ecdsap256_verify_context_clear(qsc_ecdsap256_verify_context* context)
{
	if (context != NULL)
	{
		qsc_memutils_secure_erase(context, sizeof(*context));
	}
}

bool qsc_ecdsap256_comb_verify_context_initialize(qsc_ecdsap256_comb_verify_context* context, const uint8_t* publickey)
{
	ecdsap256_aff_t q;
	ecdsap256_aff_t encoded;
#if defined(ECDSAP256_NATIVE_64) && !defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)
	ecdsap256_native_point points[63U];
#else
	ecdsap256_jac_t points[63U];
	ecdsap256_field prefix[63U];
	ecdsap256_field inverse;
	ecdsap256_field zinv;
	ecdsap256_field z2;
	ecdsap256_field z3;
	size_t round;
#endif
	size_t column;
	size_t base;
	size_t i;
	bool ret;

	ret = false;

	if (context != NULL)
	{
		qsc_memutils_clear(context, sizeof(*context));

		if (publickey != NULL)
		{
			ecdsap256_field_from_bytes(q.X, publickey);
			ecdsap256_field_from_bytes(q.Y, publickey + 32U);

			if (ecdsap256_field_cmp(q.X, ECDSAP256_P) < 0 && ecdsap256_field_cmp(q.Y, ECDSAP256_P) < 0 && ecdsap256_point_is_on_curve(&q))
			{
				ecdsap256_field_mont_encode(encoded.X, q.X);
				ecdsap256_field_mont_encode(encoded.Y, q.Y);
#if defined(ECDSAP256_NATIVE_64) && !defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)
				ecdsap256_native_load(points[0U].x, encoded.X);
				ecdsap256_native_load(points[0U].y, encoded.Y);
				ecdsap256_native_copy(points[0U].z, ECDSAP256_NATIVE_ONE);
#else
				ecdsap256_aff_to_jac(&points[0U], &encoded);
#endif

				for (column = 1U; column < 6U; ++column)
				{
					base = (size_t)1U << column;
#if defined(ECDSAP256_NATIVE_64) && !defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)
					ecdsap256_verify_native_double_n(&points[base - 1U], &points[(base / 2U) - 1U], 43U);
#else
					points[base - 1U] = points[(base / 2U) - 1U];

					for (round = 0U; round < 43U; ++round)
					{
						ecdsap256_dbl(&points[base - 1U], &points[base - 1U]);
					}
#endif

					for (i = 1U; i < base; ++i)
					{
						/* Coefficients are distinct, nonzero, and their sum is < 2^216 < n.
						 * The incomplete public projective formula cannot encounter exceptions. */
#if defined(ECDSAP256_NATIVE_64) && !defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)
						ecdsap256_verify_native_add_projective(&points[base + i - 1U], &points[i - 1U], &points[base - 1U]);
#else
						ecdsap256_add(&points[base + i - 1U], &points[i - 1U], &points[base - 1U]);
#endif
					}
				}

#if defined(ECDSAP256_NATIVE_64) && !defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)
				ecdsap256_verify_native_batch_variable(points, 63U);

				for (i = 0U; i < 63U; ++i)
				{
					ecdsap256_native_store(context->comb[i][0U], points[i].x);
					ecdsap256_native_store(context->comb[i][1U], points[i].y);
				}
#else
				ecdsap256_field_copy(prefix[0U], points[0U].Z);

				for (i = 1U; i < 63U; ++i)
				{
					ecdsap256_fe_mul(prefix[i], prefix[i - 1U], points[i].Z);
				}

				ecdsap256_fe_inv(inverse, prefix[62U]);

				for (i = 63U; i > 0U; --i)
				{
					ecdsap256_field_copy(zinv, inverse);

					if (i > 1U)
					{
						ecdsap256_fe_mul(zinv, inverse, prefix[i - 2U]);
					}

					ecdsap256_fe_mul(inverse, inverse, points[i - 1U].Z);
					ecdsap256_fe_sqr(z2, zinv);
					ecdsap256_fe_mul(z3, z2, zinv);
					ecdsap256_fe_mul(context->comb[i - 1U][0U], points[i - 1U].X, z2);
					ecdsap256_fe_mul(context->comb[i - 1U][1U], points[i - 1U].Y, z3);
				}
#endif
				qsc_memutils_copy(context->publickey, publickey, EC_NISTP256_PUBLICKEY_SIZE);
				context->initialized = true;
				ret = true;
			}
		}
	}

	return ret;
}

static void ecdsap256_verify_comb_mul2(ecdsap256_jac_t* output, const uint32_t first[8U], const uint32_t second[8U], const qsc_ecdsap256_comb_verify_context* context)
{
#if defined(ECDSAP256_NATIVE_64) && !defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)
	ecdsap256_native_point accum = { 0 };
	ecdsap256_native_point selected;
	ecdsap256_native_window_workspace work = { 0 };
#else
	ecdsap256_jac_t accum;
	ecdsap256_jac_t selected;
	ecdsap256_field zero = { 0U };
	ecdsap256_field negative;
	uint32_t scalar[10U] = { 0U };
	uint32_t magnitude;
	uint32_t sign;
#if defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)
	ecdsap256_jac_t candidate;
	uint32_t difference;
	uint32_t equal;
	size_t entry;
#endif
#endif
	size_t row;
	size_t column;
	size_t bit;
	uint32_t index;

#if defined(ECDSAP256_NATIVE_64) && !defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)
	ecdsap256_native_copy(accum.y, ECDSAP256_NATIVE_ONE);
	ecdsap256_native_copy(selected.z, ECDSAP256_NATIVE_ONE);
#else
	ecdsap256_set_infinity(&accum);
#endif

	for (row = 43U; row > 0U; --row)
	{
#if defined(ECDSAP256_NATIVE_64) && !defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)
		ecdsap256_verify_native_double_n(&accum, &accum, 1U);
#else
		ecdsap256_dbl(&accum, &accum);
#endif
		index = 0U;

		for (column = 0U; column < 6U; ++column)
		{
			bit = row - 1U + 43U * column;

			if (bit < 256U)
			{
				index |= ((second[bit / 32U] >> (bit & 31U)) & 1U) << column;
			}
		}

#if defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)
		ecdsap256_set_infinity(&selected);
		ecdsap256_field_one(candidate.Z);

		for (entry = 0U; entry < 63U; ++entry)
		{
			ecdsap256_field_copy(candidate.X, context->comb[entry][0U]);
			ecdsap256_field_copy(candidate.Y, context->comb[entry][1U]);
			difference = (uint32_t)(entry + 1U) ^ index;
			equal = 1U ^ ((difference | (0U - difference)) >> 31U);
			ecdsap256_jac_ct_select(&selected, equal, &candidate, &selected);
		}

		ecdsap256_add_mixed(&accum, &accum, &selected);
#else
		if (index != 0U)
		{
#if defined(ECDSAP256_NATIVE_64)
			ecdsap256_native_load(selected.x, context->comb[index - 1U][0U]);
			ecdsap256_native_load(selected.y, context->comb[index - 1U][1U]);
			ecdsap256_verify_native_add_mixed(&accum, &accum, &selected, &work);
#else
			ecdsap256_field_copy(selected.X, context->comb[index - 1U][0U]);
			ecdsap256_field_copy(selected.Y, context->comb[index - 1U][1U]);
			ecdsap256_field_one(selected.Z);
			ecdsap256_add_public_mixed(&accum, &accum, &selected);
#endif
		}
#endif
	}

#if defined(ECDSAP256_NATIVE_64) && !defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)
	ecdsap256_verify_native_add_generator(&accum, first);
	ecdsap256_native_store(output->X, accum.x);
	ecdsap256_native_store(output->Y, accum.y);
	ecdsap256_native_store(output->Z, accum.z);
#else
	qsc_memutils_copy(scalar, first, 8U * sizeof(uint32_t));

	for (row = 0U; row < 43U; ++row)
	{
		magnitude = ecdsap256_booth_digit(scalar, row, &sign);
#if defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)
		ecdsap256_set_infinity(&selected);
		ecdsap256_field_one(candidate.Z);

		for (entry = 0U; entry < 32U; ++entry)
		{
			ecdsap256_field_copy(candidate.X, ECDSAP256_GENERATOR_TABLE[row][entry][0U]);
			ecdsap256_field_copy(candidate.Y, ECDSAP256_GENERATOR_TABLE[row][entry][1U]);
			difference = (uint32_t)(entry + 1U) ^ magnitude;
			equal = 1U ^ ((difference | (0U - difference)) >> 31U);
			ecdsap256_jac_ct_select(&selected, equal, &candidate, &selected);
		}

		ecdsap256_fe_sub(negative, zero, selected.Y);
		ecdsap256_field_ct_select(selected.Y, sign, negative, selected.Y);
		ecdsap256_add_mixed(&accum, &accum, &selected);
#else
		if (magnitude != 0U)
		{
			ecdsap256_field_copy(selected.X, ECDSAP256_GENERATOR_TABLE[row][magnitude - 1U][0U]);
			ecdsap256_field_copy(selected.Y, ECDSAP256_GENERATOR_TABLE[row][magnitude - 1U][1U]);
			ecdsap256_field_one(selected.Z);
			ecdsap256_fe_sub(negative, zero, selected.Y);
			ecdsap256_field_ct_select(selected.Y, sign, negative, selected.Y);
			ecdsap256_add_public_mixed(&accum, &accum, &selected);
		}
#endif
	}

	*output = accum;
#endif
}

static bool ecdsap256_verify_digest_core(uint8_t* msgout, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey, const uint8_t* digest, const qsc_ecdsap256_verify_context* context, const qsc_ecdsap256_joint_verify_context* joint_context, const qsc_ecdsap256_comb_verify_context* comb_context)
{
	/* verify an ECDSA signature using the already normalized message digest */
	QSC_ASSERT(msgout != NULL);
	QSC_ASSERT(msglen != NULL);
	QSC_ASSERT(signedmsg != NULL);
	QSC_ASSERT(publickey != NULL);

	size_t mlen;
	uint8_t hash[32U] = { 0U };
	uint32_t r[8U] = { 0U };
	uint32_t s[8U] = { 0U };
	uint32_t e[8U] = { 0U };
	uint32_t w[8U] = { 0U };
	uint32_t u1[8U] = { 0U };
	uint32_t u2[8U] = { 0U };
	ecdsap256_aff_t Q = { 0U };
	ecdsap256_jac_t Jsum = { 0U };
	bool res;

	res = false;
	mlen = 0U;

	if ((digest != NULL) && (smsglen >= EC_NISTP256_SIGNATURE_SIZE))
	{
		mlen = smsglen - EC_NISTP256_SIGNATURE_SIZE;
		ecdsap256_field_from_bytes((uint32_t*)Q.X, publickey);
		ecdsap256_field_from_bytes((uint32_t*)Q.Y, publickey + 32U);

		if (ecdsap256_field_cmp((uint32_t*)Q.X, ECDSAP256_P) < 0 && ecdsap256_field_cmp((uint32_t*)Q.Y, ECDSAP256_P) < 0 &&
			((context != NULL) || (comb_context != NULL && comb_context->initialized) || ecdsap256_point_is_on_curve(&Q)))
		{
			ecdsap256_field_from_bytes(r, signedmsg);
			ecdsap256_field_from_bytes(s, signedmsg + 32U);

			if (!ecdsap256_field_is_zero(r) && ecdsap256_field_cmp(r, ECDSAP256_N) < 0 && !ecdsap256_field_is_zero(s) &&
				ecdsap256_field_cmp(s, ECDSAP256_N) < 0)
			{
				qsc_memutils_copy(hash, digest, 32U);
				ecdsap256_sc_from_bytes_reduce(e, hash);
#if defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)
				ecdsap256_sc_inv(w, s);
#else
				ecdsap256_sc_inv_public(w, s);
#endif
				ecdsap256_sc_mul(u1, e, w);
				ecdsap256_sc_mul(u2, r, w);

				if (comb_context != NULL)
				{
					ecdsap256_verify_comb_mul2(&Jsum, u1, u2, comb_context);
				}
				else
#if defined(ECDSAP256_NATIVE_64) && !defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)
					if (joint_context != NULL)
				{
					ecdsap256_verify_native_joint_window(&Jsum, u1, u2, joint_context);
				}
				else
#endif
				{
					(void)joint_context;
					ecdsap256_double_scalar_mult(&Jsum, &Q, u1, u2, context);
				}

				if (ecdsap256_verify_projective_x(&Jsum, r) == true)
				{
					qsc_memutils_copy(msgout, signedmsg + EC_NISTP256_SIGNATURE_SIZE, mlen);
					*msglen = mlen;
					res = true;
				}
			}
		}

		if (res == false)
		{
			*msglen = 0U;
		}

		qsc_memutils_secure_erase(hash, sizeof(hash));
		qsc_memutils_secure_erase(r, sizeof(r));
		qsc_memutils_secure_erase(s, sizeof(s));
		qsc_memutils_secure_erase(e, sizeof(e));
		qsc_memutils_secure_erase(w, sizeof(w));
		qsc_memutils_secure_erase(u1, sizeof(u1));
		qsc_memutils_secure_erase(u2, sizeof(u2));
		qsc_memutils_secure_erase(&Q, sizeof(Q));

		qsc_memutils_secure_erase(&Jsum, sizeof(Jsum));
	}

	return res;
}

bool qsc_ecdsap256_verify(uint8_t* msgout, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey)
{
	uint8_t digest[32U] = { 0U };
	bool res;

	res = false;

	if (msglen != NULL)
	{
		*msglen = 0U;
	}

	if ((msgout != NULL) && (msglen != NULL) && (signedmsg != NULL) && (publickey != NULL) && (smsglen >= EC_NISTP256_SIGNATURE_SIZE))
	{
		qsc_sha256_compute(digest, signedmsg + EC_NISTP256_SIGNATURE_SIZE, smsglen - EC_NISTP256_SIGNATURE_SIZE);
		res = ecdsap256_verify_digest_core(msgout, msglen, signedmsg, smsglen, publickey, digest, NULL, NULL, NULL);
	}

	/* Only the caller-declared recovered-message region can be cleared. */
	if ((res == false) && (msgout != NULL) && (smsglen > EC_NISTP256_SIGNATURE_SIZE))
	{
		qsc_memutils_clear(msgout, smsglen - EC_NISTP256_SIGNATURE_SIZE);
	}

	qsc_memutils_secure_erase(digest, sizeof(digest));

	return res;
}

bool qsc_ecdsap256_verify_prehashed(uint8_t* msgout, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey, const uint8_t* digest, size_t digestlen)
{
	uint8_t scalarhash[32U] = { 0U };
	bool res;

	res = false;

	if (msglen != NULL)
	{
		*msglen = 0U;
	}

	if ((msgout != NULL) && (msglen != NULL) && (signedmsg != NULL) && (publickey != NULL) && (smsglen >= EC_NISTP256_SIGNATURE_SIZE) && (digest != NULL) &&
		((digestlen == 32U) || (digestlen == 48U) || (digestlen == 64U)))
	{
		qsc_memutils_copy(scalarhash, digest, sizeof(scalarhash));
		res = ecdsap256_verify_digest_core(msgout, msglen, signedmsg, smsglen, publickey, scalarhash, NULL, NULL, NULL);
	}

	qsc_memutils_secure_erase(scalarhash, sizeof(scalarhash));

	return res;
}

bool qsc_ecdsap256_verify_with_context(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const qsc_ecdsap256_verify_context* context)
{
	uint8_t digest[32U] = { 0U };
	bool result;

	result = false;

	if (msglen != NULL)
	{
		*msglen = 0U;
	}

	if ((message != NULL) && (msglen != NULL) && (signedmsg != NULL) && (context != NULL) && context->initialized && (smsglen >= EC_NISTP256_SIGNATURE_SIZE))
	{
		qsc_sha256_compute(digest, signedmsg + EC_NISTP256_SIGNATURE_SIZE, smsglen - EC_NISTP256_SIGNATURE_SIZE);
		result = ecdsap256_verify_digest_core(message, msglen, signedmsg, smsglen, context->publickey, digest, context, NULL, NULL);
	}

	qsc_memutils_secure_erase(digest, sizeof(digest));

	return result;
}

bool qsc_ecdsap256_joint_verify_context_initialize(qsc_ecdsap256_joint_verify_context* context, const uint8_t* publickey)
{
	bool result;

	result = false;

	if (context != NULL)
	{
		qsc_memutils_clear(context, sizeof(*context));

		if (qsc_ecdsap256_verify_context_initialize(&context->base, publickey))
		{
#if defined(ECDSAP256_NATIVE_64) && !defined(QSC_ECDSA_CONSTANT_TIME_VERIFY)
			ecdsap256_verify_native_joint_prepare(context);
#endif
			context->initialized = true;
			result = true;
		}
	}

	return result;
}

void qsc_ecdsap256_joint_verify_context_clear(qsc_ecdsap256_joint_verify_context* context)
{
	if (context != NULL)
	{
		qsc_memutils_secure_erase(context, sizeof(*context));
	}
}

bool qsc_ecdsap256_verify_with_joint_context(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const qsc_ecdsap256_joint_verify_context* context)
{
	uint8_t digest[32U] = { 0U };
	bool result;

	result = false;

	if (msglen != NULL)
	{
		*msglen = 0U;
	}

	if ((message != NULL) && (msglen != NULL) && (signedmsg != NULL) && (context != NULL) && context->initialized && context->base.initialized &&
		(smsglen >= EC_NISTP256_SIGNATURE_SIZE))
	{
		qsc_sha256_compute(digest, signedmsg + EC_NISTP256_SIGNATURE_SIZE, smsglen - EC_NISTP256_SIGNATURE_SIZE);
		result = ecdsap256_verify_digest_core(message, msglen, signedmsg, smsglen, context->base.publickey, digest, &context->base, context, NULL);
	}

	qsc_memutils_secure_erase(digest, sizeof(digest));

	return result;
}

void qsc_ecdsap256_comb_verify_context_clear(qsc_ecdsap256_comb_verify_context* context)
{
	if (context != NULL)
	{
		qsc_memutils_clear(context, sizeof(*context));
	}
}

bool qsc_ecdsap256_verify_with_comb_context(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const qsc_ecdsap256_comb_verify_context* context)
{
	uint8_t digest[32U] = { 0U };
	bool ret;

	ret = false;

	if (msglen != NULL)
	{
		*msglen = 0U;
	}

	if (message != NULL && msglen != NULL && signedmsg != NULL && context != NULL && smsglen >= EC_NISTP256_SIGNATURE_SIZE && context->initialized)
	{
		qsc_sha256_compute(digest, signedmsg + EC_NISTP256_SIGNATURE_SIZE, smsglen - EC_NISTP256_SIGNATURE_SIZE);
		ret = qsc_ecdsap256_verify_prehashed_with_comb_context(message, msglen, signedmsg, smsglen, context, digest, sizeof(digest));
	}

	qsc_memutils_secure_erase(digest, sizeof(digest));

	return ret;
}

bool qsc_ecdsap256_verify_prehashed_with_comb_context(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const qsc_ecdsap256_comb_verify_context* context, const uint8_t* digest, size_t digestlen)
{
	bool ret;

	ret = false;

	if (msglen != NULL)
	{
		*msglen = 0U;
	}

	if (message != NULL && msglen != NULL && signedmsg != NULL && context != NULL && digest != NULL && smsglen >= EC_NISTP256_SIGNATURE_SIZE &&
		context->initialized && (digestlen == 32U || digestlen == 48U || digestlen == 64U))
	{
		ret = ecdsap256_verify_digest_core(message, msglen, signedmsg, smsglen, context->publickey, digest, NULL, NULL, context);
	}

	return ret;
}

int32_t qsc_p256_publickey_from_privatekey(uint8_t* publickey, const uint8_t* privatekey)
{
	return qsc_ecdsap256_publickey_from_privatekey(publickey, privatekey);
}

int32_t qsc_p256_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed)
{
	return qsc_ecdsap256_keypair(publickey, privatekey, seed);
}

bool qsc_p256_privatekey_validate(const uint8_t* privatekey)
{
	return qsc_ecdsap256_privatekey_validate(privatekey);
}

int32_t qsc_p256_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey)
{
	return qsc_ecdsap256_sign(signedmsg, smsglen, message, msglen, privatekey);
}

int32_t qsc_p256_sign_scalar(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey)
{
	return qsc_ecdsap256_sign_scalar(signedmsg, smsglen, message, msglen, privatekey);
}

bool qsc_p256_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey)
{
	return qsc_ecdsap256_verify(message, msglen, signedmsg, smsglen, publickey);
}

bool qsc_p256_verify_prehashed(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey, const uint8_t* digest, size_t digestlen)
{
	return qsc_ecdsap256_verify_prehashed(message, msglen, signedmsg, smsglen, publickey, digest, digestlen);
}

bool qsc_p256_joint_verify_context_initialize(qsc_p256_joint_verify_context* context, const uint8_t* publickey)
{
	return qsc_ecdsap256_joint_verify_context_initialize(context, publickey);
}

void qsc_p256_joint_verify_context_clear(qsc_p256_joint_verify_context* context)
{
	qsc_ecdsap256_joint_verify_context_clear(context);
}

bool qsc_p256_verify_with_joint_context(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const qsc_p256_joint_verify_context* context)
{
	return qsc_ecdsap256_verify_with_joint_context(message, msglen, signedmsg, smsglen, context);
}

bool qsc_p256_verify_context_initialize(qsc_p256_verify_context* context, const uint8_t* publickey)
{
	return qsc_ecdsap256_verify_context_initialize(context, publickey);
}

void qsc_p256_verify_context_clear(qsc_p256_verify_context* context)
{
	qsc_ecdsap256_verify_context_clear(context);
}

bool qsc_p256_verify_with_context(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const qsc_p256_verify_context* context)
{
	return qsc_ecdsap256_verify_with_context(message, msglen, signedmsg, smsglen, context);
}

bool qsc_p256_comb_verify_context_initialize(qsc_p256_comb_verify_context* context, const uint8_t* publickey)
{
	return qsc_ecdsap256_comb_verify_context_initialize(context, publickey);
}

void qsc_p256_comb_verify_context_clear(qsc_p256_comb_verify_context* context)
{
	qsc_ecdsap256_comb_verify_context_clear(context);
}

bool qsc_p256_verify_with_comb_context(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const qsc_p256_comb_verify_context* context)
{
	return qsc_ecdsap256_verify_with_comb_context(message, msglen, signedmsg, smsglen, context);
}

bool qsc_p256_verify_prehashed_with_comb_context(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const qsc_p256_comb_verify_context* context, const uint8_t* digest, size_t digestlen)
{
	return qsc_ecdsap256_verify_prehashed_with_comb_context(message, msglen, signedmsg, smsglen, context, digest, digestlen);
}

/* \endcond DOXYGEN_NO_DOCUMENT */
