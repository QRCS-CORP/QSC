#include "intutils.h"
#include "memutils.h"

bool qsc_intutils_are_equal8(const uint8_t* a, const uint8_t* b, size_t length)
{
	assert(a != NULL);
	assert(b != NULL);

	bool status;

	status = true;

	for (size_t i = 0; i < length; ++i)
	{
		if (a[i] != b[i])
		{
			status = false;
			break;
		}
	}

	return status;
}

void qsc_intutils_be8increment(uint8_t* output, size_t otplen)
{
	assert(output != NULL);

	size_t i = otplen;

	if (otplen > 0)
	{
		do
		{
			--i;
			++output[i];
		} 
		while (i != 0 && output[i] == 0);
	}
}

uint16_t qsc_intutils_be8to16(const uint8_t* input)
{
	assert(input != NULL);

	return (((uint16_t)input[1]) | 
		(uint16_t)((uint16_t)input[0] << 8U));
}

uint32_t qsc_intutils_be8to32(const uint8_t* input)
{
	assert(input != NULL);

	return (uint32_t)(input[3]) |
		(((uint32_t)(input[2])) << 8) |
		(((uint32_t)(input[1])) << 16) |
		(((uint32_t)(input[0])) << 24);
}

uint64_t qsc_intutils_be8to64(const uint8_t* input)
{
	assert(input != NULL);

	return (uint64_t)(input[7]) |
		(((uint64_t)(input[6])) << 8) |
		(((uint64_t)(input[5])) << 16) |
		(((uint64_t)(input[4])) << 24) |
		(((uint64_t)(input[3])) << 32) |
		(((uint64_t)(input[2])) << 40) |
		(((uint64_t)(input[1])) << 48) |
		(((uint64_t)(input[0])) << 56);
}

void qsc_intutils_be16to8(uint8_t* output, uint16_t value)
{
	assert(output != NULL);

	output[1] = (uint8_t)value & 0xFFU;
	output[0] = (uint8_t)(value >> 8) & 0xFFU;
}

void qsc_intutils_be32to8(uint8_t* output, uint32_t value)
{
	assert(output != NULL);

	output[3] = (uint8_t)value & 0xFFU;
	output[2] = (uint8_t)(value >> 8) & 0xFFU;
	output[1] = (uint8_t)(value >> 16) & 0xFFU;
	output[0] = (uint8_t)(value >> 24) & 0xFFU;
}

void qsc_intutils_be64to8(uint8_t* output, uint64_t value)
{
	assert(output != NULL);

	output[7] = (uint8_t)value & 0xFFU;
	output[6] = (uint8_t)(value >> 8) & 0xFFU;
	output[5] = (uint8_t)(value >> 16) & 0xFFU;
	output[4] = (uint8_t)(value >> 24) & 0xFFU;
	output[3] = (uint8_t)(value >> 32) & 0xFFU;
	output[2] = (uint8_t)(value >> 40) & 0xFFU;
	output[1] = (uint8_t)(value >> 48) & 0xFFU;
	output[0] = (uint8_t)(value >> 56) & 0xFFU;
}

uint64_t qsc_intutils_bit_reverse_u64(uint64_t x)
{
    x = ((x >> 1) & 0x5555555555555555ULL) | ((x & 0x5555555555555555ULL) << 1);
    x = ((x >> 2) & 0x3333333333333333ULL) | ((x & 0x3333333333333333ULL) << 2);
    x = ((x >> 4) & 0x0F0F0F0F0F0F0F0FULL) | ((x & 0x0F0F0F0F0F0F0F0FULL) << 4);
    x = ((x >> 8) & 0x00FF00FF00FF00FFULL) | ((x & 0x00FF00FF00FF00FFULL) << 8);
    x = ((x >> 16) & 0x0000FFFF0000FFFFULL) | ((x & 0x0000FFFF0000FFFFULL) << 16);
    x = (x >> 32) | (x << 32);

    return x;
}

uint32_t qsc_intutils_bit_reverse_u32(uint32_t x) 
{
    x = ((x >> 1) & 0x55555555) | ((x & 0x55555555) << 1);
    x = ((x >> 2) & 0x33333333) | ((x & 0x33333333) << 2);
    x = ((x >> 4) & 0x0F0F0F0F) | ((x & 0x0F0F0F0F) << 4);
    x = ((x >> 8) & 0x00FF00FF) | ((x & 0x00FF00FF) << 8);
    x = (x >> 16) | (x << 16);

    return x;
}

uint16_t qsc_intutils_bit_reverse_u16(uint16_t x) 
{
    x = ((x >> 1) & 0x5555) | ((x & 0x5555) << 1);
    x = ((x >> 2) & 0x3333) | ((x & 0x3333) << 2);
    x = ((x >> 4) & 0x0F0F) | ((x & 0x0F0F) << 4);
    x = (x >> 8) | (x << 8);

    return x;
}

size_t qsc_intutils_bit_reverse(size_t x, uint32_t bits) 
{
    size_t y = 0;

    for (size_t i = 0; i < bits; ++i) 
    {
        y = (y << 1) | (x & 1);
        x >>= 1;
    }

    return y;
}

#if defined(QSC_SYSTEM_HAS_AVX)
void qsc_intutils_bswap32(uint32_t* dest, const uint32_t* source, size_t length)
{
	assert(dest != NULL);
	assert(source != NULL);

	__m128i mask = _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);

	for (size_t i = 0; i < length; i += 4)
	{
		_mm_storeu_si128((__m128i*)&dest[i], _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)&source[i]), mask));
	}
}

void qsc_intutils_bswap64(uint64_t* dest, const uint64_t* source, size_t length)
{
	assert(dest != NULL);
	assert(source != NULL);

	__m128i mask = _mm_set_epi8(8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7);

	for (size_t i = 0; i < length; i += 2)
	{
		_mm_storeu_si128((__m128i*)&dest[i], _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)&source[i]), mask));
	}
}
#endif

double qsc_intutils_calculate_abs(double a)
{
    if (a < 0.0)
    {
        return -a;
    }
    return a;
}

double qsc_intutils_calculate_exp(double x)
{
	double epsilon;
	double res;
    double result;
	double term;
	uint64_t bits;
	int32_t n;
    
    /* check for NaN: NaN is the only value that is not equal to itself */
    if (x != x)
    {
        result = x; /* propagate NaN */
    }
    else if (x > 709.782712893384)
    {
        /* construct positive infinity by setting the IEEE-754 bit pattern */
        bits = 0x7FF0000000000000ULL;
        qsc_memutils_copy(&result, &bits, sizeof(result));
    }
    else if (x < -745.133219101941)
    {
        result = 0.0;
    }
    else
    {
        term = 1.0;
        res = 1.0;
        n = 1;
        epsilon = 1e-12; /* relative tolerance */
        
        while (qsc_intutils_calculate_abs(term) > epsilon * qsc_intutils_calculate_abs(res))
        {
            term *= x / n;
            res += term;
            ++n;

			/* safety break to prevent infinite loop */
            if (n > 10000)
            {
                break;
            }
        }

        result = res;
    }
    
    return result;
}

double qsc_intutils_calculate_fabs(double x)
{
    uint64_t u;
    double result;

    /* copy the bits of x into u */
    memcpy(&u, &x, sizeof(u));

    /* clear the sign bit (bit 63) */
    u &= 0x7FFFFFFFFFFFFFFFULL;

    /* copy the modified bits back into a double */
    memcpy(&result, &u, sizeof(result));

    return result;
}

double qsc_intutils_calculate_log(double x)
{
	uint64_t infbits;
	uint64_t nanbits;
	uint64_t neginfbits;
    double epsilon;
    double ln2;
	double lnx;
    double result;
    double sum;
    double term;
	double y;
    double y2;
	int32_t k;
    int32_t n;

    if (x != x)  /* NaN check: NaN != NaN */
    {
        result = x;  /* propagate NaN */
    }
    else if (x < 0.0)
    {
        /* create NaN by setting the IEEE-754 quiet NaN bit pattern inline */
        nanbits = 0x7FF8000000000000ULL;
        memcpy(&result, &nanbits, sizeof(result));
    }
    else if (x == 0.0)
    {
        /* create negative infinity by setting the IEEE-754 bit pattern inline */
        neginfbits = 0xFFF0000000000000ULL;
        memcpy(&result, &neginfbits, sizeof(result));
    }
    else if (x > 1e300)
    {
        /* create positive infinity by setting the IEEE-754 bit pattern inline */
        infbits = 0x7FF0000000000000ULL;
        memcpy(&result, &infbits, sizeof(result));
    }
    else
    {
        k = 0;

        /* range reduction: scale x into [1,2] */
        while (x >= 2.0)
        {
            x /= 2.0;
            k++;
        }

        while (x < 1.0)
        {
            x *= 2.0;
            k--;
        }

        /* compute y = (x - 1)/(x + 1) and then the series for ln(x) */
        y = (x - 1.0) / (x + 1.0);
        y2 = y * y;
        sum = 0.0;
        term = y;
        n = 1;
        epsilon = 1e-12;

        while (qsc_intutils_calculate_abs(term) > epsilon)
        {
            sum += term / n;
            term *= y2;
            n += 2;
        }

        lnx = 2.0 * sum;
		/* approximation for ln(2) */
        ln2 = 0.6931471805599453;
        result = lnx + k * ln2;
    }
    
    return result;
}

double qsc_intutils_calculate_sqrt(double x)
{
	uint64_t nanbits;
	double abs_nguess;
	double diff;
	double epsilon;
	double guess;
    double nguess;
    double result;

    if (x < 0.0)
    {
        /* create NaN by setting the IEEE-754 quiet NaN bit pattern */
        nanbits = 0x7FF8000000000000ULL;
        memcpy(&result, &nanbits, sizeof(result));
    }
    else if (x == 0.0)
    {
        result = 0.0;
    }
    else
    {
        /* use a different initial guess if x < 1 to avoid extremely small initial guesses */
        if (x >= 1.0)
        {
            guess = x / 2.0;
        }
        else
        {
            guess = 1.0;
        }

        epsilon = 1e-12;
        nguess;

        while (true)
        {
            nguess = 0.5 * (guess + x / guess);
            /* calculate the absolute difference without using a helper function */
            diff = nguess - guess;

            if (diff < 0.0)
            {
                diff = -diff;
            }

            /* stop when the relative difference is below the tolerance */
            {
                abs_nguess = (nguess < 0.0) ? -nguess : nguess;

                if (diff < epsilon * abs_nguess)
                {
                    break;
                }
            }

            guess = nguess;
        }

        result = nguess;
    }
    
    return result;
}

void qsc_intutils_clear8(uint8_t* a, size_t count)
{
	assert(a != NULL);
	
	for (size_t i = 0; i < count; ++i)
	{
		a[i] = 0;
	}
}

void qsc_intutils_clear16(uint16_t* a, size_t count)
{
	assert(a != NULL);

	for (size_t i = 0; i < count; ++i)
	{
		a[i] = 0;
	}
}

void qsc_intutils_clear32(uint32_t* a, size_t count)
{
	assert(a != NULL);

	for (size_t i = 0; i < count; ++i)
	{
		a[i] = 0;
	}
}

void qsc_intutils_clear64(uint64_t* a, size_t count)
{
	assert(a != NULL);

	for (size_t i = 0; i < count; ++i)
	{
		a[i] = 0;
	}
}

void qsc_intutils_cmov(uint8_t* dest, const uint8_t* source, size_t length, uint8_t cond)
{
	assert(dest != NULL);
	assert(source != NULL);
	
#if defined(__GNUC__) || defined(__clang__)
  // Prevent the compiler from
  //    1) inferring that b is 0/1-valued, and
  //    2) handling the two cases with a branch.
  // This is not necessary when verify.c and kem.c are separate translation
  // units, but we expect that downstream consumers will copy this code and/or
  // change how it is built.
  __asm__("" : "+dest"(cond) : /* no inputs */);
#endif

	cond = ~cond + 1;

	for (size_t i = 0; i < length; i++)
	{
		dest[i] ^= (uint8_t)(cond & (uint8_t)(source[i] ^ dest[i]));
	}
}

size_t qsc_intutils_expand_mask(size_t x)
{
	size_t r;

	r = x;

	/* fold r down to a single bit */
	for (size_t i = 1; i != sizeof(size_t) * 8; i *= 2)
	{
		r |= r >> i;
	}

	r &= 1;
	r = ~(r - 1);

	return r;
}

bool qsc_intutils_are_equal(size_t x, size_t y)
{
	return (bool)((x ^ y) == 0);
}

bool qsc_intutils_is_gte(size_t x, size_t y)
{
	return (bool)(x >= y);
}

void qsc_intutils_bin_to_hex(const uint8_t* input, char* hexstr, size_t inplen)
{
	assert(input != NULL);
	assert(hexstr != NULL);

	const uint8_t ENCODING_TABLE[16] =
	{
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
	};

	size_t ctr;
	int32_t vct;

	ctr = 0;

	for (size_t i = 0; i < inplen; ++i)
	{
		vct = input[i];
		hexstr[ctr] = ENCODING_TABLE[vct >> 4];
		++ctr;
		hexstr[ctr] = ENCODING_TABLE[vct & 0x0F];
		++ctr;
	}
}

void qsc_intutils_hex_to_bin(const char* hexstr, uint8_t* output, size_t outlen)
{
	assert(hexstr != NULL);
	assert(output != NULL);

	uint8_t idx0;
	uint8_t idx1;

	const uint8_t hashmap[] =
	{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	qsc_memutils_clear(output, outlen);

	for (size_t pos = 0; pos < (outlen * 2); pos += 2)
	{
		idx0 = ((uint8_t)hexstr[pos] & 0x1FU) ^ 0x10U;
		idx1 = ((uint8_t)hexstr[pos + 1] & 0x1FU) ^ 0x10U;
		output[pos / 2] = (uint8_t)(hashmap[idx0] << 4) | hashmap[idx1];
	}
}

void qsc_intutils_le8increment(uint8_t* output, size_t otplen)
{
	assert(output != NULL);

	size_t i;

	i = 0;

	while (i < otplen)
	{
		++output[i];

		if (output[i] != 0)
		{
			break;
		}

		++i;
	}
}

#if defined(QSC_SYSTEM_HAS_AVX)
void qsc_intutils_leincrement_x128(__m128i* counter)
{
	assert(counter != NULL);

	*counter = _mm_add_epi64(*counter, _mm_set_epi64x(0, 1));
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
void qsc_intutils_leincrement_x512(__m512i* counter)
{
	assert(counter != NULL);

	*counter = _mm512_add_epi64(*counter, _mm512_set_epi64(0, 4, 0, 4, 0, 4, 0, 4));
}
#endif

uint16_t qsc_intutils_le8to16(const uint8_t* input)
{
	assert(input != NULL);

	return (((uint16_t)input[0]) |
		(uint16_t)((uint16_t)input[1] << 8U));
}

uint32_t qsc_intutils_le8to32(const uint8_t* input)
{
	assert(input != NULL);

	return ((uint32_t)input[0]) |
		((uint32_t)input[1] << 8) |
		((uint32_t)input[2] << 16) |
		((uint32_t)input[3] << 24);
}

uint64_t qsc_intutils_le8to64(const uint8_t* input)
{
	assert(input != NULL);

	return ((uint64_t)input[0]) |
		((uint64_t)input[1] << 8) |
		((uint64_t)input[2] << 16) |
		((uint64_t)input[3] << 24) |
		((uint64_t)input[4] << 32) |
		((uint64_t)input[5] << 40) |
		((uint64_t)input[6] << 48) |
		((uint64_t)input[7] << 56);
}

void qsc_intutils_le16to8(uint8_t* output, uint16_t value)
{
	assert(output != NULL);

	output[0] = (uint8_t)value & 0xFFU;
	output[1] = (uint8_t)(value >> 8) & 0xFFU;
}

void qsc_intutils_le32to8(uint8_t* output, uint32_t value)
{
	assert(output != NULL);

	output[0] = (uint8_t)value & 0xFFU;
	output[1] = (uint8_t)(value >> 8) & 0xFFU;
	output[2] = (uint8_t)(value >> 16) & 0xFFU;
	output[3] = (uint8_t)(value >> 24) & 0xFFU;
}

void qsc_intutils_le64to8(uint8_t* output, uint64_t value)
{
	assert(output != NULL);

	output[0] = (uint8_t)value & 0xFFU;
	output[1] = (uint8_t)(value >> 8) & 0xFFU;
	output[2] = (uint8_t)(value >> 16) & 0xFFU;
	output[3] = (uint8_t)(value >> 24) & 0xFFU;
	output[4] = (uint8_t)(value >> 32) & 0xFFU;
	output[5] = (uint8_t)(value >> 40) & 0xFFU;
	output[6] = (uint8_t)(value >> 48) & 0xFFU;
	output[7] = (uint8_t)(value >> 56) & 0xFFU;
}

size_t qsc_intutils_max(size_t a, size_t b)
{
	return (a > b) ? a : b;
}

size_t qsc_intutils_min(size_t a, size_t b)
{
	return (a < b) ? a : b;
}

uint32_t qsc_intutils_popcount32(uint32_t v)
{
	v = v - ((v >> 1) & 0x55555555);
	v = (v & 0x33333333) + ((v >> 2) & 0x33333333);

	return (uint32_t)((v + ((v >> 4) & 0xF0F0F0F)) * 0x1010101) >> 24;
}

#if defined(QSC_SYSTEM_HAS_AVX)
void qsc_intutils_reverse_bytes_x128(const __m128i* input, __m128i* output)
{
	assert(input != NULL);
	assert(output != NULL);

	__m128i mask = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

	*output = _mm_shuffle_epi8(*input, mask);
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
void qsc_intutils_reverse_bytes_x512(const __m512i* input, __m512i* output)
{
	assert(input != NULL);
	assert(output != NULL);

	__m512i mask = _mm512_set_epi8(
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 
		32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 
		48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63);

	*output = _mm512_shuffle_epi8(*input, mask);
}
#endif

uint32_t qsc_intutils_rotl32(uint32_t value, size_t shift)
{
	return (value << shift) | (value >> ((sizeof(uint32_t) * 8) - shift));
}

uint64_t qsc_intutils_rotl64(uint64_t value, size_t shift)
{
	return (value << shift) | (value >> ((sizeof(uint64_t) * 8) - shift));
}

uint32_t qsc_intutils_rotr32(uint32_t value, size_t shift)
{
	return (value >> shift) | (value << ((sizeof(uint32_t) * 8) - shift));
}

uint64_t qsc_intutils_rotr64(uint64_t value, size_t shift)
{
	return (value >> shift) | (value << ((sizeof(uint64_t) * 8) - shift));
}

int32_t qsc_intutils_verify(const uint8_t* a, const uint8_t* b, size_t length)
{
	assert(a != NULL);
	assert(b != NULL);

	uint8_t d;

	d = 0;

	for (size_t i = 0; i < length; ++i)
	{
		d |= (a[i] ^ b[i]);
	}

	return d;
}
