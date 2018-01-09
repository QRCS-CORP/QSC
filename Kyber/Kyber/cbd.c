#include "cbd.h"

/* Note: cbd, in K{2,3,4} unit tested against original, 01/08/2018 */

#if (KYBER_ETA == 3 || KYBER_ETA == 4)

static uint32_t lebytesto32(const uint8_t* a, size_t bytes)
{
	size_t i;
	uint32_t r;

	r = a[0];

	for (i = 1; i < bytes; i++)
	{
		r |= (uint32_t)a[i] << (8 * i);
	}

	return r;
}

#else

static uint64_t lebytesto64(const uint8_t* a, size_t bytes)
{
	size_t i;
	uint64_t r;

	r = a[0];

	for (i = 1; i < bytes; i++)
	{
		r |= (uint64_t)a[i] << (8 * i);
	}

	return r;
}

#endif

void cbd(poly* r, const uint8_t* buf)
{
#if (KYBER_ETA == 3)

	uint16_t a[4];
	uint16_t b[4];
	size_t i;
	size_t j;
	uint32_t t;
	uint32_t d;

	for (i = 0; i < KYBER_N / 4; i++)
	{
		t = lebytesto32(buf + 3 * i, 3);
		d = 0;

		for (j = 0; j < 3; j++)
		{
			d += (t >> j) & 0x249249UL;
		}

		a[0] = (d & 0x7);
		b[0] = ((d >> 3) & 0x7);
		a[1] = ((d >> 6) & 0x7);
		b[1] = ((d >> 9) & 0x7);
		a[2] = ((d >> 12) & 0x7);
		b[2] = ((d >> 15) & 0x7);
		a[3] = ((d >> 18) & 0x7);
		b[3] = (d >> 21);

		r->coeffs[4 * i] = a[0] + (KYBER_Q - b[0]);
		r->coeffs[(4 * i) + 1] = a[1] + (KYBER_Q - b[1]);
		r->coeffs[(4 * i) + 2] = a[2] + (KYBER_Q - b[2]);
		r->coeffs[(4 * i) + 3] = a[3] + (KYBER_Q - b[3]);
	}

#elif (KYBER_ETA == 4)

	uint16_t a[4];
	uint16_t b[4];
	size_t i;
	size_t j;
	uint32_t t;
	uint32_t d;

	for (i = 0; i < KYBER_N / 4; i++)
	{
		t = lebytesto32(buf + (4 * i), 4);
		d = 0;

		for (j = 0; j < 4; j++)
		{
			d += (t >> j) & 0x11111111UL;
		}

		a[0] = (d & 0xF);
		b[0] = ((d >> 4) & 0xF);
		a[1] = ((d >> 8) & 0xF);
		b[1] = ((d >> 12) & 0xF);
		a[2] = ((d >> 16) & 0xF);
		b[2] = ((d >> 20) & 0xF);
		a[3] = ((d >> 24) & 0xF);
		b[3] = (d >> 28);

		r->coeffs[4 * i] = a[0] + (KYBER_Q - b[0]);
		r->coeffs[(4 * i) + 1] = a[1] + (KYBER_Q - b[1]);
		r->coeffs[(4 * i) + 2] = a[2] + (KYBER_Q - b[2]);
		r->coeffs[(4 * i) + 3] = a[3] + (KYBER_Q - b[3]);
	}

#elif (KYBER_ETA == 5)

	uint32_t a[4];
	uint32_t b[4];
	uint64_t d;
	uint64_t t;
	size_t i;
	size_t j;

	for (i = 0; i < KYBER_N / 4; i++)
	{
		t = lebytesto64(buf + (5 * i), 5);
		d = 0;

		for (j = 0; j < 5; j++)
		{
			d += (t >> j) & 0x0842108421ULL;
		}

		a[0] = (d & 0x1F);
		b[0] = ((d >> 5) & 0x1F);
		a[1] = ((d >> 10) & 0x1F);
		b[1] = ((d >> 15) & 0x1F);
		a[2] = ((d >> 20) & 0x1F);
		b[2] = ((d >> 25) & 0x1F);
		a[3] = ((d >> 30) & 0x1F);
		b[3] = (d >> 35);

		r->coeffs[4 * i] = a[0] + (KYBER_Q - b[0]);
		r->coeffs[(4 * i) + 1] = a[1] + (KYBER_Q - b[1]);
		r->coeffs[(4 * i) + 2] = a[2] + (KYBER_Q - b[2]);
		r->coeffs[(4 * i) + 3] = a[3] + (KYBER_Q - b[3]);
	}

#else

#	error "poly_getnoise in poly.c only supports eta in {3,4,5}"

#endif
}
