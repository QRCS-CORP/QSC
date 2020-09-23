#include "dilithiumbase.h"
#include "sha3.h"

/* params.h */

#define DILITHIUM_POLT1_SIZE_PACKED ((QSC_DILITHIUM_N * (DILITHIUM_QBITS - QSC_DILITHIUM_D)) / 8)
#define DILITHIUM_POLT0_SIZE_PACKED ((QSC_DILITHIUM_N * QSC_DILITHIUM_D) / 8)
#define DILITHIUM_POLETA_SIZE_PACKED ((QSC_DILITHIUM_N * QSC_DILITHIUM_SETABITS) / 8)
#define DILITHIUM_POLZ_SIZE_PACKED ((QSC_DILITHIUM_N * (DILITHIUM_QBITS - 3)) / 8)
#define DILITHIUM_POLW1_SIZE_PACKED ((QSC_DILITHIUM_N * 4) / 8)
#define DILITHIUM_QBITS 23
#define DILITHIUM_UNITYROOT 1753
 /* 2^32 % QSC_DILITHIUM_Q */
#define DILITHIUM_MONT 4193792U
 /* -q^(-1) mod 2^32 */
#define DILITHIUM_QINV 4236238847U

/*!
\def DILITHIUM_PUBLICKEY_SIZE
* Read Only: The public key size in bytes
*/
#define DILITHIUM_PUBLICKEY_SIZE (QSC_DILITHIUM_SEED_SIZE + QSC_DILITHIUM_K * DILITHIUM_POLT1_SIZE_PACKED)

/*!
\def DILITHIUM_SECRETKEY_SIZE
* Read Only: The private key size in bytes
*/
#define DILITHIUM_SECRETKEY_SIZE (2 * QSC_DILITHIUM_SEED_SIZE + (QSC_DILITHIUM_L + QSC_DILITHIUM_K) * DILITHIUM_POLETA_SIZE_PACKED + QSC_DILITHIUM_CRH_SIZE + QSC_DILITHIUM_K * DILITHIUM_POLT0_SIZE_PACKED)

/*!
\def DILITHIUM_SIGNATURE_SIZE
* Read Only: The signature size in bytes
*/
#define DILITHIUM_SIGNATURE_SIZE (QSC_DILITHIUM_L * DILITHIUM_POLZ_SIZE_PACKED + (QSC_DILITHIUM_OMEGA + QSC_DILITHIUM_K) + (QSC_DILITHIUM_N / 8 + 8))

/* qsc_dilithium_ntt.c */

/* Roots of unity in order needed by forward qsc_dilithium_ntt */
static const uint32_t zetas[QSC_DILITHIUM_N] =
{
	0x00000000UL, 0x000064F7UL, 0x00581103UL, 0x0077F504UL, 0x00039E44UL, 0x00740119UL, 0x00728129UL, 0x00071E24UL,
	0x001BDE2BUL, 0x0023E92BUL, 0x007A64AEUL, 0x005FF480UL, 0x002F9A75UL, 0x0053DB0AUL, 0x002F7A49UL, 0x0028E527UL,
	0x00299658UL, 0x000FA070UL, 0x006F65A5UL, 0x0036B788UL, 0x00777D91UL, 0x006ECAA1UL, 0x0027F968UL, 0x005FB37CUL,
	0x005F8DD7UL, 0x0044FAE8UL, 0x006A84F8UL, 0x004DDC99UL, 0x001AD035UL, 0x007F9423UL, 0x003D3201UL, 0x000445C5UL,
	0x00294A67UL, 0x00017620UL, 0x002EF4CDUL, 0x0035DEC5UL, 0x00668504UL, 0x0049102DUL, 0x005927D5UL, 0x003BBEAFUL,
	0x0044F586UL, 0x00516E7DUL, 0x00368A96UL, 0x00541E42UL, 0x00360400UL, 0x007B4A4EUL, 0x0023D69CUL, 0x0077A55EUL,
	0x0065F23EUL, 0x0066CAD7UL, 0x00357E1EUL, 0x00458F5AUL, 0x0035843FUL, 0x005F3618UL, 0x0067745DUL, 0x0038738CUL,
	0x000C63A8UL, 0x00081B9AUL, 0x000E8F76UL, 0x003B3853UL, 0x003B8534UL, 0x0058DC31UL, 0x001F9D54UL, 0x00552F2EUL,
	0x0043E6E6UL, 0x00688C82UL, 0x0047C1D0UL, 0x0051781AUL, 0x0069B65EUL, 0x003509EEUL, 0x002135C7UL, 0x0067AFBCUL,
	0x006CAF76UL, 0x001D9772UL, 0x00419073UL, 0x00709CF7UL, 0x004F3281UL, 0x004FB2AFUL, 0x004870E1UL, 0x0001EFCAUL,
	0x003410F2UL, 0x0070DE86UL, 0x0020C638UL, 0x00296E9FUL, 0x005297A4UL, 0x0047844CUL, 0x00799A6EUL, 0x005A140AUL,
	0x0075A283UL, 0x006D2114UL, 0x007F863CUL, 0x006BE9F8UL, 0x007A0BDEUL, 0x001495D4UL, 0x001C4563UL, 0x006A0C63UL,
	0x004CDBEAUL, 0x00040AF0UL, 0x0007C417UL, 0x002F4588UL, 0x0000AD00UL, 0x006F16BFUL, 0x000DCD44UL, 0x003C675AUL,
	0x00470BCBUL, 0x007FBE7FUL, 0x00193948UL, 0x004E49C1UL, 0x0024756CUL, 0x007CA7E0UL, 0x000B98A1UL, 0x006BC809UL,
	0x0002E46CUL, 0x0049A809UL, 0x003036C2UL, 0x00639FF7UL, 0x005B1C94UL, 0x007D2AE1UL, 0x00141305UL, 0x00147792UL,
	0x00139E25UL, 0x0067B0E1UL, 0x00737945UL, 0x0069E803UL, 0x0051CEA3UL, 0x0044A79DUL, 0x00488058UL, 0x003A97D9UL,
	0x001FEA93UL, 0x0033FF5AUL, 0x002358D4UL, 0x003A41F8UL, 0x004CDF73UL, 0x00223DFBUL, 0x005A8BA0UL, 0x00498423UL,
	0x000412F5UL, 0x00252587UL, 0x006D04F1UL, 0x00359B5DUL, 0x004A28A1UL, 0x004682FDUL, 0x006D9B57UL, 0x004F25DFUL,
	0x000DBE5EUL, 0x001C5E1AUL, 0x000DE0E6UL, 0x000C7F5AUL, 0x00078F83UL, 0x0067428BUL, 0x007F3705UL, 0x0077E6FDUL,
	0x0075E022UL, 0x00503AF7UL, 0x001F0084UL, 0x0030EF86UL, 0x0049997EUL, 0x0077DCD7UL, 0x00742593UL, 0x004901C3UL,
	0x00053919UL, 0x0004610CUL, 0x005AAD42UL, 0x003EB01BUL, 0x003472E7UL, 0x004CE03CUL, 0x001A7CC7UL, 0x00031924UL,
	0x002B5EE5UL, 0x00291199UL, 0x00585A3BUL, 0x00134D71UL, 0x003DE11CUL, 0x00130984UL, 0x0025F051UL, 0x00185A46UL,
	0x00466519UL, 0x001314BEUL, 0x00283891UL, 0x0049BB91UL, 0x0052308AUL, 0x001C853FUL, 0x001D0B4BUL, 0x006FD6A7UL,
	0x006B88BFUL, 0x0012E11BUL, 0x004D3E3FUL, 0x006A0D30UL, 0x0078FDE5UL, 0x001406C7UL, 0x00327283UL, 0x0061ED6FUL,
	0x006C5954UL, 0x001D4099UL, 0x00590579UL, 0x006AE5AEUL, 0x0016E405UL, 0x000BDBE7UL, 0x00221DE8UL, 0x0033F8CFUL,
	0x00779935UL, 0x0054AA0DUL, 0x00665FF9UL, 0x0063B158UL, 0x0058711CUL, 0x00470C13UL, 0x000910D8UL, 0x00463E20UL,
	0x00612659UL, 0x00251D8BUL, 0x002573B7UL, 0x007D5C90UL, 0x001DDD98UL, 0x00336898UL, 0x0002D4BBUL, 0x006D73A8UL,
	0x004F4CBFUL, 0x00027C1CUL, 0x0018AA08UL, 0x002DFD71UL, 0x000C5CA5UL, 0x0019379AUL, 0x00478168UL, 0x00646C3EUL,
	0x0051813DUL, 0x0035C539UL, 0x003B0115UL, 0x00041DC0UL, 0x0021C4F7UL, 0x0070FBF5UL, 0x001A35E7UL, 0x0007340EUL,
	0x00795D46UL, 0x001A4CD0UL, 0x00645CAFUL, 0x001D2668UL, 0x00666E99UL, 0x006F0634UL, 0x007BE5DBUL, 0x00455FDCUL,
	0x00530765UL, 0x005DC1B0UL, 0x007973DEUL, 0x005CFD0AUL, 0x0002CC93UL, 0x0070F806UL, 0x00189C2AUL, 0x0049C5AAUL,
	0x00776A51UL, 0x003BCF2CUL, 0x007F234FUL, 0x006B16E0UL, 0x003C15CAUL, 0x00155E68UL, 0x0072F6B7UL, 0x001E29CEUL
};

/* Roots of unity in order needed by inverse qsc_dilithium_ntt */
static const uint32_t zetas_inv[QSC_DILITHIUM_N] =
{
	0x0061B633UL, 0x000CE94AUL, 0x006A8199UL, 0x0043CA37UL, 0x0014C921UL, 0x0000BCB2UL, 0x004410D5UL, 0x000875B0UL,
	0x00361A57UL, 0x006743D7UL, 0x000EE7FBUL, 0x007D136EUL, 0x0022E2F7UL, 0x00066C23UL, 0x00221E51UL, 0x002CD89CUL,
	0x003A8025UL, 0x0003FA26UL, 0x0010D9CDUL, 0x00197168UL, 0x0062B999UL, 0x001B8352UL, 0x00659331UL, 0x000682BBUL,
	0x0078ABF3UL, 0x0065AA1AUL, 0x000EE40CUL, 0x005E1B0AUL, 0x007BC241UL, 0x0044DEECUL, 0x004A1AC8UL, 0x002E5EC4UL,
	0x001B73C3UL, 0x00385E99UL, 0x0066A867UL, 0x0073835CUL, 0x0051E290UL, 0x006735F9UL, 0x007D63E5UL, 0x00309342UL,
	0x00126C59UL, 0x007D0B46UL, 0x004C7769UL, 0x00620269UL, 0x00028371UL, 0x005A6C4AUL, 0x005AC276UL, 0x001EB9A8UL,
	0x0039A1E1UL, 0x0076CF29UL, 0x0038D3EEUL, 0x00276EE5UL, 0x001C2EA9UL, 0x00198008UL, 0x002B35F4UL, 0x000846CCUL,
	0x004BE732UL, 0x005DC219UL, 0x0074041AUL, 0x0068FBFCUL, 0x0014FA53UL, 0x0026DA88UL, 0x00629F68UL, 0x001386ADUL,
	0x001DF292UL, 0x004D6D7EUL, 0x006BD93AUL, 0x0006E21CUL, 0x0015D2D1UL, 0x0032A1C2UL, 0x006CFEE6UL, 0x00145742UL,
	0x0010095AUL, 0x0062D4B6UL, 0x00635AC2UL, 0x002DAF77UL, 0x00362470UL, 0x0057A770UL, 0x006CCB43UL, 0x00397AE8UL,
	0x006785BBUL, 0x0059EFB0UL, 0x006CD67DUL, 0x0041FEE5UL, 0x006C9290UL, 0x002785C6UL, 0x0056CE68UL, 0x0054811CUL,
	0x007CC6DDUL, 0x0065633AUL, 0x0032FFC5UL, 0x004B6D1AUL, 0x00412FE6UL, 0x002532BFUL, 0x007B7EF5UL, 0x007AA6E8UL,
	0x0036DE3EUL, 0x000BBA6EUL, 0x0008032AUL, 0x00364683UL, 0x004EF07BUL, 0x0060DF7DUL, 0x002FA50AUL, 0x0009FFDFUL,
	0x0007F904UL, 0x0000A8FCUL, 0x00189D76UL, 0x0078507EUL, 0x007360A7UL, 0x0071FF1BUL, 0x006381E7UL, 0x007221A3UL,
	0x0030BA22UL, 0x001244AAUL, 0x00395D04UL, 0x0035B760UL, 0x004A44A4UL, 0x0012DB10UL, 0x005ABA7AUL, 0x007BCD0CUL,
	0x00365BDEUL, 0x00255461UL, 0x005DA206UL, 0x0033008EUL, 0x00459E09UL, 0x005C872DUL, 0x004BE0A7UL, 0x005FF56EUL,
	0x00454828UL, 0x00375FA9UL, 0x003B3864UL, 0x002E115EUL, 0x0015F7FEUL, 0x000C66BCUL, 0x00182F20UL, 0x006C41DCUL,
	0x006B686FUL, 0x006BCCFCUL, 0x0002B520UL, 0x0024C36DUL, 0x001C400AUL, 0x004FA93FUL, 0x003637F8UL, 0x007CFB95UL,
	0x001417F8UL, 0x00744760UL, 0x00033821UL, 0x005B6A95UL, 0x00319640UL, 0x0066A6B9UL, 0x00002182UL, 0x0038D436UL,
	0x004378A7UL, 0x007212BDUL, 0x0010C942UL, 0x007F3301UL, 0x00509A79UL, 0x00781BEAUL, 0x007BD511UL, 0x00330417UL,
	0x0015D39EUL, 0x00639A9EUL, 0x006B4A2DUL, 0x0005D423UL, 0x0013F609UL, 0x000059C5UL, 0x0012BEEDUL, 0x000A3D7EUL,
	0x0025CBF7UL, 0x00064593UL, 0x00385BB5UL, 0x002D485DUL, 0x00567162UL, 0x005F19C9UL, 0x000F017BUL, 0x004BCF0FUL,
	0x007DF037UL, 0x00376F20UL, 0x00302D52UL, 0x0030AD80UL, 0x000F430AUL, 0x003E4F8EUL, 0x0062488FUL, 0x0013308BUL,
	0x00183045UL, 0x005EAA3AUL, 0x004AD613UL, 0x001629A3UL, 0x002E67E7UL, 0x00381E31UL, 0x0017537FUL, 0x003BF91BUL,
	0x002AB0D3UL, 0x006042ADUL, 0x002703D0UL, 0x00445ACDUL, 0x0044A7AEUL, 0x0071508BUL, 0x0077C467UL, 0x00737C59UL,
	0x00476C75UL, 0x00186BA4UL, 0x0020A9E9UL, 0x004A5BC2UL, 0x003A50A7UL, 0x004A61E3UL, 0x0019152AUL, 0x0019EDC3UL,
	0x00083AA3UL, 0x005C0965UL, 0x000495B3UL, 0x0049DC01UL, 0x002BC1BFUL, 0x0049556BUL, 0x002E7184UL, 0x003AEA7BUL,
	0x00442152UL, 0x0026B82CUL, 0x0036CFD4UL, 0x00195AFDUL, 0x004A013CUL, 0x0050EB34UL, 0x007E69E1UL, 0x0056959AUL,
	0x007B9A3CUL, 0x0042AE00UL, 0x00004BDEUL, 0x00650FCCUL, 0x00320368UL, 0x00155B09UL, 0x003AE519UL, 0x0020522AUL,
	0x00202C85UL, 0x0057E699UL, 0x00111560UL, 0x00086270UL, 0x00492879UL, 0x00107A5CUL, 0x00703F91UL, 0x005649A9UL,
	0x0056FADAUL, 0x005065B8UL, 0x002C04F7UL, 0x0050458CUL, 0x001FEB81UL, 0x00057B53UL, 0x005BF6D6UL, 0x006401D6UL,
	0x0078C1DDUL, 0x000D5ED8UL, 0x000BDEE8UL, 0x007C41BDUL, 0x0007EAFDUL, 0x0027CEFEUL, 0x007F7B0AUL, 0x00000000UL
};

void qsc_dilithium_ntt(uint32_t p[QSC_DILITHIUM_N])
{
	size_t j;
	size_t k;
	size_t len;
	size_t start;
	uint32_t t;
	uint32_t zeta;

	k = 1;

	for (len = 128; len > 0; len >>= 1)
	{
		for (start = 0; start < QSC_DILITHIUM_N; start = j + len)
		{
			zeta = zetas[k];
			++k;

			for (j = start; j < start + len; ++j)
			{
				t = qsc_dilithium_montgomery_reduce((uint64_t)zeta * p[j + len]);
				p[j + len] = p[j] + (2 * QSC_DILITHIUM_Q) - t;
				p[j] = p[j] + t;
			}
		}
	}
}

void qsc_dilithium_invntt_frominvmont(uint32_t p[QSC_DILITHIUM_N])
{
	const uint32_t F = (((uint64_t)DILITHIUM_MONT * DILITHIUM_MONT % QSC_DILITHIUM_Q) * (QSC_DILITHIUM_Q - 1) % QSC_DILITHIUM_Q) * ((uint32_t)(QSC_DILITHIUM_Q - 1) >> 8) % QSC_DILITHIUM_Q;
	size_t j;
	size_t k;
	size_t len;
	size_t start;
	uint32_t t;
	uint32_t zeta;

	k = 0;

	for (len = 1; len < QSC_DILITHIUM_N; len <<= 1)
	{
		for (start = 0; start < QSC_DILITHIUM_N; start = j + len)
		{
			zeta = zetas_inv[k];
			++k;

			for (j = start; j < start + len; ++j)
			{
				t = p[j];
				p[j] = t + p[j + len];
				p[j + len] = t + (256 * QSC_DILITHIUM_Q) - p[j + len];
				p[j + len] = qsc_dilithium_montgomery_reduce((uint64_t)zeta * p[j + len]);
			}
		}
	}

	for (j = 0; j < QSC_DILITHIUM_N; ++j)
	{
		p[j] = qsc_dilithium_montgomery_reduce((uint64_t)F * p[j]);
	}
}

/* qsc_dilithium_poly.c */

void qsc_dilithium_poly_reduce(qsc_dilithium_poly* a)
{
	size_t i;

	for (i = 0; i < QSC_DILITHIUM_N; ++i)
	{
		a->coeffs[i] = qsc_dilithium_reduce32(a->coeffs[i]);
	}
}

void qsc_dilithium_poly_csubq(qsc_dilithium_poly* a)
{
	size_t i;

	for (i = 0; i < QSC_DILITHIUM_N; ++i)
	{
		a->coeffs[i] = qsc_dilithium_csubq(a->coeffs[i]);
	}
}

void qsc_dilithium_poly_freeze(qsc_dilithium_poly* a)
{
	size_t i;

	for (i = 0; i < QSC_DILITHIUM_N; ++i)
	{
		a->coeffs[i] = qsc_dilithium_freeze(a->coeffs[i]);
	}
}

void qsc_dilithium_poly_add(qsc_dilithium_poly* c, const qsc_dilithium_poly* a, const qsc_dilithium_poly* b)
{
	size_t i;

	for (i = 0; i < QSC_DILITHIUM_N; ++i)
	{
		c->coeffs[i] = a->coeffs[i] + b->coeffs[i];
	}
}

void qsc_dilithium_poly_sub(qsc_dilithium_poly* c, const qsc_dilithium_poly* a, const qsc_dilithium_poly* b)
{
	size_t i;

	for (i = 0; i < QSC_DILITHIUM_N; ++i)
	{
		c->coeffs[i] = a->coeffs[i] + (2 * QSC_DILITHIUM_Q) - b->coeffs[i];
	}
}

void qsc_dilithium_poly_shiftl(qsc_dilithium_poly* a)
{
	size_t i;

	for (i = 0; i < QSC_DILITHIUM_N; ++i)
	{
		a->coeffs[i] <<= QSC_DILITHIUM_D;
	}
}

void qsc_dilithium_poly_ntt(qsc_dilithium_poly* a)
{
	qsc_dilithium_ntt(a->coeffs);
}

void qsc_dilithium_poly_invntt_montgomery(qsc_dilithium_poly* a)
{
	qsc_dilithium_invntt_frominvmont(a->coeffs);
}

void qsc_dilithium_poly_pointwise_invmontgomery(qsc_dilithium_poly* c, const qsc_dilithium_poly* a, const qsc_dilithium_poly* b)
{
	size_t i;

	for (i = 0; i < QSC_DILITHIUM_N; ++i)
	{
		c->coeffs[i] = qsc_dilithium_montgomery_reduce((uint64_t)a->coeffs[i] * b->coeffs[i]);
	}
}

void qsc_dilithium_poly_power2round(qsc_dilithium_poly* a1, qsc_dilithium_poly* a0, const qsc_dilithium_poly* a)
{
	size_t i;

	for (i = 0; i < QSC_DILITHIUM_N; ++i)
	{
		a1->coeffs[i] = qsc_dilithium_power2round(a->coeffs[i], &a0->coeffs[i]);
	}
}

void qsc_dilithium_poly_decompose(qsc_dilithium_poly* a1, qsc_dilithium_poly* a0, const qsc_dilithium_poly* a)
{
	size_t i;

	for (i = 0; i < QSC_DILITHIUM_N; ++i)
	{
		a1->coeffs[i] = qsc_dilithium_decompose(a->coeffs[i], &a0->coeffs[i]);
	}
}

uint32_t qsc_dilithium_poly_make_hint(qsc_dilithium_poly* h, const qsc_dilithium_poly* a0, const qsc_dilithium_poly* a1)
{
	size_t i;
	uint32_t s;

	s = 0;

	for (i = 0; i < QSC_DILITHIUM_N; ++i)
	{
		h->coeffs[i] = qsc_dilithium_make_hint(a0->coeffs[i], a1->coeffs[i]);
		s += h->coeffs[i];
	}

	return s;
}

void qsc_dilithium_poly_use_hint(qsc_dilithium_poly* a, const qsc_dilithium_poly* b, const qsc_dilithium_poly* h)
{
	size_t i;

	for (i = 0; i < QSC_DILITHIUM_N; ++i)
	{
		a->coeffs[i] = qsc_dilithium_use_hint(b->coeffs[i], h->coeffs[i]);
	}
}

int32_t qsc_dilithium_poly_chknorm(const qsc_dilithium_poly* a, uint32_t B)
{
	size_t i;
	int32_t s;
	int32_t t;

	/* It is ok to leak which coefficient violates the bound since
	   the probability for each coefficient is independent of secret
	   data but we must not leak the sign of the centralized representative. */

	s = 0;

	for (i = 0; i < QSC_DILITHIUM_N; ++i)
	{
		/* Absolute value of centralized representative */
		t = ((QSC_DILITHIUM_Q - 1) / 2) - a->coeffs[i];
		t ^= (t >> 31U);
		t = ((QSC_DILITHIUM_Q - 1) / 2) - t;

		if ((uint32_t)t >= B)
		{
			s = 1;
			break;
		}
	}

	return s;
}

/*************************************************
* Name:        rej_uniform
*
* Description: Sample uniformly random coefficients in [0, QSC_DILITHIUM_Q-1] by
*              performing rejection sampling using array of random bytes.
*
* Arguments:   - uint32_t *a: pointer to output array (allocated)
*              - uint32_t len: number of coefficients to be sampled
*              - const uint8_t *buf: array of random bytes
*              - uint32_t buflen: length of array of random bytes
*
* Returns number of sampled coefficients. Can be smaller than len if not enough
* random bytes were given.
**************************************************/
static uint32_t rej_uniform(uint32_t* a, uint32_t len, const uint8_t* buf, size_t buflen)
{
	size_t pos;
	size_t ctr;
	uint32_t t;

	ctr = 0;
	pos = 0;

	while (ctr < len && pos + 3 <= buflen)
	{
		t = buf[pos];
		++pos;
		t |= (uint32_t)buf[pos] << 8;
		++pos;
		t |= (uint32_t)buf[pos] << 16;
		++pos;
		t &= 0x007FFFFFUL;

		if (t < QSC_DILITHIUM_Q)
		{
			a[ctr] = t;
			++ctr;
		}
	}

	return (uint32_t)ctr;
}

void qsc_dilithium_poly_uniform(qsc_dilithium_poly* a, const uint8_t seed[QSC_DILITHIUM_SEED_SIZE], uint16_t nonce)
{
	const size_t NBLKS = (769 + QSC_KECCAK_128_RATE) / QSC_KECCAK_128_RATE;
	uint8_t buf[(((769 + QSC_KECCAK_128_RATE) / QSC_KECCAK_128_RATE) * QSC_KECCAK_128_RATE) + 2];
	qsc_keccak_state kstate;
	uint8_t tmps[QSC_DILITHIUM_SEED_SIZE + 2];
	size_t buflen;
	size_t i;
	size_t off;
	uint32_t ctr;

	for (i = 0; i < QSC_KECCAK_STATE_SIZE; ++i)
	{
		kstate.state[i] = 0;
	}

	buflen = NBLKS * QSC_KECCAK_128_RATE;

	for (i = 0; i < QSC_DILITHIUM_SEED_SIZE; ++i)
	{
		tmps[i] = seed[i];
	}

	tmps[QSC_DILITHIUM_SEED_SIZE] = (uint8_t)nonce;
	tmps[QSC_DILITHIUM_SEED_SIZE + 1] = nonce >> 8;
	qsc_shake_initialize(&kstate, keccak_rate_128, tmps, QSC_DILITHIUM_SEED_SIZE + 2);
	qsc_shake_squeezeblocks(&kstate, keccak_rate_128, buf, NBLKS);

	ctr = rej_uniform(a->coeffs, QSC_DILITHIUM_N, buf, buflen);

	while (ctr < QSC_DILITHIUM_N)
	{
		off = buflen % 3;

		for (i = 0; i < off; ++i)
		{
			buf[i] = buf[buflen - off + i];
		}

		buflen = QSC_KECCAK_128_RATE + off;
		qsc_shake_squeezeblocks(&kstate, keccak_rate_128, buf + off, 1);
		ctr += rej_uniform(a->coeffs + ctr, QSC_DILITHIUM_N - ctr, buf, buflen);
	}
}

/*************************************************
* Name:        rej_eta
*
* Description: Sample uniformly random coefficients in [-QSC_DILITHIUM_ETA, QSC_DILITHIUM_ETA] by
*              performing rejection sampling using array of random bytes.
*
* Arguments:   - uint32_t *a: pointer to output array (allocated)
*              - uint32_t len: number of coefficients to be sampled
*              - const uint8_t *buf: array of random bytes
*              - uint32_t buflen: length of array of random bytes
*
* Returns number of sampled coefficients. Can be smaller than len if not enough
* random bytes were given.
**************************************************/
static uint32_t rej_eta(uint32_t* a, uint32_t len, const uint8_t *buf, size_t buflen)
{
#if QSC_DILITHIUM_ETA > 7
#error "rej_eta() assumes QSC_DILITHIUM_ETA <= 7"
#endif

	size_t ctr;
	size_t pos;
	uint32_t t0;
	uint32_t t1;

	ctr = 0;
	pos = 0;

	while (ctr < len && pos < buflen)
	{
#if QSC_DILITHIUM_ETA <= 3
		t0 = buf[pos] & 0x07;
		t1 = buf[pos] >> 5;
		++pos;
#else
		t0 = buf[pos] & 0x0FU;
		t1 = buf[pos] >> 4;
		++pos;
#endif

		if (t0 <= 2 * QSC_DILITHIUM_ETA)
		{
			a[ctr] = QSC_DILITHIUM_Q + QSC_DILITHIUM_ETA - t0;
			++ctr;
		}

		if (t1 <= 2 * QSC_DILITHIUM_ETA && ctr < len)
		{
			a[ctr] = QSC_DILITHIUM_Q + QSC_DILITHIUM_ETA - t1;
			++ctr;
		}
	}

	return (uint32_t)ctr;
}

void qsc_dilithium_poly_uniform_eta(qsc_dilithium_poly* a, const uint8_t seed[QSC_DILITHIUM_SEED_SIZE], uint16_t nonce)
{
	const size_t NBLKS = ((QSC_DILITHIUM_N / 2 * (1U << QSC_DILITHIUM_SETABITS)) / (2 * QSC_DILITHIUM_ETA + 1) + QSC_KECCAK_128_RATE) / QSC_KECCAK_128_RATE;
	uint8_t buf[(((QSC_DILITHIUM_N / 2 * (1U << QSC_DILITHIUM_SETABITS)) / (2 * QSC_DILITHIUM_ETA + 1) + QSC_KECCAK_128_RATE) / QSC_KECCAK_128_RATE) * QSC_KECCAK_128_RATE];
	qsc_keccak_state kstate;
	uint8_t tmps[QSC_DILITHIUM_SEED_SIZE + 2];
	size_t buflen;
	size_t i;
	uint32_t ctr;

	buflen = NBLKS * QSC_KECCAK_128_RATE;

	for (i = 0; i < QSC_KECCAK_STATE_SIZE; ++i)
	{
		kstate.state[i] = 0;
	}

	for (i = 0; i < QSC_DILITHIUM_SEED_SIZE; ++i)
	{
		tmps[i] = seed[i];
	}

	tmps[QSC_DILITHIUM_SEED_SIZE] = (uint8_t)nonce;
	tmps[QSC_DILITHIUM_SEED_SIZE + 1] = nonce >> 8;
	qsc_shake_initialize(&kstate, keccak_rate_128, tmps, QSC_DILITHIUM_SEED_SIZE + 2);
	qsc_shake_squeezeblocks(&kstate, keccak_rate_128, buf, NBLKS);

	ctr = rej_eta(a->coeffs, QSC_DILITHIUM_N, buf, buflen);

	while (ctr < QSC_DILITHIUM_N)
	{
		qsc_shake_squeezeblocks(&kstate, keccak_rate_128, buf, 1);
		ctr += rej_eta(a->coeffs + ctr, QSC_DILITHIUM_N - ctr, buf, QSC_KECCAK_128_RATE);
	}
}

/*************************************************
* Name:        rej_gamma1m1
*
* Description: Sample uniformly random coefficients
*              in [-(QSC_DILITHIUM_GAMMA1 - 1), QSC_DILITHIUM_GAMMA1 - 1] by performing rejection sampling
*              using array of random bytes.
*
* Arguments:   - uint32_t *a: pointer to output array (allocated)
*              - uint32_t len: number of coefficients to be sampled
*              - const uint8_t *buf: array of random bytes
*              - uint32_t buflen: length of array of random bytes
*
* Returns number of sampled coefficients. Can be smaller than len if not enough
* random bytes were given.
**************************************************/
static uint32_t rej_gamma1m1(uint32_t* a, uint32_t len, const uint8_t* buf, size_t buflen)
{
#if QSC_DILITHIUM_GAMMA1 > (1 << 19)
#error "rej_gamma1m1() assumes QSC_DILITHIUM_GAMMA1 - 1 fits in 19 bits"
#endif

	size_t ctr;
	size_t pos;
	uint32_t t0;
	uint32_t t1;

	ctr = 0;
	pos = 0;

	while (ctr < len && pos + 5 <= buflen)
	{
		t0 = buf[pos];
		t0 |= (uint32_t)buf[pos + 1] << 8;
		t0 |= (uint32_t)buf[pos + 2] << 16;
		t0 &= 0x000FFFFFUL;

		t1 = buf[pos + 2] >> 4;
		t1 |= (uint32_t)buf[pos + 3] << 4;
		t1 |= (uint32_t)buf[pos + 4] << 12;

		pos += 5;

		if (t0 <= (2 * QSC_DILITHIUM_GAMMA1) - 2)
		{
			a[ctr] = QSC_DILITHIUM_Q + QSC_DILITHIUM_GAMMA1 - 1 - t0;
			++ctr;
		}

		if (t1 <= (2 * QSC_DILITHIUM_GAMMA1) - 2 && ctr < len)
		{
			a[ctr] = QSC_DILITHIUM_Q + QSC_DILITHIUM_GAMMA1 - 1 - t1;
			++ctr;
		}
	}

	return (uint32_t)ctr;
}

void qsc_dilithium_poly_uniform_gamma1m1(qsc_dilithium_poly* a, const uint8_t seed[QSC_DILITHIUM_CRH_SIZE], uint16_t nonce)
{
	const size_t NBLKS = (641 + QSC_KECCAK_256_RATE) / QSC_KECCAK_256_RATE;
	uint8_t buf[(((641 + QSC_KECCAK_256_RATE) / QSC_KECCAK_256_RATE) * QSC_KECCAK_256_RATE) + 4];
	qsc_keccak_state kstate;
	uint8_t tmps[QSC_DILITHIUM_CRH_SIZE + 2];
	size_t buflen;
	size_t i;
	size_t off;
	uint32_t ctr;

	for (i = 0; i < QSC_KECCAK_STATE_SIZE; ++i)
	{
		kstate.state[i] = 0;
	}

	for (i = 0; i < QSC_DILITHIUM_CRH_SIZE; ++i)
	{
		tmps[i] = seed[i];
	}

	tmps[QSC_DILITHIUM_CRH_SIZE] = (uint8_t)nonce;
	tmps[QSC_DILITHIUM_CRH_SIZE + 1] = nonce >> 8;
	qsc_shake_initialize(&kstate, keccak_rate_256, tmps, QSC_DILITHIUM_CRH_SIZE + 2);
	qsc_shake_squeezeblocks(&kstate, keccak_rate_256, buf, NBLKS);
	buflen = NBLKS * QSC_KECCAK_256_RATE;

	ctr = rej_gamma1m1(a->coeffs, QSC_DILITHIUM_N, buf, buflen);

	while (ctr < QSC_DILITHIUM_N)
	{
		off = buflen % 5;

		for (i = 0; i < off; ++i)
		{
			buf[i] = buf[buflen - off + i];
		}

		buflen = QSC_KECCAK_256_RATE + off;
		qsc_shake_squeezeblocks(&kstate, keccak_rate_256, buf + off, 1);
		ctr += rej_gamma1m1(a->coeffs + ctr, QSC_DILITHIUM_N - ctr, buf, buflen);
	}
}

void qsc_dilithium_polyeta_pack(uint8_t* r, const qsc_dilithium_poly* a)
{
#if 2 * QSC_DILITHIUM_ETA >= 16
#	error "qsc_dilithium_polyeta_pack() assumes 2*QSC_DILITHIUM_ETA < 16"
#endif
	size_t i;
	uint8_t t[8];

#if (2 * QSC_DILITHIUM_ETA) <= 7

	for (i = 0; i < QSC_DILITHIUM_N / 8; ++i)
	{
		t[0] = QSC_DILITHIUM_Q + QSC_DILITHIUM_ETA - a->coeffs[(8 * i)];
		t[1] = QSC_DILITHIUM_Q + QSC_DILITHIUM_ETA - a->coeffs[(8 * i) + 1];
		t[2] = QSC_DILITHIUM_Q + QSC_DILITHIUM_ETA - a->coeffs[(8 * i) + 2];
		t[3] = QSC_DILITHIUM_Q + QSC_DILITHIUM_ETA - a->coeffs[(8 * i) + 3];
		t[4] = QSC_DILITHIUM_Q + QSC_DILITHIUM_ETA - a->coeffs[(8 * i) + 4];
		t[5] = QSC_DILITHIUM_Q + QSC_DILITHIUM_ETA - a->coeffs[(8 * i) + 5];
		t[6] = QSC_DILITHIUM_Q + QSC_DILITHIUM_ETA - a->coeffs[(8 * i) + 6];
		t[7] = QSC_DILITHIUM_Q + QSC_DILITHIUM_ETA - a->coeffs[(8 * i) + 7];

		r[(3 * i)] = (t[0] >> 0) | (t[1] << 3) | (t[2] << 6);
		r[(3 * i) + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
		r[(3 * i) + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
	}

#else

	for (i = 0; i < QSC_DILITHIUM_N / 2; ++i)
	{
		t[0] = QSC_DILITHIUM_Q + QSC_DILITHIUM_ETA - a->coeffs[(2 * i)];
		t[1] = QSC_DILITHIUM_Q + QSC_DILITHIUM_ETA - a->coeffs[(2 * i) + 1];
		r[i] = t[0] | (uint8_t)(t[1] << 4);
	}

#endif
}

void qsc_dilithium_polyeta_unpack(qsc_dilithium_poly* r, const uint8_t* a)
{
	size_t i;

#if (2 * QSC_DILITHIUM_ETA) <= 7

	for (i = 0; i < QSC_DILITHIUM_N / 8; ++i)
	{
		r->coeffs[(8 * i)] = a[3 * i] & 0x07;
		r->coeffs[(8 * i) + 1] = (a[3 * i] >> 3) & 0x07;
		r->coeffs[(8 * i) + 2] = ((a[3 * i] >> 6) | (a[(3 * i) + 1] << 2)) & 0x07;
		r->coeffs[(8 * i) + 3] = (a[(3 * i) + 1] >> 1) & 0x07;
		r->coeffs[(8 * i) + 4] = (a[(3 * i) + 1] >> 4) & 0x07;
		r->coeffs[(8 * i) + 5] = ((a[(3 * i) + 1] >> 7) | (a[(3 * i) + 2] << 1)) & 0x07;
		r->coeffs[(8 * i) + 6] = (a[(3 * i) + 2] >> 2) & 0x07;
		r->coeffs[(8 * i) + 7] = (a[(3 * i) + 2] >> 5) & 0x07;

		r->coeffs[(8 * i)] = QSC_DILITHIUM_Q + QSC_DILITHIUM_ETA - r->coeffs[(8 * i)];
		r->coeffs[(8 * i) + 1] = QSC_DILITHIUM_Q + QSC_DILITHIUM_ETA - r->coeffs[(8 * i) + 1];
		r->coeffs[(8 * i) + 2] = QSC_DILITHIUM_Q + QSC_DILITHIUM_ETA - r->coeffs[(8 * i) + 2];
		r->coeffs[(8 * i) + 3] = QSC_DILITHIUM_Q + QSC_DILITHIUM_ETA - r->coeffs[(8 * i) + 3];
		r->coeffs[(8 * i) + 4] = QSC_DILITHIUM_Q + QSC_DILITHIUM_ETA - r->coeffs[(8 * i) + 4];
		r->coeffs[(8 * i) + 5] = QSC_DILITHIUM_Q + QSC_DILITHIUM_ETA - r->coeffs[(8 * i) + 5];
		r->coeffs[(8 * i) + 6] = QSC_DILITHIUM_Q + QSC_DILITHIUM_ETA - r->coeffs[(8 * i) + 6];
		r->coeffs[(8 * i) + 7] = QSC_DILITHIUM_Q + QSC_DILITHIUM_ETA - r->coeffs[(8 * i) + 7];
	}

#else

	for (i = 0; i < QSC_DILITHIUM_N / 2; ++i)
	{
		r->coeffs[(2 * i)] = a[i] & 0x0Fu;
		r->coeffs[(2 * i) + 1] = a[i] >> 4;
		r->coeffs[(2 * i)] = QSC_DILITHIUM_Q + QSC_DILITHIUM_ETA - r->coeffs[2 * i];
		r->coeffs[(2 * i) + 1] = QSC_DILITHIUM_Q + QSC_DILITHIUM_ETA - r->coeffs[(2 * i) + 1];
	}

#endif
}

void qsc_dilithium_polyt1_pack(uint8_t* r, const qsc_dilithium_poly* a)
{
#if QSC_DILITHIUM_D != 14
#error "qsc_dilithium_polyt1_pack() assumes QSC_DILITHIUM_D == 14"
#endif

	size_t i;

	for (i = 0; i < QSC_DILITHIUM_N / 8; ++i)
	{
		r[(9 * i)] = (a->coeffs[(8 * i)] >> 0);
		r[(9 * i) + 1] = (a->coeffs[(8 * i)] >> 8) | (a->coeffs[(8 * i) + 1] << 1);
		r[(9 * i) + 2] = (a->coeffs[(8 * i) + 1] >> 7) | (a->coeffs[(8 * i) + 2] << 2);
		r[(9 * i) + 3] = (a->coeffs[(8 * i) + 2] >> 6) | (a->coeffs[(8 * i) + 3] << 3);
		r[(9 * i) + 4] = (a->coeffs[(8 * i) + 3] >> 5) | (a->coeffs[(8 * i) + 4] << 4);
		r[(9 * i) + 5] = (a->coeffs[(8 * i) + 4] >> 4) | (a->coeffs[(8 * i) + 5] << 5);
		r[(9 * i) + 6] = (a->coeffs[(8 * i) + 5] >> 3) | (a->coeffs[(8 * i) + 6] << 6);
		r[(9 * i) + 7] = (a->coeffs[(8 * i) + 6] >> 2) | (a->coeffs[(8 * i) + 7] << 7);
		r[(9 * i) + 8] = (a->coeffs[(8 * i) + 7] >> 1);
	}
}

void qsc_dilithium_polyt1_unpack(qsc_dilithium_poly* r, const uint8_t* a)
{
	size_t i;

	for (i = 0; i < QSC_DILITHIUM_N / 8; ++i)
	{
		r->coeffs[(8 * i)] = (((uint32_t)a[(9 * i)]) | ((uint32_t)a[(9 * i) + 1] << 8)) & 0x000001FFUL;
		r->coeffs[(8 * i) + 1] = (((uint32_t)a[(9 * i) + 1] >> 1) | ((uint32_t)a[(9 * i) + 2] << 7)) & 0x000001FFUL;
		r->coeffs[(8 * i) + 2] = (((uint32_t)a[(9 * i) + 2] >> 2) | ((uint32_t)a[(9 * i) + 3] << 6)) & 0x000001FFUL;
		r->coeffs[(8 * i) + 3] = (((uint32_t)a[(9 * i) + 3] >> 3) | ((uint32_t)a[(9 * i) + 4] << 5)) & 0x000001FFUL;
		r->coeffs[(8 * i) + 4] = (((uint32_t)a[(9 * i) + 4] >> 4) | ((uint32_t)a[(9 * i) + 5] << 4)) & 0x000001FFUL;
		r->coeffs[(8 * i) + 5] = (((uint32_t)a[(9 * i) + 5] >> 5) | ((uint32_t)a[(9 * i) + 6] << 3)) & 0x000001FFUL;
		r->coeffs[(8 * i) + 6] = (((uint32_t)a[(9 * i) + 6] >> 6) | ((uint32_t)a[(9 * i) + 7] << 2)) & 0x000001FFUL;
		r->coeffs[(8 * i) + 7] = (((uint32_t)a[(9 * i) + 7] >> 7) | ((uint32_t)a[(9 * i) + 8] << 1)) & 0x000001FFUL;
	}
}

void qsc_dilithium_polyt0_pack(uint8_t* r, const qsc_dilithium_poly* a)
{
	size_t i;
	uint32_t t[4];

	for (i = 0; i < QSC_DILITHIUM_N / 4; ++i)
	{
		t[0] = QSC_DILITHIUM_Q + (1U << (QSC_DILITHIUM_D - 1)) - a->coeffs[(4 * i)];
		t[1] = QSC_DILITHIUM_Q + (1U << (QSC_DILITHIUM_D - 1)) - a->coeffs[(4 * i) + 1];
		t[2] = QSC_DILITHIUM_Q + (1U << (QSC_DILITHIUM_D - 1)) - a->coeffs[(4 * i) + 2];
		t[3] = QSC_DILITHIUM_Q + (1U << (QSC_DILITHIUM_D - 1)) - a->coeffs[(4 * i) + 3];

		r[(7 * i)] = t[0];
		r[(7 * i) + 1] = t[0] >> 8;
		r[(7 * i) + 1] |= t[1] << 6;
		r[(7 * i) + 2] = t[1] >> 2;
		r[(7 * i) + 3] = t[1] >> 10;
		r[(7 * i) + 3] |= t[2] << 4;
		r[(7 * i) + 4] = t[2] >> 4;
		r[(7 * i) + 5] = t[2] >> 12;
		r[(7 * i) + 5] |= t[3] << 2;
		r[(7 * i) + 6] = t[3] >> 6;
	}
}

void qsc_dilithium_polyt0_unpack(qsc_dilithium_poly* r, const uint8_t* a)
{
	size_t i;

	for (i = 0; i < QSC_DILITHIUM_N / 4; ++i)
	{
		r->coeffs[(4 * i)] = a[(7 * i)];
		r->coeffs[(4 * i)] |= (uint32_t)(a[(7 * i) + 1] & 0x3FU) << 8;

		r->coeffs[(4 * i) + 1] = a[(7 * i) + 1] >> 6;
		r->coeffs[(4 * i) + 1] |= (uint32_t)a[(7 * i) + 2] << 2;
		r->coeffs[(4 * i) + 1] |= (uint32_t)(a[(7 * i) + 3] & 0x0FU) << 10;

		r->coeffs[(4 * i) + 2] = a[(7 * i) + 3] >> 4;
		r->coeffs[(4 * i) + 2] |= (uint32_t)a[(7 * i) + 4] << 4;
		r->coeffs[(4 * i) + 2] |= (uint32_t)(a[(7 * i) + 5] & 0x03U) << 12;

		r->coeffs[(4 * i) + 3] = a[(7 * i) + 5] >> 2;
		r->coeffs[(4 * i) + 3] |= (uint32_t)a[(7 * i) + 6] << 6;

		r->coeffs[(4 * i)] = QSC_DILITHIUM_Q + (1U << (QSC_DILITHIUM_D - 1)) - r->coeffs[(4 * i)];
		r->coeffs[(4 * i) + 1] = QSC_DILITHIUM_Q + (1U << (QSC_DILITHIUM_D - 1)) - r->coeffs[(4 * i) + 1];
		r->coeffs[(4 * i) + 2] = QSC_DILITHIUM_Q + (1U << (QSC_DILITHIUM_D - 1)) - r->coeffs[(4 * i) + 2];
		r->coeffs[(4 * i) + 3] = QSC_DILITHIUM_Q + (1U << (QSC_DILITHIUM_D - 1)) - r->coeffs[(4 * i) + 3];
	}
}

void qsc_dilithium_polyz_pack(uint8_t* r, const qsc_dilithium_poly* a)
{
#if QSC_DILITHIUM_GAMMA1 > (1 << 19)
#error "qsc_dilithium_polyz_pack() assumes QSC_DILITHIUM_GAMMA1 <= 2^{19}"
#endif

	size_t i;
	uint32_t t[2];

	for (i = 0; i < QSC_DILITHIUM_N / 2; ++i)
	{
		/* Map to {0,...,2*QSC_DILITHIUM_GAMMA1 - 2} */
		t[0] = QSC_DILITHIUM_GAMMA1 - 1 - a->coeffs[(2 * i)];
		t[0] += ((int32_t)t[0] >> 31) & QSC_DILITHIUM_Q;
		t[1] = QSC_DILITHIUM_GAMMA1 - 1 - a->coeffs[(2 * i) + 1];
		t[1] += ((int32_t)t[1] >> 31) & QSC_DILITHIUM_Q;

		r[(5 * i)] = t[0];
		r[(5 * i) + 1] = t[0] >> 8;
		r[(5 * i) + 2] = t[0] >> 16;
		r[(5 * i) + 2] |= t[1] << 4;
		r[(5 * i) + 3] = t[1] >> 4;
		r[(5 * i) + 4] = t[1] >> 12;
	}
}

void qsc_dilithium_polyz_unpack(qsc_dilithium_poly* r, const uint8_t* a)
{
	size_t i;

	for (i = 0; i < QSC_DILITHIUM_N / 2; ++i)
	{
		r->coeffs[(2 * i)] = a[(5 * i)];
		r->coeffs[(2 * i)] |= (uint32_t)a[(5 * i) + 1] << 8;
		r->coeffs[(2 * i)] |= (uint32_t)(a[(5 * i) + 2] & 0x0FU) << 16;

		r->coeffs[(2 * i) + 1] = a[(5 * i) + 2] >> 4;
		r->coeffs[(2 * i) + 1] |= (uint32_t)a[(5 * i) + 3] << 4;
		r->coeffs[(2 * i) + 1] |= (uint32_t)a[(5 * i) + 4] << 12;

		r->coeffs[(2 * i)] = QSC_DILITHIUM_GAMMA1 - 1 - r->coeffs[(2 * i)];
		r->coeffs[(2 * i)] += ((int32_t)r->coeffs[(2 * i)] >> 31) & QSC_DILITHIUM_Q;
		r->coeffs[(2 * i) + 1] = QSC_DILITHIUM_GAMMA1 - 1 - r->coeffs[(2 * i) + 1];
		r->coeffs[(2 * i) + 1] += ((int32_t)r->coeffs[(2 * i) + 1] >> 31) & QSC_DILITHIUM_Q;
	}
}

void qsc_dilithium_polyw1_pack(uint8_t* r, const qsc_dilithium_poly* a)
{
	size_t i;

	for (i = 0; i < QSC_DILITHIUM_N / 2; ++i)
	{
		r[i] = a->coeffs[(2 * i)] | (a->coeffs[(2 * i) + 1] << 4);
	}
}

/* polyvec.c */

void qsc_dilithium_polyvecl_freeze(qsc_dilithium_polyvecl* v)
{
	size_t i;

	for (i = 0; i < QSC_DILITHIUM_L; ++i)
	{
		qsc_dilithium_poly_freeze(&v->vec[i]);
	}
}

void qsc_dilithium_polyvecl_add(qsc_dilithium_polyvecl* w, const qsc_dilithium_polyvecl* u, const qsc_dilithium_polyvecl* v)
{
	size_t i;

	for (i = 0; i < QSC_DILITHIUM_L; ++i)
	{
		qsc_dilithium_poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
	}
}

void qsc_dilithium_polyvecl_ntt(qsc_dilithium_polyvecl* v)
{
	size_t i;

	for (i = 0; i < QSC_DILITHIUM_L; ++i)
	{
		qsc_dilithium_poly_ntt(&v->vec[i]);
	}
}

void qsc_dilithium_polyvecl_pointwise_acc_invmontgomery(qsc_dilithium_poly* w, const qsc_dilithium_polyvecl* u, const qsc_dilithium_polyvecl* v)
{
	qsc_dilithium_poly t;
	size_t i;

	qsc_dilithium_poly_pointwise_invmontgomery(w, &u->vec[0], &v->vec[0]);

	for (i = 1; i < QSC_DILITHIUM_L; ++i)
	{
		qsc_dilithium_poly_pointwise_invmontgomery(&t, &u->vec[i], &v->vec[i]);
		qsc_dilithium_poly_add(w, w, &t);
	}
}

int32_t qsc_dilithium_polyvecl_chknorm(const qsc_dilithium_polyvecl* v, uint32_t bound)
{
	size_t i;
	int32_t r;

	r = 0;

	for (i = 0; i < QSC_DILITHIUM_L; ++i)
	{
		if (qsc_dilithium_poly_chknorm(&v->vec[i], bound))
		{
			r = 1;
			break;
		}
	}

	return r;
}

void qsc_dilithium_polyveck_reduce(qsc_dilithium_polyveck* v)
{
	size_t i;

	for (i = 0; i < QSC_DILITHIUM_K; ++i)
	{
		qsc_dilithium_poly_reduce(&v->vec[i]);
	}
}

void qsc_dilithium_polyveck_csubq(qsc_dilithium_polyveck* v)
{
	size_t i;

	for (i = 0; i < QSC_DILITHIUM_K; ++i)
	{
		qsc_dilithium_poly_csubq(&v->vec[i]);
	}
}

void qsc_dilithium_polyveck_freeze(qsc_dilithium_polyveck* v)
{
	size_t i;

	for (i = 0; i < QSC_DILITHIUM_K; ++i)
	{
		qsc_dilithium_poly_freeze(&v->vec[i]);
	}
}

void qsc_dilithium_polyveck_add(qsc_dilithium_polyveck* w, const qsc_dilithium_polyveck* u, const qsc_dilithium_polyveck* v)
{
	size_t i;

	for (i = 0; i < QSC_DILITHIUM_K; ++i)
	{
		qsc_dilithium_poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
	}
}

void qsc_dilithium_polyveck_sub(qsc_dilithium_polyveck* w, const qsc_dilithium_polyveck* u, const qsc_dilithium_polyveck* v)
{
	size_t i;

	for (i = 0; i < QSC_DILITHIUM_K; ++i)
	{
		qsc_dilithium_poly_sub(&w->vec[i], &u->vec[i], &v->vec[i]);
	}
}

void qsc_dilithium_polyveck_shiftl(qsc_dilithium_polyveck* v)
{
	size_t i;

	for (i = 0; i < QSC_DILITHIUM_K; ++i)
	{
		qsc_dilithium_poly_shiftl(&v->vec[i]);
	}
}

void qsc_dilithium_polyveck_ntt(qsc_dilithium_polyveck* v)
{
	size_t i;

	for (i = 0; i < QSC_DILITHIUM_K; ++i)
	{
		qsc_dilithium_poly_ntt(&v->vec[i]);
	}
}

void qsc_dilithium_polyveck_invntt_montgomery(qsc_dilithium_polyveck* v)
{
	size_t i;

	for (i = 0; i < QSC_DILITHIUM_K; ++i)
	{
		qsc_dilithium_poly_invntt_montgomery(&v->vec[i]);
	}
}

int32_t qsc_dilithium_polyveck_chknorm(const qsc_dilithium_polyveck* v, uint32_t bound)
{
	size_t i;
	int32_t r;

	r = 0;

	for (i = 0; i < QSC_DILITHIUM_K; ++i)
	{
		if (qsc_dilithium_poly_chknorm(&v->vec[i], bound))
		{
			r = 1;
			break;
		}
	}

	return r;
}

void qsc_dilithium_polyveck_power2round(qsc_dilithium_polyveck* v1, qsc_dilithium_polyveck* v0, const qsc_dilithium_polyveck* v)
{
	size_t i;

	for (i = 0; i < QSC_DILITHIUM_K; ++i)
	{
		qsc_dilithium_poly_power2round(&v1->vec[i], &v0->vec[i], &v->vec[i]);
	}
}

void qsc_dilithium_polyveck_decompose(qsc_dilithium_polyveck* v1, qsc_dilithium_polyveck* v0, const qsc_dilithium_polyveck* v)
{
	size_t i;

	for (i = 0; i < QSC_DILITHIUM_K; ++i)
	{
		qsc_dilithium_poly_decompose(&v1->vec[i], &v0->vec[i], &v->vec[i]);
	}
}

uint32_t qsc_dilithium_polyveck_make_hint(qsc_dilithium_polyveck* h, const qsc_dilithium_polyveck* v0, const qsc_dilithium_polyveck* v1)
{
	size_t i;
	uint32_t s;

	s = 0;

	for (i = 0; i < QSC_DILITHIUM_K; ++i)
	{
		s += qsc_dilithium_poly_make_hint(&h->vec[i], &v0->vec[i], &v1->vec[i]);
	}

	return s;
}

void qsc_dilithium_polyveck_use_hint(qsc_dilithium_polyveck* w, const qsc_dilithium_polyveck* u, const qsc_dilithium_polyveck* h)
{
	size_t i;

	for (i = 0; i < QSC_DILITHIUM_K; ++i)
	{
		qsc_dilithium_poly_use_hint(&w->vec[i], &u->vec[i], &h->vec[i]);
	}
}

/* packing.c */

void qsc_dilithium_pack_pk(uint8_t* pk, const uint8_t* rho, const qsc_dilithium_polyveck* t1)
{
	size_t i;

	for (i = 0; i < QSC_DILITHIUM_SEED_SIZE; ++i)
	{
		pk[i] = rho[i];
	}

	pk += QSC_DILITHIUM_SEED_SIZE;

	for (i = 0; i < QSC_DILITHIUM_K; ++i)
	{
		qsc_dilithium_polyt1_pack(pk + (i * DILITHIUM_POLT1_SIZE_PACKED), &t1->vec[i]);
	}
}

void qsc_dilithium_unpack_pk(uint8_t* rho, qsc_dilithium_polyveck* t1, const uint8_t* pk)
{
	size_t i;

	for (i = 0; i < QSC_DILITHIUM_SEED_SIZE; ++i)
	{
		rho[i] = pk[i];
	}

	pk += QSC_DILITHIUM_SEED_SIZE;

	for (i = 0; i < QSC_DILITHIUM_K; ++i)
	{
		qsc_dilithium_polyt1_unpack(&t1->vec[i], pk + (i * DILITHIUM_POLT1_SIZE_PACKED));
	}
}

void qsc_dilithium_pack_sk(uint8_t* sk, const uint8_t* rho, const uint8_t* key, const uint8_t* tr, const qsc_dilithium_polyvecl* s1, const qsc_dilithium_polyveck* s2, const qsc_dilithium_polyveck* t0)
{
	size_t i;

	for (i = 0; i < QSC_DILITHIUM_SEED_SIZE; ++i)
	{
		sk[i] = rho[i];
	}

	sk += QSC_DILITHIUM_SEED_SIZE;

	for (i = 0; i < QSC_DILITHIUM_SEED_SIZE; ++i)
	{
		sk[i] = key[i];
	}

	sk += QSC_DILITHIUM_SEED_SIZE;

	for (i = 0; i < QSC_DILITHIUM_CRH_SIZE; ++i)
	{
		sk[i] = tr[i];
	}

	sk += QSC_DILITHIUM_CRH_SIZE;

	for (i = 0; i < QSC_DILITHIUM_L; ++i)
	{
		qsc_dilithium_polyeta_pack(sk + (i * DILITHIUM_POLETA_SIZE_PACKED), &s1->vec[i]);
	}

	sk += QSC_DILITHIUM_L * DILITHIUM_POLETA_SIZE_PACKED;

	for (i = 0; i < QSC_DILITHIUM_K; ++i)
	{
		qsc_dilithium_polyeta_pack(sk + (i * DILITHIUM_POLETA_SIZE_PACKED), &s2->vec[i]);
	}

	sk += QSC_DILITHIUM_K * DILITHIUM_POLETA_SIZE_PACKED;

	for (i = 0; i < QSC_DILITHIUM_K; ++i)
	{
		qsc_dilithium_polyt0_pack(sk + (i * DILITHIUM_POLT0_SIZE_PACKED), &t0->vec[i]);
	}
}

void qsc_dilithium_unpack_sk(uint8_t* rho, uint8_t* key, uint8_t* tr, qsc_dilithium_polyvecl* s1, qsc_dilithium_polyveck* s2, qsc_dilithium_polyveck* t0, const uint8_t* sk)
{
	size_t i;

	for (i = 0; i < QSC_DILITHIUM_SEED_SIZE; ++i)
	{
		rho[i] = sk[i];
	}

	sk += QSC_DILITHIUM_SEED_SIZE;

	for (i = 0; i < QSC_DILITHIUM_SEED_SIZE; ++i)
	{
		key[i] = sk[i];
	}

	sk += QSC_DILITHIUM_SEED_SIZE;

	for (i = 0; i < QSC_DILITHIUM_CRH_SIZE; ++i)
	{
		tr[i] = sk[i];
	}

	sk += QSC_DILITHIUM_CRH_SIZE;

	for (i = 0; i < QSC_DILITHIUM_L; ++i)
	{
		qsc_dilithium_polyeta_unpack(&s1->vec[i], sk + (i * DILITHIUM_POLETA_SIZE_PACKED));
	}

	sk += QSC_DILITHIUM_L * DILITHIUM_POLETA_SIZE_PACKED;

	for (i = 0; i < QSC_DILITHIUM_K; ++i)
	{
		qsc_dilithium_polyeta_unpack(&s2->vec[i], sk + (i * DILITHIUM_POLETA_SIZE_PACKED));
	}

	sk += QSC_DILITHIUM_K * DILITHIUM_POLETA_SIZE_PACKED;

	for (i = 0; i < QSC_DILITHIUM_K; ++i)
	{
		qsc_dilithium_polyt0_unpack(&t0->vec[i], sk + (i * DILITHIUM_POLT0_SIZE_PACKED));
	}
}

void qsc_dilithium_pack_sig(uint8_t* sig, const qsc_dilithium_polyvecl* z, const qsc_dilithium_polyveck* h, const qsc_dilithium_poly* c)
{
	size_t i;
	size_t j;
	size_t k;
	uint64_t mask;
	uint64_t signs;

	for (i = 0; i < QSC_DILITHIUM_L; ++i)
	{
		qsc_dilithium_polyz_pack(sig + (i * DILITHIUM_POLZ_SIZE_PACKED), &z->vec[i]);
	}

	sig += QSC_DILITHIUM_L * DILITHIUM_POLZ_SIZE_PACKED;

	/* Encode h */
	k = 0;

	for (i = 0; i < QSC_DILITHIUM_K; ++i)
	{
		for (j = 0; j < QSC_DILITHIUM_N; ++j)
		{
			if (h->vec[i].coeffs[j] != 0)
			{
				sig[k] = (uint8_t)j;
				++k;
			}
		}

		sig[QSC_DILITHIUM_OMEGA + i] = (uint8_t)k;
	}

	while (k < QSC_DILITHIUM_OMEGA)
	{
		sig[k] = 0;
		++k;
	}

	sig += QSC_DILITHIUM_OMEGA + QSC_DILITHIUM_K;

	/* Encode c */
	signs = 0;
	mask = 1;

	for (i = 0; i < QSC_DILITHIUM_N / 8; ++i)
	{
		sig[i] = 0;

		for (j = 0; j < 8; ++j)
		{
			if (c->coeffs[(8 * i) + j] != 0)
			{
				sig[i] |= (1U << j);

				if (c->coeffs[(8 * i) + j] == (QSC_DILITHIUM_Q - 1))
				{
					signs |= mask;
				}

				mask <<= 1;
			}
		}
	}

	sig += QSC_DILITHIUM_N / 8;

	for (i = 0; i < 8; ++i)
	{
		sig[i] = (uint8_t)(signs >> (8 * i));
	}
}

int32_t qsc_dilithium_unpack_sig(qsc_dilithium_polyvecl* z, qsc_dilithium_polyveck* h, qsc_dilithium_poly* c, const uint8_t* sig)
{
	uint64_t signs;
	size_t i;
	size_t j;
	size_t k;
	int32_t ret;

	ret = 0;

	for (i = 0; i < QSC_DILITHIUM_L; ++i)
	{
		qsc_dilithium_polyz_unpack(&z->vec[i], sig + (i * DILITHIUM_POLZ_SIZE_PACKED));
	}

	sig += QSC_DILITHIUM_L * DILITHIUM_POLZ_SIZE_PACKED;

	/* Decode h */
	k = 0;

	for (i = 0; i < QSC_DILITHIUM_K; ++i)
	{
		for (j = 0; j < QSC_DILITHIUM_N; ++j)
		{
			h->vec[i].coeffs[j] = 0;
		}

		if (sig[QSC_DILITHIUM_OMEGA + i] < k || sig[QSC_DILITHIUM_OMEGA + i] > QSC_DILITHIUM_OMEGA)
		{
			ret = 1;
			break;
		}

		for (j = k; j < sig[QSC_DILITHIUM_OMEGA + i]; ++j)
		{
			/* Coefficients are ordered for strong unforgeability */
			if (j > k && sig[j] <= sig[j - 1])
			{
				ret = 1;
				break;
			}

			h->vec[i].coeffs[sig[j]] = 1;
		}

		if (ret != 0)
		{
			break;
		}

		k = sig[QSC_DILITHIUM_OMEGA + i];
	}

	if (ret == 0)
	{
		/* Extra indices are zero for strong unforgeability */
		for (j = k; j < QSC_DILITHIUM_OMEGA; ++j)
		{
			if (sig[j])
			{
				ret = 1;
				break;
			}
		}

		if (ret == 0)
		{
			sig += QSC_DILITHIUM_OMEGA + QSC_DILITHIUM_K;

			/* Decode c */
			for (i = 0; i < QSC_DILITHIUM_N; ++i)
			{
				c->coeffs[i] = 0;
			}

			signs = 0;

			for (i = 0; i < 8; ++i)
			{
				signs |= (uint64_t)sig[(QSC_DILITHIUM_N / 8) + i] << (8 * i);
			}

			/* Extra sign bits are zero for strong unforgeability */
			if (signs >> 60)
			{
				ret = 1;
			}

			if (ret == 0)
			{
				for (i = 0; i < QSC_DILITHIUM_N / 8; ++i)
				{
					for (j = 0; j < 8; ++j)
					{
						if ((uint8_t)(sig[i] >> j) & 0x01U)
						{
							c->coeffs[(8 * i) + j] = 1;
							c->coeffs[(8 * i) + j] ^= (uint32_t)(~(signs & 1ULL) + 1) & (1UL ^ (uint32_t)(QSC_DILITHIUM_Q - 1));
							signs >>= 1;
						}
					}
				}
			}
		}
	}

	return ret;
}

/* reduce.c */

uint32_t qsc_dilithium_montgomery_reduce(uint64_t a)
{
	uint64_t t;

	t = a * DILITHIUM_QINV;
	t &= (1ULL << 32) - 1;
	t *= QSC_DILITHIUM_Q;
	t = a + t;
	t >>= 32;

	return (uint32_t)t;
}

uint32_t qsc_dilithium_reduce32(uint32_t a)
{
	uint32_t t;

	t = a & 0x007FFFFFUL;
	a >>= 23;
	t += (a << 13) - a;

	return t;
}

uint32_t qsc_dilithium_csubq(uint32_t a)
{
	a -= QSC_DILITHIUM_Q;
	a += (uint32_t)((int32_t)a >> 31) & (uint32_t)QSC_DILITHIUM_Q;

	return a;
}

uint32_t qsc_dilithium_freeze(uint32_t a)
{

	a = qsc_dilithium_reduce32(a);
	a = qsc_dilithium_csubq(a);

	return a;
}

/* rounding.c */

uint32_t qsc_dilithium_power2round(uint32_t a, uint32_t* a0)
{
	int32_t t;

	/* Centralized remainder mod 2^QSC_DILITHIUM_D */
	t = a & ((1U << QSC_DILITHIUM_D) - 1);
	t -= (1U << (QSC_DILITHIUM_D - 1)) + 1;
	t += (t >> 31) & (1U << QSC_DILITHIUM_D);
	t -= (1U << (QSC_DILITHIUM_D - 1)) - 1;
	*a0 = QSC_DILITHIUM_Q + t;
	a = (a - t) >> QSC_DILITHIUM_D;

	return a;
}

uint32_t qsc_dilithium_decompose(uint32_t a, uint32_t* a0)
{
#if QSC_DILITHIUM_ALPHA != (QSC_DILITHIUM_Q-1)/16
#error "qsc_dilithium_decompose assumes QSC_DILITHIUM_ALPHA == (QSC_DILITHIUM_Q-1)/16"
#endif

	int32_t t;
	int32_t u;

	/* Centralized remainder mod QSC_DILITHIUM_ALPHA */
	t = a & 0x0007FFFFUL;
	t += (a >> 19) << 9;
	t -= QSC_DILITHIUM_ALPHA / 2 + 1;
	t += (t >> 31) & QSC_DILITHIUM_ALPHA;
	t -= QSC_DILITHIUM_ALPHA / 2 - 1;
	a -= t;

	/* Divide by QSC_DILITHIUM_ALPHA (possible to avoid) */
	u = a - 1;
	u >>= 31;
	a = (a >> 19) + 1;
	a -= u & 1;

	/* Border case */
	*a0 = QSC_DILITHIUM_Q + t - (a >> 4);
	a &= 0x0FU;

	return a;
}

uint32_t qsc_dilithium_make_hint(const uint32_t a0, const uint32_t a1)
{
	uint32_t r;

	r = 1;

	if (a0 <= QSC_DILITHIUM_GAMMA2 || a0 > QSC_DILITHIUM_Q - QSC_DILITHIUM_GAMMA2 || (a0 == QSC_DILITHIUM_Q - QSC_DILITHIUM_GAMMA2 && a1 == 0))
	{
		r = 0;
	}

	return r;
}

uint32_t qsc_dilithium_use_hint(const uint32_t a, const uint32_t hint)
{
	uint32_t a0;
	uint32_t a1;

	a1 = qsc_dilithium_decompose(a, &a0);

	if (hint == 0)
	{
		return a1;
	}
	else if (a0 > QSC_DILITHIUM_Q)
	{
		return (a1 + 1) & 0x0FU;
	}
	else
	{
		return (a1 - 1) & 0x0FU;
	}
}

/* sign.c */

void expand_mat(qsc_dilithium_polyvecl mat[QSC_DILITHIUM_K], const uint8_t rho[QSC_DILITHIUM_SEED_SIZE])
{
	size_t i;
	size_t j;

	for (i = 0; i < QSC_DILITHIUM_K; ++i)
	{
		for (j = 0; j < QSC_DILITHIUM_L; ++j)
		{
			qsc_dilithium_poly_uniform(&mat[i].vec[j], rho, (uint16_t)((i << 8) + j));
		}
	}
}

void challenge(qsc_dilithium_poly* c, const uint8_t mu[QSC_DILITHIUM_CRH_SIZE], const qsc_dilithium_polyveck *w1)
{
	uint8_t inbuf[QSC_DILITHIUM_CRH_SIZE + QSC_DILITHIUM_K * DILITHIUM_POLW1_SIZE_PACKED];
	uint8_t outbuf[QSC_KECCAK_256_RATE];
	qsc_keccak_state kstate;
	uint64_t signs;
	size_t b;
	size_t i;
	size_t pos;

	for (i = 0; i < QSC_KECCAK_STATE_SIZE; ++i)
	{
		kstate.state[i] = 0;
	}

	for (i = 0; i < QSC_DILITHIUM_CRH_SIZE; ++i)
	{
		inbuf[i] = mu[i];
	}

	for (i = 0; i < QSC_DILITHIUM_K; ++i)
	{
		qsc_dilithium_polyw1_pack(inbuf + QSC_DILITHIUM_CRH_SIZE + (i * DILITHIUM_POLW1_SIZE_PACKED), &w1->vec[i]);
	}

	qsc_shake_initialize(&kstate, keccak_rate_256, inbuf, sizeof(inbuf));
	qsc_shake_squeezeblocks(&kstate, keccak_rate_256, outbuf, 1);
	signs = 0;

	for (i = 0; i < 8; ++i)
	{
		signs |= (uint64_t)outbuf[i] << 8 * i;
	}

	pos = 8;

	for (i = 0; i < QSC_DILITHIUM_N; ++i)
	{
		c->coeffs[i] = 0;
	}

	for (i = 196; i < 256; ++i)
	{
		do
		{
			if (pos >= QSC_KECCAK_256_RATE)
			{
				qsc_shake_squeezeblocks(&kstate, keccak_rate_256, outbuf, 1);
				pos = 0;
			}

			b = (size_t)outbuf[pos];
			++pos;
		}
		while (b > i);

		c->coeffs[i] = c->coeffs[b];
		c->coeffs[b] = 1;
		c->coeffs[b] ^= (uint32_t)(~(signs & 1) + 1) & (1 ^ (QSC_DILITHIUM_Q - 1));
		signs >>= 1;
	}
}

void qsc_dilithium_ksm_generate(uint8_t* publickey, uint8_t* secretkey, void (*rng_generate)(uint8_t*, size_t))
{
	const uint8_t *key;
	const uint8_t *rho;
	const uint8_t *rhoprime;
	uint8_t seedbuf[3 * QSC_DILITHIUM_SEED_SIZE];
	uint8_t tr[QSC_DILITHIUM_CRH_SIZE];
	qsc_dilithium_polyvecl mat[QSC_DILITHIUM_K];
	qsc_dilithium_polyvecl s1;
	qsc_dilithium_polyvecl s1hat;
	qsc_dilithium_polyveck s2;
	qsc_dilithium_polyveck t;
	qsc_dilithium_polyveck t0;
	qsc_dilithium_polyveck t1;
	size_t i;
	uint16_t nonce;

	/* Expand 32 bytes of randomness into rho, rhoprime and key */
	rng_generate(seedbuf, 3 * QSC_DILITHIUM_SEED_SIZE);
	rho = seedbuf;
	rhoprime = seedbuf + QSC_DILITHIUM_SEED_SIZE;
	key = seedbuf + (2 * QSC_DILITHIUM_SEED_SIZE);

	/* Expand matrix */
	expand_mat(mat, rho);
	nonce = 0;

	/* Sample short vectors s1 and s2 */
	for (i = 0; i < QSC_DILITHIUM_L; ++i)
	{
		qsc_dilithium_poly_uniform_eta(&s1.vec[i], rhoprime, nonce);
		++nonce;
	}

	for (i = 0; i < QSC_DILITHIUM_K; ++i)
	{
		qsc_dilithium_poly_uniform_eta(&s2.vec[i], rhoprime, nonce);
		++nonce;
	}

	/* Matrix-vector multiplication */
	s1hat = s1;
	qsc_dilithium_polyvecl_ntt(&s1hat);

	for (i = 0; i < QSC_DILITHIUM_K; ++i)
	{
		qsc_dilithium_polyvecl_pointwise_acc_invmontgomery(&t.vec[i], &mat[i], &s1hat);
		qsc_dilithium_poly_reduce(&t.vec[i]);
		qsc_dilithium_poly_invntt_montgomery(&t.vec[i]);
	}

	/* Add error vector s2 */
	qsc_dilithium_polyveck_add(&t, &t, &s2);

	/* Extract t1 and write public key */
	qsc_dilithium_polyveck_freeze(&t);
	qsc_dilithium_polyveck_power2round(&t1, &t0, &t);
	qsc_dilithium_pack_pk(publickey, rho, &t1);

	/* Compute CRH(rho, t1) and write secret key */
	qsc_shake256_compute(tr, QSC_DILITHIUM_CRH_SIZE, publickey, DILITHIUM_PUBLICKEY_SIZE);
	qsc_dilithium_pack_sk(secretkey, rho, key, tr, &s1, &s2, &t0);
}

void qsc_dilithium_ksm_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey, void (*rng_generate)(uint8_t*, size_t))
{
	size_t i;
	uint32_t n;
	uint8_t seedbuf[2 * QSC_DILITHIUM_SEED_SIZE + 3 * QSC_DILITHIUM_CRH_SIZE];
	uint8_t *rho, *tr, *key, *mu, *rhoprime;
	uint16_t nonce = 0;
	qsc_dilithium_poly c, chat;
	qsc_dilithium_polyvecl mat[QSC_DILITHIUM_K], s1, y, yhat, z;
	qsc_dilithium_polyveck t0, s2, w, w1, w0;
	qsc_dilithium_polyveck h, cs2, ct0;
	int32_t nrej;

	rho = seedbuf;
	tr = rho + QSC_DILITHIUM_SEED_SIZE;
	key = tr + QSC_DILITHIUM_CRH_SIZE;
	mu = key + QSC_DILITHIUM_SEED_SIZE;
	rhoprime = mu + QSC_DILITHIUM_CRH_SIZE;
	qsc_dilithium_unpack_sk(rho, key, tr, &s1, &s2, &t0, privatekey);

	/* Copy tr and message into the signedmsg buffer,
	 * backwards since message and signedmsg can be equal in SUPERCOP API */
	for (i = 1; i <= msglen; ++i)
	{
		signedmsg[DILITHIUM_SIGNATURE_SIZE + msglen - i] = message[msglen - i];
	}

	for (i = 0; i < QSC_DILITHIUM_CRH_SIZE; ++i)
	{
		signedmsg[DILITHIUM_SIGNATURE_SIZE - QSC_DILITHIUM_CRH_SIZE + i] = tr[i];
	}

	/* Compute CRH(tr, msg) */
	qsc_shake256_compute(mu, QSC_DILITHIUM_CRH_SIZE, signedmsg + DILITHIUM_SIGNATURE_SIZE - QSC_DILITHIUM_CRH_SIZE, QSC_DILITHIUM_CRH_SIZE + msglen);

#ifdef RANDOMIZED_SIGNING
	rng_generate(rhoprime, QSC_DILITHIUM_CRH_SIZE);
#else
	qsc_shake256_compute(rhoprime, QSC_DILITHIUM_CRH_SIZE, key, QSC_DILITHIUM_SEED_SIZE + QSC_DILITHIUM_CRH_SIZE);
#endif

	/* Expand matrix and transform vectors */
	expand_mat(mat, rho);
	qsc_dilithium_polyvecl_ntt(&s1);
	qsc_dilithium_polyveck_ntt(&s2);
	qsc_dilithium_polyveck_ntt(&t0);
	nrej = 1;

	while (nrej != 0)
	{
		/* Sample intermediate vector y */
		for (i = 0; i < QSC_DILITHIUM_L; ++i)
		{
			qsc_dilithium_poly_uniform_gamma1m1(&y.vec[i], rhoprime, nonce++);
		}

		/* Matrix-vector multiplication */
		yhat = y;
		qsc_dilithium_polyvecl_ntt(&yhat);

		for (i = 0; i < QSC_DILITHIUM_K; ++i)
		{
			qsc_dilithium_polyvecl_pointwise_acc_invmontgomery(&w.vec[i], &mat[i], &yhat);
			qsc_dilithium_poly_reduce(&w.vec[i]);
			qsc_dilithium_poly_invntt_montgomery(&w.vec[i]);
		}

		/* Decompose w and call the random oracle */
		qsc_dilithium_polyveck_csubq(&w);
		qsc_dilithium_polyveck_decompose(&w1, &w0, &w);
		challenge(&c, mu, &w1);
		chat = c;
		qsc_dilithium_poly_ntt(&chat);

		/* Check that subtracting cs2 does not change high bits of w and low bits
		 * do not reveal secret information */
		for (i = 0; i < QSC_DILITHIUM_K; ++i)
		{
			qsc_dilithium_poly_pointwise_invmontgomery(&cs2.vec[i], &chat, &s2.vec[i]);
			qsc_dilithium_poly_invntt_montgomery(&cs2.vec[i]);
		}

		qsc_dilithium_polyveck_sub(&w0, &w0, &cs2);
		qsc_dilithium_polyveck_freeze(&w0);

		if (qsc_dilithium_polyveck_chknorm(&w0, QSC_DILITHIUM_GAMMA2 - QSC_DILITHIUM_BETA) != 0)
		{
			continue;
		}

		/* Compute z, reject if it reveals secret */
		for (i = 0; i < QSC_DILITHIUM_L; ++i)
		{
			qsc_dilithium_poly_pointwise_invmontgomery(&z.vec[i], &chat, &s1.vec[i]);
			qsc_dilithium_poly_invntt_montgomery(&z.vec[i]);
		}

		qsc_dilithium_polyvecl_add(&z, &z, &y);
		qsc_dilithium_polyvecl_freeze(&z);

		if (qsc_dilithium_polyvecl_chknorm(&z, QSC_DILITHIUM_GAMMA1 - QSC_DILITHIUM_BETA) != 0)
		{
			continue;
		}

		/* Compute hints for w1 */
		for (i = 0; i < QSC_DILITHIUM_K; ++i)
		{
			qsc_dilithium_poly_pointwise_invmontgomery(&ct0.vec[i], &chat, &t0.vec[i]);
			qsc_dilithium_poly_invntt_montgomery(&ct0.vec[i]);
		}

		qsc_dilithium_polyveck_csubq(&ct0);

		if (qsc_dilithium_polyveck_chknorm(&ct0, QSC_DILITHIUM_GAMMA2) != 0)
		{
			continue;
		}

		qsc_dilithium_polyveck_add(&w0, &w0, &ct0);
		qsc_dilithium_polyveck_csubq(&w0);
		n = qsc_dilithium_polyveck_make_hint(&h, &w0, &w1);

		if (n > QSC_DILITHIUM_OMEGA)
		{
			continue;
		}

		/* Write signature */
		qsc_dilithium_pack_sig(signedmsg, &z, &h, &c);
		*smsglen = msglen + DILITHIUM_SIGNATURE_SIZE;
		nrej = 0;
	}
}

bool qsc_dilithium_ksm_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey)
{
	uint8_t rho[QSC_DILITHIUM_SEED_SIZE];
	uint8_t mu[QSC_DILITHIUM_CRH_SIZE];
	qsc_dilithium_polyvecl mat[QSC_DILITHIUM_K];
	qsc_dilithium_polyvecl z;
	qsc_dilithium_polyveck t1;
	qsc_dilithium_polyveck w1;
	qsc_dilithium_polyveck h;
	qsc_dilithium_polyveck tmp1;
	qsc_dilithium_polyveck tmp2;
	qsc_dilithium_poly c;
	qsc_dilithium_poly chat;
	qsc_dilithium_poly cp;
	size_t i;
	int32_t bsig;

	bsig = 0;

	if (smsglen < DILITHIUM_SIGNATURE_SIZE)
	{
		bsig = -1;
	}

	if (bsig == 0)
	{
		*msglen = smsglen - DILITHIUM_SIGNATURE_SIZE;
		qsc_dilithium_unpack_pk(rho, &t1, publickey);

		if (qsc_dilithium_unpack_sig(&z, &h, &c, signedmsg) != 0)
		{
			bsig = -1;
		}

		if (bsig == 0)
		{
			if (qsc_dilithium_polyvecl_chknorm(&z, QSC_DILITHIUM_GAMMA1 - QSC_DILITHIUM_BETA) != 0)
			{
				bsig = -1;
			}

			if (bsig == 0)
			{
				/* Compute CRH(CRH(rho, t1), msg) using message as "playground" buffer */
				if (signedmsg != message)
				{
					for (i = 0; i < *msglen; ++i)
					{
						message[DILITHIUM_SIGNATURE_SIZE + i] = signedmsg[DILITHIUM_SIGNATURE_SIZE + i];
					}
				}

				qsc_shake256_compute((uint8_t*)message + (DILITHIUM_SIGNATURE_SIZE - QSC_DILITHIUM_CRH_SIZE), QSC_DILITHIUM_CRH_SIZE, publickey, DILITHIUM_PUBLICKEY_SIZE);
				qsc_shake256_compute(mu, QSC_DILITHIUM_CRH_SIZE, (uint8_t*)message + (DILITHIUM_SIGNATURE_SIZE - QSC_DILITHIUM_CRH_SIZE), QSC_DILITHIUM_CRH_SIZE + *msglen);

				/* Matrix-vector multiplication; compute Az - c2^dt1 */
				expand_mat(mat, rho);
				qsc_dilithium_polyvecl_ntt(&z);

				for (i = 0; i < QSC_DILITHIUM_K; ++i)
				{
					qsc_dilithium_polyvecl_pointwise_acc_invmontgomery(&tmp1.vec[i], &mat[i], &z);
				}

				chat = c;
				qsc_dilithium_poly_ntt(&chat);
				qsc_dilithium_polyveck_shiftl(&t1);
				qsc_dilithium_polyveck_ntt(&t1);

				for (i = 0; i < QSC_DILITHIUM_K; ++i)
				{
					qsc_dilithium_poly_pointwise_invmontgomery(&tmp2.vec[i], &chat, &t1.vec[i]);
				}

				qsc_dilithium_polyveck_sub(&tmp1, &tmp1, &tmp2);
				qsc_dilithium_polyveck_reduce(&tmp1);
				qsc_dilithium_polyveck_invntt_montgomery(&tmp1);

				/* Reconstruct w1 */
				qsc_dilithium_polyveck_csubq(&tmp1);
				qsc_dilithium_polyveck_use_hint(&w1, &tmp1, &h);

				/* Call random oracle and verify challenge */
				challenge(&cp, mu, &w1);

				for (i = 0; i < QSC_DILITHIUM_N; ++i)
				{
					if (c.coeffs[i] != cp.coeffs[i])
					{
						bsig = -1;
						break;
					}
				}

				if (bsig == 0)
				{
					/* All good, copy msg, return 0 */
					for (i = 0; i < *msglen; ++i)
					{
						message[i] = signedmsg[DILITHIUM_SIGNATURE_SIZE + i];
					}
				}
			}
		}
	}

	if (bsig != 0)
	{
		*msglen = 0;

		for (i = 0; i < smsglen; ++i)
		{
			message[i] = 0;
		}
	}

	return (bsig == 0);
}
