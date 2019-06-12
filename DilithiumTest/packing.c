#include "packing.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"

void pack_pk(uint8_t pk[DILITHIUM_PUBLICKEY_SIZE], const uint8_t rho[DILITHIUM_SEED_SIZE], const polyveck* t1)
{
	size_t i;

	for (i = 0; i < DILITHIUM_SEED_SIZE; ++i)
	{
		pk[i] = rho[i];
	}

	pk += DILITHIUM_SEED_SIZE;

	for (i = 0; i < DILITHIUM_K; ++i)
	{
		polyt1_pack(pk + (i * DILITHIUM_POLT1_SIZE_PACKED), &t1->vec[i]);
	}
}

void unpack_pk(uint8_t rho[DILITHIUM_SEED_SIZE], polyveck* t1, const uint8_t pk[DILITHIUM_PUBLICKEY_SIZE])
{
	size_t i;

	for (i = 0; i < DILITHIUM_SEED_SIZE; ++i)
	{
		rho[i] = pk[i];
	}

	pk += DILITHIUM_SEED_SIZE;

	for (i = 0; i < DILITHIUM_K; ++i)
	{
		polyt1_unpack(&t1->vec[i], pk + (i * DILITHIUM_POLT1_SIZE_PACKED));
	}
}

void pack_sk(uint8_t sk[DILITHIUM_SECRETKEY_SIZE], const uint8_t rho[DILITHIUM_SEED_SIZE], const uint8_t key[DILITHIUM_SEED_SIZE],
	const uint8_t tr[DILITHIUM_CRH_SIZE], const polyvecl* s1, const polyveck* s2, const polyveck* t0)
{
	size_t i;

	for (i = 0; i < DILITHIUM_SEED_SIZE; ++i)
	{
		sk[i] = rho[i];
	}

	sk += DILITHIUM_SEED_SIZE;

	for (i = 0; i < DILITHIUM_SEED_SIZE; ++i)
	{
		sk[i] = key[i];
	}

	sk += DILITHIUM_SEED_SIZE;

	for (i = 0; i < DILITHIUM_CRH_SIZE; ++i)
	{
		sk[i] = tr[i];
	}

	sk += DILITHIUM_CRH_SIZE;

	for (i = 0; i < DILITHIUM_L; ++i)
	{
		polyeta_pack(sk + (i * DILITHIUM_POLETA_SIZE_PACKED), &s1->vec[i]);
	}

	sk += DILITHIUM_L * DILITHIUM_POLETA_SIZE_PACKED;

	for (i = 0; i < DILITHIUM_K; ++i)
	{
		polyeta_pack(sk + (i * DILITHIUM_POLETA_SIZE_PACKED), &s2->vec[i]);
	}

	sk += DILITHIUM_K * DILITHIUM_POLETA_SIZE_PACKED;

	for (i = 0; i < DILITHIUM_K; ++i)
	{
		polyt0_pack(sk + (i * DILITHIUM_POLT0_SIZE_PACKED), &t0->vec[i]);
	}
}

void unpack_sk(uint8_t rho[DILITHIUM_SEED_SIZE], uint8_t key[DILITHIUM_SEED_SIZE], uint8_t tr[DILITHIUM_CRH_SIZE], polyvecl* s1, polyveck* s2, polyveck* t0, const uint8_t sk[DILITHIUM_SECRETKEY_SIZE])
{
	size_t i;

	for (i = 0; i < DILITHIUM_SEED_SIZE; ++i)
	{
		rho[i] = sk[i];
	}

	sk += DILITHIUM_SEED_SIZE;

	for (i = 0; i < DILITHIUM_SEED_SIZE; ++i)
	{
		key[i] = sk[i];
	}

	sk += DILITHIUM_SEED_SIZE;

	for (i = 0; i < DILITHIUM_CRH_SIZE; ++i)
	{
		tr[i] = sk[i];
	}

	sk += DILITHIUM_CRH_SIZE;

	for (i = 0; i < DILITHIUM_L; ++i)
	{
		polyeta_unpack(&s1->vec[i], sk + (i * DILITHIUM_POLETA_SIZE_PACKED));
	}

	sk += DILITHIUM_L * DILITHIUM_POLETA_SIZE_PACKED;

	for (i = 0; i < DILITHIUM_K; ++i)
	{
		polyeta_unpack(&s2->vec[i], sk + (i * DILITHIUM_POLETA_SIZE_PACKED));
	}

	sk += DILITHIUM_K * DILITHIUM_POLETA_SIZE_PACKED;

	for (i = 0; i < DILITHIUM_K; ++i)
	{
		polyt0_unpack(&t0->vec[i], sk + (i * DILITHIUM_POLT0_SIZE_PACKED));
	}
}

void pack_sig(uint8_t sig[DILITHIUM_SIGNATURE_SIZE], const polyvecl* z, const polyveck* h, const poly* c)
{
	size_t i;
	size_t j;
	size_t k;
	uint64_t mask;
	uint64_t signs;

	for (i = 0; i < DILITHIUM_L; ++i)
	{
		polyz_pack(sig + (i * DILITHIUM_POLZ_SIZE_PACKED), &z->vec[i]);
	}

	sig += DILITHIUM_L * DILITHIUM_POLZ_SIZE_PACKED;

	/* Encode h */
	k = 0;

	for (i = 0; i < DILITHIUM_K; ++i) 
	{
		for (j = 0; j < DILITHIUM_N; ++j)
		{
			if (h->vec[i].coeffs[j] != 0)
			{
				sig[k] = (uint8_t)j;
				++k;
			}
		}

		sig[DILITHIUM_OMEGA + i] = (uint8_t)k;
	}

	while (k < DILITHIUM_OMEGA)
	{
		sig[k] = 0;
		++k;
	}

	sig += DILITHIUM_OMEGA + DILITHIUM_K;

	/* Encode c */
	signs = 0;
	mask = 1;

	for (i = 0; i < DILITHIUM_N / 8; ++i)
	{
		sig[i] = 0;

		for (j = 0; j < 8; ++j) 
		{
			if (c->coeffs[(8 * i) + j] != 0) 
			{
				sig[i] |= (1U << j);

				if (c->coeffs[(8 * i) + j] == (DILITHIUM_Q - 1))
				{
					signs |= mask;
				}

				mask <<= 1;
			}
		}
	}

	sig += DILITHIUM_N / 8;

	for (i = 0; i < 8; ++i)
	{
		sig[i] = (uint8_t)(signs >> (8 * i));
	}
}

int32_t unpack_sig(polyvecl* z, polyveck* h, poly* c, const uint8_t sig[DILITHIUM_SIGNATURE_SIZE])
{
	uint64_t signs;
	size_t i;
	size_t j;
	size_t k;
	int32_t ret;

	ret = 0;

	for (i = 0; i < DILITHIUM_L; ++i)
	{
		polyz_unpack(&z->vec[i], sig + (i * DILITHIUM_POLZ_SIZE_PACKED));
	}

	sig += DILITHIUM_L * DILITHIUM_POLZ_SIZE_PACKED;

	/* Decode h */
	k = 0;

	for (i = 0; i < DILITHIUM_K; ++i) 
	{
		for (j = 0; j < DILITHIUM_N; ++j)
		{
			h->vec[i].coeffs[j] = 0;
		}

		if (sig[DILITHIUM_OMEGA + i] < k || sig[DILITHIUM_OMEGA + i] > DILITHIUM_OMEGA)
		{
			ret = 1;
			break;
		}

		for (j = k; j < sig[DILITHIUM_OMEGA + i]; ++j) 
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

		k = sig[DILITHIUM_OMEGA + i];
	}

	if (ret == 0)
	{
		/* Extra indices are zero for strong unforgeability */
		for (j = k; j < DILITHIUM_OMEGA; ++j)
		{
			if (sig[j])
			{
				ret = 1;
				break;
			}
		}

		if (ret == 0)
		{
			sig += DILITHIUM_OMEGA + DILITHIUM_K;

			/* Decode c */
			for (i = 0; i < DILITHIUM_N; ++i)
			{
				c->coeffs[i] = 0;
			}

			signs = 0;

			for (i = 0; i < 8; ++i)
			{
				signs |= (uint64_t)sig[(DILITHIUM_N / 8) + i] << (8 * i);
			}

			/* Extra sign bits are zero for strong unforgeability */
			if (signs >> 60)
			{
				ret = 1;
			}

			if (ret == 0)
			{
				for (i = 0; i < DILITHIUM_N / 8; ++i)
				{
					for (j = 0; j < 8; ++j)
					{
						if ((sig[i] >> j) & 0x01)
						{
							c->coeffs[(8 * i) + j] = 1;
							c->coeffs[(8 * i) + j] ^= (uint32_t)(~(signs & 1) + 1) & (1 ^ (DILITHIUM_Q - 1));
							signs >>= 1;
						}
					}
				}
			}
		}
	}

	return ret;
}
