#include "kem.h"
#include "rng.h"
#include "sha3.h"
#include "encrypt.h"
#include "decrypt.h"
#include "params.h"
#include "sk_gen.h"
#include "pk_gen.h"
#include <string.h>

bool crypto_kem_enc(uint8_t* ct, uint8_t* ss, const uint8_t* pk)
{
	uint8_t e2[1 + (SYS_N / 8)] = { 2 };
	uint8_t ec1[1 + (SYS_N / 8) + (SYND_BYTES + 32)] = { 1 };

	encrypt(ct, pk, e2 + 1);

	shake256(ct + SYND_BYTES, MCELIECE_MAC_SIZE, e2, sizeof(e2));
	memcpy(ec1 + 1, e2 + 1, SYS_N / 8);
	memcpy(ec1 + 1 + (SYS_N / 8), ct, SYND_BYTES + MCELIECE_MAC_SIZE);
	shake256(ss, MCELIECE_MAC_SIZE, ec1, sizeof(ec1));

	return true;
}

bool crypto_kem_dec(uint8_t* ss, const uint8_t* ct, const uint8_t* sk)
{
	uint8_t conf[32];
	uint8_t e2[1 + (SYS_N / 8)] = { 2 };
	uint8_t preimage[1 + (SYS_N / 8) + (SYND_BYTES + 32)];
	size_t pctr;
	size_t i;
	uint16_t m;
	uint8_t confirm;
	uint8_t derr;

	pctr = 0;
	confirm = 0;
	derr = (uint8_t)decrypt(e2 + 1, sk + (SYS_N / 8), ct);
	shake256(conf, MCELIECE_MAC_SIZE, e2, sizeof(e2));

	for (i = 0; i < 32; i++)
	{
		confirm |= conf[i] ^ ct[SYND_BYTES + i];
	}

	m = derr | confirm;
	m -= 1;
	m >>= 8;
	preimage[pctr] = (~m & 0) | (m & 1);
	++pctr;

	for (i = 0; i < SYS_N / 8; i++)
	{
		preimage[pctr] = (~m & sk[i]) | (m & e2[i + 1]);
		++pctr;
	}

	for (i = 0; i < SYND_BYTES + 32; i++)
	{
		preimage[pctr] = ct[i];
		++pctr;
	}

	shake256(ss, MCELIECE_MAC_SIZE, preimage, sizeof(preimage));

	return (confirm == 0 && derr == 0);
}

bool crypto_kem_keypair(uint8_t* pk, uint8_t* sk)
{
	uint32_t ctr;

	ctr = 0;

	for (;;)
	{
		sk_part_gen(sk);
		++ctr;

		if (pk_gen(pk, sk + SYS_N / 8) == 0 || ctr == KEYGEN_RETRIES_MAX)
		{
			break;
		}
	}

	randombytes(sk, SYS_N / 8);

	return (ctr < KEYGEN_RETRIES_MAX);
}

