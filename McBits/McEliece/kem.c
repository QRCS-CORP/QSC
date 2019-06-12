#include "kem.h"
#include "chacha20.h"
#include "decrypt.h"
#include "encrypt.h"
#include "params.h"
#include "pk_gen.h"
#include "poly1305.h"
#include "sha3.h"
#include "sk_gen.h"
#include "sysrand.h"

mqc_status crypto_kem_keypair(uint8_t* pk, uint8_t* sk)
{
	mqc_status status;

	while (1)
	{
		status = sk_gen(sk);

		if (pk_gen(pk, sk) == 0)
		{
			break;
		}
	}

	return status;
}

mqc_status crypto_kem_enc(uint8_t* ct, uint8_t* ss, const uint8_t* pk)
{
	uint8_t e[1 << (MCELIECE_GFBITS - 3)];
	uint8_t key[64];
	uint8_t nonce[8] = { 0 };
	mqc_status estat;
	mqc_status rstat;

	/* function generates key with newhope style kem */
#if defined(MCELIECE_ENCPASULATE)
	rstat = sysrand_getbytes(ss, MCELIECE_KEY_SIZE);
#else
	rstat = MQC_STATUS_SUCCESS;
#endif

	estat = encrypt(ct, e, pk);
	sha3_compute512(key, e, sizeof(e));

	chacha_state ctx;
	chacha_initialize(&ctx, key, 32, nonce);
	chacha_transform(&ctx, ct + MCELIECE_SYNDBYTES, ss, MCELIECE_KEY_SIZE);
	poly1305_compute(ct + (MCELIECE_SYNDBYTES + MCELIECE_KEY_SIZE), ct + MCELIECE_SYNDBYTES, 32, key + 32);

	return (rstat == MQC_STATUS_SUCCESS && estat == MQC_STATUS_SUCCESS) ? MQC_STATUS_SUCCESS : MQC_ERROR_RANDFAIL;
}

mqc_status crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
	uint8_t e[1 << (MCELIECE_GFBITS - 3)];
	uint8_t key[64];
	uint8_t nonce[8] = { 0 };
	mqc_status astat;
	mqc_status dstat;

	dstat = decrypt(e, sk, ct);
	sha3_compute512(key, e, sizeof(e));
	astat = poly1305_verify(ct + MCELIECE_SYNDBYTES + MCELIECE_KEY_SIZE, ct + MCELIECE_SYNDBYTES, 32, key + 32);

	chacha_state ctx;
	chacha_initialize(&ctx, key, 32, nonce);
	chacha_transform(&ctx, ss, ct + MCELIECE_SYNDBYTES, MCELIECE_KEY_SIZE);

	return (dstat == MQC_STATUS_FAILURE) ? MQC_STATUS_FAILURE : 
		(astat == MQC_STATUS_FAILURE) ? MQC_ERROR_AUTHFAIL : MQC_STATUS_SUCCESS;
}
