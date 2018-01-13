#include "kex.h"
#include "sha3.h"
#include "verify.h"

void kyber_uake_initA(uint8_t* send, uint8_t* tk, uint8_t* sk, const uint8_t* pkb)
{
	crypto_kem_keypair(send, sk);
	crypto_kem_enc(send + KYBER_PUBLICKEYBYTES, tk, pkb);
}

void kyber_uake_sharedB(uint8_t* send, uint8_t* k, const uint8_t* recv, const uint8_t* skb)
{
	uint8_t buf[2 * KYBER_SYMBYTES];
	crypto_kem_enc(send, buf, recv);
	crypto_kem_dec(buf + KYBER_SYMBYTES, recv + KYBER_PUBLICKEYBYTES, skb);
	OQS_SHA3_shake256(k, KYBER_SYMBYTES, buf, 2 * KYBER_SYMBYTES);
}

void kyber_uake_sharedA(uint8_t* k, const uint8_t* recv, const uint8_t* tk, const uint8_t* sk)
{
	uint8_t buf[2 * KYBER_SYMBYTES];
	size_t i;

	crypto_kem_dec(buf, recv, sk);

	for (i = 0; i < KYBER_SYMBYTES; i++)
	{
		buf[i + KYBER_SYMBYTES] = tk[i];
	}

	OQS_SHA3_shake256(k, KYBER_SYMBYTES, buf, 2 * KYBER_SYMBYTES);
}

void kyber_ake_initA(uint8_t* send, uint8_t* tk, uint8_t* sk, const uint8_t* pkb)
{
	crypto_kem_keypair(send, sk);
	crypto_kem_enc(send + KYBER_PUBLICKEYBYTES, tk, pkb);
}

void kyber_ake_sharedB(uint8_t* send, uint8_t* k, const uint8_t* recv, const uint8_t* skb, const uint8_t* pka)
{
	uint8_t buf[3 * KYBER_SYMBYTES];

	crypto_kem_enc(send, buf, recv);
	crypto_kem_enc(send + KYBER_CIPHERTEXTBYTES, buf + KYBER_SYMBYTES, pka);
	crypto_kem_dec(buf + 2 * KYBER_SYMBYTES, recv + KYBER_PUBLICKEYBYTES, skb);
	OQS_SHA3_shake256(k, KYBER_SYMBYTES, buf, 3 * KYBER_SYMBYTES);
}

void kyber_ake_sharedA(uint8_t* k, const uint8_t* recv, const uint8_t* tk, const uint8_t* sk, const uint8_t* ska)
{
	uint8_t buf[3 * KYBER_SYMBYTES];
	size_t i;

	crypto_kem_dec(buf, recv, sk);
	crypto_kem_dec(buf + KYBER_SYMBYTES, recv + KYBER_CIPHERTEXTBYTES, ska);

	for (i = 0; i < KYBER_SYMBYTES; i++)
	{
		buf[i + 2 * KYBER_SYMBYTES] = tk[i];
	}

	OQS_SHA3_shake256(k, KYBER_SYMBYTES, buf, 3 * KYBER_SYMBYTES);
}
