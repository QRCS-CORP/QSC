#include "tlsgroups.h"
#include "csp.h"
#include "ecdh.h"
#include "ecdhp384base.h"
#include "ecdhp521base.h"
#include "eddh448base.h"
#include "eddh.h"
#include "ecdsap256base.h"
#include "ecdsap384base.h"
#include "ecdsap521base.h"
#include "kyber.h"
#include "memutils.h"
#include "sha2.h"

static const qsc_tls_group_descriptor qsc_tls_group_descriptors[] =
{
	{ qsc_tls_group_secp256r1, "secp256r1", "P-256", 65U, EC_NISTP256_PRIVATEKEY_SIZE, 0U, 0U, 0U, EC_NISTP256_SHAREDSECRET_SIZE, 0U, 0U, true, false, false },
	{ qsc_tls_group_secp384r1, "secp384r1", "P-384", 97U, 48U, 0U, 0U, 0U, 48U, 0U, 0U, true, false, false },
	{ qsc_tls_group_secp521r1, "secp521r1", "P-521", 133U, 66U, 0U, 0U, 0U, 66U, 0U, 0U, true, false, false },
	{ qsc_tls_group_x25519, "x25519", "X25519", 32U, 32U, 0U, 0U, 0U, 32U, 0U, 0U, true, false, false },
	{ qsc_tls_group_x448, "x448", "X448", 56U, 56U, 0U, 0U, 0U, 56U, 0U, 0U, true, false, false },
	{ qsc_tls_group_mlkem512, "mlkem512", "MLKEM512", 0U, 0U, QSC_KYBER_PUBLICKEY_SIZE, QSC_KYBER_PRIVATEKEY_SIZE, QSC_KYBER_CIPHERTEXT_SIZE, QSC_KYBER_SHAREDSECRET_SIZE, QSC_KYBER_CIPHERTEXT_SIZE, 0U, true, false, true },
	{ qsc_tls_group_mlkem768, "mlkem768", "MLKEM768", 0U, 0U, QSC_KYBER_PUBLICKEY_SIZE, QSC_KYBER_PRIVATEKEY_SIZE, QSC_KYBER_CIPHERTEXT_SIZE, QSC_KYBER_SHAREDSECRET_SIZE, QSC_KYBER_CIPHERTEXT_SIZE, 0U, true, false, true },
	{ qsc_tls_group_mlkem1024, "mlkem1024", "MLKEM1024", 0U, 0U, QSC_KYBER_PUBLICKEY_SIZE, QSC_KYBER_PRIVATEKEY_SIZE, QSC_KYBER_CIPHERTEXT_SIZE, QSC_KYBER_SHAREDSECRET_SIZE, QSC_KYBER_CIPHERTEXT_SIZE, 0U, true, false, true },
	{ qsc_tls_group_x25519_mlkem512, "x25519_mlkem512", "X25519MLKEM512", 32U, 32U, QSC_KYBER_PUBLICKEY_SIZE, QSC_KYBER_PRIVATEKEY_SIZE, QSC_KYBER_CIPHERTEXT_SIZE, QSC_EDDH_SHAREDSECRET_SIZE + QSC_KYBER_SHAREDSECRET_SIZE, QSC_EDDH_PUBLICKEY_SIZE + QSC_KYBER_CIPHERTEXT_SIZE, QSC_EDDH_PRIVATEKEY_SIZE + QSC_KYBER_SHAREDSECRET_SIZE, true, true, false },
	{ qsc_tls_group_x25519_mlkem768, "x25519_mlkem768", "X25519MLKEM768", 32U, 32U, QSC_KYBER_PUBLICKEY_SIZE, QSC_KYBER_PRIVATEKEY_SIZE, QSC_KYBER_CIPHERTEXT_SIZE, QSC_EDDH_SHAREDSECRET_SIZE + QSC_KYBER_SHAREDSECRET_SIZE, QSC_EDDH_PUBLICKEY_SIZE + QSC_KYBER_CIPHERTEXT_SIZE, QSC_EDDH_PRIVATEKEY_SIZE + QSC_KYBER_SHAREDSECRET_SIZE, true, true, false },
	{ qsc_tls_group_x25519_mlkem1024, "x25519_mlkem1024", "X25519MLKEM1024", 32U, 32U, QSC_KYBER_PUBLICKEY_SIZE, QSC_KYBER_PRIVATEKEY_SIZE, QSC_KYBER_CIPHERTEXT_SIZE, QSC_EDDH_SHAREDSECRET_SIZE + QSC_KYBER_SHAREDSECRET_SIZE, QSC_EDDH_PUBLICKEY_SIZE + QSC_KYBER_CIPHERTEXT_SIZE, QSC_EDDH_PRIVATEKEY_SIZE + QSC_KYBER_SHAREDSECRET_SIZE, true, true, false },
	{ qsc_tls_group_secp256r1_mlkem512, "secp256r1_mlkem512", "P256MLKEM512", 65U, EC_NISTP256_PRIVATEKEY_SIZE, QSC_KYBER_PUBLICKEY_SIZE, QSC_KYBER_PRIVATEKEY_SIZE, QSC_KYBER_CIPHERTEXT_SIZE, EC_NISTP256_SHAREDSECRET_SIZE + QSC_KYBER_SHAREDSECRET_SIZE, 65U + QSC_KYBER_CIPHERTEXT_SIZE, EC_NISTP256_PRIVATEKEY_SIZE + QSC_KYBER_SHAREDSECRET_SIZE, true, true, false },
	{ qsc_tls_group_secp256r1_mlkem768, "secp256r1_mlkem768", "P256MLKEM768", 65U, EC_NISTP256_PRIVATEKEY_SIZE, QSC_KYBER_PUBLICKEY_SIZE, QSC_KYBER_PRIVATEKEY_SIZE, QSC_KYBER_CIPHERTEXT_SIZE, EC_NISTP256_SHAREDSECRET_SIZE + QSC_KYBER_SHAREDSECRET_SIZE, 65U + QSC_KYBER_CIPHERTEXT_SIZE, EC_NISTP256_PRIVATEKEY_SIZE + QSC_KYBER_SHAREDSECRET_SIZE, true, true, false },
	{ qsc_tls_group_secp256r1_mlkem1024, "secp256r1_mlkem1024", "P256MLKEM1024", 65U, EC_NISTP256_PRIVATEKEY_SIZE, QSC_KYBER_PUBLICKEY_SIZE, QSC_KYBER_PRIVATEKEY_SIZE, QSC_KYBER_CIPHERTEXT_SIZE, EC_NISTP256_SHAREDSECRET_SIZE + QSC_KYBER_SHAREDSECRET_SIZE, 65U + QSC_KYBER_CIPHERTEXT_SIZE, EC_NISTP256_PRIVATEKEY_SIZE + QSC_KYBER_SHAREDSECRET_SIZE, true, true, false },
	{ qsc_tls_group_secp384r1_mlkem768, "secp384r1_mlkem768", "P384MLKEM768", 97U, 48U, QSC_KYBER_PUBLICKEY_SIZE, QSC_KYBER_PRIVATEKEY_SIZE, QSC_KYBER_CIPHERTEXT_SIZE, 48U + QSC_KYBER_SHAREDSECRET_SIZE, 97U + QSC_KYBER_CIPHERTEXT_SIZE, 48U + QSC_KYBER_SHAREDSECRET_SIZE, true, true, false },
	{ qsc_tls_group_secp384r1_mlkem1024, "secp384r1_mlkem1024", "P384MLKEM1024", 97U, 48U, QSC_KYBER_PUBLICKEY_SIZE, QSC_KYBER_PRIVATEKEY_SIZE, QSC_KYBER_CIPHERTEXT_SIZE, 48U + QSC_KYBER_SHAREDSECRET_SIZE, 97U + QSC_KYBER_CIPHERTEXT_SIZE, 48U + QSC_KYBER_SHAREDSECRET_SIZE, true, true, false }
};

static const qsc_tls_group_descriptor* tls_group_descriptor(qsc_tls_named_group group)
{
	const qsc_tls_group_descriptor* res;
	size_t i;

	res = NULL;

	for (i = 0U; i < (sizeof(qsc_tls_group_descriptors) / sizeof(qsc_tls_group_descriptors[0U])); ++i)
	{
		if (qsc_tls_group_descriptors[i].group == group)
		{
			res = &qsc_tls_group_descriptors[i];
			break;
		}
	}

	return res;
}

static qsc_tls_named_group tls_group_active_mlkem_group(void)
{
	qsc_tls_named_group res;

#if defined(QSC_KYBER_S1K2P512)
	res = qsc_tls_group_mlkem512;
#elif defined(QSC_KYBER_S3K3P768)
	res = qsc_tls_group_mlkem768;
#elif defined(QSC_KYBER_S5K4P1024)
	res = qsc_tls_group_mlkem1024;
#else
	res = qsc_tls_group_none;
#endif

	return res;
}

static qsc_tls_named_group tls_group_active_x25519_mlkem_group(void)
{
	qsc_tls_named_group res;

#if defined(QSC_KYBER_S1K2P512)
	res = qsc_tls_group_x25519_mlkem512;
#elif defined(QSC_KYBER_S3K3P768)
	res = qsc_tls_group_x25519_mlkem768;
#elif defined(QSC_KYBER_S5K4P1024)
	res = qsc_tls_group_x25519_mlkem1024;
#else
	res = qsc_tls_group_none;
#endif

	return res;
}

static qsc_tls_named_group tls_group_active_secp256r1_mlkem_group(void)
{
	qsc_tls_named_group res;

#if defined(QSC_KYBER_S1K2P512)
	res = qsc_tls_group_secp256r1_mlkem512;
#elif defined(QSC_KYBER_S3K3P768)
	res = qsc_tls_group_secp256r1_mlkem768;
#elif defined(QSC_KYBER_S5K4P1024)
	res = qsc_tls_group_secp256r1_mlkem1024;
#else
	res = qsc_tls_group_none;
#endif

	return res;
}

static void tls_group_mix_seed(uint8_t* output, size_t outputlen, qsc_tls_named_group group, uint8_t tag, const uint8_t* seed, size_t seedlen)
{
	QSC_ASSERT(output != NULL);

	uint8_t block[256U] = { 0U };
	uint8_t digest512[QSC_SHA2_512_HASH_SIZE] = { 0U };
	size_t cp;
	size_t off;
	uint32_t ctr;

	off = 0U;
	ctr = 0U;
	qsc_memutils_clear(output, outputlen);

	while (off < outputlen)
	{
		block[0U] = (uint8_t)((uint16_t)group >> 8);
		block[1U] = (uint8_t)((uint16_t)group & 0xFFU);
		block[2U] = tag;
		block[3U] = (uint8_t)((ctr >> 24) & 0xFFU);
		block[4U] = (uint8_t)((ctr >> 16) & 0xFFU);
		block[5U] = (uint8_t)((ctr >> 8) & 0xFFU);
		block[6U] = (uint8_t)(ctr & 0xFFU);

		if (seed != NULL && seedlen != 0U)
		{
			cp = seedlen;

			if (cp > (sizeof(block) - 7U))
			{
				cp = sizeof(block) - 7U;
			}

			qsc_memutils_copy(block + 7U, seed, cp);
			qsc_sha512_compute(digest512, block, 7U + cp);
		}
		else
		{
			qsc_sha512_compute(digest512, block, 7U);
		}

		cp = outputlen - off;

		if (cp > sizeof(digest512))
		{
			cp = sizeof(digest512);
		}

		qsc_memutils_copy(output + off, digest512, cp);
		off += cp;
		++ctr;
	}

	qsc_memutils_secure_erase(block, sizeof(block));
	qsc_memutils_secure_erase(digest512, sizeof(digest512));
}

static size_t tls_group_classical_private_key_size(qsc_tls_named_group group)
{
	const qsc_tls_group_descriptor* desc;

	desc = tls_group_descriptor(group);

	return (desc != NULL) ? desc->classicalprivatekeysize : 0U;
}

static size_t tls_group_kem_private_key_size(qsc_tls_named_group group)
{
	const qsc_tls_group_descriptor* desc;

	desc = tls_group_descriptor(group);

	return (desc != NULL) ? desc->kemprivatekeysize : 0U;
}

static size_t tls_group_server_share_size_internal(qsc_tls_named_group group)
{
	const qsc_tls_group_descriptor* desc;

	desc = tls_group_descriptor(group);

	return (desc != NULL) ? desc->serversharesize : 0U;
}

static size_t tls_group_server_private_state_size(qsc_tls_named_group group)
{
	const qsc_tls_group_descriptor* desc;

	desc = tls_group_descriptor(group);

	return (desc != NULL) ? desc->serverprivatestatesize : 0U;
}

static qsc_tls_status tls_group_decode_sec1_public_key(const uint8_t* sec1, size_t sec1len, size_t enclen, uint8_t* rawpublic, size_t rawlen)
{
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (sec1 == NULL || rawpublic == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (sec1len != enclen || sec1[0U] != 0x04U)
	{
		status = qsc_tls_status_invalid_message;
	}
	else
	{
		qsc_memutils_copy(rawpublic, sec1 + 1U, rawlen);
	}

	return status;
}

static qsc_tls_status tls_group_secp256r1_decode_sec1_public_key(const uint8_t* sec1, size_t sec1len, uint8_t* rawpublic)
{
	return tls_group_decode_sec1_public_key(sec1, sec1len, 65U, rawpublic, 64U);
}

static qsc_tls_status tls_group_secp384r1_decode_sec1_public_key(const uint8_t* sec1, size_t sec1len, uint8_t* rawpublic)
{
	return tls_group_decode_sec1_public_key(sec1, sec1len, 97U, rawpublic, 96U);
}

static qsc_tls_status tls_group_secp521r1_decode_sec1_public_key(const uint8_t* sec1, size_t sec1len, uint8_t* rawpublic)
{
	return tls_group_decode_sec1_public_key(sec1, sec1len, 133U, rawpublic, 132U);
}

static qsc_tls_status tls_group_x448_keypair_from_seed(const uint8_t* seed, size_t seedlen, uint8_t* publickey, uint8_t* privatekey)
{
	uint8_t xseed[56U] = { 0U };
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (seed == NULL || publickey == NULL || privatekey == NULL || seedlen == 0U)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		tls_group_mix_seed(xseed, sizeof(xseed), qsc_tls_group_x448, 0x11U, seed, seedlen);
		qsc_x448_generate_seeded_keypair(publickey, privatekey, xseed);
	}

	qsc_memutils_secure_erase(xseed, sizeof(xseed));

	return status;
}

static qsc_tls_status tls_group_secp256r1_keypair_from_seed(qsc_tls_named_group group, const uint8_t* seed, size_t seedlen, uint8_t* publickey, uint8_t* privatekey)
{
	uint8_t rawpublic[64U] = { 0U };
	uint8_t seed32[EC_NISTP256_SEED_SIZE] = { 0U };
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (seed == NULL || publickey == NULL || privatekey == NULL || seedlen == 0U)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		tls_group_mix_seed(seed32, sizeof(seed32), group, 0x11U, seed, seedlen);

		if (qsc_p256_keypair(rawpublic, privatekey, seed32) != 0)
		{
			status = qsc_tls_status_failure;
		}
		else
		{
			publickey[0U] = 0x04U;
			qsc_memutils_copy(publickey + 1U, rawpublic, sizeof(rawpublic));
		}
	}

	qsc_memutils_secure_erase(rawpublic, sizeof(rawpublic));
	qsc_memutils_secure_erase(seed32, sizeof(seed32));

	return status;
}

static qsc_tls_status tls_group_secp384r1_keypair_from_seed(qsc_tls_named_group group, const uint8_t* seed, size_t seedlen, uint8_t* publickey, uint8_t* privatekey)
{
	uint8_t rawpublic[96U] = { 0U };
	uint8_t seed48[48U] = { 0U };
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (seed == NULL || publickey == NULL || privatekey == NULL || seedlen == 0U)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		tls_group_mix_seed(seed48, sizeof(seed48), group, 0x11U, seed, seedlen);

		if (qsc_p384_keypair(rawpublic, privatekey, seed48) != 0)
		{
			status = qsc_tls_status_failure;
		}
		else
		{
			publickey[0U] = 0x04U;
			qsc_memutils_copy(publickey + 1U, rawpublic, sizeof(rawpublic));
		}
	}

	qsc_memutils_secure_erase(rawpublic, sizeof(rawpublic));
	qsc_memutils_secure_erase(seed48, sizeof(seed48));

	return status;
}

static qsc_tls_status tls_group_secp521r1_keypair_from_seed(qsc_tls_named_group group, const uint8_t* seed, size_t seedlen, uint8_t* publickey, uint8_t* privatekey)
{
	uint8_t rawpublic[132U] = { 0U };
	uint8_t seed66[66U] = { 0U };
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (seed == NULL || publickey == NULL || privatekey == NULL || seedlen == 0U)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		tls_group_mix_seed(seed66, sizeof(seed66), group, 0x11U, seed, seedlen);

		if (qsc_p521_keypair(rawpublic, privatekey, seed66) != 0)
		{
			status = qsc_tls_status_failure;
		}
		else
		{
			publickey[0U] = 0x04U;
			qsc_memutils_copy(publickey + 1U, rawpublic, sizeof(rawpublic));
		}
	}

	qsc_memutils_secure_erase(rawpublic, sizeof(rawpublic));
	qsc_memutils_secure_erase(seed66, sizeof(seed66));

	return status;
}

static qsc_tls_status tls_group_x25519_mlkem_keypair_from_seed(qsc_tls_named_group group, const uint8_t* seed, size_t seedlen, uint8_t* publickey, uint8_t* privatekey)
{
	uint8_t xseed[QSC_EDDH_SEED_SIZE] = { 0U };
	uint8_t d[QSC_KYBER_SEED_SIZE] = { 0U };
	uint8_t z[QSC_KYBER_SEED_SIZE] = { 0U };
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (seed == NULL || publickey == NULL || privatekey == NULL || seedlen == 0U)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		tls_group_mix_seed(xseed, sizeof(xseed), group, 0x11U, seed, seedlen);
		tls_group_mix_seed(d, sizeof(d), group, 0x31U, seed, seedlen);
		tls_group_mix_seed(z, sizeof(z), group, 0x32U, seed, seedlen);

		if (qsc_eddh_generate_seeded_keypair(publickey, privatekey, xseed) == false)
		{
			status = qsc_tls_status_failure;
		}
		else
		{
			qsc_kyber_generate_seeded_keypair(publickey + QSC_EDDH_PUBLICKEY_SIZE, privatekey + QSC_EDDH_PRIVATEKEY_SIZE, d, z);
		}
	}

	qsc_memutils_secure_erase(xseed, sizeof(xseed));
	qsc_memutils_secure_erase(d, sizeof(d));
	qsc_memutils_secure_erase(z, sizeof(z));

	return status;
}

static qsc_tls_status tls_group_secp256r1_mlkem_keypair_from_seed(qsc_tls_named_group group, const uint8_t* seed, size_t seedlen, uint8_t* publickey, uint8_t* privatekey)
{
	uint8_t d[QSC_KYBER_SEED_SIZE] = { 0U };
	uint8_t z[QSC_KYBER_SEED_SIZE] = { 0U };
	qsc_tls_status status;

	status = tls_group_secp256r1_keypair_from_seed(group, seed, seedlen, publickey, privatekey);

	if (status == qsc_tls_status_success)
	{
		tls_group_mix_seed(d, sizeof(d), group, 0x31U, seed, seedlen);
		tls_group_mix_seed(z, sizeof(z), group, 0x32U, seed, seedlen);
		qsc_kyber_generate_seeded_keypair(publickey + 65U, privatekey + EC_NISTP256_PRIVATEKEY_SIZE, d, z);
	}

	qsc_memutils_secure_erase(d, sizeof(d));
	qsc_memutils_secure_erase(z, sizeof(z));

	return status;
}

static bool tls_group_runtime_supported(qsc_tls_named_group group)
{
	bool res;

	res = false;

	switch (group)
	{
#if defined(QSC_EDDH_S1EC25519)
	case qsc_tls_group_x25519:
		res = true;
		break;
#endif
#if defined(QSC_EDDH_S3EC448)
	case qsc_tls_group_x448:
		res = true;
		break;
#endif
#if defined(QSC_ECDSA_S1P256)
	case qsc_tls_group_secp256r1:
		res = true;
		break;
#endif
#if defined(QSC_ECDSA_S3P384)
	case qsc_tls_group_secp384r1:
		res = true;
		break;
#endif
#if defined(QSC_ECDSA_S5P521)
	case qsc_tls_group_secp521r1:
		res = true;
		break;
#endif
	case qsc_tls_group_mlkem512:
	case qsc_tls_group_mlkem768:
	case qsc_tls_group_mlkem1024:
		res = (group == tls_group_active_mlkem_group());
		break;
	case qsc_tls_group_x25519_mlkem512:
	case qsc_tls_group_x25519_mlkem768:
	case qsc_tls_group_x25519_mlkem1024:
#if defined(QSC_EDDH_S1EC25519)
		res = (group == tls_group_active_x25519_mlkem_group());
#else
		res = false;
#endif
		break;
	case qsc_tls_group_secp256r1_mlkem512:
	case qsc_tls_group_secp256r1_mlkem768:
	case qsc_tls_group_secp256r1_mlkem1024:
#if defined(QSC_ECDSA_S1P256)
		res = (group == tls_group_active_secp256r1_mlkem_group());
#else
		res = false;
#endif
		break;
	default:
		res = false;
		break;
	}

	return res;
}

const qsc_tls_group_descriptor* qsc_tls_group_descriptor_get(qsc_tls_named_group group)
{
	return tls_group_descriptor(group);
}

bool qsc_tls_group_is_supported(qsc_tls_named_group group)
{
	const qsc_tls_group_descriptor* desc;
	bool res;

	desc = tls_group_descriptor(group);
	res = false;

	if (desc != NULL && desc->supported == true)
	{
		res = tls_group_runtime_supported(group);
	}

	return res;
}

bool qsc_tls_group_is_hybrid(qsc_tls_named_group group)
{
	const qsc_tls_group_descriptor* desc;

	desc = tls_group_descriptor(group);

	return (desc != NULL) ? desc->ishybrid : false;
}

bool qsc_tls_group_is_pure_kem(qsc_tls_named_group group)
{
	const qsc_tls_group_descriptor* desc;

	desc = tls_group_descriptor(group);

	return (desc != NULL) ? desc->ispurekem : false;
}

bool qsc_tls_group_uses_encapsulation(qsc_tls_named_group group)
{
	return (qsc_tls_group_is_hybrid(group) == true || qsc_tls_group_is_pure_kem(group) == true);
}

size_t qsc_tls_group_public_key_size(qsc_tls_named_group group)
{
	const qsc_tls_group_descriptor* desc;

	desc = tls_group_descriptor(group);

	return (desc != NULL) ? (desc->classicalpublickeysize + desc->kempublickeysize) : 0U;
}

size_t qsc_tls_group_private_key_size(qsc_tls_named_group group)
{
	const qsc_tls_group_descriptor* desc;

	desc = tls_group_descriptor(group);

	return (desc != NULL) ? (desc->classicalprivatekeysize + desc->kemprivatekeysize) : 0U;
}

size_t qsc_tls_group_shared_secret_size(qsc_tls_named_group group)
{
	const qsc_tls_group_descriptor* desc;

	desc = tls_group_descriptor(group);

	return (desc != NULL) ? desc->sharedsecretsize : 0U;
}

size_t qsc_tls_group_ciphertext_size(qsc_tls_named_group group)
{
	const qsc_tls_group_descriptor* desc;

	desc = tls_group_descriptor(group);

	return (desc != NULL) ? desc->ciphertextsize : 0U;
}

size_t qsc_tls_group_classical_public_key_size(qsc_tls_named_group group)
{
	const qsc_tls_group_descriptor* desc;

	desc = tls_group_descriptor(group);

	return (desc != NULL) ? desc->classicalpublickeysize : 0U;
}

size_t qsc_tls_group_kem_public_key_size(qsc_tls_named_group group)
{
	const qsc_tls_group_descriptor* desc;

	desc = tls_group_descriptor(group);

	return (desc != NULL) ? desc->kempublickeysize : 0U;
}

size_t qsc_tls_group_client_share_size(qsc_tls_named_group group)
{
	return qsc_tls_group_public_key_size(group);
}

size_t qsc_tls_group_server_share_size(qsc_tls_named_group group)
{
	const qsc_tls_group_descriptor* desc;
	size_t res;

	desc = tls_group_descriptor(group);
	res = 0U;

	if (desc != NULL)
	{
		res = (desc->serversharesize != 0U) ? desc->serversharesize : (desc->classicalpublickeysize + desc->kempublickeysize);
	}

	return res;
}

bool qsc_tls_group_validate_client_share_length(qsc_tls_named_group group, size_t sharelen)
{
	size_t expected;

	expected = qsc_tls_group_client_share_size(group);

	return (expected != 0U && sharelen == expected);
}

bool qsc_tls_group_validate_server_share_length(qsc_tls_named_group group, size_t sharelen)
{
	size_t expected;

	expected = qsc_tls_group_server_share_size(group);

	return (expected != 0U && sharelen == expected);
}

uint16_t qsc_tls_group_active_mlkem_parameter_bits(void)
{
	uint16_t res;

#if defined(QSC_KYBER_S1K2P512)
	res = 512U;
#elif defined(QSC_KYBER_S3K3P768)
	res = 768U;
#elif defined(QSC_KYBER_S5K4P1024)
	res = 1024U;
#elif defined(QSC_KYBER_S6K5P1280)
	res = 1280U;
#else
	res = 0U;
#endif

	return res;
}

const char* qsc_tls_group_name(qsc_tls_named_group group)
{
	const qsc_tls_group_descriptor* desc;

	desc = tls_group_descriptor(group);

	return (desc != NULL) ? desc->name : "unknown";
}

const char* qsc_tls_group_active_name(qsc_tls_named_group group)
{
	return qsc_tls_group_name(group);
}

const char* qsc_tls_group_openssl_name(qsc_tls_named_group group)
{
	const qsc_tls_group_descriptor* desc;

	desc = tls_group_descriptor(group);

	return (desc != NULL) ? desc->opensslname : "unknown";
}

qsc_tls_status qsc_tls_group_key_share_generate(qsc_tls_named_group group, const uint8_t* seed, size_t seedlen, uint8_t* publickey, size_t publickeylen, uint8_t* privatekey, size_t privatekeylen)
{
	QSC_ASSERT(qsc_tls_group_is_supported(group) == false);
	QSC_ASSERT(seed != NULL);
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(privatekey != NULL);

	size_t needpk;
	size_t needsk;
	qsc_tls_status status;

	needpk = qsc_tls_group_public_key_size(group);
	needsk = qsc_tls_group_private_key_size(group);
	status = qsc_tls_status_success;

	if (qsc_tls_group_is_supported(group) == false || seed == NULL || publickey == NULL || privatekey == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (publickeylen < needpk || privatekeylen < needsk)
	{
		status = qsc_tls_status_buffer_too_small;
	}
	else
	{
		qsc_memutils_clear(publickey, publickeylen);
		qsc_memutils_clear(privatekey, privatekeylen);

		if (group == qsc_tls_group_x25519)
		{
			if (seedlen < QSC_EDDH_SEED_SIZE)
			{
				status = qsc_tls_status_invalid_input;
			}
			else if (qsc_eddh_generate_seeded_keypair(publickey, privatekey, seed) == false)
			{
				status = qsc_tls_status_failure;
			}
		}
		else if (group == qsc_tls_group_x448)
		{
			status = tls_group_x448_keypair_from_seed(seed, seedlen, publickey, privatekey);
		}
		else if (group == qsc_tls_group_secp256r1)
		{
			status = tls_group_secp256r1_keypair_from_seed(group, seed, seedlen, publickey, privatekey);
		}
		else if (group == qsc_tls_group_secp384r1)
		{
			status = tls_group_secp384r1_keypair_from_seed(group, seed, seedlen, publickey, privatekey);
		}
		else if (group == qsc_tls_group_secp521r1)
		{
			status = tls_group_secp521r1_keypair_from_seed(group, seed, seedlen, publickey, privatekey);
		}
		else if (qsc_tls_group_is_pure_kem(group) == true)
		{
			uint8_t d[QSC_KYBER_SEED_SIZE] = { 0U };
			uint8_t z[QSC_KYBER_SEED_SIZE] = { 0U };

			tls_group_mix_seed(d, sizeof(d), group, 0x31U, seed, seedlen);
			tls_group_mix_seed(z, sizeof(z), group, 0x32U, seed, seedlen);
			qsc_kyber_generate_seeded_keypair(publickey, privatekey, d, z);
			qsc_memutils_secure_erase(d, sizeof(d));
			qsc_memutils_secure_erase(z, sizeof(z));
		}
		else if (group == tls_group_active_x25519_mlkem_group())
		{
			status = tls_group_x25519_mlkem_keypair_from_seed(group, seed, seedlen, publickey, privatekey);
		}
		else if (group == tls_group_active_secp256r1_mlkem_group())
		{
			status = tls_group_secp256r1_mlkem_keypair_from_seed(group, seed, seedlen, publickey, privatekey);
		}
		else
		{
			status = qsc_tls_status_invalid_state;
		}
	}

	return status;
}

qsc_tls_status qsc_tls_group_key_share_generate_random(qsc_tls_named_group group, uint8_t* publickey, size_t publickeylen, uint8_t* privatekey, size_t privatekeylen)
{
	QSC_ASSERT(publickey != NULL);
	QSC_ASSERT(privatekey != NULL);

	uint8_t seed[QSC_SHA2_512_HASH_SIZE] = { 0U };
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (publickey == NULL || privatekey == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (qsc_csp_generate(seed, sizeof(seed)) == false)
	{
		status = qsc_tls_status_failure;
	}
	else
	{
		status = qsc_tls_group_key_share_generate(group, seed, sizeof(seed), publickey, publickeylen, privatekey, privatekeylen);
	}

	qsc_memutils_secure_erase(seed, sizeof(seed));

	return status;
}

qsc_tls_status qsc_tls_group_shared_secret_derive(qsc_tls_named_group group, const uint8_t* localprivatekey, size_t localprivatekeylen, 
	const uint8_t* peerpublickey, size_t peerpublickeylen, uint8_t* sharedsecret, size_t* sharedsecretlen)
{
	QSC_ASSERT(localprivatekey != NULL);
	QSC_ASSERT(peerpublickey != NULL);
	QSC_ASSERT(sharedsecret != NULL);

	uint8_t classicalsecret[66U] = { 0U };
	size_t needpk;
	size_t needsk;
	size_t needss;
	qsc_tls_status status;

	needpk = qsc_tls_group_public_key_size(group);
	needsk = qsc_tls_group_private_key_size(group);
	needss = qsc_tls_group_shared_secret_size(group);
	status = qsc_tls_status_success;

	if (qsc_tls_group_is_supported(group) == false || localprivatekey == NULL || peerpublickey == NULL || sharedsecret == NULL || sharedsecretlen == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (localprivatekeylen != needsk || peerpublickeylen != needpk || *sharedsecretlen < needss)
	{
		status = qsc_tls_status_buffer_too_small;
	}
	else if (qsc_tls_group_is_pure_kem(group) == true)
	{
		status = qsc_tls_status_invalid_state;
	}
	else if (group == qsc_tls_group_x25519)
	{
		if (qsc_eddh_key_exchange(sharedsecret, localprivatekey, peerpublickey) == false)
		{
			status = qsc_tls_status_authentication_failure;
		}
		else
		{
			*sharedsecretlen = QSC_EDDH_SHAREDSECRET_SIZE;
		}
	}
	else if (group == qsc_tls_group_x448)
	{
		if (qsc_x448_key_exchange(sharedsecret, peerpublickey, localprivatekey) == false)
		{
			status = qsc_tls_status_authentication_failure;
		}
		else
		{
			*sharedsecretlen = 56U;
		}
	}
	else if (group == qsc_tls_group_secp256r1)
	{
		uint8_t rawpeer[64U] = { 0U };

		status = tls_group_secp256r1_decode_sec1_public_key(peerpublickey, 65U, rawpeer);

		if (status == qsc_tls_status_success)
		{
			if (qsc_ecdh_key_exchange(sharedsecret, localprivatekey, rawpeer) == false)
			{
				status = qsc_tls_status_authentication_failure;
			}
			else
			{
				*sharedsecretlen = EC_NISTP256_SHAREDSECRET_SIZE;
			}
		}

		qsc_memutils_secure_erase(rawpeer, sizeof(rawpeer));
	}
	else if (group == qsc_tls_group_secp384r1)
	{
		uint8_t rawpeer[96U] = { 0U };

		status = tls_group_secp384r1_decode_sec1_public_key(peerpublickey, 97U, rawpeer);

		if (status == qsc_tls_status_success)
		{
			if (qsc_p384_key_exchange(sharedsecret, rawpeer, localprivatekey) == false)
			{
				status = qsc_tls_status_authentication_failure;
			}
			else
			{
				*sharedsecretlen = 48U;
			}
		}

		qsc_memutils_secure_erase(rawpeer, sizeof(rawpeer));
	}
	else if (group == qsc_tls_group_secp521r1)
	{
		uint8_t rawpeer[132U] = { 0U };

		status = tls_group_secp521r1_decode_sec1_public_key(peerpublickey, 133U, rawpeer);

		if (status == qsc_tls_status_success)
		{
			if (qsc_p521_key_exchange(sharedsecret, rawpeer, localprivatekey) == false)
			{
				status = qsc_tls_status_authentication_failure;
			}
			else
			{
				*sharedsecretlen = 66U;
			}
		}

		qsc_memutils_secure_erase(rawpeer, sizeof(rawpeer));
	}
	else if (group == tls_group_active_x25519_mlkem_group())
	{
		uint8_t kemsecret[QSC_KYBER_SHAREDSECRET_SIZE] = { 0U };

		if (qsc_eddh_key_exchange(sharedsecret, localprivatekey, peerpublickey) == false)
		{
			status = qsc_tls_status_authentication_failure;
		}
		else if (qsc_kyber_decapsulate(kemsecret, peerpublickey + QSC_EDDH_PUBLICKEY_SIZE, localprivatekey + QSC_EDDH_PRIVATEKEY_SIZE) == false)
		{
			status = qsc_tls_status_authentication_failure;
		}
		else
		{
			qsc_memutils_copy(sharedsecret + QSC_EDDH_SHAREDSECRET_SIZE, kemsecret, QSC_KYBER_SHAREDSECRET_SIZE);
			*sharedsecretlen = needss;
		}

		qsc_memutils_secure_erase(kemsecret, sizeof(kemsecret));
	}
	else if (group == tls_group_active_secp256r1_mlkem_group())
	{
		uint8_t kemsecret[QSC_KYBER_SHAREDSECRET_SIZE] = { 0U };
		uint8_t rawpeer[64U] = { 0U };

		status = tls_group_secp256r1_decode_sec1_public_key(peerpublickey, 65U, rawpeer);

		if (status == qsc_tls_status_success)
		{
			if (qsc_ecdh_key_exchange(sharedsecret, localprivatekey, rawpeer) == false)
			{
				status = qsc_tls_status_authentication_failure;
			}
			else if (qsc_kyber_decapsulate(kemsecret, peerpublickey + 65U, localprivatekey + EC_NISTP256_PRIVATEKEY_SIZE) == false)
			{
				status = qsc_tls_status_authentication_failure;
			}
			else
			{
				qsc_memutils_copy(sharedsecret + EC_NISTP256_SHAREDSECRET_SIZE, kemsecret, QSC_KYBER_SHAREDSECRET_SIZE);
				*sharedsecretlen = needss;
			}
		}

		qsc_memutils_secure_erase(kemsecret, sizeof(kemsecret));
		qsc_memutils_secure_erase(rawpeer, sizeof(rawpeer));
	}
	else
	{
		status = qsc_tls_status_invalid_state;
	}

	qsc_memutils_secure_erase(classicalsecret, sizeof(classicalsecret));

	return status;
}

qsc_tls_status qsc_tls_group_server_share_generate(qsc_tls_named_group group, const uint8_t* seed, size_t seedlen, const uint8_t* clientpublickey,
	size_t clientpublickeylen, uint8_t* servershare, size_t serversharelen, uint8_t* serverprivatekey, size_t serverprivatekeylen, uint8_t* sharedsecret, size_t* sharedsecretlen)
{
	QSC_ASSERT(seed != NULL);
	QSC_ASSERT(clientpublickey != NULL);
	QSC_ASSERT(sharedsecret != NULL);
	QSC_ASSERT(servershare != NULL);
	QSC_ASSERT(serverprivatekey != NULL);
	QSC_ASSERT(sharedsecretlen != NULL);

	uint8_t coin[QSC_KYBER_SEED_SIZE] = { 0U };
	uint8_t kemsecret[QSC_KYBER_SHAREDSECRET_SIZE] = { 0U };
	size_t needpriv;
	size_t needsecret;
	size_t needshare;
	qsc_tls_status status;

	needshare = tls_group_server_share_size_internal(group);
	needpriv = tls_group_server_private_state_size(group);
	needsecret = qsc_tls_group_shared_secret_size(group);
	status = qsc_tls_status_success;

	if ((group != tls_group_active_x25519_mlkem_group() && group != tls_group_active_secp256r1_mlkem_group() && qsc_tls_group_is_pure_kem(group) == false) || seed == NULL || clientpublickey == NULL || servershare == NULL || serverprivatekey == NULL || sharedsecret == NULL || sharedsecretlen == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (seedlen == 0U || clientpublickeylen < qsc_tls_group_public_key_size(group) || serversharelen < needshare || serverprivatekeylen < needpriv || *sharedsecretlen < needsecret)
	{
		status = qsc_tls_status_buffer_too_small;
	}
	else if (qsc_tls_group_is_pure_kem(group) == true)
	{
		qsc_memutils_clear(servershare, serversharelen);
		qsc_memutils_clear(serverprivatekey, serverprivatekeylen);
		qsc_memutils_clear(sharedsecret, *sharedsecretlen);
		tls_group_mix_seed(coin, sizeof(coin), group, 0x62U, seed, seedlen);
		qsc_kyber_seeded_encapsulate(kemsecret, servershare, clientpublickey, coin);
		qsc_memutils_copy(sharedsecret, kemsecret, QSC_KYBER_SHAREDSECRET_SIZE);
		*sharedsecretlen = QSC_KYBER_SHAREDSECRET_SIZE;
	}
	else if (group == tls_group_active_x25519_mlkem_group())
	{
		uint8_t xpublic[QSC_EDDH_PUBLICKEY_SIZE] = { 0U };
		uint8_t xsecret[QSC_EDDH_SHAREDSECRET_SIZE] = { 0U };
		uint8_t xseed[QSC_EDDH_SEED_SIZE] = { 0U };

		qsc_memutils_clear(servershare, serversharelen);
		qsc_memutils_clear(serverprivatekey, serverprivatekeylen);
		qsc_memutils_clear(sharedsecret, *sharedsecretlen);
		tls_group_mix_seed(xseed, sizeof(xseed), group, 0x61U, seed, seedlen);
		tls_group_mix_seed(coin, sizeof(coin), group, 0x62U, seed, seedlen);

		if (qsc_eddh_generate_seeded_keypair(xpublic, serverprivatekey, xseed) == false)
		{
			status = qsc_tls_status_failure;
		}
		else if (qsc_eddh_key_exchange(xsecret, serverprivatekey, clientpublickey) == false)
		{
			status = qsc_tls_status_authentication_failure;
		}
		else
		{
			qsc_memutils_copy(servershare, xpublic, QSC_EDDH_PUBLICKEY_SIZE);
			qsc_kyber_seeded_encapsulate(kemsecret, servershare + QSC_EDDH_PUBLICKEY_SIZE, clientpublickey + QSC_EDDH_PUBLICKEY_SIZE, coin);
			qsc_memutils_copy(serverprivatekey + QSC_EDDH_PRIVATEKEY_SIZE, kemsecret, QSC_KYBER_SHAREDSECRET_SIZE);
			qsc_memutils_copy(sharedsecret, xsecret, QSC_EDDH_SHAREDSECRET_SIZE);
			qsc_memutils_copy(sharedsecret + QSC_EDDH_SHAREDSECRET_SIZE, kemsecret, QSC_KYBER_SHAREDSECRET_SIZE);
			*sharedsecretlen = needsecret;
		}

		qsc_memutils_secure_erase(xpublic, sizeof(xpublic));
		qsc_memutils_secure_erase(xsecret, sizeof(xsecret));
		qsc_memutils_secure_erase(xseed, sizeof(xseed));
	}
	else
	{
		uint8_t rawclient[64U] = { 0U };

		qsc_memutils_clear(servershare, serversharelen);
		qsc_memutils_clear(serverprivatekey, serverprivatekeylen);
		qsc_memutils_clear(sharedsecret, *sharedsecretlen);
		tls_group_mix_seed(coin, sizeof(coin), group, 0x62U, seed, seedlen);

		if (tls_group_secp256r1_keypair_from_seed(group, seed, seedlen, servershare, serverprivatekey) != qsc_tls_status_success)
		{
			status = qsc_tls_status_failure;
		}
		else if (tls_group_secp256r1_decode_sec1_public_key(clientpublickey, 65U, rawclient) != qsc_tls_status_success)
		{
			status = qsc_tls_status_invalid_message;
		}
		else if (qsc_ecdh_key_exchange(sharedsecret, serverprivatekey, rawclient) == false)
		{
			status = qsc_tls_status_authentication_failure;
		}
		else
		{
			qsc_kyber_seeded_encapsulate(kemsecret, servershare + 65U, clientpublickey + 65U, coin);
			qsc_memutils_copy(serverprivatekey + EC_NISTP256_PRIVATEKEY_SIZE, kemsecret, QSC_KYBER_SHAREDSECRET_SIZE);
			qsc_memutils_copy(sharedsecret + EC_NISTP256_SHAREDSECRET_SIZE, kemsecret, QSC_KYBER_SHAREDSECRET_SIZE);
			*sharedsecretlen = needsecret;
		}

		qsc_memutils_secure_erase(rawclient, sizeof(rawclient));
	}

	qsc_memutils_secure_erase(coin, sizeof(coin));
	qsc_memutils_secure_erase(kemsecret, sizeof(kemsecret));

	return status;
}

qsc_tls_status qsc_tls_group_server_share_generate_random(qsc_tls_named_group group, const uint8_t* clientpublickey,
	size_t clientpublickeylen, uint8_t* servershare, size_t serversharelen, uint8_t* serverprivatekey, size_t serverprivatekeylen, uint8_t* sharedsecret, size_t* sharedsecretlen)
{
	QSC_ASSERT(clientpublickey != NULL);
	QSC_ASSERT(servershare != NULL);
	QSC_ASSERT(serverprivatekey != NULL);
	QSC_ASSERT(sharedsecret != NULL);
	QSC_ASSERT(sharedsecretlen != NULL);

	uint8_t seed[QSC_SHA2_512_HASH_SIZE] = { 0U };
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (clientpublickey == NULL || servershare == NULL || serverprivatekey == NULL || sharedsecret == NULL || sharedsecretlen == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (qsc_csp_generate(seed, sizeof(seed)) == false)
	{
		status = qsc_tls_status_failure;
	}
	else
	{
		status = qsc_tls_group_server_share_generate(group, seed, sizeof(seed), clientpublickey, clientpublickeylen, servershare, serversharelen, serverprivatekey, serverprivatekeylen, sharedsecret, sharedsecretlen);
	}

	qsc_memutils_secure_erase(seed, sizeof(seed));

	return status;
}

qsc_tls_status qsc_tls_group_client_shared_secret_derive(qsc_tls_named_group group, const uint8_t* clientprivatekey, size_t clientprivatekeylen,
	const uint8_t* servershare, size_t serversharelen, uint8_t* sharedsecret, size_t* sharedsecretlen)
{
	QSC_ASSERT(clientprivatekey != NULL);
	QSC_ASSERT(servershare != NULL);
	QSC_ASSERT(sharedsecret != NULL);
	QSC_ASSERT(sharedsecretlen != NULL);

	uint8_t kemsecret[QSC_KYBER_SHAREDSECRET_SIZE] = { 0U };
	size_t needpriv;
	size_t needsecret;
	size_t needshare;
	qsc_tls_status status;

	needpriv = qsc_tls_group_private_key_size(group);
	needshare = tls_group_server_share_size_internal(group);
	needsecret = qsc_tls_group_shared_secret_size(group);
	status = qsc_tls_status_success;

	if ((group != tls_group_active_x25519_mlkem_group() && group != tls_group_active_secp256r1_mlkem_group() && qsc_tls_group_is_pure_kem(group) == false) || clientprivatekey == NULL || servershare == NULL || sharedsecret == NULL || sharedsecretlen == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (clientprivatekeylen < needpriv || serversharelen < needshare || *sharedsecretlen < needsecret)
	{
		status = qsc_tls_status_buffer_too_small;
	}
	else if (qsc_tls_group_is_pure_kem(group) == true)
	{
		if (qsc_kyber_decapsulate(kemsecret, servershare, clientprivatekey) == false)
		{
			status = qsc_tls_status_authentication_failure;
		}
		else
		{
			qsc_memutils_copy(sharedsecret, kemsecret, QSC_KYBER_SHAREDSECRET_SIZE);
			*sharedsecretlen = QSC_KYBER_SHAREDSECRET_SIZE;
		}
	}
	else if (group == tls_group_active_x25519_mlkem_group())
	{
		if (qsc_eddh_key_exchange(sharedsecret, clientprivatekey, servershare) == false)
		{
			status = qsc_tls_status_authentication_failure;
		}
		else if (qsc_kyber_decapsulate(kemsecret, servershare + QSC_EDDH_PUBLICKEY_SIZE, clientprivatekey + QSC_EDDH_PRIVATEKEY_SIZE) == false)
		{
			status = qsc_tls_status_authentication_failure;
		}
		else
		{
			qsc_memutils_copy(sharedsecret + QSC_EDDH_SHAREDSECRET_SIZE, kemsecret, QSC_KYBER_SHAREDSECRET_SIZE);
			*sharedsecretlen = needsecret;
		}
	}
	else
	{
		uint8_t rawserver[64U] = { 0U };

		status = tls_group_secp256r1_decode_sec1_public_key(servershare, 65U, rawserver);

		if (status == qsc_tls_status_success)
		{
			if (qsc_ecdh_key_exchange(sharedsecret, clientprivatekey, rawserver) == false)
			{
				status = qsc_tls_status_authentication_failure;
			}
			else if (qsc_kyber_decapsulate(kemsecret, servershare + 65U, clientprivatekey + EC_NISTP256_PRIVATEKEY_SIZE) == false)
			{
				status = qsc_tls_status_authentication_failure;
			}
			else
			{
				qsc_memutils_copy(sharedsecret + EC_NISTP256_SHAREDSECRET_SIZE, kemsecret, QSC_KYBER_SHAREDSECRET_SIZE);
				*sharedsecretlen = needsecret;
			}
		}

		qsc_memutils_secure_erase(rawserver, sizeof(rawserver));
	}

	qsc_memutils_secure_erase(kemsecret, sizeof(kemsecret));

	return status;
}
