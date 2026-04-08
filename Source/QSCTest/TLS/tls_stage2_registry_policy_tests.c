#include "tls_stage2_registry_policy_tests.h"
#include "../testutils.h"
#include "memutils.h"
#include "tlsgroups.h"
#include "tlspolicy.h"
#include "tlssigalgs.h"
#include "tlstypes.h"

static size_t tls_stage2_append_group(qsc_tls_named_group* groups, size_t count, qsc_tls_named_group group)
{
	if (count < QSC_TLS_MAX_GROUPS)
	{
		groups[count] = group;
		++count;
	}

	return count;
}

static size_t tls_stage2_append_signature(qsc_tls_signature_scheme* sigs, size_t count, qsc_tls_signature_scheme sig)
{
	if (count < QSC_TLS_MAX_SIGNATURE_SCHEMES)
	{
		sigs[count] = sig;
		++count;
	}

	return count;
}

static bool tls_stage2_sequence_contains_group(const qsc_tls_named_group* groups, size_t count, qsc_tls_named_group group)
{
	bool res;
	size_t i;

	res = false;
	i = 0U;

	while (i < count)
	{
		if (groups[i] == group)
		{
			res = true;
			break;
		}
		++i;
	}

	return res;
}

static bool tls_stage2_sequence_contains_signature(const qsc_tls_signature_scheme* sigs, size_t count, qsc_tls_signature_scheme sig)
{
	bool res;
	size_t i;

	res = false;
	i = 0U;

	while (i < count)
	{
		if (sigs[i] == sig)
		{
			res = true;
			break;
		}
		++i;
	}

	return res;
}

static bool tls_stage2_expected_group_supported(qsc_tls_named_group group)
{
	bool res;

	res = false;

	switch (group)
	{
	case qsc_tls_group_x25519:
#if defined(QSC_EDDH_S1EC25519)
		res = true;
#endif
		break;
	case qsc_tls_group_secp256r1:
#if defined(QSC_ECDSA_S1P256)
		res = true;
#endif
		break;
	case qsc_tls_group_secp384r1:
#if defined(QSC_ECDSA_S3P384)
		res = true;
#endif
		break;
	case qsc_tls_group_x25519_mlkem512:
#if defined(QSC_EDDH_S1EC25519) && defined(QSC_KYBER_S1K2P512)
		res = true;
#endif
		break;
	case qsc_tls_group_x25519_mlkem768:
#if defined(QSC_EDDH_S1EC25519) && defined(QSC_KYBER_S3K3P768)
		res = true;
#endif
		break;
	case qsc_tls_group_x25519_mlkem1024:
#if defined(QSC_EDDH_S1EC25519) && defined(QSC_KYBER_S5K4P1024)
		res = true;
#endif
		break;
	case qsc_tls_group_secp256r1_mlkem512:
#if defined(QSC_ECDSA_S1P256) && defined(QSC_KYBER_S1K2P512)
		res = true;
#endif
		break;
	case qsc_tls_group_secp256r1_mlkem768:
#if defined(QSC_ECDSA_S1P256) && defined(QSC_KYBER_S3K3P768)
		res = true;
#endif
		break;
	case qsc_tls_group_secp256r1_mlkem1024:
#if defined(QSC_ECDSA_S1P256) && defined(QSC_KYBER_S5K4P1024)
		res = true;
#endif
		break;
	case qsc_tls_group_secp384r1_mlkem768:
#if defined(QSC_ECDSA_S3P384) && defined(QSC_KYBER_S3K3P768)
		res = true;
#endif
		break;
	case qsc_tls_group_secp384r1_mlkem1024:
#if defined(QSC_ECDSA_S3P384) && defined(QSC_KYBER_S5K4P1024)
		res = true;
#endif
		break;
	default:
		res = false;
		break;
	}

	return res;
}

static bool tls_stage2_expected_signature_supported(qsc_tls_signature_scheme scheme)
{
	bool res;

	res = false;

	switch (scheme)
	{
	case qsc_tls_sig_ecdsa_secp256r1_sha256:
#if defined(QSC_ECDSA_S1P256)
		res = true;
#endif
		break;
	case qsc_tls_sig_ecdsa_secp384r1_sha384:
#if defined(QSC_ECDSA_S3P384)
		res = true;
#endif
		break;
	case qsc_tls_sig_ed25519:
#if defined(QSC_EDDSA_S1EC25519)
		res = true;
#endif
		break;
	case qsc_tls_sig_mldsa44:
#if defined(QSC_DILITHIUM_S1P44)
		res = true;
#endif
		break;
	case qsc_tls_sig_mldsa65:
#if defined(QSC_DILITHIUM_S3P65)
		res = true;
#endif
		break;
	case qsc_tls_sig_mldsa87:
#if defined(QSC_DILITHIUM_S5P87)
		res = true;
#endif
		break;
	default:
		res = false;
		break;
	}

	return res;
}

static size_t tls_stage2_collect_expected_default_groups(qsc_tls_named_group* groups)
{
	size_t count;

	count = 0U;

#if defined(QSC_EDDH_S1EC25519)
	count = tls_stage2_append_group(groups, count, qsc_tls_group_x25519);
#elif defined(QSC_ECDSA_S1P256)
	count = tls_stage2_append_group(groups, count, qsc_tls_group_secp256r1);
#elif defined(QSC_ECDSA_S3P384)
	count = tls_stage2_append_group(groups, count, qsc_tls_group_secp384r1);
#endif

	return count;
}

static size_t tls_stage2_collect_expected_default_signatures(qsc_tls_signature_scheme* sigs)
{
	size_t count;

	count = 0U;

#if defined(QSC_ECDSA_S1P256)
	count = tls_stage2_append_signature(sigs, count, qsc_tls_sig_ecdsa_secp256r1_sha256);
#elif defined(QSC_ECDSA_S3P384)
	count = tls_stage2_append_signature(sigs, count, qsc_tls_sig_ecdsa_secp384r1_sha384);
#endif

	return count;
}

static size_t tls_stage2_collect_expected_hybrid_groups(qsc_tls_named_group* groups)
{
	size_t count;

	count = 0U;

#if defined(QSC_EDDH_S1EC25519) && defined(QSC_KYBER_S1K2P512)
	count = tls_stage2_append_group(groups, count, qsc_tls_group_x25519_mlkem512);
#endif
#if defined(QSC_EDDH_S1EC25519) && defined(QSC_KYBER_S3K3P768)
	count = tls_stage2_append_group(groups, count, qsc_tls_group_x25519_mlkem768);
#endif
#if defined(QSC_EDDH_S1EC25519) && defined(QSC_KYBER_S5K4P1024)
	count = tls_stage2_append_group(groups, count, qsc_tls_group_x25519_mlkem1024);
#endif
#if defined(QSC_ECDSA_S1P256) && defined(QSC_KYBER_S1K2P512)
	count = tls_stage2_append_group(groups, count, qsc_tls_group_secp256r1_mlkem512);
#endif
#if defined(QSC_ECDSA_S1P256) && defined(QSC_KYBER_S3K3P768)
	count = tls_stage2_append_group(groups, count, qsc_tls_group_secp256r1_mlkem768);
#endif
#if defined(QSC_ECDSA_S1P256) && defined(QSC_KYBER_S5K4P1024)
	count = tls_stage2_append_group(groups, count, qsc_tls_group_secp256r1_mlkem1024);
#endif
#if defined(QSC_ECDSA_S3P384) && defined(QSC_KYBER_S3K3P768)
	count = tls_stage2_append_group(groups, count, qsc_tls_group_secp384r1_mlkem768);
#endif
#if defined(QSC_ECDSA_S3P384) && defined(QSC_KYBER_S5K4P1024)
	count = tls_stage2_append_group(groups, count, qsc_tls_group_secp384r1_mlkem1024);
#endif

	return count;
}

static size_t tls_stage2_collect_expected_pq_signatures(qsc_tls_signature_scheme* sigs)
{
	size_t count;

	count = 0U;

#if defined(QSC_DILITHIUM_S1P44)
	count = tls_stage2_append_signature(sigs, count, qsc_tls_sig_mldsa44);
#endif
#if defined(QSC_DILITHIUM_S3P65)
	count = tls_stage2_append_signature(sigs, count, qsc_tls_sig_mldsa65);
#endif
#if defined(QSC_DILITHIUM_S5P87)
	count = tls_stage2_append_signature(sigs, count, qsc_tls_sig_mldsa87);
#endif

	return count;
}

static bool tls_stage2_sequence_matches_groups(const qsc_tls_named_group* lhs, const qsc_tls_named_group* rhs, size_t count)
{
	bool res;

	res = true;

	for (size_t i = 0U; i < count; ++i)
	{
		if (lhs[i] != rhs[i])
		{
			res = false;
			break;
		}
	}

	return res;
}

static bool tls_stage2_sequence_matches_signatures(const qsc_tls_signature_scheme* lhs, const qsc_tls_signature_scheme* rhs, size_t count)
{
	bool res;

	res = true;

	for (size_t i = 0U; i < count; ++i)
	{
		if (lhs[i] != rhs[i])
		{
			res = false;
			break;
		}
	}

	return res;
}

static bool qsctest_tls_stage2_group_registry_basic(void)
{
	const qsc_tls_named_group known[] =
	{
		qsc_tls_group_secp256r1,
		qsc_tls_group_secp384r1,
		qsc_tls_group_x25519,
		qsc_tls_group_x25519_mlkem512,
		qsc_tls_group_x25519_mlkem768,
		qsc_tls_group_secp256r1_mlkem768,
		qsc_tls_group_secp384r1_mlkem1024,
		qsc_tls_group_x25519_mlkem1024,
		qsc_tls_group_secp256r1_mlkem512,
		qsc_tls_group_secp256r1_mlkem1024,
		qsc_tls_group_secp384r1_mlkem768
	};

	const qsc_tls_named_group unsupported[] =
	{
		qsc_tls_group_none,
		(qsc_tls_named_group)0x1234,
		(qsc_tls_named_group)0xFFFF
	};

	bool res;
	size_t i;

	res = true;

	for (i = 0U; i < (sizeof(known) / sizeof(known[0U])); ++i)
	{
		if (qsc_tls_group_is_supported(known[i]) != tls_stage2_expected_group_supported(known[i]))
		{
			res = false;
			break;
		}
	}

	if (res == true)
	{
		for (i = 0U; i < (sizeof(unsupported) / sizeof(unsupported[0U])); ++i)
		{
			if (qsc_tls_group_is_supported(unsupported[i]) == true)
			{
				res = false;
				break;
			}
		}
	}

	return res;
}

static bool qsctest_tls_stage2_group_registry_properties(void)
{
	const qsc_tls_named_group hybrid_groups[] =
	{
		qsc_tls_group_x25519_mlkem512,
		qsc_tls_group_x25519_mlkem768,
		qsc_tls_group_x25519_mlkem1024,
		qsc_tls_group_secp256r1_mlkem512,
		qsc_tls_group_secp256r1_mlkem768,
		qsc_tls_group_secp256r1_mlkem1024,
		qsc_tls_group_secp384r1_mlkem768,
		qsc_tls_group_secp384r1_mlkem1024
	};

	bool res;
	size_t cpk;
	size_t kpk;
	size_t pk;
	size_t sk;
	size_t ct;
	size_t ss;
	size_t i;
	uint16_t bits;

	res = true;
	bits = qsc_tls_group_active_mlkem_parameter_bits();

	if (qsc_tls_group_is_hybrid(qsc_tls_group_x25519) == true ||
		qsc_tls_group_is_hybrid(qsc_tls_group_secp256r1) == true ||
		qsc_tls_group_is_hybrid(qsc_tls_group_secp384r1) == true)
	{
		res = false;
	}

	if (res == true)
	{
		const size_t hybrid_group_count = sizeof(hybrid_groups) / sizeof(hybrid_groups[0]);

		for (i = 0U; i < hybrid_group_count; ++i)
		{
			if (qsc_tls_group_is_supported(hybrid_groups[i]) == true)
			{
				if (qsc_tls_group_is_hybrid(hybrid_groups[i]) == false)
				{
					res = false;
					break;
				}

				if (qsc_tls_group_public_key_size(hybrid_groups[i]) == 0U)
				{
					res = false;
					break;
				}

				if (qsc_tls_group_ciphertext_size(hybrid_groups[i]) == 0U)
				{
					res = false;
					break;
				}

				if (qsc_tls_group_shared_secret_size(hybrid_groups[i]) == 0U)
				{
					res = false;
					break;
				}
			}
		}
	}

	cpk = qsc_tls_group_classical_public_key_size(qsc_tls_group_x25519);
	kpk = qsc_tls_group_kem_public_key_size(qsc_tls_group_x25519);
	pk = qsc_tls_group_public_key_size(qsc_tls_group_x25519);
	sk = qsc_tls_group_private_key_size(qsc_tls_group_x25519);
	ct = qsc_tls_group_ciphertext_size(qsc_tls_group_x25519);
	ss = qsc_tls_group_shared_secret_size(qsc_tls_group_x25519);

	if (res == true)
	{
		res = (cpk == 32U && kpk == 0U && pk == 32U && sk == 32U && ct == 0U && ss == 32U);
	}

	cpk = qsc_tls_group_classical_public_key_size(qsc_tls_group_secp256r1);
	kpk = qsc_tls_group_kem_public_key_size(qsc_tls_group_secp256r1);
	pk = qsc_tls_group_public_key_size(qsc_tls_group_secp256r1);
	sk = qsc_tls_group_private_key_size(qsc_tls_group_secp256r1);
	ct = qsc_tls_group_ciphertext_size(qsc_tls_group_secp256r1);
	ss = qsc_tls_group_shared_secret_size(qsc_tls_group_secp256r1);

	if (res == true)
	{
		res = (cpk == 65U && kpk == 0U && pk == 65U && sk >= 32U && ct == 0U && ss == 32U);
	}

	cpk = qsc_tls_group_classical_public_key_size(qsc_tls_group_secp384r1);
	kpk = qsc_tls_group_kem_public_key_size(qsc_tls_group_secp384r1);
	pk = qsc_tls_group_public_key_size(qsc_tls_group_secp384r1);
	sk = qsc_tls_group_private_key_size(qsc_tls_group_secp384r1);
	ct = qsc_tls_group_ciphertext_size(qsc_tls_group_secp384r1);
	ss = qsc_tls_group_shared_secret_size(qsc_tls_group_secp384r1);

	if (res == true)
	{
		res = (cpk == 97U && kpk == 0U && pk == 97U && sk >= 48U && ct == 0U && ss == 48U);
	}

	if (res == true)
	{
		const qsc_tls_named_group xhyb =
			(bits == 512U) ? qsc_tls_group_x25519_mlkem512 :
			(bits == 768U) ? qsc_tls_group_x25519_mlkem768 :
			(bits == 1024U) ? qsc_tls_group_x25519_mlkem1024 :
			qsc_tls_group_none;
		const qsc_tls_named_group phyb =
			(bits == 512U) ? qsc_tls_group_secp256r1_mlkem512 :
			(bits == 768U) ? qsc_tls_group_secp256r1_mlkem768 :
			(bits == 1024U) ? qsc_tls_group_secp256r1_mlkem1024 :
			qsc_tls_group_none;
		const qsc_tls_named_group p384hyb =
			(bits == 768U) ? qsc_tls_group_secp384r1_mlkem768 :
			(bits == 1024U) ? qsc_tls_group_secp384r1_mlkem1024 :
			qsc_tls_group_none;

		if (xhyb != qsc_tls_group_none)
		{
			cpk = qsc_tls_group_classical_public_key_size(xhyb);
			kpk = qsc_tls_group_kem_public_key_size(xhyb);
			pk = qsc_tls_group_public_key_size(xhyb);
			sk = qsc_tls_group_private_key_size(xhyb);
			ct = qsc_tls_group_ciphertext_size(xhyb);
			ss = qsc_tls_group_shared_secret_size(xhyb);
			res = (cpk == 32U && kpk != 0U && pk == (cpk + kpk) && sk > 32U && ct != 0U && ss == (32U + 32U));
		}

		if (res == true && phyb != qsc_tls_group_none)
		{
			cpk = qsc_tls_group_classical_public_key_size(phyb);
			kpk = qsc_tls_group_kem_public_key_size(phyb);
			pk = qsc_tls_group_public_key_size(phyb);
			sk = qsc_tls_group_private_key_size(phyb);
			ct = qsc_tls_group_ciphertext_size(phyb);
			ss = qsc_tls_group_shared_secret_size(phyb);
			res = (cpk == 65U && kpk != 0U && pk == (cpk + kpk) && sk > 32U && ct != 0U && ss == (32U + 32U));
		}

		//if (res == true && p384hyb != qsc_tls_group_none)
		//{
		//	cpk = qsc_tls_group_classical_public_key_size(p384hyb);
		//	kpk = qsc_tls_group_kem_public_key_size(p384hyb);
		//	pk = qsc_tls_group_public_key_size(p384hyb);
		//	sk = qsc_tls_group_private_key_size(p384hyb);
		//	ct = qsc_tls_group_ciphertext_size(p384hyb);
		//	ss = qsc_tls_group_shared_secret_size(p384hyb);
		//	res = (cpk == 97U && kpk != 0U && pk == (cpk + kpk) && sk > 48U && ct != 0U && ss == (48U + 32U));
		//}
	}

	if (res == true)
	{
		res = (qsc_tls_group_name(qsc_tls_group_x25519) != NULL &&
			qsc_tls_group_name(qsc_tls_group_x25519)[0] != '\0' &&
			qsc_tls_group_active_name(qsc_tls_group_x25519) != NULL &&
			qsc_tls_group_active_name(qsc_tls_group_x25519)[0] != '\0' &&
			qsc_tls_group_openssl_name(qsc_tls_group_x25519) != NULL &&
			qsc_tls_group_openssl_name(qsc_tls_group_x25519)[0] != '\0');
	}

	if (res == true)
	{
		for (i = 0U; i < (sizeof(hybrid_groups) / sizeof(hybrid_groups[0])); ++i)
		{
			if (qsc_tls_group_name(hybrid_groups[i]) == NULL ||
				qsc_tls_group_active_name(hybrid_groups[i]) == NULL ||
				qsc_tls_group_openssl_name(hybrid_groups[i]) == NULL)
			{
				res = false;
				break;
			}
		}
	}

	if (res == true)
	{
		res = (bits == 0U || bits == 512U || bits == 768U || bits == 1024U || bits == 1280U);
	}

	return res;
}

static bool qsctest_tls_stage2_signature_registry_basic(void)
{
	const qsc_tls_signature_scheme known[] =
	{
		qsc_tls_sig_ecdsa_secp256r1_sha256,
		qsc_tls_sig_ecdsa_secp384r1_sha384,
		qsc_tls_sig_ed25519,
		qsc_tls_sig_mldsa44,
		qsc_tls_sig_mldsa65,
		qsc_tls_sig_mldsa87
	};

	const qsc_tls_signature_scheme unsupported[] =
	{
		qsc_tls_sig_none,
		(qsc_tls_signature_scheme)0x0001,
		(qsc_tls_signature_scheme)0xFFFF
	};

	bool res;
	size_t i;

	res = true;

	for (i = 0U; i < (sizeof(known) / sizeof(known[0U])); ++i)
	{
		if (qsc_tls_signature_scheme_is_supported(known[i]) != tls_stage2_expected_signature_supported(known[i]))
		{
			res = false;
			break;
		}

		if (qsc_tls_signature_scheme_is_supported(known[i]) == true &&
			qsc_tls_signature_scheme_is_certificate_verify_capable(known[i]) == false)
		{
			res = false;
			break;
		}
	}

	if (res == true)
	{
		for (i = 0U; i < (sizeof(unsupported) / sizeof(unsupported[0U])); ++i)
		{
			if (qsc_tls_signature_scheme_is_supported(unsupported[i]) == true ||
				qsc_tls_signature_scheme_is_certificate_verify_capable(unsupported[i]) == true)
			{
				res = false;
				break;
			}
		}
	}

	return res;
}

static bool qsctest_tls_stage2_signature_registry_properties(void)
{
	bool res;

	res = true;

	if (qsc_tls_signature_scheme_is_pq(qsc_tls_sig_ecdsa_secp256r1_sha256) == true ||
		qsc_tls_signature_scheme_is_pq(qsc_tls_sig_ecdsa_secp384r1_sha384) == true ||
		qsc_tls_signature_scheme_is_pq(qsc_tls_sig_ed25519) == true)
	{
		res = false;
	}

	if (res == true)
	{
		if (qsc_tls_signature_scheme_is_pq(qsc_tls_sig_mldsa44) == false ||
			qsc_tls_signature_scheme_is_pq(qsc_tls_sig_mldsa65) == false ||
			qsc_tls_signature_scheme_is_pq(qsc_tls_sig_mldsa87) == false)
		{
			res = false;
		}
	}

	if (res == true)
	{
		if (qsc_tls_signature_scheme_is_mldsa(qsc_tls_sig_mldsa44) == false ||
			qsc_tls_signature_scheme_is_mldsa(qsc_tls_sig_mldsa65) == false ||
			qsc_tls_signature_scheme_is_mldsa(qsc_tls_sig_mldsa87) == false)
		{
			res = false;
		}
	}

	if (res == true)
	{
		res = (qsc_tls_signature_scheme_hash(qsc_tls_sig_ecdsa_secp256r1_sha256) == qsc_tls_hash_sha256 &&
			qsc_tls_signature_scheme_hash(qsc_tls_sig_ecdsa_secp384r1_sha384) == qsc_tls_hash_sha384 &&
			qsc_tls_signature_scheme_hash(qsc_tls_sig_ed25519) == qsc_tls_hash_none &&
			qsc_tls_signature_scheme_hash(qsc_tls_sig_mldsa44) == qsc_tls_hash_none &&
			qsc_tls_signature_scheme_hash(qsc_tls_sig_mldsa65) == qsc_tls_hash_none &&
			qsc_tls_signature_scheme_hash(qsc_tls_sig_mldsa87) == qsc_tls_hash_none);
	}

	if (res == true)
	{
		res = (qsc_tls_signature_scheme_signature_size(qsc_tls_sig_ecdsa_secp256r1_sha256) == 72U &&
			qsc_tls_signature_scheme_signature_size(qsc_tls_sig_ecdsa_secp384r1_sha384) == 104U &&
			qsc_tls_signature_scheme_signature_size(qsc_tls_sig_ed25519) == 64U &&
			qsc_tls_signature_scheme_signature_size(qsc_tls_sig_mldsa44) == 2420U &&
			qsc_tls_signature_scheme_signature_size(qsc_tls_sig_mldsa65) == 3309U &&
			qsc_tls_signature_scheme_signature_size(qsc_tls_sig_mldsa87) == 4627U &&
			qsc_tls_signature_scheme_signature_size(qsc_tls_sig_none) == 0U);
	}

	if (res == true)
	{
		res = (qsc_tls_signature_scheme_name(qsc_tls_sig_ecdsa_secp256r1_sha256)[0] != '\0' &&
			qsc_tls_signature_scheme_name(qsc_tls_sig_ecdsa_secp384r1_sha384)[0] != '\0' &&
			qsc_tls_signature_scheme_name(qsc_tls_sig_ed25519)[0] != '\0' &&
			qsc_tls_signature_scheme_name(qsc_tls_sig_mldsa44)[0] != '\0' &&
			qsc_tls_signature_scheme_name(qsc_tls_sig_mldsa65)[0] != '\0' &&
			qsc_tls_signature_scheme_name(qsc_tls_sig_mldsa87)[0] != '\0' &&
			qsc_tls_signature_scheme_name(qsc_tls_sig_none)[0] != '\0');
	}

	return res;
}

static bool qsctest_tls_stage2_policy_defaults(void)
{
	qsc_tls_policy policy = { 0 };
	qsc_tls_named_group expectedgroups[QSC_TLS_MAX_GROUPS] = { 0 };
	qsc_tls_signature_scheme expectedsigs[QSC_TLS_MAX_SIGNATURE_SCHEMES] = { 0 };
	size_t expectedgroupcount;
	size_t expectedsignaturecount;
	bool res;

	qsc_memutils_clear((uint8_t*)&policy, sizeof(policy));
	qsc_tls_policy_initialize_default(&policy);
	res = true;
	expectedgroupcount = tls_stage2_collect_expected_default_groups(expectedgroups);
	expectedsignaturecount = tls_stage2_collect_expected_default_signatures(expectedsigs);

	if (policy.allowclassical != true ||
		policy.allowhybrid != false ||
		policy.allowpqsignatures != false ||
		policy.permittedgroupcount != expectedgroupcount ||
		policy.permittedsignaturecount != expectedsignaturecount)
	{
		res = false;
	}

	if (res == true)
	{
		res = tls_stage2_sequence_matches_groups(policy.permittedgroups, expectedgroups, expectedgroupcount);
	}

	if (res == true)
	{
		res = tls_stage2_sequence_matches_signatures(policy.permittedsignatures, expectedsigs, expectedsignaturecount);
	}

	if (res == true)
	{
		res = (qsc_tls_policy_group_allowed(&policy, qsc_tls_group_x25519) == tls_stage2_sequence_contains_group(expectedgroups, expectedgroupcount, qsc_tls_group_x25519) &&
			qsc_tls_policy_group_allowed(&policy, qsc_tls_group_secp256r1) == tls_stage2_sequence_contains_group(expectedgroups, expectedgroupcount, qsc_tls_group_secp256r1) &&
			qsc_tls_policy_group_allowed(&policy, qsc_tls_group_secp384r1) == tls_stage2_sequence_contains_group(expectedgroups, expectedgroupcount, qsc_tls_group_secp384r1) &&
			qsc_tls_policy_group_allowed(&policy, qsc_tls_group_x25519_mlkem512) == false &&
			qsc_tls_policy_group_allowed(&policy, qsc_tls_group_x25519_mlkem768) == false &&
			qsc_tls_policy_group_allowed(&policy, qsc_tls_group_x25519_mlkem1024) == false &&
			qsc_tls_policy_group_allowed(&policy, qsc_tls_group_secp256r1_mlkem512) == false &&
			qsc_tls_policy_group_allowed(&policy, qsc_tls_group_secp256r1_mlkem768) == false &&
			qsc_tls_policy_group_allowed(&policy, qsc_tls_group_secp256r1_mlkem1024) == false &&
			qsc_tls_policy_group_allowed(&policy, qsc_tls_group_secp384r1_mlkem768) == false &&
			qsc_tls_policy_group_allowed(&policy, qsc_tls_group_secp384r1_mlkem1024) == false);
	}

	if (res == true)
	{
		res = (qsc_tls_policy_signature_allowed(&policy, qsc_tls_sig_ecdsa_secp256r1_sha256) == tls_stage2_sequence_contains_signature(expectedsigs, expectedsignaturecount, qsc_tls_sig_ecdsa_secp256r1_sha256) &&
			qsc_tls_policy_signature_allowed(&policy, qsc_tls_sig_ecdsa_secp384r1_sha384) == tls_stage2_sequence_contains_signature(expectedsigs, expectedsignaturecount, qsc_tls_sig_ecdsa_secp384r1_sha384) &&
			qsc_tls_policy_signature_allowed(&policy, qsc_tls_sig_ed25519) == tls_stage2_sequence_contains_signature(expectedsigs, expectedsignaturecount, qsc_tls_sig_ed25519) &&
			qsc_tls_policy_signature_allowed(&policy, qsc_tls_sig_mldsa44) == false &&
			qsc_tls_policy_signature_allowed(&policy, qsc_tls_sig_mldsa65) == false &&
			qsc_tls_policy_signature_allowed(&policy, qsc_tls_sig_mldsa87) == false);
	}

	if (res == true)
	{
		res = (qsc_tls_policy_group_allowed(NULL, qsc_tls_group_x25519) == false &&
			qsc_tls_policy_signature_allowed(NULL, qsc_tls_sig_ecdsa_secp256r1_sha256) == false &&
			qsc_tls_policy_group_allowed(&policy, qsc_tls_group_none) == false &&
			qsc_tls_policy_signature_allowed(&policy, qsc_tls_sig_none) == false);
	}

	return res;
}

static bool qsctest_tls_stage2_policy_filtering(void)
{
	qsc_tls_policy policy = { 0 };
	qsc_tls_named_group expectedhybridgroups[QSC_TLS_MAX_GROUPS] = { 0 };
	qsc_tls_signature_scheme expectedpqsigs[QSC_TLS_MAX_SIGNATURE_SCHEMES] = { 0 };
	bool res;
	size_t hybridcount;
	size_t pqsigcount;
	size_t i;

	qsc_memutils_clear((uint8_t*)&policy, sizeof(policy));
	qsc_tls_policy_initialize_default(&policy);
	res = true;
	hybridcount = tls_stage2_collect_expected_hybrid_groups(expectedhybridgroups);
	pqsigcount = tls_stage2_collect_expected_pq_signatures(expectedpqsigs);

	policy.allowclassical = false;
	policy.allowhybrid = true;
	policy.allowpqsignatures = true;
	policy.permittedgroupcount = hybridcount;

	for (i = 0U; i < hybridcount; ++i)
	{
		policy.permittedgroups[i] = expectedhybridgroups[i];
	}

	policy.permittedsignaturecount = 0U;

#if defined(QSC_ECDSA_S1P256)
	policy.permittedsignatures[policy.permittedsignaturecount] = qsc_tls_sig_ecdsa_secp256r1_sha256;
	++policy.permittedsignaturecount;
#endif
#if defined(QSC_ECDSA_S3P384)
	policy.permittedsignatures[policy.permittedsignaturecount] = qsc_tls_sig_ecdsa_secp384r1_sha384;
	++policy.permittedsignaturecount;
#endif
#if defined(QSC_EDDSA_S1EC25519)
	policy.permittedsignatures[policy.permittedsignaturecount] = qsc_tls_sig_ed25519;
	++policy.permittedsignaturecount;
#endif

	for (i = 0U; i < pqsigcount; ++i)
	{
		policy.permittedsignatures[policy.permittedsignaturecount] = expectedpqsigs[i];
		++policy.permittedsignaturecount;
	}

	if (qsc_tls_policy_group_allowed(&policy, qsc_tls_group_x25519) == true ||
		qsc_tls_policy_group_allowed(&policy, qsc_tls_group_secp256r1) == true ||
		qsc_tls_policy_group_allowed(&policy, qsc_tls_group_secp384r1) == true)
	{
		res = false;
	}

	if (res == true)
	{
		res = true;
		for (i = 0U; i < hybridcount; ++i)
		{
			if (qsc_tls_policy_group_allowed(&policy, expectedhybridgroups[i]) == false)
			{
				res = false;
				break;
			}
		}
	}

	if (res == true)
	{
#if defined(QSC_ECDSA_S1P256)
		if (qsc_tls_policy_signature_allowed(&policy, qsc_tls_sig_ecdsa_secp256r1_sha256) == false)
		{
			res = false;
		}
#endif
#if defined(QSC_ECDSA_S3P384)
		if (res == true && qsc_tls_policy_signature_allowed(&policy, qsc_tls_sig_ecdsa_secp384r1_sha384) == false)
		{
			res = false;
		}
#endif
#if defined(QSC_EDDSA_S1EC25519)
		if (res == true && qsc_tls_policy_signature_allowed(&policy, qsc_tls_sig_ed25519) == false)
		{
			res = false;
		}
#endif
		for (i = 0U; res == true && i < pqsigcount; ++i)
		{
			if (qsc_tls_policy_signature_allowed(&policy, expectedpqsigs[i]) == false)
			{
				res = false;
				break;
			}
		}
	}

	policy.allowhybrid = false;
	policy.allowpqsignatures = false;

	if (res == true)
	{
		for (i = 0U; i < hybridcount; ++i)
		{
			if (qsc_tls_policy_group_allowed(&policy, expectedhybridgroups[i]) == true)
			{
				res = false;
				break;
			}
		}
	}

	if (res == true)
	{
		for (i = 0U; i < pqsigcount; ++i)
		{
			if (qsc_tls_policy_signature_allowed(&policy, expectedpqsigs[i]) == true)
			{
				res = false;
				break;
			}
		}
	}

	return res;
}

bool qsctest_tls_stage2_tests(void)
{
	bool res;

	res = true;

	if (qsctest_tls_stage2_group_registry_basic() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 2 group registry support tests.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 2 group registry support tests.");
		res = false;
	}

	if (qsctest_tls_stage2_group_registry_properties() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 2 group registry property tests.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 2 group registry property tests.");
		res = false;
	}

	if (qsctest_tls_stage2_signature_registry_basic() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 2 signature registry support tests.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 2 signature registry support tests.");
		res = false;
	}

	if (qsctest_tls_stage2_signature_registry_properties() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 2 signature registry property tests.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 2 signature registry property tests.");
		res = false;
	}

	if (qsctest_tls_stage2_policy_defaults() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 2 policy default tests.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 2 policy default tests.");
		res = false;
	}

	if (qsctest_tls_stage2_policy_filtering() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 2 policy filtering tests.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 2 policy filtering tests.");
		res = false;
	}

	return res;
}
