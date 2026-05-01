#include "tlssigalgs.h"

static const qsc_tls_signature_scheme_descriptor qsc_tls_sigalg_descriptors[] =
{
	{ qsc_tls_sig_ecdsa_secp256r1_sha256, "ecdsa_secp256r1_sha256", qsc_tls_hash_sha256, 72U, true, true, false, false },
	{ qsc_tls_sig_ecdsa_secp384r1_sha384, "ecdsa_secp384r1_sha384", qsc_tls_hash_sha384, 104U, true, true, false, false },
	{ qsc_tls_sig_ed25519, "ed25519", qsc_tls_hash_none, 64U, true, true, false, false },
	{ qsc_tls_sig_mldsa44, "mldsa44", qsc_tls_hash_none, 2420U, true, true, true, true },
	{ qsc_tls_sig_mldsa65, "mldsa65", qsc_tls_hash_none, 3309U, true, true, true, true },
	{ qsc_tls_sig_mldsa87, "mldsa87", qsc_tls_hash_none, 4627U, true, true, true, true }
};

const qsc_tls_signature_scheme_descriptor* qsc_tls_signature_scheme_descriptor_get(qsc_tls_signature_scheme scheme)
{
	const qsc_tls_signature_scheme_descriptor* res;

	res = NULL;

	for (size_t i = 0U; i < (sizeof(qsc_tls_sigalg_descriptors) / sizeof(qsc_tls_sigalg_descriptors[0U])); ++i)
	{
		if (qsc_tls_sigalg_descriptors[i].scheme == scheme)
		{
			res = &qsc_tls_sigalg_descriptors[i];
			break;
		}
	}

	return res;
}

static bool tls_signature_scheme_is_build_compatible(qsc_tls_signature_scheme scheme)
{
	bool res;

	res = false;

	switch (scheme)
	{
		case qsc_tls_sig_ecdsa_secp256r1_sha256:
		{
	#if defined(QSC_ECDSA_S1P256)
			res = true;
	#else
			res = false;
	#endif
			break;
		}
		case qsc_tls_sig_ecdsa_secp384r1_sha384:
		{
	#if defined(QSC_ECDSA_S3P384)
			res = true;
	#else
			res = false;
	#endif
			break;
		}
		case qsc_tls_sig_ed25519:
		{
	#if defined(QSC_EDDSA_S1EC25519)
			res = true;
	#else
			res = false;
	#endif
			break;
		}
		case qsc_tls_sig_mldsa44:
		{
	#if defined(QSC_DILITHIUM_S1P44)
			res = true;
	#else
			res = false;
	#endif
			break;
		}
		case qsc_tls_sig_mldsa65:
		{
	#if defined(QSC_DILITHIUM_S3P65)
			res = true;
	#else
			res = false;
	#endif
			break;
		}
		case qsc_tls_sig_mldsa87:
		{
	#if defined(QSC_DILITHIUM_S5P87)
			res = true;
	#else
			res = false;
	#endif
			break;
		}
		default:
		{
			res = false;
			break;
		}
	}

	return res;
}

bool qsc_tls_signature_scheme_is_supported(qsc_tls_signature_scheme scheme)
{
	const qsc_tls_signature_scheme_descriptor* desc;

	desc = qsc_tls_signature_scheme_descriptor_get(scheme);

	return (desc != NULL) ? (desc->supported && tls_signature_scheme_is_build_compatible(scheme)) : false;
}

bool qsc_tls_signature_scheme_is_certificate_verify_capable(qsc_tls_signature_scheme scheme)
{
	const qsc_tls_signature_scheme_descriptor* desc;

	desc = qsc_tls_signature_scheme_descriptor_get(scheme);

	return (desc != NULL) ? desc->certificateverifycapable : false;
}

bool qsc_tls_signature_scheme_is_pq(qsc_tls_signature_scheme scheme)
{
	const qsc_tls_signature_scheme_descriptor* desc;

	desc = qsc_tls_signature_scheme_descriptor_get(scheme);

	return (desc != NULL) ? desc->ispq : false;
}

bool qsc_tls_signature_scheme_is_mldsa(qsc_tls_signature_scheme scheme)
{
	const qsc_tls_signature_scheme_descriptor* desc;

	desc = qsc_tls_signature_scheme_descriptor_get(scheme);

	return (desc != NULL) ? desc->ismldsa : false;
}

size_t qsc_tls_signature_scheme_private_key_size(qsc_tls_signature_scheme scheme)
{
	switch (scheme)
	{
		case qsc_tls_sig_ecdsa_secp256r1_sha256:
		{
			return 32U;
		}
		case qsc_tls_sig_ecdsa_secp384r1_sha384:
		{
			return 48U;
		}
		case qsc_tls_sig_ed25519:
		{
			return 64U;
		}
		case qsc_tls_sig_mldsa44:
		{
			return 2560U;
		}
		case qsc_tls_sig_mldsa65:
		{
			return 4032U;
		}
		case qsc_tls_sig_mldsa87:
		{
			return 4896U;
		}
		default:
		{
			return 0U;
		}
	}
}

size_t qsc_tls_signature_scheme_public_key_size(qsc_tls_signature_scheme scheme)
{
	switch (scheme)
	{
		case qsc_tls_sig_ecdsa_secp256r1_sha256:
		{
			return 64U;
		}
		case qsc_tls_sig_ecdsa_secp384r1_sha384:
		{
			return 96U;
		}
		case qsc_tls_sig_ed25519:
		{
			return 32U;
		}
		case qsc_tls_sig_mldsa44:
		{
			return 1312U;
		}
		case qsc_tls_sig_mldsa65:
		{
			return 1952U;
		}
		case qsc_tls_sig_mldsa87:
		{
			return 2592U;
		}
		default:
		{
			return 0U;
		}
	}
}

qsc_x509_signature_algorithm qsc_tls_signature_scheme_x509_algorithm(qsc_tls_signature_scheme scheme)
{
	qsc_x509_signature_algorithm res;

	res = QSC_X509_SIGNATURE_ALGORITHM_NONE;

	switch (scheme)
	{
		case qsc_tls_sig_ecdsa_secp256r1_sha256:
		{
			res = QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA256;
			break;
		}
		case qsc_tls_sig_ecdsa_secp384r1_sha384:
		{
			res = QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA384;
			break;
		}
		case qsc_tls_sig_ed25519:
		{
			res = QSC_X509_SIGNATURE_ALGORITHM_ED25519;
			break;
		}
		case qsc_tls_sig_mldsa44:
		{
			res = QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_44;
			break;
		}
		case qsc_tls_sig_mldsa65:
		{
			res = QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_65;
			break;
		}
		case qsc_tls_sig_mldsa87:
		{
			res = QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_87;
			break;
		}
		default:
		{
			break;
		}
	}

	return res;
}

bool qsc_tls_signature_scheme_matches_x509_algorithm(qsc_tls_signature_scheme scheme, qsc_x509_signature_algorithm algorithm)
{
	return (qsc_tls_signature_scheme_x509_algorithm(scheme) == algorithm);
}

size_t qsc_tls_signature_scheme_signature_size(qsc_tls_signature_scheme scheme)
{
	const qsc_tls_signature_scheme_descriptor* desc;

	desc = qsc_tls_signature_scheme_descriptor_get(scheme);

	return (desc != NULL) ? desc->signaturesize : 0U;
}

bool qsc_tls_signature_scheme_validate_signature_length(qsc_tls_signature_scheme scheme, size_t signaturelen)
{
	size_t expected;
	bool res;

	res = false;
	expected = qsc_tls_signature_scheme_signature_size(scheme);

	if (expected != 0U)
	{
		if ((scheme == qsc_tls_sig_ecdsa_secp256r1_sha256) || (scheme == qsc_tls_sig_ecdsa_secp384r1_sha384))
		{
			res = (signaturelen >= 8U && signaturelen <= expected);
		}
		else
		{
			res = (signaturelen == expected);
		}
	}

	return res;
}

qsc_tls_hash_algorithm qsc_tls_signature_scheme_hash(qsc_tls_signature_scheme scheme)
{
	const qsc_tls_signature_scheme_descriptor* desc;

	desc = qsc_tls_signature_scheme_descriptor_get(scheme);

	return (desc != NULL) ? desc->hash : qsc_tls_hash_none;
}

const char* qsc_tls_signature_scheme_name(qsc_tls_signature_scheme scheme)
{
	const qsc_tls_signature_scheme_descriptor* desc;

	desc = qsc_tls_signature_scheme_descriptor_get(scheme);

	return (desc != NULL) ? desc->name : "unknown";
}
