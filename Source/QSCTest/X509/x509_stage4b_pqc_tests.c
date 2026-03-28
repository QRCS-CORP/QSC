#include "x509_stage4b_pqc_tests.h"
#include "../testutils.h"
#include "x509_test_helper.h"
#include "asn1.h"
#include "csp.h"
#include "dilithium.h"
#include "encoding.h"
#include "kyber.h"
#include "memutils.h"
#include "stringutils.h"
#include "timestamp.h"
#include "x509cert.h"
#include "x509certwrite.h"
#include "x509csr.h"
#include "x509key.h"
#include "x509keywrite.h"
#include "x509name.h"
#include "x509pem.h"
#include "x509sigver.h"
#include "x509spki.h"
#include "x509store.h"
#include "x509verify.h"
#include "x509write.h"

#define TESTBUF 32768U
#define DERBUF QSC_X509_CERTIFICATE_WRITE_MAX
#define PEMBUF QSC_X509_PEM_TEXT_MAX

#if !defined(QSC_DILITHIUM_SIGNATURE_SIZE)
#	error Stage 4 PQC tests require a Dilithium/ML-DSA parameter set to be enabled.
#endif

#if !defined(QSC_KYBER_PUBLICKEY_SIZE) || !defined(QSC_KYBER_PRIVATEKEY_SIZE)
#	error Stage 4 PQC tests require a Kyber/ML-KEM parameter set to be enabled.
#endif

typedef struct stage4_sign_context_t
{
	uint8_t privatekey[QSC_DILITHIUM_PRIVATEKEY_SIZE];
	bool (*rng_generate)(uint8_t*, size_t);
} stage4_sign_context;

static qsc_x509_pqc_parameter_set stage4_mldsa_parameter(void)
{
#if defined(QSC_DILITHIUM_S1P44)
	return QSC_X509_PQC_PARAMETER_SET_ML_DSA_44;
#elif defined(QSC_DILITHIUM_S3P65)
	return QSC_X509_PQC_PARAMETER_SET_ML_DSA_65;
#else
	return QSC_X509_PQC_PARAMETER_SET_ML_DSA_87;
#endif
}

static uint32_t stage4_mldsa_level(void)
{
#if defined(QSC_DILITHIUM_S1P44)
	return 44U;
#elif defined(QSC_DILITHIUM_S3P65)
	return 65U;
#else
	return 87U;
#endif
}

static qsc_x509_signature_algorithm stage4_mldsa_signature_algorithm(void)
{
#if defined(QSC_DILITHIUM_S1P44)
	return QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_44;
#elif defined(QSC_DILITHIUM_S3P65)
	return QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_65;
#else
	return QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_87;
#endif
}

static uint32_t stage4_mlkem_level(void)
{
#if defined(QSC_KYBER_S1K2P512)
	return 512U;
#elif defined(QSC_KYBER_S3K3P768)
	return 768U;
#else
	return 1024U;
#endif
}

static qsc_x509_pqc_parameter_set stage4_mlkem_parameter(void)
{
#if defined(QSC_KYBER_S1K2P512)
	return QSC_X509_PQC_PARAMETER_SET_ML_KEM_512;
#elif defined(QSC_KYBER_S3K3P768)
	return QSC_X509_PQC_PARAMETER_SET_ML_KEM_768;
#else
	return QSC_X509_PQC_PARAMETER_SET_ML_KEM_1024;
#endif
}

static void stage4_fill_name(qsc_x509_name* name, const char* commonname, const char* organization)
{
	size_t len;

	qsc_memutils_clear(name, sizeof(*name));
	name->count = 0U;

	if (organization != NULL)
	{
		name->attributes[name->count].type = QSC_X509_NAME_ATTRIBUTE_ORGANIZATION_NAME;
		name->attributes[name->count].string_tag = BER_ASN1_UTF8_STRING;
		name->attributes[name->count].rdn_index = 0U;
		len = qsc_stringutils_string_size(organization);

		if (len > QSC_X509_NAME_ATTRIBUTE_STRING_MAX)
		{
			len = QSC_X509_NAME_ATTRIBUTE_STRING_MAX;
		}

		qsc_memutils_copy((uint8_t*)name->attributes[name->count].value, (const uint8_t*)organization, len);
		name->attributes[name->count].value[len] = 0;
		name->attributes[name->count].length = len;
		++name->count;
	}

	if (commonname != NULL)
	{
		name->attributes[name->count].type = QSC_X509_NAME_ATTRIBUTE_COMMON_NAME;
		name->attributes[name->count].string_tag = BER_ASN1_UTF8_STRING;
		name->attributes[name->count].rdn_index = (uint16_t)name->count;
		len = qsc_stringutils_string_size(commonname);

		if (len > QSC_X509_NAME_ATTRIBUTE_STRING_MAX)
		{
			len = QSC_X509_NAME_ATTRIBUTE_STRING_MAX;
		}

		qsc_memutils_copy((uint8_t*)name->attributes[name->count].value, (const uint8_t*)commonname, len);
		name->attributes[name->count].value[len] = 0;
		name->attributes[name->count].length = len;
		++name->count;
	}
}

static void stage4_make_validity(qsc_x509_validity* validity)
{
	qsctest_x509_current_time(&validity->notbefore);
	validity->notafter = validity->notbefore;
	++validity->notafter.year;
	validity->notafter.generalized = (validity->notafter.year >= 2050U);
}

static void stage4_fill_serial(uint8_t* serial, size_t* seriallen, uint8_t tag)
{
	serial[0U] = 0x01U;
	serial[1U] = 0x23U;
	serial[2U] = 0x45U;
	serial[3U] = 0x67U;
	serial[4U] = 0x89U;
	serial[5U] = 0xABU;
	serial[6U] = 0xCDU;
	serial[7U] = tag;
	*seriallen = 8U;
}

static qsc_asn1_status stage4_mldsa_sign_callback(qsc_x509_signature_algorithm signaturealgorithm,
	const uint8_t* tbsdata, size_t tbsdatalen, uint8_t* signature, size_t* signaturelen, void* context)
{
	stage4_sign_context* sctx;
	uint8_t signedmsg[QSC_DILITHIUM_SIGNATURE_SIZE + DERBUF] = { 0U };
	size_t smsglen;

	if ((tbsdata == NULL) || (signature == NULL) || (signaturelen == NULL) || (context == NULL))
	{
		return QSC_ASN1_STATUS_INVALID_INPUT;
	}

	if (signaturealgorithm != stage4_mldsa_signature_algorithm())
	{
		return QSC_ASN1_STATUS_UNSUPPORTED;
	}

	sctx = (stage4_sign_context*)context;

	if (sctx->rng_generate == NULL)
	{
		return QSC_ASN1_STATUS_INVALID_INPUT;
	}

	if (*signaturelen < QSC_DILITHIUM_SIGNATURE_SIZE)
	{
		*signaturelen = QSC_DILITHIUM_SIGNATURE_SIZE;
		return QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
	}

	smsglen = sizeof(signedmsg);

	if (qsc_dilithium_sign(signedmsg, &smsglen, tbsdata, tbsdatalen, sctx->privatekey, sctx->rng_generate) != true)
	{
		return QSC_ASN1_STATUS_FAILURE;
	}

	if (smsglen < (QSC_DILITHIUM_SIGNATURE_SIZE + tbsdatalen))
	{
		return QSC_ASN1_STATUS_FAILURE;
	}

	qsc_memutils_copy(signature, signedmsg, QSC_DILITHIUM_SIGNATURE_SIZE);
	*signaturelen = QSC_DILITHIUM_SIGNATURE_SIZE;

	return QSC_ASN1_STATUS_SUCCESS;
}

static bool stage4_decode_spki_der(const uint8_t* der, size_t derlen, qsc_x509_subject_public_key_info* spki)
{
	qsc_encoding_ber_element* element;
	size_t consumed;
	bool res;

	res = false;
	consumed = 0U;
	element = qsc_encoding_der_decode_element(der, derlen, &consumed);

	if (element != NULL)
	{
		res = (qsc_x509_subject_public_key_info_decode(element, spki) == QSC_ASN1_STATUS_SUCCESS);
		qsc_encoding_ber_free_element(element);
	}

	return res;
}

static bool stage4_build_mldsa_csr(uint8_t* der, size_t* derlen, uint8_t* publickey, uint8_t* privatekey)
{
	qsc_x509_csr csr = { 0 };
	qsc_x509_name subject = { 0 };
	qsc_x509_subject_alt_name san = { 0 };
	stage4_sign_context signctx = { 0 };

	qsc_memutils_clear(&csr, sizeof(csr));
	qsc_memutils_clear(&san, sizeof(san));
	stage4_fill_name(&subject, "stage4-csr.example.test", "QRCS Stage4");
	qsc_memutils_copy(signctx.privatekey, privatekey, sizeof(signctx.privatekey));
	signctx.rng_generate = qsc_csp_generate;

	if (qsc_x509_csr_set_subject(&csr, &subject) != QSC_ASN1_STATUS_SUCCESS)
	{
		return false;
	}

	if (qsc_x509_csr_set_ml_dsa_spki(&csr, stage4_mldsa_level(), publickey, QSC_DILITHIUM_PUBLICKEY_SIZE) != QSC_ASN1_STATUS_SUCCESS)
	{
		return false;
	}

	if (qsc_x509_csr_set_ml_dsa_signature_algorithm(&csr, stage4_mldsa_level()) != QSC_ASN1_STATUS_SUCCESS)
	{
		return false;
	}

	san.present = true;
	san.count = 1U;
	san.entries[0U].type = QSC_X509_GENERAL_NAME_DNS_NAME;
	san.entries[0U].length = qsc_stringutils_string_size("stage4-csr.example.test");
	qsc_memutils_copy(san.entries[0].data, (const uint8_t*)"stage4-csr.example.test", san.entries[0].length);

	if (qsc_x509_csr_set_subject_alt_name(&csr, &san) != QSC_ASN1_STATUS_SUCCESS)
	{
		return false;
	}

	return (qsc_x509_csr_sign(&csr, stage4_mldsa_sign_callback, &signctx, der, derlen) == QSC_ASN1_STATUS_SUCCESS);
}

static bool stage4_build_root_certificate(uint8_t* der, size_t* derlen, uint8_t* publickey, uint8_t* privatekey)
{
	qsc_x509_certificate_builder builder = { 0 };
	qsc_x509_name name = { 0 };
	qsc_x509_validity validity = { 0 };
	qsc_x509_algorithm_identifier sigalg = { 0 };
	qsc_x509_subject_public_key_info spki = { 0 };
	stage4_sign_context signctx = { 0 };
	uint8_t serial[8U] = { 0U };
	size_t seriallen;

	qsc_x509_certificate_builder_initialize(&builder);
	qsc_x509_subject_public_key_info_initialize(&spki);
	qsc_memutils_clear(&sigalg, sizeof(sigalg));
	qsc_memutils_copy(signctx.privatekey, privatekey, sizeof(signctx.privatekey));
	signctx.rng_generate = qsc_csp_generate;

	stage4_fill_name(&name, "stage4-root.example.test", "QRCS Stage4");
	stage4_make_validity(&validity);
	stage4_fill_serial(serial, &seriallen, 0x11U);

	if (qsc_x509_spki_initialize_ml_dsa(&spki, stage4_mldsa_parameter(), publickey, QSC_DILITHIUM_PUBLICKEY_SIZE) != QSC_ASN1_STATUS_SUCCESS)
	{
		return false;
	}

	if (qsc_x509_algorithm_identifier_initialize_mldsa(&sigalg, stage4_mldsa_parameter()) != QSC_ASN1_STATUS_SUCCESS)
	{
		return false;
	}

	if (qsc_x509_certificate_builder_set_serial(&builder, serial, seriallen) != QSC_ASN1_STATUS_SUCCESS ||
		qsc_x509_certificate_builder_set_issuer(&builder, &name) != QSC_ASN1_STATUS_SUCCESS ||
		qsc_x509_certificate_builder_set_subject(&builder, &name) != QSC_ASN1_STATUS_SUCCESS ||
		qsc_x509_certificate_builder_set_validity(&builder, &validity) != QSC_ASN1_STATUS_SUCCESS ||
		qsc_x509_certificate_builder_set_spki(&builder, &spki) != QSC_ASN1_STATUS_SUCCESS ||
		qsc_x509_certificate_builder_set_signature_algorithm(&builder, &sigalg) != QSC_ASN1_STATUS_SUCCESS ||
		qsc_x509_certificate_builder_apply_profile(&builder, QSC_X509_CERT_PROFILE_ROOT_CA) != QSC_ASN1_STATUS_SUCCESS ||
		qsc_x509_certificate_builder_apply_generated_identifiers(&builder, NULL) != QSC_ASN1_STATUS_SUCCESS ||
		qsc_x509_certificate_builder_validate_profile(&builder, NULL, QSC_X509_CERT_PROFILE_ROOT_CA) != QSC_ASN1_STATUS_SUCCESS)
	{
		return false;
	}

	return (qsc_x509_certificate_builder_sign(&builder, stage4_mldsa_sign_callback, &signctx, der, derlen) == QSC_ASN1_STATUS_SUCCESS);
}

static bool stage4_build_leaf_certificate(uint8_t* der, size_t* derlen, const qsc_x509_certificate* issuer,
	uint8_t* leafpublickey, uint8_t* issuerprivatekey)
{
	qsc_x509_certificate_builder builder = { 0 };
	qsc_x509_name subject = { 0 };
	qsc_x509_validity validity = { 0 };
	qsc_x509_algorithm_identifier sigalg = { 0 };
	qsc_x509_subject_public_key_info spki = { 0 };
	stage4_sign_context signctx = { 0 };
	uint8_t serial[8U] = { 0U };
	size_t seriallen;

	qsc_x509_certificate_builder_initialize(&builder);
	qsc_x509_subject_public_key_info_initialize(&spki);
	qsc_memutils_clear(&sigalg, sizeof(sigalg));
	qsc_memutils_copy(signctx.privatekey, issuerprivatekey, sizeof(signctx.privatekey));
	signctx.rng_generate = qsc_csp_generate;
	stage4_fill_name(&subject, "stage4-server.example.test", "QRCS Stage4");
	stage4_make_validity(&validity);
	stage4_fill_serial(serial, &seriallen, 0x22U);

	if (qsc_x509_spki_initialize_ml_dsa(&spki, stage4_mldsa_parameter(), leafpublickey, QSC_DILITHIUM_PUBLICKEY_SIZE) != QSC_ASN1_STATUS_SUCCESS)
	{
		return false;
	}

	if (qsc_x509_algorithm_identifier_initialize_mldsa(&sigalg, stage4_mldsa_parameter()) != QSC_ASN1_STATUS_SUCCESS)
	{
		return false;
	}

	if (qsc_x509_certificate_builder_set_serial(&builder, serial, seriallen) != QSC_ASN1_STATUS_SUCCESS ||
		qsc_x509_certificate_builder_set_issuer_from_certificate(&builder, issuer) != QSC_ASN1_STATUS_SUCCESS ||
		qsc_x509_certificate_builder_set_subject(&builder, &subject) != QSC_ASN1_STATUS_SUCCESS ||
		qsc_x509_certificate_builder_set_validity(&builder, &validity) != QSC_ASN1_STATUS_SUCCESS ||
		qsc_x509_certificate_builder_set_spki(&builder, &spki) != QSC_ASN1_STATUS_SUCCESS ||
		qsc_x509_certificate_builder_set_signature_algorithm(&builder, &sigalg) != QSC_ASN1_STATUS_SUCCESS ||
		qsc_x509_certificate_builder_apply_profile(&builder, QSC_X509_CERT_PROFILE_TLS_SERVER) != QSC_ASN1_STATUS_SUCCESS)
	{
		return false;
	}

	if (qsc_x509_certificate_builder_add_subject_alt_name_dns(&builder, "stage4-server.example.test", qsc_stringutils_string_size("stage4-server.example.test")) != QSC_ASN1_STATUS_SUCCESS)
	{
		return false;
	}

	if (qsc_x509_certificate_builder_apply_generated_identifiers(&builder, issuer) != QSC_ASN1_STATUS_SUCCESS ||
		qsc_x509_certificate_builder_validate_profile(&builder, issuer, QSC_X509_CERT_PROFILE_TLS_SERVER) != QSC_ASN1_STATUS_SUCCESS)
	{
		return false;
	}

	return (qsc_x509_certificate_builder_sign(&builder, stage4_mldsa_sign_callback, &signctx, der, derlen) == QSC_ASN1_STATUS_SUCCESS);
}

bool x509_stage4b_mldsa_csr_roundtrip(void)
{
	qsc_x509_csr csr1 = { 0 };
	qsc_x509_csr csr2 = { 0 };
	uint8_t publickey[QSC_DILITHIUM_PUBLICKEY_SIZE] = { 0U };
	uint8_t privatekey[QSC_DILITHIUM_PRIVATEKEY_SIZE] = { 0U };
	uint8_t der[DERBUF] = { 0U };
	char pem[PEMBUF] = { 0 };
	uint8_t seed[QSC_DILITHIUM_GENERATE_SEED_SIZE] = { 0U };
	size_t derlen;
	size_t pemlen;
	bool res;

	for (size_t i = 0U; i < sizeof(seed); ++i)
	{
		seed[i] = (uint8_t)(0xA0U + i);
	}

	qsc_dilithium_seeded_generate_keypair(publickey, privatekey, seed);
	derlen = sizeof(der);
	res = stage4_build_mldsa_csr(der, &derlen, publickey, privatekey);

	if (res == true)
	{
		res = (qsc_x509_csr_decode_der(&csr1, der, derlen) == QSC_ASN1_STATUS_SUCCESS);
	}

	if (res == true)
	{
		res = qsc_x509_csr_verify(&csr1);
	}

	if (res == true)
	{
		pemlen = sizeof(pem);
		res = (qsc_x509_csr_encode_pem(der, derlen, pem, &pemlen) == QSC_ASN1_STATUS_SUCCESS);
	}

	if (res == true)
	{
		res = (qsc_x509_csr_decode_pem(&csr2, pem, pemlen) == QSC_ASN1_STATUS_SUCCESS);
	}

	if (res == true)
	{
		res = qsc_x509_csr_verify(&csr2);
	}

	return res;
}

bool x509_stage4b_mldsa_spki_roundtrip(void)
{
	qsc_x509_subject_public_key_info spki = { 0 };
	qsc_x509_subject_public_key_info decoded = { 0 };
	uint8_t publickey[QSC_DILITHIUM_PUBLICKEY_SIZE] = { 0U };
	uint8_t privatekey[QSC_DILITHIUM_PRIVATEKEY_SIZE] = { 0U };
	uint8_t der[QSC_X509_CERTIFICATE_WRITE_MAX] = { 0U };
	uint8_t seed[QSC_DILITHIUM_GENERATE_SEED_SIZE] = { 0U };
	size_t derlen;
	size_t i;

	for (i = 0U; i < sizeof(seed); ++i)
	{
		seed[i] = (uint8_t)(0xA0U + (uint8_t)i);
	}

	qsc_dilithium_seeded_generate_keypair(publickey, privatekey, seed);

	qsc_x509_subject_public_key_info_initialize(&spki);
	qsc_x509_subject_public_key_info_initialize(&decoded);

	if (qsc_x509_spki_initialize_ml_dsa(&spki, stage4_mldsa_parameter(), publickey, sizeof(publickey)) != QSC_ASN1_STATUS_SUCCESS)
	{
		return false;
	}

	derlen = sizeof(der);

	if (qsc_x509_write_spki_ml_dsa(stage4_mldsa_parameter(), publickey, sizeof(publickey), der, &derlen) != QSC_ASN1_STATUS_SUCCESS)
	{
		return false;
	}

	if (stage4_decode_spki_der(der, derlen, &decoded) != true)
	{
		return false;
	}

	return (decoded.algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ML_DSA) &&
		(decoded.algorithm.pqcparameter == stage4_mldsa_parameter()) &&
		(decoded.publickeylen == sizeof(publickey)) &&
		(qsc_memutils_are_equal(decoded.publickey, publickey, sizeof(publickey)) == true);
}

bool x509_stage4b_mldsa_csr_tamper_reject(void)
{
	qsc_x509_csr csr = { 0 };
	uint8_t publickey[QSC_DILITHIUM_PUBLICKEY_SIZE] = { 0U };
	uint8_t privatekey[QSC_DILITHIUM_PRIVATEKEY_SIZE] = { 0U };
	uint8_t der[DERBUF] = { 0U };
	uint8_t seed[QSC_DILITHIUM_GENERATE_SEED_SIZE] = { 0U };
	size_t derlen;
	size_t i;

	for (i = 0U; i < sizeof(seed); ++i)
	{
		seed[i] = (uint8_t)(0xB0U + i);
	}

	qsc_dilithium_seeded_generate_keypair(publickey, privatekey, seed);
	derlen = sizeof(der);

	if (stage4_build_mldsa_csr(der, &derlen, publickey, privatekey) != true)
	{
		return false;
	}

	if (derlen < 8U)
	{
		return false;
	}

	der[derlen - 4U] ^= 0x01U;

	if (qsc_x509_csr_decode_der(&csr, der, derlen) != QSC_ASN1_STATUS_SUCCESS)
	{
		return false;
	}

	return (qsc_x509_csr_verify(&csr) == false);
}

bool x509_stage4b_mldsa_chain_verify(void)
{
	qsc_x509_certificate certs[2U] = { 0 };
	qsc_x509_trust_anchor anchors[1U] = { 0 };
	qsc_x509_chain chain = { 0 };
	qsc_x509_store store = { 0 };
	qsc_x509_verify_state vstate = { 0 };
	qsc_x509_verify_options options = { 0 };
	qsc_asn1_time now = { 0 };
	uint8_t verifybuf[TESTBUF] = { 0U };
	uint8_t rootpk[QSC_DILITHIUM_PUBLICKEY_SIZE] = { 0U };
	uint8_t rootsk[QSC_DILITHIUM_PRIVATEKEY_SIZE] = { 0U };
	uint8_t leafpk[QSC_DILITHIUM_PUBLICKEY_SIZE] = { 0U };
	uint8_t leafsk[QSC_DILITHIUM_PRIVATEKEY_SIZE] = { 0U };
	uint8_t rootseed[QSC_DILITHIUM_GENERATE_SEED_SIZE] = { 0U };
	uint8_t leafseed[QSC_DILITHIUM_GENERATE_SEED_SIZE] = { 0U };
	uint8_t rootder[DERBUF] = { 0U };
	uint8_t leafder[DERBUF] = { 0U };
	size_t rootderlen;
	size_t leafderlen;
	qsc_x509_verify_status st;

	for (size_t i = 0U; i < sizeof(rootseed); ++i)
	{
		rootseed[i] = (uint8_t)(0xC0U + i);
		leafseed[i] = (uint8_t)(0xD0U + i);
	}

	qsc_dilithium_seeded_generate_keypair(rootpk, rootsk, rootseed);
	qsc_dilithium_seeded_generate_keypair(leafpk, leafsk, leafseed);
	rootderlen = sizeof(rootder);
	leafderlen = sizeof(leafder);

	if (stage4_build_root_certificate(rootder, &rootderlen, rootpk, rootsk) != true)
	{
		return false;
	}

	if (qsc_x509_certificate_decode_der(rootder, rootderlen, &certs[1U]) != QSC_ASN1_STATUS_SUCCESS)
	{
		return false;
	}

	if (stage4_build_leaf_certificate(leafder, &leafderlen, &certs[1U], leafpk, rootsk) != true)
	{
		return false;
	}

	if (qsc_x509_certificate_decode_der(leafder, leafderlen, &certs[0]) != QSC_ASN1_STATUS_SUCCESS)
	{
		return false;
	}

	anchors[0U].certificate = certs[1U];
	anchors[0U].selfsigned = true;
	chain.certificates = certs;
	chain.count = 2U;
	store.anchors = anchors;
	store.count = 1U;
	qsctest_x509_current_time(&now);
	qsc_x509_qsc_verify_state_initialize(&vstate, verifybuf, sizeof(verifybuf));
	qsc_x509_verify_options_initialize(&options);
	options.purpose = QSC_X509_VERIFY_PURPOSE_TLS_SERVER;
	options.rejectunsupportedcriticalextensions = true;

	st = qsc_x509_chain_verify_ex(&chain, &store, &now, qsc_x509_qsc_signature_verify, &vstate, &options);

	if (st != QSC_X509_VERIFY_STATUS_SUCCESS)
	{
		return false;
	}

	return (qsc_x509_certificate_check_hostname(&certs[0U], "stage4-server.example.test") == QSC_X509_VERIFY_STATUS_SUCCESS);
}

bool x509_stage4b_mlkem_ca_reject(void)
{
	qsc_x509_certificate_builder builder = { 0 };
	qsc_x509_name name = { 0 };
	qsc_x509_validity validity = { 0 };
	qsc_x509_algorithm_identifier sigalg = { 0 };
	qsc_x509_subject_public_key_info spki = { 0 };
	qsc_x509_subject_key_identifier skid = { 0 };
	uint8_t serial[8U] = { 0U };
	uint8_t mlkempk[QSC_KYBER_PUBLICKEY_SIZE] = { 0U };
	size_t seriallen;

	for (size_t i = 0U; i < sizeof(mlkempk); ++i)
	{
		mlkempk[i] = (uint8_t)(i + 1U);
	}

	qsc_x509_certificate_builder_initialize(&builder);
	qsc_x509_subject_public_key_info_initialize(&spki);
	qsc_memutils_clear(&sigalg, sizeof(sigalg));
	qsc_memutils_clear(&skid, sizeof(skid));
	stage4_fill_name(&name, "stage4-mlkem-ca.example.test", "QRCS Stage4");
	stage4_make_validity(&validity);
	stage4_fill_serial(serial, &seriallen, 0x33U);

	if (qsc_x509_spki_initialize_ml_kem(&spki, stage4_mlkem_parameter(), mlkempk, sizeof(mlkempk)) != QSC_ASN1_STATUS_SUCCESS)
	{
		return false;
	}

	if (qsc_x509_algorithm_identifier_initialize_mldsa(&sigalg, stage4_mldsa_parameter()) != QSC_ASN1_STATUS_SUCCESS)
	{
		return false;
	}

	if (qsc_x509_compute_subject_key_identifier(&spki, &skid) != QSC_ASN1_STATUS_SUCCESS)
	{
		return false;
	}

	if (qsc_x509_certificate_builder_set_serial(&builder, serial, seriallen) != QSC_ASN1_STATUS_SUCCESS ||
		qsc_x509_certificate_builder_set_issuer(&builder, &name) != QSC_ASN1_STATUS_SUCCESS ||
		qsc_x509_certificate_builder_set_subject(&builder, &name) != QSC_ASN1_STATUS_SUCCESS ||
		qsc_x509_certificate_builder_set_validity(&builder, &validity) != QSC_ASN1_STATUS_SUCCESS ||
		qsc_x509_certificate_builder_set_spki(&builder, &spki) != QSC_ASN1_STATUS_SUCCESS ||
		qsc_x509_certificate_builder_set_signature_algorithm(&builder, &sigalg) != QSC_ASN1_STATUS_SUCCESS ||
		qsc_x509_certificate_builder_apply_profile(&builder, QSC_X509_CERT_PROFILE_ROOT_CA) != QSC_ASN1_STATUS_SUCCESS ||
		qsc_x509_certificate_builder_set_subject_key_identifier(&builder, &skid) != QSC_ASN1_STATUS_SUCCESS)
	{
		return false;
	}

	return (qsc_x509_certificate_builder_validate_profile(&builder, NULL, QSC_X509_CERT_PROFILE_ROOT_CA) != QSC_ASN1_STATUS_SUCCESS);
}

bool x509_stage4b_mlkem_spki_roundtrip(void)
{
	qsc_x509_subject_public_key_info spki = { 0 };
	qsc_x509_subject_public_key_info decoded = { 0 };
	uint8_t der[QSC_X509_CERTIFICATE_WRITE_MAX] = { 0U };
	uint8_t publickey[QSC_KYBER_PUBLICKEY_SIZE] = { 0U };
	size_t derlen;

	for (size_t i = 0U; i < sizeof(publickey); ++i)
	{
		publickey[i] = (uint8_t)(0x55U ^ (uint8_t)i);
	}

	qsc_x509_subject_public_key_info_initialize(&spki);
	qsc_x509_subject_public_key_info_initialize(&decoded);

	if (qsc_x509_spki_initialize_ml_kem(&spki, stage4_mlkem_parameter(), publickey, sizeof(publickey)) != QSC_ASN1_STATUS_SUCCESS)
	{
		return false;
	}

	derlen = sizeof(der);

	if (qsc_x509_write_spki_ml_kem(stage4_mlkem_parameter(), publickey, sizeof(publickey), der, &derlen) != QSC_ASN1_STATUS_SUCCESS)
	{
		return false;
	}

	if (stage4_decode_spki_der(der, derlen, &decoded) != true)
	{
		return false;
	}

	return (decoded.algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ML_KEM) &&
		(decoded.algorithm.pqcparameter == stage4_mlkem_parameter()) &&
		(decoded.publickeylen == sizeof(publickey)) &&
		(qsc_memutils_are_equal(decoded.publickey, publickey, sizeof(publickey)) == true);
}

bool x509_stage4b_mldsa_pkcs8_roundtrip_and_match(void)
{
	qsc_x509_private_key key = { 0 };
	qsc_x509_private_key decoded = { 0 };
	qsc_x509_certificate cert = { 0 };
	uint8_t publickey[QSC_DILITHIUM_PUBLICKEY_SIZE] = { 0U };
	uint8_t privatekey[QSC_DILITHIUM_PRIVATEKEY_SIZE] = { 0U };
	uint8_t seed[QSC_DILITHIUM_GENERATE_SEED_SIZE] = { 0U };
	uint8_t certder[DERBUF] = { 0U };
	char pem[PEMBUF] = { 0 };
	size_t certderlen;
	size_t pemlen;

	for (size_t i = 0U; i < sizeof(seed); ++i)
	{
		seed[i] = (uint8_t)(0xE0U + i);
	}

	qsc_dilithium_seeded_generate_keypair(publickey, privatekey, seed);
	qsc_x509_private_key_initialize(&key);
	qsc_x509_private_key_initialize(&decoded);

	if (qsc_x509_algorithm_identifier_initialize_mldsa(&key.algorithm, stage4_mldsa_parameter()) != QSC_ASN1_STATUS_SUCCESS)
	{
		return false;
	}

	qsc_memutils_copy(key.privatekey, privatekey, sizeof(privatekey));
	key.privatekeylen = sizeof(privatekey);
	qsc_memutils_copy(key.publickey, publickey, sizeof(publickey));
	key.publickeylen = sizeof(publickey);
	key.publickey_present = true;
	pemlen = sizeof(pem);

	if (qsc_x509_private_key_encode_pkcs8_pem(&key, true, pem, &pemlen) != QSC_ASN1_STATUS_SUCCESS)
	{
		return false;
	}

	if (qsc_x509_private_key_decode_pkcs8_pem(pem, pemlen, &decoded) != QSC_ASN1_STATUS_SUCCESS)
	{
		return false;
	}

	if ((decoded.algorithm.publickey != QSC_X509_PUBLIC_KEY_ALGORITHM_ML_DSA) ||
		(decoded.algorithm.pqcparameter != stage4_mldsa_parameter()) ||
		(decoded.privatekeylen != sizeof(privatekey)) ||
		(decoded.publickeylen != sizeof(publickey)) ||
		(decoded.publickey_present != true) ||
		(qsc_memutils_are_equal(decoded.privatekey, privatekey, sizeof(privatekey)) == false) ||
		(qsc_memutils_are_equal(decoded.publickey, publickey, sizeof(publickey)) == false))
	{
		return false;
	}

	certderlen = sizeof(certder);

	if (stage4_build_root_certificate(certder, &certderlen, publickey, privatekey) != true)
	{
		return false;
	}

	if (qsc_x509_certificate_decode_der(certder, certderlen, &cert) != QSC_ASN1_STATUS_SUCCESS)
	{
		return false;
	}

	return qsc_x509_certificate_key_match(&cert, &decoded);
}

bool qsctest_x509_stage4b_pqc_tests(void)
{
	bool res;

	res = true;

	if (x509_stage4b_mldsa_spki_roundtrip() == true)
	{
		qsctest_print_line("[PASS] ML-DSA SPKI round-trip test.");
	}
	else
	{
		qsctest_print_line("[FAIL] ML-DSA SPKI round-trip test.");
		res = false;
	}

	if (x509_stage4b_mldsa_csr_roundtrip() == true)
	{
		qsctest_print_line("[PASS] ML-DSA CSR DER/PEM round-trip test.");
	}
	else
	{
		qsctest_print_line("[FAIL] ML-DSA CSR DER/PEM round-trip test.");
		res = false;
	}

	if (x509_stage4b_mldsa_csr_tamper_reject() == true)
	{
		qsctest_print_line("[PASS] Tampered ML-DSA CSR rejection test.");
	}
	else
	{
		qsctest_print_line("[FAIL] Tampered ML-DSA CSR rejection test.");
		res = false;
	}

	if (x509_stage4b_mldsa_chain_verify() == true)
	{
		qsctest_print_line("[PASS] ML-DSA root/leaf chain verification test.");
	}
	else
	{
		qsctest_print_line("[FAIL] ML-DSA root/leaf chain verification test.");
		res = false;
	}

	if (x509_stage4b_mlkem_ca_reject() == true)
	{
		qsctest_print_line("[PASS] ML-KEM CA profile rejection test.");
	}
	else
	{
		qsctest_print_line("[FAIL] ML-KEM CA profile rejection test.");
		res = false;
	}

	if (x509_stage4b_mlkem_spki_roundtrip() == true)
	{
		qsctest_print_line("[PASS] ML-KEM SPKI round-trip test.");
	}
	else
	{
		qsctest_print_line("[FAIL] ML-KEM SPKI round-trip test.");
		res = false;
	}

	if (x509_stage4b_mldsa_pkcs8_roundtrip_and_match() == true)
	{
		qsctest_print_line("[PASS] ML-DSA PKCS#8 and certificate match test.");
	}
	else
	{
		qsctest_print_line("[FAIL] ML-DSA PKCS#8 and certificate match test.");
		res = false;
	}

	return res;
}
