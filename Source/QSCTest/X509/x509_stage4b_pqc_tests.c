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

static bool stage4_chain_certs_result(qsc_x509_certificate* certs, bool result)
{
	if (certs != NULL)
	{
		qsc_x509_certificate_clear(&certs[0U]);
		qsc_x509_certificate_clear(&certs[1U]);
		qsc_memutils_clear(certs, sizeof(qsc_x509_certificate) * 2U);
		qsc_memutils_alloc_free(certs);
	}

	return result;
}

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


static bool stage4_build_mldsa_pkcs8_choice(const qsc_x509_algorithm_identifier* algorithm, const uint8_t* seed, const uint8_t* privatekey, bool both, uint8_t* der, size_t* derlen)
{
	uint8_t algorithmder[64U] = { 0U };
	uint8_t choice[QSC_X509_KEY_WRITE_MAX] = { 0U };
	uint8_t content[QSC_X509_KEY_WRITE_MAX] = { 0U };
	uint8_t inner[QSC_X509_KEY_WRITE_MAX] = { 0U };
	uint8_t version[1U] = { 0U };
	size_t algorithmlen;
	size_t choicelen;
	size_t innerlen;
	size_t len;
	size_t pos;
	bool res;

	algorithmlen = sizeof(algorithmder);
	choicelen = sizeof(choice);
	innerlen = 0U;
	pos = 0U;
	res = (qsc_x509_write_algorithm_identifier(algorithm, algorithmder, &algorithmlen) == QSC_ASN1_STATUS_SUCCESS);

	if (res == true)
	{
		if (both == true)
		{
			len = sizeof(inner);
			res = (qsc_x509_write_octet_string(seed, QSC_DILITHIUM_GENERATE_SEED_SIZE, inner, &len) == QSC_ASN1_STATUS_SUCCESS);
			innerlen = len;

			if (res == true)
			{
				len = sizeof(inner) - innerlen;
				res = (qsc_x509_write_octet_string(privatekey, QSC_DILITHIUM_PRIVATEKEY_SIZE, inner + innerlen, &len) == QSC_ASN1_STATUS_SUCCESS);
				innerlen += len;
			}

			if (res == true)
			{
				res = (qsc_x509_write_sequence(inner, innerlen, choice, &choicelen) == QSC_ASN1_STATUS_SUCCESS);
			}
		}
		else
		{
			res = (qsc_x509_write_raw(QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC, false, 0U, seed, QSC_DILITHIUM_GENERATE_SEED_SIZE, choice, &choicelen) == QSC_ASN1_STATUS_SUCCESS);
		}
	}

	if (res == true)
	{
		len = sizeof(content) - pos;
		res = (qsc_x509_write_integer(version, sizeof(version), content + pos, &len) == QSC_ASN1_STATUS_SUCCESS);
		pos += len;
	}

	if (res == true)
	{
		if ((sizeof(content) - pos) < algorithmlen)
		{
			res = false;
		}
		else
		{
			qsc_memutils_copy(content + pos, algorithmder, algorithmlen);
			pos += algorithmlen;
		}
	}

	if (res == true)
	{
		len = sizeof(content) - pos;
		res = (qsc_x509_write_octet_string(choice, choicelen, content + pos, &len) == QSC_ASN1_STATUS_SUCCESS);
		pos += len;
	}

	if (res == true)
	{
		res = (qsc_x509_write_sequence(content, pos, der, derlen) == QSC_ASN1_STATUS_SUCCESS);
	}

	return res;
}

static bool stage4_build_mlkem_pkcs8_choice(const qsc_x509_algorithm_identifier* algorithm, const uint8_t* seed, const uint8_t* privatekey, bool seedonly, bool both,
	uint8_t* der, size_t* derlen)
{
	uint8_t algorithmder[64U] = { 0U };
	uint8_t choice[QSC_X509_KEY_WRITE_MAX] = { 0U };
	uint8_t content[QSC_X509_KEY_WRITE_MAX] = { 0U };
	uint8_t inner[QSC_X509_KEY_WRITE_MAX] = { 0U };
	uint8_t version[1U] = { 0U };
	size_t algorithmlen;
	size_t choicelen;
	size_t innerlen;
	size_t len;
	size_t pos;
	bool res;

	algorithmlen = sizeof(algorithmder);
	choicelen = sizeof(choice);
	innerlen = 0U;
	pos = 0U;
	res = (qsc_x509_write_algorithm_identifier(algorithm, algorithmder, &algorithmlen) == QSC_ASN1_STATUS_SUCCESS);

	if (res == true)
	{
		if (both == true)
		{
			len = sizeof(inner);
			res = (qsc_x509_write_octet_string(seed, 2U * QSC_KYBER_SEED_SIZE, inner, &len) == QSC_ASN1_STATUS_SUCCESS);
			innerlen = len;

			if (res == true)
			{
				len = sizeof(inner) - innerlen;
				res = (qsc_x509_write_octet_string(privatekey, QSC_KYBER_PRIVATEKEY_SIZE, inner + innerlen, &len) == QSC_ASN1_STATUS_SUCCESS);
				innerlen += len;
			}

			if (res == true)
			{
				res = (qsc_x509_write_sequence(inner, innerlen, choice, &choicelen) == QSC_ASN1_STATUS_SUCCESS);
			}
		}
		else if (seedonly == true)
		{
			res = (qsc_x509_write_raw(QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC, false, 0U, seed, 2U * QSC_KYBER_SEED_SIZE, choice, &choicelen) == QSC_ASN1_STATUS_SUCCESS);
		}
		else
		{
			res = (qsc_x509_write_octet_string(privatekey, QSC_KYBER_PRIVATEKEY_SIZE, choice, &choicelen) == QSC_ASN1_STATUS_SUCCESS);
		}
	}

	if (res == true)
	{
		len = sizeof(content) - pos;
		res = (qsc_x509_write_integer(version, sizeof(version), content + pos, &len) == QSC_ASN1_STATUS_SUCCESS);
		pos += len;
	}

	if (res == true)
	{
		if ((sizeof(content) - pos) < algorithmlen)
		{
			res = false;
		}
		else
		{
			qsc_memutils_copy(content + pos, algorithmder, algorithmlen);
			pos += algorithmlen;
		}
	}

	if (res == true)
	{
		len = sizeof(content) - pos;
		res = (qsc_x509_write_octet_string(choice, choicelen, content + pos, &len) == QSC_ASN1_STATUS_SUCCESS);
		pos += len;
	}

	if (res == true)
	{
		res = (qsc_x509_write_sequence(content, pos, der, derlen) == QSC_ASN1_STATUS_SUCCESS);
	}

	return res;
}

static qsc_asn1_status stage4_mldsa_sign_callback(qsc_x509_signature_algorithm signaturealgorithm, const uint8_t* tbsdata, size_t tbsdatalen, uint8_t* signature, size_t* signaturelen, void* context)
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

static bool stage4_build_leaf_certificate(uint8_t* der, size_t* derlen, const qsc_x509_certificate* issuer, uint8_t* leafpublickey, uint8_t* issuerprivatekey)
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
	qsc_x509_csr* csr1;
	qsc_x509_csr csr2 = { 0 };
	uint8_t publickey[QSC_DILITHIUM_PUBLICKEY_SIZE] = { 0U };
	uint8_t privatekey[QSC_DILITHIUM_PRIVATEKEY_SIZE] = { 0U };
	uint8_t der[DERBUF] = { 0U };
	char pem[PEMBUF] = { 0 };
	uint8_t seed[QSC_DILITHIUM_GENERATE_SEED_SIZE] = { 0U };
	size_t derlen;
	size_t pemlen;
	bool res;

	csr1 = (qsc_x509_csr*)qsc_memutils_malloc(sizeof(qsc_x509_csr));

	if (csr1 == NULL)
	{
		return false;
	}

	qsc_memutils_clear(csr1, sizeof(qsc_x509_csr));
	for (size_t i = 0U; i < sizeof(seed); ++i)
	{
		seed[i] = (uint8_t)(0xA0U + i);
	}

	qsc_dilithium_seeded_generate_keypair(publickey, privatekey, seed);
	derlen = sizeof(der);
	res = stage4_build_mldsa_csr(der, &derlen, publickey, privatekey);

	if (res == true)
	{
		res = (qsc_x509_csr_decode_der(csr1, der, derlen) == QSC_ASN1_STATUS_SUCCESS);
	}

	if (res == true)
	{
		res = qsc_x509_csr_verify(csr1);
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

	qsc_x509_csr_clear(csr1);
	qsc_memutils_alloc_free(csr1);
	qsc_x509_csr_clear(&csr2);

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
	bool res;

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
		qsc_x509_csr_clear(&csr);
		return false;
	}

	res = (qsc_x509_csr_verify(&csr) == false);
	qsc_x509_csr_clear(&csr);

	return res;
}

bool x509_stage4b_mldsa_chain_verify(void)
{
	qsc_x509_certificate* certs;
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

	certs = (qsc_x509_certificate*)qsc_memutils_malloc(sizeof(qsc_x509_certificate) * 2U);

	if (certs == NULL)
	{
		return stage4_chain_certs_result(certs, false);
	}

	qsc_memutils_clear(certs, sizeof(qsc_x509_certificate) * 2U);
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
		return stage4_chain_certs_result(certs, false);
	}

	if (qsc_x509_certificate_decode_der(rootder, rootderlen, &certs[1U]) != QSC_ASN1_STATUS_SUCCESS)
	{
		return stage4_chain_certs_result(certs, false);
	}

	if (stage4_build_leaf_certificate(leafder, &leafderlen, &certs[1U], leafpk, rootsk) != true)
	{
		return stage4_chain_certs_result(certs, false);
	}

	if (qsc_x509_certificate_decode_der(leafder, leafderlen, &certs[0]) != QSC_ASN1_STATUS_SUCCESS)
	{
		return stage4_chain_certs_result(certs, false);
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
		return stage4_chain_certs_result(certs, false);
	}

	return stage4_chain_certs_result(certs, (qsc_x509_certificate_check_hostname(&certs[0U], "stage4-server.example.test") == QSC_X509_VERIFY_STATUS_SUCCESS));
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

bool x509_stage4b_pqc_key_usage_profiles(void)
{
	qsc_x509_certificate* rootcert;
	qsc_x509_certificate leafcert = { 0 };
	qsc_x509_subject_public_key_info spki = { 0 };
	uint8_t rootpublic[QSC_DILITHIUM_PUBLICKEY_SIZE] = { 0U };
	uint8_t rootprivate[QSC_DILITHIUM_PRIVATEKEY_SIZE] = { 0U };
	uint8_t leafpublic[QSC_DILITHIUM_PUBLICKEY_SIZE] = { 0U };
	uint8_t leafprivate[QSC_DILITHIUM_PRIVATEKEY_SIZE] = { 0U };
	uint8_t mlkempublic[QSC_KYBER_PUBLICKEY_SIZE] = { 0U };
	uint8_t mlkemprivate[QSC_KYBER_PRIVATEKEY_SIZE] = { 0U };
	uint8_t rootseed[QSC_DILITHIUM_GENERATE_SEED_SIZE] = { 0U };
	uint8_t leafseed[QSC_DILITHIUM_GENERATE_SEED_SIZE] = { 0U };
	uint8_t mlkemseed[2U * QSC_KYBER_SEED_SIZE] = { 0U };
	uint8_t rootder[DERBUF] = { 0U };
	uint8_t leafder[DERBUF] = { 0U };
	size_t rootderlen;
	size_t leafderlen;
	size_t i;
	bool res;

	rootcert = (qsc_x509_certificate*)qsc_memutils_malloc(sizeof(qsc_x509_certificate));

	if (rootcert == NULL)
	{
		return false;
	}

	qsc_memutils_clear(rootcert, sizeof(qsc_x509_certificate));
	for (i = 0U; i < sizeof(rootseed); ++i)
	{
		rootseed[i] = (uint8_t)(0x21U + i);
		leafseed[i] = (uint8_t)(0x41U + i);
	}

	for (i = 0U; i < sizeof(mlkemseed); ++i)
	{
		mlkemseed[i] = (uint8_t)(0x61U + i);
	}

	qsc_dilithium_seeded_generate_keypair(rootpublic, rootprivate, rootseed);
	qsc_dilithium_seeded_generate_keypair(leafpublic, leafprivate, leafseed);
	qsc_kyber_generate_seeded_keypair(mlkempublic, mlkemprivate, mlkemseed, mlkemseed + QSC_KYBER_SEED_SIZE);
	rootderlen = sizeof(rootder);
	leafderlen = sizeof(leafder);
	res = stage4_build_root_certificate(rootder, &rootderlen, rootpublic, rootprivate);

	if (res == true)
	{
		res = (qsc_x509_certificate_decode_der(rootder, rootderlen, rootcert) == QSC_ASN1_STATUS_SUCCESS);
	}

	if (res == true)
	{
		res = stage4_build_leaf_certificate(leafder, &leafderlen, rootcert, leafpublic, rootprivate);
	}

	if (res == true)
	{
		res = (qsc_x509_certificate_decode_der(leafder, leafderlen, &leafcert) == QSC_ASN1_STATUS_SUCCESS);
	}

	qsc_x509_subject_public_key_info_initialize(&spki);

	if (res == true)
	{
		res = (qsc_x509_spki_initialize_ml_kem(&spki, stage4_mlkem_parameter(), mlkempublic, sizeof(mlkempublic)) == QSC_ASN1_STATUS_SUCCESS);
	}

	if (res == true)
	{
		leafcert.subjectpublickeyinfo = spki;
		leafcert.extensions.keyusage.present = true;
		leafcert.extensions.keyusage.bits = QSC_X509_KEY_USAGE_KEY_ENCIPHERMENT;
		res = (qsc_x509_certificate_check_structure(&leafcert) == QSC_X509_VERIFY_STATUS_SUCCESS);
	}

	if (res == true)
	{
		leafcert.extensions.keyusage.bits = (uint16_t)(QSC_X509_KEY_USAGE_KEY_ENCIPHERMENT | QSC_X509_KEY_USAGE_DATA_ENCIPHERMENT);
		res = (qsc_x509_certificate_check_structure(&leafcert) == QSC_X509_VERIFY_STATUS_KEY_USAGE_REJECTED);
	}

	if (res == true)
	{
		leafcert.extensions.keyusage.bits = (uint16_t)(QSC_X509_KEY_USAGE_KEY_ENCIPHERMENT | QSC_X509_KEY_USAGE_KEY_AGREEMENT);
		res = (qsc_x509_certificate_check_structure(&leafcert) == QSC_X509_VERIFY_STATUS_KEY_USAGE_REJECTED);
	}

	qsc_x509_subject_public_key_info_initialize(&spki);

	if (res == true)
	{
		res = (qsc_x509_spki_initialize_ml_dsa(&spki, stage4_mldsa_parameter(), leafpublic, sizeof(leafpublic)) == QSC_ASN1_STATUS_SUCCESS);
	}

	if (res == true)
	{
		leafcert.subjectpublickeyinfo = spki;
		leafcert.extensions.keyusage.bits = 0U;
		res = (qsc_x509_certificate_check_structure(&leafcert) == QSC_X509_VERIFY_STATUS_KEY_USAGE_REJECTED);
	}

	if (res == true)
	{
		leafcert.extensions.keyusage.bits = QSC_X509_KEY_USAGE_DIGITAL_SIGNATURE;
		res = (qsc_x509_certificate_check_structure(&leafcert) == QSC_X509_VERIFY_STATUS_SUCCESS);
	}

	if (res == true)
	{
		leafcert.extensions.keyusage.bits = (uint16_t)(QSC_X509_KEY_USAGE_DIGITAL_SIGNATURE | QSC_X509_KEY_USAGE_KEY_ENCIPHERMENT);
		res = (qsc_x509_certificate_check_structure(&leafcert) == QSC_X509_VERIFY_STATUS_KEY_USAGE_REJECTED);
	}

	qsc_memutils_secure_erase(leafprivate, sizeof(leafprivate));
	qsc_memutils_secure_erase(mlkemprivate, sizeof(mlkemprivate));
	qsc_memutils_secure_erase(rootprivate, sizeof(rootprivate));

	qsc_x509_certificate_clear(rootcert);
	qsc_memutils_alloc_free(rootcert);

	return res;
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


bool x509_stage4b_mldsa_rfc9881_private_key_formats(void)
{
	qsc_x509_private_key key = { 0 };
	qsc_x509_private_key decoded = { 0 };
	qsc_encoding_ber_element* root;
	const qsc_encoding_ber_element* privatefield;
	const qsc_encoding_ber_element* publicfield;
	uint8_t publickey[QSC_DILITHIUM_PUBLICKEY_SIZE] = { 0U };
	uint8_t privatekey[QSC_DILITHIUM_PRIVATEKEY_SIZE] = { 0U };
	uint8_t badprivate[QSC_DILITHIUM_PRIVATEKEY_SIZE] = { 0U };
	uint8_t seed[QSC_DILITHIUM_GENERATE_SEED_SIZE] = { 0U };
	uint8_t der[QSC_X509_KEY_WRITE_MAX] = { 0U };
	size_t consumed;
	size_t derlen;
	size_t i;
	bool res;

	for (i = 0U; i < sizeof(seed); ++i)
	{
		seed[i] = (uint8_t)(0x30U + i);
	}

	qsc_dilithium_seeded_generate_keypair(publickey, privatekey, seed);
	qsc_x509_private_key_initialize(&key);
	qsc_x509_private_key_initialize(&decoded);
	res = (qsc_x509_algorithm_identifier_initialize_mldsa(&key.algorithm, stage4_mldsa_parameter()) == QSC_ASN1_STATUS_SUCCESS);

	if (res == true)
	{
		qsc_memutils_copy(key.privatekey, privatekey, sizeof(privatekey));
		key.privatekeylen = sizeof(privatekey);
		qsc_memutils_copy(key.publickey, publickey, sizeof(publickey));
		key.publickeylen = sizeof(publickey);
		key.publickey_present = true;
		derlen = sizeof(der);
		res = (qsc_x509_private_key_encode_pkcs8_der(&key, true, der, &derlen) == QSC_ASN1_STATUS_SUCCESS);
	}

	root = (qsc_encoding_ber_element*)NULL;

	if (res == true)
	{
		consumed = 0U;
		root = qsc_encoding_der_decode_element(der, derlen, &consumed);
		res = ((root != (qsc_encoding_ber_element*)NULL) && (consumed == derlen));
	}

	if (res == true)
	{
		privatefield = qsc_asn1_get_child(root, 2U);
		publicfield = qsc_asn1_get_child(root, 3U);
		res = ((privatefield != (const qsc_encoding_ber_element*)NULL) &&
			(privatefield->tagclass == QSC_ENCODING_BER_CLASS_UNIVERSAL) &&
			(privatefield->tagnumber == BER_ASN1_OCTET_STRING) &&
			(privatefield->length > 0U) &&
			(privatefield->value[0U] == BER_ASN1_OCTET_STRING) &&
			(publicfield != (const qsc_encoding_ber_element*)NULL) &&
			(publicfield->tagclass == QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC) &&
			(publicfield->constructed == false) &&
			(publicfield->tagnumber == 1U) &&
			(publicfield->length == (sizeof(publickey) + 1U)) &&
			(publicfield->value[0U] == 0U));
	}

	if (root != (qsc_encoding_ber_element*)NULL)
	{
		qsc_encoding_ber_free_element(root);
	}

	if (res == true)
	{
		derlen = sizeof(der);
		res = stage4_build_mldsa_pkcs8_choice(&key.algorithm, seed, privatekey, false, der, &derlen);
	}

	if (res == true)
	{
		qsc_x509_private_key_initialize(&decoded);
		res = (qsc_x509_private_key_decode_pkcs8_der(der, derlen, &decoded) == QSC_ASN1_STATUS_SUCCESS);
	}

	if (res == true)
	{
		res = ((decoded.privatekeylen == sizeof(privatekey)) &&
			(decoded.publickeylen == sizeof(publickey)) &&
			(decoded.publickey_present == true) &&
			(qsc_memutils_are_equal(decoded.privatekey, privatekey, sizeof(privatekey)) == true) &&
			(qsc_memutils_are_equal(decoded.publickey, publickey, sizeof(publickey)) == true));
	}

	if (res == true)
	{
		derlen = sizeof(der);
		res = stage4_build_mldsa_pkcs8_choice(&key.algorithm, seed, privatekey, true, der, &derlen);
	}

	if (res == true)
	{
		qsc_x509_private_key_initialize(&decoded);
		res = (qsc_x509_private_key_decode_pkcs8_der(der, derlen, &decoded) == QSC_ASN1_STATUS_SUCCESS);
	}

	if (res == true)
	{
		res = ((decoded.privatekeylen == sizeof(privatekey)) && (qsc_memutils_are_equal(decoded.privatekey, privatekey, sizeof(privatekey)) == true));
	}

	if (res == true)
	{
		qsc_memutils_copy(badprivate, privatekey, sizeof(badprivate));
		badprivate[sizeof(badprivate) - 1U] ^= 0x01U;
		derlen = sizeof(der);
		res = stage4_build_mldsa_pkcs8_choice(&key.algorithm, seed, badprivate, true, der, &derlen);
	}

	if (res == true)
	{
		qsc_x509_private_key_initialize(&decoded);
		res = (qsc_x509_private_key_decode_pkcs8_der(der, derlen, &decoded) == QSC_ASN1_STATUS_INVALID_ENCODING);
	}

	qsc_memutils_secure_erase(badprivate, sizeof(badprivate));
	qsc_memutils_secure_erase(privatekey, sizeof(privatekey));
	qsc_memutils_secure_erase(seed, sizeof(seed));

	return res;
}

bool x509_stage4b_mlkem_rfc9935_private_key_formats(void)
{
	qsc_x509_private_key key = { 0 };
	qsc_x509_private_key decoded = { 0 };
	qsc_encoding_ber_element* root;
	const qsc_encoding_ber_element* privatefield;
	const qsc_encoding_ber_element* publicfield;
	uint8_t publickey[QSC_KYBER_PUBLICKEY_SIZE] = { 0U };
	uint8_t privatekey[QSC_KYBER_PRIVATEKEY_SIZE] = { 0U };
	uint8_t badprivate[QSC_KYBER_PRIVATEKEY_SIZE] = { 0U };
	uint8_t seed[2U * QSC_KYBER_SEED_SIZE] = { 0U };
	uint8_t der[QSC_X509_KEY_WRITE_MAX] = { 0U };
	size_t consumed;
	size_t derlen;
	size_t i;
	bool res;

	for (i = 0U; i < sizeof(seed); ++i)
	{
		seed[i] = (uint8_t)(0x70U + i);
	}

	qsc_kyber_generate_seeded_keypair(publickey, privatekey, seed, seed + QSC_KYBER_SEED_SIZE);
	qsc_x509_private_key_initialize(&key);
	qsc_x509_private_key_initialize(&decoded);
	res = (qsc_x509_algorithm_identifier_initialize_mlkem(&key.algorithm, stage4_mlkem_parameter()) == QSC_ASN1_STATUS_SUCCESS);

	if (res == true)
	{
		qsc_memutils_copy(key.privatekey, privatekey, sizeof(privatekey));
		key.privatekeylen = sizeof(privatekey);
		qsc_memutils_copy(key.publickey, publickey, sizeof(publickey));
		key.publickeylen = sizeof(publickey);
		key.publickey_present = true;
		derlen = sizeof(der);
		res = (qsc_x509_private_key_encode_pkcs8_der(&key, true, der, &derlen) == QSC_ASN1_STATUS_SUCCESS);
	}

	root = (qsc_encoding_ber_element*)NULL;

	if (res == true)
	{
		consumed = 0U;
		root = qsc_encoding_der_decode_element(der, derlen, &consumed);
		res = ((root != (qsc_encoding_ber_element*)NULL) && (consumed == derlen));
	}

	if (res == true)
	{
		privatefield = qsc_asn1_get_child(root, 2U);
		publicfield = qsc_asn1_get_child(root, 3U);
		res = ((privatefield != (const qsc_encoding_ber_element*)NULL) &&
			(privatefield->tagclass == QSC_ENCODING_BER_CLASS_UNIVERSAL) &&
			(privatefield->tagnumber == BER_ASN1_OCTET_STRING) &&
			(privatefield->length > 0U) &&
			(privatefield->value[0U] == BER_ASN1_OCTET_STRING) &&
			(publicfield != (const qsc_encoding_ber_element*)NULL) &&
			(publicfield->tagclass == QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC) &&
			(publicfield->constructed == false) &&
			(publicfield->tagnumber == 1U) &&
			(publicfield->length == (sizeof(publickey) + 1U)) &&
			(publicfield->value[0U] == 0U));
	}

	if (root != (qsc_encoding_ber_element*)NULL)
	{
		qsc_encoding_ber_free_element(root);
	}

	if (res == true)
	{
		qsc_x509_private_key_initialize(&decoded);
		res = (qsc_x509_private_key_decode_pkcs8_der(der, derlen, &decoded) == QSC_ASN1_STATUS_SUCCESS);
	}

	if (res == true)
	{
		res = ((decoded.privatekeylen == sizeof(privatekey)) &&
			(decoded.publickeylen == sizeof(publickey)) &&
			(decoded.publickey_present == true) &&
			(qsc_memutils_are_equal(decoded.privatekey, privatekey, sizeof(privatekey)) == true) &&
			(qsc_memutils_are_equal(decoded.publickey, publickey, sizeof(publickey)) == true));
	}

	if (res == true)
	{
		derlen = sizeof(der);
		res = stage4_build_mlkem_pkcs8_choice(&key.algorithm, seed, privatekey, true, false, der, &derlen);
	}

	if (res == true)
	{
		qsc_x509_private_key_initialize(&decoded);
		res = (qsc_x509_private_key_decode_pkcs8_der(der, derlen, &decoded) == QSC_ASN1_STATUS_SUCCESS);
	}

	if (res == true)
	{
		res = ((decoded.privatekeylen == sizeof(privatekey)) &&
			(decoded.publickeylen == sizeof(publickey)) &&
			(decoded.publickey_present == true) &&
			(qsc_memutils_are_equal(decoded.privatekey, privatekey, sizeof(privatekey)) == true) &&
			(qsc_memutils_are_equal(decoded.publickey, publickey, sizeof(publickey)) == true));
	}

	if (res == true)
	{
		derlen = sizeof(der);
		res = stage4_build_mlkem_pkcs8_choice(&key.algorithm, seed, privatekey, false, true, der, &derlen);
	}

	if (res == true)
	{
		qsc_x509_private_key_initialize(&decoded);
		res = (qsc_x509_private_key_decode_pkcs8_der(der, derlen, &decoded) == QSC_ASN1_STATUS_SUCCESS);
	}

	if (res == true)
	{
		res = ((decoded.privatekeylen == sizeof(privatekey)) &&
			(decoded.publickeylen == sizeof(publickey)) &&
			(decoded.publickey_present == true) &&
			(qsc_memutils_are_equal(decoded.privatekey, privatekey, sizeof(privatekey)) == true) &&
			(qsc_memutils_are_equal(decoded.publickey, publickey, sizeof(publickey)) == true));
	}

	if (res == true)
	{
		qsc_memutils_copy(badprivate, privatekey, sizeof(badprivate));
		badprivate[sizeof(badprivate) - (2U * QSC_KYBER_SEED_SIZE) - 1U] ^= 0x01U;
		derlen = sizeof(der);
		res = stage4_build_mlkem_pkcs8_choice(&key.algorithm, seed, badprivate, false, false, der, &derlen);
	}

	if (res == true)
	{
		qsc_x509_private_key_initialize(&decoded);
		res = (qsc_x509_private_key_decode_pkcs8_der(der, derlen, &decoded) == QSC_ASN1_STATUS_INVALID_ENCODING);
	}

	if (res == true)
	{
		qsc_memutils_copy(badprivate, privatekey, sizeof(badprivate));
		badprivate[0U] ^= 0x01U;
		derlen = sizeof(der);
		res = stage4_build_mlkem_pkcs8_choice(&key.algorithm, seed, badprivate, false, true, der, &derlen);
	}

	if (res == true)
	{
		qsc_x509_private_key_initialize(&decoded);
		res = (qsc_x509_private_key_decode_pkcs8_der(der, derlen, &decoded) == QSC_ASN1_STATUS_INVALID_ENCODING);
	}

	qsc_memutils_secure_erase(badprivate, sizeof(badprivate));
	qsc_memutils_secure_erase(privatekey, sizeof(privatekey));
	qsc_memutils_secure_erase(seed, sizeof(seed));

	return res;
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

	if (x509_stage4b_pqc_key_usage_profiles() == true)
	{
		qsctest_print_line("[PASS] RFC 9881/RFC 9935 PQC key-usage profile test.");
	}
	else
	{
		qsctest_print_line("[FAIL] RFC 9881/RFC 9935 PQC key-usage profile test.");
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

	if (x509_stage4b_mldsa_rfc9881_private_key_formats() == true)
	{
		qsctest_print_line("[PASS] RFC 9881 ML-DSA private-key format test.");
	}
	else
	{
		qsctest_print_line("[FAIL] RFC 9881 ML-DSA private-key format test.");
		res = false;
	}

	if (x509_stage4b_mlkem_rfc9935_private_key_formats() == true)
	{
		qsctest_print_line("[PASS] RFC 9935 ML-KEM private-key format test.");
	}
	else
	{
		qsctest_print_line("[FAIL] RFC 9935 ML-KEM private-key format test.");
		res = false;
	}

	return res;
}
