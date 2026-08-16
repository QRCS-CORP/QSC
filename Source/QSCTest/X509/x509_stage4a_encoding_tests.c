#include "x509_stage4a_encoding_tests.h"
#include "../testutils.h"
#include "x509_test_helper.h"
#include "asn1.h"
#include "csp.h"
#include "dilithium.h"
#include "encoding.h"
#include "memutils.h"
#include "sha3.h"
#include "stringutils.h"
#include "x509cert.h"
#include "x509certwrite.h"
#include "x509csr.h"
#include "x509key.h"
#include "x509keywrite.h"
#include "x509pem.h"
#include "x509sig.h"
#include "x509sigver.h"
#include "x509spki.h"
#include "x509verify.h"
#include "x509write.h"

#define STAGE4_ENCODER_TESTBUF 32768U
#define STAGE4_ENCODER_DERBUF QSC_X509_CERTIFICATE_WRITE_MAX
#define STAGE4_ENCODER_PEMBUF QSC_X509_PEM_TEXT_MAX
#define STAGE4_ENCODER_SIGBUF (QSC_DILITHIUM_SIGNATURE_SIZE + STAGE4_ENCODER_DERBUF)
#define STAGE4_ENCODER_LARGE_PAYLOAD 7308U

#if !defined(QSC_DILITHIUM_SIGNATURE_SIZE)
#	error Stage 4 encoder tests require a Dilithium/ML-DSA parameter set to be enabled.
#endif

typedef struct stage4_encoder_sign_context_t
{
	uint8_t privatekey[QSC_DILITHIUM_PRIVATEKEY_SIZE];
	bool (*rng_generate)(uint8_t*, size_t);
	uint8_t captured_signature[QSC_DILITHIUM_SIGNATURE_SIZE];
	size_t captured_signaturelen;
	uint8_t captured_tbs_hash[32U];
	size_t captured_tbslen;
	bool called;
} stage4_encoder_sign_context;

typedef struct
{
	qsc_x509_csr der;
	qsc_x509_csr pem;
} stage4a_csr_pair;

typedef struct
{
	qsc_x509_certificate der;
	qsc_x509_certificate pem;
} stage4a_certificate_pair;

static bool stage4a_csr_pair_result(stage4a_csr_pair* pair, bool result)
{
	if (pair != NULL)
	{
		qsc_x509_csr_clear(&pair->der);
		qsc_x509_csr_clear(&pair->pem);
		qsc_memutils_alloc_free(pair);
	}

	return result;
}

static bool stage4a_certificate_pair_result(stage4a_certificate_pair* pair, bool result)
{
	if (pair != NULL)
	{
		qsc_x509_certificate_clear(&pair->der);
		qsc_x509_certificate_clear(&pair->pem);
		qsc_memutils_alloc_free(pair);
	}

	return result;
}

static qsc_x509_pqc_parameter_set stage4_encoder_mldsa_parameter(void)
{
#if defined(QSC_DILITHIUM_S1P44)
	return QSC_X509_PQC_PARAMETER_SET_ML_DSA_44;
#elif defined(QSC_DILITHIUM_S3P65)
	return QSC_X509_PQC_PARAMETER_SET_ML_DSA_65;
#else
	return QSC_X509_PQC_PARAMETER_SET_ML_DSA_87;
#endif
}

static uint32_t stage4_encoder_mldsa_level(void)
{
#if defined(QSC_DILITHIUM_S1P44)
	return 44U;
#elif defined(QSC_DILITHIUM_S3P65)
	return 65U;
#else
	return 87U;
#endif
}

static qsc_x509_signature_algorithm stage4_encoder_mldsa_signature_algorithm(void)
{
#if defined(QSC_DILITHIUM_S1P44)
	return QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_44;
#elif defined(QSC_DILITHIUM_S3P65)
	return QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_65;
#else
	return QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_87;
#endif
}

static void stage4_encoder_fill_name(qsc_x509_name* name, const char* commonname, const char* organization)
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

static void stage4_encoder_make_validity(qsc_x509_validity* validity)
{
	qsctest_x509_current_time(&validity->notbefore);
	validity->notafter = validity->notbefore;
	++validity->notafter.year;
	validity->notafter.generalized = (validity->notafter.year >= 2050U);
}

static void stage4_encoder_fill_serial(uint8_t* serial, size_t* seriallen, uint8_t tag)
{
	serial[0U] = 0x10U;
	serial[1U] = 0x32U;
	serial[2U] = 0x54U;
	serial[3U] = 0x76U;
	serial[4U] = 0x98U;
	serial[5U] = 0xBAU;
	serial[6U] = 0xDCU;
	serial[7U] = tag;
	*seriallen = 8U;
}

static void stage4_encoder_fill_pseudorandom(uint8_t* output, size_t outputlen, uint8_t domain)
{
	uint8_t block[32U];
	uint8_t seed[16U];
	size_t i;
	size_t pos;
	uint32_t ctr;

	for (i = 0U; i < sizeof(seed); ++i)
	{
		seed[i] = (uint8_t)(domain + (uint8_t)i);
	}

	pos = 0U;
	ctr = 0U;

	while (pos < outputlen)
	{
		uint8_t input[20U];
		size_t take;

		qsc_memutils_copy(input, seed, sizeof(seed));
		input[16U] = (uint8_t)(ctr >> 24);
		input[17U] = (uint8_t)(ctr >> 16);
		input[18U] = (uint8_t)(ctr >> 8);
		input[19U] = (uint8_t)ctr;
		qsc_sha3_compute256(block, input, sizeof(input));
		take = ((outputlen - pos) < sizeof(block)) ? (outputlen - pos) : sizeof(block);
		qsc_memutils_copy(output + pos, block, take);
		pos += take;
		++ctr;
	}
}

static qsc_asn1_status stage4_encoder_sign_callback(qsc_x509_signature_algorithm signaturealgorithm, const uint8_t* tbsdata, size_t tbsdatalen, uint8_t* signature, size_t* signaturelen, void* context)
{
	stage4_encoder_sign_context* sctx;
	uint8_t signedmsg[STAGE4_ENCODER_SIGBUF] = { 0U };
	size_t smsglen;

	if ((tbsdata == NULL) || (signature == NULL) || (signaturelen == NULL) || (context == NULL))
	{
		return QSC_ASN1_STATUS_INVALID_INPUT;
	}

	if (signaturealgorithm != stage4_encoder_mldsa_signature_algorithm())
	{
		return QSC_ASN1_STATUS_UNSUPPORTED;
	}

	sctx = (stage4_encoder_sign_context*)context;

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
	qsc_memutils_copy(sctx->captured_signature, signedmsg, QSC_DILITHIUM_SIGNATURE_SIZE);
	sctx->captured_signaturelen = QSC_DILITHIUM_SIGNATURE_SIZE;
	sctx->captured_tbslen = tbsdatalen;
	qsc_sha3_compute256(sctx->captured_tbs_hash, tbsdata, tbsdatalen);
	sctx->called = true;

	return QSC_ASN1_STATUS_SUCCESS;
}

static bool stage4_encoder_bit_string_decode(const uint8_t* der, size_t derlen, uint8_t* value, size_t valuecapacity, size_t* valuelen, uint8_t* unusedbits)
{
	qsc_asn1_bit_string bits;
	qsc_encoding_ber_element* element;
	size_t consumed;
	bool res;

	res = false;
	consumed = 0U;
	element = qsc_encoding_der_decode_element(der, derlen, &consumed);

	if ((element != NULL) && (consumed == derlen) && (qsc_asn1_decode_bit_string(element, &bits) == QSC_ASN1_STATUS_SUCCESS) && (bits.length <= valuecapacity))
	{
		qsc_memutils_copy(value, bits.data, bits.length);
		*valuelen = bits.length;
		*unusedbits = bits.unused;
		res = true;
	}

	if (element != NULL)
	{
		qsc_encoding_ber_free_element(element);
	}

	return res;
}

static bool stage4_encoder_spki_decode_der(const uint8_t* der, size_t derlen, qsc_x509_subject_public_key_info* spki)
{
	qsc_encoding_ber_element* element;
	size_t consumed;
	bool res;

	res = false;
	consumed = 0U;
	element = qsc_encoding_der_decode_element(der, derlen, &consumed);

	if ((element != NULL) && (consumed == derlen))
	{
		res = (qsc_x509_subject_public_key_info_decode(element, spki) == QSC_ASN1_STATUS_SUCCESS);
		qsc_encoding_ber_free_element(element);
	}

	return res;
}

static bool stage4_encoder_build_csr(uint8_t* der, size_t* derlen, const uint8_t* publickey, const uint8_t* privatekey, stage4_encoder_sign_context* signctx)
{
	qsc_x509_csr csr = { 0 };
	qsc_x509_name subject = { 0 };
	qsc_x509_subject_alt_name san = { 0 };

	stage4_encoder_fill_name(&subject, "stage4-encoder-csr.example.test", "QRCS Stage4 Encoder");
	qsc_memutils_clear(&san, sizeof(san));
	qsc_memutils_clear(signctx, sizeof(*signctx));
	qsc_memutils_copy(signctx->privatekey, privatekey, QSC_DILITHIUM_PRIVATEKEY_SIZE);
	signctx->rng_generate = qsc_csp_generate;

	if (qsc_x509_csr_set_subject(&csr, &subject) != QSC_ASN1_STATUS_SUCCESS)
	{
		return false;
	}

	if (qsc_x509_csr_set_ml_dsa_spki(&csr, stage4_encoder_mldsa_level(), publickey, QSC_DILITHIUM_PUBLICKEY_SIZE) != QSC_ASN1_STATUS_SUCCESS)
	{
		return false;
	}

	if (qsc_x509_csr_set_ml_dsa_signature_algorithm(&csr, stage4_encoder_mldsa_level()) != QSC_ASN1_STATUS_SUCCESS)
	{
		return false;
	}

	san.present = true;
	san.count = 1U;
	san.entries[0U].type = QSC_X509_GENERAL_NAME_DNS_NAME;
	san.entries[0U].length = qsc_stringutils_string_size("stage4-encoder-csr.example.test");
	qsc_memutils_copy(san.entries[0U].data, (const uint8_t*)"stage4-encoder-csr.example.test", san.entries[0U].length);

	if (qsc_x509_csr_set_subject_alt_name(&csr, &san) != QSC_ASN1_STATUS_SUCCESS)
	{
		return false;
	}

	return (qsc_x509_csr_sign(&csr, stage4_encoder_sign_callback, signctx, der, derlen) == QSC_ASN1_STATUS_SUCCESS);
}

static bool stage4_encoder_build_root_certificate(uint8_t* der, size_t* derlen, const uint8_t* publickey, const uint8_t* privatekey, stage4_encoder_sign_context* signctx)
{
	qsc_x509_certificate_builder builder = { 0 };
	qsc_x509_name name = { 0 };
	qsc_x509_validity validity = { 0 };
	qsc_x509_algorithm_identifier sigalg = { 0 };
	qsc_x509_subject_public_key_info spki = { 0 };
	uint8_t serial[8U] = { 0U };
	size_t seriallen;

	qsc_x509_certificate_builder_initialize(&builder);
	qsc_x509_subject_public_key_info_initialize(&spki);
	qsc_memutils_clear(signctx, sizeof(*signctx));
	qsc_memutils_copy(signctx->privatekey, privatekey, QSC_DILITHIUM_PRIVATEKEY_SIZE);
	signctx->rng_generate = qsc_csp_generate;
	stage4_encoder_fill_name(&name, "stage4-encoder-root.example.test", "QRCS Stage4 Encoder");
	stage4_encoder_make_validity(&validity);
	stage4_encoder_fill_serial(serial, &seriallen, 0x41U);

	if (qsc_x509_spki_initialize_ml_dsa(&spki, stage4_encoder_mldsa_parameter(), publickey, QSC_DILITHIUM_PUBLICKEY_SIZE) != QSC_ASN1_STATUS_SUCCESS)
	{
		return false;
	}

	if (qsc_x509_algorithm_identifier_initialize_mldsa(&sigalg, stage4_encoder_mldsa_parameter()) != QSC_ASN1_STATUS_SUCCESS)
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

	return (qsc_x509_certificate_builder_sign(&builder, stage4_encoder_sign_callback, signctx, der, derlen) == QSC_ASN1_STATUS_SUCCESS);
}

bool x509_stage4a_encoder_bit_string_roundtrip(void)
{
	uint8_t decoded[STAGE4_ENCODER_LARGE_PAYLOAD] = { 0U };
	uint8_t der[STAGE4_ENCODER_LARGE_PAYLOAD + 32U] = { 0U };
	uint8_t payload[STAGE4_ENCODER_LARGE_PAYLOAD] = { 0U };
	uint8_t unusedbits;
	size_t decodedlen;
	size_t derlen;

	stage4_encoder_fill_pseudorandom(payload, sizeof(payload), 0x31U);
	derlen = sizeof(der);

	if (qsc_x509_write_bit_string(payload, sizeof(payload), 0U, der, &derlen) != QSC_ASN1_STATUS_SUCCESS)
	{
		return false;
	}

	decodedlen = 0U;
	unusedbits = 0xFFU;

	if (stage4_encoder_bit_string_decode(der, derlen, decoded, sizeof(decoded), &decodedlen, &unusedbits) != true)
	{
		return false;
	}

	return (unusedbits == 0U) &&
		(decodedlen == sizeof(payload)) &&
		(qsc_memutils_are_equal(decoded, payload, sizeof(payload)) == true);
}

bool x509_stage4a_encoder_spki_roundtrip(void)
{
	qsc_x509_subject_public_key_info decoded = { 0 };
	uint8_t der[STAGE4_ENCODER_DERBUF] = { 0U };
	uint8_t publickey[QSC_DILITHIUM_PUBLICKEY_SIZE] = { 0U };
	uint8_t privatekey[QSC_DILITHIUM_PRIVATEKEY_SIZE] = { 0U };
	uint8_t seed[QSC_DILITHIUM_GENERATE_SEED_SIZE] = { 0U };
	size_t derlen;

	stage4_encoder_fill_pseudorandom(seed, sizeof(seed), 0x41U);
	qsc_dilithium_seeded_generate_keypair(publickey, privatekey, seed);
	derlen = sizeof(der);

	if (qsc_x509_write_spki_ml_dsa(stage4_encoder_mldsa_parameter(), publickey, sizeof(publickey), der, &derlen) != QSC_ASN1_STATUS_SUCCESS)
	{
		return false;
	}

	if (stage4_encoder_spki_decode_der(der, derlen, &decoded) != true)
	{
		return false;
	}

	return (decoded.algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ML_DSA) &&
		(decoded.algorithm.pqcparameter == stage4_encoder_mldsa_parameter()) &&
		(decoded.unusedbits == 0U) &&
		(decoded.publickeylen == sizeof(publickey)) &&
		(qsc_memutils_are_equal(decoded.publickey, publickey, sizeof(publickey)) == true);
}

bool x509_stage4a_encoder_pkcs8_roundtrip(void)
{
	qsc_x509_private_key derkey = { 0 };
	qsc_x509_private_key pemkey = { 0 };
	uint8_t der[STAGE4_ENCODER_DERBUF] = { 0U };
	char pem[STAGE4_ENCODER_PEMBUF] = { 0 };
	uint8_t publickey[QSC_DILITHIUM_PUBLICKEY_SIZE] = { 0U };
	uint8_t privatekey[QSC_DILITHIUM_PRIVATEKEY_SIZE] = { 0U };
	uint8_t seed[QSC_DILITHIUM_GENERATE_SEED_SIZE] = { 0U };
	size_t derlen;
	size_t pemlen;

	stage4_encoder_fill_pseudorandom(seed, sizeof(seed), 0x51U);
	qsc_dilithium_seeded_generate_keypair(publickey, privatekey, seed);
	qsc_x509_private_key_initialize(&derkey);
	qsc_x509_private_key_initialize(&pemkey);

	derlen = sizeof(der);

	if (qsc_x509_private_key_encode_pkcs8_ml_dsa_der(stage4_encoder_mldsa_parameter(), privatekey, sizeof(privatekey), publickey, sizeof(publickey), true, der, &derlen) != QSC_ASN1_STATUS_SUCCESS)
	{
		return false;
	}

	if (qsc_x509_private_key_decode_pkcs8_der(der, derlen, &derkey) != QSC_ASN1_STATUS_SUCCESS)
	{
		return false;
	}

	pemlen = sizeof(pem);

	if (qsc_x509_private_key_encode_pkcs8_ml_dsa_pem(stage4_encoder_mldsa_parameter(), privatekey, sizeof(privatekey), publickey, sizeof(publickey), true, pem, &pemlen) != QSC_ASN1_STATUS_SUCCESS)
	{
		return false;
	}

	if (qsc_x509_private_key_decode_pkcs8_pem(pem, pemlen, &pemkey) != QSC_ASN1_STATUS_SUCCESS)
	{
		return false;
	}

	return (derkey.algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ML_DSA) &&
		(derkey.algorithm.pqcparameter == stage4_encoder_mldsa_parameter()) &&
		(derkey.privatekeylen == sizeof(privatekey)) &&
		(derkey.publickey_present == true) &&
		(derkey.publickeylen == sizeof(publickey)) &&
		(qsc_memutils_are_equal(derkey.privatekey, privatekey, sizeof(privatekey)) == true) &&
		(qsc_memutils_are_equal(derkey.publickey, publickey, sizeof(publickey)) == true) &&
		(pemkey.algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ML_DSA) &&
		(pemkey.algorithm.pqcparameter == stage4_encoder_mldsa_parameter()) &&
		(pemkey.privatekeylen == sizeof(privatekey)) &&
		(pemkey.publickey_present == true) &&
		(pemkey.publickeylen == sizeof(publickey)) &&
		(qsc_memutils_are_equal(pemkey.privatekey, privatekey, sizeof(privatekey)) == true) &&
		(qsc_memutils_are_equal(pemkey.publickey, publickey, sizeof(publickey)) == true);
}

bool x509_stage4a_encoder_csr_signature_roundtrip(void)
{
	stage4a_csr_pair* pair;
	qsc_x509_verify_state derstate = { 0 };
	qsc_x509_verify_state pemstate = { 0 };
	stage4_encoder_sign_context signctx = { 0 };
	uint8_t derverifybuf[STAGE4_ENCODER_SIGBUF + STAGE4_ENCODER_DERBUF] = { 0U };
	uint8_t pemverifybuf[STAGE4_ENCODER_SIGBUF + STAGE4_ENCODER_DERBUF] = { 0U };
	uint8_t der[STAGE4_ENCODER_DERBUF] = { 0U };
	char pem[STAGE4_ENCODER_PEMBUF] = { 0 };
	uint8_t publickey[QSC_DILITHIUM_PUBLICKEY_SIZE] = { 0U };
	uint8_t privatekey[QSC_DILITHIUM_PRIVATEKEY_SIZE] = { 0U };
	uint8_t seed[QSC_DILITHIUM_GENERATE_SEED_SIZE] = { 0U };
	uint8_t decodedtbs[32U] = { 0U };
	size_t derlen;
	size_t pemlen;
	bool res;

	pair = (stage4a_csr_pair*)qsc_memutils_malloc(sizeof(stage4a_csr_pair));

	if (pair == NULL)
	{
		return stage4a_csr_pair_result(pair, false);
	}

	qsc_memutils_clear(pair, sizeof(stage4a_csr_pair));
	qsc_x509_qsc_verify_state_initialize(&derstate, derverifybuf, sizeof(derverifybuf));
	qsc_x509_qsc_verify_state_initialize(&pemstate, pemverifybuf, sizeof(pemverifybuf));

	stage4_encoder_fill_pseudorandom(seed, sizeof(seed), 0x61U);
	qsc_dilithium_seeded_generate_keypair(publickey, privatekey, seed);
	derlen = sizeof(der);

	if (stage4_encoder_build_csr(der, &derlen, publickey, privatekey, &signctx) != true)
	{
		return stage4a_csr_pair_result(pair, false);
	}

	if ((signctx.called != true) || (signctx.captured_signaturelen != QSC_DILITHIUM_SIGNATURE_SIZE))
	{
		return stage4a_csr_pair_result(pair, false);
	}

	if (qsc_x509_csr_decode_der(&pair->der, der, derlen) != QSC_ASN1_STATUS_SUCCESS)
	{
		return stage4a_csr_pair_result(pair, false);
	}

	if (qsc_x509_qsc_csr_signature_verify(&pair->der, &derstate) != true)
	{
		return stage4a_csr_pair_result(pair, false);
	}

	qsc_sha3_compute256(decodedtbs, pair->der.infodata, pair->der.infodatalen);

	if ((pair->der.signatureunusedbits != 0U) ||
		(pair->der.signaturelen != signctx.captured_signaturelen) ||
		(qsc_memutils_are_equal(pair->der.signature, signctx.captured_signature, signctx.captured_signaturelen) == false) ||
		(qsc_memutils_are_equal(decodedtbs, signctx.captured_tbs_hash, sizeof(decodedtbs)) == false))
	{
		return stage4a_csr_pair_result(pair, false);
	}

	pemlen = sizeof(pem);

	if (qsc_x509_csr_encode_pem(der, derlen, pem, &pemlen) != QSC_ASN1_STATUS_SUCCESS)
	{
		return stage4a_csr_pair_result(pair, false);
	}

	if (qsc_x509_csr_decode_pem(&pair->pem, pem, pemlen) != QSC_ASN1_STATUS_SUCCESS)
	{
		return stage4a_csr_pair_result(pair, false);
	}

	if (qsc_x509_qsc_csr_signature_verify(&pair->pem, &pemstate) != true)
	{
		return stage4a_csr_pair_result(pair, false);
	}

	res = (pair->pem.signatureunusedbits == 0U) &&
		(pair->pem.signaturelen == signctx.captured_signaturelen) &&
		(qsc_memutils_are_equal(pair->pem.signature, signctx.captured_signature, signctx.captured_signaturelen) == true);

	return stage4a_csr_pair_result(pair, res);
}

bool x509_stage4a_encoder_certificate_signature_roundtrip(void)
{
	stage4a_certificate_pair* pair;
	qsc_x509_verify_state derstate = { 0 };
	qsc_x509_verify_state pemstate = { 0 };
	stage4_encoder_sign_context signctx = { 0 };
	uint8_t derverifybuf[STAGE4_ENCODER_SIGBUF + STAGE4_ENCODER_DERBUF] = { 0U };
	uint8_t pemverifybuf[STAGE4_ENCODER_SIGBUF + STAGE4_ENCODER_DERBUF] = { 0U };
	uint8_t der[STAGE4_ENCODER_DERBUF] = { 0U };
	char pem[STAGE4_ENCODER_PEMBUF] = { 0 };
	uint8_t publickey[QSC_DILITHIUM_PUBLICKEY_SIZE] = { 0U };
	uint8_t privatekey[QSC_DILITHIUM_PRIVATEKEY_SIZE] = { 0U };
	uint8_t seed[QSC_DILITHIUM_GENERATE_SEED_SIZE] = { 0U };
	uint8_t decodedtbs[32U] = { 0U };
	size_t derlen;
	size_t pemlen;
	bool res;

	pair = (stage4a_certificate_pair*)qsc_memutils_malloc(sizeof(stage4a_certificate_pair));

	if (pair == NULL)
	{
		return stage4a_certificate_pair_result(pair, false);
	}

	qsc_memutils_clear(pair, sizeof(stage4a_certificate_pair));
	qsc_x509_qsc_verify_state_initialize(&derstate, derverifybuf, sizeof(derverifybuf));
	qsc_x509_qsc_verify_state_initialize(&pemstate, pemverifybuf, sizeof(pemverifybuf));

	stage4_encoder_fill_pseudorandom(seed, sizeof(seed), 0x71U);
	qsc_dilithium_seeded_generate_keypair(publickey, privatekey, seed);
	derlen = sizeof(der);

	if (stage4_encoder_build_root_certificate(der, &derlen, publickey, privatekey, &signctx) != true)
	{
		return stage4a_certificate_pair_result(pair, false);
	}

	if ((signctx.called != true) || (signctx.captured_signaturelen != QSC_DILITHIUM_SIGNATURE_SIZE))
	{
		return stage4a_certificate_pair_result(pair, false);
	}

	if (qsc_x509_certificate_decode_der(der, derlen, &pair->der) != QSC_ASN1_STATUS_SUCCESS)
	{
		return stage4a_certificate_pair_result(pair, false);
	}

	if (qsc_x509_qsc_verify_signed_data(pair->der.tbsdata, pair->der.tbsdatalen, pair->der.signature,
		pair->der.signaturelen, pair->der.signatureunusedbits, pair->der.signaturealgorithm.signature,
		&pair->der.subjectpublickeyinfo, &derstate) != true)
	{
		return stage4a_certificate_pair_result(pair, false);
	}

	qsc_sha3_compute256(decodedtbs, pair->der.tbsdata, pair->der.tbsdatalen);

	if ((pair->der.signatureunusedbits != 0U) ||
		(pair->der.signaturelen != signctx.captured_signaturelen) ||
		(qsc_memutils_are_equal(pair->der.signature, signctx.captured_signature, signctx.captured_signaturelen) == false) ||
		(qsc_memutils_are_equal(decodedtbs, signctx.captured_tbs_hash, sizeof(decodedtbs)) == false))
	{
		return stage4a_certificate_pair_result(pair, false);
	}

	pemlen = sizeof(pem);

	if (qsc_x509_certificate_encode_pem(der, derlen, pem, &pemlen) != QSC_ASN1_STATUS_SUCCESS)
	{
		return stage4a_certificate_pair_result(pair, false);
	}

	if (qsc_x509_certificate_decode_pem(pem, pemlen, &pair->pem) != QSC_ASN1_STATUS_SUCCESS)
	{
		return stage4a_certificate_pair_result(pair, false);
	}

	if (qsc_x509_qsc_verify_signed_data(pair->pem.tbsdata, pair->pem.tbsdatalen, pair->pem.signature,
		pair->pem.signaturelen, pair->pem.signatureunusedbits, pair->pem.signaturealgorithm.signature,
		&pair->pem.subjectpublickeyinfo, &pemstate) != true)
	{
		return stage4a_certificate_pair_result(pair, false);
	}

	res = (pair->pem.signatureunusedbits == 0U) &&
		(pair->pem.signaturelen == signctx.captured_signaturelen) &&
		(qsc_memutils_are_equal(pair->pem.signature, signctx.captured_signature, signctx.captured_signaturelen) == true);

	return stage4a_certificate_pair_result(pair, res);
}

static bool x509_stage4a_der_recursive_canonicality(void)
{
	const uint8_t valid[] = { 0x30U, 0x03U, 0x02U, 0x01U, 0x01U };
	const uint8_t validhightag[] = { 0x9FU, 0x81U, 0x00U, 0x00U };
	const uint8_t nestednonminimal[] = { 0x30U, 0x04U, 0x02U, 0x81U, 0x01U, 0x01U };
	const uint8_t nestedindefinite[] = { 0x30U, 0x04U, 0x30U, 0x80U, 0x00U, 0x00U };
	const uint8_t nonminimaltag[] = { 0x3FU, 0x1EU, 0x00U };
	uint8_t validlonglength[134U] = { 0 };
	qsc_encoding_ber_element* element;
	bool res;

	validlonglength[0U] = 0x30U;
	validlonglength[1U] = 0x81U;
	validlonglength[2U] = 0x83U;
	validlonglength[3U] = 0x04U;
	validlonglength[4U] = 0x81U;
	validlonglength[5U] = 0x80U;
	element = NULL;
	res = (qsc_asn1_der_decode_exact(valid, sizeof(valid), &element) == QSC_ASN1_STATUS_SUCCESS && element != NULL);

	if (element != NULL)
	{
		qsc_encoding_ber_free_element(element);
		element = NULL;
	}

	res = (qsc_asn1_der_decode_exact(validhightag, sizeof(validhightag), &element) == QSC_ASN1_STATUS_SUCCESS && element != NULL) && res;

	if (element != NULL)
	{
		qsc_encoding_ber_free_element(element);
		element = NULL;
	}

	res = (qsc_asn1_der_decode_exact(validlonglength, sizeof(validlonglength), &element) == QSC_ASN1_STATUS_SUCCESS && element != NULL) && res;

	if (element != NULL)
	{
		qsc_encoding_ber_free_element(element);
		element = NULL;
	}

	res = (qsc_asn1_der_decode_exact(nestednonminimal, sizeof(nestednonminimal), &element) != QSC_ASN1_STATUS_SUCCESS) && res;

	if (element != NULL)
	{
		qsc_encoding_ber_free_element(element);
		element = NULL;
	}

	res = (qsc_asn1_der_decode_exact(nestedindefinite, sizeof(nestedindefinite), &element) != QSC_ASN1_STATUS_SUCCESS) && res;

	if (element != NULL)
	{
		qsc_encoding_ber_free_element(element);
		element = NULL;
	}

	res = (qsc_asn1_der_decode_exact(nonminimaltag, sizeof(nonminimaltag), &element) != QSC_ASN1_STATUS_SUCCESS) && res;

	if (element != NULL)
	{
		qsc_encoding_ber_free_element(element);
	}

	return res;
}

static bool x509_stage4a_oid_base128_canonicality(void)
{
	uint8_t validdata[] = { 0x88U, 0x37U, 0x03U };
	uint8_t nonminimalfirst[] = { 0x80U, 0x2AU, 0x03U };
	uint8_t nonminimallater[] = { 0x2AU, 0x80U, 0x03U };
	qsc_encoding_ber_element element = { 0 };
	qsc_asn1_oid oid = { 0 };
	bool res;

	element.tagclass = QSC_ENCODING_BER_CLASS_UNIVERSAL;
	element.constructed = false;
	element.tagnumber = BER_ASN1_OBJECT_IDENTIFIER;
	element.value = validdata;
	element.length = sizeof(validdata);

	res = (qsc_asn1_decode_oid(&element, &oid) == QSC_ASN1_STATUS_SUCCESS && oid.arcscount == 3U &&
		oid.arcs[0U] == 2U && oid.arcs[1U] == 999U && oid.arcs[2U] == 3U);

	element.value = nonminimalfirst;
	element.length = sizeof(nonminimalfirst);
	res = (qsc_asn1_decode_oid(&element, &oid) == QSC_ASN1_STATUS_INVALID_ENCODING) && res;

	element.value = nonminimallater;
	element.length = sizeof(nonminimallater);
	res = (qsc_asn1_decode_oid(&element, &oid) == QSC_ASN1_STATUS_INVALID_ENCODING) && res;

	return res;
}

static bool x509_stage4a_ecdsa_integer_canonicality(void)
{
	uint8_t valid[] = { 0x00U, 0x30U, 0x06U, 0x02U, 0x01U, 0x01U, 0x02U, 0x01U, 0x01U };
	uint8_t nonminimal[] = { 0x00U, 0x30U, 0x07U, 0x02U, 0x02U, 0x00U, 0x01U, 0x02U, 0x01U, 0x01U };
	qsc_encoding_ber_element element = { 0 };
	qsc_x509_ecdsa_signature signature = { 0 };
	bool res;

	element.tagclass = QSC_ENCODING_BER_CLASS_UNIVERSAL;
	element.constructed = false;
	element.tagnumber = BER_ASN1_BIT_STRING;
	element.value = valid;
	element.length = sizeof(valid);
	res = (qsc_x509_signature_value_decode_ecdsa(&element, QSC_X509_NAMED_CURVE_PRIME256V1, &signature) == QSC_ASN1_STATUS_SUCCESS);

	element.value = nonminimal;
	element.length = sizeof(nonminimal);
	res = (qsc_x509_signature_value_decode_ecdsa(&element, QSC_X509_NAMED_CURVE_PRIME256V1, &signature) == QSC_ASN1_STATUS_INVALID_ENCODING) && res;

	return res;
}


bool qsctest_x509_stage4a_encoding_tests(void)
{
	bool res;

	res = true;

	if (x509_stage4a_der_recursive_canonicality() == true)
	{
		qsctest_print_line("[PASS] Recursive DER canonicality test.");
	}
	else
	{
		qsctest_print_line("[FAIL] Recursive DER canonicality test.");
		res = false;
	}

	if (x509_stage4a_oid_base128_canonicality() == true)
	{
		qsctest_print_line("[PASS] OID base-128 canonicality test.");
	}
	else
	{
		qsctest_print_line("[FAIL] OID base-128 canonicality test.");
		res = false;
	}

	if (x509_stage4a_ecdsa_integer_canonicality() == true)
	{
		qsctest_print_line("[PASS] X.509 ECDSA INTEGER canonicality test.");
	}
	else
	{
		qsctest_print_line("[FAIL] X.509 ECDSA INTEGER canonicality test.");
		res = false;
	}

	if (x509_stage4a_encoder_bit_string_roundtrip() == true)
	{
		qsctest_print_line("[PASS] Encoder BIT STRING round-trip test.");
	}
	else
	{
		qsctest_print_line("[FAIL] Encoder BIT STRING round-trip test.");
		res = false;
	}

	if (x509_stage4a_encoder_spki_roundtrip() == true)
	{
		qsctest_print_line("[PASS] Encoder SPKI round-trip test.");
	}
	else
	{
		qsctest_print_line("[FAIL] Encoder SPKI round-trip test.");
		res = false;
	}

	if (x509_stage4a_encoder_pkcs8_roundtrip() == true)
	{
		qsctest_print_line("[PASS] Encoder PKCS#8 DER/PEM round-trip test.");
	}
	else
	{
		qsctest_print_line("[FAIL] Encoder PKCS#8 DER/PEM round-trip test.");
		res = false;
	}

	if (x509_stage4a_encoder_csr_signature_roundtrip() == true)
	{
		qsctest_print_line("[PASS] Encoder CSR signature field DER/PEM round-trip test.");
	}
	else
	{
		qsctest_print_line("[FAIL] Encoder CSR signature field DER/PEM round-trip test.");
		res = false;
	}

	if (x509_stage4a_encoder_certificate_signature_roundtrip() == true)
	{
		qsctest_print_line("[PASS] Encoder certificate signature field DER/PEM round-trip test.");
	}
	else
	{
		qsctest_print_line("[FAIL] Encoder certificate signature field DER/PEM round-trip test.");
		res = false;
	}

	return res;
}
