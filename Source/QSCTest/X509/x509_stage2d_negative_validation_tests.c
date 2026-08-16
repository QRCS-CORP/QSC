#include "x509_stage2d_negative_validation_tests.h"
#include "../testutils.h"
#include "x509_test_helper.h"
#include "asn1.h"
#include "ecdsap256base.h"
#include "fileutils.h"
#include "memutils.h"
#include "timestamp.h"
#include "x509pem.h"
#include "x509store.h"
#include "x509verify.h"
#include "x509sigver.h"
#include "x509certwrite.h"
#include "x509key.h"
#include "x509name.h"

#define QSCTEST_X509_STAGE2D_VECTOR_DIR QSCTEST_X509_VECTOR_ROOT "/Stage2D"
#define TESTBUF 32768U
#define MAX_CHAIN_CERTS 8U
#define MAX_ANCHORS 8U
#define FUTURE_CERT_DAYS_AHEAD 7ULL
#define FUTURE_CERT_VALID_DAYS 30ULL

static const char CCHAIN_PEM_PATH[] = "X509/Vectors/Stage2D/clientauth_chain.pem";
static const char EXP_CHAIN_PATH[] = "X509/Vectors/Stage2D/expired_chain.pem";
static const char GCERT_PEM_PATH[] = "X509/Vectors/Stage2D/good_int.cert.pem";
static const char GCHAIN_PEM_PATH[] = "X509/Vectors/Stage2D/good_chain.pem";
static const char GKEY_PEM_PATH[] = "X509/Vectors/Stage2D/good_int.key.pem";
static const char MCHAIN_PEM_PATH[] = "X509/Vectors/Stage2D/ca_misuse_chain.pem";
static const char NCERT_PEM_PATH[] = "X509/Vectors/Stage2D/notyet.cert.pem";
static const char TRUST_ROOT_PATH[] = "X509/Vectors/Stage2D/trust_roots.pem";
static const char VCHAIN_PEM_PATH[] = "X509/Vectors/Stage2D/pathlen_violation_chain.pem";
static const char WTRUST_ROOT_PATH[] = "X509/Vectors/Stage2D/wrong_trust_roots.pem";
static const char AKI_ISSUER_PATH[] = "X509/Vectors/Stage1/intermediate.cert.pem";
static const char AKI_LEAF_PATH[] = "X509/Vectors/Stage1/server.cert.pem";

typedef struct stage2d_sign_context_t
{
	qsc_x509_private_key key;
} stage2d_sign_context;

static void qsctest_x509_time_from_epoch(uint64_t epoch, qsc_asn1_time* t)
{
	char dt[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
	struct tm nt;

	if (t != NULL)
	{
		qsc_memutils_clear(t, sizeof(*t));
		qsc_memutils_clear(&nt, sizeof(nt));

		qsc_timestamp_seconds_to_datetime(epoch, dt);
		qsc_timestamp_string_to_time_struct(&nt, dt);

		t->year = (uint16_t)(nt.tm_year + 1900);
		t->month = (uint8_t)(nt.tm_mon + 1);
		t->day = (uint8_t)nt.tm_mday;
		t->hour = (uint8_t)nt.tm_hour;
		t->minute = (uint8_t)nt.tm_min;
		t->second = (uint8_t)nt.tm_sec;
		t->generalized = (t->year >= 2050U);
	}
}

static bool load_chain_and_store(const char* chain_path, const char* store_path,
	qsc_x509_certificate* certs, qsc_x509_chain* chain, qsc_x509_trust_anchor* anchors, qsc_x509_store* store)
{
	char* chain_pem;
	char* store_pem;
	size_t chain_len;
	size_t store_len;
	bool res;

	res = false;
	chain_pem = qsctest_x509_read_text_file(chain_path, &chain_len);
	store_pem = qsctest_x509_read_text_file(store_path, &store_len);

	if (chain_pem != NULL && store_pem != NULL)
	{
		if (qsc_x509_chain_decode_pem_bundle(chain_pem, chain_len, certs, MAX_CHAIN_CERTS, chain) == QSC_ASN1_STATUS_SUCCESS)
		{
			res = (qsc_x509_store_load_pem_bundle(store_pem, store_len, anchors, MAX_ANCHORS, store) == QSC_ASN1_STATUS_SUCCESS);
		}
	}

	qsc_memutils_alloc_free(chain_pem);
	qsc_memutils_alloc_free(store_pem);

	return res;
}

static qsc_x509_verify_status run_verify(const char* chain_path, const char* trust_path, qsc_x509_verify_purpose purpose, const char* hostname)
{
	qsc_x509_certificate* certs;
	qsc_x509_trust_anchor* anchors;
	qsc_x509_chain chain = { 0 };
	qsc_x509_store store = { 0 };
	qsc_x509_verify_state vstate = { 0 };
	qsc_asn1_time tnow = { 0 };
	qsc_x509_verify_options options = { 0 };
	uint8_t verifybuf[TESTBUF] = { 0U };
	qsc_x509_verify_status st;

	st = QSC_X509_VERIFY_STATUS_INVALID_INPUT;
	certs = (qsc_x509_certificate*)qsc_memutils_malloc(sizeof(qsc_x509_certificate) * MAX_CHAIN_CERTS);
	anchors = (qsc_x509_trust_anchor*)qsc_memutils_malloc(sizeof(qsc_x509_trust_anchor) * MAX_ANCHORS);

	if (certs != NULL && anchors != NULL)
	{
		qsc_memutils_clear(certs, sizeof(qsc_x509_certificate) * MAX_CHAIN_CERTS);
		qsc_memutils_clear(anchors, sizeof(qsc_x509_trust_anchor) * MAX_ANCHORS);

		if (load_chain_and_store(chain_path, trust_path, certs, &chain, anchors, &store) == true)
		{
			qsctest_x509_current_time(&tnow);
			qsc_x509_qsc_verify_state_initialize(&vstate, verifybuf, sizeof(verifybuf));
			qsc_x509_verify_options_initialize(&options);
			options.purpose = purpose;
			options.rejectunsupportedcriticalextensions = true;

			st = qsc_x509_chain_verify_ex(&chain, &store, &tnow, qsc_x509_qsc_signature_verify, &vstate, &options);

			if (st == QSC_X509_VERIFY_STATUS_SUCCESS && hostname != NULL)
			{
				st = qsc_x509_certificate_check_hostname(&chain.certificates[0], hostname);
			}
		}
	}

	qsc_x509_chain_free(&chain);
	qsc_x509_store_free(&store);

	if (certs != NULL)
	{
		qsc_memutils_clear(certs, sizeof(qsc_x509_certificate) * MAX_CHAIN_CERTS);
		qsc_memutils_alloc_free(certs);
	}

	if (anchors != NULL)
	{
		qsc_memutils_clear(anchors, sizeof(qsc_x509_trust_anchor) * MAX_ANCHORS);
		qsc_memutils_alloc_free(anchors);
	}

	return st;
}

static bool expect_status(qsc_x509_verify_status got, qsc_x509_verify_status want)
{
	return (got == want);
}

static size_t stage2d_trim_integer(const uint8_t* input, size_t inputlen, const uint8_t** start)
{
	size_t i;

	i = 0U;

	while ((i + 1U) < inputlen && input[i] == 0x00U)
	{
		++i;
	}

	*start = input + i;

	return inputlen - i;
}

static qsc_asn1_status stage2d_encode_ecdsa_der_signature(const uint8_t* rawsig, size_t rawsiglen, uint8_t* output, size_t* outputlen)
{
	const uint8_t* rptr;
	const uint8_t* sptr;
	size_t coordlen;
	size_t rlen;
	size_t slen;
	size_t renc;
	size_t senc;
	size_t seqlen;
	size_t pos;

	pos = 0U;

	if ((rawsig == NULL) || (outputlen == NULL) || ((output == NULL) && (*outputlen != 0U)) || ((rawsiglen & 1U) != 0U))
	{
		return QSC_ASN1_STATUS_INVALID_INPUT;
	}

	coordlen = rawsiglen / 2U;
	rlen = stage2d_trim_integer(rawsig, coordlen, &rptr);
	slen = stage2d_trim_integer(rawsig + coordlen, coordlen, &sptr);
	renc = rlen + (((rptr[0U] & 0x80U) != 0U) ? 1U : 0U);
	senc = slen + (((sptr[0U] & 0x80U) != 0U) ? 1U : 0U);

	/* SEQUENCE content length:
	   INTEGER r  => 1(tag) + 1(len) + renc
	   INTEGER s  => 1(tag) + 1(len) + senc
	*/
	seqlen = 2U + renc + 2U + senc;

	if (seqlen > 127U)
	{
		return QSC_ASN1_STATUS_OUT_OF_RANGE;
	}

	if (output == NULL)
	{
		*outputlen = 2U + seqlen;
		return QSC_ASN1_STATUS_SUCCESS;
	}

	if (*outputlen < (2U + seqlen))
	{
		*outputlen = 2U + seqlen;
		return QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
	}

	output[pos] = 0x30U;
	++pos;
	output[pos] = (uint8_t)seqlen;
	++pos;
	output[pos] = 0x02U;
	++pos;
	output[pos] = (uint8_t)renc;
	++pos;

	if ((rptr[0U] & 0x80U) != 0U)
	{
		output[pos++] = 0x00U;
	}

	qsc_memutils_copy(output + pos, rptr, rlen);
	pos += rlen;
	output[pos] = 0x02U;
	++pos;
	output[pos] = (uint8_t)senc;
	++pos;

	if ((sptr[0U] & 0x80U) != 0U)
	{
		output[pos++] = 0x00U;
	}

	qsc_memutils_copy(output + pos, sptr, slen);
	pos += slen;
	*outputlen = pos;

	return QSC_ASN1_STATUS_SUCCESS;
}

static qsc_asn1_status stage2d_p256_sign_callback(qsc_x509_signature_algorithm signaturealgorithm, const uint8_t* tbsdata, size_t tbsdatalen, uint8_t* signature, size_t* signaturelen, void* context)
{
	stage2d_sign_context* sctx;
	uint8_t signedmsg[EC_NISTP256_SIGNATURE_SIZE + QSC_X509_CERTIFICATE_WRITE_MAX] = { 0U };
	size_t smsglen;
	size_t derlen;

	smsglen = sizeof(signedmsg);

	if ((signature == NULL) || (signaturelen == NULL) || (tbsdata == NULL) || (context == NULL))
	{
		return QSC_ASN1_STATUS_INVALID_INPUT;
	}

	if (signaturealgorithm != QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA256)
	{
		return QSC_ASN1_STATUS_UNSUPPORTED;
	}

	sctx = (stage2d_sign_context*)context;

	if (sctx->key.algorithm.publickey != QSC_X509_PUBLIC_KEY_ALGORITHM_EC || sctx->key.algorithm.curve != QSC_X509_NAMED_CURVE_PRIME256V1)
	{
		return QSC_ASN1_STATUS_UNSUPPORTED;
	}

	/* Decoded SEC1 / PKCS#8 EC private key is the 32-byte scalar d. */
	if (sctx->key.privatekeylen != 32U)
	{
		return QSC_ASN1_STATUS_INVALID_LENGTH;
	}

	if (qsc_p256_sign_scalar(signedmsg, &smsglen, tbsdata, tbsdatalen, sctx->key.privatekey) != 0)
	{
		return QSC_ASN1_STATUS_FAILURE;
	}

	if (smsglen < (EC_NISTP256_SIGNATURE_SIZE + tbsdatalen))
	{
		return QSC_ASN1_STATUS_FAILURE;
	}

	derlen = *signaturelen;

	if (stage2d_encode_ecdsa_der_signature(signedmsg, EC_NISTP256_SIGNATURE_SIZE, signature, &derlen) != QSC_ASN1_STATUS_SUCCESS)
	{
		return QSC_ASN1_STATUS_FAILURE;
	}

	*signaturelen = derlen;

	return QSC_ASN1_STATUS_SUCCESS;
}

static bool stage2d_load_cert_file(const char* path, qsc_x509_certificate* cert)
{
	char* pem;
	size_t pemlen;
	qsc_asn1_status status;
	
	status = QSC_ASN1_STATUS_FAILURE;
	pem = qsctest_x509_read_text_file(path, &pemlen);

	if (pem != NULL)
	{
		status = qsc_x509_certificate_decode_pem(pem, pemlen, cert);
		qsc_memutils_alloc_free(pem);
	}

	return (status == QSC_ASN1_STATUS_SUCCESS);
}

static bool stage2d_load_key_file(const char* path, qsc_x509_private_key* key)
{
	char* pem;
	size_t pemlen;
	qsc_asn1_status status;

	status = QSC_ASN1_STATUS_FAILURE;
	pem = qsctest_x509_read_text_file(path, &pemlen);

	if (pem != NULL)
	{
		status = qsc_x509_private_key_decode_pem_from_bundle(pem, pemlen, key);
		qsc_memutils_alloc_free(pem);
	}

	return (status == QSC_ASN1_STATUS_SUCCESS);
}

static qsc_x509_verify_status run_dynamic_future_notyet_verify(void)
{
	qsc_x509_certificate* leafs;
	qsc_x509_trust_anchor* anchors;
	qsc_x509_chain chain = { 0 };
	qsc_x509_store store = { 0 };
	qsc_x509_verify_state vstate = { 0 };
	qsc_x509_verify_options options = { 0 };
	qsc_asn1_time tnow = { 0 };
	qsc_x509_validity validity = { 0 };
	qsc_x509_certificate* templ;
	qsc_x509_certificate issuer = { 0 };
	qsc_x509_private_key issuerkey = { 0 };
	qsc_x509_certificate_builder* builder;
	stage2d_sign_context signctx = { 0 };
	uint8_t certder[QSC_X509_CERTIFICATE_WRITE_MAX] = { 0U };
	uint8_t verifybuf[TESTBUF] = { 0U };
	size_t certderlen;
	char* store_pem;
	size_t store_len;
	uint64_t base;
	qsc_asn1_status status;
	qsc_x509_verify_status vstatus;

	leafs = (qsc_x509_certificate*)qsc_memutils_malloc(sizeof(qsc_x509_certificate) * 2U);
	anchors = (qsc_x509_trust_anchor*)qsc_memutils_malloc(sizeof(qsc_x509_trust_anchor) * MAX_ANCHORS);
	templ = (qsc_x509_certificate*)qsc_memutils_malloc(sizeof(qsc_x509_certificate));
	builder = (qsc_x509_certificate_builder*)qsc_memutils_malloc(sizeof(qsc_x509_certificate_builder));

	if (leafs != NULL)
	{
		qsc_memutils_clear(leafs, sizeof(qsc_x509_certificate) * 2U);
	}

	if (anchors != NULL)
	{
		qsc_memutils_clear(anchors, sizeof(qsc_x509_trust_anchor) * MAX_ANCHORS);
	}

	if (templ != NULL)
	{
		qsc_memutils_clear(templ, sizeof(qsc_x509_certificate));
	}

	if (builder != NULL)
	{
		qsc_memutils_clear(builder, sizeof(qsc_x509_certificate_builder));
	}

	certderlen = sizeof(certder);
	store_pem = NULL;
	status = QSC_ASN1_STATUS_FAILURE;
	vstatus = QSC_X509_VERIFY_STATUS_INVALID_INPUT;

	if (leafs != NULL && anchors != NULL && templ != NULL && builder != NULL)
	{
		if (stage2d_load_cert_file(NCERT_PEM_PATH, templ) == true)
		{
			status = QSC_ASN1_STATUS_SUCCESS;
		}

		if (status == QSC_ASN1_STATUS_SUCCESS && stage2d_load_cert_file(GCERT_PEM_PATH, &issuer) == false)
		{
			status = QSC_ASN1_STATUS_FAILURE;
		}

		if (status == QSC_ASN1_STATUS_SUCCESS && stage2d_load_key_file(GKEY_PEM_PATH, &issuerkey) == false)
		{
			status = QSC_ASN1_STATUS_FAILURE;
		}

		if (status == QSC_ASN1_STATUS_SUCCESS)
		{
			store_pem = qsctest_x509_read_text_file(TRUST_ROOT_PATH, &store_len);

			if (store_pem == NULL)
			{
				status = QSC_ASN1_STATUS_FAILURE;
			}
			else
			{
				status = qsc_x509_store_load_pem_bundle(store_pem, store_len, anchors, MAX_ANCHORS, &store);
				qsc_memutils_alloc_free(store_pem);
				store_pem = NULL;
			}
		}

		if (status == QSC_ASN1_STATUS_SUCCESS)
		{
			qsc_x509_certificate_builder_initialize(builder);
			status = qsc_x509_certificate_builder_set_serial(builder, templ->serialnumber, templ->serialnumberlen);
		}

		if (status == QSC_ASN1_STATUS_SUCCESS)
		{
			/* Make the dynamic cert distinct from the fixture. */
			if (builder->serialnumberlen != 0U)
			{
				builder->serialnumber[builder->serialnumberlen - 1U] ^= 0x55U;
			}

			status = qsc_x509_certificate_builder_set_issuer_from_certificate(builder, &issuer);
		}

		if (status == QSC_ASN1_STATUS_SUCCESS)
		{
			status = qsc_x509_certificate_builder_set_subject(builder, &templ->subject);
		}

		if (status == QSC_ASN1_STATUS_SUCCESS)
		{
			status = qsc_x509_certificate_builder_set_spki(builder, &templ->subjectpublickeyinfo);
		}

		if (status == QSC_ASN1_STATUS_SUCCESS)
		{
			status = qsc_x509_certificate_builder_set_signature_algorithm(builder, &templ->signaturealgorithm);
		}

		if (status == QSC_ASN1_STATUS_SUCCESS)
		{
			/* Rebuild extensions semantically. Do not memcpy templ->extensions. */
			status = qsc_x509_certificate_builder_set_basic_constraints(builder, &templ->extensions.basicconstraints);
		}

		if (status == QSC_ASN1_STATUS_SUCCESS)
		{
			status = qsc_x509_certificate_builder_set_key_usage(builder, &templ->extensions.keyusage);
		}

		if (status == QSC_ASN1_STATUS_SUCCESS)
		{
			status = qsc_x509_certificate_builder_set_extended_key_usage(builder, &templ->extensions.extendedkeyusage);
		}

		if (status == QSC_ASN1_STATUS_SUCCESS)
		{
			/* Preserve SAN exactly as parsed from the template. */
			builder->extensions.subjectaltname = templ->extensions.subjectaltname;
			builder->extensions.subjectaltname.present = templ->extensions.subjectaltname.present;

			/* Preserve IAN if present. */
			builder->extensions.issueraltname = templ->extensions.issueraltname;
			builder->extensions.issueraltname.present = templ->extensions.issueraltname.present;

			/* Do not copy raw decoded extension entries/count.
			 * Let the writer synthesize SKI and AKI cleanly from SPKI and issuer. */
			builder->extensions.subjectkeyidentifier.present = false;
			builder->extensions.authoritykeyidentifier.present = false;
			builder->extensions.count = 0U;
			qsc_memutils_clear(builder->extensions.entries, sizeof(builder->extensions.entries));

			base = qsc_timestamp_epochtime_seconds() + (FUTURE_CERT_DAYS_AHEAD * 86400ULL);
			qsctest_x509_time_from_epoch(base, &validity.notbefore);
			qsctest_x509_time_from_epoch(base + (FUTURE_CERT_VALID_DAYS * 86400ULL), &validity.notafter);
			status = qsc_x509_certificate_builder_set_validity(builder, &validity);
		}

		if (status == QSC_ASN1_STATUS_SUCCESS)
		{
			signctx.key = issuerkey;
			status = qsc_x509_certificate_builder_sign(builder, stage2d_p256_sign_callback, &signctx, certder, &certderlen);
		}

		if (status == QSC_ASN1_STATUS_SUCCESS)
		{
			status = qsc_x509_certificate_decode_der(certder, certderlen, &leafs[0]);
		}

		if (status == QSC_ASN1_STATUS_SUCCESS)
		{
			leafs[1] = issuer;
			chain.certificates = leafs;
			chain.count = 2U;
			qsctest_x509_current_time(&tnow);
			qsc_x509_qsc_verify_state_initialize(&vstate, verifybuf, sizeof(verifybuf));
			qsc_x509_verify_options_initialize(&options);
			options.purpose = QSC_X509_VERIFY_PURPOSE_TLS_SERVER;
			options.rejectunsupportedcriticalextensions = true;
			vstatus = qsc_x509_chain_verify_ex(&chain, &store, &tnow, qsc_x509_qsc_signature_verify, &vstate, &options);
		}
	}

	if (store_pem != NULL)
	{
		qsc_memutils_alloc_free(store_pem);
	}

	if (leafs != NULL)
	{
		qsc_x509_certificate_clear(&leafs[0]);
		qsc_memutils_clear(leafs, sizeof(qsc_x509_certificate) * 2U);
		qsc_memutils_alloc_free(leafs);
	}

	qsc_x509_store_free(&store);
	qsc_x509_certificate_clear(&issuer);
	if (templ != NULL)
	{
		qsc_x509_certificate_clear(templ);
		qsc_memutils_alloc_free(templ);
	}

	if (builder != NULL)
	{
		qsc_x509_certificate_builder_clear(builder);
		qsc_memutils_alloc_free(builder);
	}
	qsc_memutils_secure_erase(&issuerkey, sizeof(issuerkey));
	qsc_memutils_secure_erase(&signctx, sizeof(signctx));

	if (anchors != NULL)
	{
		qsc_memutils_clear(anchors, sizeof(qsc_x509_trust_anchor) * MAX_ANCHORS);
		qsc_memutils_alloc_free(anchors);
	}

	return vstatus;
}

bool x509_stage2d_expired_certificate(void)
{
	qsc_x509_verify_status st = run_verify(EXP_CHAIN_PATH, TRUST_ROOT_PATH, QSC_X509_VERIFY_PURPOSE_TLS_SERVER, "expired.example.test");

	return expect_status(st, QSC_X509_VERIFY_STATUS_EXPIRED);
}

bool x509_stage2d_not_yet_valid_certificate(void)
{
	qsc_x509_verify_status st = run_dynamic_future_notyet_verify();

	return expect_status(st, QSC_X509_VERIFY_STATUS_NOT_YET_VALID);
}

bool x509_stage2d_untrusted_root(void)
{
	qsc_x509_verify_status st = run_verify(GCHAIN_PEM_PATH, WTRUST_ROOT_PATH, QSC_X509_VERIFY_PURPOSE_TLS_SERVER, "good.example.test");

	return expect_status(st, QSC_X509_VERIFY_STATUS_TRUST_NOT_FOUND);
}

bool x509_stage2d_hostname_mismatch(void)
{
	qsc_x509_verify_status st = run_verify(GCHAIN_PEM_PATH, TRUST_ROOT_PATH, QSC_X509_VERIFY_PURPOSE_TLS_SERVER, "wrong.example.test");

	return expect_status(st, QSC_X509_VERIFY_STATUS_NAME_MISMATCH);
}

bool x509_stage2d_ca_misuse(void)
{
	qsc_x509_verify_status st = run_verify(MCHAIN_PEM_PATH, TRUST_ROOT_PATH, QSC_X509_VERIFY_PURPOSE_TLS_SERVER, "ca-misuse.example.test");

	return (st != QSC_X509_VERIFY_STATUS_SUCCESS);
}

bool x509_stage2d_pathlen_violation(void)
{
	qsc_x509_verify_status st = run_verify(VCHAIN_PEM_PATH, TRUST_ROOT_PATH, QSC_X509_VERIFY_PURPOSE_TLS_SERVER, "pathlen.example.test");

	return expect_status(st, QSC_X509_VERIFY_STATUS_PATH_LENGTH_EXCEEDED);
}

bool x509_stage2d_purpose_rejection(void)
{
	qsc_x509_verify_status st = run_verify(CCHAIN_PEM_PATH, TRUST_ROOT_PATH, QSC_X509_VERIFY_PURPOSE_TLS_SERVER, "clientauth.example.test");

	return expect_status(st, QSC_X509_VERIFY_STATUS_PURPOSE_REJECTED);
}

static bool x509_stage2d_aki_path_selection(void)
{
	qsc_x509_certificate* candidates;
	qsc_x509_certificate* output;
	qsc_x509_certificate issuer = { 0 };
	qsc_x509_certificate* leaf;
	qsc_x509_chain chain = { 0 };
	bool res;

	candidates = (qsc_x509_certificate*)qsc_memutils_malloc(sizeof(qsc_x509_certificate) * 2U);
	output = (qsc_x509_certificate*)qsc_memutils_malloc(sizeof(qsc_x509_certificate) * 3U);
	leaf = (qsc_x509_certificate*)qsc_memutils_malloc(sizeof(qsc_x509_certificate));

	if (candidates != NULL)
	{
		qsc_memutils_clear(candidates, sizeof(qsc_x509_certificate) * 2U);
	}

	if (output != NULL)
	{
		qsc_memutils_clear(output, sizeof(qsc_x509_certificate) * 3U);
	}

	if (leaf != NULL)
	{
		qsc_memutils_clear(leaf, sizeof(qsc_x509_certificate));
	}

	res = (candidates != NULL && output != NULL && leaf != NULL);

	if (res == true)
	{
		res = stage2d_load_cert_file(AKI_ISSUER_PATH, &issuer);
		res = stage2d_load_cert_file(AKI_LEAF_PATH, leaf) && res;
	}

	if (res == true && leaf->extensions.authoritykeyidentifier.keyidentifierlen != 0U)
	{
		leaf->extensions.authoritykeyidentifier.keyidentifier[0U] ^= 0x5AU;
		res = (qsc_x509_certificate_check_issuer(&issuer, leaf, 0U) == QSC_X509_VERIFY_STATUS_SUCCESS) && res;
		leaf->extensions.authoritykeyidentifier.keyidentifier[0U] ^= 0x5AU;
	}
	else
	{
		res = false;
	}

	if (res == true && issuer.extensions.subjectkeyidentifier.identifierlen != 0U)
	{
		candidates[0U] = issuer;
		candidates[1U] = issuer;
		candidates[0U].extensions.subjectkeyidentifier.identifier[0U] ^= 0x33U;
		res = (qsc_x509_chain_build(leaf, candidates, 2U, NULL, output, 3U, &chain) == QSC_X509_VERIFY_STATUS_SUCCESS) && res;
		res = (chain.count >= 2U && output[1U].extensions.subjectkeyidentifier.identifier[0U] == candidates[1U].extensions.subjectkeyidentifier.identifier[0U]) && res;
	}
	else
	{
		res = false;
	}

	if (res == true)
	{
		leaf->extensions.authoritykeyidentifier.keyidentifierlen = 0U;
		leaf->extensions.authoritykeyidentifier.issuer_present = true;
		leaf->extensions.authoritykeyidentifier.issuername_present = true;
		leaf->extensions.authoritykeyidentifier.issuername = issuer.issuer;
		leaf->extensions.authoritykeyidentifier.serial_present = true;
		leaf->extensions.authoritykeyidentifier.seriallen = issuer.serialnumberlen;
		qsc_memutils_copy(leaf->extensions.authoritykeyidentifier.serial, issuer.serialnumber, issuer.serialnumberlen);
		candidates[0U] = issuer;
		candidates[1U] = issuer;
		candidates[0U].issuer = leaf->subject;
		candidates[0U].serialnumber[0U] ^= 0x01U;
		chain.count = 0U;
		res = (qsc_x509_chain_build(leaf, candidates, 2U, NULL, output, 3U, &chain) == QSC_X509_VERIFY_STATUS_SUCCESS) && res;
		res = (chain.count >= 2U && qsc_x509_name_equals(&output[1U].issuer, &issuer.issuer) == true && output[1U].serialnumber[0U] == issuer.serialnumber[0U]) && res;
	}

	if (leaf != NULL)
	{
		qsc_x509_certificate_clear(leaf);
		qsc_memutils_alloc_free(leaf);
	}
	qsc_x509_certificate_clear(&issuer);

	if (candidates != NULL)
	{
		qsc_memutils_clear(candidates, sizeof(qsc_x509_certificate) * 2U);
		qsc_memutils_alloc_free(candidates);
	}

	if (output != NULL)
	{
		qsc_memutils_clear(output, sizeof(qsc_x509_certificate) * 3U);
		qsc_memutils_alloc_free(output);
	}

	return res;
}


bool qsctest_x509_stage2d_negative_validation_tests(void)
{
	bool res;

	res = true;

	if (x509_stage2d_aki_path_selection() == true)
	{
		qsctest_print_line("[PASS] Authority key identifier path-selection test.");
	}
	else
	{
		qsctest_print_line("[FAIL] Authority key identifier path-selection test.");
		res = false;
	}

	if (x509_stage2d_expired_certificate() == true)
	{
		qsctest_print_line("[PASS] Expired certificate test.");
	}
	else
	{
		qsctest_print_line("[FAIL] Expired certificate test.");
		res = false;
	}

	if (x509_stage2d_not_yet_valid_certificate() == true)
	{
		qsctest_print_line("[PASS] Invalid certificate test.");
	}
	else
	{
		qsctest_print_line("[FAIL] Invalid certificate test.");
		res = false;
	}

	if (x509_stage2d_untrusted_root() == true)
	{
		qsctest_print_line("[PASS] Untrusted root test.");
	}
	else
	{
		qsctest_print_line("[FAIL] Untrusted root test.");
		res = false;
	}

	if (x509_stage2d_hostname_mismatch() == true)
	{
		qsctest_print_line("[PASS] Hostname mismatch test.");
	}
	else
	{
		qsctest_print_line("[FAIL] Hostname mismatch test.");
		res = false;
	}

	if (x509_stage2d_ca_misuse() == true)
	{
		qsctest_print_line("[PASS] CA misuse test.");
	}
	else
	{
		qsctest_print_line("[FAIL] CA misuse test.");
		res = false;
	}

	if (x509_stage2d_pathlen_violation() == true)
	{
		qsctest_print_line("[PASS] Path length violation test.");
	}
	else
	{
		qsctest_print_line("[FAIL] Path length violation test.");
		res = false;
	}

	if (x509_stage2d_purpose_rejection() == true)
	{
		qsctest_print_line("[PASS] Improper usage rejection test.");
	}
	else
	{
		qsctest_print_line("[FAIL] Improper usage rejection test.");
		res = false;
	}

	return res;
}
