#include "tls_stage12_ecdsa_signer_tests.h"
#include "../testutils.h"
#include "../QSC/tlssignerdefault.h"
#include "../QSC/tlskeyschedule.h"
#include "../QSC/tlscert.h"
#include "../QSC/memutils.h"
#include "../QSC/ecdsa.h"

static void qsctest_tls_stage12_make_transcript(uint8_t* transcript, size_t transcriptlen)
{
	for (size_t i = 0U; i < transcriptlen; ++i)
	{
		transcript[i] = (uint8_t)(((uint8_t)i * 3U) ^ 0x5AU);
	}
}

static bool qsctest_tls_stage12_make_keypair(uint8_t* publickey, uint8_t* privatekey)
{
	uint8_t seed[QSC_ECDSA_SEED_SIZE] = { 0U };

	for (size_t i = 0U; i < sizeof(seed); ++i)
	{
		seed[i] = (uint8_t)(0xA5U ^ (uint8_t)(i + 1U));
	}

	return qsc_ecdsa_generate_seeded_keypair(publickey, privatekey, seed);
}

static bool qsctest_tls_stage12_select_schemes(qsc_tls_signature_scheme* scheme, qsc_tls_signature_scheme* wrongscheme)
{
	bool res;

	res = true;

#if defined(QSC_ECDSA_S1P256)
	*scheme = qsc_tls_sig_ecdsa_secp256r1_sha256;
	*wrongscheme = qsc_tls_sig_ecdsa_secp384r1_sha384;
#elif defined(QSC_ECDSA_S3P384)
	*scheme = qsc_tls_sig_ecdsa_secp384r1_sha384;
	*wrongscheme = qsc_tls_sig_ecdsa_secp256r1_sha256;
#else
	*scheme = qsc_tls_sig_none;
	*wrongscheme = qsc_tls_sig_none;
	res = false;
#endif

	return res;
}

static bool qsctest_tls_stage12_build_cv_input(uint8_t* cvinput, size_t cvinputlen, size_t* outlen)
{
	uint8_t transcript[48U] = { 0U };
	qsc_tls_status st;

	qsctest_tls_stage12_make_transcript(transcript, sizeof(transcript));

	st = qsc_tls_keyschedule_build_certificate_verify_input("TLS 1.3, server CertificateVerify", transcript, sizeof(transcript), cvinput, cvinputlen, outlen);

	return (st == qsc_tls_status_success);
}

static bool qsctest_tls_stage12_sign_verify_success(void)
{

	qsc_tls_certificate_view view = { 0 };
	qsc_tls_signature_scheme scheme = { 0 };
	qsc_tls_signature_scheme wrongscheme;
	qsc_tls_signer_default_context ctx = { 0 };
	uint8_t cvinput[256U] = { 0U };
	uint8_t publickey[QSC_ECDSA_PUBLICKEY_SIZE] = { 0U };
	uint8_t privatekey[QSC_ECDSA_PRIVATEKEY_SIZE] = { 0U };
	uint8_t signature[QSC_ECDSA_SIGNATURE_DER_MAX_SIZE] = { 0U };
	size_t cvlen;
	size_t siglen;
	bool ok;

	ok = false;
	cvlen = 0U;
	siglen = sizeof(signature);

	if (qsctest_tls_stage12_select_schemes(&scheme, &wrongscheme) == false)
	{
		return true;
	}

	if (qsctest_tls_stage12_make_keypair(publickey, privatekey) == false)
	{
		return false;
	}

	if (qsctest_tls_stage12_build_cv_input(cvinput, sizeof(cvinput), &cvlen) == false)
	{
		return false;
	}

	ctx.scheme = scheme;
	ctx.privatekey = privatekey;
	ctx.privatekeylen = QSC_ECDSA_PRIVATEKEY_SIZE;

	ok = qsc_tls_signer_default_sign(scheme, cvinput, cvlen, signature, &siglen, &ctx);

	if (ok == true)
	{
		ok = (siglen > 0U && siglen <= sizeof(signature));
	}

	if (ok == true)
	{
		view.data = publickey;
		view.datalen = QSC_ECDSA_PUBLICKEY_SIZE;
		ok = qsc_tls_signer_default_verify(scheme, cvinput, cvlen, signature, siglen, &view, NULL);
	}

	return ok;
}

static bool qsctest_tls_stage12_tamper_rejected(void)
{
	qsc_tls_certificate_view view = { 0 };
	qsc_tls_signature_scheme scheme = { 0 };
	qsc_tls_signature_scheme wrongscheme = { 0 };
	qsc_tls_signer_default_context ctx = { 0 };
	uint8_t cvinput[256U] = { 0U };
	uint8_t publickey[QSC_ECDSA_PUBLICKEY_SIZE] = { 0U };
	uint8_t privatekey[QSC_ECDSA_PRIVATEKEY_SIZE] = { 0U };
	uint8_t signature[QSC_ECDSA_SIGNATURE_DER_MAX_SIZE] = { 0U };
	size_t cvlen;
	size_t siglen;
	bool ok;

	ok = false;
	cvlen = 0U;
	siglen = sizeof(signature);

	if (qsctest_tls_stage12_select_schemes(&scheme, &wrongscheme) == false)
	{
		return true;
	}

	if (qsctest_tls_stage12_make_keypair(publickey, privatekey) == false)
	{
		return false;
	}

	if (qsctest_tls_stage12_build_cv_input(cvinput, sizeof(cvinput), &cvlen) == false)
	{
		return false;
	}

	ctx.scheme = scheme;
	ctx.privatekey = privatekey;
	ctx.privatekeylen = QSC_ECDSA_PRIVATEKEY_SIZE;

	ok = qsc_tls_signer_default_sign(scheme, cvinput, cvlen, signature, &siglen, &ctx);

	if (ok == true)
	{
		ok = (siglen > 0U && siglen <= sizeof(signature));
	}

	if (ok == true)
	{
		signature[0U] ^= 0x01U;
		view.data = publickey;
		view.datalen = QSC_ECDSA_PUBLICKEY_SIZE;
		ok = (qsc_tls_signer_default_verify(scheme, cvinput, cvlen, signature, siglen, &view, NULL) == false);
	}

	return ok;
}

static bool qsctest_tls_stage12_wrong_scheme_rejected(void)
{
	qsc_tls_certificate_view view = { 0 };
	qsc_tls_signature_scheme scheme = { 0 };
	qsc_tls_signature_scheme wrongscheme = { 0 };
	qsc_tls_signer_default_context ctx = { 0 };
	uint8_t cvinput[256U] = { 0U };
	uint8_t publickey[QSC_ECDSA_PUBLICKEY_SIZE] = { 0U };
	uint8_t privatekey[QSC_ECDSA_PRIVATEKEY_SIZE] = { 0U };
	uint8_t signature[QSC_ECDSA_SIGNATURE_DER_MAX_SIZE] = { 0U };
	size_t cvlen;
	size_t siglen;
	bool ok;

	ok = false;
	cvlen = 0U;
	siglen = sizeof(signature);

	if (qsctest_tls_stage12_select_schemes(&scheme, &wrongscheme) == false)
	{
		return true;
	}

	if (qsctest_tls_stage12_make_keypair(publickey, privatekey) == false)
	{
		return false;
	}

	if (qsctest_tls_stage12_build_cv_input(cvinput, sizeof(cvinput), &cvlen) == false)
	{
		return false;
	}

	ctx.scheme = scheme;
	ctx.privatekey = privatekey;
	ctx.privatekeylen = QSC_ECDSA_PRIVATEKEY_SIZE;

	ok = qsc_tls_signer_default_sign(scheme, cvinput, cvlen, signature, &siglen, &ctx);

	if (ok == true)
	{
		ok = (siglen > 0U && siglen <= sizeof(signature));
	}

	if (ok == true)
	{
		view.data = publickey;
		view.datalen = QSC_ECDSA_PUBLICKEY_SIZE;
		ok = (qsc_tls_signer_default_verify(wrongscheme, cvinput, cvlen, signature, siglen, &view, NULL) == false);
	}

	return ok;
}

bool qsctest_tls_stage12_tests(void)
{
	bool res;

	res = true;

	if (qsctest_tls_stage12_sign_verify_success() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 12 ECDSA signer sign and verify test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 12 ECDSA signer sign and verify test.");
		res = false;
	}

	if (qsctest_tls_stage12_tamper_rejected() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 12 ECDSA signer tamper rejection test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 12 ECDSA signer tamper rejection test.");
		res = false;
	}

	if (qsctest_tls_stage12_wrong_scheme_rejected() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 12 ECDSA signer wrong scheme rejection test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 12 ECDSA signer wrong scheme rejection test.");
		res = false;
	}

	return res;
}
