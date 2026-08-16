#include "tls_stage11_ecdsa_der_tests.h"
#include "../testutils.h"
#include "csp.h"
#include "tlsecdsader.h"
#include "tlskeyschedule.h"
#include "tlssignerdefault.h"
#include "memutils.h"
#include "ecdsa.h"

static bool qsctest_tls_stage11_der_roundtrip_basic(void)
{
	uint8_t der[80U] = { 0U };
	uint8_t roundtrip[64U] = { 0U };
	uint8_t rs[64U] = { 0U };
	size_t derlen;
	qsc_tls_status st;
	size_t i;
	bool res;

	res = true;
	derlen = 0U;

	for (i = 0U; i < 32U; ++i)
	{
		rs[i] = (uint8_t)(0x01U + i);
	}

	for (i = 32U; i < 64U; ++i)
	{
		rs[i] = (uint8_t)(0x7FU - (i - 32U));
	}

	st = qsc_tls_ecdsa_der_encode(rs, 32U, der, sizeof(der), &derlen);

	if (st != qsc_tls_status_success)
	{
		res = false;
	}
	else if (derlen != 70U)
	{
		res = false;
	}
	else if (der[0U] != 0x30U)
	{
		res = false;
	}
	else if (der[2U] != 0x02U || der[3U] != 32U)
	{
		res = false;
	}
	else if (qsc_memutils_are_equal(der + 4U, rs, 32U) == false)
	{
		res = false;
	}
	else if (der[36U] != 0x02U || der[37U] != 32U)
	{
		res = false;
	}
	else if (qsc_memutils_are_equal(der + 38U, rs + 32U, 32U) == false)
	{
		res = false;
	}
	else
	{
		st = qsc_tls_ecdsa_der_decode(der, derlen, 32U, roundtrip, sizeof(roundtrip));

		if (st != qsc_tls_status_success)
		{
			res = false;
		}
		else if (qsc_memutils_are_equal(roundtrip, rs, sizeof(roundtrip)) == false)
		{
			res = false;
		}
	}

	return res;
}

static bool qsctest_tls_stage11_der_high_bit_prefix(void)
{
	uint8_t der[80U] = { 0U };
	uint8_t roundtrip[64U] = { 0U };
	uint8_t rs[64U] = { 0U };
	size_t derlen;
	qsc_tls_status st;
	bool res;

	res = true;
	derlen = 0U;
	qsc_memutils_clear(der, sizeof(der));
	qsc_memutils_clear(roundtrip, sizeof(roundtrip));
	qsc_memutils_clear(rs, sizeof(rs));

	rs[0U] = 0x80U;

	for (size_t i = 1U; i < 32U; ++i)
	{
		rs[i] = 0x11U;
	}

	rs[32U] = 0x00U;
	rs[33U] = 0x80U;

	for (size_t i = 34U; i < 64U; ++i)
	{
		rs[i] = 0x22U;
	}

	st = qsc_tls_ecdsa_der_encode(rs, 32U, der, sizeof(der), &derlen);

	if (st != qsc_tls_status_success)
	{
		res = false;
	}
	else if (der[2U] != 0x02U || der[3U] != 33U || der[4U] != 0x00U)
	{
		res = false;
	}
	else if (qsc_memutils_are_equal(der + 5U, rs, 32U) == false)
	{
		res = false;
	}
	else
	{
		st = qsc_tls_ecdsa_der_decode(der, derlen, 32U, roundtrip, sizeof(roundtrip));

		if (st != qsc_tls_status_success)
		{
			res = false;
		}
		else if (qsc_memutils_are_equal(roundtrip, rs, sizeof(roundtrip)) == false)
		{
			res = false;
		}
	}

	return res;
}

static bool qsctest_tls_stage11_der_malformed(void)
{
	uint8_t bad1[] = { 0x31U, 0x04U, 0x02U, 0x01U, 0x01U, 0x02U, 0x01U, 0x01U };
	uint8_t bad2[] = { 0x30U, 0x04U, 0x02U, 0x01U };
	uint8_t out[64U] = { 0U };
	qsc_tls_status st;
	bool res;

	res = true;
	qsc_memutils_clear(out, sizeof(out));

	st = qsc_tls_ecdsa_der_decode(bad1, sizeof(bad1), 32U, out, sizeof(out));

	if (st != qsc_tls_status_invalid_message)
	{
		res = false;
	}

	st = qsc_tls_ecdsa_der_decode(bad2, sizeof(bad2), 32U, out, sizeof(out));

	if (st == qsc_tls_status_success)
	{
		res = false;
	}

	return res;
}

static bool qsctest_tls_stage11_der_noncanonical_integer_rejected(void)
{
	uint8_t redundant_r[] = { 0x30U, 0x07U, 0x02U, 0x02U, 0x00U, 0x01U, 0x02U, 0x01U, 0x01U };
	uint8_t redundant_s[] = { 0x30U, 0x07U, 0x02U, 0x01U, 0x01U, 0x02U, 0x02U, 0x00U, 0x01U };
	uint8_t multiple_zero_r[] = { 0x30U, 0x08U, 0x02U, 0x03U, 0x00U, 0x00U, 0x80U, 0x02U, 0x01U, 0x01U };
	uint8_t negative_r[] = { 0x30U, 0x06U, 0x02U, 0x01U, 0x80U, 0x02U, 0x01U, 0x01U };
	uint8_t negative_s[] = { 0x30U, 0x06U, 0x02U, 0x01U, 0x01U, 0x02U, 0x01U, 0x80U };
	uint8_t out[64U] = { 0U };
	qsc_tls_status st;
	bool res;

	res = true;
	st = qsc_tls_ecdsa_der_decode(redundant_r, sizeof(redundant_r), 32U, out, sizeof(out));

	if (st != qsc_tls_status_invalid_message)
	{
		res = false;
	}

	if (res == true)
	{
		st = qsc_tls_ecdsa_der_decode(redundant_s, sizeof(redundant_s), 32U, out, sizeof(out));
		res = (st == qsc_tls_status_invalid_message);
	}

	if (res == true)
	{
		st = qsc_tls_ecdsa_der_decode(multiple_zero_r, sizeof(multiple_zero_r), 32U, out, sizeof(out));
		res = (st == qsc_tls_status_invalid_message);
	}

	if (res == true)
	{
		st = qsc_tls_ecdsa_der_decode(negative_r, sizeof(negative_r), 32U, out, sizeof(out));
		res = (st == qsc_tls_status_invalid_message);
	}

	if (res == true)
	{
		st = qsc_tls_ecdsa_der_decode(negative_s, sizeof(negative_s), 32U, out, sizeof(out));
		res = (st == qsc_tls_status_invalid_message);
	}

	return res;
}

static bool qsctest_tls_stage11_der_nonminimal_length_rejected(void)
{
	uint8_t long_sequence[] = { 0x30U, 0x81U, 0x06U, 0x02U, 0x01U, 0x01U, 0x02U, 0x01U, 0x01U };
	uint8_t long_integer[] = { 0x30U, 0x07U, 0x02U, 0x81U, 0x01U, 0x01U, 0x02U, 0x01U, 0x01U };
	uint8_t out[64U] = { 0U };
	qsc_tls_status st;
	bool res;

	res = true;
	st = qsc_tls_ecdsa_der_decode(long_sequence, sizeof(long_sequence), 32U, out, sizeof(out));

	if (st != qsc_tls_status_invalid_length)
	{
		res = false;
	}

	if (res == true)
	{
		st = qsc_tls_ecdsa_der_decode(long_integer, sizeof(long_integer), 32U, out, sizeof(out));
		res = (st == qsc_tls_status_invalid_length);
	}

	return res;
}

static bool qsctest_tls_stage11_ecdsa_signer_roundtrip_via_der(void)
{
	qsc_tls_certificate_view view = { 0 };
	qsc_tls_signer_default_context ctx = { 0 };
	qsc_tls_signature_scheme scheme = { 0 };
	uint8_t cv_input[256U] = { 0U };
	uint8_t pk[QSC_ECDSA_PUBLICKEY_SIZE] = { 0U };
	uint8_t signature_buf[128U] = { 0U };
	uint8_t sk[QSC_ECDSA_PRIVATEKEY_SIZE] = { 0U };
	uint8_t transcript[48U] = { 0U };
	size_t cv_len;
	size_t siglen;
	size_t i;
	bool ok;
	bool res;

	res = true;
	cv_len = 0U;
	siglen = sizeof(signature_buf);

	qsc_ecdsa_generate_keypair(pk, sk, qsc_csp_generate);

	for (i = 0U; i < sizeof(transcript); ++i)
	{
		transcript[i] = (uint8_t)(i ^ 0xA5U);
	}

	qsc_tls_keyschedule_build_certificate_verify_input("TLS 1.3, server CertificateVerify",
		transcript, sizeof(transcript), cv_input, sizeof(cv_input), &cv_len);

#if defined(QSC_ECDSA_S1P256)
	scheme = qsc_tls_sig_ecdsa_secp256r1_sha256;
#elif defined(QSC_ECDSA_S3P384)
	scheme = qsc_tls_sig_ecdsa_secp384r1_sha384;
#else
	return true;
#endif

	ctx.scheme = scheme;
	ctx.privatekey = sk;
	ctx.privatekeylen = QSC_ECDSA_PRIVATEKEY_SIZE;

	ok = qsc_tls_signer_default_sign(scheme, cv_input, cv_len, signature_buf, &siglen, &ctx);

	if (ok == false)
	{
		res = false;
	}
	else if (signature_buf[0U] != 0x30U)
	{
		res = false;
	}
	else if (siglen < 8U || siglen > sizeof(signature_buf))
	{
		res = false;
	}
	else
	{
		view.data = pk;
		view.datalen = QSC_ECDSA_PUBLICKEY_SIZE;
		ok = qsc_tls_signer_default_verify(scheme, cv_input, cv_len, signature_buf, siglen, &view, NULL);

		if (ok == false)
		{
			res = false;
		}
		else
		{
			signature_buf[siglen / 2U] ^= 0x01U;
			ok = qsc_tls_signer_default_verify(scheme, cv_input, cv_len, signature_buf, siglen, &view, NULL);

			if (ok == true)
			{
				res = false;
			}
		}
	}

	return res;
}

bool qsctest_tls_stage11_tests(void)
{
	bool res;

	res = true;

	if (qsctest_tls_stage11_der_roundtrip_basic() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 11 ECDSA DER basic round-trip test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 11 ECDSA DER basic round-trip test.");
		res = false;
	}

	if (qsctest_tls_stage11_der_high_bit_prefix() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 11 ECDSA DER high-bit prefix test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 11 ECDSA DER high-bit prefix test.");
		res = false;
	}

	if (qsctest_tls_stage11_der_malformed() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 11 ECDSA DER malformed input test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 11 ECDSA DER malformed input test.");
		res = false;
	}

	if (qsctest_tls_stage11_der_noncanonical_integer_rejected() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 11 ECDSA DER non-canonical INTEGER rejection test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 11 ECDSA DER non-canonical INTEGER rejection test.");
		res = false;
	}

	if (qsctest_tls_stage11_der_nonminimal_length_rejected() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 11 ECDSA DER non-minimal length rejection test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 11 ECDSA DER non-minimal length rejection test.");
		res = false;
	}

	if (qsctest_tls_stage11_ecdsa_signer_roundtrip_via_der() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 11 ECDSA signer DER interoperability test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 11 ECDSA signer DER interoperability test.");
		res = false;
	}

	return res;
}
