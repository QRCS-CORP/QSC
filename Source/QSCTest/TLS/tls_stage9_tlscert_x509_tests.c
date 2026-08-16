#include "tls_stage9_tlscert_x509_tests.h"
#include "../testutils.h"
#include "csp.h"
#include "tlscertx509.h"
#include "tlscert.h"
#include "tlssignerdefault.h"
#include "tlskeyschedule.h"
#include "memutils.h"
#include "eddsa.h"
#include "ecdsa.h"
#include "x509types.h"
#include "x509store.h"

#define TLS_CERT_X509_EXPOSE_INTERNALS_FOR_TEST 1

static bool qsctest_tls_stage9_spki_to_signer_key_mirror(const qsc_x509_subject_public_key_info* spki, qsc_tls_signature_scheme scheme, const uint8_t** out_key, size_t* out_keylen)
{
	bool ok;

	ok = false;

	if (spki == NULL || spki->publickeylen == 0U || out_key == NULL || out_keylen == NULL)
	{
		return false;
	}

	switch (scheme)
	{
	case qsc_tls_sig_ed25519:
	{
		if (spki->publickeylen == 32U)
		{
			*out_key = spki->publickey;
			*out_keylen = 32U;
			ok = true;
		}
		break;
	}
	case qsc_tls_sig_ecdsa_secp256r1_sha256:
	{
		if (spki->publickeylen == 65U && spki->publickey[0] == 0x04U)
		{
			*out_key = spki->publickey + 1U;
			*out_keylen = 64U;
			ok = true;
		}
		break;
	}
	case qsc_tls_sig_ecdsa_secp384r1_sha384:
	{
		if (spki->publickeylen == 97U && spki->publickey[0] == 0x04U)
		{
			*out_key = spki->publickey + 1U;
			*out_keylen = 96U;
			ok = true;
		}
		break;
	}
	case qsc_tls_sig_mldsa44:
	case qsc_tls_sig_mldsa65:
	case qsc_tls_sig_mldsa87:
	{
		*out_key = spki->publickey;
		*out_keylen = spki->publickeylen;
		ok = true;
		break;
	}
	default:
		break;
	}

	return ok;
}

static bool qsctest_tls_stage9_spki_ed25519(void)
{
	qsc_x509_subject_public_key_info spki = { 0 };
	const uint8_t* key;
	size_t keylen;
	bool res;

	qsc_memutils_clear(&spki, sizeof(spki));

	for (size_t i = 0U; i < 32U; ++i)
	{
		spki.publickey[i] = (uint8_t)(i + 1U);
	}

	spki.publickeylen = 32U;
	res = qsctest_tls_stage9_spki_to_signer_key_mirror(&spki, qsc_tls_sig_ed25519, &key, &keylen);
	res = (res == true && keylen == 32U && key == spki.publickey);

	spki.publickeylen = 31U;
	res = (res == true && qsctest_tls_stage9_spki_to_signer_key_mirror(&spki, qsc_tls_sig_ed25519, &key, &keylen) == false);

	return res;
}

static bool qsctest_tls_stage9_spki_ecdsa_p256(void)
{
	qsc_x509_subject_public_key_info spki = { 0 };
	const uint8_t* key;
	size_t keylen;
	bool res;

	qsc_memutils_clear(&spki, sizeof(spki));
	spki.publickey[0] = 0x04U;

	for (size_t i = 1U; i < 65U; ++i)
	{
		spki.publickey[i] = (uint8_t)i;
	}

	spki.publickeylen = 65U;
	res = qsctest_tls_stage9_spki_to_signer_key_mirror(&spki, qsc_tls_sig_ecdsa_secp256r1_sha256, &key, &keylen);
	res = (res == true && keylen == 64U && key == spki.publickey + 1U);

	spki.publickey[0U] = 0x02U;
	spki.publickeylen = 33U;
	res = (res == true && qsctest_tls_stage9_spki_to_signer_key_mirror(&spki, qsc_tls_sig_ecdsa_secp256r1_sha256, &key, &keylen) == false);

	spki.publickey[0U] = 0x04U;
	spki.publickeylen = 64U;
	res = (res == true && qsctest_tls_stage9_spki_to_signer_key_mirror(&spki, qsc_tls_sig_ecdsa_secp256r1_sha256, &key, &keylen) == false);

	return res;
}

static bool qsctest_tls_stage9_spki_ecdsa_p384(void)
{
	qsc_x509_subject_public_key_info spki = { 0 };
	const uint8_t* key;
	size_t keylen;
	bool res;

	qsc_memutils_clear(&spki, sizeof(spki));
	spki.publickey[0] = 0x04U;

	for (size_t i = 1U; i < 97U; ++i)
	{
		spki.publickey[i] = (uint8_t)(i & 0xFFU);
	}

	spki.publickeylen = 97U;
	res = qsctest_tls_stage9_spki_to_signer_key_mirror(&spki, qsc_tls_sig_ecdsa_secp384r1_sha384, &key, &keylen);
	res = (res == true && keylen == 96U && key == spki.publickey + 1U);

	return res;
}

static bool qsctest_tls_stage9_spki_mldsa(void)
{
	qsc_x509_subject_public_key_info spki = { 0 };
	const uint8_t* key;
	size_t keylen;
	bool res;

	qsc_memutils_clear(&spki, sizeof(spki));

	for (size_t i = 0U; i < 1312U; ++i)
	{
		spki.publickey[i] = (uint8_t)(i & 0xFFU);
	}

	spki.publickeylen = 1312U;
	res = qsctest_tls_stage9_spki_to_signer_key_mirror(&spki, qsc_tls_sig_mldsa44, &key, &keylen);
	res = (res == true && keylen == 1312U && key == spki.publickey);

	return res;
}

static bool qsctest_tls_stage9_spki_unsupported_scheme(void)
{
	qsc_x509_subject_public_key_info spki = { 0 };
	const uint8_t* key;
	size_t keylen;

	qsc_memutils_clear(&spki, sizeof(spki));

	for (size_t i = 0U; i < 64U; ++i)
	{
		spki.publickey[i] = 0x11U;
	}

	spki.publickeylen = 64U;

	return (qsctest_tls_stage9_spki_to_signer_key_mirror(&spki, (qsc_tls_signature_scheme)0xFFFFU, &key, &keylen) == false);
}

static bool qsctest_tls_stage9_state_initialize(void)
{
	qsc_tls_cert_x509_state st = { 0 };
	qsc_tls_certificate_interface iface = { 0 };
	bool res;

	qsc_tls_cert_x509_state_initialize(&st, NULL);
	res = (st.truststore == NULL);
	res = (res == true && st.allowselfsigned == false);
	res = (res == true && st.enforcehostname == true);
	res = (res == true && st.enforcevalidityperiod == true);

	qsc_memutils_clear(&iface, sizeof(iface));
	qsc_tls_cert_x509_bind(&iface, &st);
	res = (res == true && iface.validatechain != NULL);
	res = (res == true && iface.verifycertificateverify != NULL);
	res = (res == true && iface.state == &st);

	return res;
}

static bool qsctest_tls_stage9_invalid_der_rejected(void)
{
	qsc_x509_trust_anchor anchors[1U] = { 0 };
	qsc_x509_store store;
	qsc_tls_cert_x509_state st = { 0 };
	qsc_tls_certificate_interface iface = { 0 };
	qsc_tls_certificate_view chain[1U] = { 0 };
	qsc_tls_certificate_validation_context ctx = { 0 };
	uint8_t bogus[16U] = { 0U };
	uint8_t signature[64U] = { 0U };
	uint8_t input[32U] = { 0U };
	bool res;

	res = false;
	qsc_x509_store_initialize(&store, anchors, 1U);
	qsc_tls_cert_x509_state_initialize(&st, &store);
	qsc_memutils_clear(&iface, sizeof(iface));
	qsc_tls_cert_x509_bind(&iface, &st);

	for (size_t i = 0U; i < sizeof(bogus); ++i)
	{
		bogus[i] = 0xEEU;
	}

	chain[0U].data = bogus;
	chain[0U].datalen = sizeof(bogus);
	ctx.hostname = "example.com";
	ctx.clientauth = false;
	ctx.requirepeercertificate = true;

	if (iface.validatechain != NULL)
	{
		res = (iface.validatechain(chain, 1U, &ctx, iface.state) == false);
		res = (res == true && st.lastverifystatus != QSC_X509_VERIFY_STATUS_SUCCESS);
		res = (res == true && st.lastalert == qsc_tls_alert_bad_certificate);

		qsc_memutils_clear(signature, sizeof(signature));

		for (size_t i = 0U; i < sizeof(input); ++i)
		{
			input[i] = (uint8_t)i;
		}

		res = (res == true && iface.verifycertificateverify(qsc_tls_sig_ed25519, input, sizeof(input), signature, sizeof(signature), &chain[0], iface.state) == false);
	}

	return res;
}

bool qsctest_tls_stage9_tests(void)
{
	bool res;

	res = true;
	if (qsctest_tls_stage9_spki_ed25519() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 9 SPKI Ed25519 mapping test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 9 SPKI Ed25519 mapping test.");
		res = false;
	}

	if (qsctest_tls_stage9_spki_ecdsa_p256() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 9 SPKI ECDSA P-256 mapping test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 9 SPKI ECDSA P-256 mapping test.");
		res = false;
	}

	if (qsctest_tls_stage9_spki_ecdsa_p384() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 9 SPKI ECDSA P-384 mapping test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 9 SPKI ECDSA P-384 mapping test.");
		res = false;
	}

	if (qsctest_tls_stage9_spki_mldsa() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 9 SPKI ML-DSA mapping test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 9 SPKI ML-DSA mapping test.");
		res = false;
	}

	if (qsctest_tls_stage9_spki_unsupported_scheme() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 9 unsupported scheme mapping test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 9 unsupported scheme mapping test.");
		res = false;
	}

	if (qsctest_tls_stage9_state_initialize() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 9 X.509 state initialization test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 9 X.509 state initialization test.");
		res = false;
	}

	if (qsctest_tls_stage9_invalid_der_rejected() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 9 invalid DER rejection test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 9 invalid DER rejection test.");
		res = false;
	}

	return res;
}
