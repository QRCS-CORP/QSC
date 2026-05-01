#include "tls_stage14_e2e_tests.h"
#include "../testutils.h"
#include "tlsclient.h"
#include "tlsserver.h"
#include "tlscert.h"
#include "tlssignerdefault.h"
#include "memutils.h"
#include "secrand.h"
#include "acp.h"
#include "eddsa.h"

static uint8_t qsctest_tls_stage14_server_pk[32U];
static uint8_t qsctest_tls_stage14_server_sk[64U];
static uint8_t qsctest_tls_stage14_server_cert_der[32U];

static bool qsctest_tls_stage14_validate_chain(const qsc_tls_certificate_view* chain, size_t chainlength,
	const qsc_tls_certificate_validation_context* context, void* state)
{
	(void)context;
	(void)state;

	return (chain != NULL) && (chainlength == 1U) && (chain[0].datalen == 32U);
}

static bool qsctest_tls_stage14_verify_cv(qsc_tls_signature_scheme scheme, const uint8_t* input, size_t inputlen,
	const uint8_t* signature, size_t signaturelen, const qsc_tls_certificate_view* signer, void* state)
{
	qsc_tls_certificate_view view;
	(void)signer;
	(void)state;

	view.data = qsctest_tls_stage14_server_pk;
	view.datalen = sizeof(qsctest_tls_stage14_server_pk);

	return qsc_tls_signer_default_verify(scheme, input, inputlen, signature, signaturelen, &view, NULL);
}

static bool qsctest_tls_stage14_e2e_handshake(void)
{
	static const qsc_tls_cipher_suite c_suites[1U] = { qsc_tls_cipher_suite_tls_aes_128_gcm_sha256 };
	static const qsc_tls_named_group c_groups[1U] = { qsc_tls_group_x25519 };
	static const qsc_tls_signature_scheme c_sigs[1U] = { qsc_tls_sig_ed25519 };
	static const qsc_tls_cipher_suite s_suites[1U] = { qsc_tls_cipher_suite_tls_aes_128_gcm_sha256 };
	static const qsc_tls_named_group s_groups[1U] = { qsc_tls_group_x25519 };
	static const qsc_tls_signature_scheme s_sigs[1U] = { qsc_tls_sig_ed25519 };
	qsc_tls_signer_default_context signer_ctx = { 0 };
	qsc_tls_client_config ccfg = { 0 };
	qsc_tls_server_config scfg = { 0 };
	qsc_tls_client_state cs = { 0 };
	qsc_tls_server_state ss = { 0 };
	qsc_tls_status st = { 0 };
	uint8_t c2s_flight2[4096U] = { 0U };
	uint8_t c2s[4096U] = { 0U };
	uint8_t s2c[16384U] = { 0U };
	uint8_t seed[32U] = { 0U };
	size_t s2c_len;
	size_t consumed;
	size_t c2s_len;
	size_t c2s_flight2_len;
	size_t s2c_off;
	bool res;

	res = true;
	c2s_len = 0U;
	s2c_len = 0U;
	c2s_flight2_len = 0U;
	s2c_off = 0U;

	qsc_acp_generate(seed, sizeof(seed));
	qsc_secrand_initialize(seed, sizeof(seed), NULL, 0U);
	qsc_eddsa_generate_keypair(qsctest_tls_stage14_server_pk, qsctest_tls_stage14_server_sk, qsc_secrand_generate);
	qsc_memutils_copy(qsctest_tls_stage14_server_cert_der, qsctest_tls_stage14_server_pk, sizeof(qsctest_tls_stage14_server_cert_der));

	qsc_memutils_clear(&ccfg, sizeof(ccfg));
	ccfg.ciphersuites = c_suites;
	ccfg.ciphersuitecount = 1U;
	ccfg.groups = c_groups;
	ccfg.groupcount = 1U;
	ccfg.sigschemes = c_sigs;
	ccfg.sigschemecount = 1U;
	ccfg.sigschemes = c_sigs;
	ccfg.sigschemecount = 1U;
	ccfg.hostname = "example.com";
	ccfg.certinterface.validatechain = qsctest_tls_stage14_validate_chain;
	ccfg.certinterface.verifycertificateverify = qsctest_tls_stage14_verify_cv;
	ccfg.certinterface.state = NULL;

	qsc_memutils_clear(&scfg, sizeof(scfg));
	scfg.ciphersuitepreference = s_suites;
	scfg.ciphersuitepreferencecount = 1U;
	scfg.groupspreference = s_groups;
	scfg.groupspreferencecount = 1U;
	scfg.sigschemepreference = s_sigs;
	scfg.sigschemepreferencecount = 1U;
	scfg.localcert.chain[0].data = qsctest_tls_stage14_server_cert_der;
	scfg.localcert.chain[0].datalen = sizeof(qsctest_tls_stage14_server_cert_der);
	scfg.localcert.chainlength = 1U;
	scfg.localcert.verifyscheme = qsc_tls_sig_ed25519;
	scfg.localcert.configured = true;

	signer_ctx.scheme = qsc_tls_sig_ed25519;
	signer_ctx.privatekey = qsctest_tls_stage14_server_sk;
	signer_ctx.privatekeylen = sizeof(qsctest_tls_stage14_server_sk);
	scfg.localcert.signcallback = qsc_tls_signer_default_sign;
	scfg.localcert.signstate = &signer_ctx;

	st = qsc_tls_client_initialize(&cs, &ccfg);

	if (st != qsc_tls_status_success)
	{
		return false;
	}

	st = qsc_tls_server_initialize(&ss, &scfg);

	if (st != qsc_tls_status_success)
	{
		qsc_tls_client_dispose(&cs);
		return false;
	}

	st = qsc_tls_client_send_hello(&cs, c2s, sizeof(c2s), &c2s_len);

	if (st != qsc_tls_status_success)
	{
		res = false;
	}

	consumed = 0U;

	if (res == true)
	{
		st = qsc_tls_server_process_record(&ss, c2s, c2s_len, &consumed, s2c, sizeof(s2c), &s2c_len);

		if ((st != qsc_tls_status_success) || (consumed != c2s_len) || (s2c_len == 0U))
		{
			res = false;
		}
	}

	while ((res == true) && (s2c_off < s2c_len) && (cs.phase != qsc_tls_client_phase_established) && (cs.phase != qsc_tls_client_phase_failed))
	{
		size_t c;
		size_t w;

		c = 0U;
		w = 0U;
		st = qsc_tls_client_process_record(&cs, s2c + s2c_off, s2c_len - s2c_off, &c, c2s_flight2, sizeof(c2s_flight2), &w);

		if (st != qsc_tls_status_success)
		{
			res = false;
			break;
		}

		s2c_off += c;

		if (w > 0U)
		{
			c2s_flight2_len = w;
		}
	}

	if ((res == true) && ((cs.phase != qsc_tls_client_phase_established) || (c2s_flight2_len == 0U)))
	{
		res = false;
	}

	consumed = 0U;

	if (res == true)
	{
		uint8_t junk[16U] = { 0 };
		size_t junk_out;

		junk_out = 0U;
		st = qsc_tls_server_process_record(&ss, c2s_flight2, c2s_flight2_len, &consumed, junk, sizeof(junk), &junk_out);

		if ((st != qsc_tls_status_success) || (ss.phase != qsc_tls_server_phase_established))
		{
			res = false;
		}
	}

	if (res == true)
	{
		if (qsc_tls_client_get_negotiated_cipher_suite(&cs) != qsc_tls_cipher_suite_tls_aes_128_gcm_sha256)
		{
			res = false;
		}
		if (qsc_tls_server_get_negotiated_cipher_suite(&ss) != qsc_tls_cipher_suite_tls_aes_128_gcm_sha256)
		{
			res = false;
		}
	}

	qsc_tls_client_dispose(&cs);
	qsc_tls_server_dispose(&ss);

	return res;
}

bool qsctest_tls_stage14_tests(void)
{
	bool res;

	res = true;

	if (qsctest_tls_stage14_e2e_handshake() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 14 end-to-end handshake test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 14 end-to-end handshake test.");
		res = false;
	}

	return res;
}
