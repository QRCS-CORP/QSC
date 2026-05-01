#include "tls_stage6_session_resumption_tests.h"
#include "../testutils.h"
#include "tlsengine.h"
#include "tlsclient.h"
#include "tlsserver.h"
#include "tlssession.h"
#include "tlssignerdefault.h"
#include "memutils.h"
#include "secrand.h"
#include "acp.h"
#include "eddsa.h"

static uint8_t qsctest_tls_stage6_server_pk[32U];
static uint8_t qsctest_tls_stage6_server_sk[64U];
static uint8_t qsctest_tls_stage6_server_cert[32U];

static bool qsctest_tls_stage6_stub_validate(const qsc_tls_certificate_view* chain, size_t chainlength, const qsc_tls_certificate_validation_context* ctx, void* state)
{
	(void)ctx;
	(void)state;

	return (chain != NULL && chainlength == 1U && chain[0].datalen == 32U);
}

static bool qsctest_tls_stage6_stub_verify(qsc_tls_signature_scheme scheme, const uint8_t* input, size_t inputlen,
	const uint8_t* signature, size_t signaturelen, const qsc_tls_certificate_view* signer, void* state)
{
	qsc_tls_certificate_view view = { 0 };

	(void)signer;
	(void)state;

	view.data = qsctest_tls_stage6_server_pk;
	view.datalen = 32U;

	return qsc_tls_signer_default_verify(scheme, input, inputlen, signature, signaturelen, &view, NULL);
}

static bool qsctest_tls_stage6_do_handshake(qsc_tls_connection* client, qsc_tls_connection* server)
{
	uint8_t bufc2s[4096U] = { 0 };
	uint8_t bufs2c[16384U] = { 0 };
	uint8_t junk[128U] = { 0 };
	size_t c2slen;
	size_t consumed;
	size_t offset;
	size_t s2clen;
	size_t w;
	size_t written;
	qsc_tls_status status;

	c2slen = 0U;
	s2clen = 0U;
	consumed = 0U;
	status = qsc_tls_engine_handshake(client, NULL, 0U, &consumed, bufc2s, sizeof(bufc2s), &c2slen);

	if (status != qsc_tls_status_success || c2slen == 0U)
	{
		return false;
	}

	status = qsc_tls_engine_handshake(server, bufc2s, c2slen, &consumed, bufs2c, sizeof(bufs2c), &s2clen);

	if (status != qsc_tls_status_success)
	{
		return false;
	}

	offset = 0U;
	c2slen = 0U;

	while (offset < s2clen && qsc_tls_engine_is_handshake_complete(client) == false)
	{
		w = 0U;
		status = qsc_tls_engine_handshake(client, bufs2c + offset, s2clen - offset, &consumed, bufc2s, sizeof(bufc2s), &w);

		if (status != qsc_tls_status_success)
		{
			return false;
		}

		offset += consumed;

		if (w > 0U)
		{
			c2slen = w;
		}
	}

	if (qsc_tls_engine_is_handshake_complete(client) == false)
	{
		return false;
	}

	written = 0U;
	status = qsc_tls_engine_handshake(server, bufc2s, c2slen, &consumed, junk, sizeof(junk), &written);

	return (status == qsc_tls_status_success && qsc_tls_engine_is_handshake_complete(server) == true);
}

bool qsctest_tls_stage6_session_resumption(void)
{
	static const qsc_tls_cipher_suite suites[1U] = { qsc_tls_cipher_suite_tls_aes_128_gcm_sha256 };
	static const qsc_tls_named_group groups[1U] = { qsc_tls_group_x25519 };
	static const qsc_tls_signature_scheme sigs[1U] = { qsc_tls_sig_ed25519 };
	qsc_tls_client_config ccfg = { 0 };
	qsc_tls_connection client = { 0 };
	qsc_tls_session_ticket clientticket = { 0 };
	qsc_tls_session_ticket serverticket = { 0 };
	qsc_tls_server_config scfg = { 0 };
	qsc_tls_connection server = { 0 };
	qsc_tls_signer_default_context signerctx = { 0 };
	uint8_t nstrec[2048U] = { 0 };
	uint8_t seed[32U] = { 0 };
	size_t consumed;
	size_t i;
	size_t nstlen;
	qsc_tls_status status;
	bool clientrmsnonzero;
	bool serverrmsnonzero;
	bool res;

	res = true;
	clientrmsnonzero = false;
	serverrmsnonzero = false;
	qsc_memutils_clear(&client, sizeof(qsc_tls_connection));
	qsc_memutils_clear(&server, sizeof(qsc_tls_connection));
	qsc_memutils_clear(&ccfg, sizeof(qsc_tls_client_config));
	qsc_memutils_clear(&scfg, sizeof(qsc_tls_server_config));
	qsc_memutils_clear(&clientticket, sizeof(qsc_tls_session_ticket));
	qsc_memutils_clear(&serverticket, sizeof(qsc_tls_session_ticket));
	qsc_memutils_clear(&signerctx, sizeof(qsc_tls_signer_default_context));
	qsc_memutils_clear(nstrec, sizeof(nstrec));

	qsc_acp_generate(seed, sizeof(seed));
	qsc_secrand_initialize(seed, sizeof(seed), NULL, 0U);
	qsc_eddsa_generate_keypair(qsctest_tls_stage6_server_pk, qsctest_tls_stage6_server_sk, qsc_secrand_generate);
	qsc_memutils_copy(qsctest_tls_stage6_server_cert, qsctest_tls_stage6_server_pk, sizeof(qsctest_tls_stage6_server_cert));

	ccfg.ciphersuites = suites;
	ccfg.ciphersuitecount = 1U;
	ccfg.groups = groups;
	ccfg.groupcount = 1U;
	ccfg.sigschemes = sigs;
	ccfg.sigschemecount = 1U;
	ccfg.sigschemes = sigs;
	ccfg.sigschemecount = 1U;
	ccfg.hostname = "example.com";
	ccfg.certinterface.validatechain = qsctest_tls_stage6_stub_validate;
	ccfg.certinterface.verifycertificateverify = qsctest_tls_stage6_stub_verify;

	scfg.ciphersuitepreference = suites;
	scfg.ciphersuitepreferencecount = 1U;
	scfg.groupspreference = groups;
	scfg.groupspreferencecount = 1U;
	scfg.sigschemepreference = sigs;
	scfg.sigschemepreferencecount = 1U;
	scfg.localcert.chain[0].data = qsctest_tls_stage6_server_cert;
	scfg.localcert.chain[0].datalen = sizeof(qsctest_tls_stage6_server_cert);
	scfg.localcert.chainlength = 1U;
	scfg.localcert.verifyscheme = qsc_tls_sig_ed25519;
	scfg.localcert.configured = true;
	signerctx.scheme = qsc_tls_sig_ed25519;
	signerctx.privatekey = qsctest_tls_stage6_server_sk;
	signerctx.privatekeylen = sizeof(qsctest_tls_stage6_server_sk);
	scfg.localcert.signcallback = qsc_tls_signer_default_sign;
	scfg.localcert.signstate = &signerctx;

	qsc_tls_engine_initialize_client(&client, &ccfg);
	qsc_tls_engine_initialize_server(&server, &scfg);

	if (qsctest_tls_stage6_do_handshake(&client, &server) == false)
	{
		res = false;
	}

	for (i = 0U; i < client.state.client.keyschedule.digestsize; ++i)
	{
		if (client.state.client.keyschedule.resumptionmastersecret[i] != 0U)
		{
			clientrmsnonzero = true;
			break;
		}
	}

	for (i = 0U; i < server.state.server.keyschedule.digestsize; ++i)
	{
		if (server.state.server.keyschedule.resumptionmastersecret[i] != 0U)
		{
			serverrmsnonzero = true;
			break;
		}
	}

	if (clientrmsnonzero == false || serverrmsnonzero == false)
	{
		res = false;
	}

	if (client.state.client.keyschedule.digestsize != server.state.server.keyschedule.digestsize)
	{
		res = false;
	}
	else if (qsc_memutils_are_equal(client.state.client.keyschedule.resumptionmastersecret,
		server.state.server.keyschedule.resumptionmastersecret,
		client.state.client.keyschedule.digestsize) == false)
	{
		res = false;
	}

	nstlen = 0U;
	status = qsc_tls_engine_emit_session_ticket(&server, 7200U, nstrec, sizeof(nstrec), &nstlen, &serverticket);

	if (status != qsc_tls_status_success || nstlen == 0U)
	{
		res = false;
	}

	if (serverticket.ticketlen != 32U || serverticket.noncelen != 8U || serverticket.lifetime != 7200U ||
		serverticket.suite != qsc_tls_cipher_suite_tls_aes_128_gcm_sha256 || serverticket.resumptionsecretlen != 32U)
	{
		res = false;
	}

	consumed = 0U;
	status = qsc_tls_engine_consume_session_ticket(&client, nstrec, nstlen, &consumed, &clientticket);

	if (status != qsc_tls_status_success || consumed != nstlen)
	{
		res = false;
	}

	if (clientticket.ticketlen != serverticket.ticketlen || clientticket.noncelen != serverticket.noncelen ||
		clientticket.lifetime != serverticket.lifetime || clientticket.ageadd != serverticket.ageadd ||
		clientticket.suite != serverticket.suite || clientticket.resumptionsecretlen != serverticket.resumptionsecretlen)
	{
		res = false;
	}

	if (qsc_memutils_are_equal(clientticket.nonce, serverticket.nonce, serverticket.noncelen) == false)
	{
		res = false;
	}

	if (qsc_memutils_are_equal(clientticket.ticket, serverticket.ticket, serverticket.ticketlen) == false)
	{
		res = false;
	}

	if (qsc_memutils_are_equal(clientticket.resumptionsecret, serverticket.resumptionsecret, serverticket.resumptionsecretlen) == false)
	{
		res = false;
	}

	qsc_tls_session_ticket_dispose(&serverticket);
	qsc_tls_session_ticket_dispose(&clientticket);
	qsc_tls_engine_dispose(&client);
	qsc_tls_engine_dispose(&server);

	return res;
}

bool qsctest_tls_stage6_tests(void)
{
	bool res;

	res = true;

	if (qsctest_tls_stage6_session_resumption() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 6 session resumption test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 6 session resumption test.");
		res = false;
	}

	return res;
}
