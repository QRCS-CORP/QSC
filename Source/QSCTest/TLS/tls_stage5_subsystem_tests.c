#include "tls_stage5_subsystem_tests.h"
#include "../testutils.h"
#include "csp.h"
#include "tlsclient.h"
#include "tlsserver.h"
#include "tlsengine.h"
#include "tlssignerdefault.h"
#include "memutils.h"
#include "eddsa.h"

typedef struct
{
    qsc_tls_connection client;
    qsc_tls_connection server;
} stage5_connection_pair;

static stage5_connection_pair* stage5_connection_pair_allocate(void)
{
    stage5_connection_pair* pair;

    pair = (stage5_connection_pair*)qsc_memutils_malloc(sizeof(stage5_connection_pair));

    if (pair != NULL)
    {
        qsc_memutils_clear(pair, sizeof(stage5_connection_pair));
    }

    return pair;
}

static void stage5_connection_pair_free(stage5_connection_pair* pair)
{
    if (pair != NULL)
    {
        qsc_memutils_alloc_free(pair);
    }
}

static uint8_t g_server_pk[32U];
static uint8_t g_server_sk[64U];
static uint8_t g_server_cert[32U];
static bool g_stage5_initialized = false;

static bool qsctest_tls_stage5_stub_validate(const qsc_tls_certificate_view* chain, size_t chainlength, const qsc_tls_certificate_validation_context* ctx, void* state)
{
	(void)ctx;
	(void)state;

	return (chainlength == 1U && chain[0U].datalen == 32U);
}

static bool qsctest_tls_stage5_stub_verify(qsc_tls_signature_scheme scheme, const uint8_t* input, size_t inputlen, const uint8_t* signature, 
	size_t signaturelen, const qsc_tls_certificate_view* signer, void* state)
{
	qsc_tls_certificate_view v = { 0 };

	(void)signer;
	(void)state;
	v.data = g_server_pk;
	v.datalen = 32U;

	return qsc_tls_signer_default_verify(scheme, input, inputlen, signature, signaturelen, &v, NULL);
}

static void qsctest_tls_stage5_initialize_material(void)
{
	if (g_stage5_initialized == false)
	{
		qsc_eddsa_generate_keypair(g_server_pk, g_server_sk, qsc_csp_generate);
		qsc_memutils_copy(g_server_cert, g_server_pk, 32U);
		g_stage5_initialized = true;
	}
}

static int32_t qsctest_tls_stage5_do_handshake(qsc_tls_connection* client, qsc_tls_connection* server)
{
	uint8_t buf_c2s[4096U] = { 0U };
	uint8_t buf_s2c[16384U] = { 0U };
	uint8_t junk[64U] = { 0U };
	size_t c2slen;
	size_t client_fin_len;
	size_t consumed;
	size_t offset;
	size_t s2clen;
	size_t written;
	qsc_tls_status st;

	c2slen = 0U;
	s2clen = 0U;
	st = qsc_tls_engine_handshake(client, NULL, 0U, &consumed, buf_c2s, sizeof(buf_c2s), &c2slen);

	if (st != qsc_tls_status_success || c2slen == 0U)
	{
		return 0;
	}

	st = qsc_tls_engine_handshake(server, buf_c2s, c2slen, &consumed, buf_s2c, sizeof(buf_s2c), &s2clen);

	if (st != qsc_tls_status_success || s2clen == 0U)
	{
		return 0;
	}

	offset = 0U;
	client_fin_len = 0U;

	while (offset < s2clen && qsc_tls_engine_is_handshake_complete(client) == false)
	{
		size_t w;

		w = 0U;
		st = qsc_tls_engine_handshake(client, buf_s2c + offset, s2clen - offset, &consumed, buf_c2s, sizeof(buf_c2s), &w);

		if (st != qsc_tls_status_success)
		{
			return 0;
		}

		offset += consumed;

		if (w > 0U)
		{
			client_fin_len = w;
		}
	}

	if (qsc_tls_engine_is_handshake_complete(client) == false)
	{
		return 0;
	}

	st = qsc_tls_engine_handshake(server, buf_c2s, client_fin_len, &consumed, junk, sizeof(junk), &written);

	if (st != qsc_tls_status_success)
	{
		return 0;
	}

	return (qsc_tls_engine_is_handshake_complete(server) == true) ? 1 : 0;
}

static void qsctest_tls_stage5_setup_configs(qsc_tls_client_config* ccfg, qsc_tls_server_config* scfg, qsc_tls_signer_default_context* signer_ctx,
	const qsc_tls_cipher_suite* suites, const qsc_tls_named_group* groups, const qsc_tls_signature_scheme* sigs)
{
	qsc_memutils_clear(ccfg, sizeof(*ccfg));
	ccfg->ciphersuites = suites;
	ccfg->ciphersuitecount = 1U;
	ccfg->groups = groups;
	ccfg->groupcount = 1U;
	ccfg->sigschemes = sigs;
	ccfg->sigschemecount = 1U;
	ccfg->sigschemes = sigs;
	ccfg->sigschemecount = 1U;
	ccfg->hostname = "example.com";
	ccfg->certinterface.validatechain = qsctest_tls_stage5_stub_validate;
	ccfg->certinterface.verifycertificateverify = qsctest_tls_stage5_stub_verify;

	qsc_memutils_clear(scfg, sizeof(*scfg));
	scfg->ciphersuitepreference = suites;
	scfg->ciphersuitepreferencecount = 1U;
	scfg->groupspreference = groups;
	scfg->groupspreferencecount = 1U;
	scfg->sigschemepreference = sigs;
	scfg->sigschemepreferencecount = 1U;
	scfg->localcert.chain[0U].data = g_server_cert;
	scfg->localcert.chain[0U].datalen = 32U;
	scfg->localcert.chainlength = 1U;
	scfg->localcert.verifyscheme = qsc_tls_sig_ed25519;
	scfg->localcert.configured = true;
	signer_ctx->scheme = qsc_tls_sig_ed25519;
	signer_ctx->privatekey = g_server_sk;
	signer_ctx->privatekeylen = 64U;
	scfg->localcert.signcallback = qsc_tls_signer_default_sign;
	scfg->localcert.signstate = signer_ctx;
}

static bool qsctest_tls_stage5_app_data_roundtrip(void)
{
	qsc_tls_client_config ccfg = { 0 };
	stage5_connection_pair* pair;
	qsc_tls_server_config scfg = { 0 };
	qsc_tls_signer_default_context sctx = { 0 };
	const qsc_tls_cipher_suite suites[1U] = { qsc_tls_cipher_suite_tls_aes_128_gcm_sha256 };
	const qsc_tls_named_group groups[1U] = { qsc_tls_group_x25519 };
	const qsc_tls_signature_scheme sigs[1U] = { qsc_tls_sig_ed25519 };
	const uint8_t payload_c[] = "hello from client";
	const uint8_t payload_s[] = "hi client, this is server with a longer message";
	uint8_t plain[512U] = { 0U };
	uint8_t recbuf[512U] = { 0U };
	size_t consumed;
	size_t plainlen;
	size_t reclen;
	qsc_tls_status st;
	bool res;

	pair = stage5_connection_pair_allocate();

	if (pair == NULL)
	{
		return false;
	}

	qsctest_tls_stage5_setup_configs(&ccfg, &scfg, &sctx, suites, groups, sigs);
	qsc_tls_engine_initialize_client(&pair->client, &ccfg);
	qsc_tls_engine_initialize_server(&pair->server, &scfg);
	res = (qsctest_tls_stage5_do_handshake(&pair->client, &pair->server) == 1);

	if (res == true)
	{
		reclen = 0U;
		st = qsc_tls_engine_write_application_data(&pair->client, payload_c, sizeof(payload_c) - 1U, recbuf, sizeof(recbuf), &reclen);
		res = (st == qsc_tls_status_success && reclen > 0U);
	}

	if (res == true)
	{
		consumed = 0U;
		plainlen = 0U;
		st = qsc_tls_engine_read_application_data(&pair->server, recbuf, reclen, &consumed, plain, sizeof(plain), &plainlen);
		res = (st == qsc_tls_status_success);
	}

	if (res == true)
	{
		res = (plainlen == (sizeof(payload_c) - 1U));
	}

	if (res == true)
	{
		res = qsc_memutils_are_equal(plain, payload_c, plainlen);
	}

	if (res == true)
	{
		reclen = 0U;
		st = qsc_tls_engine_write_application_data(&pair->server, payload_s, sizeof(payload_s) - 1U, recbuf, sizeof(recbuf), &reclen);
		res = (st == qsc_tls_status_success && reclen > 0U);
	}

	if (res == true)
	{
		consumed = 0U;
		plainlen = 0U;
		st = qsc_tls_engine_read_application_data(&pair->client, recbuf, reclen, &consumed, plain, sizeof(plain), &plainlen);
		res = (st == qsc_tls_status_success);
	}

	if (res == true)
	{
		res = (plainlen == (sizeof(payload_s) - 1U));
	}

	if (res == true)
	{
		res = qsc_memutils_are_equal(plain, payload_s, plainlen);
	}

	if (res == true)
	{
		reclen = 0U;
		st = qsc_tls_engine_close(&pair->client, recbuf, sizeof(recbuf), &reclen);
		res = (st == qsc_tls_status_success && reclen > 0U);
	}

	qsc_tls_engine_dispose(&pair->client);
	qsc_tls_engine_dispose(&pair->server);
	stage5_connection_pair_free(pair);

	return res;
}

static bool qsctest_tls_stage5_malformed_client_hello(void)
{
	qsc_tls_client_config ccfg = { 0 };
	qsc_tls_server_config scfg = { 0 };
	qsc_tls_signer_default_context sctx = { 0 };
	qsc_tls_connection* s;
	const qsc_tls_cipher_suite suites[1U] = { qsc_tls_cipher_suite_tls_aes_128_gcm_sha256 };
	const qsc_tls_named_group groups[1U] = { qsc_tls_group_x25519 };
	const qsc_tls_signature_scheme sigs[1U] = { qsc_tls_sig_ed25519 };
	uint8_t bogus[6U] = { 0x16U, 0x03U, 0x03U, 0x03U, 0xE8U, 0x00U };
	uint8_t mal[10U] = { 0x16U, 0x03U, 0x03U, 0x00U, 0x05U, 0x01U, 0x00U, 0x00U, 0x01U, 0x00U };
	uint8_t out[256U];
	size_t consumed;
	size_t written;
	qsc_tls_status st;
	bool res;

	s = (qsc_tls_connection*)qsc_memutils_malloc(sizeof(qsc_tls_connection));

	if (s == NULL)
	{
		return false;
	}

	qsc_memutils_clear(s, sizeof(qsc_tls_connection));
	qsctest_tls_stage5_setup_configs(&ccfg, &scfg, &sctx, suites, groups, sigs);
	qsc_tls_engine_initialize_server(s, &scfg);

	consumed = 0U;
	written = 0U;
	st = qsc_tls_engine_handshake(s, bogus, sizeof(bogus), &consumed, out, sizeof(out), &written);
	res = (st == qsc_tls_status_success && consumed == 0U);

	if (res == true)
	{
		st = qsc_tls_engine_handshake(s, mal, sizeof(mal), &consumed, out, sizeof(out), &written);
		res = (st != qsc_tls_status_success);
	}

	qsc_tls_engine_dispose(s);
	qsc_memutils_alloc_free(s);

	return res;
}

static bool qsctest_tls_stage5_tampered_finished(void)
{
	qsc_tls_client_config ccfg = { 0 };
	stage5_connection_pair* pair;
	qsc_tls_server_config scfg = { 0 };
	qsc_tls_signer_default_context sctx = { 0 };
	const qsc_tls_cipher_suite suites[1U] = { qsc_tls_cipher_suite_tls_aes_128_gcm_sha256 };
	const qsc_tls_named_group groups[1U] = { qsc_tls_group_x25519 };
	const qsc_tls_signature_scheme sigs[1U] = { qsc_tls_sig_ed25519 };
	uint8_t bufc2s[4096U] = { 0U };
	uint8_t bufs2c[16384U] = { 0U };
	uint8_t junk[64U] = { 0U };
	size_t c2slen;
	size_t cfinlen;
	size_t consumed;
	size_t offset;
	size_t s2c_len;
	size_t written;
	qsc_tls_status st;
	bool res;

	pair = stage5_connection_pair_allocate();

	if (pair == NULL)
	{
		return false;
	}

	qsctest_tls_stage5_setup_configs(&ccfg, &scfg, &sctx, suites, groups, sigs);
	qsc_tls_engine_initialize_client(&pair->client, &ccfg);
	qsc_tls_engine_initialize_server(&pair->server, &scfg);

	c2slen = 0U;
	s2c_len = 0U;
	st = qsc_tls_engine_handshake(&pair->client, NULL, 0U, &consumed, bufc2s, sizeof(bufc2s), &c2slen);
	res = (st == qsc_tls_status_success && c2slen > 0U);

	if (res == true)
	{
		st = qsc_tls_engine_handshake(&pair->server, bufc2s, c2slen, &consumed, bufs2c, sizeof(bufs2c), &s2c_len);
		res = (st == qsc_tls_status_success && s2c_len > 0U);
	}

	offset = 0U;
	cfinlen = 0U;

	while (res == true && offset < s2c_len && qsc_tls_engine_is_handshake_complete(&pair->client) == false)
	{
		size_t w;

		w = 0U;
		st = qsc_tls_engine_handshake(&pair->client, bufs2c + offset, s2c_len - offset, &consumed, bufc2s, sizeof(bufc2s), &w);
		res = (st == qsc_tls_status_success);
		offset += consumed;

		if (w > 0U)
		{
			cfinlen = w;
		}
	}

	if (res == true)
	{
		res = (cfinlen > 0U && qsc_tls_engine_is_handshake_complete(&pair->client) == true);
	}

	if (res == true && cfinlen > 10U)
	{
		bufc2s[cfinlen / 2U] ^= 0x01U;
	}

	if (res == true)
	{
		st = qsc_tls_engine_handshake(&pair->server, bufc2s, cfinlen, &consumed, junk, sizeof(junk), &written);
		res = (st != qsc_tls_status_success);
	}

	qsc_tls_engine_dispose(&pair->client);
	qsc_tls_engine_dispose(&pair->server);
	stage5_connection_pair_free(pair);

	return res;
}

bool qsctest_tls_stage5_tests(void)
{
	bool res;

	qsctest_tls_stage5_initialize_material();
	res = true;

	if (qsctest_tls_stage5_app_data_roundtrip() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 5 subsystem application data round-trip test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 5 subsystem application data round-trip test.");
		res = false;
	}

	if (qsctest_tls_stage5_malformed_client_hello() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 5 malformed ClientHello rejection test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 5 malformed ClientHello rejection test.");
		res = false;
	}

	if (qsctest_tls_stage5_tampered_finished() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 5 tampered Finished rejection test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 5 tampered Finished rejection test.");
		res = false;
	}

	return res;
}
