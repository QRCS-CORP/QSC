#include "tls_stage3_keyupdate_tests.h"
#include "../testutils.h"
#include "csp.h"
#include "tlsengine.h"
#include "tlsclient.h"
#include "tlsserver.h"
#include "tlssignerdefault.h"
#include "memutils.h"
#include "eddsa.h"

typedef struct
{
    qsc_tls_connection client;
    qsc_tls_connection server;
} stage3_connection_pair;

static stage3_connection_pair* stage3_connection_pair_allocate(void)
{
    stage3_connection_pair* pair;

    pair = (stage3_connection_pair*)qsc_memutils_malloc(sizeof(stage3_connection_pair));

    if (pair != NULL)
    {
        qsc_memutils_clear(pair, sizeof(stage3_connection_pair));
    }

    return pair;
}

static void stage3_connection_pair_free(stage3_connection_pair* pair)
{
    if (pair != NULL)
    {
        qsc_memutils_alloc_free(pair);
    }
}

static uint8_t qsctest_tls_stage3_server_pk[32];
static uint8_t qsctest_tls_stage3_server_sk[64];
static uint8_t qsctest_tls_stage3_server_cert[32];

static bool qsctest_tls_stage3_stub_validate(const qsc_tls_certificate_view* chain, size_t chainlength, const qsc_tls_certificate_validation_context* ctx, void* state)
{
	(void)ctx;
	(void)state;

	return (chain != NULL && chainlength == 1U && chain[0].datalen == 32U);
}

static bool qsctest_tls_stage3_stub_verify(qsc_tls_signature_scheme scheme, const uint8_t* input, size_t inputlen,
	const uint8_t* signature, size_t signaturelen, const qsc_tls_certificate_view* signer, void* state)
{
	qsc_tls_certificate_view v;

	(void)signer;
	(void)state;

	v.data = qsctest_tls_stage3_server_pk;
	v.datalen = 32U;

	return qsc_tls_signer_default_verify(scheme, input, inputlen, signature, signaturelen, &v, NULL);
}

static bool qsctest_tls_stage3_do_handshake(qsc_tls_connection* client, qsc_tls_connection* server)
{
	uint8_t buf_c2s[4096U] = { 0U };
	uint8_t buf_s2c[16384U] = { 0U };
	uint8_t junk[128U] = { 0U };
	size_t c2slen;
	size_t s2clen;
	size_t consumed;
	size_t written;
	size_t offset;
	size_t cfinlen;
	qsc_tls_status st;

	st = qsc_tls_status_failure;
	c2slen = 0U;
	s2clen = 0U;
	consumed = 0U;
	written = 0U;
	offset = 0U;
	cfinlen = 0U;

	st = qsc_tls_engine_handshake(client, NULL, 0U, &consumed, buf_c2s, sizeof(buf_c2s), &c2slen);

	if (st == qsc_tls_status_success && c2slen != 0U)
	{
		st = qsc_tls_engine_handshake(server, buf_c2s, c2slen, &consumed, buf_s2c, sizeof(buf_s2c), &s2clen);

		if (st == qsc_tls_status_success)
		{
			while (offset < s2clen && qsc_tls_engine_is_handshake_complete(client) == false)
			{
				size_t w;

				w = 0U;
				st = qsc_tls_engine_handshake(client, buf_s2c + offset, s2clen - offset, &consumed, buf_c2s, sizeof(buf_c2s), &w);

				if (st != qsc_tls_status_success)
				{
					return false;
				}

				offset += consumed;

				if (w > 0U)
				{
					cfinlen = w;
				}
			}

			if (qsc_tls_engine_is_handshake_complete(client) == false)
			{
				return false;
			}
		}

		st = qsc_tls_engine_handshake(server, buf_c2s, cfinlen, &consumed, junk, sizeof(junk), &written);
	}

	return (st == qsc_tls_status_success && qsc_tls_engine_is_handshake_complete(server));
}

static bool qsctest_tls_stage3_send_app(qsc_tls_connection* src, qsc_tls_connection* dst, const uint8_t* msg, size_t msglen)
{
	uint8_t rec[2048U] = { 0U };
	uint8_t plain[2048U] = { 0U };
	uint8_t resp[2048U] = { 0U };
	size_t reclen;
	size_t consumed;
	size_t plainlen;
	size_t resplen;
	qsc_tls_status st;

	st = qsc_tls_status_failure;
	reclen = 0U;
	consumed = 0U;
	plainlen = 0U;
	resplen = 0U;

	st = qsc_tls_engine_write_application_data(src, msg, msglen, rec, sizeof(rec), &reclen);

	if (st == qsc_tls_status_success)
	{
		st = qsc_tls_engine_read_application_data_ex(dst, rec, reclen, &consumed, plain, sizeof(plain), &plainlen, resp, sizeof(resp), &resplen);

		if (st != qsc_tls_status_success)
		{
			return false;
		}

		if (plainlen != msglen)
		{
			return false;
		}
	}

	return qsc_memutils_are_equal(plain, msg, msglen);
}

static bool qsctest_tls_stage3_keyupdate_e2e(void)
{
	const qsc_tls_cipher_suite suites[1U] = { qsc_tls_cipher_suite_tls_aes_128_gcm_sha256 };
	const qsc_tls_named_group groups[1U] = { qsc_tls_group_x25519 };
	const qsc_tls_signature_scheme sigs[1U] = { qsc_tls_sig_ed25519 };
	qsc_tls_client_config ccfg = { 0 };
	qsc_tls_server_config scfg = { 0 };
    stage3_connection_pair* pair;
	qsc_tls_signer_default_context signerctx;
	const uint8_t msg1[4U] = { 0x6DU, 0x73U, 0x67U, 0x31U };
	const uint8_t msg2[4U] = { 0x6DU, 0x73U, 0x67U, 0x32U };
	const uint8_t msg3[4U] = { 0x6DU, 0x73U, 0x67U, 0x33U };
	const uint8_t r1[2U] = { 0x72U, 0x31U };
	const uint8_t r2[2U] = { 0x72U, 0x32U };
	const uint8_t r3[2U] = { 0x72U, 0x33U };
	uint8_t kurec[512U] = { 0U };
	uint8_t rxplain[512U] = { 0U };
	uint8_t rxresp[512U] = { 0U };
	size_t dummy;
	size_t kulen;
	size_t rxconsumed;
	size_t rxplainlen;
	size_t rxresplen;
	qsc_tls_status st;
	bool res;

    pair = stage3_connection_pair_allocate();

    if (pair == NULL)
    {
        return false;
    }

	qsc_eddsa_generate_keypair(qsctest_tls_stage3_server_pk, qsctest_tls_stage3_server_sk, qsc_csp_generate);
	qsc_memutils_copy(qsctest_tls_stage3_server_cert, qsctest_tls_stage3_server_pk, 32U);

	qsc_memutils_clear(&ccfg, sizeof(ccfg));
	ccfg.ciphersuites = suites;
	ccfg.ciphersuitecount = 1U;
	ccfg.groups = groups;
	ccfg.groupcount = 1U;
	ccfg.sigschemes = sigs;
	ccfg.sigschemecount = 1U;
	ccfg.sigschemes = sigs;
	ccfg.sigschemecount = 1U;
	ccfg.hostname = "example.com";
	ccfg.certinterface.validatechain = qsctest_tls_stage3_stub_validate;
	ccfg.certinterface.verifycertificateverify = qsctest_tls_stage3_stub_verify;

	qsc_memutils_clear(&scfg, sizeof(scfg));
	scfg.ciphersuitepreference = suites;
	scfg.ciphersuitepreferencecount = 1U;
	scfg.groupspreference = groups;
	scfg.groupspreferencecount = 1U;
	scfg.sigschemepreference = sigs;
	scfg.sigschemepreferencecount = 1U;
	scfg.localcert.chain[0].data = qsctest_tls_stage3_server_cert;
	scfg.localcert.chain[0].datalen = 32U;
	scfg.localcert.chainlength = 1U;
	scfg.localcert.verifyscheme = qsc_tls_sig_ed25519;
	scfg.localcert.configured = true;
	signerctx.scheme = qsc_tls_sig_ed25519;
	signerctx.privatekey = qsctest_tls_stage3_server_sk;
	signerctx.privatekeylen = 64U;
	scfg.localcert.signcallback = qsc_tls_signer_default_sign;
	scfg.localcert.signstate = &signerctx;

	qsc_tls_engine_initialize_client(&pair->client, &ccfg);
	qsc_tls_engine_initialize_server(&pair->server, &scfg);
	res = qsctest_tls_stage3_do_handshake(&pair->client, &pair->server);

	if (res == true)
	{
		res = qsctest_tls_stage3_send_app(&pair->client, &pair->server, msg1, sizeof(msg1));
	}

	if (res == true)
	{
		res = qsctest_tls_stage3_send_app(&pair->server, &pair->client, r1, sizeof(r1));
	}

	if (res == true)
	{
		kulen = 0U;
		st = qsc_tls_engine_request_key_update(&pair->client, false, kurec, sizeof(kurec), &kulen);
		res = (st == qsc_tls_status_success && kulen > 0U);
	}

	if (res == true)
	{
		rxconsumed = 0U;
		rxplainlen = 0U;
		rxresplen = 0U;

		st = qsc_tls_engine_read_application_data_ex(&pair->server, kurec, kulen, &rxconsumed, rxplain, sizeof(rxplain), &rxplainlen, rxresp, sizeof(rxresp), &rxresplen);

		res = (st == qsc_tls_status_success && rxplainlen == 0U && rxresplen == 0U);
	}

	if (res == true)
	{
		res = qsctest_tls_stage3_send_app(&pair->client, &pair->server, msg2, sizeof(msg2));
	}

	if (res == true)
	{
		res = qsctest_tls_stage3_send_app(&pair->server, &pair->client, r2, sizeof(r2));
	}

	if (res == true)
	{
		kulen = 0U;
		st = qsc_tls_engine_request_key_update(&pair->server, true, kurec, sizeof(kurec), &kulen);
		res = (st == qsc_tls_status_success && kulen > 0U);
	}

	if (res == true)
	{
		rxconsumed = 0U;
		rxplainlen = 0U;
		rxresplen = 0U;

		st = qsc_tls_engine_read_application_data_ex(&pair->client, kurec, kulen, &rxconsumed, rxplain, sizeof(rxplain), &rxplainlen, rxresp, sizeof(rxresp), &rxresplen);

		res = (st == qsc_tls_status_success && rxplainlen == 0U && rxresplen > 0U);
	}

	if (res == true)
	{
		rxconsumed = 0U;
		rxplainlen = 0U;
		dummy = 0U;

		st = qsc_tls_engine_read_application_data_ex(&pair->server, rxresp, rxresplen, &rxconsumed, rxplain, sizeof(rxplain), &rxplainlen, NULL, 0U, &dummy);

		res = (st == qsc_tls_status_success);
	}

	if (res == true)
	{
		res = qsctest_tls_stage3_send_app(&pair->client, &pair->server, msg3, sizeof(msg3));
	}

	if (res == true)
	{
		res = qsctest_tls_stage3_send_app(&pair->server, &pair->client, r3, sizeof(r3));
	}

	qsc_tls_engine_dispose(&pair->client);
	qsc_tls_engine_dispose(&pair->server);
    stage3_connection_pair_free(pair);

	return res;
}

bool qsctest_tls_stage3_tests(void)
{
	bool res;

	res = true;

	if (qsctest_tls_stage3_keyupdate_e2e() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 3 key update end-to-end test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 3 key update end-to-end test.");
		res = false;
	}

	return res;
}
