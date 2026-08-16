#include "tls_stage13_secp256r1_tests.h"
#include "../testutils.h"
#include "csp.h"
#include "tlsgroups.h"
#include "memutils.h"

static bool qsctest_tls_stage13_secp256r1_roundtrip(void)
{
	bool res = false;

	if (qsc_tls_groups_is_supported(qsc_tls_group_secp256r1) == false)
	{
		res = true;
	}
	else
	{
		qsc_tls_key_exchange_state client = { 0 };
		qsc_tls_status st = { 0 };
		uint8_t serverpub[128U] = { 0U };
		uint8_t serverss[64U] = { 0U };
		uint8_t clientss[64U] = { 0U };
		size_t serverpublen;
		size_t serversslen;
		size_t clientsslen;

		serverpublen = 0U;
		serversslen = 0U;
		clientsslen = 0U;

		qsc_memutils_clear(&client, sizeof(qsc_tls_key_exchange_state));
		st = qsc_tls_groups_generate_client_keypair(&client, qsc_tls_group_secp256r1);

		if (st == qsc_tls_status_success && client.publicshare[0U] == 0x04U && client.publicsharelen == 65U)
		{
			st = qsc_tls_groups_server_respond(qsc_tls_group_secp256r1, client.publicshare, client.publicsharelen, serverpub, sizeof(serverpub), &serverpublen, serverss, sizeof(serverss), &serversslen);

			if (st == qsc_tls_status_success && serverpublen == 65U && serverpub[0U] == 0x04U)
			{
				st = qsc_tls_groups_client_derive_shared_secret(&client, serverpub, serverpublen, clientss, sizeof(clientss), &clientsslen);

				if (st == qsc_tls_status_success && clientsslen == serversslen && qsc_memutils_are_equal(clientss, serverss, clientsslen) == true)
				{
					res = true;
				}
			}
		}

		qsc_tls_groups_key_exchange_state_dispose(&client);
	}

	return res;
}

bool qsctest_tls_stage13_tests(void)
{
	bool res = true;

	if (qsctest_tls_stage13_secp256r1_roundtrip() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 13 secp256r1 round-trip test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 13 secp256r1 round-trip test.");
		res = false;
	}

	return res;
}
