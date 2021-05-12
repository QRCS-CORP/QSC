#include "qsmp_test.h"
#include "../QSC/acp.h"
#include "../QSC/consoleutils.h"
#include "../QSC/intutils.h"
#include "../QSC/qclient.h"
#include "../QSC/qserver.h"

void qsc_qsmp_test_run()
{
	// host-id is organization (4 bytes), institution (4 bytes), and owner (8 bytes): ORG | INS | OWN
	const uint8_t PKEYID[QSC_QSMP_KEYID_SIZE] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	char strk[QSC_QSMP_PUBKEY_STRING_SIZE] = { 0 };
	uint8_t encsk[QSC_QSMP_SIGKEY_ENCODED_SIZE] = { 0 };
	qsc_qsmp_kex_client_state cctx = { 0 };
	qsc_qsmp_client_key ckey = { 0 };
	qsc_qsmp_kex_server_state sctx = { 0 };
	qsc_qsmp_server_key skey = { 0 };
	qsc_qsmp_server_key tmpsk = { 0 };
	qsc_qsmp_packet conreqt = { 0 };
	qsc_qsmp_packet conresp = { 0 };
	qsc_qsmp_client_key tmpck = { 0 };
	uint8_t cdata[121] = { 0 };
	uint8_t sdata[93] = { 0 };
	uint8_t cmsg[93] = { 0 };
	uint8_t smsg[121] = { 0 };
	qsc_qsmp_packet cpac = { 0 };
	qsc_qsmp_packet spac = { 0 };
	qsc_qsmp_errors err;
	size_t mlen;

	mlen = 0;

	qsc_qsmp_server_generate_keypair(&ckey, &skey, PKEYID);
	qsc_consoleutils_print_line("Encoding and printing the public key..");
	qsc_qsmp_server_encode_public_key(&sctx, strk, &skey);
	qsc_consoleutils_print_safe(strk);
	qsc_qsmp_client_decode_public_key(&tmpck, strk);
	qsc_consoleutils_print_line("");

	if (qsc_intutils_are_equal8(skey.config, tmpck.config, sizeof(skey.config)) == true &&
		qsc_intutils_are_equal8(skey.keyid, tmpck.keyid, sizeof(skey.keyid)) == true &&
		qsc_intutils_are_equal8(skey.verkey, tmpck.verkey, sizeof(skey.verkey)) == true &&
		skey.expiration == tmpck.expiration)
	{
		qsc_consoleutils_print_line("Success! Public key encoding and decoding test succeeded.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Public key encoding and decoding test failed.");
	}

	qsc_consoleutils_print_line("Encoding and decoding the secret key..");
	
	qsc_qsmp_server_serialize_signature_key(encsk, &skey);
	qsc_qsmp_server_deserialize_signature_key(&tmpsk, encsk);

	if (qsc_intutils_are_equal8(skey.config, tmpsk.config, sizeof(skey.config)) == true &&
		qsc_intutils_are_equal8(skey.keyid, tmpsk.keyid, sizeof(skey.keyid)) == true &&
		qsc_intutils_are_equal8(skey.verkey, tmpsk.verkey, sizeof(skey.verkey)) == true &&
		qsc_intutils_are_equal8(skey.sigkey, tmpsk.sigkey, sizeof(skey.sigkey)) == true &&
		skey.expiration == tmpsk.expiration)
	{
		qsc_consoleutils_print_line("Success! Private key encoding and decoding test succeeded.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Private key encoding and decoding test failed.");
	}


	/* initialize the client */
	qsc_qsmp_client_initialize(&cctx, &ckey);

	/* client sends a session token, the configuration string, and initiates a connection request */
	err = qsc_qsmp_client_connection_request(&cctx, &conreqt);

	if (err == qsc_qsmp_error_none)
	{
		qsc_consoleutils_print_line("Success! Client connection request succeeded.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Client connection request failed.");
	}

	/* initialize the server */
	qsc_qsmp_server_initialize(&sctx, &skey);

	/* server generates an asymmetric encryption key-pair, signs the public key, and sends it to client */
	if (err == qsc_qsmp_error_none)
	{
		err = qsc_qsmp_server_connection_response(&sctx, &conreqt, &conresp);
	}

	if (err == qsc_qsmp_error_none)
	{
		qsc_consoleutils_print_line("Success! Server connection response succeeded.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Server connection response failed.");
	}

	/* client verifies public encapsulation key, creates the shared secret, initializes the client transmit channel, encapsulates the secret, and sends to server */
	if (err == qsc_qsmp_error_none)
	{
		err = qsc_qsmp_client_exstart_request(&cctx, &conresp, &conreqt);
	}

	if (err == qsc_qsmp_error_none)
	{
		qsc_consoleutils_print_line("Success! Client exstart request succeeded.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Client exstart request failed.");
	}

	/* server decapsulates the shared secret, loads the symmetric key, and initializes channel 1 */
	if (err == qsc_qsmp_error_none)
	{
		err = qsc_qsmp_server_exstart_response(&sctx, &conreqt, &conresp);
	}

	if (err == qsc_qsmp_error_none)
	{
		qsc_consoleutils_print_line("Success! Server exstart response succeeded.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Server exstart response failed.");
	}

	/* client generates its own asymmetric encryption key-pair, and sends the public key to the server over the encrypted channel */
	if (err == qsc_qsmp_error_none)
	{
		err = qsc_qsmp_client_exchange_request(&cctx, &conresp, &conreqt);
	}

	if (err == qsc_qsmp_error_none)
	{
		qsc_consoleutils_print_line("Success! Client exchange request succeeded.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Client exchange request failed.");
	}

	/* server decrypts public key, encapsulates the secret for channel 2, sends to client */
	if (err == qsc_qsmp_error_none)
	{
		err = qsc_qsmp_server_exchange_response(&sctx, &conreqt, &conresp);
	}

	if (err == qsc_qsmp_error_none)
	{
		qsc_consoleutils_print_line("Success! Server exchange response succeeded.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Server exchange response failed.");
	}

	/* client decrypts the secret, and establishes channel 2, sends an established response */
	if (err == qsc_qsmp_error_none)
	{
		err = qsc_qsmp_client_establish_request(&cctx, &conresp, &conreqt);
	}

	if (err == qsc_qsmp_error_none)
	{
		qsc_consoleutils_print_line("Success! Client establish request succeeded.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Client establish request failed.");
	}

	/* server respose to established, both channels active */
	if (err == qsc_qsmp_error_none)
	{
		err = qsc_qsmp_server_establish_response(&sctx, &conreqt, &conresp);
	}

	if (err == qsc_qsmp_error_none)
	{
		qsc_consoleutils_print_line("Success! Server establish response succeeded.");
	}
	else
	{
		qsc_consoleutils_print_line("Failure! Server establish response failed.");
	}

	if (err == qsc_qsmp_error_none)
	{
		qsc_consoleutils_print_line("Success! The VPN has been established.");

		qsc_acp_generate(cdata, sizeof(cdata));
		qsc_qsmp_client_encrypt_packet(&cctx, cdata, sizeof(cdata), &cpac);
		qsc_qsmp_server_decrypt_packet(&sctx, &cpac, smsg, &mlen);

		if (qsc_intutils_are_equal8(cdata, smsg, sizeof(cdata)))
		{
			qsc_consoleutils_print_line("Success! Client packet decryption succeeded.");
		}
		else
		{
			qsc_consoleutils_print_line("Failure! Client packet decryption failed.");
		}

		qsc_acp_generate(sdata, sizeof(sdata));
		qsc_qsmp_server_encrypt_packet(&sctx, sdata, sizeof(sdata), &spac);
		qsc_qsmp_client_decrypt_packet(&cctx, &spac, cmsg, &mlen);

		if (qsc_intutils_are_equal8(sdata, cmsg, sizeof(sdata)))
		{
			qsc_consoleutils_print_line("Success! Server packet decryption succeeded.");
		}
		else
		{
			qsc_consoleutils_print_line("Failure! Server packet decryption failed.");
		}
	}
}
