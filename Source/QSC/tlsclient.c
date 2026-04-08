#include "tlsclient.h"

void qsc_tls_client_initialize(qsc_tls_client* client)
{
	QSC_ASSERT(client != NULL);

	if (client != NULL)
	{
		qsc_tls_connection_state_initialize(&client->state, true);
	}
}

void qsc_tls_client_dispose(qsc_tls_client* client)
{
	QSC_ASSERT(client != NULL);

	if (client != NULL)
	{
		qsc_tls_connection_state_dispose(&client->state);
	}
}

void qsc_tls_client_set_certificate_interface(qsc_tls_client* client, const qsc_tls_certificate_interface* iface, const char* hostname, bool requirepeercertificate)
{
	QSC_ASSERT(client != NULL);

	if (client != NULL)
	{
		qsc_tls_handshake_set_certificate_interface(&client->state, iface, hostname, requirepeercertificate);
	}
}

qsc_tls_status qsc_tls_client_set_qsc_x509_interface(qsc_tls_client* client, qsc_tls_qsc_x509_context* context, const char* hostname, bool requirepeercertificate)
{
	QSC_ASSERT(client != NULL);
	QSC_ASSERT(context != NULL);

	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (client == NULL || context == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		status = qsc_tls_handshake_set_qsc_x509_interface(&client->state, context, hostname, requirepeercertificate);
	}

	return status;
}

qsc_tls_status qsc_tls_client_set_local_certificate(qsc_tls_client* client, const qsc_tls_certificate_view* chain, size_t chainlength, qsc_tls_signature_scheme verifyscheme, const uint8_t* verifysignature, size_t verifysignaturelen)
{
	QSC_ASSERT(client != NULL);

	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (client == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		status = qsc_tls_handshake_set_local_certificate(&client->state, chain, chainlength, verifyscheme, verifysignature, verifysignaturelen);
	}

	return status;
}

qsc_tls_status qsc_tls_client_set_local_certificate_signer(qsc_tls_client* client, const qsc_tls_certificate_view* chain, size_t chainlength, qsc_tls_signature_scheme verifyscheme, qsc_tls_certificate_sign_callback signcallback, void* signstate)
{
	QSC_ASSERT(client != NULL);

	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (client == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		status = qsc_tls_handshake_set_local_certificate_signer(&client->state, chain, chainlength, verifyscheme, signcallback, signstate);
	}

	return status;
}

qsc_tls_status qsc_tls_client_clear_local_certificate(qsc_tls_client* client)
{
	QSC_ASSERT(client != NULL);

	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (client == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		status = qsc_tls_handshake_clear_local_certificate(&client->state);
	}

	return status;
}

qsc_tls_status qsc_tls_client_connect_start(qsc_tls_client* client, uint8_t* output, size_t outlen, size_t* msglen)
{
	QSC_ASSERT(client != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(msglen != NULL);

	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (client == NULL || output == NULL || msglen == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (qsc_tls_connection_state_configuration_permitted(&client->state) == false)
	{
		status = qsc_tls_status_invalid_state;
	}
	else
	{
		status = qsc_tls_client_build_client_hello(&client->state, output, outlen, msglen);
	}

	return status;
}

qsc_tls_status qsc_tls_client_process_server(qsc_tls_client* client, const uint8_t* input, size_t inlen, uint8_t* output, size_t outlen, size_t* msglen)
{
	QSC_ASSERT(client != NULL);
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(msglen != NULL);

	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (client == NULL || input == NULL || output == NULL || msglen == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (client->state.stage != qsc_tls_connection_stage_client_hello_sent)
	{
		status = qsc_tls_status_invalid_state;
	}
	else
	{
		status = qsc_tls_client_process_server_flight(&client->state, input, inlen, output, outlen, msglen);

		if (status != qsc_tls_status_success)
		{
			qsc_tls_connection_state_fail(&client->state);
		}
	}

	return status;
}

bool qsc_tls_client_is_handshake_complete(const qsc_tls_client* client)
{
	QSC_ASSERT(client != NULL);

	bool res;

	res = false;

	if (client != NULL)
	{
		res = client->state.handshakecomplete;
	}

	return res;
}

qsc_tls_status qsc_tls_client_set_resumption_ticket(qsc_tls_client* client, const qsc_tls_session_ticket* ticket)
{
	QSC_ASSERT(client != NULL);
	QSC_ASSERT(ticket != NULL);

	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (client == NULL || ticket == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		status = qsc_tls_handshake_enable_resumption(&client->state, ticket);
	}

	return status;
}

bool qsc_tls_client_is_resumption_enabled(const qsc_tls_client* client)
{
	QSC_ASSERT(client != NULL);

	bool res;

	res = false;

	if (client != NULL)
	{
		res = qsc_tls_handshake_is_resumption_enabled(&client->state);
	}

	return res;
}

qsc_tls_status qsc_tls_client_encrypt_application_data(qsc_tls_client* client, uint8_t* output, size_t outlen, size_t* written, const uint8_t* input, size_t inlen)
{
	QSC_ASSERT(client != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(written != NULL);
	QSC_ASSERT(input != NULL);

	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (client == NULL || output == NULL || written == NULL || input == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (qsc_tls_connection_state_application_data_permitted(&client->state) == false)
	{
		status = qsc_tls_status_invalid_state;
	}
	else
	{
		status = qsc_tls_handshake_encrypt_application_data(&client->state, output, outlen, written, input, inlen);
	}

	return status;
}

qsc_tls_status qsc_tls_client_decrypt_application_data(qsc_tls_client* client, uint8_t* output, size_t outlen, size_t* written, const uint8_t* input, size_t inlen)
{
	QSC_ASSERT(client != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(written != NULL);
	QSC_ASSERT(input != NULL);

	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (client == NULL || output == NULL || written == NULL || input == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (qsc_tls_connection_state_application_data_permitted(&client->state) == false)
	{
		status = qsc_tls_status_invalid_state;
	}
	else
	{
		status = qsc_tls_handshake_decrypt_application_data(&client->state, output, outlen, written, input, inlen);
	}

	return status;
}

qsc_tls_status qsc_tls_client_encrypt_alert(qsc_tls_client* client, uint8_t* output, size_t outlen, size_t* written, const uint8_t* alert, size_t alertlen)
{
	QSC_ASSERT(client != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(written != NULL);
	QSC_ASSERT(alert != NULL);

	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (client == NULL || output == NULL || written == NULL || alert == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (qsc_tls_connection_state_application_data_permitted(&client->state) == false)
	{
		status = qsc_tls_status_invalid_state;
	}
	else
	{
		status = qsc_tls_handshake_encrypt_alert(&client->state, output, outlen, written, alert, alertlen);
	}

	return status;
}

qsc_tls_status qsc_tls_client_decrypt_alert(qsc_tls_client* client, uint8_t* output, size_t outlen, size_t* written, const uint8_t* input, size_t inlen)
{
	QSC_ASSERT(client != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(written != NULL);
	QSC_ASSERT(input != NULL);

	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (client == NULL || output == NULL || written == NULL || input == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (qsc_tls_connection_state_application_data_permitted(&client->state) == false)
	{
		status = qsc_tls_status_invalid_state;
	}
	else
	{
		status = qsc_tls_handshake_decrypt_alert(&client->state, output, outlen, written, input, inlen);
	}

	return status;
}
