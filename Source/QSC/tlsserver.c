#include "tlsserver.h"

void qsc_tls_server_initialize(qsc_tls_server* server)
{
	QSC_ASSERT(server != NULL);

	if (server != NULL)
	{
		qsc_tls_connection_state_initialize(&server->state, false);
	}
}

void qsc_tls_server_dispose(qsc_tls_server* server)
{
	QSC_ASSERT(server != NULL);

	if (server != NULL)
	{
		qsc_tls_connection_state_dispose(&server->state);
	}
}

void qsc_tls_server_set_certificate_interface(qsc_tls_server* server, const qsc_tls_certificate_interface* iface, const char* hostname, bool requirepeercertificate)
{
	QSC_ASSERT(server != NULL);

	if (server != NULL)
	{
		qsc_tls_handshake_set_certificate_interface(&server->state, iface, hostname, requirepeercertificate);
	}
}

qsc_tls_status qsc_tls_server_set_qsc_x509_interface(qsc_tls_server* server, qsc_tls_qsc_x509_context* context, const char* hostname, bool requirepeercertificate)
{
	QSC_ASSERT(server != NULL);
	QSC_ASSERT(context != NULL);

	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (server == NULL || context == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		status = qsc_tls_handshake_set_qsc_x509_interface(&server->state, context, hostname, requirepeercertificate);
	}

	return status;
}

qsc_tls_status qsc_tls_server_set_local_certificate(qsc_tls_server* server, const qsc_tls_certificate_view* chain, size_t chainlength, qsc_tls_signature_scheme verifyscheme, const uint8_t* verifysignature, size_t verifysignaturelen)
{
	QSC_ASSERT(server != NULL);

	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (server == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		status = qsc_tls_handshake_set_local_certificate(&server->state, chain, chainlength, verifyscheme, verifysignature, verifysignaturelen);
	}

	return status;
}

qsc_tls_status qsc_tls_server_set_local_certificate_signer(qsc_tls_server* server, const qsc_tls_certificate_view* chain, size_t chainlength, qsc_tls_signature_scheme verifyscheme, qsc_tls_certificate_sign_callback signcallback, void* signstate)
{
	QSC_ASSERT(server != NULL);

	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (server == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		status = qsc_tls_handshake_set_local_certificate_signer(&server->state, chain, chainlength, verifyscheme, signcallback, signstate);
	}

	return status;
}

qsc_tls_status qsc_tls_server_clear_local_certificate(qsc_tls_server* server)
{
	QSC_ASSERT(server != NULL);

	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (server == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		status = qsc_tls_handshake_clear_local_certificate(&server->state);
	}

	return status;
}

qsc_tls_status qsc_tls_server_process_client(qsc_tls_server* server, const uint8_t* input, size_t inlen, uint8_t* output, size_t outlen, size_t* msglen)
{
	QSC_ASSERT(server != NULL);
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(msglen != NULL);

	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (server == NULL || input == NULL || output == NULL || msglen == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (server->state.stage != qsc_tls_connection_stage_none && server->state.stage != qsc_tls_connection_stage_hello_retry_request_sent)
	{
		status = qsc_tls_status_invalid_state;
	}
	else
	{
		status = qsc_tls_server_process_client_hello(&server->state, input, inlen, output, outlen, msglen);

		if (status != qsc_tls_status_success)
		{
			qsc_tls_connection_state_fail(&server->state);
		}
	}

	return status;
}

qsc_tls_status qsc_tls_server_complete(qsc_tls_server* server, const uint8_t* input, size_t inlen)
{
	QSC_ASSERT(server != NULL);
	QSC_ASSERT(input != NULL);

	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (server == NULL || input == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (server->state.stage != qsc_tls_connection_stage_server_flight_sent)
	{
		status = qsc_tls_status_invalid_state;
	}
	else
	{
		status = qsc_tls_server_process_client_finished(&server->state, input, inlen);

		if (status != qsc_tls_status_success)
		{
			qsc_tls_connection_state_fail(&server->state);
		}
	}

	return status;
}

bool qsc_tls_server_is_handshake_complete(const qsc_tls_server* server)
{
	QSC_ASSERT(server != NULL);

	bool res;

	res = false;

	if (server != NULL)
	{
		res = server->state.handshakecomplete;
	}

	return res;
}

qsc_tls_status qsc_tls_server_export_resumption_ticket(const qsc_tls_server* server, const uint8_t* ticketbytes, size_t ticketlen, const uint8_t* nonce, size_t noncelen, uint32_t lifetime, uint32_t ageadd, qsc_tls_session_ticket* ticket)
{
	QSC_ASSERT(server != NULL);
	QSC_ASSERT(ticket != NULL);
	QSC_ASSERT(ticketbytes != NULL);
	QSC_ASSERT(nonce != NULL);

	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (server == NULL || ticket == NULL || ticketbytes == NULL || nonce == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		status = qsc_tls_handshake_export_resumption_ticket(&server->state, ticketbytes, ticketlen, nonce, noncelen, lifetime, ageadd, ticket);
	}

	return status;
}

qsc_tls_status qsc_tls_server_encrypt_application_data(qsc_tls_server* server, uint8_t* output, size_t outlen, size_t* written, const uint8_t* input, size_t inlen)
{
	QSC_ASSERT(server != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(written != NULL);

	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (server == NULL || output == NULL || written == NULL || (input == NULL && inlen != 0U))
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (qsc_tls_connection_state_application_data_permitted(&server->state) == false)
	{
		status = qsc_tls_status_invalid_state;
	}
	else
	{
		status = qsc_tls_handshake_encrypt_application_data(&server->state, output, outlen, written, input, inlen);
	}

	return status;
}

qsc_tls_status qsc_tls_server_decrypt_application_data(qsc_tls_server* server, uint8_t* output, size_t outlen, size_t* written, const uint8_t* input, size_t inlen)
{
	QSC_ASSERT(server != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(written != NULL);
	QSC_ASSERT(input != NULL);

	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (server == NULL || output == NULL || written == NULL || input == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (qsc_tls_connection_state_application_data_permitted(&server->state) == false)
	{
		status = qsc_tls_status_invalid_state;
	}
	else
	{
		status = qsc_tls_handshake_decrypt_application_data(&server->state, output, outlen, written, input, inlen);
	}

	return status;
}

qsc_tls_status qsc_tls_server_encrypt_alert(qsc_tls_server* server, uint8_t* output, size_t outlen, size_t* written, const uint8_t* alert, size_t alertlen)
{
	QSC_ASSERT(server != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(written != NULL);

	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (server == NULL || output == NULL || written == NULL || (alert == NULL && alertlen != 0U))
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (qsc_tls_connection_state_application_data_permitted(&server->state) == false)
	{
		status = qsc_tls_status_invalid_state;
	}
	else
	{
		status = qsc_tls_handshake_encrypt_alert(&server->state, output, outlen, written, alert, alertlen);
	}

	return status;
}

qsc_tls_status qsc_tls_server_decrypt_alert(qsc_tls_server* server, uint8_t* output, size_t outlen, size_t* written, const uint8_t* input, size_t inlen)
{
	QSC_ASSERT(server != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(written != NULL);
	QSC_ASSERT(input != NULL);

	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (server == NULL || output == NULL || written == NULL || input == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (qsc_tls_connection_state_application_data_permitted(&server->state) == false)
	{
		status = qsc_tls_status_invalid_state;
	}
	else
	{
		status = qsc_tls_handshake_decrypt_alert(&server->state, output, outlen, written, input, inlen);
	}

	return status;
}
