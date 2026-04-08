#include "tls_stage6_certificate_message_tests.h"
#include "../testutils.h"
#include "memutils.h"
#include "tlscert.h"
#include "tlscertmsg.h"
#include "tlserrors.h"
#include "tlssigalgs.h"

#define TLS_STAGE6_TEST_CERT0_SIZE 64U
#define TLS_STAGE6_TEST_CERT1_SIZE 96U
#define TLS_STAGE6_TEST_EXT0_SIZE 4U
#define TLS_STAGE6_TEST_EXT1_SIZE 6U
#define TLS_STAGE6_TEST_CONTEXT_SIZE 8U
#define TLS_STAGE6_TEST_TRANSCRIPT_SIZE 48U
#define TLS_STAGE6_TEST_VERIFY_SIG_SIZE 72U
#define TLS_STAGE6_TEST_MESSAGE_BUFFER 512U

typedef struct tls_stage6_callback_state
{
	bool validatechainresult;
	bool verifyresult;
	bool validatechaincalled;
	bool verifycalled;
	size_t chainlength;
	bool requirepeercertificate;
	bool clientauth;
	const char* hostname;
	qsc_tls_signature_scheme verifyscheme;
	const uint8_t* transcript;
	size_t transcriptlen;
	const uint8_t* signature;
	size_t signaturelen;
	const uint8_t* signerdata;
	size_t signerdatalen;
} tls_stage6_callback_state;

static void tls_stage6_fill_sequence(uint8_t* output, size_t outlen, uint8_t seed)
{
	size_t i;

	QSC_ASSERT(output != NULL);

	if (output != NULL)
	{
		for (i = 0U; i < outlen; ++i)
		{
			output[i] = (uint8_t)(seed + (uint8_t)i);
		}
	}
}

static bool tls_stage6_validate_chain(const qsc_tls_certificate_view* chain, size_t chainlength, const qsc_tls_certificate_validation_context* context, void* state)
{
	tls_stage6_callback_state* cstate;
	bool res;

	cstate = (tls_stage6_callback_state*)state;
	res = false;

	if (chain != NULL && context != NULL && cstate != NULL)
	{
		cstate->validatechaincalled = true;
		cstate->chainlength = chainlength;
		cstate->requirepeercertificate = context->requirepeercertificate;
		cstate->clientauth = context->clientauth;
		cstate->hostname = context->hostname;

		if (chainlength != 0U)
		{
			cstate->signerdata = chain[0U].data;
			cstate->signerdatalen = chain[0U].datalen;
		}

		res = cstate->validatechainresult;
	}

	return res;
}

static bool tls_stage6_verify_callback(qsc_tls_signature_scheme scheme, const uint8_t* transcript, size_t transcriptlen, const uint8_t* signature, size_t signaturelen, const qsc_tls_certificate_view* signer, void* state)
{
	tls_stage6_callback_state* cstate;
	bool res;

	cstate = (tls_stage6_callback_state*)state;
	res = false;

	if (transcript != NULL && signature != NULL && signer != NULL && cstate != NULL)
	{
		cstate->verifycalled = true;
		cstate->verifyscheme = scheme;
		cstate->transcript = transcript;
		cstate->transcriptlen = transcriptlen;
		cstate->signature = signature;
		cstate->signaturelen = signaturelen;
		cstate->signerdata = signer->data;
		cstate->signerdatalen = signer->datalen;
		res = cstate->verifyresult;
	}

	return res;
}

bool tls_stage6_certificate_message_roundtrip(void)
{
	static const uint8_t requestcontext[TLS_STAGE6_TEST_CONTEXT_SIZE] =
	{
		0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U
	};

	qsc_tls_certificate_entry_view entries[2U] = { 0 };
	qsc_tls_certificate_message_view message = { 0 };
	uint8_t cert0[TLS_STAGE6_TEST_CERT0_SIZE] = { 0U };
	uint8_t cert1[TLS_STAGE6_TEST_CERT1_SIZE] = { 0U };
	uint8_t ext0[TLS_STAGE6_TEST_EXT0_SIZE] = { 0U };
	uint8_t ext1[TLS_STAGE6_TEST_EXT1_SIZE] = { 0U };
	uint8_t buffer[TLS_STAGE6_TEST_MESSAGE_BUFFER] = { 0U };
	size_t msglen;
	qsc_tls_status status;
	bool res;

	tls_stage6_fill_sequence(cert0, sizeof(cert0), 0x21U);
	tls_stage6_fill_sequence(cert1, sizeof(cert1), 0x41U);
	tls_stage6_fill_sequence(ext0, sizeof(ext0), 0xC1U);
	tls_stage6_fill_sequence(ext1, sizeof(ext1), 0xD1U);
	entries[0U].certdata = cert0;
	entries[0U].certdatalen = sizeof(cert0);
	entries[0U].extensions = ext0;
	entries[0U].extensionslen = sizeof(ext0);
	entries[1U].certdata = cert1;
	entries[1U].certdatalen = sizeof(cert1);
	entries[1U].extensions = ext1;
	entries[1U].extensionslen = sizeof(ext1);
	msglen = 0U;
	status = qsc_tls_certificate_message_build(requestcontext, sizeof(requestcontext), entries, 2U, buffer, sizeof(buffer), &msglen);
	res = (status == qsc_tls_status_success);

	if (res == true)
	{
		status = qsc_tls_certificate_message_parse(buffer, msglen, &message);
		res = (status == qsc_tls_status_success);
	}

	if (res == true)
	{
		res = (message.requestcontextlen == sizeof(requestcontext));
	}

	if (res == true)
	{
		res = (qsc_memutils_are_equal(message.requestcontext, requestcontext, sizeof(requestcontext)) == true);
	}

	if (res == true)
	{
		res = (message.entrycount == 2U);
	}

	if (res == true)
	{
		res = (message.entries[0U].certdatalen == sizeof(cert0) &&
			message.entries[0U].extensionslen == sizeof(ext0) &&
			qsc_memutils_are_equal(message.entries[0U].certdata, cert0, sizeof(cert0)) == true &&
			qsc_memutils_are_equal(message.entries[0U].extensions, ext0, sizeof(ext0)) == true);
	}

	if (res == true)
	{
		res = (message.entries[1U].certdatalen == sizeof(cert1) &&
			message.entries[1U].extensionslen == sizeof(ext1) &&
			qsc_memutils_are_equal(message.entries[1U].certdata, cert1, sizeof(cert1)) == true &&
			qsc_memutils_are_equal(message.entries[1U].extensions, ext1, sizeof(ext1)) == true);
	}

	return res;
}

bool tls_stage6_certificate_message_negative(void)
{
	qsc_tls_certificate_entry_view entry = { 0 };
	qsc_tls_certificate_message_view message = { 0 };
	uint8_t cert[TLS_STAGE6_TEST_CERT0_SIZE] = { 0U };
	uint8_t ext[TLS_STAGE6_TEST_EXT0_SIZE] = { 0U };
	uint8_t context[TLS_STAGE6_TEST_CONTEXT_SIZE] = { 0U };
	uint8_t buffer[TLS_STAGE6_TEST_MESSAGE_BUFFER] = { 0U };
	size_t msglen;
	qsc_tls_status status;
	bool res;

	tls_stage6_fill_sequence(cert, sizeof(cert), 0x61U);
	tls_stage6_fill_sequence(ext, sizeof(ext), 0xE1U);
	tls_stage6_fill_sequence(context, sizeof(context), 0x01U);
	entry.certdata = cert;
	entry.certdatalen = sizeof(cert);
	entry.extensions = ext;
	entry.extensionslen = sizeof(ext);
	msglen = 0U;
	res = true;

	status = qsc_tls_certificate_message_build(NULL, sizeof(context), &entry, 1U, buffer, sizeof(buffer), &msglen);

	if (status != qsc_tls_status_invalid_input)
	{
		res = false;
	}

	if (res == true)
	{
		status = qsc_tls_certificate_message_build(context, QSC_TLS_CERTIFICATE_REQUEST_CONTEXT_MAX_SIZE + 1U, &entry, 1U, buffer, sizeof(buffer), &msglen);
		
		if (status != qsc_tls_status_invalid_length)
		{
			res = false;
		}
	}

	if (res == true)
	{
		status = qsc_tls_certificate_message_build(context, sizeof(context), &entry, 1U, buffer, sizeof(buffer), &msglen);

		if (status != qsc_tls_status_success)
		{
			res = false;
		}
	}

	if (res == true)
	{
		buffer[9U] ^= 0x01U;
		status = qsc_tls_certificate_message_parse(buffer, msglen, &message);

		if (status != qsc_tls_status_invalid_length)
		{
			res = false;
		}

		buffer[9U] ^= 0x01U;
	}

	if (res == true)
	{
		status = qsc_tls_certificate_message_parse(NULL, msglen, &message);

		if (status != qsc_tls_status_invalid_input)
		{
			res = false;
		}
	}

	return res;
}

bool tls_stage6_certificate_request_roundtrip(void)
{
	static const uint8_t requestcontext[3U] = { 0xAAU, 0xBBU, 0xCCU };
	static const qsc_tls_signature_scheme sigschemes[3U] =
	{
		qsc_tls_sig_ecdsa_secp256r1_sha256,
		qsc_tls_sig_ed25519,
		qsc_tls_sig_mldsa65
	};

	qsc_tls_certificate_request_message message = { 0 };
	uint8_t buffer[TLS_STAGE6_TEST_MESSAGE_BUFFER] = { 0U };
	size_t msglen;
	qsc_tls_status status;
	bool res;

	qsc_memutils_clear(&message, sizeof(qsc_tls_certificate_request_message));
	qsc_memutils_clear(buffer, sizeof(buffer));
	msglen = 0U;
	status = qsc_tls_certificate_request_build(requestcontext, sizeof(requestcontext), sigschemes, 3U, buffer, sizeof(buffer), &msglen);

	res = (status == qsc_tls_status_success);

	if (res == true)
	{
		status = qsc_tls_certificate_request_parse(buffer, msglen, &message);
		res = (status == qsc_tls_status_success);
	}

	if (res == true)
	{
		res = (message.requestcontextlen == sizeof(requestcontext) &&
			qsc_memutils_are_equal(message.requestcontext, requestcontext, sizeof(requestcontext)) == true);
	}

	if (res == true)
	{
		res = (message.sigschemecount == 3U &&
			message.sigschemes[0U] == sigschemes[0U] &&
			message.sigschemes[1U] == sigschemes[1U] &&
			message.sigschemes[2U] == sigschemes[2U]);
	}

	return res;
}

bool tls_stage6_certificate_request_negative(void)
{
	static const uint8_t requestcontext[2U] = { 0x31U, 0x32U };
	static const qsc_tls_signature_scheme sigschemes[2U] =
	{
		qsc_tls_sig_ecdsa_secp256r1_sha256,
		qsc_tls_sig_ed25519
	};
	qsc_tls_certificate_request_message message = { 0 };
	uint8_t buffer[TLS_STAGE6_TEST_MESSAGE_BUFFER] = { 0U };
	size_t msglen;
	qsc_tls_status status;
	bool res;

	qsc_memutils_clear(&message, sizeof(qsc_tls_certificate_request_message));
	qsc_memutils_clear(buffer, sizeof(buffer));
	msglen = 0U;
	res = true;

	status = qsc_tls_certificate_request_build(NULL, sizeof(requestcontext), sigschemes, 2U, buffer, sizeof(buffer), &msglen);

	if (status != qsc_tls_status_invalid_input)
	{
		res = false;
	}

	if (res == true)
	{
		status = qsc_tls_certificate_request_build(requestcontext, sizeof(requestcontext), sigschemes, 2U, buffer, sizeof(buffer), &msglen);

		if (status != qsc_tls_status_success)
		{
			res = false;
		}
	}

	if (res == true)
	{
		buffer[4U] ^= 0x01U;
		status = qsc_tls_certificate_request_parse(buffer, msglen, &message);

		if (status != qsc_tls_status_invalid_length)
		{
			res = false;
		}

		buffer[4U] ^= 0x01U;
	}

	if (res == true)
	{
		status = qsc_tls_certificate_request_build(requestcontext, sizeof(requestcontext), sigschemes, 2U, buffer, sizeof(buffer), &msglen);

		if (status != qsc_tls_status_success)
		{
			res = false;
		}
	}

	if (res == true)
	{
		buffer[9U] = 0x00U;
		buffer[10U] = 0x03U;
		status = qsc_tls_certificate_request_parse(buffer, msglen, &message);

		if (status != qsc_tls_status_invalid_length)
		{
			res = false;
		}
	}

	return res;
}

bool tls_stage6_certificate_verify_roundtrip(void)
{
	qsc_tls_certificate_verify_message message = { 0 };
	uint8_t signature[TLS_STAGE6_TEST_VERIFY_SIG_SIZE] = { 0U };
	uint8_t buffer[TLS_STAGE6_TEST_MESSAGE_BUFFER] = { 0U };
	size_t msglen;
	qsc_tls_status status;
	bool res;

	tls_stage6_fill_sequence(signature, sizeof(signature), 0x51U);
	msglen = 0U;
	status = qsc_tls_certificate_verify_build(qsc_tls_sig_ecdsa_secp256r1_sha256, signature, sizeof(signature), buffer, sizeof(buffer), &msglen);
	res = (status == qsc_tls_status_success);

	if (res == true)
	{
		status = qsc_tls_certificate_verify_parse(buffer, msglen, &message);
		res = (status == qsc_tls_status_success);
	}

	if (res == true)
	{
		res = (message.scheme == qsc_tls_sig_ecdsa_secp256r1_sha256 && message.signaturelen == sizeof(signature));
	}

	if (res == true)
	{
		res = (qsc_memutils_are_equal(message.signature, signature, sizeof(signature)) == true);
	}

	return res;
}

bool tls_stage6_certificate_verify_negative(void)
{
	qsc_tls_certificate_verify_message message = { 0 };
	uint8_t signature[TLS_STAGE6_TEST_VERIFY_SIG_SIZE] = { 0 };
	uint8_t buffer[TLS_STAGE6_TEST_MESSAGE_BUFFER] = { 0 };
	size_t msglen;
	qsc_tls_status status;
	bool res;

	tls_stage6_fill_sequence(signature, sizeof(signature), 0x71U);
	msglen = 0U;
	res = true;

	status = qsc_tls_certificate_verify_build(qsc_tls_sig_none, signature, sizeof(signature), buffer, sizeof(buffer), &msglen);

	if (status != qsc_tls_status_not_supported)
	{
		res = false;
	}

	if (res == true)
	{
		status = qsc_tls_certificate_verify_build(qsc_tls_sig_ecdsa_secp256r1_sha256, signature, sizeof(signature), buffer, sizeof(buffer), &msglen);
		
		if (status != qsc_tls_status_success)
		{
			res = false;
		}
	}

	if (res == true)
	{
		buffer[0U] = (uint8_t)((uint16_t)qsc_tls_sig_none >> 8);
		buffer[1U] = (uint8_t)((uint16_t)qsc_tls_sig_none & 0xFFU);
		status = qsc_tls_certificate_verify_parse(buffer, msglen, &message);

		if (status != qsc_tls_status_not_supported)
		{
			res = false;
		}
	}

	if (res == true)
	{
		status = qsc_tls_certificate_verify_build(qsc_tls_sig_ecdsa_secp256r1_sha256, signature, sizeof(signature), buffer, sizeof(buffer), &msglen);
		
		if (status != qsc_tls_status_success)
		{
			res = false;
		}
	}

	if (res == true)
	{
		buffer[2U] = 0x00U;
		buffer[3U] = (uint8_t)(sizeof(signature) - 1U);
		status = qsc_tls_certificate_verify_parse(buffer, msglen, &message);

		if (status != qsc_tls_status_invalid_length)
		{
			res = false;
		}
	}

	return res;
}

bool tls_stage6_certificate_peer_validation(void)
{
	tls_stage6_callback_state cstate = { 0 };
	qsc_tls_certificate_interface iface = { 0 };
	qsc_tls_certificate_message_view message = { 0 };
	qsc_tls_certificate_validation_context context = { 0 };
	uint8_t cert[TLS_STAGE6_TEST_CERT0_SIZE] = { 0U };
	qsc_tls_status status;
	bool res;

	tls_stage6_fill_sequence(cert, sizeof(cert), 0x81U);
	context.hostname = "server.example.test";
	context.clientauth = false;
	context.requirepeercertificate = true;
	message.entrycount = 1U;
	message.entries[0U].certdata = cert;
	message.entries[0U].certdatalen = sizeof(cert);
	cstate.validatechainresult = true;
	qsc_tls_certificate_interface_initialize(&iface, tls_stage6_validate_chain, tls_stage6_verify_callback, &cstate);
	res = (qsc_tls_certificate_interface_is_valid(&iface) == true);

	if (res == true)
	{
		status = qsc_tls_certificate_validate_peer(&message, &context, &iface);
		res = (status == qsc_tls_status_success);
	}

	if (res == true)
	{
		res = (cstate.validatechaincalled == true && cstate.chainlength == 1U &&
			cstate.requirepeercertificate == true && cstate.hostname == context.hostname &&
			cstate.signerdatalen == sizeof(cert) && qsc_memutils_are_equal(cstate.signerdata, cert, sizeof(cert)) == true);
	}

	if (res == true)
	{
		cstate.validatechainresult = false;
		status = qsc_tls_certificate_validate_peer(&message, &context, &iface);
		res = (status == qsc_tls_status_authentication_failure);
	}

	if (res == true)
	{
		message.entrycount = 0U;
		status = qsc_tls_certificate_validate_peer(&message, &context, &iface);
		res = (status == qsc_tls_status_invalid_message);
	}

	if (res == true)
	{
		qsc_memutils_clear(&iface, sizeof(qsc_tls_certificate_interface));
		status = qsc_tls_certificate_validate_peer(&message, &context, &iface);
		res = (status == qsc_tls_status_invalid_state);
	}

	return res;
}

bool tls_stage6_certificate_verify_validation(void)
{
	tls_stage6_callback_state cstate = { 0 };
	qsc_tls_certificate_interface iface = { 0 };
	qsc_tls_certificate_message_view message = { 0 };
	qsc_tls_certificate_verify_message verify = { 0 };
	uint8_t cert[TLS_STAGE6_TEST_CERT0_SIZE] = { 0U };
	uint8_t signature[TLS_STAGE6_TEST_VERIFY_SIG_SIZE] = { 0U };
	uint8_t transcript[TLS_STAGE6_TEST_TRANSCRIPT_SIZE] = { 0U };
	qsc_tls_status status;
	bool res;

	tls_stage6_fill_sequence(cert, sizeof(cert), 0x91U);
	tls_stage6_fill_sequence(signature, sizeof(signature), 0xA1U);
	tls_stage6_fill_sequence(transcript, sizeof(transcript), 0xB1U);
	message.entrycount = 1U;
	message.entries[0U].certdata = cert;
	message.entries[0U].certdatalen = sizeof(cert);
	verify.scheme = qsc_tls_sig_ecdsa_secp256r1_sha256;
	verify.signature = signature;
	verify.signaturelen = sizeof(signature);
	cstate.verifyresult = true;
	qsc_tls_certificate_interface_initialize(&iface, tls_stage6_validate_chain, tls_stage6_verify_callback, &cstate);
	status = qsc_tls_certificate_validate_verify(&message, &verify, transcript, sizeof(transcript), &iface);
	res = (status == qsc_tls_status_success);

	if (res == true)
	{
		res = (cstate.verifycalled == true && cstate.verifyscheme == verify.scheme &&
			cstate.transcript == transcript && cstate.transcriptlen == sizeof(transcript) &&
			cstate.signature == signature && cstate.signaturelen == sizeof(signature) &&
			cstate.signerdata == cert && cstate.signerdatalen == sizeof(cert));
	}

	if (res == true)
	{
		cstate.verifyresult = false;
		status = qsc_tls_certificate_validate_verify(&message, &verify, transcript, sizeof(transcript), &iface);
		res = (status == qsc_tls_status_authentication_failure);
	}

	if (res == true)
	{
		message.entrycount = 0U;
		status = qsc_tls_certificate_validate_verify(&message, &verify, transcript, sizeof(transcript), &iface);
		res = (status == qsc_tls_status_invalid_message);
	}

	if (res == true)
	{
		qsc_memutils_clear(&iface, sizeof(qsc_tls_certificate_interface));
		status = qsc_tls_certificate_validate_verify(&message, &verify, transcript, sizeof(transcript), &iface);
		res = (status == qsc_tls_status_invalid_state);
	}

	return res;
}

bool qsctest_tls_stage6_tests(void)
{
	bool res;

	res = true;

	if (tls_stage6_certificate_message_roundtrip() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 6 Certificate message round-trip test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 6 Certificate message round-trip test.");
		res = false;
	}

	if (tls_stage6_certificate_message_negative() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 6 Certificate message negative-path test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 6 Certificate message negative-path test.");
		res = false;
	}

	if (tls_stage6_certificate_request_roundtrip() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 6 CertificateRequest round-trip test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 6 CertificateRequest round-trip test.");
		res = false;
	}

	if (tls_stage6_certificate_request_negative() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 6 CertificateRequest negative-path test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 6 CertificateRequest negative-path test.");
		res = false;
	}

	if (tls_stage6_certificate_verify_roundtrip() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 6 CertificateVerify round-trip test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 6 CertificateVerify round-trip test.");
		res = false;
	}

	if (tls_stage6_certificate_verify_negative() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 6 CertificateVerify negative-path test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 6 CertificateVerify negative-path test.");
		res = false;
	}

	if (tls_stage6_certificate_peer_validation() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 6 certificate peer-validation callback test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 6 certificate peer-validation callback test.");
		res = false;
	}

	if (tls_stage6_certificate_verify_validation() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 6 certificate verify-validation callback test.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 6 certificate verify-validation callback test.");
		res = false;
	}

	return res;
}
