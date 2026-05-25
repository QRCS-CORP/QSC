#include "tlscert.h"
#include "memutils.h"
#include "tlsalert.h"
#include "tlscodec.h"
#include "tlslimits.h"
#include "tlssigalgs.h"
#include "x509cert.h"
#include "x509host.h"
#include "x509sig.h"
#include "x509sigver.h"
#include "x509spki.h"
#include "x509verify.h"

#define QSC_TLS_X509_CHAIN_MAX 8U

typedef struct qsc_tls_qsc_x509_local_state
{
	qsc_x509_verify_state verifystate;
	uint8_t localbuffer[QSC_X509_CERTIFICATE_WRITE_MAX];
} qsc_tls_qsc_x509_local_state;

static qsc_x509_verify_purpose tls_x509_purpose_from_context(const qsc_tls_certificate_validation_context* context)
{
	qsc_x509_verify_purpose res;

	res = QSC_X509_VERIFY_PURPOSE_TLS_SERVER;

	if (context != NULL && context->clientauth == true)
	{
		res = QSC_X509_VERIFY_PURPOSE_TLS_CLIENT;
	}

	return res;
}

static void tls_x509_store_result(qsc_tls_qsc_x509_context* context, qsc_x509_verify_status status)
{
	if (context != NULL)
	{
		context->lastverifystatus = status;
		context->lastalert = qsc_tls_x509_alert_from_verify_status(status);
	}
}

static qsc_tls_status tls_x509_decode_chain(const qsc_tls_certificate_view* chain, size_t chainlength, qsc_x509_certificate* output, size_t outputcount)
{
	qsc_tls_status status;
	size_t i;
	qsc_asn1_status xstatus;

	status = qsc_tls_status_success;
	i = 0U;
	xstatus = QSC_ASN1_STATUS_SUCCESS;

	if ((chain == NULL && chainlength != 0U) || output == NULL || outputcount == 0U || chainlength > outputcount)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		while (status == qsc_tls_status_success && i < chainlength)
		{
			if (chain[i].data == NULL || chain[i].datalen == 0U)
			{
				status = qsc_tls_status_invalid_input;
			}
			else
			{
				xstatus = qsc_x509_certificate_decode_der(chain[i].data, chain[i].datalen, &output[i]);
				if (xstatus != QSC_ASN1_STATUS_SUCCESS)
				{
					status = qsc_tls_status_failure;
				}
			}

			++i;
		}
	}

	return status;
}

static bool tls_x509_certificate_verify_inputs_are_valid(qsc_tls_signature_scheme scheme, size_t signaturelen, const qsc_x509_certificate* certificate, qsc_x509_signature_algorithm sigalg)
{
	bool res;

	res = false;

	if (certificate != NULL && sigalg != QSC_X509_SIGNATURE_ALGORITHM_NONE && 
		qsc_tls_signature_scheme_validate_signature_length(scheme, signaturelen) == true)
	{
		res = qsc_x509_signature_algorithm_matches_spki(sigalg, &certificate->subjectpublickeyinfo);

		if (res == true && qsc_x509_signature_algorithm_is_ml_dsa(sigalg) == true)
		{
			size_t exppk;

			exppk = qsc_x509_pqc_public_key_size(certificate->subjectpublickeyinfo.algorithm.pqcparameter);
			res = (exppk != 0U && certificate->subjectpublickeyinfo.publickeylen == exppk);
		}
	}

	return res;
}

qsc_tls_status qsc_tls_certificate_encode_message(const uint8_t* requestcontext, size_t requestcontextlen, const qsc_tls_certificate_view* chain,
	size_t chainlength, uint8_t* output, size_t outlen, size_t* offset)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(offset != NULL);

	size_t listhdr;
	size_t i;
	size_t empty;
	qsc_tls_status status;

	if (output != NULL && offset != NULL)
	{
		if (requestcontextlen <= 0xFFU)
		{
			if (chainlength <= QSC_TLS_CERTIFICATE_LIST_MAX_ENTRIES)
			{
				/* certificate_request_context */
				status = qsc_tls_codec_write_vector8(output, outlen, offset, requestcontextlen == 0U ? (const uint8_t*)"" : requestcontext, requestcontextlen);

				if (status == qsc_tls_status_success)
				{
					/* certificate_list outer vector24 */
					status = qsc_tls_codec_vector_begin_u24(output, outlen, offset, &listhdr);

					if (status == qsc_tls_status_success)
					{
						for (i = 0U; i < chainlength && status == qsc_tls_status_success; ++i)
						{
							const qsc_tls_certificate_view* e = &chain[i];

							if (e->data == NULL || e->datalen == 0U || e->datalen > QSC_TLS_CERTIFICATE_MAX_SIZE)
							{
								status = qsc_tls_status_invalid_length;
								break;
							}

							/* cert_data<1..2^24-1> */
							status = qsc_tls_codec_write_vector24(output, outlen, offset, e->data, e->datalen);

							if (status != qsc_tls_status_success)
							{
								break;
							}

							/* empty per-entry extensions<0..2^16-1> */
							status = qsc_tls_codec_vector_begin_u16(output, outlen, offset, &empty);

							if (status != qsc_tls_status_success)
							{
								break;
							}

							status = qsc_tls_codec_vector_end_u16(output, outlen, offset, empty);
						}

						if (status == qsc_tls_status_success)
						{
							status = qsc_tls_codec_vector_end_u24(output, outlen, offset, listhdr);
						}
					}
				}
			}
			else
			{
				status = qsc_tls_status_invalid_length;
			}
		}
		else
		{
			status = qsc_tls_status_invalid_length;
		}
	}
	else
	{
		status = qsc_tls_status_invalid_input;
	}

	return status;
}

qsc_tls_status qsc_tls_certificate_decode_message(const uint8_t* input, size_t inlen, const uint8_t** requestcontext, size_t* requestcontextlen,
	qsc_tls_certificate_view* chain, size_t chaincapacity, size_t* chainlength)
{
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(requestcontext != NULL);
	QSC_ASSERT(requestcontextlen != NULL);
	QSC_ASSERT(chainlength != NULL);

	const uint8_t* ctx;
	const uint8_t* list;
	size_t ctxlen;
	size_t listlen;
	size_t inner;
	size_t n;
	size_t off;
	qsc_tls_status status;

	if (input != NULL && requestcontext != NULL && requestcontextlen != NULL && chainlength != NULL)
	{
		*requestcontext = NULL;
		*requestcontextlen = 0U;
		*chainlength = 0U;

		off = 0U;
		status = qsc_tls_codec_read_vector8_span(input, inlen, &off, &ctx, &ctxlen);

		if (status == qsc_tls_status_success)
		{
			*requestcontext = ctx;
			*requestcontextlen = ctxlen;

			status = qsc_tls_codec_read_vector24_span(input, inlen, &off, &list, &listlen);

			if (status == qsc_tls_status_success)
			{
				if (off == inlen)
				{
					inner = 0U;
					n = 0U;

					while (inner < listlen)
					{
						const uint8_t* certdata;
						const uint8_t* extspan;
						size_t certdatalen;
						size_t extspanlen;

						status = qsc_tls_codec_read_vector24_span(list, listlen, &inner, &certdata, &certdatalen);

						if (status != qsc_tls_status_success)
						{
							return status;
						}

						if (certdatalen == 0U)
						{
							return qsc_tls_status_invalid_length;
						}

						status = qsc_tls_codec_read_vector16_span(list, listlen, &inner, &extspan, &extspanlen);

						if (status != qsc_tls_status_success)
						{
							return status;
						}

						(void)extspan;
						(void)extspanlen;

						if (n >= chaincapacity) { return qsc_tls_status_invalid_length; }
						chain[n].data = certdata;
						chain[n].datalen = certdatalen;
						n += 1U;
					}

					if (inner != listlen)
					{
						return qsc_tls_status_invalid_length;
					}

					*chainlength = n;
					status = qsc_tls_status_success;
				}
				else
				{
					status = qsc_tls_status_invalid_length;
				}
			}
		}
	}
	else
	{
		status = qsc_tls_status_invalid_input;
	}

	return status;
}

void qsc_tls_certificate_interface_initialize(qsc_tls_certificate_interface* iface, qsc_tls_certificate_chain_validate_callback validatechain, qsc_tls_certificate_verify_callback verifycertificateverify, void* state)
{
	QSC_ASSERT(iface != NULL);

	if (iface != NULL)
	{
		iface->validatechain = validatechain;
		iface->verifycertificateverify = verifycertificateverify;
		iface->state = state;
	}
}

bool qsc_tls_certificate_interface_is_valid(const qsc_tls_certificate_interface* iface)
{
	QSC_ASSERT(iface != NULL);

	bool res;

	res = false;

	if (iface != NULL)
	{
		res = (iface->validatechain != NULL && iface->verifycertificateverify != NULL);
	}

	return res;
}

qsc_tls_alert_description qsc_tls_x509_alert_from_verify_status(qsc_x509_verify_status status)
{
	qsc_tls_alert_description alert;

	alert = qsc_tls_alert_bad_certificate;

	switch (status)
	{
		case QSC_X509_VERIFY_STATUS_SUCCESS:
		{
			alert = qsc_tls_alert_close_notify;
			break;
		}
		case QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE:
		case QSC_X509_VERIFY_STATUS_ALGORITHM_MISMATCH:
		case QSC_X509_VERIFY_STATUS_SIGNATURE_REJECTED:
		{
			alert = qsc_tls_alert_bad_certificate;
			break;
		}
		case QSC_X509_VERIFY_STATUS_EXPIRED:
		case QSC_X509_VERIFY_STATUS_NOT_YET_VALID:
		{
			alert = qsc_tls_alert_certificate_expired;
			break;
		}
		case QSC_X509_VERIFY_STATUS_ISSUER_MISMATCH:
		case QSC_X509_VERIFY_STATUS_KEY_IDENTIFIER_MISMATCH:
		case QSC_X509_VERIFY_STATUS_TRUST_NOT_FOUND:
		{
			alert = qsc_tls_alert_unknown_ca;
			break;
		}
		case QSC_X509_VERIFY_STATUS_NOT_CA:
		case QSC_X509_VERIFY_STATUS_PATH_LENGTH_EXCEEDED:
		case QSC_X509_VERIFY_STATUS_CHAIN_LOOP:
		{
			alert = qsc_tls_alert_bad_certificate;
			break;
		}
		case QSC_X509_VERIFY_STATUS_KEY_USAGE_REJECTED:
		case QSC_X509_VERIFY_STATUS_PURPOSE_REJECTED:
		{
			alert = qsc_tls_alert_access_denied;
			break;
		}
		case QSC_X509_VERIFY_STATUS_UNSUPPORTED:
		case QSC_X509_VERIFY_STATUS_UNSUPPORTED_CRITICAL_EXTENSION:
		{
			alert = qsc_tls_alert_unsupported_certificate;
			break;
		}
		case QSC_X509_VERIFY_STATUS_REVOKED:
		{
			alert = qsc_tls_alert_certificate_revoked;
			break;
		}
		case QSC_X509_VERIFY_STATUS_REVOCATION_UNKNOWN:
		{
			alert = qsc_tls_alert_certificate_unknown;
			break;
		}
		case QSC_X509_VERIFY_STATUS_NAME_MISMATCH:
		{
			alert = qsc_tls_alert_bad_certificate;
			break;
		}
		case QSC_X509_VERIFY_STATUS_INVALID_INPUT:
		case QSC_X509_VERIFY_STATUS_CALLBACK_FAILURE:
		default:
		{
			alert = qsc_tls_alert_internal_error;
			break;
		}
	}

	return alert;
}

qsc_tls_alert_description qsc_tls_certificate_interface_get_last_alert(const qsc_tls_certificate_interface* iface, bool verifyphase)
{
	QSC_ASSERT(iface != NULL);

	qsc_tls_alert_description alert;

	alert = (verifyphase == true) ? qsc_tls_alert_decrypt_error : qsc_tls_alert_bad_certificate;

	if (iface != NULL && iface->state != NULL)
	{
		if ((verifyphase == false && iface->validatechain == qsc_tls_x509_validate_chain) ||
			(verifyphase == true && iface->verifycertificateverify == qsc_tls_x509_verify_certificate_verify))
		{
			const qsc_tls_qsc_x509_context* xctx;

			xctx = (const qsc_tls_qsc_x509_context*)iface->state;
			alert = xctx->lastalert;

			if (alert == qsc_tls_alert_close_notify)
			{
				alert = (verifyphase == true) ? qsc_tls_alert_decrypt_error : qsc_tls_alert_bad_certificate;
			}
		}
	}

	return alert;
}

qsc_tls_status qsc_tls_certificate_interface_initialize_qsc_x509(qsc_tls_certificate_interface* iface, qsc_tls_qsc_x509_context* context)
{
	QSC_ASSERT(context != NULL);
	QSC_ASSERT(iface != NULL);

	qsc_tls_status status;

	status = qsc_tls_status_invalid_input;

	if (iface != NULL && context != NULL && context->truststore != NULL && context->validationtime != NULL)
	{
		qsc_tls_certificate_interface_initialize(iface, qsc_tls_x509_validate_chain, qsc_tls_x509_verify_certificate_verify, context);
		status = qsc_tls_status_success;
	}

	return status;
}

qsc_tls_status qsc_tls_certificate_request_decode(const uint8_t* input, size_t inlen, const uint8_t** requestcontext, size_t* requestcontextlen,
	const uint8_t** extensionsblock, size_t* extensionsblocklen)
{
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(requestcontext != NULL);
	QSC_ASSERT(requestcontextlen != NULL);
	QSC_ASSERT(extensionsblock != NULL);
	QSC_ASSERT(extensionsblocklen != NULL);

	size_t off;
	qsc_tls_status status;

	if (input != NULL && requestcontext != NULL && requestcontextlen != NULL && extensionsblock != NULL && extensionsblocklen != NULL)
	{
		*requestcontext = NULL;
		*requestcontextlen = 0U;
		*extensionsblock = NULL;
		*extensionsblocklen = 0U;

		off = 0U;
		status = qsc_tls_codec_read_vector8_span(input, inlen, &off, requestcontext, requestcontextlen);

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_read_vector16_span(input, inlen, &off, extensionsblock, extensionsblocklen);

			if (status == qsc_tls_status_success)
			{
				if (off != inlen)
				{
					status = qsc_tls_status_invalid_length;
				}
			}
		}
	}
	else
	{
		status = qsc_tls_status_invalid_input;
	}

	return status;
}

qsc_tls_status qsc_tls_certificate_request_encode(const uint8_t* requestcontext, size_t requestcontextlen, const uint8_t* extensionsblock,
	size_t extensionsblocklen, uint8_t* output, size_t outlen, size_t* offset)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(offset != NULL);

	qsc_tls_status status;

	if (output != NULL && offset != NULL)
	{
		if (requestcontextlen <= 0xFFU)
		{
			if (extensionsblock != NULL && extensionsblocklen != 0U)
			{
				status = qsc_tls_codec_write_vector8(output, outlen, offset, requestcontextlen == 0U ? (const uint8_t*)"" : requestcontext, requestcontextlen);

				if (status == qsc_tls_status_success)
				{
					status = qsc_tls_codec_write_vector16(output, outlen, offset, extensionsblock, extensionsblocklen);
				}
			}
			else
			{
				status = qsc_tls_status_invalid_input;
			}
		}
		else
		{
			status = qsc_tls_status_invalid_length;
		}
	}
	else
	{
		status = qsc_tls_status_invalid_input;
	}

	return status;
}

qsc_tls_status qsc_tls_x509_context_initialize(qsc_tls_qsc_x509_context* context, const qsc_x509_store* truststore, const qsc_x509_certificate* intermediates, 
	size_t intermediatecount, const qsc_x509_time* validationtime, uint8_t* verifybuffer, size_t verifybufferlen)
{
	QSC_ASSERT(context != NULL);

	qsc_tls_status status;

	status = qsc_tls_status_invalid_input;

	if (context != NULL)
	{
		context->truststore = truststore;
		context->intermediates = intermediates;
		context->intermediatecount = intermediatecount;
		context->validationtime = validationtime;
		context->verifybuffer = verifybuffer;
		context->verifybufferlen = verifybufferlen;
		context->rejectunsupportedcriticalextensions = true;
		context->lastverifystatus = QSC_X509_VERIFY_STATUS_INVALID_INPUT;
		context->lastalert = qsc_tls_alert_internal_error;

		status = qsc_tls_status_success;
	}

	return status;
}

qsc_x509_signature_algorithm qsc_tls_x509_signature_algorithm_from_tls(qsc_tls_signature_scheme scheme)
{
	return qsc_tls_signature_scheme_x509_algorithm(scheme);
}

bool qsc_tls_x509_verify_certificate_verify(qsc_tls_signature_scheme scheme, const uint8_t* input, size_t inputlen, const uint8_t* signature, 
	size_t signaturelen, const qsc_tls_certificate_view* signer, void* state)
{
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(signature != NULL);
	QSC_ASSERT(signer != NULL);

	qsc_tls_qsc_x509_local_state localstate = { 0 };
	qsc_x509_certificate certificate = { 0 };
	qsc_tls_qsc_x509_context* xctx;
	qsc_x509_signature_algorithm sigalg;
	qsc_asn1_status xstatus;
	bool res;

	xstatus = QSC_ASN1_STATUS_SUCCESS;
	res = false;
	xctx = (qsc_tls_qsc_x509_context*)state;
	tls_x509_store_result(xctx, QSC_X509_VERIFY_STATUS_SUCCESS);
	sigalg = qsc_tls_x509_signature_algorithm_from_tls(scheme);

	if (xctx != NULL && signer != NULL && signer->data != NULL && signer->datalen != 0U && input != NULL && 
		inputlen != 0U && signature != NULL && signaturelen != 0U && sigalg != QSC_X509_SIGNATURE_ALGORITHM_NONE)
	{
		xstatus = qsc_x509_certificate_decode_der(signer->data, signer->datalen, &certificate);

		if (xstatus == QSC_ASN1_STATUS_SUCCESS && tls_x509_certificate_verify_inputs_are_valid(scheme, signaturelen, &certificate, sigalg) == true)
		{
			if (xctx->verifybuffer != NULL && xctx->verifybufferlen != 0U)
			{
				qsc_x509_verify_state verifystate;

				qsc_x509_qsc_verify_state_initialize(&verifystate, xctx->verifybuffer, xctx->verifybufferlen);
				res = qsc_x509_qsc_verify_signed_data(input, inputlen, signature, signaturelen, 0U, sigalg, &certificate.subjectpublickeyinfo, &verifystate);
			}
			else
			{
				qsc_x509_qsc_verify_state_initialize(&localstate.verifystate, localstate.localbuffer, sizeof(localstate.localbuffer));
				res = qsc_x509_qsc_verify_signed_data(input, inputlen, signature, signaturelen, 0U, sigalg, &certificate.subjectpublickeyinfo, &localstate.verifystate);
			}

			tls_x509_store_result(xctx, (res == true) ? QSC_X509_VERIFY_STATUS_SUCCESS : QSC_X509_VERIFY_STATUS_SIGNATURE_REJECTED);
		}
		else
		{
			tls_x509_store_result(xctx, (xstatus == QSC_ASN1_STATUS_SUCCESS) ? QSC_X509_VERIFY_STATUS_ALGORITHM_MISMATCH : QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE);
		}
	}

	return res;
}

bool qsc_tls_x509_validate_chain(const qsc_tls_certificate_view* chain, size_t chainlength, const qsc_tls_certificate_validation_context* context, void* state)
{
	QSC_ASSERT(chain != NULL);
	QSC_ASSERT(context != NULL);

	qsc_x509_certificate* decoded;
	qsc_x509_certificate* built;
	qsc_tls_qsc_x509_context* xctx;
	qsc_tls_qsc_x509_local_state localstate = { 0 };
	qsc_x509_chain builtchain = { 0 };
	qsc_x509_verify_options options = { 0 };
	qsc_x509_verify_status vstatus;
	qsc_tls_status status;
	bool res;

	decoded = (qsc_x509_certificate*)NULL;
	built = (qsc_x509_certificate*)NULL;
	qsc_x509_verify_options_initialize(&options);
	vstatus = QSC_X509_VERIFY_STATUS_INVALID_INPUT;
	status = qsc_tls_status_success;
	res = false;
	xctx = (qsc_tls_qsc_x509_context*)state;

	if (xctx == NULL || chain == NULL || chainlength == 0U || chainlength > QSC_TLS_X509_CHAIN_MAX || xctx->truststore == NULL || xctx->validationtime == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		decoded = (qsc_x509_certificate*)qsc_memutils_malloc(sizeof(qsc_x509_certificate) * QSC_TLS_X509_CHAIN_MAX);
		built = (qsc_x509_certificate*)qsc_memutils_malloc(sizeof(qsc_x509_certificate) * QSC_TLS_X509_CHAIN_MAX);

		if (decoded == (qsc_x509_certificate*)NULL || built == (qsc_x509_certificate*)NULL)
		{
			status = qsc_tls_status_failure;
		}
		else
		{
			qsc_memutils_clear(decoded, sizeof(qsc_x509_certificate) * QSC_TLS_X509_CHAIN_MAX);
			qsc_memutils_clear(built, sizeof(qsc_x509_certificate) * QSC_TLS_X509_CHAIN_MAX);
			status = tls_x509_decode_chain(chain, chainlength, decoded, QSC_TLS_X509_CHAIN_MAX);
		}
	}

	if (status == qsc_tls_status_success)
	{
		qsc_x509_chain_build(&decoded[0], (chainlength > 1U) ? &decoded[1] : xctx->intermediates,
			(chainlength > 1U) ? (chainlength - 1U) : xctx->intermediatecount, xctx->truststore, built, QSC_TLS_X509_CHAIN_MAX, &builtchain);
		
		options.purpose = tls_x509_purpose_from_context(context);
		options.rejectunsupportedcriticalextensions = xctx->rejectunsupportedcriticalextensions;

		if (xctx->verifybuffer != NULL && xctx->verifybufferlen != 0U)
		{
			qsc_x509_verify_state verifystate;
			
			qsc_x509_qsc_verify_state_initialize(&verifystate, xctx->verifybuffer, xctx->verifybufferlen);
			
			vstatus = qsc_x509_chain_verify_ex(&builtchain, xctx->truststore, xctx->validationtime,
				qsc_x509_qsc_signature_verify, &verifystate, &options);
		}
		else
		{
			qsc_x509_qsc_verify_state_initialize(&localstate.verifystate, localstate.localbuffer, sizeof(localstate.localbuffer));
			
			vstatus = qsc_x509_chain_verify_ex(&builtchain, xctx->truststore, xctx->validationtime,
				qsc_x509_qsc_signature_verify, &localstate.verifystate, &options);
		}
	}

	if (status == qsc_tls_status_success && vstatus == QSC_X509_VERIFY_STATUS_SUCCESS && context != NULL && context->hostname != NULL)
	{
		vstatus = qsc_x509_certificate_check_hostname(&builtchain.certificates[0], context->hostname);
	}

	if (status != qsc_tls_status_success)
	{
		vstatus = QSC_X509_VERIFY_STATUS_INVALID_INPUT;
	}

	tls_x509_store_result(xctx, vstatus);

	if (status == qsc_tls_status_success && vstatus == QSC_X509_VERIFY_STATUS_SUCCESS)
	{
		res = true;
	}

	if (decoded != (qsc_x509_certificate*)NULL)
	{
		for (size_t i = 0U; i < chainlength && i < QSC_TLS_X509_CHAIN_MAX; ++i)
		{
			qsc_x509_certificate_clear(&decoded[i]);
		}

		qsc_memutils_alloc_free(decoded);
	}

	if (built != (qsc_x509_certificate*)NULL)
	{
		qsc_memutils_alloc_free(built);
	}

	return res;
}
