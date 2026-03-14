#include "x509verify.h"
#include "memutils.h"
#include "x509cert.h"
#include "x509name.h"
#include "x509sig.h"
#include "x509time.h"

static bool x509_time_is_zero(const qsc_asn1_time* time)
{
	bool res;

	res = false;

	if (time != (const qsc_asn1_time*)NULL)
	{
		res = (time->year == 0U &&
			time->month == 0U &&
			time->day == 0U &&
			time->hour == 0U &&
			time->minute == 0U &&
			time->second == 0U);
	}

	return res;
}

static qsc_x509_verify_status x509_check_certificate_minimal(const qsc_x509_certificate* certificate)
{
	qsc_x509_verify_status status;

	status = QSC_X509_VERIFY_STATUS_SUCCESS;

	if (certificate == (const qsc_x509_certificate*)NULL)
	{
		status = QSC_X509_VERIFY_STATUS_INVALID_INPUT;
	}
	else if (certificate->version < 1U || certificate->version > 3U)
	{
		status = QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE;
	}
	else if (certificate->serialnumberlen == 0U)
	{
		status = QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE;
	}
	else if (certificate->tbsdata == (const uint8_t*)NULL || certificate->tbsdatalen == 0U)
	{
		status = QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE;
	}
	else if (certificate->signaturelen == 0U)
	{
		status = QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE;
	}
	else if (certificate->subjectpublickeyinfo.publickeylen == 0U)
	{
		status = QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE;
	}

	return status;
}

static bool x509_key_identifier_matches(const qsc_x509_subject_key_identifier* ski, const qsc_x509_authority_key_identifier* aki)
{
	bool res;

	res = true;

	if (ski != (const qsc_x509_subject_key_identifier*)NULL &&
		aki != (const qsc_x509_authority_key_identifier*)NULL &&
		ski->present == true &&
		aki->present == true &&
		aki->keyidentifierlen != 0U)
	{
		if (ski->identifierlen != aki->keyidentifierlen)
		{
			res = false;
		}
		else
		{
			res = qsc_memutils_are_equal((uint8_t*)ski->identifier, (uint8_t*)aki->keyidentifier, ski->identifierlen);
		}
	}

	return res;
}

static bool x509_name_present(const qsc_x509_name* name)
{
	bool res;

	res = false;

	if (name != (const qsc_x509_name*)NULL)
	{
		res = (name->count != 0U);
	}

	return res;
}

static bool x509_usage_has_cert_sign(const qsc_x509_certificate* certificate)
{
	bool res;

	res = true;

	if (certificate != (const qsc_x509_certificate*)NULL &&
		certificate->extensions.keyusage.present == true)
	{
		res = ((certificate->extensions.keyusage.bits & QSC_X509_KEY_USAGE_KEY_CERT_SIGN) != 0U);
	}

	return res;
}

static size_t x509_count_non_self_issued_intermediates_below(const qsc_x509_chain* chain, size_t last_index_inclusive)
{
	size_t count;

	count = 0U;

	if (chain != (const qsc_x509_chain*)NULL &&
		chain->certificates != (const qsc_x509_certificate*)NULL)
	{
		/*
		 * chain->certificates[0] is the target certificate.
		 * pathLenConstraint counts only non-self-issued intermediate CA certificates
		 * that follow the current issuer, and therefore must not count the target.
		 */
		for (size_t i = 1U; i <= last_index_inclusive && i < chain->count; ++i)
		{
			const qsc_x509_certificate* certificate;

			certificate = &chain->certificates[i];

			if (qsc_x509_certificate_is_ca(certificate) == true &&
				qsc_x509_certificate_is_self_issued(certificate) == false)
			{
				count += 1U;
			}
		}
	}

	return count;
}

static bool x509_extension_is_verification_supported(qsc_x509_extension_type type)
{
	bool res;

	res = false;

	if (type == QSC_X509_EXTENSION_BASIC_CONSTRAINTS ||
		type == QSC_X509_EXTENSION_KEY_USAGE ||
		type == QSC_X509_EXTENSION_SUBJECT_KEY_IDENTIFIER ||
		type == QSC_X509_EXTENSION_AUTHORITY_KEY_IDENTIFIER)
	{
		res = true;
	}

	return res;
}

static qsc_x509_verify_status x509_check_critical_extensions(const qsc_x509_certificate* certificate)
{
	qsc_x509_verify_status status;

	status = QSC_X509_VERIFY_STATUS_SUCCESS;

	if (certificate == (const qsc_x509_certificate*)NULL)
	{
		status = QSC_X509_VERIFY_STATUS_INVALID_INPUT;
	}
	else
	{
		for (size_t i = 0U; i < certificate->extensions.count; ++i)
		{
			const qsc_x509_extension* extension;

			extension = &certificate->extensions.entries[i];

			if (extension->critical == true &&
				x509_extension_is_verification_supported(extension->type) == false)
			{
				status = QSC_X509_VERIFY_STATUS_UNSUPPORTED;
				break;
			}
		}
	}

	return status;
}

static qsc_x509_verify_status x509_authority_cert_issuer_matches(const qsc_x509_certificate* issuer, const qsc_x509_authority_key_identifier* aki)
{
	qsc_x509_verify_status status;

	status = QSC_X509_VERIFY_STATUS_SUCCESS;

	if (issuer != (const qsc_x509_certificate*)NULL &&
		aki != (const qsc_x509_authority_key_identifier*)NULL &&
		aki->present == true &&
		aki->issuer_present == true)
	{
		if (aki->issuername_present == false)
		{
			status = QSC_X509_VERIFY_STATUS_UNSUPPORTED;
		}
		else if (x509_name_present(&issuer->subject) == false || x509_name_present(&aki->issuername) == false)
		{
			status = QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE;
		}
		else if (qsc_x509_name_equals(&issuer->subject, &aki->issuername) == false)
		{
			status = QSC_X509_VERIFY_STATUS_ISSUER_MISMATCH;
		}
	}

	return status;
}

static bool x509_authority_serial_matches(const qsc_x509_certificate* issuer, const qsc_x509_authority_key_identifier* aki)
{
	const uint8_t* serial;
	size_t seriallen;
	size_t ofs;
	bool res;

	res = true;
	serial = (const uint8_t*)NULL;
	seriallen = 0U;
	ofs = 0U;

	if (issuer != (const qsc_x509_certificate*)NULL &&
		aki != (const qsc_x509_authority_key_identifier*)NULL &&
		aki->present == true &&
		aki->serial_present == true)
	{
		if (aki->seriallen == 0U)
		{
			res = false;
		}
		else if ((aki->serial[0U] & 0x80U) != 0U)
		{
			/*
			 * authorityCertSerialNumber must be non-negative.
			 */
			res = false;
		}
		else
		{
			/*
			 * Normalize the raw INTEGER content octets from the IMPLICIT [2] field.
			 * A leading 0x00 is allowed only when needed to keep the value positive.
			 */
			if (aki->seriallen > 1U && aki->serial[0U] == 0x00U)
			{
				if ((aki->serial[1U] & 0x80U) == 0U)
				{
					res = false;
				}
				else
				{
					ofs = 1U;
				}
			}

			if (res == true)
			{
				serial = aki->serial + ofs;
				seriallen = aki->seriallen - ofs;

				if (seriallen == 0U || issuer->serialnumberlen != seriallen)
				{
					res = false;
				}
				else
				{
					res = qsc_memutils_are_equal((uint8_t*)issuer->serialnumber, (uint8_t*)serial, issuer->serialnumberlen);
				}
			}
		}
	}

	return res;
}

static qsc_x509_verify_status x509_check_trust_anchor_match(const qsc_x509_trust_anchor* anchor, const qsc_x509_certificate* subject)
{
	qsc_x509_verify_status status;
	const qsc_x509_certificate* issuer;

	status = QSC_X509_VERIFY_STATUS_SUCCESS;
	issuer = (const qsc_x509_certificate*)NULL;

	if (anchor == (const qsc_x509_trust_anchor*)NULL || subject == (const qsc_x509_certificate*)NULL)
	{
		status = QSC_X509_VERIFY_STATUS_INVALID_INPUT;
	}
	else
	{
		issuer = &anchor->certificate;

		if (x509_name_present(&issuer->subject) == false || x509_name_present(&subject->issuer) == false)
		{
			status = QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE;
		}
		else if (qsc_x509_name_equals(&issuer->subject, &subject->issuer) == false)
		{
			status = QSC_X509_VERIFY_STATUS_ISSUER_MISMATCH;
		}
		else
		{
			status = x509_authority_cert_issuer_matches(issuer, &subject->extensions.authoritykeyidentifier);

			if (status == QSC_X509_VERIFY_STATUS_SUCCESS &&
				x509_key_identifier_matches(&issuer->extensions.subjectkeyidentifier, &subject->extensions.authoritykeyidentifier) == false)
			{
				status = QSC_X509_VERIFY_STATUS_KEY_IDENTIFIER_MISMATCH;
			}

			if (status == QSC_X509_VERIFY_STATUS_SUCCESS &&
				x509_authority_serial_matches(issuer, &subject->extensions.authoritykeyidentifier) == false)
			{
				status = QSC_X509_VERIFY_STATUS_KEY_IDENTIFIER_MISMATCH;
			}
		}
	}

	return status;
}

static qsc_x509_verify_status x509_check_trust_anchor_minimal(const qsc_x509_trust_anchor* anchor)
{
	const qsc_x509_certificate* certificate;
	qsc_x509_verify_status status;

	status = QSC_X509_VERIFY_STATUS_SUCCESS;
	certificate = (const qsc_x509_certificate*)NULL;

	if (anchor == (const qsc_x509_trust_anchor*)NULL)
	{
		status = QSC_X509_VERIFY_STATUS_INVALID_INPUT;
	}
	else
	{
		certificate = &anchor->certificate;

		if (x509_name_present(&certificate->subject) == false)
		{
			status = QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE;
		}
		else if (certificate->subjectpublickeyinfo.publickeylen == 0U)
		{
			status = QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE;
		}
	}

	return status;
}

bool qsc_x509_certificate_is_self_issued(const qsc_x509_certificate* certificate)
{
	QSC_ASSERT(certificate != NULL);

	bool res;

	res = false;

	if (certificate != (const qsc_x509_certificate*)NULL)
	{
		if (x509_name_present(&certificate->issuer) == true &&
			x509_name_present(&certificate->subject) == true)
		{
			res = qsc_x509_name_equals(&certificate->issuer, &certificate->subject);
		}
	}

	return res;
}

bool qsc_x509_certificate_is_self_signed(const qsc_x509_certificate* certificate, qsc_x509_signature_verify_callback callback, void* state)
{
	QSC_ASSERT(certificate != NULL);
	QSC_ASSERT(state != NULL);

	bool res;

	res = false;

	if (certificate != (const qsc_x509_certificate*)NULL && callback != (qsc_x509_signature_verify_callback)NULL)
	{
		if (qsc_x509_certificate_is_self_issued(certificate) == true &&
			qsc_x509_certificate_check_algorithms(certificate) == QSC_X509_VERIFY_STATUS_SUCCESS)
		{
			res = callback(certificate, certificate, state);
		}
	}

	return res;
}

bool qsc_x509_certificate_is_ca(const qsc_x509_certificate* certificate)
{
	QSC_ASSERT(certificate != NULL);

	bool res;

	res = false;

	if (certificate != (const qsc_x509_certificate*)NULL)
	{
		if (certificate->extensions.basicconstraints.present == true &&
			certificate->extensions.basicconstraints.ca == true)
		{
			res = true;

			if (certificate->extensions.keyusage.present == true)
			{
				res = ((certificate->extensions.keyusage.bits & QSC_X509_KEY_USAGE_KEY_CERT_SIGN) != 0U);
			}
		}
	}

	return res;
}

qsc_x509_verify_status qsc_x509_certificate_check_algorithms(const qsc_x509_certificate* certificate)
{
	QSC_ASSERT(certificate != NULL);

	qsc_x509_verify_status status;

	status = QSC_X509_VERIFY_STATUS_INVALID_INPUT;

	if (certificate != (const qsc_x509_certificate*)NULL)
	{
		status = x509_check_certificate_minimal(certificate);

		if (status == QSC_X509_VERIFY_STATUS_SUCCESS)
		{
			if (qsc_x509_signature_algorithm_equal(&certificate->tbsignature, &certificate->signaturealgorithm) == false)
			{
				status = QSC_X509_VERIFY_STATUS_ALGORITHM_MISMATCH;
			}
			else if (certificate->signaturealgorithm.signature == QSC_X509_SIGNATURE_ALGORITHM_NONE)
			{
				status = QSC_X509_VERIFY_STATUS_UNSUPPORTED;
			}
			else if (certificate->signatureunusedbits != 0U)
			{
				status = QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE;
			}
		}
	}

	return status;
}

qsc_x509_verify_status qsc_x509_certificate_check_validity(const qsc_x509_certificate* certificate, const qsc_asn1_time* now)
{
	qsc_x509_verify_status status;
	int32_t cmpnb;
	int32_t cmpna;

	status = x509_check_certificate_minimal(certificate);
	cmpnb = 0;
	cmpna = 0;

	if (status == QSC_X509_VERIFY_STATUS_SUCCESS)
	{
		if (now == (const qsc_asn1_time*)NULL || x509_time_is_zero(now) == true)
		{
			status = QSC_X509_VERIFY_STATUS_INVALID_INPUT;
		}
		else
		{
			cmpnb = qsc_x509_time_compare(now, &certificate->validity.notbefore);
			cmpna = qsc_x509_time_compare(now, &certificate->validity.notafter);

			if (cmpnb < 0)
			{
				status = QSC_X509_VERIFY_STATUS_NOT_YET_VALID;
			}
			else if (cmpna > 0)
			{
				status = QSC_X509_VERIFY_STATUS_EXPIRED;
			}
		}
	}

	return status;
}

qsc_x509_verify_status qsc_x509_certificate_check_issuer(const qsc_x509_certificate* issuer, const qsc_x509_certificate* subject, size_t remainingdepth)
{
	qsc_x509_verify_status status;

	status = QSC_X509_VERIFY_STATUS_SUCCESS;

	if (issuer == (const qsc_x509_certificate*)NULL || subject == (const qsc_x509_certificate*)NULL)
	{
		status = QSC_X509_VERIFY_STATUS_INVALID_INPUT;
	}
	else if (x509_name_present(&issuer->subject) == false || x509_name_present(&subject->issuer) == false)
	{
		status = QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE;
	}
	else if (qsc_x509_name_equals(&issuer->subject, &subject->issuer) == false)
	{
		status = QSC_X509_VERIFY_STATUS_ISSUER_MISMATCH;
	}
	else
	{
		status = x509_authority_cert_issuer_matches(issuer, &subject->extensions.authoritykeyidentifier);

		if (status == QSC_X509_VERIFY_STATUS_SUCCESS &&
			x509_key_identifier_matches(&issuer->extensions.subjectkeyidentifier, &subject->extensions.authoritykeyidentifier) == false)
		{
			status = QSC_X509_VERIFY_STATUS_KEY_IDENTIFIER_MISMATCH;
		}

		if (status == QSC_X509_VERIFY_STATUS_SUCCESS &&
			x509_authority_serial_matches(issuer, &subject->extensions.authoritykeyidentifier) == false)
		{
			status = QSC_X509_VERIFY_STATUS_KEY_IDENTIFIER_MISMATCH;
		}

		if (status == QSC_X509_VERIFY_STATUS_SUCCESS &&
			qsc_x509_certificate_is_ca(issuer) == false)
		{
			status = QSC_X509_VERIFY_STATUS_NOT_CA;
		}

		if (status == QSC_X509_VERIFY_STATUS_SUCCESS &&
			x509_usage_has_cert_sign(issuer) == false)
		{
			status = QSC_X509_VERIFY_STATUS_KEY_USAGE_REJECTED;
		}

		if (status == QSC_X509_VERIFY_STATUS_SUCCESS &&
			issuer->extensions.basicconstraints.present == true &&
			issuer->extensions.basicconstraints.pathlen_present == true &&
			remainingdepth > issuer->extensions.basicconstraints.pathlen)
		{
			status = QSC_X509_VERIFY_STATUS_PATH_LENGTH_EXCEEDED;
		}
	}

	return status;
}

qsc_x509_verify_status qsc_x509_certificate_verify(const qsc_x509_certificate* certificate, const qsc_x509_certificate* issuer, const qsc_asn1_time* now, qsc_x509_signature_verify_callback callback, void* state)
{
	qsc_x509_verify_status status;

	status = QSC_X509_VERIFY_STATUS_SUCCESS;

	if (callback == (qsc_x509_signature_verify_callback)NULL)
	{
		status = QSC_X509_VERIFY_STATUS_INVALID_INPUT;
	}
	else
	{
		status = x509_check_certificate_minimal(certificate);

		if (status == QSC_X509_VERIFY_STATUS_SUCCESS)
		{
			status = x509_check_certificate_minimal(issuer);
		}

		if (status == QSC_X509_VERIFY_STATUS_SUCCESS)
		{
			status = qsc_x509_certificate_check_algorithms(certificate);
		}

		if (status == QSC_X509_VERIFY_STATUS_SUCCESS)
		{
			status = qsc_x509_certificate_check_algorithms(issuer);
		}

		if (status == QSC_X509_VERIFY_STATUS_SUCCESS)
		{
			status = qsc_x509_certificate_check_validity(certificate, now);
		}

		if (status == QSC_X509_VERIFY_STATUS_SUCCESS)
		{
			status = qsc_x509_certificate_check_validity(issuer, now);
		}

		if (status == QSC_X509_VERIFY_STATUS_SUCCESS)
		{
			status = x509_check_critical_extensions(certificate);
		}

		if (status == QSC_X509_VERIFY_STATUS_SUCCESS)
		{
			status = x509_check_critical_extensions(issuer);
		}

		if (status == QSC_X509_VERIFY_STATUS_SUCCESS)
		{
			status = qsc_x509_certificate_check_issuer(issuer, certificate, 0U);
		}

		if (status == QSC_X509_VERIFY_STATUS_SUCCESS)
		{
			if (callback(certificate, issuer, state) == false)
			{
				status = QSC_X509_VERIFY_STATUS_SIGNATURE_REJECTED;
			}
		}
	}

	return status;
}

qsc_x509_verify_status qsc_x509_chain_verify(const qsc_x509_chain* chain, const qsc_x509_store* store, const qsc_asn1_time* now, qsc_x509_signature_verify_callback callback, void* state)
{
	qsc_x509_verify_status status;
	const qsc_x509_certificate* subject;
	const qsc_x509_certificate* issuer;
	const qsc_x509_certificate* anchor;
	bool anchorfound;

	status = QSC_X509_VERIFY_STATUS_SUCCESS;
	subject = (const qsc_x509_certificate*)NULL;
	issuer = (const qsc_x509_certificate*)NULL;
	anchor = (const qsc_x509_certificate*)NULL;
	anchorfound = false;

	if (chain == (const qsc_x509_chain*)NULL ||
		store == (const qsc_x509_store*)NULL ||
		now == (const qsc_asn1_time*)NULL ||
		callback == (qsc_x509_signature_verify_callback)NULL)
	{
		status = QSC_X509_VERIFY_STATUS_INVALID_INPUT;
	}
	else if (chain->certificates == (qsc_x509_certificate*)NULL || chain->count == 0U)
	{
		status = QSC_X509_VERIFY_STATUS_INVALID_INPUT;
	}
	else if (store->anchors == (qsc_x509_trust_anchor*)NULL || store->count == 0U)
	{
		status = QSC_X509_VERIFY_STATUS_INVALID_INPUT;
	}
	else
	{
		for (size_t i = 0U; i < chain->count; ++i)
		{
			status = qsc_x509_certificate_check_algorithms(&chain->certificates[i]);

			if (status != QSC_X509_VERIFY_STATUS_SUCCESS)
			{
				break;
			}

			status = qsc_x509_certificate_check_validity(&chain->certificates[i], now);

			if (status != QSC_X509_VERIFY_STATUS_SUCCESS)
			{
				break;
			}

			status = x509_check_critical_extensions(&chain->certificates[i]);

			if (status != QSC_X509_VERIFY_STATUS_SUCCESS)
			{
				break;
			}
		}

		for (size_t i = 0U; status == QSC_X509_VERIFY_STATUS_SUCCESS && (i + 1U) < chain->count; ++i)
		{
			size_t remainingdepth;

			subject = &chain->certificates[i];
			issuer = &chain->certificates[i + 1U];
			remainingdepth = x509_count_non_self_issued_intermediates_below(chain, i);

			status = qsc_x509_certificate_check_issuer(issuer, subject, remainingdepth);

			if (status == QSC_X509_VERIFY_STATUS_SUCCESS)
			{
				if (callback(subject, issuer, state) == false)
				{
					status = QSC_X509_VERIFY_STATUS_SIGNATURE_REJECTED;
				}
			}
		}

		if (status == QSC_X509_VERIFY_STATUS_SUCCESS)
		{
			subject = &chain->certificates[chain->count - 1U];

			for (size_t i = 0U; i < store->count; ++i)
			{
				const qsc_x509_trust_anchor* trustanchor;

				trustanchor = &store->anchors[i];
				anchor = &trustanchor->certificate;

				status = x509_check_trust_anchor_minimal(trustanchor);

				if (status != QSC_X509_VERIFY_STATUS_SUCCESS)
				{
					continue;
				}

				status = x509_check_trust_anchor_match(trustanchor, subject);

				if (status != QSC_X509_VERIFY_STATUS_SUCCESS)
				{
					continue;
				}

				if (callback(subject, anchor, state) == true)
				{
					anchorfound = true;
					status = QSC_X509_VERIFY_STATUS_SUCCESS;
					break;
				}
			}

			if (anchorfound == false)
			{
				status = QSC_X509_VERIFY_STATUS_TRUST_NOT_FOUND;
			}
		}
	}

	return status;
}
