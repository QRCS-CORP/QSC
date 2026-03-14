#include "x509sig.h"
#include "encoding.h"
#include "memutils.h"
#include "x509spki.h"

static void x509_signature_initialize(qsc_x509_ecdsa_signature* signature)
{
	qsc_memutils_clear((uint8_t*)signature, sizeof(qsc_x509_ecdsa_signature));
}

static bool x509_algorithm_identifier_parameters_equal(const qsc_x509_algorithm_identifier* left, const qsc_x509_algorithm_identifier* right)
{
	bool res;

	res = false;

	if (left->parameters_present == right->parameters_present &&
		left->parameters_null == right->parameters_null &&
		left->parameters_oid == right->parameters_oid &&
		left->curve == right->curve)
	{
		if (left->parameters_oid == true)
		{
			res = (qsc_asn1_oid_compare(&left->parameter_oid, &right->parameter_oid) == true);
		}
		else
		{
			res = true;
		}
	}

	return res;
}

static qsc_asn1_status x509_integer_to_fixed_width(const qsc_encoding_ber_element* element, uint8_t* output, size_t outlen)
{
	qsc_asn1_status status;
	size_t ofs;
	size_t ilen;
	size_t nzpos;

	status = QSC_ASN1_STATUS_FAILURE;
	ofs = 0U;
	ilen = 0U;
	nzpos = 0U;

	if (element == (const qsc_encoding_ber_element*)NULL || output == (uint8_t*)NULL || outlen == 0U)
	{
		status = QSC_ASN1_STATUS_INVALID_INPUT;
	}
	else if (qsc_asn1_is_integer(element) == false)
	{
		status = QSC_ASN1_STATUS_INVALID_TAG;
	}
	else if (element->length == 0U || element->value == (uint8_t*)NULL)
	{
		status = QSC_ASN1_STATUS_INVALID_LENGTH;
	}
	else if ((element->value[0U] & 0x80U) != 0U)
	{
		status = QSC_ASN1_STATUS_INVALID_ENCODING;
	}
	else
	{
		qsc_memutils_clear(output, outlen);

		/* Strip a single DER sign-protection zero if present. */
		if (element->length > 1U && element->value[0U] == 0x00U && (element->value[1U] & 0x80U) != 0U)
		{
			nzpos = 1U;
		}

		ilen = element->length - nzpos;

		if (ilen > outlen)
		{
			status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
		}
		else
		{
			ofs = outlen - ilen;
			qsc_memutils_copy(output + ofs, element->value + nzpos, ilen);
			status = QSC_ASN1_STATUS_SUCCESS;
		}
	}

	return status;
}

qsc_asn1_status qsc_x509_signature_algorithm_decode(const qsc_encoding_ber_element* element, qsc_x509_algorithm_identifier* algorithm)
{
	QSC_ASSERT(element != NULL);
	QSC_ASSERT(algorithm != NULL);

	qsc_asn1_status status;

	status = QSC_ASN1_STATUS_FAILURE;

	if (element != NULL && algorithm != NULL)
	{
		status = qsc_x509_algorithm_identifier_decode(element, algorithm);
	}

	return status;
}

bool qsc_x509_signature_algorithm_equal(const qsc_x509_algorithm_identifier* left, const qsc_x509_algorithm_identifier* right)
{
	QSC_ASSERT(left != NULL);
	QSC_ASSERT(right != NULL);

	bool res;

	res = false;

	if (left != (const qsc_x509_algorithm_identifier*)NULL && right != (const qsc_x509_algorithm_identifier*)NULL)
	{
		if (left->oid == right->oid &&
			left->publickey == right->publickey &&
			left->signature == right->signature &&
			left->hash == right->hash &&
			qsc_asn1_oid_compare(&left->algorithm_oid, &right->algorithm_oid) == true)
		{
			res = x509_algorithm_identifier_parameters_equal(left, right);
		}
	}

	return res;
}

qsc_asn1_status qsc_x509_signature_value_decode_raw(const qsc_encoding_ber_element* element, uint8_t* signature, size_t signaturelen, size_t* outlen)
{
	QSC_ASSERT(element != NULL);
	QSC_ASSERT(signature != NULL);
	QSC_ASSERT(outlen != NULL);

	qsc_asn1_status status;
	qsc_asn1_bit_string bitstr;

	status = QSC_ASN1_STATUS_FAILURE;
	qsc_memutils_clear((uint8_t*)&bitstr, sizeof(qsc_asn1_bit_string));

	if (element == (const qsc_encoding_ber_element*)NULL || signature == (uint8_t*)NULL || outlen == (size_t*)NULL)
	{
		status = QSC_ASN1_STATUS_INVALID_INPUT;
	}
	else
	{
		*outlen = 0U;
		status = qsc_asn1_decode_bit_string(element, &bitstr);

		if (status == QSC_ASN1_STATUS_SUCCESS)
		{
			if (bitstr.unused != 0U)
			{
				status = QSC_ASN1_STATUS_INVALID_ENCODING;
			}
			else if (bitstr.length > signaturelen)
			{
				status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
			}
			else
			{
				qsc_memutils_copy(signature, bitstr.data, bitstr.length);
				*outlen = bitstr.length;
			}
		}
	}

	return status;
}

size_t qsc_x509_signature_component_size(qsc_x509_named_curve curve)
{
	return qsc_x509_named_curve_coordinate_size(curve);
}

qsc_asn1_status qsc_x509_signature_value_decode_ecdsa(const qsc_encoding_ber_element* element, qsc_x509_named_curve curve, qsc_x509_ecdsa_signature* signature)
{
	QSC_ASSERT(element != NULL);
	QSC_ASSERT(signature != NULL);

	qsc_asn1_status status;
	qsc_asn1_bit_string bitstr;
	qsc_encoding_ber_element* seq;
	const qsc_encoding_ber_element* relem;
	const qsc_encoding_ber_element* selem;
	size_t consumed;
	size_t flen;

	status = QSC_ASN1_STATUS_FAILURE;
	seq = (qsc_encoding_ber_element*)NULL;
	relem = (const qsc_encoding_ber_element*)NULL;
	selem = (const qsc_encoding_ber_element*)NULL;
	consumed = 0U;
	flen = 0U;
	qsc_memutils_clear((uint8_t*)&bitstr, sizeof(qsc_asn1_bit_string));

	if (element == (const qsc_encoding_ber_element*)NULL || signature == (qsc_x509_ecdsa_signature*)NULL)
	{
		status = QSC_ASN1_STATUS_INVALID_INPUT;
	}
	else
	{
		x509_signature_initialize(signature);
		flen = qsc_x509_signature_component_size(curve);

		if (flen == 0U || flen > QSC_X509_MAX_SIGNATURE_COMPONENT_SIZE)
		{
			status = QSC_ASN1_STATUS_UNSUPPORTED;
		}
		else
		{
			status = qsc_asn1_decode_bit_string(element, &bitstr);

			if (status == QSC_ASN1_STATUS_SUCCESS)
			{
				if (bitstr.unused != 0U || bitstr.length == 0U)
				{
					status = QSC_ASN1_STATUS_INVALID_ENCODING;
				}
				else
				{
					seq = qsc_encoding_der_decode_element(bitstr.data, bitstr.length, &consumed);

					if (seq == (qsc_encoding_ber_element*)NULL)
					{
						status = QSC_ASN1_STATUS_INVALID_ENCODING;
					}
					else if (consumed != bitstr.length)
					{
						status = QSC_ASN1_STATUS_INVALID_LENGTH;
					}
					else
					{
						status = qsc_asn1_require_sequence(seq, 2U, 2U);

						if (status == QSC_ASN1_STATUS_SUCCESS)
						{
							relem = qsc_asn1_get_child(seq, 0U);
							selem = qsc_asn1_get_child(seq, 1U);

							if (relem == (const qsc_encoding_ber_element*)NULL || selem == (const qsc_encoding_ber_element*)NULL)
							{
								status = QSC_ASN1_STATUS_NOT_FOUND;
							}
							else
							{
								status = x509_integer_to_fixed_width(relem, signature->r, flen);

								if (status == QSC_ASN1_STATUS_SUCCESS)
								{
									status = x509_integer_to_fixed_width(selem, signature->s, flen);

									if (status == QSC_ASN1_STATUS_SUCCESS)
									{
										signature->length = flen;
									}
								}
							}
						}
					}

					qsc_encoding_ber_free_element(seq);
					seq = (qsc_encoding_ber_element*)NULL;
				}
			}
		}
	}

	return status;
}
