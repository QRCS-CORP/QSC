#include "x509sig.h"
#include "dilithium.h"
#include "eddsa.h"
#include "encoding.h"
#include "memutils.h"
#include "x509spki.h"

static qsc_x509_pqc_parameter_set x509_sig_active_mldsa_parameter_set(void)
{
#if defined(QSC_DILITHIUM_S1P44)
    return QSC_X509_PQC_PARAMETER_SET_ML_DSA_44;
#elif defined(QSC_DILITHIUM_S3P65)
    return QSC_X509_PQC_PARAMETER_SET_ML_DSA_65;
#elif defined(QSC_DILITHIUM_S5P87)
    return QSC_X509_PQC_PARAMETER_SET_ML_DSA_87;
#else
    return QSC_X509_PQC_PARAMETER_SET_NONE;
#endif
}

static void x509_signature_initialize(qsc_x509_ecdsa_signature* signature)
{
	qsc_memutils_clear((uint8_t*)signature, sizeof(qsc_x509_ecdsa_signature));
}

static bool x509_algorithm_identifier_parameters_equal(const qsc_x509_algorithm_identifier* left, const qsc_x509_algorithm_identifier* right)
{
	bool res;

	res = false;

	if (left->parameters_present == right->parameters_present && left->parameters_null == right->parameters_null &&
		left->parameters_oid == right->parameters_oid && left->curve == right->curve && left->pqcparameter == right->pqcparameter)
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

	if (element == NULL || output == NULL || outlen == 0U)
	{
		status = QSC_ASN1_STATUS_INVALID_INPUT;
	}
	else if (qsc_asn1_is_integer(element) == false)
	{
		status = QSC_ASN1_STATUS_INVALID_TAG;
	}
	else if (element->length == 0U || element->value == NULL)
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

	if (left != NULL && right != NULL)
	{
		if (left->oid == right->oid && left->publickey == right->publickey && left->signature == right->signature && left->hash == right->hash && 
			left->pqcparameter == right->pqcparameter && qsc_asn1_oid_compare(&left->algorithm_oid, &right->algorithm_oid) == true)
		{
			res = x509_algorithm_identifier_parameters_equal(left, right);
		}
	}

	return res;
}

bool qsc_x509_signature_algorithm_is_ecdsa(qsc_x509_signature_algorithm algorithm)
{
    bool res;

    res = false;

    if ((algorithm == QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA256) ||
        (algorithm == QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA384) ||
        (algorithm == QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA512))
    {
        res = true;
    }

    return res;
}

bool qsc_x509_signature_algorithm_is_ml_dsa(qsc_x509_signature_algorithm algorithm)
{
    bool res;

    res = false;

    if ((algorithm == QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_44) ||
        (algorithm == QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_65) ||
        (algorithm == QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_87))
    {
        res = true;
    }

    return res;
}

bool qsc_x509_signature_algorithm_matches_spki(qsc_x509_signature_algorithm algorithm, const qsc_x509_subject_public_key_info* spki)
{
    QSC_ASSERT(spki != NULL);

    bool res;

    res = false;

    if (spki != NULL)
    {
        if (qsc_x509_signature_algorithm_is_ecdsa(algorithm) == true)
        {
            if (spki->algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_EC)
            {
                res = ((algorithm == QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA256) &&
                    (spki->algorithm.curve == QSC_X509_NAMED_CURVE_PRIME256V1)) ||
                    ((algorithm == QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA384) &&
                    (spki->algorithm.curve == QSC_X509_NAMED_CURVE_SECP384R1)) ||
                    ((algorithm == QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA512) &&
                    (spki->algorithm.curve == QSC_X509_NAMED_CURVE_SECP521R1));
            }
        }
		else if (algorithm == QSC_X509_SIGNATURE_ALGORITHM_ED25519)
		{
			res = (spki->algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ED25519) &&
				(spki->algorithm.parameters_present == false);
		}
        else if (qsc_x509_signature_algorithm_is_ml_dsa(algorithm) == true)
        {
            if (spki->algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ML_DSA)
            {
                res = ((algorithm == QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_44) &&
                    (spki->algorithm.pqcparameter == QSC_X509_PQC_PARAMETER_SET_ML_DSA_44)) ||
                    ((algorithm == QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_65) &&
                    (spki->algorithm.pqcparameter == QSC_X509_PQC_PARAMETER_SET_ML_DSA_65)) ||
                    ((algorithm == QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_87) &&
                    (spki->algorithm.pqcparameter == QSC_X509_PQC_PARAMETER_SET_ML_DSA_87));
            }
        }
    }

    return res;
}

size_t qsc_x509_signature_expected_size(qsc_x509_signature_algorithm algorithm, qsc_x509_named_curve curve)
{
    size_t res;

    res = 0U;

    if (qsc_x509_signature_algorithm_is_ecdsa(algorithm) == true)
    {
        res = (2U * qsc_x509_signature_component_size(curve));
    }
	else if (algorithm == QSC_X509_SIGNATURE_ALGORITHM_ED25519)
	{
		res = QSC_EDDSA_SIGNATURE_SIZE;
	}
    else if (qsc_x509_signature_algorithm_is_ml_dsa(algorithm) == true)
    {
#if defined(QSC_DILITHIUM_SIGNATURE_SIZE)
        qsc_x509_pqc_parameter_set active;

        active = x509_sig_active_mldsa_parameter_set();

        if (((algorithm == QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_44) && (active == QSC_X509_PQC_PARAMETER_SET_ML_DSA_44)) ||
            ((algorithm == QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_65) && (active == QSC_X509_PQC_PARAMETER_SET_ML_DSA_65)) ||
            ((algorithm == QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_87) && (active == QSC_X509_PQC_PARAMETER_SET_ML_DSA_87)))
        {
            res = QSC_DILITHIUM_SIGNATURE_SIZE;
        }
        else
#endif
        if (algorithm == QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_44)
        {
            res = 2420U;
        }
        else if (algorithm == QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_65)
        {
            res = 3309U;
        }
        else if (algorithm == QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_87)
        {
            res = 4627U;
        }
    }

    return res;
}

qsc_asn1_status qsc_x509_signature_value_decode_raw(const qsc_encoding_ber_element* element, uint8_t* signature, size_t signaturelen, size_t* outlen)
{
    QSC_ASSERT(element != NULL);
    QSC_ASSERT(signature != NULL);
    QSC_ASSERT(outlen != NULL);

    qsc_asn1_bit_string bitstr;
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;
    qsc_memutils_clear((uint8_t*)&bitstr, sizeof(qsc_asn1_bit_string));

    if ((element != NULL) && (signature != NULL) && (outlen != NULL))
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
    size_t res;

    res = qsc_x509_named_curve_coordinate_size(curve);

    return res;
}

qsc_asn1_status qsc_x509_signature_value_decode_ecdsa(const qsc_encoding_ber_element* element, qsc_x509_named_curve curve, qsc_x509_ecdsa_signature* signature)
{
	QSC_ASSERT(element != NULL);
	QSC_ASSERT(signature != NULL);

	qsc_asn1_bit_string bitstr = { 0 };
	qsc_encoding_ber_element* seq;
	const qsc_encoding_ber_element* relem;
	const qsc_encoding_ber_element* selem;
	size_t consumed;
	size_t flen;
	qsc_asn1_status status;

	status = QSC_ASN1_STATUS_FAILURE;
	seq = (qsc_encoding_ber_element*)NULL;
	relem = (const qsc_encoding_ber_element*)NULL;
	selem = (const qsc_encoding_ber_element*)NULL;
	consumed = 0U;
	flen = 0U;

	qsc_memutils_clear((uint8_t*)&bitstr, sizeof(qsc_asn1_bit_string));

	if (element == NULL || signature == NULL)
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
								status = QSC_ASN1_STATUS_INVALID_ENCODING;
							}
							else if (x509_integer_to_fixed_width(relem, signature->r, flen) != QSC_ASN1_STATUS_SUCCESS)
							{
								status = QSC_ASN1_STATUS_INVALID_ENCODING;
							}
							else if (x509_integer_to_fixed_width(selem, signature->s, flen) != QSC_ASN1_STATUS_SUCCESS)
							{
								status = QSC_ASN1_STATUS_INVALID_ENCODING;
							}
							else
							{
								signature->length = flen;
							}
						}
					}

					if (seq != (qsc_encoding_ber_element*)NULL)
					{
						qsc_encoding_ber_free_element(seq);
						seq = (qsc_encoding_ber_element*)NULL;
					}
				}
			}
		}
	}

	return status;
}
