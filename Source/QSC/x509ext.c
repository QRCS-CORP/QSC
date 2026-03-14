#include "x509ext.h"
#include "asn1.h"
#include "encoding.h"
#include "memutils.h"
#include "oid.h"
#include "x509name.h"

static void x509_extension_initialize(qsc_x509_extension* ext)
{
	qsc_memutils_clear((uint8_t*)ext, sizeof(qsc_x509_extension));
}

static uint32_t x509_map_eku_bits(qsc_oid_id oid)
{
	uint32_t bits;

	bits = QSC_X509_EXTENDED_KEY_USAGE_NONE;

	if (oid == QSC_OID_ID_ANY_EXTENDED_KEY_USAGE)
	{
		bits = QSC_X509_EXTENDED_KEY_USAGE_ANY;
	}
	else if (oid == QSC_OID_ID_SERVER_AUTH)
	{
		bits = QSC_X509_EXTENDED_KEY_USAGE_SERVER_AUTH;
	}
	else if (oid == QSC_OID_ID_CLIENT_AUTH)
	{
		bits = QSC_X509_EXTENDED_KEY_USAGE_CLIENT_AUTH;
	}
	else if (oid == QSC_OID_ID_CODE_SIGNING)
	{
		bits = QSC_X509_EXTENDED_KEY_USAGE_CODE_SIGNING;
	}
	else if (oid == QSC_OID_ID_EMAIL_PROTECTION)
	{
		bits = QSC_X509_EXTENDED_KEY_USAGE_EMAIL_PROTECTION;
	}
	else if (oid == QSC_OID_ID_TIME_STAMPING)
	{
		bits = QSC_X509_EXTENDED_KEY_USAGE_TIME_STAMPING;
	}
	else if (oid == QSC_OID_ID_OCSP_SIGNING)
	{
		bits = QSC_X509_EXTENDED_KEY_USAGE_OCSP_SIGNING;
	}

	return bits;
}

static qsc_x509_extension_type x509_extension_type_from_oid(qsc_oid_id oid)
{
	qsc_x509_extension_type type;

	type = QSC_X509_EXTENSION_UNKNOWN;

	if (oid == QSC_OID_ID_SUBJECT_KEY_IDENTIFIER)
	{
		type = QSC_X509_EXTENSION_SUBJECT_KEY_IDENTIFIER;
	}
	else if (oid == QSC_OID_ID_KEY_USAGE)
	{
		type = QSC_X509_EXTENSION_KEY_USAGE;
	}
	else if (oid == QSC_OID_ID_SUBJECT_ALT_NAME)
	{
		type = QSC_X509_EXTENSION_SUBJECT_ALT_NAME;
	}
	else if (oid == QSC_OID_ID_ISSUER_ALT_NAME)
	{
		type = QSC_X509_EXTENSION_ISSUER_ALT_NAME;
	}
	else if (oid == QSC_OID_ID_BASIC_CONSTRAINTS)
	{
		type = QSC_X509_EXTENSION_BASIC_CONSTRAINTS;
	}
	else if (oid == QSC_OID_ID_NAME_CONSTRAINTS)
	{
		type = QSC_X509_EXTENSION_NAME_CONSTRAINTS;
	}
	else if (oid == QSC_OID_ID_CRL_DISTRIBUTION_POINTS)
	{
		type = QSC_X509_EXTENSION_CRL_DISTRIBUTION_POINTS;
	}
	else if (oid == QSC_OID_ID_CERTIFICATE_POLICIES)
	{
		type = QSC_X509_EXTENSION_CERTIFICATE_POLICIES;
	}
	else if (oid == QSC_OID_ID_AUTHORITY_KEY_IDENTIFIER)
	{
		type = QSC_X509_EXTENSION_AUTHORITY_KEY_IDENTIFIER;
	}
	else if (oid == QSC_OID_ID_EXTENDED_KEY_USAGE)
	{
		type = QSC_X509_EXTENSION_EXTENDED_KEY_USAGE;
	}
	else if (oid == QSC_OID_ID_AUTHORITY_INFO_ACCESS)
	{
		type = QSC_X509_EXTENSION_AUTHORITY_INFO_ACCESS;
	}
	else if (oid == QSC_OID_ID_SUBJECT_INFO_ACCESS)
	{
		type = QSC_X509_EXTENSION_SUBJECT_INFO_ACCESS;
	}

	return type;
}

static uint16_t x509_ext_map_key_usage_bits(const uint8_t* data, size_t datalen)
{
	static const uint16_t masktab[9] =
	{
		QSC_X509_KEY_USAGE_DIGITAL_SIGNATURE,
		QSC_X509_KEY_USAGE_NON_REPUDIATION,
		QSC_X509_KEY_USAGE_KEY_ENCIPHERMENT,
		QSC_X509_KEY_USAGE_DATA_ENCIPHERMENT,
		QSC_X509_KEY_USAGE_KEY_AGREEMENT,
		QSC_X509_KEY_USAGE_KEY_CERT_SIGN,
		QSC_X509_KEY_USAGE_CRL_SIGN,
		QSC_X509_KEY_USAGE_ENCIPHER_ONLY,
		QSC_X509_KEY_USAGE_DECIPHER_ONLY
	};

	uint16_t bits;
	size_t bit;

	bits = 0U;

	if (data != (const uint8_t*)NULL)
	{
		for (bit = 0U; bit < 9U; ++bit)
		{
			size_t bytepos;
			uint8_t bitmask;

			bytepos = bit / 8U;
			bitmask = (uint8_t)(0x80U >> (bit % 8U));

			if (bytepos < datalen && (data[bytepos] & bitmask) != 0U)
			{
				bits |= masktab[bit];
			}
		}
	}

	return bits;
}

static qsc_asn1_status x509_ext_parse_authority_cert_issuer(const qsc_encoding_ber_element* element, qsc_x509_authority_key_identifier* aki)
{
	const qsc_encoding_ber_element* child;
	const qsc_encoding_ber_element* inner;
	qsc_asn1_status status;

	child = (const qsc_encoding_ber_element*)NULL;
	inner = (const qsc_encoding_ber_element*)NULL;
	status = QSC_ASN1_STATUS_FAILURE;

	if (element == (const qsc_encoding_ber_element*)NULL || aki == (qsc_x509_authority_key_identifier*)NULL)
	{
		status = QSC_ASN1_STATUS_INVALID_INPUT;
	}
	else if (element->tagclass != 0x80U || element->tagnumber != 1U || element->constructed == false)
	{
		status = QSC_ASN1_STATUS_INVALID_TAG;
	}
	else
	{
		aki->issuer_present = true;
		status = QSC_ASN1_STATUS_SUCCESS;

		for (size_t i = 0U; i < element->ccount; ++i)
		{
			child = element->children[i];

			if (child == (const qsc_encoding_ber_element*)NULL)
			{
				status = QSC_ASN1_STATUS_NOT_FOUND;
				break;
			}

			if (child->tagclass == 0x80U && child->tagnumber == 4U && child->constructed == true)
			{
				if (aki->issuername_present == true)
				{
					status = QSC_ASN1_STATUS_INVALID_ENCODING;
					break;
				}

				status = qsc_asn1_get_explicit_child(child, &inner);

				if (status != QSC_ASN1_STATUS_SUCCESS)
				{
					break;
				}

				status = qsc_x509_name_parse(inner, &aki->issuername);

				if (status != QSC_ASN1_STATUS_SUCCESS)
				{
					break;
				}

				aki->issuername_present = true;
			}
		}
	}

	return status;
}

qsc_asn1_status qsc_x509_extension_decode(const qsc_encoding_ber_element* element, qsc_x509_extension* ext)
{
	QSC_ASSERT(element != NULL);
	QSC_ASSERT(ext != NULL);

	qsc_asn1_status status;
	const qsc_encoding_ber_element* child;
	qsc_oid_id oid;

	status = QSC_ASN1_STATUS_FAILURE;
	child = (const qsc_encoding_ber_element*)NULL;
	oid = QSC_OID_ID_NONE;

	if (element == (const qsc_encoding_ber_element*)NULL || ext == (qsc_x509_extension*)NULL)
	{
		status = QSC_ASN1_STATUS_INVALID_INPUT;
	}
	else
	{
		x509_extension_initialize(ext);
		status = qsc_asn1_require_sequence(element, 2U, 3U);

		if (status == QSC_ASN1_STATUS_SUCCESS)
		{
			child = qsc_asn1_get_child(element, 0U);

			if (child == (const qsc_encoding_ber_element*)NULL)
			{
				status = QSC_ASN1_STATUS_NOT_FOUND;
			}
			else
			{
				status = qsc_asn1_decode_oid(child, &ext->extension_oid);

				if (status == QSC_ASN1_STATUS_SUCCESS)
				{
					oid = qsc_oid_identify(&ext->extension_oid);
					ext->oid = oid;
					ext->type = x509_extension_type_from_oid(oid);

					if (element->ccount == 3U)
					{
						child = qsc_asn1_get_child(element, 1U);

						if (child == (const qsc_encoding_ber_element*)NULL)
						{
							status = QSC_ASN1_STATUS_NOT_FOUND;
						}
						else
						{
							status = qsc_asn1_decode_boolean(child, &ext->critical);

							if (status == QSC_ASN1_STATUS_SUCCESS)
							{
								child = qsc_asn1_get_child(element, 2U);

								if (child == (const qsc_encoding_ber_element*)NULL)
								{
									status = QSC_ASN1_STATUS_NOT_FOUND;
								}
							}
						}
					}
					else
					{
						ext->critical = false;
						child = qsc_asn1_get_child(element, 1U);

						if (child == (const qsc_encoding_ber_element*)NULL)
						{
							status = QSC_ASN1_STATUS_NOT_FOUND;
						}
					}

					if (status == QSC_ASN1_STATUS_SUCCESS)
					{
						status = qsc_asn1_decode_octet_string(child, ext->value, sizeof(ext->value), &ext->valuelen);
					}
				}
			}
		}
	}

	return status;
}

qsc_asn1_status qsc_x509_extensions_decode(const qsc_encoding_ber_element* element, qsc_x509_extensions* extensions)
{
	QSC_ASSERT(element != NULL);
	QSC_ASSERT(extensions != NULL);

	qsc_asn1_status status;
	const qsc_encoding_ber_element* child;
	qsc_x509_extension* ext;

	status = QSC_ASN1_STATUS_FAILURE;
	child = (const qsc_encoding_ber_element*)NULL;
	ext = (qsc_x509_extension*)NULL;

	if (element == (const qsc_encoding_ber_element*)NULL || extensions == (qsc_x509_extensions*)NULL)
	{
		status = QSC_ASN1_STATUS_INVALID_INPUT;
	}
	else if (element->constructed == false)
	{
		status = QSC_ASN1_STATUS_INVALID_TAG;
	}
	else
	{
		qsc_memutils_clear((uint8_t*)extensions, sizeof(qsc_x509_extensions));
		status = QSC_ASN1_STATUS_SUCCESS;

		for (size_t i = 0U; i < element->ccount && extensions->count < QSC_X509_EXTENSIONS_MAX; ++i)
		{
			child = element->children[i];

			if (child == (const qsc_encoding_ber_element*)NULL)
			{
				status = QSC_ASN1_STATUS_NOT_FOUND;
				break;
			}

			ext = &extensions->entries[extensions->count];
			status = qsc_x509_extension_decode(child, ext);

			if (status != QSC_ASN1_STATUS_SUCCESS)
			{
				break;
			}

			extensions->count += 1U;
		}
	}

	return status;
}

qsc_asn1_status qsc_x509_ext_basic_constraints_decode(const uint8_t* data, size_t datalen, qsc_x509_basic_constraints* bc)
{
	QSC_ASSERT(data != NULL);
	QSC_ASSERT(bc != NULL);

	size_t consumed;
	qsc_encoding_ber_element* root;
	qsc_asn1_status status;
	uint64_t value;

	consumed = 0U;
	root = (qsc_encoding_ber_element*)NULL;
	status = QSC_ASN1_STATUS_FAILURE;
	value = 0U;

	if (data == (const uint8_t*)NULL || bc == (qsc_x509_basic_constraints*)NULL)
	{
		status = QSC_ASN1_STATUS_INVALID_INPUT;
	}
	else
	{
		root = qsc_encoding_der_decode_element(data, datalen, &consumed);

		if (root == (qsc_encoding_ber_element*)NULL)
		{
			status = QSC_ASN1_STATUS_INVALID_ENCODING;
		}
		else if (consumed != datalen)
		{
			status = QSC_ASN1_STATUS_INVALID_LENGTH;
		}
		else if (root->constructed == false)
		{
			status = QSC_ASN1_STATUS_INVALID_TAG;
		}
		else
		{
			qsc_memutils_clear((uint8_t*)bc, sizeof(qsc_x509_basic_constraints));
			bc->present = true;

			if (root->ccount > 0U && qsc_asn1_is_boolean(root->children[0]) == true)
			{
				(void)qsc_asn1_decode_boolean(root->children[0], &bc->ca);
			}

			if (root->ccount > 1U && qsc_asn1_is_integer(root->children[1]) == true)
			{
				status = qsc_asn1_decode_integer_u64(root->children[1], &value);

				if (status == QSC_ASN1_STATUS_SUCCESS)
				{
					bc->pathlen_present = true;
					bc->pathlen = (uint32_t)value;
				}
			}
			else
			{
				status = QSC_ASN1_STATUS_SUCCESS;
			}
		}

		if (root != (qsc_encoding_ber_element*)NULL)
		{
			qsc_encoding_ber_free_element(root);
		}
	}

	return status;
}

qsc_asn1_status qsc_x509_ext_key_usage_decode(const uint8_t* data, size_t datalen, uint16_t* usage)
{
	QSC_ASSERT(data != NULL);
	QSC_ASSERT(usage != NULL);

	size_t consumed;
	qsc_encoding_ber_element* root;
	qsc_asn1_bit_string bs;
	qsc_asn1_status status;

	consumed = 0U;
	root = (qsc_encoding_ber_element*)NULL;
	status = QSC_ASN1_STATUS_FAILURE;
	qsc_memutils_clear((uint8_t*)&bs, sizeof(qsc_asn1_bit_string));

	if (data == (const uint8_t*)NULL || usage == (uint16_t*)NULL)
	{
		status = QSC_ASN1_STATUS_INVALID_INPUT;
	}
	else
	{
		*usage = 0U;
		root = qsc_encoding_der_decode_element(data, datalen, &consumed);

		if (root == (qsc_encoding_ber_element*)NULL)
		{
			status = QSC_ASN1_STATUS_INVALID_ENCODING;
		}
		else if (consumed != datalen)
		{
			status = QSC_ASN1_STATUS_INVALID_LENGTH;
		}
		else
		{
			status = qsc_asn1_decode_bit_string(root, &bs);

			if (status == QSC_ASN1_STATUS_SUCCESS)
			{
				*usage = x509_ext_map_key_usage_bits(bs.data, bs.length);
			}
		}

		if (root != (qsc_encoding_ber_element*)NULL)
		{
			qsc_encoding_ber_free_element(root);
		}
	}

	return status;
}

qsc_asn1_status qsc_x509_ext_extended_key_usage_decode(const uint8_t* data, size_t datalen, qsc_x509_extended_key_usage* eku)
{
	QSC_ASSERT(data != NULL);
	QSC_ASSERT(eku != NULL);

	size_t consumed;
	qsc_encoding_ber_element* root;
	qsc_asn1_status status;
	qsc_asn1_oid oid;
	qsc_oid_id oidid;

	consumed = 0U;
	root = (qsc_encoding_ber_element*)NULL;
	status = QSC_ASN1_STATUS_FAILURE;
	oidid = QSC_OID_ID_NONE;
	qsc_memutils_clear((uint8_t*)&oid, sizeof(qsc_asn1_oid));

	if (data == (const uint8_t*)NULL || eku == (qsc_x509_extended_key_usage*)NULL)
	{
		status = QSC_ASN1_STATUS_INVALID_INPUT;
	}
	else
	{
		root = qsc_encoding_der_decode_element(data, datalen, &consumed);

		if (root == (qsc_encoding_ber_element*)NULL)
		{
			status = QSC_ASN1_STATUS_INVALID_ENCODING;
		}
		else if (consumed != datalen)
		{
			status = QSC_ASN1_STATUS_INVALID_LENGTH;
		}
		else if (root->constructed == false)
		{
			status = QSC_ASN1_STATUS_INVALID_TAG;
		}
		else
		{
			qsc_memutils_clear((uint8_t*)eku, sizeof(qsc_x509_extended_key_usage));
			eku->present = true;
			eku->bits = QSC_X509_EXTENDED_KEY_USAGE_NONE;
			status = QSC_ASN1_STATUS_SUCCESS;

			for (size_t i = 0U; i < root->ccount; ++i)
			{
				status = qsc_asn1_decode_oid(root->children[i], &oid);

				if (status != QSC_ASN1_STATUS_SUCCESS)
				{
					break;
				}

				oidid = qsc_oid_identify(&oid);
				eku->bits |= x509_map_eku_bits(oidid);
			}
		}

		if (root != (qsc_encoding_ber_element*)NULL)
		{
			qsc_encoding_ber_free_element(root);
		}
	}

	return status;
}

qsc_asn1_status qsc_x509_ext_subject_key_identifier_decode(const uint8_t* data, size_t datalen, qsc_x509_subject_key_identifier* ski)
{
	QSC_ASSERT(data != NULL);
	QSC_ASSERT(ski != NULL);

	size_t consumed;
	qsc_encoding_ber_element* root;
	qsc_asn1_status status;

	consumed = 0U;
	root = (qsc_encoding_ber_element*)NULL;
	status = QSC_ASN1_STATUS_FAILURE;

	if (data == (const uint8_t*)NULL || ski == (qsc_x509_subject_key_identifier*)NULL)
	{
		status = QSC_ASN1_STATUS_INVALID_INPUT;
	}
	else
	{
		root = qsc_encoding_der_decode_element(data, datalen, &consumed);

		if (root == (qsc_encoding_ber_element*)NULL)
		{
			status = QSC_ASN1_STATUS_INVALID_ENCODING;
		}
		else if (consumed != datalen)
		{
			status = QSC_ASN1_STATUS_INVALID_LENGTH;
		}
		else
		{
			qsc_memutils_clear((uint8_t*)ski, sizeof(qsc_x509_subject_key_identifier));
			status = qsc_asn1_decode_octet_string(root, ski->identifier, sizeof(ski->identifier), &ski->identifierlen);

			if (status == QSC_ASN1_STATUS_SUCCESS)
			{
				ski->present = true;
			}
		}

		if (root != (qsc_encoding_ber_element*)NULL)
		{
			qsc_encoding_ber_free_element(root);
		}
	}

	return status;
}

qsc_asn1_status qsc_x509_ext_authority_key_identifier_decode(const uint8_t* data, size_t datalen, qsc_x509_authority_key_identifier* aki)
{
	QSC_ASSERT(data != NULL);
	QSC_ASSERT(aki != NULL);

	size_t consumed;
	qsc_encoding_ber_element* root;
	const qsc_encoding_ber_element* child;
	qsc_asn1_status status;

	consumed = 0U;
	root = (qsc_encoding_ber_element*)NULL;
	child = (const qsc_encoding_ber_element*)NULL;
	status = QSC_ASN1_STATUS_FAILURE;

	if (data == (const uint8_t*)NULL || aki == (qsc_x509_authority_key_identifier*)NULL)
	{
		status = QSC_ASN1_STATUS_INVALID_INPUT;
	}
	else
	{
		root = qsc_encoding_der_decode_element(data, datalen, &consumed);

		if (root == (qsc_encoding_ber_element*)NULL)
		{
			status = QSC_ASN1_STATUS_INVALID_ENCODING;
		}
		else if (consumed != datalen)
		{
			status = QSC_ASN1_STATUS_INVALID_LENGTH;
		}
		else if (root->constructed == false)
		{
			status = QSC_ASN1_STATUS_INVALID_TAG;
		}
		else
		{
			qsc_memutils_clear((uint8_t*)aki, sizeof(qsc_x509_authority_key_identifier));
			aki->present = true;
			status = QSC_ASN1_STATUS_SUCCESS;

			for (size_t i = 0U; i < root->ccount; ++i)
			{
				child = root->children[i];

				if (child == (const qsc_encoding_ber_element*)NULL)
				{
					status = QSC_ASN1_STATUS_NOT_FOUND;
					break;
				}

				if (child->tagclass == 0x80U && child->tagnumber == 0U && child->constructed == false)
				{
					if (aki->keyidentifierlen != 0U)
					{
						status = QSC_ASN1_STATUS_INVALID_ENCODING;
						break;
					}

					if (child->length > sizeof(aki->keyidentifier))
					{
						status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
						break;
					}

					qsc_memutils_copy(aki->keyidentifier, child->value, child->length);
					aki->keyidentifierlen = child->length;
				}
				else if (child->tagclass == 0x80U && child->tagnumber == 1U && child->constructed == true)
				{
					if (aki->issuer_present == true)
					{
						status = QSC_ASN1_STATUS_INVALID_ENCODING;
						break;
					}

					status = x509_ext_parse_authority_cert_issuer(child, aki);

					if (status != QSC_ASN1_STATUS_SUCCESS)
					{
						break;
					}
				}
				else if (child->tagclass == 0x80U && child->tagnumber == 2U && child->constructed == false)
				{
					if (aki->serial_present == true)
					{
						status = QSC_ASN1_STATUS_INVALID_ENCODING;
						break;
					}

					if (child->length > sizeof(aki->serial))
					{
						status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
						break;
					}

					aki->serial_present = true;
					qsc_memutils_copy(aki->serial, child->value, child->length);
					aki->seriallen = child->length;
				}
				else
				{
					status = QSC_ASN1_STATUS_INVALID_TAG;
					break;
				}
			}
		}

		if (root != (qsc_encoding_ber_element*)NULL)
		{
			qsc_encoding_ber_free_element(root);
		}
	}

	return status;
}
