#include "x509ext.h"
#include "asn1.h"
#include "encoding.h"
#include "memutils.h"
#include "oid.h"
#include "x509name.h"
#include "x509write.h"

static bool x509_extension_oid_equal(const qsc_x509_extension* left, const qsc_x509_extension* right)
{
	bool res;

	res = false;

	if (left != (const qsc_x509_extension*)NULL && right != (const qsc_x509_extension*)NULL)
	{
		if (left->extension_oid.length == right->extension_oid.length)
		{
			res = qsc_memutils_are_equal(left->extension_oid.data, right->extension_oid.data, left->extension_oid.length);
		}
	}

	return res;
}

static bool x509_ext_is_ascii_string(const uint8_t* data, size_t datalen)
{
	bool res;
	size_t i;

	res = false;

	if (data != (const uint8_t*)NULL && datalen != 0U)
	{
		res = true;

		for (i = 0U; i < datalen; ++i)
		{
			if (data[i] > 0x7FU)
			{
				res = false;
				break;
			}
		}
	}

	return res;
}

static qsc_asn1_status x509_ext_validate_general_name_entry(const qsc_x509_general_name* entry)
{
	qsc_asn1_status status;

	status = QSC_ASN1_STATUS_FAILURE;

	if (entry == (const qsc_x509_general_name*)NULL)
	{
		status = QSC_ASN1_STATUS_INVALID_INPUT;
	}
	else if (entry->length == 0U)
	{
		status = QSC_ASN1_STATUS_INVALID_LENGTH;
	}
	else
	{
		status = QSC_ASN1_STATUS_SUCCESS;

		switch (entry->type)
		{
			case QSC_X509_GENERAL_NAME_RFC822_NAME:
			case QSC_X509_GENERAL_NAME_DNS_NAME:
			case QSC_X509_GENERAL_NAME_UNIFORM_RESOURCE_IDENTIFIER:
				if (x509_ext_is_ascii_string(entry->data, entry->length) == false)
				{
					status = QSC_ASN1_STATUS_INVALID_ENCODING;
				}
				break;
			case QSC_X509_GENERAL_NAME_IP_ADDRESS:
				if (entry->length != 4U && entry->length != 16U)
				{
					status = QSC_ASN1_STATUS_INVALID_LENGTH;
				}
				break;
			case QSC_X509_GENERAL_NAME_REGISTERED_ID:
				if (entry->registeredid.length == 0U)
				{
					status = QSC_ASN1_STATUS_INVALID_ENCODING;
				}
				break;
			default:
				status = QSC_ASN1_STATUS_UNSUPPORTED;
				break;
		}
	}

	return status;
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

static uint16_t x509_ext_map_key_usage_bits(const uint8_t* data, size_t datalen, uint8_t unused)
{
	static const uint16_t masktab[9U] =
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
			uint8_t validmask;

			bytepos = bit / 8U;
			bitmask = (uint8_t)(0x80U >> (bit % 8U));
			validmask = bitmask;

			if (bytepos == (datalen - 1U) && unused > 0U && unused < 8U)
			{
				validmask = (uint8_t)(bitmask & (uint8_t)(0xFFU << unused));
			}

			if (bytepos < datalen && (data[bytepos] & validmask) != 0U)
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

static qsc_asn1_status x509_ext_decode_general_names(const uint8_t* data, size_t datalen, qsc_x509_general_name* entries, size_t* count, size_t capacity)
{
    size_t consumed = 0U;
    qsc_encoding_ber_element* root = NULL;
    qsc_asn1_status status = QSC_ASN1_STATUS_FAILURE;

    if ((data == NULL) || (entries == NULL) || (count == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    *count = 0U;
    root = qsc_encoding_der_decode_element(data, datalen, &consumed);

    if (root == NULL)
    {
        return QSC_ASN1_STATUS_INVALID_ENCODING;
    }
    else if (consumed != datalen)
    {
        qsc_encoding_ber_free_element(root);
        return QSC_ASN1_STATUS_INVALID_LENGTH;
    }
    else if (root->constructed == false)
    {
        qsc_encoding_ber_free_element(root);
        return QSC_ASN1_STATUS_INVALID_TAG;
    }

    status = QSC_ASN1_STATUS_SUCCESS;

    for (size_t i = 0U; i < root->ccount; ++i)
    {
        const qsc_encoding_ber_element* child = root->children[i];
        qsc_x509_general_name* entry = NULL;

        if (child == NULL)
        {
            status = QSC_ASN1_STATUS_NOT_FOUND;
            break;
        }

        if (*count >= capacity)
        {
            status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        entry = &entries[*count];
        qsc_memutils_clear(entry, sizeof(*entry));

        if (child->tagclass != QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC)
        {
            status = QSC_ASN1_STATUS_INVALID_TAG;
            break;
        }

        switch (child->tagnumber)
        {
            case 1U:
                entry->type = QSC_X509_GENERAL_NAME_RFC822_NAME;
                break;
            case 2U:
                entry->type = QSC_X509_GENERAL_NAME_DNS_NAME;
                break;
            case 6U:
                entry->type = QSC_X509_GENERAL_NAME_UNIFORM_RESOURCE_IDENTIFIER;
                break;
            case 7U:
                entry->type = QSC_X509_GENERAL_NAME_IP_ADDRESS;
                break;
            case 8U:
                entry->type = QSC_X509_GENERAL_NAME_REGISTERED_ID;
                break;
            default:
                status = QSC_ASN1_STATUS_UNSUPPORTED;
        }

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            break;
        }

        if (child->length > sizeof(entry->data))
        {
            status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        qsc_memutils_copy(entry->data, child->value, child->length);
        entry->length = child->length;

        if (entry->type == QSC_X509_GENERAL_NAME_REGISTERED_ID)
        {
            if (child->length > sizeof(entry->registeredid.data))
            {
                status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
                break;
            }

            qsc_memutils_copy(entry->registeredid.data, child->value, child->length);
            entry->registeredid.length = child->length;
            entry->oid = QSC_OID_ID_NONE;
        }

        status = x509_ext_validate_general_name_entry(entry);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            break;
        }

        *count += 1U;
    }

    qsc_encoding_ber_free_element(root);
    return status;
}

void qsc_x509_extension_initialize(qsc_x509_extension* ext)
{
	QSC_ASSERT(ext != NULL);

	if (ext != NULL)
	{
		qsc_memutils_clear((uint8_t*)ext, sizeof(qsc_x509_extension));
		ext->rawextnvalue.storage = QSC_X509_STORAGE_CLASS_NONE;
	}
}

void qsc_x509_extensions_initialize(qsc_x509_extensions* extensions)
{
	QSC_ASSERT(extensions != NULL);

	if (extensions != NULL)
	{
		qsc_memutils_clear((uint8_t*)extensions, sizeof(qsc_x509_extensions));
		extensions->duplicatesrejected = true;
	}
}

qsc_asn1_status qsc_x509_extension_validate(const qsc_x509_extension* ext)
{
	QSC_ASSERT(ext != NULL);

	qsc_asn1_status status;

	status = QSC_ASN1_STATUS_FAILURE;

	if (ext == (const qsc_x509_extension*)NULL)
	{
		status = QSC_ASN1_STATUS_INVALID_INPUT;
	}
	else if (ext->decoded == false)
	{
		status = QSC_ASN1_STATUS_INVALID_ENCODING;
	}
	else if (ext->extension_oid.length == 0U || ext->valuelen == 0U)
	{
		status = QSC_ASN1_STATUS_INVALID_LENGTH;
	}
	else if (ext->rawextnvalue.data == (const uint8_t*)NULL || ext->rawextnvalue.length != ext->valuelen)
	{
		status = QSC_ASN1_STATUS_INVALID_ENCODING;
	}
	else if (ext->critical == true && ext->type == QSC_X509_EXTENSION_UNKNOWN)
	{
		status = QSC_ASN1_STATUS_SUCCESS;
	}
	else
	{
		status = QSC_ASN1_STATUS_SUCCESS;
	}

	return status;
}

qsc_asn1_status qsc_x509_extensions_validate(const qsc_x509_extensions* extensions)
{
	QSC_ASSERT(extensions != NULL);

	qsc_asn1_status status;
	size_t i;
	size_t j;

	status = QSC_ASN1_STATUS_FAILURE;
	i = 0U;
	j = 0U;

	if (extensions == (const qsc_x509_extensions*)NULL)
	{
		status = QSC_ASN1_STATUS_INVALID_INPUT;
	}
	else if (extensions->decoded == false)
	{
		status = QSC_ASN1_STATUS_INVALID_ENCODING;
	}
	else
	{
		status = QSC_ASN1_STATUS_SUCCESS;

		for (i = 0U; i < extensions->count && status == QSC_ASN1_STATUS_SUCCESS; ++i)
		{
			status = qsc_x509_extension_validate(&extensions->entries[i]);

			for (j = i + 1U; j < extensions->count && status == QSC_ASN1_STATUS_SUCCESS; ++j)
			{
				if (x509_extension_oid_equal(&extensions->entries[i], &extensions->entries[j]) == true)
				{
					status = QSC_ASN1_STATUS_INVALID_ENCODING;
				}
			}
		}

		if (status == QSC_ASN1_STATUS_SUCCESS &&
			extensions->basicconstraints.pathlen_present == true &&
			extensions->basicconstraints.ca == false)
		{
			status = QSC_ASN1_STATUS_INVALID_ENCODING;
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
		qsc_x509_extension_initialize(ext);
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

						if (status == QSC_ASN1_STATUS_SUCCESS)
						{
							ext->rawextnvalue.data = child->value;
							ext->rawextnvalue.length = ext->valuelen;
							ext->rawextnvalue.storage = QSC_X509_STORAGE_CLASS_BORROWED;
							ext->decoded = true;
							status = qsc_x509_extension_validate(ext);
						}
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
	else if (qsc_asn1_require_sequence(element, 0U, QSC_X509_EXTENSIONS_MAX) != QSC_ASN1_STATUS_SUCCESS)
	{
		status = QSC_ASN1_STATUS_INVALID_TAG;
	}
	else
	{
		qsc_x509_extensions_initialize(extensions);
		status = QSC_ASN1_STATUS_SUCCESS;

		for (size_t i = 0U; i < element->ccount; ++i)
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

			for (size_t j = 0U; j < extensions->count; ++j)
			{
				if (x509_extension_oid_equal(&extensions->entries[j], ext) == true)
				{
					status = QSC_ASN1_STATUS_INVALID_ENCODING;
					break;
				}
			}

			if (status != QSC_ASN1_STATUS_SUCCESS)
			{
				break;
			}

			extensions->count += 1U;

			switch (ext->type)
			{
				case QSC_X509_EXTENSION_BASIC_CONSTRAINTS:
					status = qsc_x509_ext_basic_constraints_decode(ext->value, ext->valuelen, &extensions->basicconstraints);
					if (status == QSC_ASN1_STATUS_SUCCESS) 
					{ 
						extensions->basicconstraints.critical = ext->critical; 
					}
					break;
				case QSC_X509_EXTENSION_KEY_USAGE:
					status = qsc_x509_ext_key_usage_decode(ext->value, ext->valuelen, &extensions->keyusage.bits);
					if (status == QSC_ASN1_STATUS_SUCCESS) 
					{ 
						extensions->keyusage.present = true; extensions->keyusage.critical = ext->critical; 
					}
					break;
				case QSC_X509_EXTENSION_EXTENDED_KEY_USAGE:
					status = qsc_x509_ext_extended_key_usage_decode(ext->value, ext->valuelen, &extensions->extendedkeyusage);
					if (status == QSC_ASN1_STATUS_SUCCESS) 
					{ 
						extensions->extendedkeyusage.critical = ext->critical; 
					}
					break;
				case QSC_X509_EXTENSION_SUBJECT_KEY_IDENTIFIER:
					status = qsc_x509_ext_subject_key_identifier_decode(ext->value, ext->valuelen, &extensions->subjectkeyidentifier);
					if (status == QSC_ASN1_STATUS_SUCCESS) 
					{ 
						extensions->subjectkeyidentifier.critical = ext->critical; 
					}
					break;
				case QSC_X509_EXTENSION_AUTHORITY_KEY_IDENTIFIER:
					status = qsc_x509_ext_authority_key_identifier_decode(ext->value, ext->valuelen, &extensions->authoritykeyidentifier);
					if (status == QSC_ASN1_STATUS_SUCCESS) 
					{ 
						extensions->authoritykeyidentifier.critical = ext->critical; 
					}
					break;
				case QSC_X509_EXTENSION_SUBJECT_ALT_NAME:
					status = qsc_x509_ext_subject_alt_name_decode(ext->value, ext->valuelen, &extensions->subjectaltname);
					if (status == QSC_ASN1_STATUS_SUCCESS)
					{ 
						extensions->subjectaltname.critical = ext->critical; 
					}
					break;
				case QSC_X509_EXTENSION_ISSUER_ALT_NAME:
					status = qsc_x509_ext_issuer_alt_name_decode(ext->value, ext->valuelen, &extensions->issueraltname);
					if (status == QSC_ASN1_STATUS_SUCCESS) 
					{ 
						extensions->issueraltname.critical = ext->critical; 
					}
					break;
				case QSC_X509_EXTENSION_CRL_NUMBER:
				{
					qsc_encoding_ber_element* root;
					size_t consumed;

					root = (qsc_encoding_ber_element*)NULL;
					consumed = 0U;

					root = qsc_encoding_der_decode_element(ext->value, ext->valuelen, &consumed);

					if (root == (qsc_encoding_ber_element*)NULL)
					{
						status = QSC_ASN1_STATUS_INVALID_ENCODING;
					}
					else if (consumed != ext->valuelen)
					{
						status = QSC_ASN1_STATUS_INVALID_LENGTH;
					}
					else if (qsc_asn1_is_integer(root) == false)
					{
						status = QSC_ASN1_STATUS_INVALID_TAG;
					}
					else if (root->length == 0U)
					{
						status = QSC_ASN1_STATUS_INVALID_LENGTH;
					}
					else if (root->length > sizeof(extensions->crlnumber.value))
					{
						status = QSC_ASN1_STATUS_OUT_OF_RANGE;
					}
					else
					{
						size_t offset;
						size_t length;

						offset = 0U;

						while ((offset < root->length) && (root->value[offset] == 0U))
						{
							++offset;
						}

						length = root->length - offset;

						if (length == 0U)
						{
							status = QSC_ASN1_STATUS_INVALID_ENCODING;
						}
						else
						{
							qsc_memutils_clear(extensions->crlnumber.value, sizeof(extensions->crlnumber.value));
							qsc_memutils_copy(extensions->crlnumber.value, root->value + offset, length);
							extensions->crlnumber.valuelen = length;
							extensions->crlnumber.present = true;
							extensions->crlnumber.critical = ext->critical;
							status = QSC_ASN1_STATUS_SUCCESS;
						}
					}

					if (root != (qsc_encoding_ber_element*)NULL)
					{
						qsc_encoding_ber_free_element(root);
					}

					break;
				}
				default:
					status = QSC_ASN1_STATUS_SUCCESS;
					break;
			}

			if (status != QSC_ASN1_STATUS_SUCCESS)
			{
				break;
			}
		}

		if (status == QSC_ASN1_STATUS_SUCCESS)
		{
			extensions->decoded = true;
			status = qsc_x509_extensions_validate(extensions);
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
				if (bs.unused > 7U)
				{
					status = QSC_ASN1_STATUS_INVALID_ENCODING;
				}
				else
				{
					*usage = x509_ext_map_key_usage_bits(bs.data, bs.length, bs.unused);
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

qsc_asn1_status qsc_x509_ext_basic_constraints_encode(const qsc_x509_basic_constraints* bc, uint8_t* output, size_t* outputlen)
{
	QSC_ASSERT(bc != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(outputlen != NULL);

	qsc_asn1_status status;

	if ((bc != NULL) && (output != NULL) && (outputlen != NULL))
	{
		status = qsc_x509_write_basic_constraints(bc, output, outputlen);
	}
	else
	{
		status = QSC_ASN1_STATUS_INVALID_INPUT;
	}

	return status;
}

qsc_asn1_status qsc_x509_ext_key_usage_encode(const qsc_x509_key_usage* keyusage, uint8_t* output, size_t* outputlen)
{
	QSC_ASSERT(keyusage != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(outputlen != NULL);

	qsc_asn1_status status;

	if ((keyusage != NULL) && (output != NULL) && (outputlen != NULL))
	{
		status = qsc_x509_write_key_usage(keyusage, output, outputlen);
	}
	else
	{
		status = QSC_ASN1_STATUS_INVALID_INPUT;
	}

	return status;
}

qsc_asn1_status qsc_x509_ext_extended_key_usage_encode(const qsc_x509_extended_key_usage* eku, uint8_t* output, size_t* outputlen)
{
	QSC_ASSERT(eku != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(outputlen != NULL);

	qsc_asn1_status status;

	if ((eku != NULL) && (output != NULL) && (outputlen != NULL))
	{
		status = qsc_x509_write_extended_key_usage(eku, output, outputlen);
	}
	else
	{
		status = QSC_ASN1_STATUS_INVALID_INPUT;
	}

	return status;
}

bool qsc_x509_ext_has_eku(const qsc_x509_extended_key_usage* eku, uint32_t bitmask)
{
	QSC_ASSERT(eku != NULL);

	bool res;

	res = false;

	if (eku != NULL)
	{
		if ((eku->bits & QSC_X509_EXTENDED_KEY_USAGE_ANY) != 0U)
		{
			res = true;
		}
		else
		{
			res = ((eku->bits & bitmask) == bitmask);
		}
	}

	return res;
}

qsc_asn1_status qsc_x509_ext_subject_key_identifier_encode(const qsc_x509_subject_key_identifier* ski, uint8_t* output, size_t* outputlen)
{
	QSC_ASSERT(ski != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(outputlen != NULL);

	qsc_asn1_status status;

	if ((ski != NULL) && (output != NULL) && (outputlen != NULL))
	{
		status = qsc_x509_write_subject_key_identifier(ski, output, outputlen);
	}
	else
	{
		status = QSC_ASN1_STATUS_INVALID_INPUT;
	}

	return status;
}

qsc_asn1_status qsc_x509_ext_authority_key_identifier_encode(const qsc_x509_authority_key_identifier* aki, uint8_t* output, size_t* outputlen)
{
	QSC_ASSERT(aki != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(outputlen != NULL);

	qsc_asn1_status status;

	if ((aki != NULL) && (output != NULL) && (outputlen != NULL))
	{
		status = qsc_x509_write_authority_key_identifier(aki, output, outputlen);
	}
	else
	{
		status = QSC_ASN1_STATUS_INVALID_INPUT;
	}

	return status;
}

qsc_asn1_status qsc_x509_ext_subject_alt_name_decode(const uint8_t* data, size_t datalen, qsc_x509_subject_alt_name* san)
{
	QSC_ASSERT(data != NULL);
	QSC_ASSERT(san != NULL);

    qsc_asn1_status status;

	status = QSC_ASN1_STATUS_INVALID_INPUT;

	if ((data != NULL) && (san != NULL))
	{
		qsc_memutils_clear(san, sizeof(qsc_x509_subject_alt_name));
		status = x509_ext_decode_general_names(data, datalen, san->entries, &san->count, QSC_X509_SAN_ENTRIES_MAX);

		if (status == QSC_ASN1_STATUS_SUCCESS)
		{
			san->present = true;
		}
	}

    return status;
}

qsc_asn1_status qsc_x509_ext_subject_alt_name_encode(const qsc_x509_subject_alt_name* san, uint8_t* output, size_t* outputlen)
{
	QSC_ASSERT(san != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(outputlen != NULL);

	qsc_asn1_status status;

	if ((san != NULL) && (output != NULL) && (outputlen != NULL))
	{
		status = qsc_x509_write_subject_alt_name(san, output, outputlen);
	}
	else
	{
		status = QSC_ASN1_STATUS_INVALID_INPUT;
	}

	return status;
}

qsc_asn1_status qsc_x509_ext_issuer_alt_name_decode(const uint8_t* data, size_t datalen, qsc_x509_issuer_alt_name* ian)
{
	QSC_ASSERT(data != NULL);
	QSC_ASSERT(ian != NULL);

    qsc_asn1_status status;

	if ((data != NULL) && (ian != NULL))
	{
		qsc_memutils_clear(ian, sizeof(qsc_x509_issuer_alt_name));
		status = x509_ext_decode_general_names(data, datalen, ian->entries, &ian->count, QSC_X509_SAN_ENTRIES_MAX);

		if (status == QSC_ASN1_STATUS_SUCCESS)
		{
			ian->present = true;
		}
	}
	else
	{
		status = QSC_ASN1_STATUS_INVALID_INPUT;
	}

    return status;
}

qsc_asn1_status qsc_x509_ext_issuer_alt_name_encode(const qsc_x509_issuer_alt_name* ian, uint8_t* output, size_t* outputlen)
{
	QSC_ASSERT(ian != NULL);

	qsc_asn1_status status;

	if ((ian != NULL) && (output != NULL) && (outputlen != NULL))
	{
		status = qsc_x509_write_issuer_alt_name(ian, output, outputlen);
	}
	else
	{
		status = QSC_ASN1_STATUS_INVALID_INPUT;
	}

	return status;
}

qsc_asn1_status qsc_x509_ext_subject_alt_name_add_dns(qsc_x509_subject_alt_name* san, const char* dnsname, size_t dnsnamelen)
{
	QSC_ASSERT(san != NULL);

    qsc_x509_general_name* entry;
	qsc_asn1_status status;

    if ((san == NULL) || ((dnsname == NULL) && (dnsnamelen != 0U)) || (dnsnamelen == 0U))
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else if (dnsnamelen > QSC_X509_NAME_ATTRIBUTE_STRING_MAX)
    {
		status = QSC_ASN1_STATUS_OUT_OF_RANGE;
    }
    else if (san->count >= QSC_X509_SAN_ENTRIES_MAX)
    {
		status = QSC_ASN1_STATUS_OUT_OF_RANGE;
    }
	else
	{
		entry = &san->entries[san->count++];
		qsc_memutils_clear(entry, sizeof(*entry));
		entry->type = QSC_X509_GENERAL_NAME_DNS_NAME;
		entry->length = dnsnamelen;
		qsc_memutils_copy(entry->data, dnsname, dnsnamelen);
		san->present = true;

		status = QSC_ASN1_STATUS_SUCCESS;
	}

	return status;
}

qsc_asn1_status qsc_x509_ext_subject_alt_name_add_ip(qsc_x509_subject_alt_name* san, const uint8_t* address, size_t addresslen)
{
	QSC_ASSERT(san != NULL);

    qsc_x509_general_name* entry = NULL;
	qsc_asn1_status status;

    if ((san == NULL) || ((address == NULL) && (addresslen != 0U)))
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else if ((addresslen != 4U) && (addresslen != 16U))
    {
		status = QSC_ASN1_STATUS_OUT_OF_RANGE;
    }
    else if (san->count >= QSC_X509_SAN_ENTRIES_MAX)
    {
		status = QSC_ASN1_STATUS_OUT_OF_RANGE;
    }
	else
	{
		entry = &san->entries[san->count++];
		qsc_memutils_clear(entry, sizeof(*entry));
		entry->type = QSC_X509_GENERAL_NAME_IP_ADDRESS;
		entry->length = addresslen;
		qsc_memutils_copy(entry->data, address, addresslen);
		san->present = true;
		status = QSC_ASN1_STATUS_SUCCESS;
	}

	return status;
}
