#include "x509cert.h"
#include "x509name.h"
#include "x509time.h"
#include "x509spki.h"
#include "x509sig.h"
#include "asn1.h"
#include "encoding.h"
#include "memutils.h"

#define QSC_ASN1_CLASS_UNIVERSAL 0x00U
#define QSC_ASN1_CLASS_CONTEXT 0x80U
#define QSC_ASN1_TAG_BOOLEAN 1U
#define QSC_ASN1_TAG_INTEGER 2U
#define QSC_ASN1_TAG_BIT_STRING 3U
#define QSC_ASN1_TAG_SEQUENCE 16U

static void x509_certificate_release_preserved_der(qsc_x509_certificate* certificate)
{
	if (certificate != (qsc_x509_certificate*)NULL)
	{
		if ((certificate->derowned == true) && (certificate->der != (const uint8_t*)NULL))
		{
			qsc_memutils_secure_erase((uint8_t*)certificate->der, certificate->derlen);
			qsc_memutils_alloc_free((void*)certificate->der);
		}

		certificate->tbsdata = (const uint8_t*)NULL;
		certificate->tbsdatalen = 0U;
		certificate->der = (const uint8_t*)NULL;
		certificate->derlen = 0U;
		certificate->derowned = false;
	}
}

static qsc_asn1_status x509_require_sequence(const qsc_encoding_ber_element* element)
{
	qsc_asn1_status status;

	status = qsc_asn1_require_tag(element, QSC_ASN1_CLASS_UNIVERSAL, true, QSC_ASN1_TAG_SEQUENCE);

	return status;
}

static qsc_x509_extension_type x509_extension_type_from_oid(qsc_oid_id id)
{
	qsc_x509_extension_type type;

	type = QSC_X509_EXTENSION_UNKNOWN;

	if (id == QSC_OID_ID_SUBJECT_KEY_IDENTIFIER)
	{
		type = QSC_X509_EXTENSION_SUBJECT_KEY_IDENTIFIER;
	}
	else if (id == QSC_OID_ID_CRL_NUMBER)
	{
		type = QSC_X509_EXTENSION_CRL_NUMBER;
	}
	else if (id == QSC_OID_ID_KEY_USAGE)
	{
		type = QSC_X509_EXTENSION_KEY_USAGE;
	}
	else if (id == QSC_OID_ID_SUBJECT_ALT_NAME)
	{
		type = QSC_X509_EXTENSION_SUBJECT_ALT_NAME;
	}
	else if (id == QSC_OID_ID_ISSUER_ALT_NAME)
	{
		type = QSC_X509_EXTENSION_ISSUER_ALT_NAME;
	}
	else if (id == QSC_OID_ID_BASIC_CONSTRAINTS)
	{
		type = QSC_X509_EXTENSION_BASIC_CONSTRAINTS;
	}
	else if (id == QSC_OID_ID_NAME_CONSTRAINTS)
	{
		type = QSC_X509_EXTENSION_NAME_CONSTRAINTS;
	}
	else if (id == QSC_OID_ID_CRL_DISTRIBUTION_POINTS)
	{
		type = QSC_X509_EXTENSION_CRL_DISTRIBUTION_POINTS;
	}
	else if (id == QSC_OID_ID_CERTIFICATE_POLICIES)
	{
		type = QSC_X509_EXTENSION_CERTIFICATE_POLICIES;
	}
	else if (id == QSC_OID_ID_AUTHORITY_KEY_IDENTIFIER)
	{
		type = QSC_X509_EXTENSION_AUTHORITY_KEY_IDENTIFIER;
	}
	else if (id == QSC_OID_ID_EXTENDED_KEY_USAGE)
	{
		type = QSC_X509_EXTENSION_EXTENDED_KEY_USAGE;
	}
	else if (id == QSC_OID_ID_AUTHORITY_INFO_ACCESS)
	{
		type = QSC_X509_EXTENSION_AUTHORITY_INFO_ACCESS;
	}
	else if (id == QSC_OID_ID_SUBJECT_INFO_ACCESS)
	{
		type = QSC_X509_EXTENSION_SUBJECT_INFO_ACCESS;
	}
	else if (id == QSC_OID_ID_CRL_NUMBER)
	{
		type = QSC_X509_EXTENSION_CRL_NUMBER;
	}

	return type;
}

static qsc_asn1_status x509_copy_unsigned_integer(const qsc_encoding_ber_element* element, uint8_t* output, size_t otplen, size_t* outlen)
{
	qsc_asn1_status status;
	size_t ofs;
	size_t ilen;
	size_t i;
	bool nonzero;

	status = QSC_ASN1_STATUS_FAILURE;
	ofs = 0U;
	ilen = 0U;
	nonzero = false;

	if (element == (const qsc_encoding_ber_element*)NULL || output == (uint8_t*)NULL || outlen == (size_t*)NULL)
	{
		status = QSC_ASN1_STATUS_INVALID_INPUT;
	}
	else
	{
		status = qsc_asn1_require_tag(element, QSC_ASN1_CLASS_UNIVERSAL, false, QSC_ASN1_TAG_INTEGER);

		if (status == QSC_ASN1_STATUS_SUCCESS)
		{
			if (element->length == 0U || element->value == (const uint8_t*)NULL)
			{
				status = QSC_ASN1_STATUS_INVALID_LENGTH;
			}
			else if ((element->value[0U] & 0x80U) != 0U)
			{
				/* CertificateSerialNumber must be non-negative. */
				status = QSC_ASN1_STATUS_INVALID_ENCODING;
			}
			else
			{
				/* DER INTEGER must be minimally encoded.
				 * A leading 0x00 is permitted only when needed to keep the value positive. */
				if (element->length > 1U && element->value[0U] == 0x00U)
				{
					if ((element->value[1U] & 0x80U) == 0U)
					{
						status = QSC_ASN1_STATUS_INVALID_ENCODING;
					}
					else
					{
						ofs = 1U;
					}
				}

				if (status == QSC_ASN1_STATUS_SUCCESS)
				{
					ilen = element->length - ofs;

					if (ilen == 0U)
					{
						status = QSC_ASN1_STATUS_INVALID_LENGTH;
					}
					else if (ilen > otplen)
					{
						status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
					}
					else
					{
						for (i = ofs; i < element->length; ++i)
						{
							if (element->value[i] != 0U)
							{
								nonzero = true;
								break;
							}
						}

						if (nonzero == false)
						{
							status = QSC_ASN1_STATUS_INVALID_ENCODING;
						}
						else
						{
							qsc_memutils_clear(output, otplen);
							qsc_memutils_copy(output, element->value + ofs, ilen);
							*outlen = ilen;
							status = QSC_ASN1_STATUS_SUCCESS;
						}
					}
				}
			}
		}
	}

	return status;
}

static uint16_t x509_map_key_usage_bits(const uint8_t* data, size_t datalen, uint8_t unused)
{
	uint16_t masktab[9U] =
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

	size_t bytepos;
	size_t lastbyte;
	uint16_t bits;
	uint8_t bitmask;
	uint8_t effectivemask;

	bits = 0U;

	if (data != (const uint8_t*)NULL && datalen > 0U)
	{
		for (size_t bit = 0U; bit < 9U; ++bit)
		{
			bytepos = bit / 8U;
			bitmask = (uint8_t)(0x80U >> (bit % 8U));

			lastbyte = (datalen > 0U) ? datalen - 1U : 0U;
			effectivemask = (bytepos == lastbyte && unused > 0U)
				? (uint8_t)(bitmask & (uint8_t)(0xFFU << unused))
				: bitmask;

			if (bytepos < datalen && (data[bytepos] & effectivemask) != 0U)
			{
				bits |= masktab[bit];
			}
		}
	}

	return bits;
}

static uint32_t x509_map_eku_bits(qsc_oid_id id)
{
	uint32_t bits;

	bits = QSC_X509_EXTENDED_KEY_USAGE_NONE;

	if (id == QSC_OID_ID_ANY_EXTENDED_KEY_USAGE)
	{
		bits = QSC_X509_EXTENDED_KEY_USAGE_ANY;
	}
	else if (id == QSC_OID_ID_SERVER_AUTH)
	{
		bits = QSC_X509_EXTENDED_KEY_USAGE_SERVER_AUTH;
	}
	else if (id == QSC_OID_ID_CLIENT_AUTH)
	{
		bits = QSC_X509_EXTENDED_KEY_USAGE_CLIENT_AUTH;
	}
	else if (id == QSC_OID_ID_CODE_SIGNING)
	{
		bits = QSC_X509_EXTENDED_KEY_USAGE_CODE_SIGNING;
	}
	else if (id == QSC_OID_ID_EMAIL_PROTECTION)
	{
		bits = QSC_X509_EXTENDED_KEY_USAGE_EMAIL_PROTECTION;
	}
	else if (id == QSC_OID_ID_TIME_STAMPING)
	{
		bits = QSC_X509_EXTENDED_KEY_USAGE_TIME_STAMPING;
	}
	else if (id == QSC_OID_ID_OCSP_SIGNING)
	{
		bits = QSC_X509_EXTENDED_KEY_USAGE_OCSP_SIGNING;
	}

	return bits;
}

static qsc_asn1_status x509_decode_raw_extension(const qsc_encoding_ber_element* element, qsc_x509_extension* extension)
{
	qsc_asn1_status status;
	const qsc_encoding_ber_element* child;
	size_t index;
	qsc_oid_id oidid;

	status = QSC_ASN1_STATUS_FAILURE;
	child = (const qsc_encoding_ber_element*)NULL;
	index = 0U;
	oidid = QSC_OID_ID_NONE;

	if (element == (const qsc_encoding_ber_element*)NULL || extension == (qsc_x509_extension*)NULL)
	{
		status = QSC_ASN1_STATUS_INVALID_INPUT;
	}
	else
	{
		qsc_memutils_clear((uint8_t*)extension, sizeof(qsc_x509_extension));
		status = x509_require_sequence(element);

		if (status == QSC_ASN1_STATUS_SUCCESS)
		{
			if (qsc_asn1_child_count(element) < 2U || qsc_asn1_child_count(element) > 3U)
			{
				status = QSC_ASN1_STATUS_INVALID_LENGTH;
			}
			else
			{
				child = qsc_asn1_child_at(element, 0U);

				if (child == (const qsc_encoding_ber_element*)NULL)
				{
					status = QSC_ASN1_STATUS_NOT_FOUND;
				}
				else
				{
					status = qsc_asn1_decode_oid(child, &extension->extension_oid);

					if (status == QSC_ASN1_STATUS_SUCCESS)
					{
						oidid = qsc_oid_identify(&extension->extension_oid);
						extension->oid = oidid;
						extension->type = x509_extension_type_from_oid(oidid);
						index = 1U;
						child = qsc_asn1_child_at(element, index);

						if (child != (const qsc_encoding_ber_element*)NULL &&
							qsc_asn1_element_is_tag(child, QSC_ASN1_CLASS_UNIVERSAL, false, QSC_ASN1_TAG_BOOLEAN) == true)
						{
							status = qsc_asn1_decode_boolean(child, &extension->critical);
							index = 2U;
						}
						else
						{
							extension->critical = false;
						}

						if (status == QSC_ASN1_STATUS_SUCCESS)
						{
							child = qsc_asn1_child_at(element, index);

							if (child == (const qsc_encoding_ber_element*)NULL)
							{
								status = QSC_ASN1_STATUS_NOT_FOUND;
							}
							else
							{
								status = qsc_asn1_decode_octet_string(child, extension->value, sizeof(extension->value), &extension->valuelen);
							}
						}
					}
				}
			}
		}
	}

	return status;
}

static qsc_asn1_status x509_parse_basic_constraints(const qsc_x509_extension* extension, qsc_x509_basic_constraints* constraints)
{
	qsc_encoding_ber_element* root;
	const qsc_encoding_ber_element* child;
	uint64_t value;
	size_t ci;
	size_t consumed;
	qsc_asn1_status status;

	root = (qsc_encoding_ber_element*)NULL;
	child = (const qsc_encoding_ber_element*)NULL;
	consumed = 0U;
	value = 0U;
	status = QSC_ASN1_STATUS_FAILURE;

	if (extension == (const qsc_x509_extension*)NULL || constraints == (qsc_x509_basic_constraints*)NULL)
	{
		status = QSC_ASN1_STATUS_INVALID_INPUT;
	}
	else
	{
		root = qsc_encoding_der_decode_element(extension->value, extension->valuelen, &consumed);

		if (root == (qsc_encoding_ber_element*)NULL)
		{
			status = QSC_ASN1_STATUS_INVALID_ENCODING;
		}
		else if (consumed != extension->valuelen)
		{
			status = QSC_ASN1_STATUS_INVALID_LENGTH;
		}
		else
		{
			status = x509_require_sequence(root);

			if (status == QSC_ASN1_STATUS_SUCCESS)
			{
				constraints->present = true;
				constraints->critical = extension->critical;
				constraints->ca = false;
				constraints->pathlen_present = false;
				constraints->pathlen = 0U;

				ci = 0U;

				child = qsc_asn1_child_at(root, ci);

				if (child != NULL && qsc_asn1_element_is_tag(child,
					QSC_ASN1_CLASS_UNIVERSAL, false, QSC_ASN1_TAG_BOOLEAN))
				{
					status = qsc_asn1_decode_boolean(child, &constraints->ca);
					ci = 1U;
				}

				if (status == QSC_ASN1_STATUS_SUCCESS)
				{
					child = qsc_asn1_child_at(root, ci);
					if (child != NULL)
					{
						status = qsc_asn1_decode_uint64(child, &value);
						if (status == QSC_ASN1_STATUS_SUCCESS)
						{
							constraints->pathlen_present = true;
							constraints->pathlen = (uint32_t)value;
						}
					}
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

static qsc_asn1_status x509_parse_key_usage(const qsc_x509_extension* extension, qsc_x509_key_usage* usage)
{
	qsc_encoding_ber_element* root;
	qsc_asn1_bit_string bitstr = { 0 };
	size_t consumed;
	qsc_asn1_status status;

	root = (qsc_encoding_ber_element*)NULL;
	consumed = 0U;
	status = QSC_ASN1_STATUS_FAILURE;

	if (extension == (const qsc_x509_extension*)NULL || usage == (qsc_x509_key_usage*)NULL)
	{
		status = QSC_ASN1_STATUS_INVALID_INPUT;
	}
	else
	{
		root = qsc_encoding_der_decode_element(extension->value, extension->valuelen, &consumed);

		if (root == (qsc_encoding_ber_element*)NULL)
		{
			status = QSC_ASN1_STATUS_INVALID_ENCODING;
		}
		else if (consumed != extension->valuelen)
		{
			status = QSC_ASN1_STATUS_INVALID_LENGTH;
		}
		else
		{
			status = qsc_asn1_decode_bit_string(root, &bitstr);

			if (status == QSC_ASN1_STATUS_SUCCESS)
			{
				usage->present = true;
				usage->critical = extension->critical;
				usage->bits = x509_map_key_usage_bits(bitstr.data, bitstr.length, bitstr.unused);
			}
		}

		if (root != (qsc_encoding_ber_element*)NULL)
		{
			qsc_encoding_ber_free_element(root);
		}
	}

	return status;
}

static qsc_asn1_status x509_parse_extended_key_usage(const qsc_x509_extension* extension, qsc_x509_extended_key_usage* eku)
{
	qsc_encoding_ber_element* root;
	const qsc_encoding_ber_element* child;
	qsc_asn1_oid oid = { 0 };
	qsc_oid_id id;
	size_t consumed;
	qsc_asn1_status status;

	root = (qsc_encoding_ber_element*)NULL;
	child = (const qsc_encoding_ber_element*)NULL;
	id = QSC_OID_ID_NONE;
	consumed = 0U;
	status = QSC_ASN1_STATUS_FAILURE;

	if (extension == (const qsc_x509_extension*)NULL || eku == (qsc_x509_extended_key_usage*)NULL)
	{
		status = QSC_ASN1_STATUS_INVALID_INPUT;
	}
	else
	{
		root = qsc_encoding_der_decode_element(extension->value, extension->valuelen, &consumed);

		if (root == (qsc_encoding_ber_element*)NULL)
		{
			status = QSC_ASN1_STATUS_INVALID_ENCODING;
		}
		else if (consumed != extension->valuelen)
		{
			status = QSC_ASN1_STATUS_INVALID_LENGTH;
		}
		else
		{
			status = x509_require_sequence(root);

			if (status == QSC_ASN1_STATUS_SUCCESS)
			{
				eku->present = true;
				eku->critical = extension->critical;
				eku->bits = QSC_X509_EXTENDED_KEY_USAGE_NONE;

				for (size_t i = 0U; i < qsc_asn1_child_count(root); ++i)
				{
					child = qsc_asn1_child_at(root, i);

					if (child == (const qsc_encoding_ber_element*)NULL)
					{
						status = QSC_ASN1_STATUS_NOT_FOUND;
						break;
					}

					status = qsc_asn1_decode_oid(child, &oid);

					if (status != QSC_ASN1_STATUS_SUCCESS)
					{
						break;
					}

					id = qsc_oid_identify(&oid);
					eku->bits |= x509_map_eku_bits(id);
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

static qsc_asn1_status x509_parse_subject_key_identifier(const qsc_x509_extension* extension, qsc_x509_subject_key_identifier* ski)
{
	qsc_encoding_ber_element* root;
	size_t consumed;
	qsc_asn1_status status;

	root = (qsc_encoding_ber_element*)NULL;
	consumed = 0U;
	status = QSC_ASN1_STATUS_FAILURE;

	if (extension == (const qsc_x509_extension*)NULL || ski == (qsc_x509_subject_key_identifier*)NULL)
	{
		status = QSC_ASN1_STATUS_INVALID_INPUT;
	}
	else
	{
		root = qsc_encoding_der_decode_element(extension->value, extension->valuelen, &consumed);

		if (root == (qsc_encoding_ber_element*)NULL)
		{
			status = QSC_ASN1_STATUS_INVALID_ENCODING;
		}
		else if (consumed != extension->valuelen)
		{
			status = QSC_ASN1_STATUS_INVALID_LENGTH;
		}
		else
		{
			status = qsc_asn1_decode_octet_string(root, ski->identifier, sizeof(ski->identifier), &ski->identifierlen);

			if (status == QSC_ASN1_STATUS_SUCCESS)
			{
				ski->present = true;
				ski->critical = extension->critical;
			}
		}

		if (root != (qsc_encoding_ber_element*)NULL)
		{
			qsc_encoding_ber_free_element(root);
		}
	}

	return status;
}

static qsc_asn1_status x509_parse_authority_cert_issuer(const qsc_encoding_ber_element* element, qsc_x509_authority_key_identifier* aki)
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
	else if (qsc_asn1_element_is_tag(element, QSC_ASN1_CLASS_CONTEXT, true, 1U) == false)
	{
		status = QSC_ASN1_STATUS_INVALID_TAG;
	}
	else
	{
		aki->issuer_present = true;
		status = QSC_ASN1_STATUS_SUCCESS;

		for (size_t i = 0U; i < qsc_asn1_child_count(element); ++i)
		{
			child = qsc_asn1_child_at(element, i);

			if (child == (const qsc_encoding_ber_element*)NULL)
			{
				status = QSC_ASN1_STATUS_NOT_FOUND;
				break;
			}

			if (qsc_asn1_element_is_tag(child, QSC_ASN1_CLASS_CONTEXT, true, 4U) == true)
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

static qsc_asn1_status x509_parse_authority_key_identifier(const qsc_x509_extension* extension, qsc_x509_authority_key_identifier* aki)
{
	qsc_encoding_ber_element* root;
	const qsc_encoding_ber_element* child;
	size_t consumed;
	qsc_asn1_status status;

	root = (qsc_encoding_ber_element*)NULL;
	child = (const qsc_encoding_ber_element*)NULL;
	consumed = 0U;
	status = QSC_ASN1_STATUS_FAILURE;

	if (extension == (const qsc_x509_extension*)NULL || aki == (qsc_x509_authority_key_identifier*)NULL)
	{
		status = QSC_ASN1_STATUS_INVALID_INPUT;
	}
	else
	{
		qsc_memutils_clear((uint8_t*)aki, sizeof(qsc_x509_authority_key_identifier));

		root = qsc_encoding_der_decode_element(extension->value, extension->valuelen, &consumed);

		if (root == (qsc_encoding_ber_element*)NULL)
		{
			status = QSC_ASN1_STATUS_INVALID_ENCODING;
		}
		else if (consumed != extension->valuelen)
		{
			status = QSC_ASN1_STATUS_INVALID_LENGTH;
		}
		else
		{
			status = x509_require_sequence(root);

			if (status == QSC_ASN1_STATUS_SUCCESS)
			{
				aki->present = true;
				aki->critical = extension->critical;

				for (size_t i = 0U; i < qsc_asn1_child_count(root); ++i)
				{
					child = qsc_asn1_child_at(root, i);

					if (child == (const qsc_encoding_ber_element*)NULL)
					{
						status = QSC_ASN1_STATUS_NOT_FOUND;
						break;
					}

					if (qsc_asn1_element_is_tag(child, QSC_ASN1_CLASS_CONTEXT, false, 0U) == true)
					{
						if (aki->keyidentifierlen != 0U)
						{
							status = QSC_ASN1_STATUS_INVALID_ENCODING;
							break;
						}

						if (child->length > sizeof(aki->keyidentifier) || child->value == (const uint8_t*)NULL)
						{
							status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
							break;
						}

						qsc_memutils_copy(aki->keyidentifier, child->value, child->length);
						aki->keyidentifierlen = child->length;
					}
					else if (qsc_asn1_element_is_tag(child, QSC_ASN1_CLASS_CONTEXT, true, 1U) == true)
					{
						if (aki->issuer_present == true)
						{
							status = QSC_ASN1_STATUS_INVALID_ENCODING;
							break;
						}

						status = x509_parse_authority_cert_issuer(child, aki);

						if (status != QSC_ASN1_STATUS_SUCCESS)
						{
							break;
						}
					}
					else if (qsc_asn1_element_is_tag(child, QSC_ASN1_CLASS_CONTEXT, false, 2U) == true)
					{
						if (aki->serial_present == true)
						{
							status = QSC_ASN1_STATUS_INVALID_ENCODING;
							break;
						}

						if (child->length > sizeof(aki->serial) || child->value == (const uint8_t*)NULL)
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
		}

		if (root != (qsc_encoding_ber_element*)NULL)
		{
			qsc_encoding_ber_free_element(root);
		}
	}

	return status;
}

static qsc_asn1_status x509_parse_general_names(const qsc_x509_extension* extension, qsc_x509_general_name* entries, size_t* count, bool* present, bool* critical)
{
	qsc_encoding_ber_element* root;
	const qsc_encoding_ber_element* child;
	qsc_asn1_oid oid = { 0 };
	qsc_oid_id oidid;
	size_t consumed;
	size_t ecount;
	qsc_asn1_status status;

	root = (qsc_encoding_ber_element*)NULL;
	child = (const qsc_encoding_ber_element*)NULL;
	oidid = QSC_OID_ID_NONE;
	consumed = 0U;
	ecount = 0U;
	status = QSC_ASN1_STATUS_FAILURE;

	if (extension == (const qsc_x509_extension*)NULL || entries == (qsc_x509_general_name*)NULL || count == (size_t*)NULL || present == (bool*)NULL || critical == (bool*)NULL)
	{
		status = QSC_ASN1_STATUS_INVALID_INPUT;
	}
	else
	{
		root = qsc_encoding_der_decode_element(extension->value, extension->valuelen, &consumed);

		if (root == (qsc_encoding_ber_element*)NULL)
		{
			status = QSC_ASN1_STATUS_INVALID_ENCODING;
		}
		else if (consumed != extension->valuelen)
		{
			status = QSC_ASN1_STATUS_INVALID_LENGTH;
		}
		else
		{
			status = x509_require_sequence(root);

			if (status == QSC_ASN1_STATUS_SUCCESS)
			{
				*present = true;
				*critical = extension->critical;
				*count = 0U;

				for (size_t i = 0U; i < qsc_asn1_child_count(root) && ecount < QSC_X509_SAN_ENTRIES_MAX; ++i)
				{
					child = qsc_asn1_child_at(root, i);

					if (child == (const qsc_encoding_ber_element*)NULL)
					{
						status = QSC_ASN1_STATUS_NOT_FOUND;
						break;
					}

					qsc_memutils_clear((uint8_t*)&entries[ecount], sizeof(qsc_x509_general_name));

					if ((child->tagclass & 0xC0U) != QSC_ASN1_CLASS_CONTEXT)
					{
						continue;
					}

					entries[ecount].type = QSC_X509_GENERAL_NAME_NONE;

					if (child->tagnumber == 8U)
					{
						status = qsc_asn1_decode_oid(child, &oid);

						if (status == QSC_ASN1_STATUS_SUCCESS)
						{
							oidid = qsc_oid_identify(&oid);
							entries[ecount].type = QSC_X509_GENERAL_NAME_REGISTERED_ID;
							entries[ecount].oid = oidid;
							entries[ecount].registeredid = oid;
							entries[ecount].length = oid.length;
							++ecount;
						}
					}
					else if (child->tagnumber == 1U || child->tagnumber == 2U || child->tagnumber == 6U || child->tagnumber == 7U)
					{
						if (child->length <= QSC_X509_NAME_ATTRIBUTE_STRING_MAX && child->value != (const uint8_t*)NULL)
						{
							entries[ecount].type = (child->tagnumber == 1U) ? QSC_X509_GENERAL_NAME_RFC822_NAME :
								(child->tagnumber == 2U) ? QSC_X509_GENERAL_NAME_DNS_NAME :
								(child->tagnumber == 6U) ? QSC_X509_GENERAL_NAME_UNIFORM_RESOURCE_IDENTIFIER :
								QSC_X509_GENERAL_NAME_IP_ADDRESS;

							qsc_memutils_copy(entries[ecount].data, child->value, child->length);
							entries[ecount].length = child->length;
							++ecount;
						}
					}
				}

				if (status == QSC_ASN1_STATUS_SUCCESS)
				{
					*count = ecount;
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

static bool x509_extension_is_duplicate(const qsc_x509_extensions* extensions, const qsc_x509_extension* extension)
{
	bool res;

	res = false;

	if (extensions != (const qsc_x509_extensions*)NULL &&
		extension != (const qsc_x509_extension*)NULL)
	{
		for (size_t i = 0U; i < extensions->count; ++i)
		{
			const qsc_x509_extension* cur;

			cur = &extensions->entries[i];

			if (extension->type != QSC_X509_EXTENSION_UNKNOWN &&
				cur->type == extension->type)
			{
				res = true;
				break;
			}

			if (extension->type == QSC_X509_EXTENSION_UNKNOWN &&
				cur->type == QSC_X509_EXTENSION_UNKNOWN &&
				qsc_asn1_oid_compare(&cur->extension_oid, &extension->extension_oid) == true)
			{
				res = true;
				break;
			}
		}
	}

	return res;
}

static qsc_asn1_status x509_parse_extensions(const qsc_encoding_ber_element* element, qsc_x509_extensions* extensions)
{
	qsc_asn1_status status;
	qsc_x509_extension* ext;
	const qsc_encoding_ber_element* child;

	status = QSC_ASN1_STATUS_FAILURE;
	ext = (qsc_x509_extension*)NULL;
	child = (const qsc_encoding_ber_element*)NULL;

	if (element == (const qsc_encoding_ber_element*)NULL || extensions == (qsc_x509_extensions*)NULL)
	{
		status = QSC_ASN1_STATUS_INVALID_INPUT;
	}
	else
	{
		qsc_memutils_clear((uint8_t*)extensions, sizeof(qsc_x509_extensions));
		status = x509_require_sequence(element);

		if (status == QSC_ASN1_STATUS_SUCCESS)
		{
			for (size_t i = 0U; i < qsc_asn1_child_count(element) && extensions->count < QSC_X509_EXTENSIONS_MAX; ++i)
			{
				child = qsc_asn1_child_at(element, i);

				if (child == (const qsc_encoding_ber_element*)NULL)
				{
					status = QSC_ASN1_STATUS_NOT_FOUND;
					break;
				}

				ext = &extensions->entries[extensions->count];
				status = x509_decode_raw_extension(child, ext);

				if (status != QSC_ASN1_STATUS_SUCCESS)
				{
					break;
				}

				if (x509_extension_is_duplicate(extensions, ext) == true)
				{
					status = QSC_ASN1_STATUS_INVALID_ENCODING;
					break;
				}

				switch (ext->type)
				{
				case QSC_X509_EXTENSION_BASIC_CONSTRAINTS:
					status = x509_parse_basic_constraints(ext, &extensions->basicconstraints);
					break;
				case QSC_X509_EXTENSION_KEY_USAGE:
					status = x509_parse_key_usage(ext, &extensions->keyusage);
					break;
				case QSC_X509_EXTENSION_EXTENDED_KEY_USAGE:
					status = x509_parse_extended_key_usage(ext, &extensions->extendedkeyusage);
					break;
				case QSC_X509_EXTENSION_SUBJECT_KEY_IDENTIFIER:
					status = x509_parse_subject_key_identifier(ext, &extensions->subjectkeyidentifier);
					break;
				case QSC_X509_EXTENSION_AUTHORITY_KEY_IDENTIFIER:
					status = x509_parse_authority_key_identifier(ext, &extensions->authoritykeyidentifier);
					break;
				case QSC_X509_EXTENSION_SUBJECT_ALT_NAME:
					status = x509_parse_general_names(ext, extensions->subjectaltname.entries, &extensions->subjectaltname.count, &extensions->subjectaltname.present, &extensions->subjectaltname.critical);
					break;
				case QSC_X509_EXTENSION_ISSUER_ALT_NAME:
					status = x509_parse_general_names(ext, extensions->issueraltname.entries, &extensions->issueraltname.count, &extensions->issueraltname.present, &extensions->issueraltname.critical);
					break;
				default:
					status = QSC_ASN1_STATUS_SUCCESS;
				}

				if (status != QSC_ASN1_STATUS_SUCCESS)
				{
					break;
				}

				extensions->count += 1U;
			}

			if (status == QSC_ASN1_STATUS_SUCCESS && qsc_asn1_child_count(element) > QSC_X509_EXTENSIONS_MAX)
			{
				status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
			}
		}
	}

	return status;
}

static qsc_asn1_status x509_validate_implicit_bit_string_content(const qsc_encoding_ber_element* element)
{
	uint8_t unusedbits;
	uint8_t lastoctet;
	qsc_asn1_status status;

	status = QSC_ASN1_STATUS_SUCCESS;
	unusedbits = 0U;
	lastoctet = 0U;

	if (element == (const qsc_encoding_ber_element*)NULL)
	{
		status = QSC_ASN1_STATUS_INVALID_INPUT;
	}
	else if (element->length == 0U || element->value == (const uint8_t*)NULL)
	{
		status = QSC_ASN1_STATUS_INVALID_ENCODING;
	}
	else
	{
		unusedbits = element->value[0];

		if (unusedbits > 7U)
		{
			status = QSC_ASN1_STATUS_INVALID_ENCODING;
		}
		else if (element->length == 1U)
		{
			if (unusedbits != 0U)
			{
				status = QSC_ASN1_STATUS_INVALID_ENCODING;
			}
		}
		else if (unusedbits != 0U)
		{
			lastoctet = element->value[element->length - 1U];

			if ((lastoctet & ((1U << unusedbits) - 1U)) != 0U)
			{
				status = QSC_ASN1_STATUS_INVALID_ENCODING;
			}
		}
	}

	return status;
}

static qsc_asn1_status x509_parse_tbs_certificate(const qsc_encoding_ber_element* tbs, qsc_x509_certificate* certificate)
{
	qsc_asn1_status status;
	const qsc_encoding_ber_element* child;
	const qsc_encoding_ber_element* inner;
	size_t index;
	uint64_t version;

	status = QSC_ASN1_STATUS_FAILURE;
	child = (const qsc_encoding_ber_element*)NULL;
	inner = (const qsc_encoding_ber_element*)NULL;
	index = 0U;
	version = 0U;

	if (tbs == (const qsc_encoding_ber_element*)NULL || certificate == (qsc_x509_certificate*)NULL)
	{
		status = QSC_ASN1_STATUS_INVALID_INPUT;
	}
	else
	{
		status = x509_require_sequence(tbs);

		if (status == QSC_ASN1_STATUS_SUCCESS)
		{
			certificate->version = 1U;
			child = qsc_asn1_child_at(tbs, 0U);

			if (status == QSC_ASN1_STATUS_SUCCESS &&
				child != (const qsc_encoding_ber_element*)NULL &&
				qsc_asn1_element_is_tag(child, QSC_ASN1_CLASS_CONTEXT, true, 0U) == true)
			{
				status = qsc_asn1_get_explicit_child(child, &inner);

				if (status == QSC_ASN1_STATUS_SUCCESS)
				{
					status = qsc_asn1_decode_uint64(inner, &version);

					if (status == QSC_ASN1_STATUS_SUCCESS)
					{
						if (version > 2U)
						{
							status = QSC_ASN1_STATUS_OUT_OF_RANGE;
						}
						else
						{
							certificate->version = (uint32_t)version + 1U;
							index = 1U;
						}
					}
				}
			}

			if (status == QSC_ASN1_STATUS_SUCCESS)
			{
				child = qsc_asn1_child_at(tbs, index + 0U);
				status = x509_copy_unsigned_integer(child, certificate->serialnumber, sizeof(certificate->serialnumber), &certificate->serialnumberlen);
			}

			if (status == QSC_ASN1_STATUS_SUCCESS)
			{
				child = qsc_asn1_child_at(tbs, index + 1U);
				status = qsc_x509_signature_algorithm_decode(child, &certificate->tbsignature);
			}

			if (status == QSC_ASN1_STATUS_SUCCESS)
			{
				child = qsc_asn1_child_at(tbs, index + 2U);
				status = qsc_x509_name_parse(child, &certificate->issuer);
			}

			if (status == QSC_ASN1_STATUS_SUCCESS)
			{
				child = qsc_asn1_child_at(tbs, index + 3U);
				status = qsc_x509_validity_decode(&certificate->validity, child);
			}

			if (status == QSC_ASN1_STATUS_SUCCESS)
			{
				child = qsc_asn1_child_at(tbs, index + 4U);
				status = qsc_x509_name_parse(child, &certificate->subject);
			}

			if (status == QSC_ASN1_STATUS_SUCCESS)
			{
				child = qsc_asn1_child_at(tbs, index + 5U);
				status = qsc_x509_subject_public_key_info_decode(child, &certificate->subjectpublickeyinfo);
			}

			{
				bool seenissueruid;
				bool seensubjectuid;
				bool seenextensions;

				seenissueruid = false;
				seensubjectuid = false;
				seenextensions = false;

				for (size_t i = index + 6U; status == QSC_ASN1_STATUS_SUCCESS && i < qsc_asn1_child_count(tbs); ++i)
				{
					child = qsc_asn1_child_at(tbs, i);

					if (child == (const qsc_encoding_ber_element*)NULL)
					{
						status = QSC_ASN1_STATUS_NOT_FOUND;
						break;
					}

					if (qsc_asn1_element_is_tag(child, QSC_ASN1_CLASS_CONTEXT, false, 1U) == true)
					{
						if (certificate->version < 2U || seenissueruid == true)
						{
							status = QSC_ASN1_STATUS_INVALID_ENCODING;
							break;
						}

						status = x509_validate_implicit_bit_string_content(child);

						if (status != QSC_ASN1_STATUS_SUCCESS)
						{
							break;
						}

						certificate->issueruniqueid_present = true;
						seenissueruid = true;
					}
					else if (qsc_asn1_element_is_tag(child, QSC_ASN1_CLASS_CONTEXT, false, 2U) == true)
					{
						if (certificate->version < 2U || seensubjectuid == true)
						{
							status = QSC_ASN1_STATUS_INVALID_ENCODING;
							break;
						}

						status = x509_validate_implicit_bit_string_content(child);

						if (status != QSC_ASN1_STATUS_SUCCESS)
						{
							break;
						}

						certificate->subjectuniqueid_present = true;
						seensubjectuid = true;
					}
					else if (qsc_asn1_element_is_tag(child, QSC_ASN1_CLASS_CONTEXT, true, 3U) == true)
					{
						if (certificate->version < 3U || seenextensions == true)
						{
							status = QSC_ASN1_STATUS_INVALID_ENCODING;
							break;
						}

						status = qsc_asn1_get_explicit_child(child, &inner);

						if (status == QSC_ASN1_STATUS_SUCCESS)
						{
							status = x509_parse_extensions(inner, &certificate->extensions);

							if (status == QSC_ASN1_STATUS_SUCCESS)
							{
								seenextensions = true;
							}
						}
					}
					else
					{
						status = QSC_ASN1_STATUS_INVALID_TAG;
						break;
					}
				}
			}
		}
	}

	return status;
}

void qsc_x509_certificate_clear(qsc_x509_certificate* certificate)
{
	QSC_ASSERT(certificate != NULL);

	if (certificate != (qsc_x509_certificate*)NULL)
	{
		x509_certificate_release_preserved_der(certificate);
		qsc_memutils_secure_erase((uint8_t*)certificate, sizeof(qsc_x509_certificate));
	}
}

void qsc_x509_certificate_free(qsc_x509_certificate* certificate)
{
	qsc_x509_certificate_clear(certificate);
}

qsc_asn1_status qsc_x509_certificate_decode_der(const uint8_t* der, size_t derlen, qsc_x509_certificate* certificate)
{
	QSC_ASSERT(der != NULL);
	QSC_ASSERT(certificate != NULL);

	qsc_encoding_ber_element* root;
	const qsc_encoding_ber_element* child;
	const uint8_t* tbsraw;
	qsc_asn1_bit_string bitstr = { 0 };
	qsc_asn1_status status;

	root = (qsc_encoding_ber_element*)NULL;
	child = (const qsc_encoding_ber_element*)NULL;
	tbsraw = (const uint8_t*)NULL;
	status = QSC_ASN1_STATUS_FAILURE;

	if (der == (const uint8_t*)NULL || derlen == 0U || certificate == (qsc_x509_certificate*)NULL)
	{
		status = QSC_ASN1_STATUS_INVALID_INPUT;
	}
	else
	{
		qsc_x509_certificate_clear(certificate);
		certificate->der = der;
		certificate->derlen = derlen;

		status = qsc_asn1_der_decode_exact(der, derlen, &root);

		if (status == QSC_ASN1_STATUS_SUCCESS)
		{
			status = qsc_asn1_der_get_child_region(der, derlen, 0U, &tbsraw, &certificate->tbsdatalen);
		}

		if (status == QSC_ASN1_STATUS_SUCCESS)
		{
			status = x509_require_sequence(root);

			if (status == QSC_ASN1_STATUS_SUCCESS)
			{
				if (qsc_asn1_child_count(root) != 3U)
				{
					status = QSC_ASN1_STATUS_INVALID_LENGTH;
				}
			}

			if (status == QSC_ASN1_STATUS_SUCCESS)
			{
				child = qsc_asn1_child_at(root, 0U);

				if (child == (const qsc_encoding_ber_element*)NULL)
				{
					status = QSC_ASN1_STATUS_NOT_FOUND;
				}
				else
				{
					status = x509_parse_tbs_certificate(child, certificate);

					if (status == QSC_ASN1_STATUS_SUCCESS)
					{
						if (tbsraw == (const uint8_t*)NULL || certificate->tbsdatalen == 0U)
						{
							status = QSC_ASN1_STATUS_INVALID_ENCODING;
						}
						else
						{
							certificate->tbsdata = tbsraw;
						}
					}
				}
			}

			if (status == QSC_ASN1_STATUS_SUCCESS)
			{
				child = qsc_asn1_child_at(root, 1U);
				status = qsc_x509_signature_algorithm_decode(child, &certificate->signaturealgorithm);
			}

			if (status == QSC_ASN1_STATUS_SUCCESS)
			{
				if (qsc_x509_signature_algorithm_equal(&certificate->tbsignature, &certificate->signaturealgorithm) == false)
				{
					status = QSC_ASN1_STATUS_INVALID_ENCODING;
				}
			}

			if (status == QSC_ASN1_STATUS_SUCCESS)
			{
				child = qsc_asn1_child_at(root, 2U);
				status = qsc_asn1_decode_bit_string(child, &bitstr);

				if (status == QSC_ASN1_STATUS_SUCCESS)
				{
					if (bitstr.unused != 0U)
					{
						status = QSC_ASN1_STATUS_INVALID_ENCODING;
					}
					else if (bitstr.length > sizeof(certificate->signature))
					{
						status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
					}
					else
					{
						qsc_memutils_copy(certificate->signature, bitstr.data, bitstr.length);
						certificate->signaturelen = bitstr.length;
						certificate->signatureunusedbits = bitstr.unused;
					}
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

const qsc_x509_extension* qsc_x509_certificate_find_extension(const qsc_x509_certificate* certificate, qsc_x509_extension_type type)
{
	QSC_ASSERT(certificate != NULL);

	const qsc_x509_extension* extension;

	extension = (const qsc_x509_extension*)NULL;

	if (certificate != (const qsc_x509_certificate*)NULL)
	{
		for (size_t i = 0U; i < certificate->extensions.count; ++i)
		{
			if (certificate->extensions.entries[i].type == type)
			{
				extension = &certificate->extensions.entries[i];
				break;
			}
		}
	}

	return extension;
}
