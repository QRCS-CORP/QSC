#include "x509aia.h"
#include "asn1.h"
#include "encoding.h"
#include "memutils.h"
#include "qsccommon.h"

static bool x509_aia_oid_equals(const qsc_asn1_oid* oid, const uint8_t* data, size_t datalen)
{
    bool res;

    res = (oid != (const qsc_asn1_oid*)NULL &&
        data != (const uint8_t*)NULL &&
        oid->length == datalen &&
        qsc_memutils_are_equal(oid->data, data, datalen));

    return res;
}

bool qsc_x509_aia_get_ocsp_url(const uint8_t* ext, size_t extlen, char* url, size_t* urllen)
{
    QSC_ASSERT(ext != NULL);
    QSC_ASSERT(url != NULL);
    QSC_ASSERT(urllen != NULL);

    static const uint8_t OID_ID_AD_OCSP[] = { 0x2BU, 0x06U, 0x01U, 0x05U, 0x05U, 0x07U, 0x30U, 0x01U };
    qsc_encoding_ber_element* root;
    qsc_asn1_oid oid = { 0 };
    size_t consumed;
    bool res;
    size_t i;

    res = false;
    root = (qsc_encoding_ber_element*)NULL;

    if (ext != (const uint8_t*)NULL && extlen != 0U && url != (char*)NULL && urllen != (size_t*)NULL && *urllen != 0U)
    {
        url[0U] = '\0';
        consumed = 0U;
        root = qsc_encoding_ber_decode_element(ext, extlen, &consumed);

        if (root != (qsc_encoding_ber_element*)NULL && qsc_asn1_require_sequence(root, 1U, SIZE_MAX) == QSC_ASN1_STATUS_SUCCESS)
        {
            for (i = 0U; i < qsc_asn1_child_count(root); ++i)
            {
                const qsc_encoding_ber_element* ad;
                const qsc_encoding_ber_element* loc;

                ad = qsc_asn1_get_child(root, i);

                if (qsc_asn1_require_sequence(ad, 2U, 2U) != QSC_ASN1_STATUS_SUCCESS)
                {
                    continue;
                }

                if (qsc_asn1_decode_oid(qsc_asn1_get_child(ad, 0U), &oid) != QSC_ASN1_STATUS_SUCCESS ||
                    x509_aia_oid_equals(&oid, OID_ID_AD_OCSP, sizeof(OID_ID_AD_OCSP)) == false)
                {
                    continue;
                }

                loc = qsc_asn1_get_child(ad, 1U);

                if (loc != (const qsc_encoding_ber_element*)NULL &&
                    qsc_asn1_require_tag(loc, QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC, false, 6U) == QSC_ASN1_STATUS_SUCCESS &&
                    (loc->length + 1U) <= *urllen)
                {
                    qsc_memutils_copy(url, loc->value, loc->length);
                    url[loc->length] = '\0';
                    *urllen = loc->length;
                    res = true;
                    break;
                }
            }
        }

        if (root != (qsc_encoding_ber_element*)NULL)
        {
            qsc_encoding_ber_free_element(root);
        }
    }

    return res;
}
