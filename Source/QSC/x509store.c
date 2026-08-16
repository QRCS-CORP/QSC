#include "x509store.h"
#include "memutils.h"
#include "x509name.h"
#include "x509verify.h"

static bool x509_serial_equal(const uint8_t* left, size_t leftlen, const uint8_t* right, size_t rightlen)
{
    if (left == (const uint8_t*)NULL || right == (const uint8_t*)NULL || leftlen != rightlen)
    {
        return false;
    }

    return qsc_memutils_are_equal(left, right, leftlen);
}

static bool x509_certificate_equal(const qsc_x509_certificate* left, const qsc_x509_certificate* right)
{
    if (left == (const qsc_x509_certificate*)NULL || right == (const qsc_x509_certificate*)NULL)
    {
        return false;
    }

    if (left->der != (const uint8_t*)NULL && right->der != (const uint8_t*)NULL && left->derlen == right->derlen)
    {
        return qsc_memutils_are_equal(left->der, right->der, left->derlen);
    }

    return (left->serialnumberlen == right->serialnumberlen &&
        qsc_memutils_are_equal(left->serialnumber, right->serialnumber, left->serialnumberlen) == true &&
        qsc_x509_name_equals(&left->issuer, &right->issuer) == true &&
        qsc_x509_name_equals(&left->subject, &right->subject) == true);
}

static bool x509_aki_candidate_matches(const qsc_x509_certificate* issuer, const qsc_x509_certificate* subject)
{
    const qsc_x509_authority_key_identifier* aki;
    bool match;
    bool selectorpresent;

    match = true;
    selectorpresent = false;

    if (issuer == (const qsc_x509_certificate*)NULL || subject == (const qsc_x509_certificate*)NULL)
    {
        match = false;
    }
    else
    {
        aki = &subject->extensions.authoritykeyidentifier;

        if (aki->present == true && aki->keyidentifierlen != 0U)
        {
            selectorpresent = true;

            if (issuer->extensions.subjectkeyidentifier.present == false ||
                x509_serial_equal(issuer->extensions.subjectkeyidentifier.identifier, issuer->extensions.subjectkeyidentifier.identifierlen,
                    aki->keyidentifier, aki->keyidentifierlen) == false)
            {
                match = false;
            }
        }

        if (match == true && aki->present == true && aki->issuer_present == true && aki->issuername_present == true)
        {
            selectorpresent = true;

            if (qsc_x509_name_equals(&issuer->issuer, &aki->issuername) == false)
            {
                match = false;
            }
        }

        if (match == true && aki->present == true && aki->serial_present == true)
        {
            selectorpresent = true;

            if (x509_serial_equal(issuer->serialnumber, issuer->serialnumberlen, aki->serial, aki->seriallen) == false)
            {
                match = false;
            }
        }

        if (selectorpresent == false)
        {
            match = false;
        }
    }

    return match;
}

static bool x509_names_match_issuer_subject(const qsc_x509_certificate* issuer, const qsc_x509_certificate* subject)
{
    return (issuer != (const qsc_x509_certificate*)NULL &&
        subject != (const qsc_x509_certificate*)NULL &&
        qsc_x509_name_equals(&issuer->subject, &subject->issuer) == true);
}

static bool x509_anchor_matches(const qsc_x509_trust_anchor* anchor, const qsc_x509_certificate* certificate)
{
    if (anchor == (const qsc_x509_trust_anchor*)NULL || certificate == (const qsc_x509_certificate*)NULL)
    {
        return false;
    }

    return x509_names_match_issuer_subject(&anchor->certificate, certificate);
}

void qsc_x509_store_initialize(qsc_x509_store* store, qsc_x509_trust_anchor* anchors, size_t capacity)
{
    QSC_ASSERT(store != NULL);

    if (store != NULL)
    {
        store->anchors = anchors;
        store->count = 0U;          /* start empty */
        store->capacity = capacity; /* maximum slots */
    }
}

qsc_asn1_status qsc_x509_store_add_anchor(qsc_x509_store* store, const qsc_x509_certificate* certificate, bool selfsigned)
{
    if (store == (qsc_x509_store*)NULL || certificate == (const qsc_x509_certificate*)NULL || store->anchors == (qsc_x509_trust_anchor*)NULL)
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    if (store->count >= store->capacity)
    {
        return QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
    }

    store->anchors[store->count].certificate = *certificate;
    store->anchors[store->count].selfsigned = selfsigned;
    store->count += 1U;

    return QSC_ASN1_STATUS_SUCCESS;
}

const qsc_x509_trust_anchor* qsc_x509_store_find_anchor_by_subject(const qsc_x509_store* store, const qsc_x509_name* subject)
{
    size_t i;

    if (store == (const qsc_x509_store*)NULL || subject == (const qsc_x509_name*)NULL)
    {
        return (const qsc_x509_trust_anchor*)NULL;
    }

    for (i = 0U; i < store->count; ++i)
    {
        if (qsc_x509_name_equals(&store->anchors[i].certificate.subject, subject) == true)
        {
            return &store->anchors[i];
        }
    }

    return (const qsc_x509_trust_anchor*)NULL;
}

const qsc_x509_trust_anchor* qsc_x509_store_find_anchor_by_subject_key_identifier(const qsc_x509_store* store, const uint8_t* keyidentifier, size_t keyidentifierlen)
{
    size_t i;

    if (store == (const qsc_x509_store*)NULL || keyidentifier == (const uint8_t*)NULL || keyidentifierlen == 0U)
    {
        return (const qsc_x509_trust_anchor*)NULL;
    }

    for (i = 0U; i < store->count; ++i)
    {
        const qsc_x509_subject_key_identifier* ski = &store->anchors[i].certificate.extensions.subjectkeyidentifier;

        if (ski->present == true && ski->identifierlen == keyidentifierlen &&
            qsc_memutils_are_equal(ski->identifier, keyidentifier, keyidentifierlen) == true)
        {
            return &store->anchors[i];
        }
    }

    return (const qsc_x509_trust_anchor*)NULL;
}

bool qsc_x509_store_contains_anchor(const qsc_x509_store* store, const qsc_x509_certificate* certificate)
{
    size_t i;

    if (store == (const qsc_x509_store*)NULL || certificate == (const qsc_x509_certificate*)NULL)
    {
        return false;
    }

    for (i = 0U; i < store->count; ++i)
    {
        if (x509_certificate_equal(&store->anchors[i].certificate, certificate) == true)
        {
            return true;
        }
    }

    return false;
}

const qsc_x509_trust_anchor* qsc_x509_store_find_anchor_for_certificate(const qsc_x509_store* store, const qsc_x509_certificate* certificate)
{
    const qsc_x509_trust_anchor* anchor;
    size_t i;

    anchor = (const qsc_x509_trust_anchor*)NULL;

    if (store != (const qsc_x509_store*)NULL && certificate != (const qsc_x509_certificate*)NULL)
    {
        for (i = 0U; i < store->count; ++i)
        {
            if (x509_names_match_issuer_subject(&store->anchors[i].certificate, certificate) == true &&
                x509_aki_candidate_matches(&store->anchors[i].certificate, certificate) == true)
            {
                anchor = &store->anchors[i];
                break;
            }
        }

        if (anchor == (const qsc_x509_trust_anchor*)NULL)
        {
            for (i = 0U; i < store->count; ++i)
            {
                if (x509_anchor_matches(&store->anchors[i], certificate) == true)
                {
                    anchor = &store->anchors[i];
                    break;
                }
            }
        }
    }

    return anchor;
}

const qsc_x509_certificate* qsc_x509_store_find_issuer(const qsc_x509_store* store, const qsc_x509_certificate* certificate)
{
    const qsc_x509_trust_anchor* anchor;

    anchor = qsc_x509_store_find_anchor_for_certificate(store, certificate);
    return (anchor == (const qsc_x509_trust_anchor*)NULL) ? (const qsc_x509_certificate*)NULL : &anchor->certificate;
}

qsc_x509_verify_status qsc_x509_chain_build(const qsc_x509_certificate* leaf, const qsc_x509_certificate* intermediates, size_t intermediatecount,
    const qsc_x509_store* store, qsc_x509_certificate* output, size_t outputcount, qsc_x509_chain* chain)
{
    const qsc_x509_certificate* current;
    size_t depth;

    if (leaf == (const qsc_x509_certificate*)NULL || output == (qsc_x509_certificate*)NULL || chain == (qsc_x509_chain*)NULL || outputcount == 0U)
    {
        return QSC_X509_VERIFY_STATUS_INVALID_INPUT;
    }

    output[0] = *leaf;
    chain->certificates = output;
    chain->count = 1U;
    current = leaf;

    for (depth = 1U; depth < outputcount; ++depth)
    {
        const qsc_x509_certificate* issuer;
        size_t i;
        bool seen;

        issuer = (const qsc_x509_certificate*)NULL;
        seen = false;

        for (i = 0U; i < intermediatecount; ++i)
        {
            if (x509_names_match_issuer_subject(&intermediates[i], current) == true &&
                x509_aki_candidate_matches(&intermediates[i], current) == true)
            {
                issuer = &intermediates[i];
                break;
            }
        }

        if (issuer == (const qsc_x509_certificate*)NULL)
        {
            for (i = 0U; i < intermediatecount; ++i)
            {
                if (x509_names_match_issuer_subject(&intermediates[i], current) == true)
                {
                    issuer = &intermediates[i];
                    break;
                }
            }
        }

        if (issuer == (const qsc_x509_certificate*)NULL && store != (const qsc_x509_store*)NULL)
        {
            issuer = qsc_x509_store_find_issuer(store, current);
        }

        if (issuer == (const qsc_x509_certificate*)NULL)
        {
            break;
        }

        for (i = 0U; i < chain->count; ++i)
        {
            if (x509_certificate_equal(&output[i], issuer) == true)
            {
                seen = true;
                break;
            }
        }

        if (seen == true)
        {
            return QSC_X509_VERIFY_STATUS_CHAIN_LOOP;
        }

        output[chain->count] = *issuer;
        chain->count += 1U;
        current = issuer;

        if ((store != (const qsc_x509_store*)NULL && qsc_x509_store_contains_anchor(store, current) == true) ||
            qsc_x509_certificate_is_self_issued(current) == true)
        {
            break;
        }
    }

    if (chain->count == outputcount && qsc_x509_certificate_is_self_issued(&output[chain->count - 1U]) == false &&
        (store == (const qsc_x509_store*)NULL || qsc_x509_store_contains_anchor(store, &output[chain->count - 1U]) == false))
    {
        return QSC_X509_VERIFY_STATUS_PATH_LENGTH_EXCEEDED;
    }

    return QSC_X509_VERIFY_STATUS_SUCCESS;
}
