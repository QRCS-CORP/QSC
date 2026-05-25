#include "tlsgroups.h"
#include "csp.h"
#include "memutils.h"
#include "eddh.h"
#include "kyber.h"
#include "ecdh.h"

/* backend dispatch: each supported group maps to either a pure classical ECDH,
 * a pure KEM, or a hybrid that concatenates both. The descriptor table encodes
 * the wire sizes so encoders can validate peer key shares before invoking the primitive. */

static const qsc_tls_group_descriptor tls_groups_x25519 = {
    qsc_tls_group_x25519,
    "x25519",
    32U,    /* private */
    32U,    /* client public */
    32U,    /* server public */
    32U,    /* shared secret */
    true,   /* classical */
    false,
    false,
    true
};

#if defined(QSC_ECDH_S1P256)
/* secp256r1 wire format per RFC 8446 4.2.8.2: uncompressed SEC1 point
 * 0x04 || X(32) || Y(32) = 65 bytes on the wire.
 * QSC's qsc_ecdh stores the raw X||Y (64 bytes); we wrap with the 0x04 prefix
 * when emitting on the wire and strip it on receive. */
static const qsc_tls_group_descriptor tls_groups_secp256r1 = {
    qsc_tls_group_secp256r1,
    "secp256r1",
    QSC_ECDH_PRIVATEKEY_SIZE,
    65U,    /* client public = uncompressed SEC1 point */
    65U,    /* server public = uncompressed SEC1 point */
    QSC_ECDH_SHAREDSECRET_SIZE,
    true,
    false,
    false,
    true
};
#endif

#if defined(QSC_KYBER_S1K2P512) || defined(QSC_KYBER_S3K3P768) || defined(QSC_KYBER_S5K4P1024)
static const qsc_tls_group_descriptor tls_groups_mlkem = {
    qsc_tls_group_mlkem768,
    "mlkem768",
    QSC_KYBER_PRIVATEKEY_SIZE,
    QSC_KYBER_PUBLICKEY_SIZE,
    QSC_KYBER_CIPHERTEXT_SIZE,
    QSC_KYBER_SHAREDSECRET_SIZE,
    false,
    true,
    false,
    true
};

/* Hybrid x25519 + ML-KEM-768 per draft-ietf-tls-hybrid-design.
 * Client key share: classical_pub || kem_pub.
 * Server key share: classical_pub || kem_ct.
 * Shared secret: classical_ss || kem_ss.
 */
static const qsc_tls_group_descriptor tls_groups_x25519_mlkem = {
    qsc_tls_group_x25519_mlkem768,
    "x25519_mlkem768",
    32U + QSC_KYBER_PRIVATEKEY_SIZE,
    32U + QSC_KYBER_PUBLICKEY_SIZE,
    32U + QSC_KYBER_CIPHERTEXT_SIZE,
    32U + QSC_KYBER_SHAREDSECRET_SIZE,
    true,
    true,
    true,
    true
};
#endif

const qsc_tls_group_descriptor* qsc_tls_groups_descriptor_get(qsc_tls_named_group group)
{
    const qsc_tls_group_descriptor* res;

    res = NULL;

    switch (group)
    {
        case qsc_tls_group_x25519:
        {
            res = &tls_groups_x25519;
            break;
        }
    #if defined(QSC_ECDH_S1P256)
        case qsc_tls_group_secp256r1:
        {
            res = &tls_groups_secp256r1;
            break;
        }
    #endif
    #if defined(QSC_KYBER_S1K2P512) || defined(QSC_KYBER_S3K3P768) || defined(QSC_KYBER_S5K4P1024)
        case qsc_tls_group_mlkem768:
        {
            res = &tls_groups_mlkem;
            break;
        }
        case qsc_tls_group_x25519_mlkem768:
        {
            res = &tls_groups_x25519_mlkem;
            break;
        }
    #endif
        default:
        {
            break;
        }
    }

    return res;
}

bool qsc_tls_groups_is_supported(qsc_tls_named_group group)
{
    const qsc_tls_group_descriptor* d;

    d = qsc_tls_groups_descriptor_get(group);

    return (d != NULL && d->supported);
}

qsc_tls_status qsc_tls_groups_generate_client_keypair(qsc_tls_key_exchange_state* state, qsc_tls_named_group group)
{
    QSC_ASSERT(state != NULL);

    const qsc_tls_group_descriptor* d;
    qsc_tls_status status;
    bool res;

    status = qsc_tls_status_success;
    res = false;

    if (state == NULL)
    {
        status = qsc_tls_status_invalid_input;
    }
    else
    {
        d = qsc_tls_groups_descriptor_get(group);

        if (d == NULL || d->supported == false)
        {
            status = qsc_tls_status_not_supported;
        }
        else
        {
            qsc_memutils_clear(state, sizeof(*state));
            state->group = group;

            switch (group)
            {
            case qsc_tls_group_x25519:
            {
                res = qsc_eddh_generate_keypair(state->publicshare, state->privatekey, qsc_csp_generate);

                if (res == true)
                {
                    state->privatekeylen = 32U;
                    state->publicsharelen = 32U;
                    state->initialized = true;
                }

                break;
            }
#if defined(QSC_ECDH_S1P256)
            case qsc_tls_group_secp256r1:
            {
                /* qsc_ecdh produces raw X||Y (64 bytes). Wire format per RFC 8446 4.2.8.2
                 * is the uncompressed SEC1 point: 0x04 || X || Y = 65 bytes. */
                uint8_t rawpub[QSC_ECDH_PUBLICKEY_SIZE] = { 0U };

                res = qsc_ecdh_generate_keypair(rawpub, state->privatekey, qsc_csp_generate);

                if (res == true)
                {
                    state->publicshare[0] = 0x04U;
                    qsc_memutils_copy(state->publicshare + 1U, rawpub, QSC_ECDH_PUBLICKEY_SIZE);
                    state->privatekeylen = QSC_ECDH_PRIVATEKEY_SIZE;
                    state->publicsharelen = 1U + QSC_ECDH_PUBLICKEY_SIZE;
                    state->initialized = true;
                }

                qsc_memutils_secure_erase(rawpub, sizeof(rawpub));

                break;
            }
#endif
#if defined(QSC_KYBER_S1K2P512) || defined(QSC_KYBER_S3K3P768) || defined(QSC_KYBER_S5K4P1024)
            case qsc_tls_group_mlkem768:
            {
                res = qsc_kyber_generate_keypair(state->publicshare, state->privatekey, qsc_csp_generate);

                if (res == true)
                {
                    state->privatekeylen = QSC_KYBER_PRIVATEKEY_SIZE;
                    state->publicsharelen = QSC_KYBER_PUBLICKEY_SIZE;
                    state->initialized = true;
                }

                break;
            }
            case qsc_tls_group_x25519_mlkem768:
            {
                /* classical segment first, then KEM public. */
                res = qsc_eddh_generate_keypair(state->publicshare, state->privatekey, qsc_csp_generate);

                if (res)
                {
                    res = qsc_kyber_generate_keypair(state->publicshare + 32U, state->privatekey + 32U, qsc_csp_generate);
                }

                if (res)
                {
                    state->privatekeylen = 32U + QSC_KYBER_PRIVATEKEY_SIZE;
                    state->publicsharelen = 32U + QSC_KYBER_PUBLICKEY_SIZE;
                    state->initialized = true;
                }

                break;
            }
#endif
            default:
            {
                status = qsc_tls_status_not_supported;
                break;
            }
            }

            if (status == qsc_tls_status_success && !res)
            {
                status = qsc_tls_status_failure;
            }
        }
    }

    return status;
}

qsc_tls_status qsc_tls_groups_client_derive_shared_secret(qsc_tls_key_exchange_state* state, const uint8_t* serverkeyshare, size_t serverkeysharelen, 
    uint8_t* sharedsecret, size_t sharedsecretlen, size_t* written)
{
    QSC_ASSERT(state != NULL);
    QSC_ASSERT(serverkeyshare != NULL);
    QSC_ASSERT(sharedsecret != NULL);
    QSC_ASSERT(written != NULL);

    const qsc_tls_group_descriptor* d;
    qsc_tls_status status;
    bool res;

    status = qsc_tls_status_success;
    res = false;

    if (written != NULL) 
    { 
        *written = 0U; 
    }

    if (state == NULL || serverkeyshare == NULL || sharedsecret == NULL || written == NULL)
    {
        status = qsc_tls_status_invalid_input;
    }
    else if (state->initialized == false)
    {
        status = qsc_tls_status_invalid_state;
    }
    else
    {
        d = qsc_tls_groups_descriptor_get(state->group);

        if (d == NULL)
        {
            status = qsc_tls_status_not_supported;
        }
        else if (serverkeysharelen != d->serverpublicsize)
        {
            status = qsc_tls_status_invalid_length;
        }
        else if (sharedsecretlen < d->sharedsecretsize)
        {
            status = qsc_tls_status_buffer_too_small;
        }
        else
        {
            switch (state->group)
            {
            case qsc_tls_group_x25519:
            {
                res = qsc_eddh_key_exchange(sharedsecret, state->privatekey, serverkeyshare);

                if (res == true)
                {
                    *written = 32U;
                }

                break;
            }
#if defined(QSC_ECDH_S1P256)
            case qsc_tls_group_secp256r1:
            {
                /* server key share arrives as 65-byte uncompressed SEC1 point 0x04||X||Y.
                 * strip the 0x04 and feed the raw X||Y into qsc_ecdh_key_exchange. */
                if (serverkeyshare[0] != 0x04U)
                {
                    status = qsc_tls_status_invalid_message;
                }
                else
                {
                    res = qsc_ecdh_key_exchange(sharedsecret, state->privatekey, serverkeyshare + 1U);

                    if (res == true)
                    {
                        *written = QSC_ECDH_SHAREDSECRET_SIZE;
                    }
                }

                break;
            }
#endif
#if defined(QSC_KYBER_S1K2P512) || defined(QSC_KYBER_S3K3P768) || defined(QSC_KYBER_S5K4P1024)
            case qsc_tls_group_mlkem768:
            {
                res = qsc_kyber_decapsulate(sharedsecret, serverkeyshare, state->privatekey);

                if (res == true)
                {
                    *written = QSC_KYBER_SHAREDSECRET_SIZE;
                }

                break;
            }
            case qsc_tls_group_x25519_mlkem768:
            {
                /* classical portion */
                res = qsc_eddh_key_exchange(sharedsecret, state->privatekey, serverkeyshare);

                if (res == true)
                {
                    /* KEM portion: decapsulate the ciphertext that follows the classical half. */
                    res = qsc_kyber_decapsulate(sharedsecret + 32U, serverkeyshare + 32U, state->privatekey + 32U);

                    if (res == true)
                    { 
                        *written = 32U + QSC_KYBER_SHAREDSECRET_SIZE; 
                    }
                }

                break;
            }
#endif
            default:
            {
                status = qsc_tls_status_not_supported;

                break;
            }
            }

            if (status == qsc_tls_status_success && !res)
            {
                status = qsc_tls_status_authentication_failure;
            }
        }
    }

    return status;
}

qsc_tls_status qsc_tls_groups_server_respond(qsc_tls_named_group group, const uint8_t* clientkeyshare, size_t clientkeysharelen, uint8_t* serverkeyshare, 
    size_t serverkeysharelen, size_t* serverkeysharewritten, uint8_t* sharedsecret, size_t sharedsecretlen, size_t* sharedsecretwritten)
{
    QSC_ASSERT(clientkeyshare != NULL);
    QSC_ASSERT(serverkeyshare != NULL);
    QSC_ASSERT(sharedsecret != NULL);
    QSC_ASSERT(serverkeysharewritten != NULL);
    QSC_ASSERT(sharedsecretwritten != NULL);

    qsc_tls_status status;
    const qsc_tls_group_descriptor* d;
    uint8_t serverpriv[QSC_TLS_MAX_PRIVATE_KEY_SIZE];
    bool res;

    status = qsc_tls_status_success;
    res = false;

    if (serverkeysharewritten != NULL) 
    { 
        *serverkeysharewritten = 0U; 
    }

    if (sharedsecretwritten != NULL) 
    { 
        *sharedsecretwritten = 0U; 
    }

    if (clientkeyshare == NULL || serverkeyshare == NULL || sharedsecret == NULL || serverkeysharewritten == NULL || sharedsecretwritten == NULL)
    {
        status = qsc_tls_status_invalid_input;
    }
    else
    {
        d = qsc_tls_groups_descriptor_get(group);

        if (d == NULL)
        {
            status = qsc_tls_status_not_supported;
        }
        else if (clientkeysharelen != d->clientpublicsize)
        {
            status = qsc_tls_status_invalid_length;
        }
        else if (serverkeysharelen < d->serverpublicsize || sharedsecretlen < d->sharedsecretsize)
        {
            status = qsc_tls_status_buffer_too_small;
        }
        else
        {
            qsc_memutils_clear(serverpriv, sizeof(serverpriv));

            switch (group)
            {
            case qsc_tls_group_x25519:
            {
                /* generate ephemeral server key, derive, emit public. */
                res = qsc_eddh_generate_keypair(serverkeyshare, serverpriv, qsc_csp_generate);

                if (res)
                {
                    res = qsc_eddh_key_exchange(sharedsecret, serverpriv, clientkeyshare);

                    if (res == true)
                    {
                        *serverkeysharewritten = 32U;
                        *sharedsecretwritten = 32U;
                    }
                }

                break;
            }
#if defined(QSC_ECDH_S1P256)
            case qsc_tls_group_secp256r1:
            {
                uint8_t serverrawpub[QSC_ECDH_PUBLICKEY_SIZE] = { 0U };

                /* client share arrives as 0x04||X||Y (65 bytes); reject if marker wrong. */
                if (clientkeyshare[0] != 0x04U)
                {
                    status = qsc_tls_status_invalid_message;
                    break;
                }

                /* generate ephemeral ECDH keypair, compute shared secret, write response
                 * to wire with the 0x04 uncompressed-point marker prefix. */

                res = qsc_ecdh_generate_keypair(serverrawpub, serverpriv, qsc_csp_generate);

                if (res == true)
                {
                    res = qsc_ecdh_key_exchange(sharedsecret, serverpriv, clientkeyshare + 1U);

                    if (res == true)
                    {
                        serverkeyshare[0] = 0x04U;
                        qsc_memutils_copy(serverkeyshare + 1U, serverrawpub, QSC_ECDH_PUBLICKEY_SIZE);
                        *serverkeysharewritten = 1U + QSC_ECDH_PUBLICKEY_SIZE;
                        *sharedsecretwritten = QSC_ECDH_SHAREDSECRET_SIZE;
                    }
                }
                qsc_memutils_secure_erase(serverrawpub, sizeof(serverrawpub));

                break;
            }
#endif
#if defined(QSC_KYBER_S1K2P512) || defined(QSC_KYBER_S3K3P768) || defined(QSC_KYBER_S5K4P1024)
            case qsc_tls_group_mlkem768:
            {
                /* encapsulate against the client's public key. */
                res = qsc_kyber_encapsulate(sharedsecret, serverkeyshare, clientkeyshare, qsc_csp_generate);

                if (res == true)
                {
                    *serverkeysharewritten = QSC_KYBER_CIPHERTEXT_SIZE;
                    *sharedsecretwritten = QSC_KYBER_SHAREDSECRET_SIZE;
                }

                break;
            }
            case qsc_tls_group_x25519_mlkem768:
            {
                /* classical first. */
                res = qsc_eddh_generate_keypair(serverkeyshare, serverpriv, qsc_csp_generate);

                if (res == true)
                {
                    res = qsc_eddh_key_exchange(sharedsecret, serverpriv, clientkeyshare);
                }

                if (res == true)
                {
                    /* then KEM encapsulation into the server key share tail and the shared secret tail. */
                    res = qsc_kyber_encapsulate(sharedsecret + 32U, serverkeyshare + 32U, clientkeyshare + 32U, qsc_csp_generate);
                }

                if (res == true)
                {
                    *serverkeysharewritten = 32U + QSC_KYBER_CIPHERTEXT_SIZE;
                    *sharedsecretwritten = 32U + QSC_KYBER_SHAREDSECRET_SIZE;
                }

                break;
            }
#endif
            default:
            {
                status = qsc_tls_status_not_supported;
                break;
            }
            }

            if (status == qsc_tls_status_success && !res)
            {
                status = qsc_tls_status_authentication_failure;
            }

            qsc_memutils_secure_erase(serverpriv, sizeof(serverpriv));
        }
    }

    return status;
}

void qsc_tls_groups_key_exchange_state_dispose(qsc_tls_key_exchange_state* state)
{
    QSC_ASSERT(state != NULL);

    if (state != NULL)
    {
        qsc_memutils_secure_erase(state, sizeof(*state));
    }
}
