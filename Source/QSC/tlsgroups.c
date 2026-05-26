#include "tlsgroups.h"
#include "csp.h"
#include "memutils.h"
#include "eddh.h"
#include "kyber.h"
#include "ecdh.h"
#include "ecdhp384base.h"
#include "eddh448base.h"

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

static const qsc_tls_group_descriptor tls_groups_x448 = {
    qsc_tls_group_x448,
    "x448",
    QSC_X448_PRIVATEKEY_SIZE,
    QSC_X448_PUBLICKEY_SIZE,
    QSC_X448_PUBLICKEY_SIZE,
    QSC_X448_SECRET_SIZE,
    true,
    false,
    false,
    true
};

static const qsc_tls_group_descriptor tls_groups_secp384r1 = {
    qsc_tls_group_secp384r1,
    "secp384r1",
    QSC_ECDHP384_PRIVATEKEY_SIZE,
    1U + QSC_ECDHP384_PUBLICKEY_SIZE,
    1U + QSC_ECDHP384_PUBLICKEY_SIZE,
    QSC_ECDHP384_SHAREDSECRET_SIZE,
    true,
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

#   if defined(QSC_KYBER_S1K2P512)
#   define QSC_TLS_ACTIVE_MLKEM_GROUP qsc_tls_group_mlkem512
#   define QSC_TLS_ACTIVE_MLKEM_NAME "mlkem512"
#   elif defined(QSC_KYBER_S5K4P1024)
#   define QSC_TLS_ACTIVE_MLKEM_GROUP qsc_tls_group_mlkem1024
#   define QSC_TLS_ACTIVE_MLKEM_NAME "mlkem1024"
#   else
#   define QSC_TLS_ACTIVE_MLKEM_GROUP qsc_tls_group_mlkem768
#   define QSC_TLS_ACTIVE_MLKEM_NAME "mlkem768"
#   endif

static const qsc_tls_group_descriptor tls_groups_mlkem = {
    QSC_TLS_ACTIVE_MLKEM_GROUP,
    QSC_TLS_ACTIVE_MLKEM_NAME,
    QSC_KYBER_PRIVATEKEY_SIZE,
    QSC_KYBER_PUBLICKEY_SIZE,
    QSC_KYBER_CIPHERTEXT_SIZE,
    QSC_KYBER_SHAREDSECRET_SIZE,
    false,
    true,
    false,
    true
};

#   if defined(QSC_KYBER_S3K3P768)
/* Hybrid x25519 + ML-KEM-768 per OpenSSL/TLS hybrid group encoding.
 * Client key share: kem_pub || classical_pub.
 * Server key share: kem_ct || classical_pub.
 * Shared secret: kem_ss || classical_ss.
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

#       if defined(QSC_ECDH_S1P256)
/* Hybrid secp256r1 + ML-KEM-768 per OpenSSL/TLS hybrid group encoding.
 * Client key share: uncompressed_sec1_p256_pub || kem_pub.
 * Server key share: uncompressed_sec1_p256_pub || kem_ct.
 * Shared secret: p256_ss || kem_ss.
 */
static const qsc_tls_group_descriptor tls_groups_secp256r1_mlkem = {
    qsc_tls_group_secp256r1_mlkem768,
    "secp256r1_mlkem768",
    QSC_ECDH_PRIVATEKEY_SIZE + QSC_KYBER_PRIVATEKEY_SIZE,
    65U + QSC_KYBER_PUBLICKEY_SIZE,
    65U + QSC_KYBER_CIPHERTEXT_SIZE,
    QSC_ECDH_SHAREDSECRET_SIZE + QSC_KYBER_SHAREDSECRET_SIZE,
    true,
    true,
    true,
    true
};
#       endif
#   endif

#   if defined(QSC_KYBER_S5K4P1024)
/* Hybrid secp384r1 + ML-KEM-1024 per OpenSSL/TLS hybrid group encoding.
 * Client key share: uncompressed_sec1_p384_pub || kem_pub.
 * Server key share: uncompressed_sec1_p384_pub || kem_ct.
 * Shared secret: p384_ss || kem_ss.
 */
static const qsc_tls_group_descriptor tls_groups_secp384r1_mlkem1024 = {
    qsc_tls_group_secp384r1_mlkem1024,
    "secp384r1_mlkem1024",
    QSC_ECDHP384_PRIVATEKEY_SIZE + QSC_KYBER_PRIVATEKEY_SIZE,
    1U + QSC_ECDHP384_PUBLICKEY_SIZE + QSC_KYBER_PUBLICKEY_SIZE,
    1U + QSC_ECDHP384_PUBLICKEY_SIZE + QSC_KYBER_CIPHERTEXT_SIZE,
    QSC_ECDHP384_SHAREDSECRET_SIZE + QSC_KYBER_SHAREDSECRET_SIZE,
    true,
    true,
    true,
    true
};
#   endif
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
        case qsc_tls_group_x448:
        {
            res = &tls_groups_x448;
            break;
        }
        case qsc_tls_group_secp384r1:
        {
            res = &tls_groups_secp384r1;
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
        case QSC_TLS_ACTIVE_MLKEM_GROUP:
        {
            res = &tls_groups_mlkem;
            break;
        }
    #if defined(QSC_KYBER_S3K3P768)
        case qsc_tls_group_x25519_mlkem768:
        {
            res = &tls_groups_x25519_mlkem;
            break;
        }
    #if defined(QSC_ECDH_S1P256)
        case qsc_tls_group_secp256r1_mlkem768:
        {
            res = &tls_groups_secp256r1_mlkem;
            break;
        }
    #endif
    #endif
    #if defined(QSC_KYBER_S5K4P1024)
        case qsc_tls_group_secp384r1_mlkem1024:
        {
            res = &tls_groups_secp384r1_mlkem1024;
            break;
        }
    #endif
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
            case qsc_tls_group_x448:
            {
                qsc_x448_generate_keypair(state->publicshare, state->privatekey, qsc_csp_generate);
                state->privatekeylen = QSC_X448_PRIVATEKEY_SIZE;
                state->publicsharelen = QSC_X448_PUBLICKEY_SIZE;
                state->initialized = true;
                res = true;

                break;
            }
            case qsc_tls_group_secp384r1:
            {
                uint8_t rawpub[QSC_ECDHP384_PUBLICKEY_SIZE] = { 0U };

                qsc_p384_generate_keypair(rawpub, state->privatekey, qsc_csp_generate);
                state->publicshare[0] = 0x04U;
                qsc_memutils_copy(state->publicshare + 1U, rawpub, QSC_ECDHP384_PUBLICKEY_SIZE);
                state->privatekeylen = QSC_ECDHP384_PRIVATEKEY_SIZE;
                state->publicsharelen = 1U + QSC_ECDHP384_PUBLICKEY_SIZE;
                state->initialized = true;
                res = true;

                qsc_memutils_secure_erase(rawpub, sizeof(rawpub));

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
            case QSC_TLS_ACTIVE_MLKEM_GROUP:
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
                /* OpenSSL-compatible hybrid wire order: KEM public first, then classical public.
                 * Private storage mirrors that order: KEM private first, then X25519 private. */
                res = qsc_kyber_generate_keypair(state->publicshare, state->privatekey, qsc_csp_generate);

                if (res == true)
                {
                    res = qsc_eddh_generate_keypair(state->publicshare + QSC_KYBER_PUBLICKEY_SIZE,
                        state->privatekey + QSC_KYBER_PRIVATEKEY_SIZE, qsc_csp_generate);
                }

                if (res == true)
                {
                    state->privatekeylen = QSC_KYBER_PRIVATEKEY_SIZE + 32U;
                    state->publicsharelen = QSC_KYBER_PUBLICKEY_SIZE + 32U;
                    state->initialized = true;
                }

                break;
            }
#   if defined(QSC_ECDH_S1P256)
            case qsc_tls_group_secp256r1_mlkem768:
            {
                uint8_t rawpub[QSC_ECDH_PUBLICKEY_SIZE] = { 0U };

                /* OpenSSL-compatible hybrid wire order: SEC1 P-256 public first, then KEM public. */
                res = qsc_ecdh_generate_keypair(rawpub, state->privatekey, qsc_csp_generate);

                if (res == true)
                {
                    state->publicshare[0] = 0x04U;
                    qsc_memutils_copy(state->publicshare + 1U, rawpub, QSC_ECDH_PUBLICKEY_SIZE);
                    res = qsc_kyber_generate_keypair(state->publicshare + 1U + QSC_ECDH_PUBLICKEY_SIZE,
                        state->privatekey + QSC_ECDH_PRIVATEKEY_SIZE, qsc_csp_generate);
                }

                if (res == true)
                {
                    state->privatekeylen = QSC_ECDH_PRIVATEKEY_SIZE + QSC_KYBER_PRIVATEKEY_SIZE;
                    state->publicsharelen = 1U + QSC_ECDH_PUBLICKEY_SIZE + QSC_KYBER_PUBLICKEY_SIZE;
                    state->initialized = true;
                }

                qsc_memutils_secure_erase(rawpub, sizeof(rawpub));

                break;
            }
#   endif
#   if defined(QSC_KYBER_S5K4P1024)
            case qsc_tls_group_secp384r1_mlkem1024:
            {
                uint8_t rawpub[QSC_ECDHP384_PUBLICKEY_SIZE] = { 0U };

                res = true;
                qsc_p384_generate_keypair(rawpub, state->privatekey, qsc_csp_generate);

                if (res == true)
                {
                    state->publicshare[0] = 0x04U;
                    qsc_memutils_copy(state->publicshare + 1U, rawpub, QSC_ECDHP384_PUBLICKEY_SIZE);
                    res = qsc_kyber_generate_keypair(state->publicshare + 1U + QSC_ECDHP384_PUBLICKEY_SIZE,
                        state->privatekey + QSC_ECDHP384_PRIVATEKEY_SIZE, qsc_csp_generate);
                }

                if (res == true)
                {
                    state->privatekeylen = QSC_ECDHP384_PRIVATEKEY_SIZE + QSC_KYBER_PRIVATEKEY_SIZE;
                    state->publicsharelen = 1U + QSC_ECDHP384_PUBLICKEY_SIZE + QSC_KYBER_PUBLICKEY_SIZE;
                    state->initialized = true;
                }

                qsc_memutils_secure_erase(rawpub, sizeof(rawpub));

                break;
            }
#   endif
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

qsc_tls_status qsc_tls_groups_client_derive_shared_secret(qsc_tls_key_exchange_state* state, const uint8_t* serverkeyshare, size_t serverkeysharelen, uint8_t* sharedsecret, size_t sharedsecretlen, size_t* written)
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
            case qsc_tls_group_x448:
            {
                res = qsc_x448_key_exchange(sharedsecret, serverkeyshare, state->privatekey);

                if (res == true)
                {
                    *written = QSC_X448_SECRET_SIZE;
                }

                break;
            }
            case qsc_tls_group_secp384r1:
            {
                if (serverkeyshare[0] != 0x04U)
                {
                    status = qsc_tls_status_invalid_message;
                }
                else
                {
                    res = qsc_p384_key_exchange(sharedsecret, serverkeyshare + 1U, state->privatekey);

                    if (res == true)
                    {
                        *written = QSC_ECDHP384_SHAREDSECRET_SIZE;
                    }
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
            case QSC_TLS_ACTIVE_MLKEM_GROUP:
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
                /* OpenSSL-compatible order: KEM ciphertext/shared secret first, then X25519. */
                res = qsc_kyber_decapsulate(sharedsecret, serverkeyshare, state->privatekey);

                if (res == true)
                {
                    res = qsc_eddh_key_exchange(sharedsecret + QSC_KYBER_SHAREDSECRET_SIZE, state->privatekey + QSC_KYBER_PRIVATEKEY_SIZE, serverkeyshare + QSC_KYBER_CIPHERTEXT_SIZE);

                    if (res == true)
                    {
                        *written = QSC_KYBER_SHAREDSECRET_SIZE + 32U;
                    }
                }

                break;
            }
#if defined(QSC_ECDH_S1P256)
            case qsc_tls_group_secp256r1_mlkem768:
            {
                /* OpenSSL-compatible order: SEC1 P-256 shared secret first, then KEM shared secret. */
                if (serverkeyshare[0] != 0x04U)
                {
                    status = qsc_tls_status_invalid_message;
                }
                else
                {
                    res = qsc_ecdh_key_exchange(sharedsecret, state->privatekey, serverkeyshare + 1U);

                    if (res == true)
                    {
                        res = qsc_kyber_decapsulate(sharedsecret + QSC_ECDH_SHAREDSECRET_SIZE,
                            serverkeyshare + 1U + QSC_ECDH_PUBLICKEY_SIZE, state->privatekey + QSC_ECDH_PRIVATEKEY_SIZE);

                        if (res == true)
                        {
                            *written = QSC_ECDH_SHAREDSECRET_SIZE + QSC_KYBER_SHAREDSECRET_SIZE;
                        }
                    }
                }

                break;
            }
#endif
#if defined(QSC_KYBER_S5K4P1024)
            case qsc_tls_group_secp384r1_mlkem1024:
            {
                if (serverkeyshare[0] != 0x04U)
                {
                    status = qsc_tls_status_invalid_message;
                }
                else
                {
                    res = qsc_p384_key_exchange(sharedsecret, serverkeyshare + 1U, state->privatekey);

                    if (res == true)
                    {
                        res = qsc_kyber_decapsulate(sharedsecret + QSC_ECDHP384_SHAREDSECRET_SIZE,
                            serverkeyshare + 1U + QSC_ECDHP384_PUBLICKEY_SIZE, state->privatekey + QSC_ECDHP384_PRIVATEKEY_SIZE);

                        if (res == true)
                        {
                            *written = QSC_ECDHP384_SHAREDSECRET_SIZE + QSC_KYBER_SHAREDSECRET_SIZE;
                        }
                    }
                }

                break;
            }
#endif
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

qsc_tls_status qsc_tls_groups_server_respond(qsc_tls_named_group group, const uint8_t* clientkeyshare, size_t clientkeysharelen, uint8_t* serverkeyshare, size_t serverkeysharelen, size_t* serverkeysharewritten, uint8_t* sharedsecret, size_t sharedsecretlen, size_t* sharedsecretwritten)
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
            case qsc_tls_group_x448:
            {
                qsc_x448_generate_keypair(serverkeyshare, serverpriv, qsc_csp_generate);
                res = qsc_x448_key_exchange(sharedsecret, clientkeyshare, serverpriv);

                if (res == true)
                {
                    *serverkeysharewritten = QSC_X448_PUBLICKEY_SIZE;
                    *sharedsecretwritten = QSC_X448_SECRET_SIZE;
                }

                break;
            }
            case qsc_tls_group_secp384r1:
            {
                uint8_t serverrawpub[QSC_ECDHP384_PUBLICKEY_SIZE] = { 0U };

                if (clientkeyshare[0] != 0x04U)
                {
                    status = qsc_tls_status_invalid_message;
                }
                else
                {
                    res = true;
                    qsc_p384_generate_keypair(serverrawpub, serverpriv, qsc_csp_generate);
                }

                if (res == true)
                {
                    res = qsc_p384_key_exchange(sharedsecret, clientkeyshare + 1U, serverpriv);
                }

                if (res == true)
                {
                    serverkeyshare[0] = 0x04U;
                    qsc_memutils_copy(serverkeyshare + 1U, serverrawpub, QSC_ECDHP384_PUBLICKEY_SIZE);
                    *serverkeysharewritten = 1U + QSC_ECDHP384_PUBLICKEY_SIZE;
                    *sharedsecretwritten = QSC_ECDHP384_SHAREDSECRET_SIZE;
                }

                qsc_memutils_secure_erase(serverrawpub, sizeof(serverrawpub));

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
            case QSC_TLS_ACTIVE_MLKEM_GROUP:
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
                /* OpenSSL-compatible order: encapsulate KEM first, then append X25519. */
                res = qsc_kyber_encapsulate(sharedsecret, serverkeyshare, clientkeyshare, qsc_csp_generate);

                if (res == true)
                {
                    res = qsc_eddh_generate_keypair(serverkeyshare + QSC_KYBER_CIPHERTEXT_SIZE, serverpriv, qsc_csp_generate);
                }

                if (res == true)
                {
                    res = qsc_eddh_key_exchange(sharedsecret + QSC_KYBER_SHAREDSECRET_SIZE, serverpriv,
                        clientkeyshare + QSC_KYBER_PUBLICKEY_SIZE);
                }

                if (res == true)
                {
                    *serverkeysharewritten = QSC_KYBER_CIPHERTEXT_SIZE + 32U;
                    *sharedsecretwritten = QSC_KYBER_SHAREDSECRET_SIZE + 32U;
                }

                break;
            }
#if defined(QSC_ECDH_S1P256)
            case qsc_tls_group_secp256r1_mlkem768:
            {
                uint8_t serverrawpub[QSC_ECDH_PUBLICKEY_SIZE] = { 0U };

                /* OpenSSL-compatible order: SEC1 P-256 first, then KEM. */
                if (clientkeyshare[0] != 0x04U)
                {
                    status = qsc_tls_status_invalid_message;
                }
                else
                {
                    res = qsc_ecdh_generate_keypair(serverrawpub, serverpriv, qsc_csp_generate);
                }

                if (res == true)
                {
                    res = qsc_ecdh_key_exchange(sharedsecret, serverpriv, clientkeyshare + 1U);
                }

                if (res == true)
                {
                    res = qsc_kyber_encapsulate(sharedsecret + QSC_ECDH_SHAREDSECRET_SIZE,
                        serverkeyshare + 1U + QSC_ECDH_PUBLICKEY_SIZE, clientkeyshare + 1U + QSC_ECDH_PUBLICKEY_SIZE, qsc_csp_generate);
                }

                if (res == true)
                {
                    serverkeyshare[0] = 0x04U;
                    qsc_memutils_copy(serverkeyshare + 1U, serverrawpub, QSC_ECDH_PUBLICKEY_SIZE);
                    *serverkeysharewritten = 1U + QSC_ECDH_PUBLICKEY_SIZE + QSC_KYBER_CIPHERTEXT_SIZE;
                    *sharedsecretwritten = QSC_ECDH_SHAREDSECRET_SIZE + QSC_KYBER_SHAREDSECRET_SIZE;
                }

                qsc_memutils_secure_erase(serverrawpub, sizeof(serverrawpub));

                break;
            }
#endif
#if defined(QSC_KYBER_S5K4P1024)
            case qsc_tls_group_secp384r1_mlkem1024:
            {
                uint8_t serverrawpub[QSC_ECDHP384_PUBLICKEY_SIZE] = { 0U };

                if (clientkeyshare[0] != 0x04U)
                {
                    status = qsc_tls_status_invalid_message;
                }
                else
                {
                    res = true;
                    qsc_p384_generate_keypair(serverrawpub, serverpriv, qsc_csp_generate);
                }

                if (res == true)
                {
                    res = qsc_p384_key_exchange(sharedsecret, clientkeyshare + 1U, serverpriv);
                }

                if (res == true)
                {
                    res = qsc_kyber_encapsulate(sharedsecret + QSC_ECDHP384_SHAREDSECRET_SIZE,
                        serverkeyshare + 1U + QSC_ECDHP384_PUBLICKEY_SIZE,
                        clientkeyshare + 1U + QSC_ECDHP384_PUBLICKEY_SIZE, qsc_csp_generate);
                }

                if (res == true)
                {
                    serverkeyshare[0] = 0x04U;
                    qsc_memutils_copy(serverkeyshare + 1U, serverrawpub, QSC_ECDHP384_PUBLICKEY_SIZE);
                    *serverkeysharewritten = 1U + QSC_ECDHP384_PUBLICKEY_SIZE + QSC_KYBER_CIPHERTEXT_SIZE;
                    *sharedsecretwritten = QSC_ECDHP384_SHAREDSECRET_SIZE + QSC_KYBER_SHAREDSECRET_SIZE;
                }

                qsc_memutils_secure_erase(serverrawpub, sizeof(serverrawpub));

                break;
            }
#endif
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
