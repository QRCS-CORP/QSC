/* 2020-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#include "tlsgroups.h"
#include "csp.h"
#include "memutils.h"
#include "eddh25519.h"
#include "kyber512.h"
#include "kyber768.h"
#include "kyber1024.h"
#include "ecdhp256.h"
#include "ecdhp384.h"
#include "ecdhp521.h"
#include "eddh448.h"

#define QSC_TLS_MLKEM_MODULUS 3329U
#define QSC_TLS_MLKEM_RHO_SIZE 32U

static bool tls_groups_mlkem_encapsulation_key_is_valid(const uint8_t* key, size_t keylen)
{
    size_t coeffbytes;
    size_t i;
    uint16_t c0;
    uint16_t c1;
    bool res;

    coeffbytes = 0U;
    i = 0U;
    c0 = 0U;
    c1 = 0U;
    res = false;

    if (key != NULL && keylen > QSC_TLS_MLKEM_RHO_SIZE)
    {
        coeffbytes = keylen - QSC_TLS_MLKEM_RHO_SIZE;

        if ((coeffbytes % 3U) == 0U)
        {
            res = true;

            for (i = 0U; i < coeffbytes; i += 3U)
            {
                c0 = (uint16_t)key[i] | ((uint16_t)(key[i + 1U] & 0x0FU) << 8U);
                c1 = (uint16_t)(key[i + 1U] >> 4U) | ((uint16_t)key[i + 2U] << 4U);

                if (c0 >= QSC_TLS_MLKEM_MODULUS || c1 >= QSC_TLS_MLKEM_MODULUS)
                {
                    res = false;
                    break;
                }
            }
        }
    }

    return res;
}

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

static const qsc_tls_group_descriptor tls_groups_secp521r1 = {
    qsc_tls_group_secp521r1,
    "secp521r1",
    QSC_ECDHP521_PRIVATEKEY_SIZE,
    1U + QSC_ECDHP521_PUBLICKEY_SIZE,
    1U + QSC_ECDHP521_PUBLICKEY_SIZE,
    QSC_ECDHP521_SHAREDSECRET_SIZE,
    true,
    false,
    false,
    true
};

/* secp256r1 wire format per RFC 9846 Section 4.3.8.2: uncompressed SEC1 point
 * 0x04 || X(32) || Y(32) = 65 bytes on the wire.
 * QSC's qsc_ecdh stores the raw X||Y (64 bytes); we wrap with the 0x04 prefix
 * when emitting on the wire and strip it on receive. */
static const qsc_tls_group_descriptor tls_groups_secp256r1 = {
    qsc_tls_group_secp256r1,
    "secp256r1",
    QSC_ECDHP256_PRIVATEKEY_SIZE,
    65U,    /* client public = uncompressed SEC1 point */
    65U,    /* server public = uncompressed SEC1 point */
    QSC_ECDHP256_SHAREDSECRET_SIZE,
    true,
    false,
    false,
    true
};

/* Each group is independent of the selected-default facade. */
static const qsc_tls_group_descriptor tls_groups_mlkem512 = {
    qsc_tls_group_mlkem512, "mlkem512",
    QSC_KYBER512_PRIVATEKEY_SIZE,
    QSC_KYBER512_PUBLICKEY_SIZE,
    QSC_KYBER512_CIPHERTEXT_SIZE,
    QSC_KYBER512_SHAREDSECRET_SIZE,
    false, true, false, true
};

static const qsc_tls_group_descriptor tls_groups_mlkem768 = {
    qsc_tls_group_mlkem768, "mlkem768",
    QSC_KYBER768_PRIVATEKEY_SIZE,
    QSC_KYBER768_PUBLICKEY_SIZE,
    QSC_KYBER768_CIPHERTEXT_SIZE,
    QSC_KYBER768_SHAREDSECRET_SIZE,
    false, true, false, true
};

static const qsc_tls_group_descriptor tls_groups_mlkem1024 = {
    qsc_tls_group_mlkem1024, "mlkem1024",
    QSC_KYBER1024_PRIVATEKEY_SIZE,
    QSC_KYBER1024_PUBLICKEY_SIZE,
    QSC_KYBER1024_CIPHERTEXT_SIZE,
    QSC_KYBER1024_SHAREDSECRET_SIZE,
    false, true, false, true
};

/* RFC 10024: X25519MLKEM768 has KEM-first wire and secret ordering. */
static const qsc_tls_group_descriptor tls_groups_x25519_mlkem = {
    qsc_tls_group_x25519_mlkem768, "x25519_mlkem768",
    QSC_KYBER768_PRIVATEKEY_SIZE + QSC_X25519_PRIVATEKEY_SIZE,
    QSC_KYBER768_PUBLICKEY_SIZE + QSC_X25519_PUBLICKEY_SIZE,
    QSC_KYBER768_CIPHERTEXT_SIZE + QSC_X25519_PUBLICKEY_SIZE,
    QSC_KYBER768_SHAREDSECRET_SIZE + QSC_X25519_SECRET_SIZE,
    true, true, true, true
};

/* RFC 10024: P-256 then ML-KEM-768. */
static const qsc_tls_group_descriptor tls_groups_secp256r1_mlkem = {
    qsc_tls_group_secp256r1_mlkem768, "secp256r1_mlkem768",
    QSC_ECDHP256_PRIVATEKEY_SIZE + QSC_KYBER768_PRIVATEKEY_SIZE,
    1U + QSC_ECDHP256_PUBLICKEY_SIZE + QSC_KYBER768_PUBLICKEY_SIZE,
    1U + QSC_ECDHP256_PUBLICKEY_SIZE + QSC_KYBER768_CIPHERTEXT_SIZE,
    QSC_ECDHP256_SHAREDSECRET_SIZE + QSC_KYBER768_SHAREDSECRET_SIZE,
    true, true, true, true
};

/* RFC 10024: P-384 then ML-KEM-1024. */
static const qsc_tls_group_descriptor tls_groups_secp384r1_mlkem1024 = {
    qsc_tls_group_secp384r1_mlkem1024, "secp384r1_mlkem1024",
    QSC_ECDHP384_PRIVATEKEY_SIZE + QSC_KYBER1024_PRIVATEKEY_SIZE,
    1U + QSC_ECDHP384_PUBLICKEY_SIZE + QSC_KYBER1024_PUBLICKEY_SIZE,
    1U + QSC_ECDHP384_PUBLICKEY_SIZE + QSC_KYBER1024_CIPHERTEXT_SIZE,
    QSC_ECDHP384_SHAREDSECRET_SIZE + QSC_KYBER1024_SHAREDSECRET_SIZE,
    true, true, true, true
};

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
        case qsc_tls_group_secp521r1:
        {
            res = &tls_groups_secp521r1;
            break;
        }
        case qsc_tls_group_secp256r1:
        {
            res = &tls_groups_secp256r1;
            break;
        }
        case qsc_tls_group_mlkem512:
        {
            res = &tls_groups_mlkem512;
            break;
        }
        case qsc_tls_group_mlkem768:
        {
            res = &tls_groups_mlkem768;
            break;
        }
        case qsc_tls_group_mlkem1024:
        {
            res = &tls_groups_mlkem1024;
            break;
        }
        case qsc_tls_group_x25519_mlkem768:
        {
            res = &tls_groups_x25519_mlkem;
            break;
        }
        case qsc_tls_group_secp256r1_mlkem768:
        {
            res = &tls_groups_secp256r1_mlkem;
            break;
        }
        case qsc_tls_group_secp384r1_mlkem1024:
        {
            res = &tls_groups_secp384r1_mlkem1024;
            break;
        }
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
                res = true;
                qsc_x25519_generate_keypair(state->publicshare, state->privatekey, qsc_csp_generate);

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
            case qsc_tls_group_secp521r1:
            {
                uint8_t rawpub[QSC_ECDHP521_PUBLICKEY_SIZE] = { 0U };

                qsc_p521_generate_keypair(rawpub, state->privatekey, qsc_csp_generate);
                state->publicshare[0] = 0x04U;
                qsc_memutils_copy(state->publicshare + 1U, rawpub, QSC_ECDHP521_PUBLICKEY_SIZE);
                state->privatekeylen = QSC_ECDHP521_PRIVATEKEY_SIZE;
                state->publicsharelen = 1U + QSC_ECDHP521_PUBLICKEY_SIZE;
                state->initialized = true;
                res = true;

                qsc_memutils_secure_erase(rawpub, sizeof(rawpub));

                break;
            }
            case qsc_tls_group_secp256r1:
            {
                /* qsc_ecdh produces raw X||Y (64 bytes). Wire format per RFC 9846 Section 4.3.8.2
                 * is the uncompressed SEC1 point: 0x04 || X || Y = 65 bytes. */
                uint8_t rawpub[QSC_ECDHP256_PUBLICKEY_SIZE] = { 0U };

                res = true;
                qsc_p256_generate_keypair(rawpub, state->privatekey, qsc_csp_generate);

                if (res == true)
                {
                    state->publicshare[0] = 0x04U;
                    qsc_memutils_copy(state->publicshare + 1U, rawpub, QSC_ECDHP256_PUBLICKEY_SIZE);
                    state->privatekeylen = QSC_ECDHP256_PRIVATEKEY_SIZE;
                    state->publicsharelen = 1U + QSC_ECDHP256_PUBLICKEY_SIZE;
                    state->initialized = true;
                }

                qsc_memutils_secure_erase(rawpub, sizeof(rawpub));

                break;
            }

            case qsc_tls_group_mlkem512:
            {
                res = qsc_kyber512_generate_keypair(state->publicshare, state->privatekey, qsc_csp_generate);

                if (res == true)
                {
                    state->privatekeylen = QSC_KYBER512_PRIVATEKEY_SIZE;
                    state->publicsharelen = QSC_KYBER512_PUBLICKEY_SIZE;
                    state->initialized = true;
                }

                break;
            }
case qsc_tls_group_mlkem768:
            {
                res = qsc_kyber768_generate_keypair(state->publicshare, state->privatekey, qsc_csp_generate);

                if (res == true)
                {
                    state->privatekeylen = QSC_KYBER768_PRIVATEKEY_SIZE;
                    state->publicsharelen = QSC_KYBER768_PUBLICKEY_SIZE;
                    state->initialized = true;
                }

                break;
            }
case qsc_tls_group_mlkem1024:
            {
                res = qsc_kyber1024_generate_keypair(state->publicshare, state->privatekey, qsc_csp_generate);

                if (res == true)
                {
                    state->privatekeylen = QSC_KYBER1024_PRIVATEKEY_SIZE;
                    state->publicsharelen = QSC_KYBER1024_PUBLICKEY_SIZE;
                    state->initialized = true;
                }

                break;
            }
            case qsc_tls_group_x25519_mlkem768:
            {
                /* RFC 10024 X25519MLKEM768 order: KEM public first, then X25519 public.
                 * Private storage mirrors that order: KEM private first, then X25519 private. */
                res = qsc_kyber768_generate_keypair(state->publicshare, state->privatekey, qsc_csp_generate);

                if (res == true)
                {
                    res = true;
                qsc_x25519_generate_keypair(state->publicshare + QSC_KYBER768_PUBLICKEY_SIZE, state->privatekey + QSC_KYBER768_PRIVATEKEY_SIZE, qsc_csp_generate);
                }

                if (res == true)
                {
                    state->privatekeylen = QSC_KYBER768_PRIVATEKEY_SIZE + 32U;
                    state->publicsharelen = QSC_KYBER768_PUBLICKEY_SIZE + 32U;
                    state->initialized = true;
                }

                break;
            }
            case qsc_tls_group_secp256r1_mlkem768:
            {
                uint8_t rawpub[QSC_ECDHP256_PUBLICKEY_SIZE] = { 0U };

                /* RFC 10024 SecP256r1MLKEM768 order: SEC1 P-256 public first, then KEM public. */
                res = true;
                qsc_p256_generate_keypair(rawpub, state->privatekey, qsc_csp_generate);

                if (res == true)
                {
                    state->publicshare[0] = 0x04U;
                    qsc_memutils_copy(state->publicshare + 1U, rawpub, QSC_ECDHP256_PUBLICKEY_SIZE);
                    res = qsc_kyber768_generate_keypair(state->publicshare + 1U + QSC_ECDHP256_PUBLICKEY_SIZE, state->privatekey + QSC_ECDHP256_PRIVATEKEY_SIZE, qsc_csp_generate);
                }

                if (res == true)
                {
                    state->privatekeylen = QSC_ECDHP256_PRIVATEKEY_SIZE + QSC_KYBER768_PRIVATEKEY_SIZE;
                    state->publicsharelen = 1U + QSC_ECDHP256_PUBLICKEY_SIZE + QSC_KYBER768_PUBLICKEY_SIZE;
                    state->initialized = true;
                }

                qsc_memutils_secure_erase(rawpub, sizeof(rawpub));

                break;
            }
            case qsc_tls_group_secp384r1_mlkem1024:
            {
                uint8_t rawpub[QSC_ECDHP384_PUBLICKEY_SIZE] = { 0U };

                res = true;
                qsc_p384_generate_keypair(rawpub, state->privatekey, qsc_csp_generate);

                if (res == true)
                {
                    state->publicshare[0] = 0x04U;
                    qsc_memutils_copy(state->publicshare + 1U, rawpub, QSC_ECDHP384_PUBLICKEY_SIZE);
                    res = qsc_kyber1024_generate_keypair(state->publicshare + 1U + QSC_ECDHP384_PUBLICKEY_SIZE, state->privatekey + QSC_ECDHP384_PRIVATEKEY_SIZE, qsc_csp_generate);
                }

                if (res == true)
                {
                    state->privatekeylen = QSC_ECDHP384_PRIVATEKEY_SIZE + QSC_KYBER1024_PRIVATEKEY_SIZE;
                    state->publicsharelen = 1U + QSC_ECDHP384_PUBLICKEY_SIZE + QSC_KYBER1024_PUBLICKEY_SIZE;
                    state->initialized = true;
                }

                qsc_memutils_secure_erase(rawpub, sizeof(rawpub));

                break;
            }
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
                res = qsc_x25519_key_exchange(sharedsecret, serverkeyshare, state->privatekey);

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
            case qsc_tls_group_secp521r1:
            {
                if (serverkeyshare[0] != 0x04U)
                {
                    status = qsc_tls_status_invalid_message;
                }
                else
                {
                    res = qsc_p521_key_exchange(sharedsecret, serverkeyshare + 1U, state->privatekey);

                    if (res == true)
                    {
                        *written = QSC_ECDHP521_SHAREDSECRET_SIZE;
                    }
                }

                break;
            }
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
                    res = qsc_p256_key_exchange(sharedsecret, serverkeyshare + 1U, state->privatekey);

                    if (res == true)
                    {
                        *written = QSC_ECDHP256_SHAREDSECRET_SIZE;
                    }
                }

                break;
            }
            case qsc_tls_group_mlkem512:
            {
                res = qsc_kyber512_decapsulate(sharedsecret, serverkeyshare, state->privatekey);

                if (res == true)
                {
                    *written = QSC_KYBER512_SHAREDSECRET_SIZE;
                }

                break;
            }
case qsc_tls_group_mlkem768:
            {
                res = qsc_kyber768_decapsulate(sharedsecret, serverkeyshare, state->privatekey);

                if (res == true)
                {
                    *written = QSC_KYBER768_SHAREDSECRET_SIZE;
                }

                break;
            }
case qsc_tls_group_mlkem1024:
            {
                res = qsc_kyber1024_decapsulate(sharedsecret, serverkeyshare, state->privatekey);

                if (res == true)
                {
                    *written = QSC_KYBER1024_SHAREDSECRET_SIZE;
                }

                break;
            }
            case qsc_tls_group_x25519_mlkem768:
            {
                /* RFC 10024 X25519MLKEM768 order: KEM ciphertext/shared secret first, then X25519. */
                res = qsc_kyber768_decapsulate(sharedsecret, serverkeyshare, state->privatekey);

                if (res == false)
                {
                    status = qsc_tls_status_authentication_failure;
                }
                else
                {
                    res = qsc_x25519_key_exchange(sharedsecret + QSC_KYBER768_SHAREDSECRET_SIZE, serverkeyshare + QSC_KYBER768_CIPHERTEXT_SIZE, state->privatekey + QSC_KYBER768_PRIVATEKEY_SIZE);

                    if (res == false)
                    {
                        status = qsc_tls_status_invalid_message;
                    }
                    else
                    {
                        *written = QSC_KYBER768_SHAREDSECRET_SIZE + 32U;
                    }
                }

                break;
            }
            case qsc_tls_group_secp256r1_mlkem768:
            {
                /* RFC 10024 SecP256r1MLKEM768 order: P-256 shared secret first, then KEM shared secret. */
                if (serverkeyshare[0] != 0x04U)
                {
                    status = qsc_tls_status_invalid_message;
                }
                else
                {
                    res = qsc_p256_key_exchange(sharedsecret, serverkeyshare + 1U, state->privatekey);

                    if (res == false)
                    {
                        status = qsc_tls_status_invalid_message;
                    }
                    else
                    {
                        res = qsc_kyber768_decapsulate(sharedsecret + QSC_ECDHP256_SHAREDSECRET_SIZE, serverkeyshare + 1U + QSC_ECDHP256_PUBLICKEY_SIZE, state->privatekey + QSC_ECDHP256_PRIVATEKEY_SIZE);

                        if (res == false)
                        {
                            status = qsc_tls_status_authentication_failure;
                        }
                        else
                        {
                            *written = QSC_ECDHP256_SHAREDSECRET_SIZE + QSC_KYBER768_SHAREDSECRET_SIZE;
                        }
                    }
                }

                break;
            }
            case qsc_tls_group_secp384r1_mlkem1024:
            {
                if (serverkeyshare[0] != 0x04U)
                {
                    status = qsc_tls_status_invalid_message;
                }
                else
                {
                    res = qsc_p384_key_exchange(sharedsecret, serverkeyshare + 1U, state->privatekey);

                    if (res == false)
                    {
                        status = qsc_tls_status_invalid_message;
                    }
                    else
                    {
                        res = qsc_kyber1024_decapsulate(sharedsecret + QSC_ECDHP384_SHAREDSECRET_SIZE, serverkeyshare + 1U + QSC_ECDHP384_PUBLICKEY_SIZE, state->privatekey + QSC_ECDHP384_PRIVATEKEY_SIZE);

                        if (res == false)
                        {
                            status = qsc_tls_status_authentication_failure;
                        }
                        else
                        {
                            *written = QSC_ECDHP384_SHAREDSECRET_SIZE + QSC_KYBER1024_SHAREDSECRET_SIZE;
                        }
                    }
                }

                break;
            }
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

            if (d->iskem == true && status != qsc_tls_status_success)
            {
                qsc_memutils_secure_erase(sharedsecret, d->sharedsecretsize);
                *written = 0U;
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
                res = true;
                qsc_x25519_generate_keypair(serverkeyshare, serverpriv, qsc_csp_generate);

                if (res)
                {
                    res = qsc_x25519_key_exchange(sharedsecret, clientkeyshare, serverpriv);

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
            case qsc_tls_group_secp521r1:
            {
                uint8_t serverrawpub[QSC_ECDHP521_PUBLICKEY_SIZE] = { 0U };

                if (clientkeyshare[0] != 0x04U)
                {
                    status = qsc_tls_status_invalid_message;
                }
                else
                {
                    res = true;
                    qsc_p521_generate_keypair(serverrawpub, serverpriv, qsc_csp_generate);
                }

                if (res == true)
                {
                    res = qsc_p521_key_exchange(sharedsecret, clientkeyshare + 1U, serverpriv);
                }

                if (res == true)
                {
                    serverkeyshare[0] = 0x04U;
                    qsc_memutils_copy(serverkeyshare + 1U, serverrawpub, QSC_ECDHP521_PUBLICKEY_SIZE);
                    *serverkeysharewritten = 1U + QSC_ECDHP521_PUBLICKEY_SIZE;
                    *sharedsecretwritten = QSC_ECDHP521_SHAREDSECRET_SIZE;
                }

                qsc_memutils_secure_erase(serverrawpub, sizeof(serverrawpub));

                break;
            }
            case qsc_tls_group_secp256r1:
            {
                uint8_t serverrawpub[QSC_ECDHP256_PUBLICKEY_SIZE] = { 0U };

                /* client share arrives as 0x04||X||Y (65 bytes); reject if marker wrong. */
                if (clientkeyshare[0] != 0x04U)
                {
                    status = qsc_tls_status_invalid_message;
                    break;
                }

                /* generate ephemeral ECDH keypair, compute shared secret, write response
                 * to wire with the 0x04 uncompressed-point marker prefix. */

                res = true;
                qsc_p256_generate_keypair(serverrawpub, serverpriv, qsc_csp_generate);

                if (res == true)
                {
                    res = qsc_p256_key_exchange(sharedsecret, clientkeyshare + 1U, serverpriv);

                    if (res == true)
                    {
                        serverkeyshare[0] = 0x04U;
                        qsc_memutils_copy(serverkeyshare + 1U, serverrawpub, QSC_ECDHP256_PUBLICKEY_SIZE);
                        *serverkeysharewritten = 1U + QSC_ECDHP256_PUBLICKEY_SIZE;
                        *sharedsecretwritten = QSC_ECDHP256_SHAREDSECRET_SIZE;
                    }
                }
                qsc_memutils_secure_erase(serverrawpub, sizeof(serverrawpub));

                break;
            }
            case qsc_tls_group_mlkem512:
            {
                /* The standalone ML-KEM TLS groups require the FIPS 203 encapsulation-key check before encapsulation. */
                if (tls_groups_mlkem_encapsulation_key_is_valid(clientkeyshare, QSC_KYBER512_PUBLICKEY_SIZE) == false)
                {
                    status = qsc_tls_status_invalid_message;
                }
                else
                {
                    res = qsc_kyber512_encapsulate(sharedsecret, serverkeyshare, clientkeyshare, qsc_csp_generate);

                    if (res == false)
                    {
                        status = qsc_tls_status_authentication_failure;
                    }
                }

                if (status == qsc_tls_status_success)
                {
                    *serverkeysharewritten = QSC_KYBER512_CIPHERTEXT_SIZE;
                    *sharedsecretwritten = QSC_KYBER512_SHAREDSECRET_SIZE;
                }

                break;
            }
case qsc_tls_group_mlkem768:
            {
                /* The standalone ML-KEM TLS groups require the FIPS 203 encapsulation-key check before encapsulation. */
                if (tls_groups_mlkem_encapsulation_key_is_valid(clientkeyshare, QSC_KYBER768_PUBLICKEY_SIZE) == false)
                {
                    status = qsc_tls_status_invalid_message;
                }
                else
                {
                    res = qsc_kyber768_encapsulate(sharedsecret, serverkeyshare, clientkeyshare, qsc_csp_generate);

                    if (res == false)
                    {
                        status = qsc_tls_status_authentication_failure;
                    }
                }

                if (status == qsc_tls_status_success)
                {
                    *serverkeysharewritten = QSC_KYBER768_CIPHERTEXT_SIZE;
                    *sharedsecretwritten = QSC_KYBER768_SHAREDSECRET_SIZE;
                }

                break;
            }
case qsc_tls_group_mlkem1024:
            {
                /* The standalone ML-KEM TLS groups require the FIPS 203 encapsulation-key check before encapsulation. */
                if (tls_groups_mlkem_encapsulation_key_is_valid(clientkeyshare, QSC_KYBER1024_PUBLICKEY_SIZE) == false)
                {
                    status = qsc_tls_status_invalid_message;
                }
                else
                {
                    res = qsc_kyber1024_encapsulate(sharedsecret, serverkeyshare, clientkeyshare, qsc_csp_generate);

                    if (res == false)
                    {
                        status = qsc_tls_status_authentication_failure;
                    }
                }

                if (status == qsc_tls_status_success)
                {
                    *serverkeysharewritten = QSC_KYBER1024_CIPHERTEXT_SIZE;
                    *sharedsecretwritten = QSC_KYBER1024_SHAREDSECRET_SIZE;
                }

                break;
            }
            case qsc_tls_group_x25519_mlkem768:
            {
                /* RFC 10024 requires the FIPS 203 encapsulation-key check before ML-KEM encapsulation. */
                if (tls_groups_mlkem_encapsulation_key_is_valid(clientkeyshare, QSC_KYBER768_PUBLICKEY_SIZE) == false)
                {
                    status = qsc_tls_status_invalid_message;
                }
                else
                {
                    res = qsc_kyber768_encapsulate(sharedsecret, serverkeyshare, clientkeyshare, qsc_csp_generate);

                    if (res == false)
                    {
                        status = qsc_tls_status_authentication_failure;
                    }
                }

                if (status == qsc_tls_status_success)
                {
                    res = true;
                qsc_x25519_generate_keypair(serverkeyshare + QSC_KYBER768_CIPHERTEXT_SIZE, serverpriv, qsc_csp_generate);

                    if (res == false)
                    {
                        status = qsc_tls_status_authentication_failure;
                    }
                }

                if (status == qsc_tls_status_success)
                {
                    res = qsc_x25519_key_exchange(sharedsecret + QSC_KYBER768_SHAREDSECRET_SIZE, clientkeyshare + QSC_KYBER768_PUBLICKEY_SIZE, serverpriv);

                    if (res == false)
                    {
                        status = qsc_tls_status_invalid_message;
                    }
                }

                if (status == qsc_tls_status_success)
                {
                    *serverkeysharewritten = QSC_KYBER768_CIPHERTEXT_SIZE + 32U;
                    *sharedsecretwritten = QSC_KYBER768_SHAREDSECRET_SIZE + 32U;
                }

                break;
            }
            case qsc_tls_group_secp256r1_mlkem768:
            {
                uint8_t serverrawpub[QSC_ECDHP256_PUBLICKEY_SIZE] = { 0U };

                /* RFC 10024 SecP256r1MLKEM768 order: SEC1 P-256 public first, then KEM ciphertext. */
                if (clientkeyshare[0] != 0x04U ||
                    tls_groups_mlkem_encapsulation_key_is_valid(clientkeyshare + 1U + QSC_ECDHP256_PUBLICKEY_SIZE, QSC_KYBER768_PUBLICKEY_SIZE) == false)
                {
                    status = qsc_tls_status_invalid_message;
                }
                else
                {
                    res = true;
                qsc_p256_generate_keypair(serverrawpub, serverpriv, qsc_csp_generate);

                    if (res == false)
                    {
                        status = qsc_tls_status_authentication_failure;
                    }
                }

                if (status == qsc_tls_status_success)
                {
                    res = qsc_p256_key_exchange(sharedsecret, clientkeyshare + 1U, serverpriv);

                    if (res == false)
                    {
                        status = qsc_tls_status_invalid_message;
                    }
                }

                if (status == qsc_tls_status_success)
                {
                    res = qsc_kyber768_encapsulate(sharedsecret + QSC_ECDHP256_SHAREDSECRET_SIZE, serverkeyshare + 1U + QSC_ECDHP256_PUBLICKEY_SIZE, clientkeyshare + 1U + QSC_ECDHP256_PUBLICKEY_SIZE, qsc_csp_generate);

                    if (res == false)
                    {
                        status = qsc_tls_status_authentication_failure;
                    }
                }

                if (status == qsc_tls_status_success)
                {
                    serverkeyshare[0] = 0x04U;
                    qsc_memutils_copy(serverkeyshare + 1U, serverrawpub, QSC_ECDHP256_PUBLICKEY_SIZE);
                    *serverkeysharewritten = 1U + QSC_ECDHP256_PUBLICKEY_SIZE + QSC_KYBER768_CIPHERTEXT_SIZE;
                    *sharedsecretwritten = QSC_ECDHP256_SHAREDSECRET_SIZE + QSC_KYBER768_SHAREDSECRET_SIZE;
                }

                qsc_memutils_secure_erase(serverrawpub, sizeof(serverrawpub));

                break;
            }
            case qsc_tls_group_secp384r1_mlkem1024:
            {
                uint8_t serverrawpub[QSC_ECDHP384_PUBLICKEY_SIZE] = { 0U };

                if (clientkeyshare[0] != 0x04U ||
                    tls_groups_mlkem_encapsulation_key_is_valid(clientkeyshare + 1U + QSC_ECDHP384_PUBLICKEY_SIZE, QSC_KYBER1024_PUBLICKEY_SIZE) == false)
                {
                    status = qsc_tls_status_invalid_message;
                }
                else
                {
                    res = true;
                    qsc_p384_generate_keypair(serverrawpub, serverpriv, qsc_csp_generate);
                }

                if (status == qsc_tls_status_success)
                {
                    res = qsc_p384_key_exchange(sharedsecret, clientkeyshare + 1U, serverpriv);

                    if (res == false)
                    {
                        status = qsc_tls_status_invalid_message;
                    }
                }

                if (status == qsc_tls_status_success)
                {
                    res = qsc_kyber1024_encapsulate(sharedsecret + QSC_ECDHP384_SHAREDSECRET_SIZE, serverkeyshare + 1U + QSC_ECDHP384_PUBLICKEY_SIZE, clientkeyshare + 1U + QSC_ECDHP384_PUBLICKEY_SIZE, qsc_csp_generate);

                    if (res == false)
                    {
                        status = qsc_tls_status_authentication_failure;
                    }
                }

                if (status == qsc_tls_status_success)
                {
                    serverkeyshare[0] = 0x04U;
                    qsc_memutils_copy(serverkeyshare + 1U, serverrawpub, QSC_ECDHP384_PUBLICKEY_SIZE);
                    *serverkeysharewritten = 1U + QSC_ECDHP384_PUBLICKEY_SIZE + QSC_KYBER1024_CIPHERTEXT_SIZE;
                    *sharedsecretwritten = QSC_ECDHP384_SHAREDSECRET_SIZE + QSC_KYBER1024_SHAREDSECRET_SIZE;
                }

                qsc_memutils_secure_erase(serverrawpub, sizeof(serverrawpub));

                break;
            }
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

            if (d->iskem == true && status != qsc_tls_status_success)
            {
                qsc_memutils_secure_erase(serverkeyshare, d->serverpublicsize);
                qsc_memutils_secure_erase(sharedsecret, d->sharedsecretsize);
                *serverkeysharewritten = 0U;
                *sharedsecretwritten = 0U;
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
