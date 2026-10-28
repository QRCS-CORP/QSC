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

#include "ecdsa.h"
#include "memutils.h"
#include "ecdsap256.h"
#include "ecdsap384.h"
#include "ecdsap521.h"

int32_t qsc_ecdsa_publickey_from_privatekey(uint8_t* publickey, const uint8_t* privatekey)
{
    QSC_ASSERT(publickey != NULL);
    QSC_ASSERT(privatekey != NULL);

    int32_t res;

    res = -1;

    if (publickey != NULL && privatekey != NULL)
    {
#if defined(QSC_ECDSA_S1P256)
        res = qsc_p256_publickey_from_privatekey(publickey, privatekey);
#elif defined(QSC_ECDSA_S3P384)
        res = qsc_p384_publickey_from_privatekey(publickey, privatekey);
#elif defined(QSC_ECDSA_S5P521)
        res = qsc_p521_publickey_from_privatekey(publickey, privatekey);
#endif
    }

    return res;
}

bool qsc_ecdsa_publickey_from_sec1(uint8_t* publickey, const uint8_t* secpub)
{
    bool res;

    QSC_ASSERT(publickey != NULL);
    QSC_ASSERT(secpub != NULL);

    res = false;

    if (publickey != NULL && secpub != NULL)
    {
        if (secpub[0U] == 0x04U)
        {
            qsc_memutils_copy(publickey, secpub + 1U, QSC_ECDSA_PUBLICKEY_SIZE);
            res = true;
        }
    }

    return res;
}

void qsc_ecdsa_publickey_to_sec1(uint8_t* secpub, const uint8_t* publickey)
{
    QSC_ASSERT(secpub != NULL);
    QSC_ASSERT(publickey != NULL);

    if (secpub != NULL && publickey != NULL)
    {
        secpub[0U] = 0x04U;
        qsc_memutils_copy(secpub + 1U, publickey, QSC_ECDSA_PUBLICKEY_SIZE);
    }
}

bool qsc_ecdsa_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed)
{
    QSC_ASSERT(publickey != NULL);
    QSC_ASSERT(privatekey != NULL);
    QSC_ASSERT(seed != NULL);

    bool res;

    res = false;

    if (publickey != NULL && privatekey != NULL && seed != NULL)
    {
#if defined(QSC_ECDSA_S1P256)
        res = (qsc_p256_keypair(publickey, privatekey, seed) == 0);
#elif defined(QSC_ECDSA_S3P384)
        res = (qsc_p384_keypair(publickey, privatekey, seed) == 0);
#elif defined(QSC_ECDSA_S5P521)
        res = (qsc_p521_keypair(publickey, privatekey, seed) == 0);
#endif
    }

    return res;
}

bool qsc_ecdsa_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
    QSC_ASSERT(publickey != NULL);
    QSC_ASSERT(privatekey != NULL);
    QSC_ASSERT(rng_generate != NULL);

    uint8_t seed[QSC_ECDSA_SEED_SIZE] = { 0U };
    bool res;

    res = false;

    if (publickey != NULL && privatekey != NULL && rng_generate != NULL)
    {
        res = rng_generate(seed, sizeof(seed));

        if (res == true)
        {
#if defined(QSC_ECDSA_S1P256)
            res = (qsc_p256_keypair(publickey, privatekey, seed) == 0);
#elif defined(QSC_ECDSA_S3P384)
            res = (qsc_p384_keypair(publickey, privatekey, seed) == 0);
#elif defined(QSC_ECDSA_S5P521)
            res = (qsc_p521_keypair(publickey, privatekey, seed) == 0);
#endif
            if (res == false)
            {
                qsc_memutils_secure_erase(publickey, QSC_ECDSA_PUBLICKEY_SIZE);
                qsc_memutils_secure_erase(privatekey, QSC_ECDSA_PRIVATEKEY_SIZE);
            }

            qsc_memutils_secure_erase(seed, sizeof(seed));
        }
    }

    return res;
}

bool qsc_ecdsa_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey)
{
    QSC_ASSERT(signedmsg != NULL);
    QSC_ASSERT(smsglen != NULL);
    QSC_ASSERT(message != NULL);
    QSC_ASSERT(privatekey != NULL);

    bool res;

    res = false;

    if (signedmsg != NULL && smsglen != NULL && message != NULL && privatekey != NULL)
    {
#if defined(QSC_ECDSA_S1P256)
        res = (qsc_p256_sign(signedmsg, smsglen, message, msglen, privatekey) == 0);
#elif defined(QSC_ECDSA_S3P384)
        res = (qsc_p384_sign(signedmsg, smsglen, message, msglen, privatekey) == 0);
#elif defined(QSC_ECDSA_S5P521)
        res = (qsc_p521_sign(signedmsg, smsglen, message, msglen, privatekey) == 0);
#endif
        if (res == false)
        {
            qsc_memutils_secure_erase(signedmsg, msglen + QSC_ECDSA_SIGNATURE_SIZE);
            
            if (smsglen != NULL)
            {
                *smsglen = 0U;
            }
        }
    }

    return res;
}

bool qsc_ecdsa_sign_scalar(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey)
{
    QSC_ASSERT(signedmsg != NULL);
    QSC_ASSERT(smsglen != NULL);
    QSC_ASSERT(message != NULL);
    QSC_ASSERT(privatekey != NULL);

    bool res;

    res = false;

    if (signedmsg != NULL && smsglen != NULL && message != NULL && privatekey != NULL)
    {
#if defined(QSC_ECDSA_S1P256)
        res = (qsc_p256_sign_scalar(signedmsg, smsglen, message, msglen, privatekey) == 0);
#elif defined(QSC_ECDSA_S3P384)
        res = (qsc_p384_sign_scalar(signedmsg, smsglen, message, msglen, privatekey) == 0);
#elif defined(QSC_ECDSA_S5P521)
        res = (qsc_p521_sign_scalar(signedmsg, smsglen, message, msglen, privatekey) == 0);
#endif
        if (res == false)
        {
            qsc_memutils_secure_erase(signedmsg, msglen + QSC_ECDSA_SIGNATURE_SIZE);

            if (smsglen != NULL)
            {
                *smsglen = 0U;
            }
        }
    }

    return res;
}

bool qsc_ecdsa_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey)
{
    QSC_ASSERT(message != NULL);
    QSC_ASSERT(msglen != NULL);
    QSC_ASSERT(signedmsg != NULL);
    QSC_ASSERT(publickey != NULL);
    QSC_ASSERT(smsglen >  QSC_ECDSA_SIGNATURE_SIZE);

    bool res;

    res = false;

    if (message != NULL && msglen != NULL && signedmsg != NULL && publickey != NULL && smsglen > QSC_ECDSA_SIGNATURE_SIZE)
    {
#if defined(QSC_ECDSA_S1P256)
        res = qsc_p256_verify(message, msglen, signedmsg, smsglen, publickey);
#elif defined(QSC_ECDSA_S3P384)
        res = qsc_p384_verify(message, msglen, signedmsg, smsglen, publickey);
#elif defined(QSC_ECDSA_S5P521)
        res = qsc_p521_verify(message, msglen, signedmsg, smsglen, publickey);
#endif
    }

    return res;
}
