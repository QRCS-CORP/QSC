#include "tlssignerdefault.h"
#include "csp.h"
#include "dilithium.h"
#include "ecdsa.h"
#include "eddsa.h"
#include "memutils.h"
#include "tlsecdsader.h"
#include "tlssigalgs.h"

#define QSC_TLS_SIGNER_ED25519_SIG_LEN 64U

static bool tls_signer_default_sign_ed25519(const uint8_t* input, size_t inputlen, uint8_t* signature, size_t* signaturelen, const uint8_t* privatekey)
{
    uint8_t* signedmsg;
    size_t need;
    size_t smsglen;
    bool res;

    need = QSC_TLS_SIGNER_ED25519_SIG_LEN + inputlen;
    signedmsg = (uint8_t*)qsc_memutils_malloc(need);
    res = false;

    if (signedmsg != NULL)
    {
        smsglen = 0U;
        qsc_eddsa_sign(signedmsg, &smsglen, input, inputlen, privatekey);

        if (smsglen == need)
        {
            qsc_memutils_copy(signature, signedmsg, QSC_TLS_SIGNER_ED25519_SIG_LEN);
            *signaturelen = QSC_TLS_SIGNER_ED25519_SIG_LEN;
            res = true;
        }

        qsc_memutils_secure_erase(signedmsg, need);
        qsc_memutils_alloc_free(signedmsg);
    }

    return res;
}

static bool tls_signer_default_verify_ed25519(const uint8_t* input, size_t inputlen, const uint8_t* signature, size_t signaturelen, const uint8_t* publickey)
{
    uint8_t* recovered;
    uint8_t* signedmsg;
    size_t recoveredlen;
    size_t smsglen;
    bool res;

    res = false;

    if (signaturelen == QSC_TLS_SIGNER_ED25519_SIG_LEN)
    {
        smsglen = signaturelen + inputlen;
        signedmsg = (uint8_t*)qsc_memutils_malloc(smsglen);

        if (signedmsg != NULL)
        {
            recovered = (uint8_t*)qsc_memutils_malloc(inputlen);

            if (recovered != NULL)
            {
                qsc_memutils_copy(signedmsg, signature, signaturelen);
                qsc_memutils_copy(signedmsg + signaturelen, input, inputlen);
                recoveredlen = 0U;
                res = qsc_eddsa_verify(recovered, &recoveredlen, signedmsg, smsglen, publickey);

                if (res && recoveredlen == inputlen)
                {
                    res = qsc_memutils_are_equal(recovered, input, inputlen);
                }
                else
                {
                    res = false;
                }

                qsc_memutils_secure_erase(recovered, inputlen);
                qsc_memutils_alloc_free(recovered);
            }

            qsc_memutils_secure_erase(signedmsg, smsglen);
            qsc_memutils_alloc_free(signedmsg);
        }
    }

    return res;
}

static bool tls_signer_default_sign_mldsa(const uint8_t* input, size_t inputlen, uint8_t* signature, size_t* signaturelen, const uint8_t* privatekey)
{
    uint8_t* signedmsg;
    size_t need;
    size_t smsglen;
    bool res;

    need = QSC_DILITHIUM_SIGNATURE_SIZE + inputlen;
    signedmsg = (uint8_t*)qsc_memutils_malloc(need);
    res = false;

    if (signedmsg != NULL)
    {
        smsglen = 0U;
        res = qsc_dilithium_sign(signedmsg, &smsglen, input, inputlen, privatekey, qsc_csp_generate);

        if (res)
        {
            size_t siglen;

            /* the sig size is determined by the parameter set; the combined length minus the message
             * length yields the actual signature bytes prefix. */
            siglen = smsglen - inputlen;
            qsc_memutils_copy(signature, signedmsg, siglen);
            *signaturelen = siglen;
        }

        qsc_memutils_secure_erase(signedmsg, need);
        qsc_memutils_alloc_free(signedmsg);
    }

    return res;
}

static bool tls_signer_default_verify_mldsa(const uint8_t* input, size_t inputlen, const uint8_t* signature, size_t signaturelen, const uint8_t* publickey)
{
    uint8_t* recovered;
    uint8_t* signedmsg;
    size_t recoveredlen;
    size_t smsglen;
    bool res;

    res = false;
    smsglen = signaturelen + inputlen;
    signedmsg = (uint8_t*)qsc_memutils_malloc(smsglen);

    if (signedmsg != NULL)
    {
        recovered = (uint8_t*)qsc_memutils_malloc(inputlen);

        if (recovered != NULL)
        {
            qsc_memutils_copy(signedmsg, signature, signaturelen);
            qsc_memutils_copy(signedmsg + signaturelen, input, inputlen);
            recoveredlen = 0U;
            res = qsc_dilithium_verify(recovered, &recoveredlen, signedmsg, smsglen, publickey);

            if (res && recoveredlen == inputlen)
            {
                res = qsc_memutils_are_equal(recovered, input, inputlen);
            }
            else
            {
                res = false;
            }

            qsc_memutils_secure_erase(recovered, inputlen); 
            qsc_memutils_alloc_free(recovered); 
        }

        qsc_memutils_secure_erase(signedmsg, smsglen);
        qsc_memutils_alloc_free(signedmsg); 
    }

    return res;
}

static bool tls_signer_default_ecdsa_matches_scheme(qsc_tls_signature_scheme scheme)
{
#if defined(QSC_ECDSA_S1P256)
    return scheme == qsc_tls_sig_ecdsa_secp256r1_sha256;
#elif defined(QSC_ECDSA_S3P384)
    return scheme == qsc_tls_sig_ecdsa_secp384r1_sha384;
#elif defined(QSC_ECDSA_S5P521)
    (void)scheme;
    return false;  /* ecdsa_secp521r1_sha512 scheme enum not in tlstypes.h */
#else
    (void)scheme;
    return false;
#endif
}

static bool tls_signer_default_sign_ecdsa_internal(const uint8_t* input, size_t inputlen, uint8_t* signature, size_t* signaturelen, const uint8_t* privatekey, bool scalaronly)
{
    uint8_t rs[QSC_ECDSA_SIGNATURE_SIZE] = { 0U };
    uint8_t* signedmsg;
    size_t derwritten;
    size_t need;
    size_t smsglen;
    qsc_tls_status status;
    bool res;

    need = QSC_ECDSA_SIGNATURE_SIZE + inputlen;
    signedmsg = (uint8_t*)qsc_memutils_malloc(need);
    res = false;

    if (signedmsg != NULL)
    {
        smsglen = 0U;

        if (scalaronly == true)
        {
            res = qsc_ecdsa_sign_scalar(signedmsg, &smsglen, input, inputlen, privatekey);
        }
        else
        {
            res = qsc_ecdsa_sign(signedmsg, &smsglen, input, inputlen, privatekey);
        }

        if (res && smsglen == need)
        {
            qsc_memutils_copy(rs, signedmsg, QSC_ECDSA_SIGNATURE_SIZE);

            /* DER-encode r||s into the caller's buffer. componentsize = half the raw signature. */
            status = qsc_tls_ecdsa_der_encode(rs, QSC_ECDSA_SIGNATURE_SIZE / 2U, signature, *signaturelen, &derwritten);

            if (status == qsc_tls_status_success)
            {
                *signaturelen = derwritten;
            }
            else
            {
                res = false;
            }
        }
        else
        {
            res = false;
        }

        qsc_memutils_secure_erase(signedmsg, need);
        qsc_memutils_alloc_free(signedmsg);
    }

    qsc_memutils_secure_erase(rs, sizeof(rs));

    return res;
}

static bool tls_signer_default_sign_ecdsa(const uint8_t* input, size_t inputlen, uint8_t* signature, size_t* signaturelen, const uint8_t* privatekey)
{
    return tls_signer_default_sign_ecdsa_internal(input, inputlen, signature, signaturelen, privatekey, false);
}

static bool tls_signer_default_sign_ecdsa_scalar(const uint8_t* input, size_t inputlen, uint8_t* signature, size_t* signaturelen, const uint8_t* privatekey)
{
    return tls_signer_default_sign_ecdsa_internal(input, inputlen, signature, signaturelen, privatekey, true);
}

static bool tls_signer_default_verify_ecdsa(const uint8_t* input, size_t inputlen, const uint8_t* signature, size_t signaturelen, const uint8_t* publickey)
{
    /* decode DER signature from the wire back to raw r||s for QSC verify. */
    uint8_t rs[QSC_ECDSA_SIGNATURE_SIZE] = { 0U };
    uint8_t* signedmsg;
    uint8_t* recovered;
    size_t recoveredlen;
    size_t smsglen;
    qsc_tls_status status;
    bool res;

    res = false;

    status = qsc_tls_ecdsa_der_decode(signature, signaturelen, QSC_ECDSA_SIGNATURE_SIZE / 2U, rs, sizeof(rs));

    if (status == qsc_tls_status_success)
    {
        smsglen = QSC_ECDSA_SIGNATURE_SIZE + inputlen;
        signedmsg = (uint8_t*)qsc_memutils_malloc(smsglen);

        if (signedmsg != NULL)
        {
            recovered = (uint8_t*)qsc_memutils_malloc(inputlen);

            if (recovered != NULL)
            {
                qsc_memutils_copy(signedmsg, rs, QSC_ECDSA_SIGNATURE_SIZE);
                qsc_memutils_copy(signedmsg + QSC_ECDSA_SIGNATURE_SIZE, input, inputlen);
                recoveredlen = 0U;
                res = qsc_ecdsa_verify(recovered, &recoveredlen, signedmsg, smsglen, publickey);

                if (res && recoveredlen == inputlen)
                {
                    if (qsc_memutils_are_equal(recovered, input, inputlen) == false)
                    {
                        res = false;
                    }
                }
                else
                {
                    res = false;
                }

                qsc_memutils_secure_erase(recovered, inputlen);
                qsc_memutils_alloc_free(recovered); 
            }

            qsc_memutils_secure_erase(signedmsg, smsglen); 
            qsc_memutils_alloc_free(signedmsg); 
        }
    }

    qsc_memutils_secure_erase(rs, sizeof(rs));

    return res;
}

bool qsc_tls_signer_default_sign(qsc_tls_signature_scheme scheme, const uint8_t* input, size_t inputlen, uint8_t* signature, size_t* signaturelen, void* state)
{
    QSC_ASSERT(state != NULL);
    QSC_ASSERT(input != NULL);
    QSC_ASSERT(inputlen != 0U);
    QSC_ASSERT(signature != NULL);
    QSC_ASSERT(signaturelen != NULL);

    qsc_tls_signer_default_context* ctx;
    bool res;

    res = false;

    if (state != NULL && input != NULL && inputlen != 0U && signature != NULL && signaturelen != NULL)
    {
        ctx = (qsc_tls_signer_default_context*)state;

        if (ctx->privatekey != NULL && ctx->privatekeylen != 0U)
        {
            switch (scheme)
            {
                case qsc_tls_sig_ed25519:
                {
                    res = tls_signer_default_sign_ed25519(input, inputlen, signature, signaturelen, ctx->privatekey);
                    break;
                }
                case qsc_tls_sig_ecdsa_secp256r1_sha256:
                case qsc_tls_sig_ecdsa_secp384r1_sha384:
                {
                    if (tls_signer_default_ecdsa_matches_scheme(scheme) && ctx->privatekeylen == QSC_ECDSA_PRIVATEKEY_SIZE)
                    {
                        res = tls_signer_default_sign_ecdsa(input, inputlen, signature, signaturelen, ctx->privatekey);
                    }
                    else if (tls_signer_default_ecdsa_matches_scheme(scheme) && ctx->privatekeylen == QSC_ECDSA_SEED_SIZE)
                    {
                        res = tls_signer_default_sign_ecdsa_scalar(input, inputlen, signature, signaturelen, ctx->privatekey);
                    }

                    break;
                }
                case qsc_tls_sig_mldsa44:
                case qsc_tls_sig_mldsa65:
                case qsc_tls_sig_mldsa87:
                {
                    if (ctx->privatekeylen == QSC_DILITHIUM_PRIVATEKEY_SIZE)
                    {
                        res = tls_signer_default_sign_mldsa(input, inputlen, signature, signaturelen, ctx->privatekey);
                    }
                    break;
                }
                default:
                {
                    break;
                }
            }
        }
    }

    return res;
}

bool qsc_tls_signer_default_verify(qsc_tls_signature_scheme scheme, const uint8_t* input, size_t inputlen, const uint8_t* signature, size_t signaturelen, const qsc_tls_certificate_view* signer, void* state)
{
    QSC_ASSERT(signer != NULL);
    QSC_ASSERT(input != NULL);
    QSC_ASSERT(signature != NULL);

    bool res;
    const uint8_t* publickey;

    res = false;
    (void)state;

    if (signer != NULL && signer->data != NULL && signer->datalen != 0U)
    {
        /* the public key is assumed to be presented directly via the certificate data.
         * Real integration with X.509 SPKI extraction is performed in Stage 11 (tlscert encode/decode);
         * this routine keeps the signer module independent of the X.509 DER decoder. If the caller
         * wants SPKI-aware verification, they can set up a qsc_tls_certificate_interface that pre-parses
         * the cert and exposes the raw key bytes through a different callback path. */
        publickey = signer->data;

        switch (scheme)
        {
            case qsc_tls_sig_ed25519:
            {
                if (signer->datalen >= 32U)
                {
                    res = tls_signer_default_verify_ed25519(input, inputlen, signature, signaturelen, publickey);
                }

                break;
            }
            case qsc_tls_sig_ecdsa_secp256r1_sha256:
            case qsc_tls_sig_ecdsa_secp384r1_sha384:
            {
                if (tls_signer_default_ecdsa_matches_scheme(scheme) && signer->datalen >= QSC_ECDSA_PUBLICKEY_SIZE)
                {
                    res = tls_signer_default_verify_ecdsa(input, inputlen, signature, signaturelen, publickey);
                }

                break;
            }
            case qsc_tls_sig_mldsa44:
            case qsc_tls_sig_mldsa65:
            case qsc_tls_sig_mldsa87:
            {
                if (signer->datalen >= QSC_DILITHIUM_PUBLICKEY_SIZE)
                {
                    res = tls_signer_default_verify_mldsa(input, inputlen, signature, signaturelen, publickey);
                }

                break;
            }
            default:
            {
                break;
            }
        }
    }

    return res;
}
