#include "tlssignerdefault.h"
#include "csp.h"
#include "ecdsap256.h"
#include "ecdsap384.h"
#include "ecdsap521.h"
#include "eddsa25519.h"
#include "eddsa448.h"
#include "mldsa.h"
#include "memutils.h"
#include "tlsecdsader.h"
#include "tlssigalgs.h"

/**
 * \brief Sign a TLS CertificateVerify input with the chosen EdDSA parameter set.
 * \param scheme Selected Ed25519 or Ed448 signature scheme.
 * \param input Nonempty message bytes to sign.
 * \param inputlen Message length in bytes.
 * \param signature Caller output, capacity in signaturelen on entry.
 * \param signaturelen In/out signature length in bytes.
 * \param privatekey Caller-owned seed or expanded private key.
 * \param privatekeylen Input key length in bytes.
 * \return True on successful signing; false for insufficient capacity or invalid key.
 * \note No global state; caller protects private key and is responsible for concurrency.
 */
static bool tls_signer_default_sign_eddsa(qsc_tls_signature_scheme scheme, const uint8_t* input, size_t inputlen, uint8_t* signature, size_t* signaturelen, const uint8_t* privatekey, size_t privatekeylen)
{
    uint8_t derivedprivate[QSC_ED448_PRIVATEKEY_SIZE] = { 0U };
    uint8_t derivedpublic[QSC_ED448_PUBLICKEY_SIZE] = { 0U };
    const uint8_t* signingkey;
    uint8_t* signedmsg;
    size_t seedlen;
    size_t keylen;
    size_t siglen;
    size_t need;
    size_t smsglen;
    bool res;

    signingkey = NULL;
    signedmsg = NULL;
    seedlen = 0U;
    keylen = 0U;
    siglen = qsc_tls_signature_scheme_signature_size(scheme);
    smsglen = 0U;
    res = false;

    if (scheme == qsc_tls_sig_ed25519)
    {
        seedlen = QSC_ED25519_SEED_SIZE;
        keylen = QSC_ED25519_PRIVATEKEY_SIZE;
    }
    else if (scheme == qsc_tls_sig_ed448)
    {
        seedlen = QSC_ED448_SEED_SIZE;
        keylen = QSC_ED448_PRIVATEKEY_SIZE;
    }

    if (keylen != 0U && *signaturelen >= siglen)
    {
        if (privatekeylen == keylen)
        {
            signingkey = privatekey;
        }
        else if (privatekeylen == seedlen)
        {
            if (scheme == qsc_tls_sig_ed25519)
            {
                qsc_ed25519_generate_seeded_keypair(derivedpublic, derivedprivate, privatekey);
            }
            else
            {
                qsc_ed448_generate_seeded_keypair(derivedpublic, derivedprivate, privatekey);
            }

            signingkey = derivedprivate;
        }

        if (signingkey != NULL && inputlen <= (SIZE_MAX - siglen))
        {
            need = siglen + inputlen;
            signedmsg = (uint8_t*)qsc_memutils_malloc(need);

            if (signedmsg != NULL)
            {
                if (scheme == qsc_tls_sig_ed25519)
                {
                    res = qsc_ed25519_sign(signedmsg, &smsglen, input, inputlen, signingkey);
                }
                else
                {
                    res = qsc_ed448_sign(signedmsg, &smsglen, input, inputlen, signingkey);
                }

                if (res == true && smsglen == need)
                {
                    qsc_memutils_copy(signature, signedmsg, siglen);
                    *signaturelen = siglen;
                }
                else
                {
                    res = false;
                }

                qsc_memutils_secure_erase(signedmsg, need);
                qsc_memutils_alloc_free(signedmsg);
            }
        }
    }

    qsc_memutils_secure_erase(derivedprivate, sizeof(derivedprivate));
    qsc_memutils_clear(derivedpublic, sizeof(derivedpublic));
    return res;
}

/**
 * \brief Verify an Ed25519 or Ed448 detached signature and the recovered message.
 * \param scheme Selected EdDSA parameter set.
 * \param input Signed TLS CertificateVerify message.
 * \param inputlen Message length in bytes.
 * \param signature Detached signature buffer.
 * \param signaturelen Signature length in bytes.
 * \param publickey Exact-size curve public key.
 * \return True only when both signature and recovered message verify.
 * \note Uses temporary caller-independent buffers; thread-safe for immutable inputs.
 */
static bool tls_signer_default_verify_eddsa(qsc_tls_signature_scheme scheme, const uint8_t* input, size_t inputlen, const uint8_t* signature, size_t signaturelen, const uint8_t* publickey)
{
    uint8_t* recovered;
    uint8_t* signedmsg;
    size_t recoveredlen;
    size_t smsglen;
    bool res;

    recovered = NULL;
    signedmsg = NULL;
    recoveredlen = 0U;
    smsglen = 0U;
    res = false;

    if (signaturelen == qsc_tls_signature_scheme_signature_size(scheme) && inputlen <= SIZE_MAX - signaturelen)
    {
        smsglen = signaturelen + inputlen;
        signedmsg = (uint8_t*)qsc_memutils_malloc(smsglen);
        recovered = (uint8_t*)qsc_memutils_malloc(inputlen);

        if (signedmsg != NULL && recovered != NULL)
        {
            qsc_memutils_copy(signedmsg, signature, signaturelen);
            qsc_memutils_copy(signedmsg + signaturelen, input, inputlen);

            if (scheme == qsc_tls_sig_ed25519)
            {
                res = qsc_ed25519_verify(recovered, &recoveredlen, signedmsg, smsglen, publickey);
            }
            else if (scheme == qsc_tls_sig_ed448)
            {
                res = qsc_ed448_verify(recovered, &recoveredlen, signedmsg, smsglen, publickey);
            }

            res = (res == true && recoveredlen == inputlen && qsc_memutils_are_equal(recovered, input, inputlen) == true);
        }

        if (recovered != NULL)
        {
            qsc_memutils_secure_erase(recovered, inputlen);
            qsc_memutils_alloc_free(recovered);
        }

        if (signedmsg != NULL)
        {
            qsc_memutils_secure_erase(signedmsg, smsglen);
            qsc_memutils_alloc_free(signedmsg);
        }
    }

    return res;
}

/**
 * \brief Sign with a specific ML-DSA parameter set using pure signing with empty context.
 * \param scheme Selected ML-DSA-44, 65, or 87.
 * \param input Nonempty input message.
 * \param inputlen Message size in bytes.
 * \param signature Caller-owned signature buffer.
 * \param signaturelen In/out capacity and resulting signature length.
 * \param privatekey Parameter-specific secret signing key.
 * \return True only if the output signature was generated within bounds.
 * \note RNG callback must be thread safe; the temporary signed message is erased.
 */
static bool tls_signer_default_sign_mldsa(qsc_tls_signature_scheme scheme, const uint8_t* input, size_t inputlen, uint8_t* signature, size_t* signaturelen, const uint8_t* privatekey)
{
    uint8_t* signedmsg;
    size_t siglen;
    size_t need;
    size_t smsglen;
    bool res;

    signedmsg = NULL;
    siglen = qsc_tls_signature_scheme_signature_size(scheme);
    smsglen = 0U;
    res = false;

    if (siglen != 0U && *signaturelen >= siglen && inputlen <= SIZE_MAX - siglen)
    {
        need = siglen + inputlen;
        signedmsg = (uint8_t*)qsc_memutils_malloc(need);

        if (signedmsg != NULL)
        {
            switch (scheme)
            {
                case qsc_tls_sig_mldsa44:
                {
                    res = qsc_mldsa44_sign_ex(signedmsg, &smsglen, input, inputlen, NULL, 0U, privatekey, qsc_csp_generate);
                    break;
                }
                case qsc_tls_sig_mldsa65:
                {
                    res = qsc_mldsa65_sign_ex(signedmsg, &smsglen, input, inputlen, NULL, 0U, privatekey, qsc_csp_generate);
                    break;
                }
                case qsc_tls_sig_mldsa87:
                {
                    res = qsc_mldsa87_sign_ex(signedmsg, &smsglen, input, inputlen, NULL, 0U, privatekey, qsc_csp_generate);
                    break;
                }
                default:
                {
                    break;
                }
            }

            if (res == true && smsglen == need)
            {
                qsc_memutils_copy(signature, signedmsg, siglen);
                *signaturelen = siglen;
            }
            else
            {
                res = false;
            }

            qsc_memutils_secure_erase(signedmsg, need);
            qsc_memutils_alloc_free(signedmsg);
        }
    }

    return res;
}

/**
 * \brief Verify an exact ML-DSA scheme using its parameter-specific FIPS 204 API.
 * \param scheme ML-DSA variant indicated by the wire signature scheme.
 * \param input Original input message.
 * \param inputlen Length of input in bytes.
 * \param signature Detached signature bytes.
 * \param signaturelen Signature size in bytes.
 * \param publickey Exact matching parameter-set verification key.
 * \return True if the signed message verifies and matches input.
 * \note Temporary buffers are erased and freed before return.
 */
static bool tls_signer_default_verify_mldsa(qsc_tls_signature_scheme scheme, const uint8_t* input, size_t inputlen, const uint8_t* signature, size_t signaturelen, const uint8_t* publickey)
{
    uint8_t* signedmsg;
    uint8_t* recovered;
    size_t smsglen;
    size_t recoveredlen;
    bool res;

    signedmsg = NULL;
    recovered = NULL;
    smsglen = 0U;
    recoveredlen = 0U;
    res = false;

    if (signaturelen == qsc_tls_signature_scheme_signature_size(scheme) && inputlen <= SIZE_MAX - signaturelen)
    {
        smsglen = signaturelen + inputlen;
        signedmsg = (uint8_t*)qsc_memutils_malloc(smsglen);
        recovered = (uint8_t*)qsc_memutils_malloc(inputlen);

        if (signedmsg != NULL && recovered != NULL)
        {
            qsc_memutils_copy(signedmsg, signature, signaturelen);
            qsc_memutils_copy(signedmsg + signaturelen, input, inputlen);

            switch (scheme)
            {
                case qsc_tls_sig_mldsa44:
                {
                    res = qsc_mldsa44_verify_ex(recovered, &recoveredlen, NULL, 0U, signedmsg, smsglen, publickey);
                    break;
                }
                case qsc_tls_sig_mldsa65:
                {
                    res = qsc_mldsa65_verify_ex(recovered, &recoveredlen, NULL, 0U, signedmsg, smsglen, publickey);
                    break;
                }
                case qsc_tls_sig_mldsa87:
                {
                    res = qsc_mldsa87_verify_ex(recovered, &recoveredlen, NULL, 0U, signedmsg, smsglen, publickey);
                    break;
                }
                default:
                {
                    break;
                }
            }

            res = (res == true && recoveredlen == inputlen && qsc_memutils_are_equal(recovered, input, inputlen) == true);
        }

        if (recovered != NULL)
        {
            qsc_memutils_secure_erase(recovered, inputlen);
            qsc_memutils_alloc_free(recovered);
        }

        if (signedmsg != NULL)
        {
            qsc_memutils_secure_erase(signedmsg, smsglen);
            qsc_memutils_alloc_free(signedmsg);
        }
    }

    return res;
}

/**
 * \brief Sign a TLS ECDSA message using its exact P-256, P-384 or P-521 scheme.
 * \param scheme ECDSA signature scheme.
 * \param input Original input message.
 * \param inputlen Length in bytes.
 * \param signature DER signature destination.
 * \param signaturelen In/out capacity and DER length.
 * \param privatekey Curve-specific private key or scalar.
 * \param scalaronly True for the existing scalar signing mode.
 * \return True on successful DER-encoded signature.
 * \note Local buffers are erased before returning; no internal shared state.
 */
static bool tls_signer_default_sign_ecdsa(qsc_tls_signature_scheme scheme, const uint8_t* input, size_t inputlen, uint8_t* signature, size_t* signaturelen, const uint8_t* privatekey, bool scalaronly)
{
    uint8_t rs[132U] = { 0U };
    uint8_t* signedmsg;
    size_t rawlen;
    size_t need;
    size_t smsglen;
    size_t derwritten;
    qsc_tls_status status;
    int32_t result;
    bool res;

    rawlen = 0U;
    signedmsg = NULL;
    smsglen = 0U;
    derwritten = 0U;
    result = -1;
    res = false;

    if (scheme == qsc_tls_sig_ecdsa_secp256r1_sha256)
    {
        rawlen = 64U;
    }
    else if (scheme == qsc_tls_sig_ecdsa_secp384r1_sha384)
    {
        rawlen = 96U;
    }
    else if (scheme == qsc_tls_sig_ecdsa_secp521r1_sha512)
    {
        rawlen = 132U;
    }

    if (rawlen != 0U && inputlen <= SIZE_MAX - rawlen)
    {
        need = rawlen + inputlen;
        signedmsg = (uint8_t*)qsc_memutils_malloc(need);

        if (signedmsg != NULL)
        {
            switch (scheme)
            {
                case qsc_tls_sig_ecdsa_secp256r1_sha256:
                {
                    result = (scalaronly == true) ? qsc_p256_sign_scalar(signedmsg, &smsglen, input, inputlen, privatekey) : qsc_p256_sign(signedmsg, &smsglen, input, inputlen, privatekey);
                    break;
                }
                case qsc_tls_sig_ecdsa_secp384r1_sha384:
                {
                    result = (scalaronly == true) ? qsc_p384_sign_scalar(signedmsg, &smsglen, input, inputlen, privatekey) : qsc_p384_sign(signedmsg, &smsglen, input, inputlen, privatekey);
                    break;
                }
                case qsc_tls_sig_ecdsa_secp521r1_sha512:
                {
                    result = (scalaronly == true) ? qsc_p521_sign_scalar(signedmsg, &smsglen, input, inputlen, privatekey) : qsc_p521_sign(signedmsg, &smsglen, input, inputlen, privatekey);
                    break;
                }
                default:
                {
                    break;
                }
            }

            if (result == 0 && smsglen == need)
            {
                qsc_memutils_copy(rs, signedmsg, rawlen);
                status = qsc_tls_ecdsa_der_encode(rs, rawlen / 2U, signature, *signaturelen, &derwritten);

                if (status == qsc_tls_status_success)
                {
                    *signaturelen = derwritten;
                    res = true;
                }
            }

            qsc_memutils_secure_erase(signedmsg, need);
            qsc_memutils_alloc_free(signedmsg);
        }
    }

    qsc_memutils_secure_erase(rs, sizeof(rs));
    return res;
}

/**
 * \brief Verify a DER-encoded TLS ECDSA signature with exact curve dispatch.
 * \param scheme ECDSA scheme matching the signer's curve.
 * \param input Original message.
 * \param inputlen Message bytes.
 * \param signature DER signature bytes.
 * \param signaturelen Signature length in bytes.
 * \param publickey Curve-specific verification key.
 * \return True for a valid DER signature and recovered original message.
 * \note Does not modify the caller's buffers and erases intermediate values.
 */
static bool tls_signer_default_verify_ecdsa(qsc_tls_signature_scheme scheme, const uint8_t* input, size_t inputlen, const uint8_t* signature, size_t signaturelen, const uint8_t* publickey)
{
    uint8_t rs[132U] = { 0U };
    uint8_t* signedmsg;
    uint8_t* recovered;
    size_t rawlen;
    size_t smsglen;
    size_t recoveredlen;
    qsc_tls_status status;
    bool res;

    signedmsg = NULL;
    recovered = NULL;
    rawlen = 0U;
    smsglen = 0U;
    recoveredlen = 0U;
    res = false;

    if (scheme == qsc_tls_sig_ecdsa_secp256r1_sha256)
    {
        rawlen = 64U;
    }
    else if (scheme == qsc_tls_sig_ecdsa_secp384r1_sha384)
    {
        rawlen = 96U;
    }
    else if (scheme == qsc_tls_sig_ecdsa_secp521r1_sha512)
    {
        rawlen = 132U;
    }

    if (rawlen != 0U && inputlen <= SIZE_MAX - rawlen)
    {
        status = qsc_tls_ecdsa_der_decode(signature, signaturelen, rawlen / 2U, rs, sizeof(rs));

        if (status == qsc_tls_status_success)
        {
            smsglen = rawlen + inputlen;
            signedmsg = (uint8_t*)qsc_memutils_malloc(smsglen);
            recovered = (uint8_t*)qsc_memutils_malloc(inputlen);

            if (signedmsg != NULL && recovered != NULL)
            {
                qsc_memutils_copy(signedmsg, rs, rawlen);
                qsc_memutils_copy(signedmsg + rawlen, input, inputlen);

                switch (scheme)
                {
                    case qsc_tls_sig_ecdsa_secp256r1_sha256:
                    {
                        res = qsc_p256_verify(recovered, &recoveredlen, signedmsg, smsglen, publickey);
                        break;
                    }
                    case qsc_tls_sig_ecdsa_secp384r1_sha384:
                    {
                        res = qsc_p384_verify(recovered, &recoveredlen, signedmsg, smsglen, publickey);
                        break;
                    }
                    case qsc_tls_sig_ecdsa_secp521r1_sha512:
                    {
                        res = qsc_p521_verify(recovered, &recoveredlen, signedmsg, smsglen, publickey);
                        break;
                    }
                    default:
                    {
                        break;
                    }
                }

                res = (res == true && recoveredlen == inputlen && qsc_memutils_are_equal(recovered, input, inputlen) == true);
            }

            if (recovered != NULL)
            {
                qsc_memutils_secure_erase(recovered, inputlen);
                qsc_memutils_alloc_free(recovered);
            }

            if (signedmsg != NULL)
            {
                qsc_memutils_secure_erase(signedmsg, smsglen);
                qsc_memutils_alloc_free(signedmsg);
            }
        }
    }

    qsc_memutils_secure_erase(rs, sizeof(rs));
    return res;
}

bool qsc_tls_signer_default_sign(qsc_tls_signature_scheme scheme, const uint8_t* input, size_t inputlen, uint8_t* signature, size_t* signaturelen, void* state)
{
    qsc_tls_signer_default_context* ctx;
    size_t keylen;
    bool res;

    ctx = NULL;
    keylen = 0U;
    res = false;

    if (state != NULL && input != NULL && inputlen != 0U && signature != NULL && signaturelen != NULL)
    {
        ctx = (qsc_tls_signer_default_context*)state;

        if (ctx->privatekey != NULL && ctx->privatekeylen != 0U)
        {
            switch (scheme)
            {
                case qsc_tls_sig_ed25519:
                case qsc_tls_sig_ed448:
                {
                    res = tls_signer_default_sign_eddsa(scheme, input, inputlen, signature, signaturelen, ctx->privatekey, ctx->privatekeylen);
                    break;
                }
                case qsc_tls_sig_ecdsa_secp256r1_sha256:
                case qsc_tls_sig_ecdsa_secp384r1_sha384:
                case qsc_tls_sig_ecdsa_secp521r1_sha512:
                {
                    keylen = qsc_tls_signature_scheme_private_key_size(scheme);

                    if (ctx->privatekeylen == keylen)
                    {
                        res = tls_signer_default_sign_ecdsa(scheme, input, inputlen, signature, signaturelen, ctx->privatekey, false);
                    }
                    else if (ctx->privatekeylen == keylen / 3U)
                    {
                        /* The scalar API takes only the seed; expanded keys include two extra coordinates. */
                        res = tls_signer_default_sign_ecdsa(scheme, input, inputlen, signature, signaturelen, ctx->privatekey, true);
                    }

                    break;
                }
                case qsc_tls_sig_mldsa44:
                case qsc_tls_sig_mldsa65:
                case qsc_tls_sig_mldsa87:
                {
                    keylen = qsc_tls_signature_scheme_private_key_size(scheme);

                    if (ctx->privatekeylen == keylen)
                    {
                        res = tls_signer_default_sign_mldsa(scheme, input, inputlen, signature, signaturelen, ctx->privatekey);
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
    const uint8_t* publickey;
    size_t keylen;
    bool res;

    publickey = NULL;
    keylen = 0U;
    res = false;
    (void)state;

    if (signer != NULL && signer->data != NULL && input != NULL && inputlen != 0U && signature != NULL &&
        qsc_tls_signature_scheme_validate_signature_length(scheme, signaturelen) == true)
    {
        publickey = signer->data;
        keylen = qsc_tls_signature_scheme_public_key_size(scheme);

        if (keylen != 0U && signer->datalen == keylen)
        {
            switch (scheme)
            {
                case qsc_tls_sig_ed25519:
                case qsc_tls_sig_ed448:
                {
                    res = tls_signer_default_verify_eddsa(scheme, input, inputlen, signature, signaturelen, publickey);
                    break;
                }
                case qsc_tls_sig_ecdsa_secp256r1_sha256:
                case qsc_tls_sig_ecdsa_secp384r1_sha384:
                case qsc_tls_sig_ecdsa_secp521r1_sha512:
                {
                    res = tls_signer_default_verify_ecdsa(scheme, input, inputlen, signature, signaturelen, publickey);
                    break;
                }
                case qsc_tls_sig_mldsa44:
                case qsc_tls_sig_mldsa65:
                case qsc_tls_sig_mldsa87:
                {
                    res = tls_signer_default_verify_mldsa(scheme, input, inputlen, signature, signaturelen, publickey);
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
