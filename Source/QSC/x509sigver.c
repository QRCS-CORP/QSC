#include "x509sigver.h"
#include "mldsa.h"
#include "ecdsap256.h"
#include "ecdsap384.h"
#include "ecdsap521.h"
#include "eddsa25519.h"
#include "eddsa448.h"
#include "memutils.h"
#include "sha2.h"
#include "x509sig.h"
#include "x509spki.h"
#include "x509verify.h"

static bool x509_sigver_ct_equal(const uint8_t* left, const uint8_t* right, size_t length)
{
    uint8_t diff;
    size_t i;
    bool res;

    diff = 0U;
    i = 0U;
    res = false;

    if ((left != NULL) && (right != NULL))
    {
        for (i = 0U; i < length; ++i)
        {
            diff |= (uint8_t)(left[i] ^ right[i]);
        }

        res = (diff == 0U);
    }

    return res;
}

static size_t x509_sigver_expected_mldsa_signature_size(qsc_x509_signature_algorithm sigalg)
{
    return qsc_x509_signature_expected_size(sigalg, QSC_X509_NAMED_CURVE_NONE);
}

static size_t x509_curve_coordinate_size(qsc_x509_named_curve curve)
{
    return qsc_x509_named_curve_coordinate_size(curve);
}

/**
 * \brief Validate an ECDSA signature hash and EC subject-key curve independently.
 * \param sigalg Certificate signature hash algorithm.
 * \param curve Issuer EC public-key named curve.
 * \return True for the supported SHA-2 and NIST curve combinations.
 * \note No state is modified. TLS CertificateVerify pairings are not affected.
 */
static bool x509_qsc_verify_is_supported_ecdsa(qsc_x509_signature_algorithm sigalg, qsc_x509_named_curve curve)
{
	bool res;

	res = ((sigalg == QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA256) ||
		(sigalg == QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA384) ||
		(sigalg == QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA512)) &&
		((curve == QSC_X509_NAMED_CURVE_PRIME256V1) ||
		(curve == QSC_X509_NAMED_CURVE_SECP384R1) ||
		(curve == QSC_X509_NAMED_CURVE_SECP521R1));

	return res;
}

static bool x509_qsc_copy_ecdsa_signature_raw(uint8_t* rawsig, size_t rawsiglen, const qsc_x509_ecdsa_signature* esig)
{
    bool res;

    res = false;

    if ((rawsig != NULL) && (esig != NULL) && (rawsiglen >= (2U * esig->length)))
    {
        qsc_memutils_copy(rawsig, esig->r, esig->length);
        qsc_memutils_copy(rawsig + esig->length, esig->s, esig->length);
        res = true;
    }

    return res;
}

/**
 * \brief Verify an ECDSA signature against the digest selected by the X.509 OID.
 * \param msgout Output recovered certificate signed-message bytes.
 * \param msglen Output length in bytes.
 * \param signedmsg Raw fixed-width signature followed by the signed DER region.
 * \param smsglen Signed-message total size in bytes.
 * \param publickey Issuer raw NIST-curve public key.
 * \param curve Issuer EC public-key named curve.
 * \param sigalg ECDSA SHA-2 signature algorithm OID.
 * \return True if the certificate signature matches the signed region.
 * \note Scratch digest is erased. No allocations or shared mutable state.
 */
static bool x509_qsc_verify_message(uint8_t* msgout, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey, qsc_x509_named_curve curve, qsc_x509_signature_algorithm sigalg)
{
	uint8_t digest[64U] = { 0U };
	const uint8_t* message;
	size_t digestlen;
	size_t offset;
	bool res;

	digestlen = 0U;
	offset = 2U * qsc_x509_named_curve_coordinate_size(curve);
	message = NULL;
	res = false;

	if ((signedmsg != NULL) && (publickey != NULL) && (msgout != NULL) && (msglen != NULL) &&
		(offset != 0U) && (smsglen >= offset))
	{
		message = signedmsg + offset;

		switch (sigalg)
		{
			case QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA256:
			{
				qsc_sha256_compute(digest, message, smsglen - offset);
				digestlen = 32U;
				break;
			}
			case QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA384:
			{
				qsc_sha384_compute(digest, message, smsglen - offset);
				digestlen = 48U;
				break;
			}
			case QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA512:
			{
				qsc_sha512_compute(digest, message, smsglen - offset);
				digestlen = 64U;
				break;
			}
			default:
			{
				break;
			}
		}

		if (digestlen != 0U)
		{
			if (curve == QSC_X509_NAMED_CURVE_PRIME256V1)
			{
				res = qsc_p256_verify_prehashed(msgout, msglen, signedmsg, smsglen, publickey, digest, digestlen);
			}
			else if (curve == QSC_X509_NAMED_CURVE_SECP384R1)
			{
				res = qsc_p384_verify_prehashed(msgout, msglen, signedmsg, smsglen, publickey, digest, digestlen);
			}
			else if (curve == QSC_X509_NAMED_CURVE_SECP521R1)
			{
				res = qsc_p521_verify_prehashed(msgout, msglen, signedmsg, smsglen, publickey, digest, digestlen);
			}
		}
	}

	qsc_memutils_secure_erase(digest, sizeof(digest));
	return res;
}

static bool x509_sigver_state_is_valid(const qsc_x509_verify_state* state)
{
    bool res;

    res = false;

    if (state != NULL)
    {
        res = (state->signaturemessage != NULL) && (state->signaturemessage_size != 0U);
    }

    return res;
}

static bool x509_sigver_signed_region_is_valid(const uint8_t* data, size_t datalen)
{
    return (data != NULL) && (datalen != 0U);
}

static bool x509_qsc_verify_ecdsa(const uint8_t* data, size_t datalen, const uint8_t* dersignature, size_t dersignaturelen, uint8_t unusedbits,
    qsc_x509_signature_algorithm sigalg, const qsc_x509_subject_public_key_info* spki, qsc_x509_verify_state* vstate)
{
    qsc_x509_ecdsa_signature esig = { 0 };
    qsc_encoding_ber_element outer = { 0 };
    uint8_t bitstring[1U + QSC_X509_SIGNATURE_MAX] = { 0U };
    uint8_t pubkey[132U] = { 0U };
    uint8_t x[66U] = { 0U };
    uint8_t y[66U] = { 0U };
    uint8_t* signedmsg;
    uint8_t* recovered;
    size_t buflen;
    size_t coordlen;
    size_t msglen;
    size_t sigrawlen;
    size_t signedmsglen;
    bool res;

    signedmsg = NULL;
    recovered = NULL;
    buflen = 0U;
    coordlen = 0U;
    msglen = 0U;
    sigrawlen = 0U;
    signedmsglen = 0U;
    res = false;

    if (x509_sigver_signed_region_is_valid(data, datalen) == true &&
        (dersignature != NULL) && (dersignaturelen != 0U) &&
        (spki != NULL) && (x509_sigver_state_is_valid(vstate) == true) &&
        (x509_qsc_verify_is_supported_ecdsa(sigalg, spki->algorithm.curve) == true) &&
        (unusedbits == 0U) &&
        (qsc_x509_signature_algorithm_matches_spki(sigalg, spki) == true))
    {
        coordlen = x509_curve_coordinate_size(spki->algorithm.curve);
        sigrawlen = 2U * coordlen;
        signedmsglen = sigrawlen + datalen;
        buflen = vstate->signaturemessage_size;

        if (((dersignaturelen + 1U) <= sizeof(bitstring)) && (coordlen != 0U) && (buflen >= (signedmsglen + datalen)))
        {
            signedmsg = vstate->signaturemessage;
            recovered = vstate->signaturemessage + signedmsglen;

            outer.tagclass = 0x00U;
            outer.constructed = false;
            outer.tagnumber = 3U;
            outer.length = dersignaturelen + 1U;
            outer.value = bitstring;

            bitstring[0U] = unusedbits;
            qsc_memutils_copy(bitstring + 1U, dersignature, dersignaturelen);

            if ((qsc_x509_signature_value_decode_ecdsa(&outer, spki->algorithm.curve, &esig) == QSC_ASN1_STATUS_SUCCESS) &&
                (qsc_x509_spki_get_ec_coordinates(spki, x, coordlen, y, coordlen) == QSC_ASN1_STATUS_SUCCESS) &&
                (x509_qsc_copy_ecdsa_signature_raw(signedmsg, sigrawlen, &esig) == true))
            {
                qsc_memutils_copy(pubkey, x, coordlen);
                qsc_memutils_copy(pubkey + coordlen, y, coordlen);
                qsc_memutils_copy(signedmsg + sigrawlen, data, datalen);
                qsc_memutils_secure_erase(recovered, datalen);

                res = x509_qsc_verify_message(recovered, &msglen, signedmsg, signedmsglen, pubkey, spki->algorithm.curve, sigalg);

                if ((res == true) && ((msglen != datalen) || (x509_sigver_ct_equal(recovered, data, datalen) == false)))
                {
                    res = false;
                }
            }
        }
    }

    qsc_memutils_secure_erase(pubkey, sizeof(pubkey));
    qsc_memutils_secure_erase(x, sizeof(x));
    qsc_memutils_secure_erase(y, sizeof(y));
    qsc_memutils_secure_erase((uint8_t*)&esig, sizeof(qsc_x509_ecdsa_signature));

    return res;
}

static bool x509_qsc_verify_mldsa(const uint8_t* data, size_t datalen, const uint8_t* signature, size_t signaturelen,
    qsc_x509_signature_algorithm sigalg, const qsc_x509_subject_public_key_info* spki, qsc_x509_verify_state* vstate)
{
    uint8_t* signedmsg;
    uint8_t* recovered;
    size_t msglen;
    size_t required;
    bool res;
    bool verified;

    signedmsg = NULL;
    recovered = NULL;
    msglen = 0U;
    required = 0U;
    res = false;
    verified = false;

    if (x509_sigver_signed_region_is_valid(data, datalen) == true &&
        (signature != NULL) && (signaturelen != 0U) &&
        (spki != NULL) && (x509_sigver_state_is_valid(vstate) == true) &&
        (qsc_x509_signature_algorithm_matches_spki(sigalg, spki) == true) &&
        (signaturelen == x509_sigver_expected_mldsa_signature_size(sigalg)) &&
        (spki->publickeylen == qsc_x509_pqc_public_key_size(spki->algorithm.pqcparameter)))
    {
        required = signaturelen + (2U * datalen);

        if (vstate->signaturemessage_size >= required)
        {
            signedmsg = vstate->signaturemessage;
            recovered = vstate->signaturemessage + signaturelen + datalen;
            qsc_memutils_copy(signedmsg, signature, signaturelen);
            qsc_memutils_copy(signedmsg + signaturelen, data, datalen);
            qsc_memutils_secure_erase(recovered, datalen);

            verified = false;

            if (sigalg == QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_44)
            {
                verified = qsc_mldsa44_verify(recovered, &msglen, signedmsg, signaturelen + datalen, spki->publickey);
            }
            else if (sigalg == QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_65)
            {
                verified = qsc_mldsa65_verify(recovered, &msglen, signedmsg, signaturelen + datalen, spki->publickey);
            }
            else if (sigalg == QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_87)
            {
                verified = qsc_mldsa87_verify(recovered, &msglen, signedmsg, signaturelen + datalen, spki->publickey);
            }

            if (verified == true)
            {
                res = (msglen == datalen) && (x509_sigver_ct_equal(recovered, data, datalen) == true);
            }
        }
    }

    return res;
}

static bool x509_sigver_algorithm_is_supported(qsc_x509_signature_algorithm signaturealgorithm)
{
    return (signaturealgorithm == QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA256) ||
           (signaturealgorithm == QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA384) ||
           (signaturealgorithm == QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA512) ||
           (signaturealgorithm == QSC_X509_SIGNATURE_ALGORITHM_ED25519) ||
           (signaturealgorithm == QSC_X509_SIGNATURE_ALGORITHM_ED448) ||
           (signaturealgorithm == QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_44) ||
           (signaturealgorithm == QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_65) ||
           (signaturealgorithm == QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_87);
}

static bool x509_sigver_verify_preserved_region(const uint8_t* data, size_t datalen, const uint8_t* signature, size_t signaturelen, uint8_t unusedbits,
    const qsc_x509_algorithm_identifier* inneralgorithm, const qsc_x509_algorithm_identifier* outeralgorithm, const qsc_x509_subject_public_key_info* spki, qsc_x509_verify_state* vstate)
{
    bool res;

    res = false;

    if (x509_sigver_signed_region_is_valid(data, datalen) == true &&
        (signature != NULL) && (signaturelen != 0U) &&
        (spki != NULL) && (x509_sigver_state_is_valid(vstate) == true) &&
        (outeralgorithm != NULL) &&
        (x509_sigver_algorithm_is_supported(outeralgorithm->signature) == true) &&
        ((inneralgorithm == NULL) || (qsc_x509_signature_algorithm_equal(inneralgorithm, outeralgorithm) == true)) &&
        (qsc_x509_signature_algorithm_matches_spki(outeralgorithm->signature, spki) == true))
    {
        res = qsc_x509_qsc_verify_signed_data(data, datalen, signature, signaturelen,
            unusedbits, outeralgorithm->signature, spki, vstate);
    }

    return res;
}

void qsc_x509_qsc_verify_state_initialize(qsc_x509_verify_state* state, uint8_t* buffer, size_t buflen)
{
    QSC_ASSERT(state != NULL);

    if (state != NULL)
    {
        state->signaturemessage = buffer;
        state->signaturemessage_size = buflen;
    }
}

bool qsc_x509_qsc_verify_signed_data(const uint8_t* data, size_t datalen, const uint8_t* signature, size_t signaturelen, uint8_t unusedbits,
    qsc_x509_signature_algorithm signaturealgorithm, const qsc_x509_subject_public_key_info* spki, void* state)
{
    QSC_ASSERT(spki != NULL);
    QSC_ASSERT(state != NULL);

    bool res;

    res = false;

    if ((spki != NULL) && (state != NULL) &&
        (x509_sigver_signed_region_is_valid(data, datalen) == true) &&
        (signature != NULL) && (signaturelen != 0U) &&
        (x509_sigver_algorithm_is_supported(signaturealgorithm) == true) &&
        (qsc_x509_signature_algorithm_matches_spki(signaturealgorithm, spki) == true))
    {
        if ((signaturealgorithm == QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA256) ||
            (signaturealgorithm == QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA384) ||
            (signaturealgorithm == QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA512))
        {
            res = x509_qsc_verify_ecdsa(data, datalen, signature, signaturelen, unusedbits, signaturealgorithm, spki, (qsc_x509_verify_state*)state);
        }
        else if ((signaturealgorithm == QSC_X509_SIGNATURE_ALGORITHM_ED25519) ||
            (signaturealgorithm == QSC_X509_SIGNATURE_ALGORITHM_ED448))
        {
            uint8_t* signedmsg;
            uint8_t* recovered;
            size_t msglen;
            size_t required;

            msglen = 0U;
            required = 0U;
            signedmsg = NULL;
            recovered = NULL;

            if ((unusedbits == 0U) &&
                (signaturelen == qsc_x509_signature_expected_size(signaturealgorithm, QSC_X509_NAMED_CURVE_NONE)) &&
                (spki->publickeylen == ((signaturealgorithm == QSC_X509_SIGNATURE_ALGORITHM_ED25519) ?
                    QSC_ED25519_PUBLICKEY_SIZE : QSC_ED448_PUBLICKEY_SIZE)) &&
                (x509_sigver_state_is_valid((qsc_x509_verify_state*)state) == true))
            {
                required = signaturelen + (2U * datalen);

                if (((qsc_x509_verify_state*)state)->signaturemessage_size >= required)
                {
                    signedmsg = ((qsc_x509_verify_state*)state)->signaturemessage;
                    recovered = signedmsg + signaturelen + datalen;
                    qsc_memutils_copy(signedmsg, signature, signaturelen);
                    qsc_memutils_copy(signedmsg + signaturelen, data, datalen);
                    qsc_memutils_secure_erase(recovered, datalen);

                    bool verified;

                    verified = false;

                    if (signaturealgorithm == QSC_X509_SIGNATURE_ALGORITHM_ED25519)
                    {
                        verified = qsc_ed25519_verify(recovered, &msglen, signedmsg, signaturelen + datalen, spki->publickey);
                    }
                    else
                    {
                        verified = qsc_ed448_verify(recovered, &msglen, signedmsg, signaturelen + datalen, spki->publickey);
                    }

                    if (verified == true)
                    {
                        res = (msglen == datalen) && (x509_sigver_ct_equal(recovered, data, datalen) == true);
                    }
                }
            }
        }
        else if ((signaturealgorithm == QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_44) ||
                 (signaturealgorithm == QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_65) ||
                 (signaturealgorithm == QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_87))
        {
            if (unusedbits == 0U)
            {
                res = x509_qsc_verify_mldsa(data, datalen, signature, signaturelen, signaturealgorithm, spki, (qsc_x509_verify_state*)state);
            }
        }
        else
        {
            res = false;
        }
    }

    return res;
}

bool qsc_x509_qsc_signature_verify(const qsc_x509_certificate* certificate, const qsc_x509_certificate* issuer, void* state)
{
    QSC_ASSERT(certificate != NULL);
    QSC_ASSERT(issuer != NULL);
    QSC_ASSERT(state != NULL);

    bool res;

    res = false;

    if ((certificate != NULL) && (issuer != NULL) && (state != NULL))
    {
        res = x509_sigver_verify_preserved_region(certificate->tbsdata, certificate->tbsdatalen,
            certificate->signature, certificate->signaturelen, certificate->signatureunusedbits,
            &certificate->tbsignature, &certificate->signaturealgorithm,
            &issuer->subjectpublickeyinfo, (qsc_x509_verify_state*)state);
    }

    return res;
}

bool qsc_x509_qsc_crl_signature_verify(const qsc_x509_crl* crl, const qsc_x509_certificate* issuer, void* state)
{
    QSC_ASSERT(crl != NULL);
    QSC_ASSERT(issuer != NULL);
    QSC_ASSERT(state != NULL);

    bool res;

    res = false;

    if ((crl != NULL) && (issuer != NULL) && (state != NULL))
    {
        res = x509_sigver_verify_preserved_region(crl->tbsdata, crl->tbsdatalen,
            crl->signature, crl->signaturelen, crl->signatureunusedbits,
            &crl->tbsignature, &crl->signaturealgorithm,
            &issuer->subjectpublickeyinfo, (qsc_x509_verify_state*)state);
    }

    return res;
}

bool qsc_x509_qsc_csr_signature_verify(const qsc_x509_csr* csr, void* state)
{
    QSC_ASSERT(csr != NULL);
    QSC_ASSERT(state != NULL);

    bool res;

    res = false;

    if ((csr != NULL) && (state != NULL))
    {
        res = x509_sigver_verify_preserved_region(csr->infodata, csr->infodatalen,
            csr->signature, csr->signaturelen, csr->signatureunusedbits,
            NULL, &csr->signaturealgorithm,
            &csr->spki, (qsc_x509_verify_state*)state);
    }

    return res;
}
