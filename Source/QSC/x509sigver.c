#include "x509sigver.h"
#include "x509cert.h"
#include "memutils.h"

static bool x509_qsc_verify_is_supported_algorithm(const qsc_x509_certificate* certificate, const qsc_x509_certificate* issuer)
{
	bool res;

	res = false;

	if (certificate != (const qsc_x509_certificate*)NULL &&
		issuer != (const qsc_x509_certificate*)NULL)
	{
		if (certificate->signaturealgorithm.signature == QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA256 &&
			issuer->subjectpublickeyinfo.algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_EC &&
			issuer->subjectpublickeyinfo.algorithm.curve == QSC_X509_NAMED_CURVE_PRIME256V1)
		{
			res = true;
		}
	}

	return res;
}

static bool x509_qsc_copy_ecdsa_signature_raw(uint8_t* rawsig, size_t rawsiglen, const qsc_x509_ecdsa_signature* esig)
{
	bool res;

	res = false;

	if (rawsig != NULL &&
		esig != NULL &&
		rawsiglen >= QSC_ECDSA_SIGNATURE_SIZE &&
		esig->length == 32U)
	{
		qsc_memutils_copy(rawsig, esig->r, 32U);
		qsc_memutils_copy(rawsig + 32U, esig->s, 32U);
		res = true;
	}

	return res;
}

void qsc_x509_qsc_verify_state_initialize(qsc_x509_verify_state* state, uint8_t* buffer, size_t buflen)
{
	QSC_ASSERT(state != NULL);
	QSC_ASSERT(buffer != NULL);

	if (state != (qsc_x509_verify_state*)NULL)
	{
		state->signaturemessage = buffer;
		state->signaturemessage_size = buflen;
	}
}

bool qsc_x509_qsc_signature_verify(const qsc_x509_certificate* certificate, const qsc_x509_certificate* issuer, void* state)
{
	QSC_ASSERT(certificate != NULL);
	QSC_ASSERT(issuer != NULL);
	QSC_ASSERT(state != NULL);

	qsc_x509_verify_state* vstate;
	qsc_x509_ecdsa_signature esig;
	qsc_encoding_ber_element outer;

	uint8_t pubkey[QSC_ECDSA_PUBLICKEY_SIZE];
	uint8_t x[32U];
	uint8_t y[32U];

	uint8_t* buffer;
	uint8_t* recovered;

	size_t buflen;
	size_t msglen;
	size_t signedlen;

	bool res;

	vstate = (qsc_x509_verify_state*)state;

	buffer = NULL;
	recovered = NULL;
	buflen = 0U;
	msglen = 0U;
	signedlen = 0U;
	res = false;

	qsc_memutils_clear((uint8_t*)&esig, sizeof(qsc_x509_ecdsa_signature));
	qsc_memutils_clear((uint8_t*)&outer, sizeof(qsc_encoding_ber_element));
	qsc_memutils_clear(pubkey, sizeof(pubkey));
	qsc_memutils_clear(x, sizeof(x));
	qsc_memutils_clear(y, sizeof(y));

	if (certificate != NULL &&
		issuer != NULL &&
		vstate != NULL)
	{
		buffer = vstate->signaturemessage;
		buflen = vstate->signaturemessage_size;

		if (buffer != NULL &&
			certificate->tbsdata != NULL &&
			certificate->tbsdatalen != 0U &&
			x509_qsc_verify_is_supported_algorithm(certificate, issuer) == true &&
			buflen >= (QSC_ECDSA_SIGNATURE_SIZE + certificate->tbsdatalen) &&
			certificate->signaturelen != 0U &&
			certificate->signatureunusedbits == 0U)
		{
			uint8_t bitstring[1U + sizeof(certificate->signature)];

			qsc_memutils_clear(bitstring, sizeof(bitstring));

			if ((certificate->signaturelen + 1U) <= sizeof(bitstring))
			{
				outer.tagclass = 0x00U;
				outer.constructed = false;
				outer.tagnumber = 3U;
				outer.length = certificate->signaturelen + 1U;
				outer.value = bitstring;

				bitstring[0U] = certificate->signatureunusedbits;
				qsc_memutils_copy(bitstring + 1U, certificate->signature, certificate->signaturelen);

				if (qsc_x509_signature_value_decode_ecdsa(&outer,
					QSC_X509_NAMED_CURVE_PRIME256V1,
					&esig) == QSC_ASN1_STATUS_SUCCESS &&
					qsc_x509_spki_get_ec_coordinates(&issuer->subjectpublickeyinfo,
						x,
						sizeof(x),
						y,
						sizeof(y)) == QSC_ASN1_STATUS_SUCCESS &&
					x509_qsc_copy_ecdsa_signature_raw(buffer, buflen, &esig) == true)
				{
					qsc_memutils_copy(pubkey, x, sizeof(x));
					qsc_memutils_copy(pubkey + sizeof(x), y, sizeof(y));

					qsc_memutils_copy(buffer + QSC_ECDSA_SIGNATURE_SIZE,
						certificate->tbsdata,
						certificate->tbsdatalen);

					signedlen = QSC_ECDSA_SIGNATURE_SIZE + certificate->tbsdatalen;

					recovered = qsc_memutils_malloc(certificate->tbsdatalen);

					if (recovered != NULL)
					{
						qsc_memutils_clear(recovered, certificate->tbsdatalen);

						res = qsc_ecdsa_verify(recovered,
							&msglen,
							buffer,
							signedlen,
							pubkey);

						if (res == true)
						{
							if (msglen != certificate->tbsdatalen)
							{
								res = false;
							}
							else
							{
								res = qsc_memutils_are_equal(
									recovered,
									certificate->tbsdata,
									certificate->tbsdatalen);
							}
						}

						qsc_memutils_secure_erase(recovered, certificate->tbsdatalen);
						qsc_memutils_alloc_free(recovered);
					}
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
