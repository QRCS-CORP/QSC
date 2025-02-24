#include "encoding_test.h"
#include "testutils.h"
#include "../QSC/encoding.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool qsctest_encoding_base64(void)
{
    const char* ptext = "This is a test string of a fixed length";
    uint8_t* decoded;
    char* encoded;
    size_t decbuflen;
    size_t encbuflen;
    size_t txtlen;
    bool res;

    res = false;
    txtlen = strlen(ptext);
    encbuflen = qsc_encoding_base64_encoded_size(txtlen) + 1;
    encoded = (char*)malloc(encbuflen);

    if (encoded != NULL)
    {
        memset(encoded, 0, encbuflen);

        /* encode the plain text */
        qsc_encoding_base64_encode(encoded, encbuflen, (const uint8_t*)ptext, txtlen);

        /* allocate a buffer for decoding */
        decbuflen = qsc_encoding_base64_decoded_size(encoded, strlen(encoded));
        decoded = (uint8_t*)malloc(decbuflen + 1);

        if (decoded != NULL)
        {
            memset(decoded, 0, decbuflen + 1);

            /* Decode the Base64 string */
            if (qsc_encoding_base64_decode(decoded, decbuflen, encoded, strlen(encoded)) == true)
            {
                if (strcmp(ptext, (char*)decoded) == 0)
                {
                    res = true;
                }
            }

            free(encoded);
            free(decoded);
        }
    }

    return res;
}

bool qsctest_encoding_ber(void)
{
    qsc_encoding_ber_element element;
    bool res;

    res = false;
    memset(&element, 0, sizeof(element));
    element.tagclass = QSC_ENCODING_BER_CLASS_UNIVERSAL;
    element.constructed = false;
    element.tagnumber = BER_ASN1_INTEGER;  /* INTEGER */
    element.indefinite = false;

    /* sample INTEGER value: 0x3039 (12345) */
    uint8_t aint[] = { 0x30, 0x39 };
    element.length = sizeof(aint);
    element.value = (uint8_t*)malloc(sizeof(aint));

    if (element.value != NULL)
    {
        qsc_encoding_ber_element* decelem;
        uint8_t berbuf[256];
        size_t berenclen;
        size_t bercons;

        memcpy(element.value, aint, sizeof(aint));
        element.children = NULL;
        element.ccount = 0;
        memset(berbuf, 0, sizeof(berbuf));
        berenclen = qsc_encoding_ber_encode_element(&element, berbuf, sizeof(berbuf));

        if (berenclen != 0)
        {
            bercons = 0;
            decelem = qsc_encoding_ber_decode_element(berbuf, berenclen, &bercons);

            if (decelem != NULL)
            {
                if ((decelem->constructed == false) &&
                    (decelem->length == element.length) &&
                    (memcmp(decelem->value, element.value, element.length) == 0))
                {
                    res = true;
                }

                encoding_ber_free_element(decelem);
            }
        }

        free(element.value);
    }

    return res;
}

bool qsctest_encoding_der(void)
{
    qsc_encoding_ber_element element;
    bool res;

    res = false;
    memset(&element, 0, sizeof(element));
    element.tagclass = QSC_ENCODING_BER_CLASS_UNIVERSAL;
    element.constructed = false;
    element.tagnumber = BER_ASN1_INTEGER;  /* INTEGER */
    element.indefinite = false;            /* DER disallows indefinite length */
    
    /* Use a sample INTEGER value: 0x3039 (12345) */
    uint8_t iarr[] = { 0x30, 0x39 };
    element.length = sizeof(iarr);
    element.value = (uint8_t*)malloc(sizeof(iarr));

    if (element.value != NULL)
    {
        uint8_t derbuf[256];
        size_t derenclen;
        size_t dercons;

        memcpy(element.value, iarr, sizeof(iarr));
        element.children = NULL;
        element.ccount = 0;
        memset(derbuf, 0, sizeof(derbuf));

        derenclen = qsc_encoding_der_encode_element(&element, derbuf, sizeof(derbuf));

        if (derenclen != 0)
        {
            qsc_encoding_ber_element* decelem;

            dercons = 0;
            decelem = qsc_encoding_der_decode_element(derbuf, derenclen, &dercons);

            if (decelem != NULL)
            {
                if ((decelem->constructed == false) &&
                    (decelem->length == element.length) &&
                    (memcmp(decelem->value, element.value, element.length) == 0))
                {
                    res = true;
                }

                encoding_ber_free_element(decelem);
            }
        }

        free(element.value);
    }

    return res;
}

bool qsctest_encoding_hex(void)
{
    uint8_t data[] = { 0xDE, 0xAD, 0xBE, 0xEF };
    char hexenc[2 * sizeof(data) + 1];
    size_t datalen = sizeof(data);
    bool res;

    res = false;
    memset(hexenc, 0, sizeof(hexenc));

    if (qsc_encoding_hex_encode(data, datalen, hexenc, sizeof(hexenc)))
    {
        uint8_t hexdec[sizeof(data)];
        size_t hexdeclen;

        hexdeclen = 0;

        if (qsc_encoding_hex_decode(hexenc, strlen(hexenc), hexdec, sizeof(hexdec), &hexdeclen) == true)
        {
            if ((hexdeclen == datalen) && (memcmp(data, hexdec, datalen) == 0))
            {
                res = true;
            }
        }
    }

    return res;
}

bool qsctest_encoding_pem(void)
{
    bool res = false;
    uint8_t data[] = { 0x30, 0x82, 0x01, 0x0A, 0x02, 0x82, 0x01, 0x01 };
    size_t datalen = sizeof(data);
    char pemout[1024];
    uint8_t pemdec[1024];
    size_t pemdeclen = 0;

    /* Clear output buffers */
    memset(pemout, 0, sizeof(pemout));
    memset(pemdec, 0, sizeof(pemdec));

    /* Encode the binary data into PEM format */
    if (qsc_encoding_pem_encode("TEST LABEL", pemout, sizeof(pemout), data, datalen) == true)
    {
        /* Decode the PEM-formatted string back into binary data */
        if (qsc_encoding_pem_decode(pemout, pemdec, sizeof(pemdec), &pemdeclen) == true)
        {
            /* Check that the decoded length and data match the original */
            if ((pemdeclen == datalen) && (memcmp(data, pemdec, datalen) == 0))
            {
                res = true;
            }
        }
    }

    return res;
}

void qsctest_encoding_run(void)
{
	if (qsctest_encoding_base64() == true)
	{
		qsctest_print_safe("Success! Passed BASE64 Encoding and Decoding test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the BASE64 Encoding and Decoding test. \n");
	}

    if (qsctest_encoding_ber() == true)
	{
		qsctest_print_safe("Success! Passed BER Encoding and Decoding test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the BER Encoding and Decoding test. \n");
	}

    if (qsctest_encoding_der() == true)
	{
		qsctest_print_safe("Success! Passed DER Encoding and Decoding test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the DER Encoding and Decoding test. \n");
	}

    if (qsctest_encoding_hex() == true)
	{
		qsctest_print_safe("Success! Passed HEX Encoding and Decoding test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the HEX Encoding and Decoding test. \n");
	}

    if (qsctest_encoding_pem() == true)
	{
		qsctest_print_safe("Success! Passed PEM Encoding and Decoding test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the PEM Encoding and Decoding test. \n");
	}
}
