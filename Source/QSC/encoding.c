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

#include "encoding.h"
#include "memutils.h"
#include "stringutils.h"
#include <stdio.h>

 /* ========================================================================== */
 /*                        File-Scope Static Constants                         */
 /* ========================================================================== */

 /*!
  * \brief Base64 decode table indexed from ASCII '+' (0x2B, decimal 43).
  *
  * Maps each printable character in the range ['+', 'z'] to its 6-bit Base64
  * value, per RFC 4648, Table 1.  Entries of -1 denote characters that are not
  * members of the Base64 alphabet.  The '=' padding character maps to -1 and is
  * handled explicitly by the caller rather than through this table.
  */
static const int32_t QSC_BASE64_DECODE_TABLE[80U] =
{
    62, -1, -1, -1, 63, /* + , - . / */
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, /* 0-9 */
    -1, -1, -1, -1, -1, -1, -1, /* : ; < = > ? @ */
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, /* A-Z */
    -1, -1, -1, -1, -1, -1, /* [ \ ] ^ _ ` */
    26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
    42, 43, 44, 45, 46, 47, 48, 49, 50, 51 /* a-z */
};

/*!
 * \brief Base64 encode table: the 64-character alphabet from RFC 4648, Table 1.
 */
static const char QSC_BASE64_ENCODE_TABLE[65U] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/* Maximum nesting depth for DER/BER element decoding. Prevents stack overflow
 * from pathologically crafted deeply-nested structures. RFC 5280 certificates
 * have a maximum practical depth of about 12 levels. */
#define QSC_ENCODING_BER_MAX_DECODE_DEPTH 32U


static qsc_encoding_ber_element* encoding_ber_alloc_element(void)
{
    qsc_encoding_ber_element* elem;

    elem = (qsc_encoding_ber_element*)qsc_memutils_malloc(sizeof(qsc_encoding_ber_element));

    if (elem != NULL)
    {
        qsc_memutils_clear(elem, sizeof(qsc_encoding_ber_element));
    }

    return elem;
}

static bool encoding_ber_grow_children(qsc_encoding_ber_element* elem, size_t* pcap)
{
    qsc_encoding_ber_element** tmp;
    size_t newcap;
    bool res;

    res = false;
    newcap = (*pcap == 0U) ? 4U : (*pcap * 2U);

    if (elem->children == NULL)
    {
        tmp = (qsc_encoding_ber_element**)qsc_memutils_malloc(newcap * sizeof(qsc_encoding_ber_element*));
    }
    else
    {
        tmp = (qsc_encoding_ber_element**)qsc_memutils_realloc(elem->children, newcap * sizeof(qsc_encoding_ber_element*));
    }

    if (tmp != NULL)
    {
        if (newcap > *pcap)
        {
            qsc_memutils_clear(((uint8_t*)tmp) + (*pcap * sizeof(qsc_encoding_ber_element*)),
                (newcap - *pcap) * sizeof(qsc_encoding_ber_element*));
        }

        elem->children = tmp;
        *pcap = newcap;
        res = true;
    }

    return res;
}

static uint8_t* encoding_alloc_bytes(size_t len)
{
    uint8_t* buf;

    buf = NULL;

    if (len > 0U)
    {
        buf = (uint8_t*)qsc_memutils_malloc(len);
    }

    return buf;
}

static char* encoding_alloc_chars(size_t len)
{
    char* buf;

    buf = NULL;

    if (len > 0U)
    {
        buf = (char*)qsc_memutils_malloc(len);

        if (buf != NULL)
        {
            qsc_memutils_clear(buf, len);
        }
    }

    return buf;
}

static bool encoding_header_labels_check(const char* input, const char* header, const char* footer, const char* separator)
{
    char lbla[128U] = { 0U };
    char lblb[128U] = { 0U };
    int64_t posa;
    int64_t posb;
    size_t sepl;
    bool res;

    res = false;
    sepl = qsc_stringutils_string_size(header);

    if (input != NULL && header != NULL && footer != NULL && separator != NULL && sepl > 0U)
    {
        if (qsc_stringutils_string_contains(input, header) == true && qsc_stringutils_string_contains(input, footer) == true)
        {
            posa = (int64_t)sepl;
            posb = qsc_stringutils_find_string(input + posa, separator);

            if (posb > 0)
            {
                qsc_stringutils_copy_substring(lbla, sizeof(lbla), input + posa, posb);

                posa = qsc_stringutils_find_string(input, footer);

                if (posa > 0)
                {
                    posa += (int64_t)qsc_stringutils_string_size(footer);
                    posb = qsc_stringutils_find_string(input + posa, separator);

                    if (posb > 0)
                    {
                        qsc_stringutils_copy_substring(lblb, sizeof(lblb), input + posa, posb);
                        res = qsc_memutils_are_equal((uint8_t*)lbla, (uint8_t*)lblb, (size_t)posb);
                    }
                }
            }
        }
    }

    return res;
}

static bool encoding_base64_length_valid(const char* input, const char* separator)
{
    int64_t posa;
    int64_t posb;
    size_t pctr;
    size_t sepl;
    bool res;

    res = false;
    pctr = 0U;
    sepl = qsc_stringutils_string_size(separator);

    if (input != NULL && separator != NULL && sepl > 0U)
    {
        posa = qsc_stringutils_find_string(input, separator);

        if (posa >= 0)
        {
            posa += (int64_t)sepl;
            posb = qsc_stringutils_find_string(input + posa, separator);

            if (posb >= 0)
            {
                posa += (int64_t)sepl + posb;
                posb = qsc_stringutils_find_string(input + posa, separator);

                if (posb >= 0)
                {
                    posb += posa;

                    for (int64_t i = posa; i < posb; ++i)
                    {
                        char c;

                        c = input[i];

                        if ((c >= 'A' && c <= 'Z') ||
                            (c >= 'a' && c <= 'z') ||
                            (c >= '0' && c <= '9') ||
                            c == '+' || c == '/' || c == '=')
                        {
                            ++pctr;
                        }
                    }

                    res = (pctr % 4U == 0U);
                }
            }
        }
    }

    return res;
}

static size_t encoding_der_element_size(const qsc_encoding_ber_element* element)
{
    uint8_t dummy[10U];
    size_t content;
    size_t lfield;
    size_t taglen;
    size_t total;
    size_t i;
    bool ok;

    total = 0U;

    if (element != NULL && element->indefinite == false)
    {
        taglen = qsc_encoding_ber_encode_tag(element->tagclass, element->constructed, element->tagnumber, dummy, sizeof(dummy));

        if (taglen > 0U)
        {
            if (element->constructed == true)
            {
                content = 0U;
                ok = true;
                i = 0U;

                while ((i < element->ccount) && (ok == true))
                {
                    size_t cs;

                    cs = encoding_der_element_size(element->children[i]);

                    if (cs == 0U && element->children[i] != NULL)
                    {
                        ok = false;
                    }
                    else
                    {
                        content += cs;
                    }

                    ++i;
                }

                if (ok == true)
                {
                    lfield = qsc_encoding_ber_encode_length(content, dummy, sizeof(dummy));

                    if (lfield > 0U)
                    {
                        total = taglen + lfield + content;
                    }
                }
            }
            else
            {
                lfield = qsc_encoding_ber_encode_length(element->length, dummy, sizeof(dummy));

                if (lfield > 0U)
                {
                    total = taglen + lfield + element->length;
                }
            }
        }
    }

    return total;
}

bool qsc_encoding_base64_is_valid_char(char value)
{
    bool res;

    if ((value >= 'A' && value <= 'Z') ||
        (value >= 'a' && value <= 'z') ||
        (value >= '0' && value <= '9') ||
        value == '+' || value == '/' || value == '=')
    {
        res = true;
    }
    else
    {
        res = false;
    }

    return res;
}

size_t qsc_encoding_base64_encoded_size(size_t length)
{
    QSC_ASSERT(length != 0U);

    size_t ret;

    ret = 0U;

    if (length != 0U)
    {
        ret = length;

        if (ret % 3U != 0U)
        {
            ret += 3U - (ret % 3U);
        }

        ret = (ret / 3U) * 4U;
    }

    return ret;
}

size_t qsc_encoding_base64_decoded_size(const char* input, size_t length)
{
    QSC_ASSERT(input != NULL);
    QSC_ASSERT(length != 0U);

    size_t res;

    res = 0U;

    if (input != NULL && length != 0U && (length % 4U == 0U))
    {
        res = (length / 4U) * 3U;

        /* walk backward from the end to count padding characters. */
        for (size_t i = length - 1U; i > 0U; --i)
        {
            if (input[i] == '=')
            {
                --res;

                if (input[i - 1U] == '=')
                {
                    --res;
                }

                break;
            }
        }
    }

    return res;
}

bool qsc_encoding_base64_encode(char* output, size_t otplen, const uint8_t* input, size_t inplen)
{
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(otplen != 0U);
    QSC_ASSERT(input != NULL);
    QSC_ASSERT(inplen != 0U);

    size_t enclen;
    size_t i;
    size_t j;
    size_t v;
    bool res;

    res = false;

    if (output != NULL && input != NULL && inplen != 0U && otplen != 0U)
    {
        enclen = qsc_encoding_base64_encoded_size(inplen);

        if (enclen > 0U && (enclen + 1U) <= otplen)
        {
            for (i = 0U, j = 0U; i < inplen; i += 3U, j += 4U)
            {
                v = (size_t)input[i];
                v = (i + 1U < inplen) ? ((v << 8U) | (size_t)input[i + 1U]) : (v << 8U);
                v = (i + 2U < inplen) ? ((v << 8U) | (size_t)input[i + 2U]) : (v << 8U);

                output[j] = QSC_BASE64_ENCODE_TABLE[(v >> 18U) & 0x3FU];
                output[j + 1U] = QSC_BASE64_ENCODE_TABLE[(v >> 12U) & 0x3FU];
                output[j + 2U] = (i + 1U < inplen) ? QSC_BASE64_ENCODE_TABLE[(v >> 6U) & 0x3FU] : '=';
                output[j + 3U] = (i + 2U < inplen) ? QSC_BASE64_ENCODE_TABLE[v & 0x3FU] : '=';
            }

            output[enclen] = '\0';
            res = true;
        }
    }

    return res;
}

bool qsc_encoding_base64_decode(uint8_t* output, size_t otplen, const char* input, size_t inplen)
{
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(input != NULL);
    QSC_ASSERT(inplen != 0U);

    size_t i;
    size_t j;
    int32_t v;
    bool res;

    res = false;

    if (output != NULL && input != NULL && inplen != 0U)
    {
        /* RFC 4648: encoded length must be a non-zero multiple of four. */
        if ((inplen % 4U == 0U) && (otplen >= qsc_encoding_base64_decoded_size(input, inplen)))
        {
            res = true;

            /* pass 1: validate every character is a legal Base64 symbol. */
            for (i = 0U; (i < inplen) && (res == true); ++i)
            {
                if (qsc_encoding_base64_is_valid_char(input[i]) == false)
                {
                    res = false;
                }
            }

            /* pass 2: validate padding placement per RFC 4648 section 3.5.
             * '=' may appear only at positions 2 and/or 3 of the final group.
             * all groups except the last must be free of '='.              */
            if (res == true && inplen >= 4U)
            {
                for (i = 0U; (i < inplen - 4U) && (res == true); ++i)
                {
                    if (input[i] == '=')
                    {
                        res = false;
                    }
                }

                if (res == true)
                {
                    size_t last;

                    last = inplen - 4U;

                    /* positions 0 and 1 of the last group must not be '='. */
                    if (input[last] == '=' || input[last + 1U] == '=')
                    {
                        res = false;
                    }

                    /* if position 2 is '=', position 3 must also be '='. */
                    if (res == true && input[last + 2U] == '=' && input[last + 3U] != '=')
                    {
                        res = false;
                    }
                }
            }

            /* pass 3: decode. */
            if (res == true)
            {
                for (i = 0U, j = 0U; (i < inplen) && (res == true); i += 4U, j += 3U)
                {
                    char c0;
                    int32_t idx0;
                    int32_t idx1;

                    c0 = input[i];

                    /* guard against characters outside the lookup-table range. */
                    if (c0 < '+' || c0 > 'z')
                    {
                        res = false;
                    }
                    else
                    {
                        idx0 = (int32_t)((uint8_t)c0 - 43U);
                        idx1 = (int32_t)((uint8_t)input[i + 1U] - 43U);

                        v = QSC_BASE64_DECODE_TABLE[idx0];
                        v = ((int32_t)((uint32_t)v << 6U)) | QSC_BASE64_DECODE_TABLE[idx1];

                        v = (input[i + 2U] == '=')
                            ? (int32_t)((uint32_t)v << 6U)
                            : (int32_t)((uint32_t)v << 6U) |
                            QSC_BASE64_DECODE_TABLE[(uint8_t)input[i + 2U] - 43U];

                        v = (input[i + 3U] == '=')
                            ? (int32_t)((uint32_t)v << 6U)
                            : (int32_t)((uint32_t)v << 6U) |
                            QSC_BASE64_DECODE_TABLE[(uint8_t)input[i + 3U] - 43U];

                        output[j] = (uint8_t)((v >> 16) & 0xFF);

                        if (input[i + 2U] != '=')
                        {
                            output[j + 1U] = (uint8_t)((v >> 8) & 0xFF);
                        }

                        if (input[i + 3U] != '=')
                        {
                            output[j + 2U] = (uint8_t)(v & 0xFF);
                        }
                    }
                }
            }
        }
    }

    return res;
}

size_t qsc_encoding_ber_encode_tag(uint8_t tagclass, bool construct, uint32_t tagnum, uint8_t* buffer, size_t buflen)
{
    QSC_ASSERT(buffer != NULL);
    QSC_ASSERT(buflen != 0U);

    size_t pos;
    uint8_t first;

    pos = 0U;

    if (buffer != NULL && buflen > 0U)
    {
        /* Compose the first byte: class | P/C | tag-number field. */
        first = tagclass;

        if (construct == true)
        {
            first |= 0x20U;
        }

        if (tagnum < 31U)
        {
            /* Short form: tag number fits in the low five bits. */
            first |= (uint8_t)(tagnum & 0x1FU);
            buffer[pos] = first;
            pos = 1U;
        }
        else
        {
            /* Long form: low five bits of first byte set to 11111. */
            uint8_t temp[5U] = { 0U };
            size_t tmplen;
            uint32_t tnum;
            bool overflow;

            first |= 0x1FU;
            buffer[pos] = first;
            pos = 1U;

            /* Encode tag number in base-128, little-endian into temp. */
            tmplen = 0U;
            tnum = tagnum;

            do
            {
                temp[tmplen] = (uint8_t)(tnum & 0x7FU);
                ++tmplen;
                tnum >>= 7U;
            } while (tnum > 0U);

            /* Emit bytes in big-endian order with continuation bits. */
            overflow = false;

            for (int32_t k = (int32_t)tmplen - 1; (k >= 0) && (overflow == false); --k)
            {
                if (pos >= buflen)
                {
                    pos = 0U;
                    overflow = true;
                }
                else
                {
                    uint8_t b;

                    b = temp[k];

                    if (k != 0)
                    {
                        b |= 0x80U;
                    }

                    buffer[pos] = b;
                    ++pos;
                }
            }
        }
    }

    return pos;
}

size_t qsc_encoding_ber_encode_length(size_t length, uint8_t* buffer, size_t buflen)
{
    QSC_ASSERT(buffer != NULL);
    QSC_ASSERT(buflen != 0U);

    size_t res;

    res = 0U;

    if (buffer != NULL && buflen >= 1U)
    {
        if (length == QSC_BER_ENCODING_INDEFINITE_LENGTH)
        {
            /* indefinite-length form: single byte 0x80 (X.690 8.1.3.6). */
            buffer[0U] = 0x80U;
            res = 1U;
        }
        else if (length < 128U)
        {
            /* short definite-length form (X.690 8.1.3.4). */
            buffer[0U] = (uint8_t)length;
            res = 1U;
        }
        else
        {
            /* long definite-length form (X.690 8.1.3.5).
             * determine the minimum number of octets required and emit them in big-endian order. */
            uint8_t alen[8U] = { 0U };
            size_t bnum;
            size_t tlen;

            bnum = 0U;
            tlen = length;

            while (tlen > 0U)
            {
                alen[bnum] = (uint8_t)(tlen & 0xFFU);
                ++bnum;
                tlen >>= 8U;
            }

            if (buflen >= 1U + bnum)
            {
                buffer[0U] = 0x80U | (uint8_t)bnum;

                for (size_t k = 0U; k < bnum; ++k)
                {
                    buffer[1U + k] = alen[bnum - 1U - k];
                }

                res = 1U + bnum;
            }
        }
    }

    return res;
}

size_t qsc_encoding_ber_decode_tag(const uint8_t* buffer, size_t buflen, uint8_t* tagclass, bool* construct, uint32_t* tagnum)
{
    QSC_ASSERT(buffer != NULL);
    QSC_ASSERT(buflen != 0U);
    QSC_ASSERT(tagclass != NULL);
    QSC_ASSERT(construct != NULL);
    QSC_ASSERT(tagnum != NULL);

    size_t pos;

    pos = 0U;

    if (buffer != NULL && buflen > 0U &&
        tagclass != NULL && construct != NULL && tagnum != NULL)
    {
        uint8_t first;
        uint8_t tagval;

        first = buffer[0U];
        *tagclass = first & 0xC0U;
        *construct = ((first & 0x20U) != 0U);
        tagval = first & 0x1FU;
        pos = 1U;

        if (tagval != 0x1FU)
        {
            /* short form: tag number is in the low five bits. */
            *tagnum = (uint32_t)tagval;
        }
        else
        {
            /* long form (X.690 8.1.2.4): tag number encoded in subsequent base-128 bytes, 
             * MSB of each byte is the continuation flag, 0 on the final byte. */
            uint32_t num;
            bool found_end;

            num = 0U;
            found_end = false;

            while (pos < buflen)
            {
                uint8_t b;

                b = buffer[pos];
                ++pos;
                num = (num << 7U) | (uint32_t)(b & 0x7FU);

                if ((b & 0x80U) == 0U)
                {
                    found_end = true;
                    break;
                }
            }

            if (found_end == true)
            {
                *tagnum = num;
            }
            else
            {
                /* buffer exhausted before the terminal byte. */
                pos = 0U;
            }
        }
    }

    return pos;
}

size_t qsc_encoding_ber_decode_length(const uint8_t* buffer, size_t buflen, size_t* length, bool* indef)
{
    QSC_ASSERT(buffer != NULL);
    QSC_ASSERT(buflen != 0U);
    QSC_ASSERT(length != NULL);
    QSC_ASSERT(indef != NULL);

    size_t res;

    res = 0U;

    if (buffer != NULL && buflen >= 1U && length != NULL && indef != NULL)
    {
        uint8_t first;

        first = buffer[0U];

        if (first == 0x80U)
        {
            /* indefinite-length form (X.690 8.1.3.6).
             * content length is unknown; caller locates the EOC. */
            *indef = true;
            *length = 0U;
            res = 1U;
        }
        else if ((first & 0x80U) == 0U)
        {
            /* short definite-length form (X.690 8.1.3.4). */
            *indef = false;
            *length = (size_t)first;
            res = 1U;
        }
        else
        {
            /* long definite-length form (X.690 8.1.3.5).
             * low seven bits of first byte give the count of subsequent length octets. */
            uint8_t bnum;

            *indef = false;
            bnum = first & 0x7FU;

            /* per X.690 8.1.3.5c, the value 0xFF is reserved.
             * reject bnum == 0 (that is the 0x80 indefinite form already handled above, but guard it here for robustness).
             * Reject counts that would overflow a native size_t. */
            if ((bnum == 0U) || (bnum > (uint8_t)sizeof(size_t)) || (buflen < (size_t)(1U + bnum)))
            {
                res = 0U;
            }
            else
            {
                size_t len;
                size_t k;

                len = 0U;

                for (k = 0U; k < (size_t)bnum; ++k)
                {
                    len = (len << 8U) | (size_t)buffer[1U + k];
                }

                *length = len;
                res = 1U + (size_t)bnum;
            }
        }
    }

    return res;
}

void qsc_encoding_ber_free_element(qsc_encoding_ber_element* element)
{
    QSC_ASSERT(element != NULL);

    if (element != NULL)
    {
        if (element->constructed == true)
        {
            if (element->children != NULL)
            {
                for (size_t i = 0U; i < element->ccount; ++i)
                {
                    if (element->children[i] != NULL)
                    {
                        qsc_encoding_ber_free_element(element->children[i]);
                        element->children[i] = NULL;
                    }
                }

                qsc_memutils_alloc_free(element->children);
                element->children = NULL;
            }
        }
        else
        {
            if (element->value != NULL)
            {
                qsc_memutils_alloc_free(element->value);
                element->value = NULL;
            }
        }

        qsc_memutils_alloc_free(element);
    }
}

static qsc_encoding_ber_element* encoding_ber_decode_element_depth(
    const uint8_t* buffer, size_t buflen, size_t* consumed, uint32_t depth)
{
    if (depth > QSC_ENCODING_BER_MAX_DECODE_DEPTH)
    {
        if (consumed != NULL) { *consumed = 0U; }
        return NULL;
    }

    QSC_ASSERT(buffer != NULL);
    QSC_ASSERT(buflen != 0U);
    QSC_ASSERT(consumed != NULL);

    qsc_encoding_ber_element* child;
    qsc_encoding_ber_element* elem;
    qsc_encoding_ber_element* relem;
    size_t achildren;
    size_t chconsumed;
    size_t llen;
    size_t length;
    size_t pos;
    size_t start;
    size_t taglen;
    uint8_t tagclass;
    uint32_t tagnumber;
    bool constructed;
    bool indefinite;
    bool loop_ok;

    relem = NULL;
    pos = 0U;

    if (buffer != NULL && buflen >= 2U && consumed != NULL)
    {
        elem = NULL;
        child = NULL;
        length = 0U;
        tagclass = 0U;
        tagnumber = 0U;
        constructed = false;
        indefinite = false;

        taglen = qsc_encoding_ber_decode_tag(buffer, buflen, &tagclass, &constructed, &tagnumber);

        if (taglen > 0U)
        {
            pos = taglen;
            llen = qsc_encoding_ber_decode_length(buffer + pos, buflen - pos, &length, &indefinite);

            if (llen > 0U)
            {
                pos += llen;
                elem = encoding_ber_alloc_element();

                if (elem != NULL)
                {
                    elem->tagclass = tagclass;
                    elem->constructed = constructed;
                    elem->tagnumber = tagnumber;
                    elem->indefinite = indefinite;

                    if (constructed == true)
                    {
                        achildren = 0U;
                        start = pos;
                        loop_ok = true;

                        if (indefinite == true)
                        {
                            /* indefinite-length constructed: accumulate children
                             * until the End-of-Contents (EOC) marker 0x00 0x00. */
                            bool found_eoc;

                            found_eoc = false;

                            while (loop_ok == true && (pos + 2U) <= buflen)
                            {
                                if (buffer[pos] == 0x00U && buffer[pos + 1U] == 0x00U)
                                {
                                    pos += 2U;
                                    found_eoc = true;
                                    break;
                                }

                                chconsumed = 0U;
                                child = encoding_ber_decode_element_depth(buffer + pos, buflen - pos, &chconsumed, depth + 1U);

                                if (child == NULL || chconsumed == 0U)
                                {
                                    loop_ok = false;
                                }
                                else
                                {
                                    pos += chconsumed;

                                    if (elem->ccount >= achildren)
                                    {
                                        if (encoding_ber_grow_children(elem, &achildren) == false)
                                        {
                                            qsc_encoding_ber_free_element(child);
                                            child = NULL;
                                            loop_ok = false;
                                        }
                                    }

                                    if (loop_ok == true)
                                    {
                                        elem->children[elem->ccount] = child;
                                        elem->ccount += 1U;
                                        child = NULL;
                                    }
                                }
                            }

                            if (loop_ok == true && found_eoc == true)
                            {
                                elem->length = pos - start;
                                elem->value = NULL;
                                relem = elem;
                                elem = NULL;
                            }
                            else
                            {
                                qsc_encoding_ber_free_element(elem);
                                elem = NULL;
                            }
                        }
                        else
                        {
                            /* definite-length constructed: consume exactly [pos, pos+length) bytes as child elements.   */
                            size_t end;

                            end = pos + length;

                            if (end <= buflen)
                            {
                                while (loop_ok == true && pos < end)
                                {
                                    chconsumed = 0U;
                                    child = encoding_ber_decode_element_depth(buffer + pos, end - pos, &chconsumed, depth + 1U);

                                    if (child == NULL || chconsumed == 0U)
                                    {
                                        loop_ok = false;
                                    }
                                    else
                                    {
                                        pos += chconsumed;

                                        if (elem->ccount >= achildren)
                                        {
                                            if (encoding_ber_grow_children(elem, &achildren) == false)
                                            {
                                                qsc_encoding_ber_free_element(child);
                                                child = NULL;
                                                loop_ok = false;
                                            }
                                        }

                                        if (loop_ok == true)
                                        {
                                            elem->children[elem->ccount] = child;
                                            elem->ccount += 1U;
                                            child = NULL;
                                        }
                                    }
                                }

                                if (loop_ok == true && pos == end)
                                {
                                    elem->length = length;
                                    elem->value = NULL;
                                    relem = elem;
                                    elem = NULL;
                                }
                                else
                                {
                                    qsc_encoding_ber_free_element(elem);
                                    elem = NULL;
                                }
                            }
                            else
                            {
                                /* content extends beyond the supplied buffer. */
                                qsc_encoding_ber_free_element(elem);
                                elem = NULL;
                            }
                        }
                    }
                    else
                    {
                        /* primitive element.
                         * indefinite length is illegal for primitive types per X.690 8.1.3.2. */
                        if (indefinite == true)
                        {
                            qsc_encoding_ber_free_element(elem);
                            elem = NULL;
                        }
                        else if ((pos + length) > buflen)
                        {
                            qsc_encoding_ber_free_element(elem);
                            elem = NULL;
                        }
                        else
                        {
                            elem->length = length;

                            if (length == 0U)
                            {
                                /* zero-length primitive is valid (e.g. NULL, empty OCTET STRING). */
                                elem->value = NULL;
                                relem = elem;
                                elem = NULL;
                            }
                            else
                            {
                                elem->value = encoding_alloc_bytes(length);

                                if (elem->value != NULL)
                                {
                                    qsc_memutils_copy(elem->value, buffer + pos, length);
                                    pos += length;
                                    relem = elem;
                                    elem = NULL;
                                }
                                else
                                {
                                    qsc_encoding_ber_free_element(elem);
                                    elem = NULL;
                                }
                            }
                        }
                    }
                }
            }
        }

        *consumed = (relem != NULL) ? pos : 0U;
    }
    else if (consumed != NULL)
    {
        *consumed = 0U;
    }

    return relem;
}

size_t qsc_encoding_ber_encode_element(qsc_encoding_ber_element* element, uint8_t* buffer, size_t buflen)
{
    QSC_ASSERT(element != NULL);
    QSC_ASSERT(buffer != NULL);
    QSC_ASSERT(buflen != 0U);

    uint8_t alen[10U] = { 0U };
    uint8_t tagbuf[10U] = { 0U };
    size_t llen;
    size_t ret;
    size_t taglen;
    size_t total;

    ret = 0U;
    total = 0U;

    if (element != NULL && buffer != NULL && buflen != 0U)
    {
        taglen = qsc_encoding_ber_encode_tag(element->tagclass, element->constructed, element->tagnumber, tagbuf, sizeof(tagbuf));

        if (taglen > 0U && taglen <= buflen)
        {
            qsc_memutils_copy(buffer, tagbuf, taglen);
            total += taglen;

            /* encode the length field. */
            if (element->constructed == true && element->indefinite == true)
            {
                if ((buflen - total) >= 1U)
                {
                    alen[0U] = 0x80U;
                    llen = 1U;
                }
                else
                {
                    llen = 0U;
                }
            }
            else
            {
                llen = qsc_encoding_ber_encode_length(element->length, alen, sizeof(alen));
            }

            if (llen > 0U && (total + llen) <= buflen)
            {
                qsc_memutils_copy(buffer + total, alen, llen);
                total += llen;

                if (element->constructed == true)
                {
                    if (element->indefinite == true)
                    {
                        /* encode children followed by the EOC marker. */
                        bool child_ok;
                        size_t k;

                        child_ok = true;
                        k = 0U;

                        while ((k < element->ccount) && (child_ok == true))
                        {
                            size_t clen;

                            clen = qsc_encoding_ber_encode_element(element->children[k], buffer + total, buflen - total);

                            if (clen == 0U)
                            {
                                child_ok = false;
                                total = 0U;
                            }
                            else
                            {
                                total += clen;
                            }

                            ++k;
                        }

                        if (child_ok == true && (buflen - total) >= 2U)
                        {
                            buffer[total] = 0x00U;
                            ++total;
                            buffer[total] = 0x00U;
                            ++total;
                            ret = total;
                        }
                    }
                    else
                    {
                        /* definite constructed: copy the pre-encoded content block. */
                        if ((total + element->length) <= buflen)
                        {
                            qsc_memutils_copy(buffer + total, element->value, element->length);
                            total += element->length;
                            ret = total;
                        }
                    }
                }
                else
                {
                    /* primitive: copy the raw value bytes. */
                    if ((total + element->length) <= buflen)
                    {
                        qsc_memutils_copy(buffer + total, element->value, element->length);
                        total += element->length;
                        ret = total;
                    }
                }
            }
        }
    }

    return ret;
}

qsc_encoding_ber_element* qsc_encoding_ber_decode_element(
    const uint8_t* buffer, size_t buflen, size_t* consumed)
{
    QSC_ASSERT(buffer != NULL);
    QSC_ASSERT(buflen != 0U);
    QSC_ASSERT(consumed != NULL);

    /* Defensive null check - returns cleanly even without NDEBUG. */
    if (buffer == NULL || buflen == 0U || consumed == NULL)
    {
        if (consumed != NULL) { *consumed = 0U; }
        return NULL;
    }

    return encoding_ber_decode_element_depth(buffer, buflen, consumed, 0U);
}


static size_t encoding_der_tag_field_length(const uint8_t* buffer, size_t buflen)
{
    size_t len;

    len = 0U;

    if (buffer != NULL && buflen != 0U)
    {
        len = 1U;

        if ((buffer[0U] & 0x1FU) == 0x1FU)
        {
            while (len < buflen)
            {
                uint8_t octet;

                octet = buffer[len];
                ++len;

                if ((octet & 0x80U) == 0U)
                {
                    break;
                }
            }
        }
    }

    return len;
}

static bool encoding_der_has_minimal_length_encoding(const uint8_t* buffer, size_t buflen, size_t contentlen, size_t totalconsumed)
{
    uint8_t enc[sizeof(size_t) + 1U];
    size_t actlen;
    size_t enclen;
    size_t taglen;
    bool res;

    qsc_memutils_clear(enc, sizeof(enc));
    res = false;
    taglen = encoding_der_tag_field_length(buffer, buflen);

    if (taglen != 0U && totalconsumed >= taglen && buflen >= totalconsumed)
    {
        actlen = totalconsumed - taglen - contentlen;
        enclen = qsc_encoding_ber_encode_length(contentlen, enc, sizeof(enc));

        if (enclen != 0U && actlen == enclen)
        {
            res = true;
        }
    }

    return res;
}
qsc_encoding_ber_element* qsc_encoding_der_decode_element(const uint8_t* buffer, size_t buflen, size_t* consumed)
{
    QSC_ASSERT(buffer != NULL);
    QSC_ASSERT(buflen != 0U);
    QSC_ASSERT(consumed != NULL);

    qsc_encoding_ber_element* elem;

    elem = NULL;

    if (buffer != NULL && buflen != 0U && consumed != NULL)
    {
        elem = qsc_encoding_ber_decode_element(buffer, buflen, consumed);

        if (elem != NULL)
        {
            /* DER (X.690 11.1) forbids indefinite-length encoding. */
            if (elem->indefinite == true)
            {
                qsc_encoding_ber_free_element(elem);
                elem = NULL;
                *consumed = 0U;
            }
            else if (encoding_der_has_minimal_length_encoding(buffer, buflen, elem->length, *consumed) == false)
            {
                qsc_encoding_ber_free_element(elem);
                elem = NULL;
                *consumed = 0U;
            }
        }
    }

    return elem;
}

size_t qsc_encoding_der_encode_element(qsc_encoding_ber_element* element, uint8_t* buffer, size_t buflen)
{
    QSC_ASSERT(element != NULL);

    size_t total;

    total = 0U;

    if (element != NULL)
    {
        /* Sizing pass: callers may request the exact DER length with (NULL, 0). */
        if (buffer == NULL)
        {
            if (buflen == 0U)
            {
                total = encoding_der_element_size(element);
            }

            return total;
        }

        if (buflen == 0U)
        {
            return 0U;
        }

        /* DER (X.690 11.1) forbids indefinite-length encoding. */
        if (element->indefinite == false)
        {
            size_t taglen;

            taglen = qsc_encoding_ber_encode_tag(element->tagclass, element->constructed, element->tagnumber, buffer, buflen);

            if (taglen > 0U && taglen <= buflen)
            {
                total += taglen;

                if (element->constructed == true)
                {
                    /* compute total content size from the child tree.
                     * this avoids a fixed-size temporary buffer and correctly handles 
                     * arbitrarily large structures (e.g. post-quantum X.509 certificates). */
                    size_t content;
                    bool ok;
                    size_t k;

                    content = 0U;
                    ok = true;
                    k = 0U;

                    while ((k < element->ccount) && (ok == true))
                    {
                        size_t cs;

                        cs = encoding_der_element_size(element->children[k]);

                        if (cs == 0U && element->children[k] != NULL)
                        {
                            ok = false;
                            total = 0U;
                        }
                        else
                        {
                            content += cs;
                        }

                        ++k;
                    }

                    if (ok == true)
                    {
                        size_t lfield;

                        lfield = qsc_encoding_ber_encode_length(content, buffer + total, buflen - total);

                        if (lfield > 0U && (total + lfield + content) <= buflen)
                        {
                            total += lfield;

                            /* recursively encode each child directly into the output buffer at the correct offset. */
                            k = 0U;

                            while ((k < element->ccount) && (ok == true))
                            {
                                size_t clen;

                                clen = qsc_encoding_der_encode_element(element->children[k], buffer + total, buflen - total);

                                if (clen == 0U)
                                {
                                    ok = false;
                                    total = 0U;
                                }
                                else
                                {
                                    total += clen;
                                }

                                ++k;
                            }
                        }
                        else
                        {
                            total = 0U;
                        }
                    }
                }
                else
                {
                    /* primitive element. */
                    size_t lfield;

                    lfield = qsc_encoding_ber_encode_length(element->length, buffer + total, buflen - total);

                    if (lfield > 0U && (total + lfield + element->length) <= buflen)
                    {
                        total += lfield;

                        if (element->length != 0U)
                        {
                            if (element->value == NULL)
                            {
                                total = 0U;
                            }
                            else
                            {
                                qsc_memutils_copy(buffer + total, element->value, element->length);
                                total += element->length;
                            }
                        }
                    }
                    else
                    {
                        total = 0U;
                    }
                }
            }
        }
    }

    return total;
}

bool qsc_encoding_hex_decode(const char* input, size_t inplen, uint8_t* output, size_t otplen, size_t* declen)
{
    QSC_ASSERT(input != NULL);
    QSC_ASSERT(inplen != 0U);
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(otplen != 0U);
    QSC_ASSERT(declen != NULL);

    size_t req;
    bool res;

    res = false;
    *declen = 0U;

    if (input != NULL && output != NULL && declen != NULL && otplen != 0U && inplen != 0U)
    {
        /* hex-encoded input must have an even number of characters. */
        if (inplen % 2U == 0U)
        {
            req = inplen / 2U;

            if (req <= otplen)
            {
                bool ok;
                size_t i;

                ok = true;
                i = 0U;

                while ((i < req) && (ok == true))
                {
                    char c1;
                    char c2;
                    uint8_t hi;
                    uint8_t lo;

                    c1 = input[2U * i];
                    c2 = input[(2U * i) + 1U];
                    hi = 0U;
                    lo = 0U;

                    if (c1 >= '0' && c1 <= '9')
                    {
                        hi = (uint8_t)(c1 - '0');
                    }
                    else if (c1 >= 'A' && c1 <= 'F')
                    {
                        hi = (uint8_t)(c1 - 'A') + 10U;
                    }
                    else if (c1 >= 'a' && c1 <= 'f')
                    {
                        hi = (uint8_t)(c1 - 'a') + 10U;
                    }
                    else
                    {
                        ok = false;
                    }

                    if (ok == true)
                    {
                        if (c2 >= '0' && c2 <= '9')
                        {
                            lo = (uint8_t)(c2 - '0');
                        }
                        else if (c2 >= 'A' && c2 <= 'F')
                        {
                            lo = (uint8_t)(c2 - 'A') + 10U;
                        }
                        else if (c2 >= 'a' && c2 <= 'f')
                        {
                            lo = (uint8_t)(c2 - 'a') + 10U;
                        }
                        else
                        {
                            ok = false;
                        }
                    }

                    if (ok == true)
                    {
                        output[i] = (uint8_t)((hi << 4U) | lo);
                    }

                    ++i;
                }

                if (ok == true)
                {
                    *declen = req;
                    res = true;
                }
                else
                {
                    /* clear any partial output to avoid leaking a half-decoded buffer to the caller. */
                    qsc_memutils_clear(output, req);
                }
            }
        }
    }

    return res;
}

bool qsc_encoding_hex_encode(const uint8_t* input, size_t inplen, char* output, size_t otplen)
{
    QSC_ASSERT(input != NULL);
    QSC_ASSERT(inplen != 0U);
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(otplen != 0U);

    static const char HEX_DIGITS[] = "0123456789ABCDEF";
    bool res;

    res = false;

    if (output != NULL && input != NULL && inplen != 0U && otplen >= (inplen * 2U) + 1U)
    {
        for (size_t i = 0U; i < inplen; ++i)
        {
            output[2U * i] = HEX_DIGITS[(input[i] >> 4U) & 0x0FU];
            output[(2U * i) + 1U] = HEX_DIGITS[input[i] & 0x0FU];
        }

        output[inplen * 2U] = '\0';
        res = true;
    }

    return res;
}

bool qsc_encoding_pem_decode(const char* input, size_t inplen, uint8_t* output, size_t otplen, size_t* declen)
{
    QSC_ASSERT(input != NULL);
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(otplen != 0U);
    QSC_ASSERT(declen != NULL);

    const char* lstart;
    const char* ppos;
    char* b64data;
    size_t b64idx;
    size_t linelen;
    size_t pinplen;
    char ch;
    bool res;

    res = false;
    b64data = NULL;

    if (input != NULL && output != NULL && declen != NULL && otplen != 0U)
    {
        *declen = 0U;

        /* verify that the header and footer carry matching type labels,
         * and that the Base64 payload length is a multiple of four.    */
        if (encoding_header_labels_check(input, "-----BEGIN ", "-----END ", "-----") == true &&
            encoding_base64_length_valid(input, "-----") == true)
        {
            pinplen = inplen;
            b64data = encoding_alloc_chars(pinplen + 1U);

            if (b64data != NULL)
            {
                b64idx = 0U;
                lstart = input;
                ppos = input;

                /* walk the PEM text line by line and accumulate the
                 * Base64 payload, discarding header/footer lines and
                 * stripping intra-line whitespace (' ', '\r', '\t').  */
                while (*ppos != '\0')
                {
                    if (*ppos == '\n')
                    {
                        linelen = (size_t)(ppos - lstart);

                        if (linelen > 0U && lstart[0U] != '-')
                        {
                            for (size_t i = 0U; i < linelen; ++i)
                            {
                                ch = lstart[i];

                                if (ch != ' ' && ch != '\r' && ch != '\t')
                                {
                                    b64data[b64idx] = ch;
                                    ++b64idx;
                                }
                            }
                        }

                        lstart = ppos + 1U;
                    }

                    ++ppos;
                }

                /* handle a final line that has no trailing newline. */
                if (lstart < ppos)
                {
                    linelen = (size_t)(ppos - lstart);

                    if (linelen > 0U && lstart[0U] != '-')
                    {
                        for (size_t i = 0U; i < linelen; ++i)
                        {
                            ch = lstart[i];

                            if (ch != ' ' && ch != '\r' && ch != '\t')
                            {
                                b64data[b64idx] = ch;
                                ++b64idx;
                            }
                        }
                    }
                }

                b64data[b64idx] = '\0';

                /* decode the accumulated Base64 block.
                 * the length-mod-4 check performed above guarantees that
                 * b64idx is already a multiple of four; no padding is added. */
                if (b64idx > 0U && b64idx % 4U == 0U)
                {
                    size_t dexp;

                    dexp = qsc_encoding_base64_decoded_size(b64data, b64idx);

                    if (dexp <= otplen)
                    {
                        if (qsc_encoding_base64_decode(output, otplen, b64data, b64idx) == true)
                        {
                            *declen = dexp;
                            res = true;
                        }
                    }
                }

                qsc_memutils_alloc_free(b64data);
                b64data = NULL;
            }
        }
    }

    return res;
}

bool qsc_encoding_pem_encode(const char* label, char* output, size_t otplen, const uint8_t* data, size_t datalen)
{
    QSC_ASSERT(label != NULL);
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(otplen != 0U);
    QSC_ASSERT(data != NULL);
    QSC_ASSERT(datalen != 0U);

    /* RFC 7468 specifies 64 Base64 characters per line. */
    const size_t LINE_LENGTH = 64U;

    char header[128U] = { 0U };
    char footer[128U] = { 0U };
    char* b64data;
    size_t b64len;
    size_t cnklen;
    size_t pidx;
    int32_t hdrlen;
    int32_t ftrlen;
    bool res;

    res = false;
    b64data = NULL;

    if (label != NULL && output != NULL && otplen != 0U &&
        data != NULL && datalen != 0U)
    {
        hdrlen = snprintf(header, sizeof(header), "-----BEGIN %s-----\n", label);
        ftrlen = snprintf(footer, sizeof(footer), "-----END %s-----\n", label);

        /* snprintf returns the number of characters written (excluding the
         * null terminator) on success; a negative value or a value equal to
         * or greater than the buffer size indicates an error or truncation. */
        if (hdrlen > 0 && hdrlen < (int32_t)sizeof(header) && ftrlen > 0 && ftrlen < (int32_t)sizeof(footer))
        {
            b64len = qsc_encoding_base64_encoded_size(datalen);
            b64data = encoding_alloc_chars(b64len + 1U);

            if (b64data != NULL)
            {
                if (qsc_encoding_base64_encode(b64data, b64len + 1U, data, datalen) == true)
                {
                    pidx = 0U;

                    if ((pidx + (size_t)hdrlen) < otplen)
                    {
                        qsc_memutils_copy(output + pidx, header, (size_t)hdrlen);
                        pidx += (size_t)hdrlen;

                        /* Write Base64 data with a newline every LINE_LENGTH characters. */
                        bool write_ok;
                        size_t i;

                        write_ok = true;
                        i = 0U;

                        while ((i < b64len) && (write_ok == true))
                        {
                            cnklen = ((b64len - i) >= LINE_LENGTH) ? LINE_LENGTH : (b64len - i);

                            if ((pidx + cnklen + 1U) < otplen)
                            {
                                qsc_memutils_copy(output + pidx, b64data + i, cnklen);
                                pidx += cnklen;
                                output[pidx] = '\n';
                                ++pidx;
                            }
                            else
                            {
                                write_ok = false;
                            }

                            i += cnklen;
                        }

                        if (write_ok == true && (pidx + (size_t)ftrlen) < otplen)
                        {
                            qsc_memutils_copy(output + pidx, footer, (size_t)ftrlen);
                            pidx += (size_t)ftrlen;
                            output[pidx] = '\0';
                            res = true;
                        }
                    }
                }

                qsc_memutils_alloc_free(b64data);
                b64data = NULL;
            }
        }
    }

    return res;
}

#if defined(QSC_DEBUG_MODE)

static bool encoding_test_expect_pem_decode(const char* pem, size_t pemlen, const uint8_t* expected, size_t explen)
{
    uint8_t out[512U] = { 0U };
    size_t declen;
    bool res;

    res = false;
    declen = 0U;
    qsc_memutils_set_value(out, sizeof(out), 0xA5U);

    if (qsc_encoding_pem_decode(pem, pemlen, out, sizeof(out), &declen) == true)
    {
        if (declen == explen && qsc_memutils_are_equal(out, expected, explen) == true)
        {
            res = true;
        }
    }

    return res;
}

static bool encoding_test_contains_substr(const char* s, const char* sub)
{
    size_t i;
    size_t slen;
    size_t sublen;
    bool res;

    res = false;

    if (s != NULL && sub != NULL)
    {
        slen = qsc_stringutils_string_size(s);
        sublen = qsc_stringutils_string_size(sub);

        if (sublen != 0U && sublen <= slen)
        {
            for (i = 0U; i + sublen <= slen; ++i)
            {
                if (qsc_stringutils_string_compare(s + i, sub, sublen) == 0)
                {
                    res = true;
                    break;
                }
            }
        }
    }

    return res;
}

static bool encoding_test_pem_line_wrap(const char* pem, size_t maxline)
{
    const char* p;
    const char* bol;
    size_t linelen;
    size_t i;
    bool inpayload;
    bool res;

    res = false;

    if (pem != NULL)
    {
        res = true;
        p = pem;
        bol = pem;
        inpayload = false;

        while ((*p != '\0') && (res == true))
        {
            if (*p == '\n' || *(p + 1U) == '\0')
            {
                const char* eol;

                eol = (*p == '\n') ? p : (p + 1U);
                linelen = (size_t)(eol - bol);

                if (linelen >= 11U && qsc_stringutils_string_compare(bol, "-----BEGIN ", 11U) == 0)
                {
                    inpayload = true;
                }
                else if (linelen >= 9U && qsc_stringutils_string_compare(bol, "-----END ", 9U) == 0)
                {
                    inpayload = false;
                }
                else if (inpayload == true)
                {
                    if (linelen > 0U && linelen > maxline)
                    {
                        res = false;
                    }

                    if (res == true)
                    {
                        for (i = 0U; (i < linelen) && (res == true); ++i)
                        {
                            const char c = bol[i];

                            if ((c < 'A' || c > 'Z') &&
                                (c < 'a' || c > 'z') &&
                                (c < '0' || c > '9') &&
                                c != '+' && c != '/' && c != '=')
                            {
                                res = false;
                            }
                        }
                    }
                }

                bol = (*p == '\n') ? (p + 1U) : eol;
            }

            ++p;
        }
    }

    return res;
}

static bool encoding_test_expect_pem_pass(const char* pem, size_t pemlen, const uint8_t* expected, size_t explen)
{
    uint8_t out[256U] = { 0U };
    size_t declen;
    bool res;

    res = false;
    declen = 0U;
    qsc_memutils_set_value(out, sizeof(out), 0xA5U);

    if (qsc_encoding_pem_decode(pem, pemlen, out, sizeof(out), &declen) == true)
    {
        res = (declen == explen && qsc_memutils_are_equal(out, expected, explen));
    }

    return res;
}

static bool encoding_expect_test_pem_fail(const char* pem, size_t pemlen)
{
    uint8_t out[256U] = { 0U };
    size_t declen;
    bool res;

    res = false;
    declen = 123U;
    qsc_memutils_set_value(out, sizeof(out), 0xA5U);

    if (qsc_encoding_pem_decode(pem, pemlen, out, sizeof(out), &declen) == false)
    {
        res = (declen == 0U);
    }

    return res;
}

static bool encoding_test_pem_decode(void)
{
    const char* valabc = "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n";
    const uint8_t exp_abc[3U] = { 0x61U, 0x62U, 0x63U };
    const uint8_t exp_abcd[4U] = { 0x61U, 0x62U, 0x63U, 0x64U };
    uint8_t small_buf[3U] = { 0U };
    size_t declen;
    size_t enclen;
    bool res;

    res = false;

    enclen = qsc_stringutils_string_size(valabc);

    if (encoding_test_expect_pem_pass(valabc, enclen, exp_abc, sizeof(exp_abc)) == true)
    {
        const char* valabcdws = "-----BEGIN CERTIFICATE-----\r\n  Y W J j Z A = =  \r\n\t\r\n-----END CERTIFICATE-----\r\n";
        enclen = qsc_stringutils_string_size(valabcdws);

        if (encoding_test_expect_pem_pass(valabcdws, enclen, exp_abcd, sizeof(exp_abcd)) == true)
        {
            /* Mismatched header/footer labels must fail. */
            const char* invlabel = "-----BEGIN CERTIFICATE-----\nYWJj\n-----END PUBLIC KEY-----\n";
            enclen = qsc_stringutils_string_size(invlabel);

            if (encoding_expect_test_pem_fail(invlabel, enclen) == true)
            {
                /* Non-multiple-of-4 Base64 payload must fail. */
                const char* invlenmod4 = "-----BEGIN CERTIFICATE-----\nYWJ\n-----END CERTIFICATE-----\n";
                enclen = qsc_stringutils_string_size(invlenmod4);

                if (encoding_expect_test_pem_fail(invlenmod4, enclen) == true)
                {
                    /* Padding in an illegal position must fail. */
                    const char* invpad = "-----BEGIN CERTIFICATE-----\nYW=Jj\n-----END CERTIFICATE-----\n";
                    enclen = qsc_stringutils_string_size(invpad);

                    if (encoding_expect_test_pem_fail(invpad, enclen) == true)
                    {
                        /* Output buffer too small must fail. */
                        const char* invsmout = "-----BEGIN CERTIFICATE-----\nYWJjZA==\n-----END CERTIFICATE-----\n";

                        qsc_memutils_set_value(small_buf, sizeof(small_buf), 0xA5U);
                        declen = 999U;
                        enclen = qsc_stringutils_string_size(invsmout);

                        if (qsc_encoding_pem_decode(invsmout, enclen, small_buf, sizeof(small_buf), &declen) == false)
                        {
                            res = (declen == 0U);
                        }
                    }
                }
            }
        }
    }

    return res;
}

static bool encoding_test_pem_encode(void)
{
    const char* lok = "CERTIFICATE";
    char pem[2048U] = { 0U };
    char pemsm[32U] = { 0U };
    uint8_t data1[3U] = { 0x61U, 0x62U, 0x63U };
    uint8_t data2[96U] = { 0U };
    size_t enclen;
    bool res;

    res = false;

    for (size_t i = 0U; i < sizeof(data2); ++i)
    {
        data2[i] = (uint8_t)i;
    }

    /* Encode must succeed with a well-formed label. */
    if (qsc_encoding_pem_encode(lok, pem, sizeof(pem), data1, sizeof(data1)) == true)
    {
        /* Verify canonical header and footer lines are present. */
        if (encoding_test_contains_substr(pem, "-----BEGIN CERTIFICATE-----\n") == true &&
            encoding_test_contains_substr(pem, "-----END CERTIFICATE-----\n") == true)
        {
            enclen = qsc_stringutils_string_size(pem);
            /* Round-trip: encode then decode must reproduce the original. */
            if (encoding_test_expect_pem_decode(pem, enclen, data1, sizeof(data1)) == true)
            {
                /* Wrapping and alphabet constraints for a larger payload. */
                qsc_memutils_clear(pem, sizeof(pem));
                enclen = qsc_stringutils_string_size(pem);

                if (qsc_encoding_pem_encode(lok, pem, sizeof(pem), data2, sizeof(data2)) == true &&
                    encoding_test_pem_line_wrap(pem, 64U) == true &&
                    encoding_test_expect_pem_decode(pem, enclen, data2, sizeof(data2)) == true)
                {
                    /* Output buffer too small must fail. */
                    qsc_memutils_clear(pemsm, sizeof(pemsm));

                    if (qsc_encoding_pem_encode(lok, pemsm, sizeof(pemsm), data2, sizeof(data2)) == false)
                    {
                        res = true;
                    }
                }
            }
        }
    }

    return res;
}

bool qsc_encoding_tests(void)
{
    bool res;

    res = false;

    if (encoding_test_pem_decode() == true)
    {
        if (encoding_test_pem_encode() == true)
        {
            res = true;
        }
    }

    return res;
}

#endif
