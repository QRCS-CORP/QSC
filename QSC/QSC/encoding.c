#include "encoding.h"
#include "memutils.h"
#include "stringutils.h"
#include <stdio.h>

qsc_encoding_ber_element* qsc_encoding_ber_decode_element(const uint8_t* buffer, size_t buflen, size_t* consumed)
{
    assert(buffer != NULL);
    assert(buflen != 0);
    assert(consumed != NULL);

    qsc_encoding_ber_element* relem;
    qsc_encoding_ber_element* elem;
    qsc_encoding_ber_element** tmp;
    qsc_encoding_ber_element* child;
    size_t pos;
    size_t taglen;
    size_t llen;
    size_t length;
    size_t achildren;
    size_t start;
    size_t chconsumed;
    uint8_t tagclass;
    uint32_t tagnumber;
    bool constructed;
    bool indefinite;

    relem = (qsc_encoding_ber_element*)NULL;

    if (buffer != NULL && buflen != 0 && consumed != NULL)
    {
        elem = (qsc_encoding_ber_element*)NULL;
        tmp = (qsc_encoding_ber_element**)NULL;
        child = (qsc_encoding_ber_element*)NULL;
        pos = 0U;
        taglen = 0U;
        llen = 0U;
        length = 0U;
        achildren = 0U;
        start = 0U;
        chconsumed = 0U;
        tagclass = 0U;
        constructed = false;
        tagnumber = 0U;
        indefinite = false;

        if ((buffer == (const uint8_t*)NULL) || (buflen < 2U))
        {
            if (consumed != (size_t*)NULL)
            {
                *consumed = 0U;
            }

            relem = (qsc_encoding_ber_element*)NULL;
        }
        else
        {
            taglen = qsc_encoding_ber_decode_tag(buffer, buflen, &tagclass, &constructed, &tagnumber);

            if (taglen == 0U)
            {
                relem = (qsc_encoding_ber_element*)NULL;
            }
            else
            {
                pos = pos + taglen;
                llen = qsc_encoding_ber_decode_length(buffer + pos, buflen - pos, &length, &indefinite);

                if (llen == 0U)
                {
                    relem = (qsc_encoding_ber_element*)NULL;
                }
                else
                {
                    pos = pos + llen;
                    elem = (qsc_encoding_ber_element*)qsc_memutils_malloc(sizeof(qsc_encoding_ber_element));
                    qsc_memutils_clear(elem, sizeof(qsc_encoding_ber_element));

                    if (elem == (qsc_encoding_ber_element*)NULL)
                    {
                        relem = (qsc_encoding_ber_element*)NULL;
                    }
                    else
                    {
                        elem->tagclass = tagclass;
                        elem->constructed = constructed;
                        elem->tagnumber = tagnumber;
                        elem->indefinite = indefinite;

                        if (constructed == true)
                        {
                            elem->ccount = 0U;
                            elem->children = (qsc_encoding_ber_element**)NULL;
                            achildren = 0U;
                            start = pos;

                            if (indefinite == true)
                            {
                                while ((pos + 2U) <= buflen)
                                {
                                    if ((buffer[pos] == 0U) && (buffer[pos + 1U] == 0U))
                                    {
                                        break;
                                    }

                                    chconsumed = 0U;
                                    child = qsc_encoding_ber_decode_element(buffer + pos, buflen - pos, &chconsumed);

                                    if (child == (qsc_encoding_ber_element*)NULL)
                                    {
                                        break;
                                    }

                                    pos = pos + chconsumed;

                                    if (elem->ccount >= achildren)
                                    {
                                        if (achildren == 0U)
                                        {
                                            achildren = 4U;
                                        }
                                        else
                                        {
                                            achildren = achildren * 2U;
                                        }

                                        tmp = (qsc_encoding_ber_element**)realloc(elem->children, achildren * sizeof(qsc_encoding_ber_element*));

                                        if (tmp == (qsc_encoding_ber_element**)NULL)
                                        {
                                            break;
                                        }
                                        else
                                        {
                                            elem->children = tmp;
                                        }
                                    }

                                    elem->children[elem->ccount] = child;
                                    elem->ccount = elem->ccount + 1U;
                                    child = (qsc_encoding_ber_element*)NULL;
                                }

                                if (((pos + 2U) > buflen) || (buffer[pos] != 0U) || (buffer[pos + 1U] != 0U))
                                {
                                    relem = (qsc_encoding_ber_element*)NULL;
                                }
                                else
                                {
                                    pos = pos + 2U;
                                    elem->length = pos - start;
                                    elem->value = (uint8_t*)NULL;
                                    relem = elem;
                                    elem = (qsc_encoding_ber_element*)NULL;
                                }
                            }
                            else
                            {
                                size_t end;

                                end = pos + length;

                                while (pos < end)
                                {
                                    chconsumed = 0U;
                                    child = qsc_encoding_ber_decode_element(buffer + pos, end - pos, &chconsumed);

                                    if (child == (qsc_encoding_ber_element*)NULL)
                                    {
                                        break;
                                    }

                                    pos = pos + chconsumed;

                                    if (elem->ccount >= achildren)
                                    {
                                        if (achildren == 0U)
                                        {
                                            achildren = 4U;
                                        }
                                        else
                                        {
                                            achildren = achildren * 2U;
                                        }
                                        tmp = (qsc_encoding_ber_element**)realloc(elem->children, achildren * sizeof(qsc_encoding_ber_element*));
                                        if (tmp == (qsc_encoding_ber_element**)NULL)
                                        {
                                            break;
                                        }
                                        else
                                        {
                                            elem->children = tmp;
                                        }
                                    }

                                    elem->children[elem->ccount] = child;
                                    elem->ccount = elem->ccount + 1U;
                                    child = (qsc_encoding_ber_element*)NULL;
                                }

                                if (pos != end)
                                {
                                    relem = (qsc_encoding_ber_element*)NULL;
                                }
                                else
                                {
                                    elem->length = pos - start;
                                    elem->value = (uint8_t*)NULL;
                                    relem = elem;
                                    elem = (qsc_encoding_ber_element*)NULL;
                                }
                            }
                        }
                        else
                        {
                            if (indefinite == true)
                            {
                                relem = (qsc_encoding_ber_element*)NULL;
                            }
                            else if ((pos + length) > buflen)
                            {
                                relem = (qsc_encoding_ber_element*)NULL;
                            }
                            else
                            {
                                elem->length = length;
                                
                                elem->value = qsc_memutils_malloc(length);

                                if (elem->value != (uint8_t*)NULL)
                                {
                                    (void)memcpy(elem->value, buffer + pos, length);
                                    pos = pos + length;
                                    relem = elem;
                                    elem = (qsc_encoding_ber_element*)NULL;
                                }
                                else
                                {
                                    relem = (qsc_encoding_ber_element*)NULL;
                                }
                            }
                        }
                    }
                }
            }

            if (consumed != (size_t*)NULL)
            {
                *consumed = pos;
            }
        }
    }

    return relem;
}

size_t qsc_encoding_ber_decode_length(const uint8_t* buffer, size_t buflen, size_t* length, bool* indef)
{
    assert(buffer != NULL);
    assert(buflen != 0);
    assert(length != NULL);
    assert(indef != NULL);

    size_t res;

    res = 0;

    if (buffer != NULL && buflen >= 1 && length != NULL && indef != NULL)
    {
        uint8_t first;

        first = buffer[0];

        if (first == 0x80)
        {
            *indef = true;
            /* for indefinite lengths the length isn't pre-known */
            *length = 0;
            res = 1;
        }
        else if ((first & 0x80) == 0)
        {
            *indef = false;
            *length = first;
            res = 1;
        }
        else
        {
            uint8_t bnum;

            *indef = false;
            bnum = first & 0x7F;

            if (buflen < 1 + bnum)
            {
                res = 0;
            }
            else
            {
                size_t len;

                len = 0;

                for (size_t i = 0; i < bnum; ++i)
                {
                    len = (len << 8) | buffer[1 + i];
                }

                *length = len;

                res = 1 + bnum;
            }
        }
    }

    return res;
}

size_t qsc_encoding_ber_decode_tag(const uint8_t* buffer, size_t buflen, uint8_t* tagclass, bool* construct, uint32_t* tagnum)
{
    assert(buffer != NULL);
    assert(buflen != 0);
    assert(tagclass != NULL);
    assert(construct != NULL);
    assert(tagnum != NULL);

    size_t pos;

    pos = 0;

    if (buffer != NULL && buflen > 0 && tagclass != NULL && construct != NULL && tagnum != NULL)
    {
        uint8_t first;
        uint8_t tagval;

        first = buffer[0];
        *tagclass = first & 0xC0;
        *construct = (first & 0x20) ? true : false;
        tagval = first & 0x1F;
        pos = 1;

        if (tagval != 0x1F)
        {
            *tagnum = tagval;
        }
        else
        {
            /* extended tag number: read base-128 encoded bytes */
            uint32_t num;

            num = 0;

            while (pos < buflen) 
            {
                uint8_t b;

                b = buffer[pos];
                ++pos;
                num = (num << 7) | (b & 0x7F);

                if ((b & 0x80) == 0)
                {
                    break;
                }
            }

            *tagnum = num;
        }
    }

    return pos;
}

size_t qsc_encoding_ber_encode_element(qsc_encoding_ber_element* element, uint8_t* buffer, size_t buflen)
{
    assert(element != NULL);
    assert(buffer != NULL);
    assert(buflen != 0);

    uint8_t alen[10] = { 0 };
    uint8_t tagbuf[10] = { 0 };
    size_t ret;
    size_t total;
    size_t taglen;
    size_t llen;

    ret = 0U;
    total = 0U;
    taglen = 0U;
    llen = 0U;

    if (element != NULL && buffer != NULL && buflen != 0)
    {
        if ((element != (qsc_encoding_ber_element*)NULL) && (buffer != (uint8_t*)NULL) && (buflen != 0U))
        {
            taglen = qsc_encoding_ber_encode_tag(element->tagclass, element->constructed, element->tagnumber, tagbuf, (size_t)sizeof(tagbuf));
            
            if ((taglen != 0U) && (taglen <= buflen))
            {
                (void)memcpy(buffer, tagbuf, taglen);
                total = total + taglen;

                if ((element->constructed == true) && (element->indefinite == true))
                {
                    if ((buflen - total) >= 1U)
                    {
                        alen[0] = 0x80U;
                        llen = 1U;
                    }
                    else
                    {
                        llen = 0U;
                    }
                }
                else
                {
                    llen = qsc_encoding_ber_encode_length(element->length, alen, (size_t)sizeof(alen));
                }

                if ((llen != 0U) && ((total + llen) <= buflen))
                {
                    (void)memcpy(buffer + total, alen, llen);
                    total = total + llen;

                    if (element->constructed == true)
                    {
                        if (element->indefinite == true)
                        {
                            {
                                for (size_t i = 0U; i < element->ccount; i++)
                                {
                                    size_t clen;

                                    clen = qsc_encoding_ber_encode_element(element->children[i], buffer + total, buflen - total);
                                    
                                    if (clen == 0U)
                                    {
                                        total = 0U;
                                        /* Exit the loop on error */
                                        i = element->ccount;
                                    }
                                    else
                                    {
                                        total = total + clen;
                                    }
                                }
                            }

                            if ((total != 0U) && ((buflen - total) >= 2U))
                            {
                                buffer[total] = 0x00U;
                                total = total + 1U;
                                buffer[total] = 0x00U;
                                total = total + 1U;
                                ret = total;
                            }
                            else
                            {
                                ret = 0U;
                            }
                        }
                        else
                        {
                            if ((total + element->length) <= buflen)
                            {
                                qsc_memutils_copy(buffer + total, element->value, element->length);
                                total = total + element->length;
                                ret = total;
                            }
                            else
                            {
                                ret = 0U;
                            }
                        }
                    }
                    else
                    {
                        /* primitive element */
                        if ((total + element->length) <= buflen)
                        {
                            qsc_memutils_copy(buffer + total, element->value, element->length);
                            total = total + element->length;
                            ret = total;
                        }
                        else
                        {
                            ret = 0U;
                        }
                    }
                }
                else
                {
                    ret = 0U;
                }
            }
            else
            {
                ret = 0U;
            }
        }
        else
        {
            ret = 0U;
        }
    }

    return ret;
}

size_t qsc_encoding_ber_encode_length(size_t length, uint8_t* buffer, size_t buflen)
{
    assert(buffer != NULL);
    assert(buflen != 0);

    size_t res;

    res = 1;

    if (buffer != NULL && buflen >= 1)
    {
        if (length == QSC_BER_ENCODING_INDEFINITE_LENGTH)
        {
            /* indefinite length: one byte 0x80 */
            buffer[0] = 0x80;
        }
        else if (length < 128)
        {
            /* short form */
            buffer[0] = (uint8_t)length;
        }
        else
        {
            /* long form: determine the number of bytes needed to encode the length */
            uint8_t alen[8] = { 0 };
            size_t bnum;
            size_t tlen;

            bnum = 0;
            tlen = length;

            while (tlen > 0)
            {
                alen[bnum] = tlen & 0xFF;
                ++bnum;
                tlen >>= 8;
            }

            if (buflen < 1 + bnum)
            {
                res = 0;
            }
            else
            {
                buffer[0] = 0x80 | (uint8_t)bnum;

                for (size_t i = 0; i < bnum; i++)
                {
                    /* big-endian order */
                    buffer[1 + i] = alen[bnum - 1 - i];
                }

                res = 1 + bnum;
            }
        }
    }

    return res;
}

size_t qsc_encoding_ber_encode_tag(uint8_t tagclass, bool construct, uint32_t tagnum, uint8_t* buffer, size_t buflen)
{
    assert(buffer != NULL);
    assert(buflen != 0);

    size_t pos;
    uint8_t first;

    pos = 0;

    if (buffer != NULL && buflen > 0)
    {
        first = tagclass;

        if (construct)
        {
            /* set the constructed bit */
            first |= 0x20;
        }

        if (tagnum < 31)
        {
            first |= (uint8_t)(tagnum & 0x1F);
            buffer[pos] = first;
            ++pos;
        }
        else 
        {
            uint8_t temp[5] = { 0 };
            size_t tmplen;

            /* indicate long-form tag */
            first |= 0x1F;
            buffer[pos] = first;
            ++pos;
            tmplen = 0;

            /* encode tagnumber in base-128 (big-endian, with continuation bits) */
            do 
            {
                temp[tmplen] = tagnum & 0x7F;
                ++tmplen;
                tagnum >>= 7;
            } 
            while (tagnum > 0);

            for (int32_t i = (int32_t)tmplen - 1; i >= 0; --i)
            {
                uint8_t b;

                b = temp[i];

                if (i != 0)
                {
                    /* set continuation bit on all but the last byte */
                    b |= 0x80;
                }

                if (pos >= buflen)
                {
                    pos = 0;
                    break;
                }

                buffer[pos] = b;
                ++pos;
            }
        }
    }

    return pos;
}

void encoding_ber_free_element(qsc_encoding_ber_element* element)
{
    assert(element != NULL);

    if (element != NULL)
    {
        if (element->constructed)
        {
            for (size_t i = 0; i < element->ccount; ++i) 
            {
                encoding_ber_free_element(element->children[i]);
            }
            
            qsc_memutils_alloc_free(element->children);
        }
        else 
        {
            qsc_memutils_alloc_free(element->value);
        }

        qsc_memutils_alloc_free(element);
    }
}

bool qsc_encoding_base64_decode(uint8_t* output, size_t otplen, const char* input, size_t inplen)
{
    assert(output != NULL);
    assert(input != NULL);
    assert(inplen != 0);

	const static int32_t DECTBL[] = 
	{
		62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58,
		59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5,
		6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
		21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
		29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
		43, 44, 45, 46, 47, 48, 49, 50, 51 
	};

	size_t i;
	size_t j;
	int32_t v;
	bool res;

    res = false;

    if (output != NULL && input != NULL && inplen != 0)
    {
        res = true;

        if (input != NULL && output != NULL)
        {
            if (otplen < qsc_encoding_base64_decoded_size(input, inplen) || inplen % 4 != 0)
            {
                res = false;
            }

            if (res == true)
            {
                for (i = 0; i < inplen; i++)
                {
                    if (qsc_encoding_base64_is_valid_char(input[i]) == false)
                    {
                        res = false;
                        break;
                    }
                }

                if (res == true)
                {
                    for (i = 0, j = 0; i < inplen; i += 4, j += 3)
                    {
                        v = DECTBL[input[i] - 43];
                        v = ((uint32_t)v << 6) | DECTBL[input[i + 1] - 43];
                        v = input[i + 2] == '=' ? (uint32_t)v << 6 : ((uint32_t)v << 6) | DECTBL[input[i + 2] - 43];
                        v = input[i + 3] == '=' ? (uint32_t)v << 6 : ((uint32_t)v << 6) | DECTBL[input[i + 3] - 43];
                        output[j] = (v >> 16) & 0xFF;

                        if (input[i + 2] != '=')
                        {
                            output[j + 1] = (v >> 8) & 0xFF;
                        }

                        if (input[i + 3] != '=')
                        {
                            output[j + 2] = v & 0xFF;
                        }
                    }
                }
            }
        }
    }

	return res;
}

size_t qsc_encoding_base64_decoded_size(const char* input, size_t length)
{
    assert(input != NULL);
    assert(length != 0);

	size_t res;

	res = 0;

	if (input != NULL && length != 0)
	{
		res = (length / 4) * 3;

		for (size_t i = length - 1; i > 0; --i)
		{
			if (input[i] == '=')
			{
				--res;

				if (i > 0 && input[i - 1] == '=')
				{
					--res;
				}

				break;
			}
		}
	}

	return res;
}

void qsc_encoding_base64_encode(char* output, size_t otplen, const uint8_t* input, size_t inplen)
{
    assert(output != NULL);
    assert(otplen != 0);
    assert(input != NULL);
    assert(inplen != 0);

	const char ENCTBL[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	size_t i;
	size_t j;
	size_t v;

	if (output != NULL && input != NULL && inplen != 0 && qsc_encoding_base64_encoded_size(inplen) <= otplen)
	{
		for (i = 0, j = 0; i < inplen; i += 3, j += 4)
		{
			v = input[i];
			v = i + 1 < inplen ? v << 8 | input[i + 1] : v << 8;
			v = i + 2 < inplen ? v << 8 | input[i + 2] : v << 8;

			output[j] = ENCTBL[(v >> 18) & 0x3F];
			output[j + 1] = ENCTBL[(v >> 12) & 0x3F];

			if (i + 1 < inplen)
			{
				output[j + 2] = ENCTBL[(v >> 6) & 0x3F];
			}
			else
			{
				output[j + 2] = '=';
			}

			if (i + 2 < inplen)
			{
				output[j + 3] = ENCTBL[v & 0x3F];
			}
			else
			{
				output[j + 3] = '=';
			}
		}
	}
}

size_t qsc_encoding_base64_encoded_size(size_t length)
{
    assert(length != 0);

	size_t ret;

	ret = length;

	if (length % 3 != 0)
	{
		ret += 3 - (length % 3);
	}

	ret /= 3;
	ret *= 4;

	return ret;
}

bool qsc_encoding_base64_is_valid_char(char value)
{
	bool res;

	if (value >= '0' && value <= '9')
	{
		res = true;
	}
	else if (value >= 'A' && value <= 'Z')
	{
		res = true;
	}
	else if (value >= 'a' && value <= 'z')
	{
		res = true;
	}
	else if (value == '+' || value == '/' || value == '=')
	{
		res = true;
	}
	else
	{
		res = false;
	}

	return res;
}

qsc_encoding_ber_element* qsc_encoding_der_decode_element(const uint8_t* buffer, size_t buflen, size_t* consumed)
{
    assert(buffer != NULL);
    assert(buflen != 0);
    assert(consumed != NULL);

    qsc_encoding_ber_element* elem;

    elem = NULL;

    if (buffer != NULL && buflen != 0 && consumed != NULL)
    {
        elem = qsc_encoding_ber_decode_element(buffer, buflen, consumed);

        if (elem != NULL)
        {
            if (elem->indefinite == true)
            {
                /* DER disallows indefinite lengths */
                encoding_ber_free_element(elem);
                elem = NULL;
            }
        }
    }

    return elem;
}

size_t qsc_encoding_der_encode_element(qsc_encoding_ber_element* element, uint8_t* buffer, size_t buflen)
{
    uint8_t* contbuf;
    const size_t TEMP_BUF_SIZE = 4096U;
    size_t total;
    size_t taglen;
    size_t lfield;
    size_t contlen;
    bool bcond;

    contlen = 0U;
    lfield = 0U;
    taglen = 0U;
    total = 0U;

    if (element != NULL && buffer != NULL && buflen != 0U)
    {
        /* For constructed elements, recursively encode each child element into a temporary buffer.
        * Here we allocate a temporary buffer. In a real implementation, you may wish to compute the
        * required size dynamically or reuse an allocation strategy.
        */
        contbuf = (uint8_t*)qsc_memutils_malloc(TEMP_BUF_SIZE);

        if (contbuf != NULL)
        {
            /* DER does not allow indefinite-length encoding. */
            if (element->indefinite == false)
            {
                /* Encode the tag using the BER tag encoding routine */
                taglen = qsc_encoding_ber_encode_tag(element->tagclass, element->constructed, element->tagnumber, buffer, buflen);

                if ((taglen != 0U) && (taglen <= buflen))
                {
                    bcond = true;
                    total += taglen;

                    if (element->constructed == true)
                    {
                        contlen = 0U;

                        for (size_t i = 0U; i < element->ccount; i++)
                        {
                            size_t clen;

                            clen = qsc_encoding_der_encode_element(element->children[i], contbuf + contlen, TEMP_BUF_SIZE - contlen);
                            
                            if (clen == 0U)
                            {
                                bcond = false;
                                break;
                            }

                            contlen += clen;
                        }
                    }
                    else
                    {
                        /* For primitive elements, the content is the raw value. */
                        contlen = element->length;
                    }

                    if (bcond == true)
                    {
                        /* Encode the length field (definite-length only) */
                        lfield = qsc_encoding_ber_encode_length(contlen, buffer + total, buflen - total);

                        if (lfield != 0U && (total + lfield) <= buflen)
                        {
                            total += lfield;

                            /* Copy the content bytes into the output buffer */
                            if ((total + contlen) <= buflen)
                            {
                                if (element->constructed == true)
                                {
                                    qsc_memutils_copy(buffer + total, contbuf, contlen);
                                }
                                else
                                {
                                    qsc_memutils_copy(buffer + total, element->value, contlen);
                                }

                                total += contlen;
                            }
                        }
                    }
                }

                qsc_memutils_alloc_free(contbuf);
            }
        }
    }

    return total;
}

bool qsc_encoding_hex_decode(const char* input, size_t inplen, uint8_t* output, size_t otplen, size_t* declen)
{
    assert(input != NULL);
    assert(inplen != 0);
    assert(output != NULL);
    assert(otplen != 0);
    assert(declen != NULL);

    size_t req;
    bool res;

    req = inplen / 2;
    res = false;

    if (inplen % 2 == 0 && req >= otplen && input != NULL && output != NULL && declen != NULL)
    {
        res = true;

        for (size_t i = 0; i < req; i++)
        {
            char c1;
            char c2;
            uint8_t nibble1;
            uint8_t nibble2;

            c1 = input[2 * i];
            c2 = input[2 * i + 1];

            if (c1 >= '0' && c1 <= '9')
            {
                nibble1 = c1 - '0';
            }
            else if (c1 >= 'A' && c1 <= 'F')
            {
                nibble1 = c1 - 'A' + 10;
            }
            else if (c1 >= 'a' && c1 <= 'f')
            {
                nibble1 = c1 - 'a' + 10;
            }
            else
            {
                res = false;
                break;
            }

            if (c2 >= '0' && c2 <= '9')
            {
                nibble2 = c2 - '0';
            }
            else if (c2 >= 'A' && c2 <= 'F')
            {
                nibble2 = c2 - 'A' + 10;
            }
            else if (c2 >= 'a' && c2 <= 'f')
            {
                nibble2 = c2 - 'a' + 10;
            }
            else
            {
                res = false;
                break;
            }

            output[i] = (nibble1 << 4) | nibble2;
        }

        *declen = req;
    }

    return res;
}

bool qsc_encoding_hex_encode(const uint8_t* input, size_t inplen, char* output, size_t otplen)
{
    assert(input != NULL);
    assert(inplen != 0);
    assert(output != NULL);
    assert(otplen != 0);

    bool res;

    res = false;

    if (output != NULL && input != NULL && otplen >= (inplen * 2) + 1)
    {
        static const char hex_digits[] = "0123456789ABCDEF";

        for (size_t i = 0; i < inplen; i++)
        {
            output[2 * i] = hex_digits[(input[i] >> 4) & 0x0F];
            output[2 * i + 1] = hex_digits[input[i] & 0x0F];
        }

        output[inplen * 2] = '\0';
        res = true;
    }

    return res;
}

bool qsc_encoding_pem_decode(const char* input, uint8_t* output, size_t otplen, size_t* declen)
{
    const char* lstart;
    const char* ppos;
    char* b64data;
    size_t linelen;
    size_t pinplen;
    size_t b64idx;
    char ch;
    bool res;

    b64idx = 0U;
    pinplen = 0U;
    res = false;

    if ((input != NULL) && (output != NULL) && (otplen != 0U))
    {
        pinplen = qsc_stringutils_string_size(input);
        b64data = qsc_memutils_malloc(pinplen + 1U);

        if (b64data != NULL)
        {
            b64idx = 0U;
            lstart = input;
            ppos = input;

            /* process the PEM input line by line */
            while (*ppos != '\0')
            {
                if (*ppos == '\n')
                {
                    linelen = (size_t)(ppos - lstart);

                    if (linelen > 0U)
                    {
                        /* skip the line if its first non-whitespace character is '-' */
                        if (lstart[0] != '-')
                        {
                            for (size_t i = 0U; i < linelen; i++)
                            {
                                ch = lstart[i];

                                if ((ch != ' ') && (ch != '\r') && (ch != '\t'))
                                {
                                    b64data[b64idx] = ch;
                                    ++b64idx;
                                }
                            }
                        }
                    }

                    lstart = ppos + 1;
                }

                ++ppos;
            }

            /* process any final line (if there is no trailing newline) */
            if (lstart < ppos)
            {
                linelen = (size_t)(ppos - lstart);

                if (linelen > 0U)
                {
                    if (lstart[0] != '-')
                    {
                        for (size_t i = 0U; i < linelen; i++)
                        {
                            ch = lstart[i];

                            if ((ch != ' ') && (ch != '\r') && (ch != '\t'))
                            {
                                b64data[b64idx] = ch;
                                ++b64idx;
                            }
                        }
                    }
                }
            }

            b64data[b64idx] = '\0';

            /* pad the Base64 string if necessary so that its length is a multiple of 4 */
            {
                size_t pad;
                size_t rmd;

                rmd = b64idx % 4;

                if (rmd != 0U)
                {
                    pad = 4U - rmd;

                    /* assuming our temporary buffer is large enough */
                    for (size_t i = 0U; i < pad; i++)
                    {
                        b64data[b64idx] = '=';
                        ++b64idx;
                    }

                    b64data[b64idx] = '\0';
                }
            }

            /* determine the expected decoded size */
            {
                size_t dexp;

                dexp = qsc_encoding_base64_decoded_size(b64data, b64idx);

                if (dexp <= otplen)
                {
                    res = qsc_encoding_base64_decode(output, otplen, b64data, b64idx);

                    if (declen != NULL)
                    {
                        *declen = dexp;
                    }
                }
            }

            qsc_memutils_alloc_free(b64data);
        }
    }

    return res;
}

bool qsc_encoding_pem_encode(const char* label, char* output, size_t otplen, const uint8_t* data, size_t data_len)
{
    /* insert newline every 64 base64 characters */
    const size_t LINE_LENGTH = 64;
    char header[128];
    char footer[128];
    char* b64data;
    size_t b64len;
    size_t cnklen;
    size_t pidx;
    int32_t hdrlen;
    int32_t ftrlen;
    bool res;

    /* create header and footer lines */
    hdrlen = snprintf(header, sizeof(header), "-----BEGIN %s-----\n", label);
    ftrlen = snprintf(footer, sizeof(footer), "-----END %s-----\n", label);
    b64data = NULL;
    res = false;

    if (hdrlen != 0 && ftrlen != 0)
    {
        /* compute the length required for Base64 encoding */
        b64len = qsc_encoding_base64_encoded_size(data_len);
        /* allocate a temporary buffer for the Base64 encoded data */
        /* +1 for null terminator */
        b64data = qsc_memutils_malloc(b64len + 1);

        if (b64data != NULL)
        {
            qsc_memutils_clear(b64data, b64len + 1);
            qsc_encoding_base64_encode(b64data, b64len + 1, data, data_len);
            pidx = 0;

            /* write the header line */
            if (pidx + hdrlen < otplen)
            {
                qsc_memutils_copy(output + pidx, header, hdrlen);
                pidx += hdrlen;

                /* write the base64 data, inserting newline characters every LINE_LENGTH characters */
                for (size_t i = 0; i < b64len; i += LINE_LENGTH)
                {
                    cnklen = (b64len - i >= LINE_LENGTH) ? LINE_LENGTH : (b64len - i);

                    if (pidx + cnklen + 1 < otplen)
                    {
                        qsc_memutils_copy(output + pidx, b64data + i, cnklen);
                        pidx += cnklen;
                        output[pidx] = '\n';
                        ++pidx;
                    }
                }

                /* append the footer */
                if (pidx + ftrlen < otplen)
                {
                    qsc_memutils_copy(output + pidx, footer, ftrlen);
                    pidx += ftrlen;

                    /* null-terminate the output */
                    if (pidx < otplen)
                    {
                        output[pidx] = '\0';
                    }
                    
                    res = true;
                }
            }

            qsc_memutils_alloc_free(b64data);
        }
    }

    return res;
}
