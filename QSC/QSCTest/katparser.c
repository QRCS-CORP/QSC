#include "katparser.h"
#include <stdlib.h>
#include "../QSC/fileutils.h"
#include "../QSC/intutils.h"
#include "../QSC/stringutils.h"

static char* file_to_string(const char* path, size_t* flen)
{
	FILE* fp;
	char* fbuf;
	errno_t ferr;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	ferr = fopen_s(&fp, path, "r");
#else
	fp = fopen(path, "r");
	ferr = (fp != NULL) ? 0 : -1;
#endif

	fbuf = NULL;
	*flen = qsc_fileutils_get_size(path);

	if (*flen > 0 && ferr == 0 && fp != NULL)
	{
		fbuf = (char*)malloc(*flen);

		if (fbuf != NULL)
		{
			*flen = fread(fbuf, 1, *flen, fp);
		}
	}

	return fbuf;
}

void parse_nist_signature_kat(const char* path, uint8_t* seed, size_t* seedlen, uint8_t* msg, size_t* msglen,
	uint8_t* pk, size_t* pklen, uint8_t* sk, size_t* sklen, uint8_t* sm, size_t* smlen, uint32_t setnum)
{
	const char CNTTAG[] = "count = ";
	const char SEDTAG[] = "seed = ";
	const char MSGTAG[] = "msg = ";
	const char PKYTAG[] = "pk = ";
	const char SKYTAG[] = "sk = ";
	const char SMGTAG[] = "sm = ";
	size_t flen;
	int64_t fpos;
	int64_t llen;
	size_t sctr;
	uint32_t setc;
	const char* fbuf;
	char* pbuf;

	sctr = 0;

	if (qsc_fileutils_exists(path))
	{
		pbuf = file_to_string(path, &flen);

		if (pbuf != NULL)
		{
			fbuf = pbuf;

			while (true)
			{
				fpos = (size_t)qsc_stringutils_find_string(fbuf, CNTTAG) + sizeof(CNTTAG) - 1;

				if (fpos < 0)
				{
					break;
				}

				fbuf += fpos;
				setc = (uint32_t)qsc_stringutils_string_to_int(fbuf);

				if (setc == setnum || fpos == 0 || sctr > 100)
				{
					break;
				}

				++sctr;
			}

			fpos = (size_t)qsc_stringutils_find_string(fbuf, SEDTAG) + sizeof(SEDTAG) - 1;

			if (fpos > 0)
			{
				fbuf += fpos;
				llen = (size_t)qsc_stringutils_find_string(fbuf, "\n") / 2;

				if (llen > 0)
				{
					qsc_intutils_hex_to_bin(fbuf, seed, llen);
					*seedlen = llen;

					fpos = (size_t)qsc_stringutils_find_string(fbuf, MSGTAG) + sizeof(MSGTAG) - 1;

					if (fpos > 0)
					{
						fbuf += fpos;
						llen = (size_t)qsc_stringutils_find_string(fbuf, "\n") / 2;

						if (llen > 0)
						{
							qsc_intutils_hex_to_bin(fbuf, msg, llen);
							*msglen = llen;

							fpos = (size_t)qsc_stringutils_find_string(fbuf, PKYTAG) + sizeof(PKYTAG) - 1;

							if (fpos > 0)
							{
								fbuf += fpos;
								llen = (size_t)qsc_stringutils_find_string(fbuf, "\n") / 2;

								if (llen > 0)
								{
									qsc_intutils_hex_to_bin(fbuf, pk, llen);
									*pklen = llen;

									fpos = (size_t)qsc_stringutils_find_string(fbuf, SKYTAG) + sizeof(SKYTAG) - 1;

									if (fpos > 0)
									{
										fbuf += fpos;
										llen = (size_t)qsc_stringutils_find_string(fbuf, "\n") / 2;

										if (llen > 0)
										{
											qsc_intutils_hex_to_bin(fbuf, sk, llen);
											*sklen = llen;

											fpos = (size_t)qsc_stringutils_find_string(fbuf, SMGTAG) + sizeof(SMGTAG) - 1;

											if (fpos > 0)
											{
												fbuf += fpos;
												llen = (size_t)qsc_stringutils_find_string(fbuf, "\n") / 2;

												if (llen > 0)
												{
													qsc_intutils_hex_to_bin(fbuf, sm, llen);
													*smlen = llen;
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}

			free(pbuf);
		}
	}
}

void parse_nist_cipher_kat(const char* path, uint8_t* seed, size_t* seedlen, uint8_t* pk, size_t* pklen,
	uint8_t* sk, size_t* sklen, uint8_t* ct, size_t* ctlen, uint8_t* ss, size_t* sslen, uint32_t setnum)
{
	const char CNTTAG[] = "count = ";
	const char SEDTAG[] = "seed = ";
	const char PKYTAG[] = "pk = ";
	const char SKYTAG[] = "sk = ";
	const char CPRTAG[] = "ct = ";
	const char SSTTAG[] = "ss = ";
	char* pbuf;
	const char* fbuf;
	size_t flen;
	int64_t fpos;
	int64_t llen;
	size_t sctr;
	uint32_t setc;

	sctr = 0;

	if (qsc_fileutils_exists(path))
	{
		pbuf = file_to_string(path, &flen);

		if (pbuf != NULL)
		{
			fbuf = pbuf;

			while (true)
			{
				fpos = (size_t)qsc_stringutils_find_string(fbuf, CNTTAG) + sizeof(CNTTAG) - 1;

				if (fpos < 0)
				{
					break;
				}

				fbuf += fpos;
				setc = (uint32_t)qsc_stringutils_string_to_int(fbuf);

				if (setc == setnum || fpos == 0 || sctr > 100)
				{
					break;
				}

				++sctr;
			}

			fpos = (size_t)qsc_stringutils_find_string(fbuf, SEDTAG) + sizeof(SEDTAG) - 1;

			if (fpos > 0)
			{
				fbuf += fpos;
				llen = (size_t)qsc_stringutils_find_string(fbuf, "\n") / 2;

				if (llen > 0)
				{
					qsc_intutils_hex_to_bin(fbuf, seed, llen);
					*seedlen = llen;

					fpos = (size_t)qsc_stringutils_find_string(fbuf, PKYTAG) + sizeof(PKYTAG) - 1;

					if (fpos > 0)
					{
						fbuf += fpos;
						llen = (size_t)qsc_stringutils_find_string(fbuf, "\n") / 2;

						if (llen > 0)
						{
							qsc_intutils_hex_to_bin(fbuf, pk, llen);
							*pklen = llen;

							fpos = (size_t)qsc_stringutils_find_string(fbuf, SKYTAG) + sizeof(SKYTAG) - 1;

							if (fpos > 0)
							{
								fbuf += fpos;
								llen = (size_t)qsc_stringutils_find_string(fbuf, "\n") / 2;

								if (llen > 0)
								{
									qsc_intutils_hex_to_bin(fbuf, sk, llen);
									*sklen = llen;

									fpos = (size_t)qsc_stringutils_find_string(fbuf, CPRTAG) + sizeof(CPRTAG) - 1;

									if (fpos > 0)
									{
										fbuf += fpos;
										llen = (size_t)qsc_stringutils_find_string(fbuf, "\n") / 2;

										if (llen > 0)
										{
											qsc_intutils_hex_to_bin(fbuf, ct, llen);
											*ctlen = llen;

											fpos = (size_t)qsc_stringutils_find_string(fbuf, SSTTAG) + sizeof(SSTTAG) - 1;

											if (fpos > 0)
											{
												fbuf += fpos;
												llen = (size_t)qsc_stringutils_find_string(fbuf, "\n") / 2;

												if (llen > 0)
												{
													qsc_intutils_hex_to_bin(fbuf, ss, llen);
													*sslen = llen;
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}

			free(pbuf);
		}
	}
}
