#include "cavp_kyber.h"
#include "cavp_utils.h"
#include "arrayutils.h"
#include "fileutils.h"
#include "intutils.h"
#include "kyber.h"
#include "memutils.h"

#define KYBER_CTEXT_MAX 2048
#define KYBER_MESSAGE_INT_SIZE 8
#define KYBER_PUBKEY_MAX 2048
#define KYBER_PRIKEY_MAX 4096
#define KYBER_SECRET_SIZE 32
#define KYBER_SEED_SIZE 32
#define KYBER_TEST_COUNT 25

static const char* CAVP_KYBER_CTEXT = "Ciphertext = ";
static const char* CAVP_KYBER_COUNT = "Count = ";
static const char* CAVP_KYBER_PUBKEY = "Pubkey = ";
static const char* CAVP_KYBER_PRIKEY = "Prikey = ";
static const char* CAVP_KYBER_SECRET = "Secret = ";
static const char* CAVP_KYBER_SEEDD = "SeedD = ";
static const char* CAVP_KYBER_SEEDM = "SeedM = ";
static const char* CAVP_KYBER_SEEDZ = "SeedZ = ";

static bool kyber_encap_kat(const char* filepath)
{
	FILE* fp;
	char* line;
	uint8_t cpt[QSC_KYBER_CIPHERTEXT_SIZE] = { 0 };
	uint8_t excpt[QSC_KYBER_CIPHERTEXT_SIZE] = { 0 };
	uint8_t pubk[QSC_KYBER_PUBLICKEY_SIZE] = { 0 };
	uint8_t prik[QSC_KYBER_PRIVATEKEY_SIZE] = { 0 };
	uint8_t sec[KYBER_SECRET_SIZE] = { 0 };
	uint8_t exsec[KYBER_SECRET_SIZE] = { 0 };
	uint8_t seedm[KYBER_SEED_SIZE] = { 0 };
	char* sln;
	int64_t read;
	size_t rlen;
	int32_t tcnt;
	errno_t err;
	bool res;
	size_t ctr = 0;
	res = true;
	line = NULL;
	err = 0;
	rlen = 0;

    fp = qsc_fileutils_open(filepath, qsc_fileutils_mode_read, false);

	if (fp != NULL && err == 0)
	{
		read = 0;
		
		while (read != -1)
		{
			read = qsc_fileutils_get_line(&line, &rlen, fp);

			if (read > 0 && line != NULL)
			{
				if (memcmp(line, CAVP_KYBER_COUNT, strlen(CAVP_KYBER_COUNT)) == 0)
				{
					sln = line + strlen(CAVP_KYBER_COUNT);
					tcnt = qsc_arrayutils_string_to_uint32(sln, rlen - (strlen(CAVP_KYBER_COUNT) + 1));

					if (tcnt > 0 && tcnt <= KYBER_TEST_COUNT)
					{
						for (size_t i = 0; i < 5; ++i)
						{
							read = qsc_fileutils_get_line(&line, &rlen, fp);

							if (memcmp(line, CAVP_KYBER_PUBKEY, strlen(CAVP_KYBER_PUBKEY)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_KYBER_PUBKEY), pubk, QSC_KYBER_PUBLICKEY_SIZE);
							}
							else if (memcmp(line, CAVP_KYBER_PRIKEY, strlen(CAVP_KYBER_PRIKEY)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_KYBER_PRIKEY), prik, QSC_KYBER_PRIVATEKEY_SIZE);
							}
							else if (memcmp(line, CAVP_KYBER_CTEXT, strlen(CAVP_KYBER_CTEXT)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_KYBER_CTEXT), excpt, QSC_KYBER_CIPHERTEXT_SIZE);
							}
							else if (memcmp(line, CAVP_KYBER_SECRET, strlen(CAVP_KYBER_SECRET)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_KYBER_SECRET), exsec, KYBER_SECRET_SIZE);
							}
							else if (memcmp(line, CAVP_KYBER_SEEDM, strlen(CAVP_KYBER_SEEDM)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_KYBER_SEEDM), seedm, KYBER_SEED_SIZE);
							}
							else
							{
								res = false;
								break;
							}
						}
						
						qsc_kyber_seeded_encapsulate(sec, cpt, pubk, seedm);

						if (cavp_byte_arrays_are_equal8(cpt, excpt, sizeof(excpt)) == false)
						{
							res = false;
							break;
						}

						if (cavp_byte_arrays_are_equal8(sec, exsec, sizeof(exsec)) == false)
						{
							res = false;
							break;
						}

						qsc_memutils_clear(cpt, sizeof(cpt));
						qsc_memutils_clear(excpt, sizeof(excpt));
						qsc_memutils_clear(pubk, sizeof(pubk));
						qsc_memutils_clear(prik, sizeof(prik));
						qsc_memutils_clear(sec, sizeof(sec));
						qsc_memutils_clear(exsec, sizeof(exsec));
						qsc_memutils_clear(seedm, sizeof(seedm));
					}
					else
					{
						res = false;
						break;
					}
				}
			}
		}
	}
	else
	{
		res = false;
	}

	qsc_fileutils_close(fp);

	if (line != NULL)
	{
		free(line);
	}

	return res;
}

static bool kyber_keygen_kat(const char* filepath)
{
	FILE* fp;
	char* line;
	uint8_t expubk[QSC_KYBER_PUBLICKEY_SIZE] = { 0 };
	uint8_t exprik[QSC_KYBER_PRIVATEKEY_SIZE] = { 0 };
	uint8_t pubk[QSC_KYBER_PUBLICKEY_SIZE] = { 0 };
	uint8_t prik[QSC_KYBER_PRIVATEKEY_SIZE] = { 0 };
	uint8_t sd[KYBER_SEED_SIZE] = { 0 };
	uint8_t sec[KYBER_SECRET_SIZE] = { 0 };
	uint8_t sz[KYBER_SEED_SIZE] = { 0 };
	char* sln;
	int64_t read;
	size_t rlen;
	size_t pklen;
	size_t sklen;
	int32_t tcnt;
	errno_t err;
	bool res;
	size_t ctr = 0;
	res = true;
	line = NULL;
	err = 0;
	rlen = 0;

    fp = qsc_fileutils_open(filepath, qsc_fileutils_mode_read, false);

	if (fp != NULL && err == 0)
	{
		read = 0;
		
		while (read != -1)
		{
			read = qsc_fileutils_get_line(&line, &rlen, fp);

			if (read > 0 && line != NULL)
			{
				if (memcmp(line, CAVP_KYBER_COUNT, strlen(CAVP_KYBER_COUNT)) == 0)
				{
					sln = line + strlen(CAVP_KYBER_COUNT);
					tcnt = qsc_arrayutils_string_to_uint32(sln, rlen - (strlen(CAVP_KYBER_COUNT) + 1));

					if (tcnt > 0 && tcnt <= KYBER_TEST_COUNT)
					{
						for (size_t i = 0; i < 4; ++i)
						{
							read = qsc_fileutils_get_line(&line, &rlen, fp);

							if (memcmp(line, CAVP_KYBER_SEEDZ, strlen(CAVP_KYBER_SEEDZ)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_KYBER_SEEDZ), sz, KYBER_SEED_SIZE);
							}
							else if (memcmp(line, CAVP_KYBER_SEEDD, strlen(CAVP_KYBER_SEEDD)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_KYBER_SEEDD), sd, KYBER_SEED_SIZE);
							}
							else if (memcmp(line, CAVP_KYBER_PUBKEY, strlen(CAVP_KYBER_PUBKEY)) == 0)
							{
								pklen = ((size_t)read - (strlen(CAVP_KYBER_PUBKEY) + 1)) / 2;
								cavp_hex_to_bin(line + strlen(CAVP_KYBER_PUBKEY), expubk, pklen);
							}
							else if (memcmp(line, CAVP_KYBER_PRIKEY, strlen(CAVP_KYBER_PRIKEY)) == 0)
							{
								sklen = ((size_t)read - (strlen(CAVP_KYBER_PRIKEY) + 1)) / 2;
								cavp_hex_to_bin(line + strlen(CAVP_KYBER_PRIKEY), exprik, sklen);
							}
							else
							{
								res = false;
								break;
							}
						}
						
						qsc_kyber_generate_seeded_keypair(pubk, prik, sd, sz);

						if (cavp_byte_arrays_are_equal8(pubk, expubk, sizeof(pubk)) == false)
						{
							res = false;
							break;
						}

						if (cavp_byte_arrays_are_equal8(prik, exprik, sizeof(prik)) == false)
						{
							res = false;
							break;
						}

						qsc_memutils_clear(expubk, sizeof(expubk));
						qsc_memutils_clear(pubk, sizeof(pubk));
						qsc_memutils_clear(exprik, sizeof(exprik));
						qsc_memutils_clear(prik, sizeof(prik));
						qsc_memutils_clear(sd, sizeof(sd));
						qsc_memutils_clear(sec, sizeof(sec));
						qsc_memutils_clear(sz, sizeof(sz));
					}
					else
					{
						res = false;
						break;
					}
				}
			}
		}
	}
	else
	{
		res = false;
	}

	qsc_fileutils_close(fp);

	if (line != NULL)
	{
		free(line);
	}

	return res;
}

static bool kyber_encap_kat_tests()
{
	bool res;

	if (qsc_fileutils_exists(CAVP_MLKEM_ENCAP_512_KAT) && qsc_fileutils_exists(CAVP_MLKEM_ENCAP_768_KAT) && qsc_fileutils_exists(CAVP_MLKEM_ENCAP_1024_KAT))
	{
		res = true;

#if defined(QSC_KYBER_S1K2P512)
		if (kyber_encap_kat(CAVP_MLKEM_ENCAP_512_KAT))
		{
			cavp_print_line("Kyber passed the 512 parameters encapsulation KAT test.");
		}
		else
		{
			cavp_print_line("Kyber failed the 512 parameters encapsulation KAT test.");
			res = false;
		}
#elif defined(QSC_KYBER_S3K3P768)
		if (kyber_encap_kat(CAVP_MLKEM_ENCAP_768_KAT))
		{
			cavp_print_line("Kyber passed the 768 parameters encapsulation KAT test.");
		}
		else
		{
			cavp_print_line("Kyber failed the 768 parameters encapsulation KAT test.");
			res = false;
		}
#elif defined(QSC_KYBER_S5K4P1024)
		if (kyber_encap_kat(CAVP_MLKEM_ENCAP_1024_KAT))
		{
			cavp_print_line("Kyber passed the 1024 parameters encapsulation KAT test.");
		}
		else
		{
			cavp_print_line("Kyber failed the 1024 parameters encapsulation KAT test.");
			res = false;
		}
#else
		cavp_print_line("Kyber the parameter set is not supported.");
#endif
	}
	else
	{
		res = false;
	}

	return res;
}

static bool kyber_keygen_kat_tests()
{
	bool res;

	if (qsc_fileutils_exists(CAVP_MLKEM_KEYGEN_512_KAT) && qsc_fileutils_exists(CAVP_MLKEM_KEYGEN_768_KAT) && qsc_fileutils_exists(CAVP_MLKEM_KEYGEN_1024_KAT))
	{
		res = true;

#if defined(QSC_KYBER_S1K2P512)
		if (kyber_keygen_kat(CAVP_MLKEM_KEYGEN_512_KAT))
		{
			cavp_print_line("Kyber passed the 512 parameters key generation KAT test.");
		}
		else
		{
			cavp_print_line("Kyber failed the 512 parameters key generation KAT test.");
			res = false;
		}
#elif defined(QSC_KYBER_S3K3P768)
		if (kyber_keygen_kat(CAVP_MLKEM_KEYGEN_768_KAT))
		{
			cavp_print_line("Kyber passed the 768 parameters key generation KAT test.");
		}
		else
		{
			cavp_print_line("Kyber failed the 768 parameters key generation KAT test.");
			res = false;
		}
#elif defined(QSC_KYBER_S5K4P1024)
		if (kyber_keygen_kat(CAVP_MLKEM_KEYGEN_1024_KAT))
		{
			cavp_print_line("Kyber passed the 1024 parameters key generation KAT test.");
		}
		else
		{
			cavp_print_line("Kyber failed the 1024 parameters key generation KAT test.");
			res = false;
		}
#else
		cavp_print_line("Kyber the parameter set is not supported.");
#endif
	}
	else
	{
		res = false;
	}

	return res;
}

void cavp_kyber_run()
{
	cavp_print_line("Running the NIST ACVP ML-KEM tests, testing known answers for the 512, 768, and 1024 parameter sets.");
	cavp_print_line("Tests Kyber key generation, encapsulation, and decapsulation using NIST ACVP known answer tests.");
	cavp_print_line("Runs tests on the parameter set selected in qsccommon.c in the QSC library.");
	cavp_print_line("Uses the ACVP vector set from the official NIST ML-KEM vector sets.");
	cavp_print_line("Seperate vector sets test the key generation and encapsulation functions against known answer sets.");
	cavp_print_line("");

	if (kyber_keygen_kat_tests())
	{
		cavp_print_line("Success! Passed the ACVP key generation KAT tests.");
	}
	else
	{
		cavp_print_line("Failure! Failed the ACVP key generation KAT tests.");
	}

	cavp_print_line("");
	
	if (kyber_encap_kat_tests())
	{
		cavp_print_line("Success! Passed the ACVP encapsulation KAT tests.");
	}
	else
	{
		cavp_print_line("Failure! Failed the ACVP encapsulation KAT tests.");
	}

}
