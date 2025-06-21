#include "cavp_dilithium.h"
#include "cavp_utils.h"
#include "arrayutils.h"
#include "dilithium.h"
#include "fileutils.h"
#include "intutils.h"
#include "memutils.h"

#define DILITHIUM_CONTEXT_MAX 2048
#define DILITHIUM_MESSAGE_MAX 8192
#define DILITHIUM_SEED_SIZE 32
#define DILITHIUM_TEST_COUNT 75

static const char* CAVP_DILITHIUM_CONTEXT = "Context = ";
static const char* CAVP_DILITHIUM_MESSAGE = "Message = ";
static const char* CAVP_DILITHIUM_PUBKEY = "Pubkey = ";
static const char* CAVP_DILITHIUM_PRIKEY = "Prikey = ";
static const char* CAVP_DILITHIUM_SEED = "Seed = ";
static const char* CAVP_DILITHIUM_SIGNATURE = "Signature = ";
static const char* CAVP_DILITHIUM_TCID = "Tcid = ";

static bool dilithium_keygen_kat(const char* filepath)
{
	FILE* fp;
	char* line;
	uint8_t pubk[QSC_DILITHIUM_PUBLICKEY_SIZE] = { 0 };
	uint8_t pubkex[QSC_DILITHIUM_PUBLICKEY_SIZE] = { 0 };
	uint8_t prik[QSC_DILITHIUM_PRIVATEKEY_SIZE] = { 0 };
	uint8_t prikex[QSC_DILITHIUM_PRIVATEKEY_SIZE] = { 0 };
	uint8_t seed[DILITHIUM_SEED_SIZE] = { 0 };
	char* sln;
	int64_t read;
	size_t pklen;
	size_t rlen;
	size_t sklen;
	int32_t tcnt;
	errno_t err;
	bool res;

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
				if (memcmp(line, CAVP_DILITHIUM_TCID, strlen(CAVP_DILITHIUM_TCID)) == 0)
				{
					sln = line + strlen(CAVP_DILITHIUM_TCID);
					tcnt = qsc_arrayutils_string_to_uint32(sln, rlen - (strlen(CAVP_DILITHIUM_TCID) + 1));

					if (tcnt > 0 && tcnt <= DILITHIUM_TEST_COUNT)
					{
						for (size_t i = 0; i < 3; ++i)
						{
							read = qsc_fileutils_get_line(&line, &rlen, fp);

							if (memcmp(line, CAVP_DILITHIUM_SEED, strlen(CAVP_DILITHIUM_SEED)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_DILITHIUM_SEED), seed, DILITHIUM_SEED_SIZE);
							}
							else if (memcmp(line, CAVP_DILITHIUM_PUBKEY, strlen(CAVP_DILITHIUM_PUBKEY)) == 0)
							{
								pklen = ((size_t)read - (strlen(CAVP_DILITHIUM_PUBKEY) + 1)) / 2;
								cavp_hex_to_bin(line + strlen(CAVP_DILITHIUM_PUBKEY), pubkex, pklen);
							}
							else if (memcmp(line, CAVP_DILITHIUM_PRIKEY, strlen(CAVP_DILITHIUM_PRIKEY)) == 0)
							{
								sklen = ((size_t)read - (strlen(CAVP_DILITHIUM_PRIKEY) + 1)) / 2;
								cavp_hex_to_bin(line + strlen(CAVP_DILITHIUM_PRIKEY), prikex, sklen);
							}
							
							else
							{
								res = false;
								break;
							}
						}
						
						qsc_dilithium_seeded_generate_keypair(pubk, prik, seed);

						if (cavp_byte_arrays_are_equal8(pubk, pubkex, sizeof(pubk)) == false)
						{
							res = false;
							break;
						}

						if (cavp_byte_arrays_are_equal8(prik, prikex, sizeof(prik)) == false)
						{
							res = false;
							break;
						}

						qsc_memutils_clear(pubkex, sizeof(pubkex));
						qsc_memutils_clear(prikex, sizeof(prikex));
						qsc_memutils_clear(pubk, sizeof(pubk));
						qsc_memutils_clear(prik, sizeof(prik));
						qsc_memutils_clear(seed, sizeof(seed));
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

static bool dilithium_siggen_kat(const char* filepath)
{
	FILE* fp;
	char* line;
	uint8_t context[DILITHIUM_CONTEXT_MAX] = { 0 };
	uint8_t msg[DILITHIUM_MESSAGE_MAX] = { 0 };
	uint8_t msgex[DILITHIUM_MESSAGE_MAX] = { 0 };
	uint8_t pubk[QSC_DILITHIUM_PUBLICKEY_SIZE] = { 0 };
	uint8_t prik[QSC_DILITHIUM_PRIVATEKEY_SIZE] = { 0 };
	uint8_t seed[DILITHIUM_SEED_SIZE] = { 0 };
	uint8_t sig[QSC_DILITHIUM_SIGNATURE_SIZE + DILITHIUM_MESSAGE_MAX] = { 0 };
	uint8_t sigex[QSC_DILITHIUM_SIGNATURE_SIZE + DILITHIUM_MESSAGE_MAX] = { 0 };
	char* sln;
	int64_t read;
	size_t clen;
	size_t mlen;
	size_t rlen;
	size_t sglen;
	size_t smsglen;
	int32_t tcnt;
	errno_t err;
	bool res;

	res = true;
	line = NULL;
	err = 0;
	clen = 0;
	mlen = 0;
	rlen = 0;
	sglen = 0;
	smsglen = 0;

    fp = qsc_fileutils_open(filepath, qsc_fileutils_mode_read, false);

	if (fp != NULL && err == 0)
	{
		read = 0;
		
		while (read != -1)
		{
			read = qsc_fileutils_get_line(&line, &rlen, fp);

			if (read > 0 && line != NULL)
			{
				if (memcmp(line, CAVP_DILITHIUM_TCID, strlen(CAVP_DILITHIUM_TCID)) == 0)
				{
					sln = line + strlen(CAVP_DILITHIUM_TCID);
					tcnt = qsc_arrayutils_string_to_uint32(sln, rlen - (strlen(CAVP_DILITHIUM_TCID) + 1));

					if (tcnt > 0 && tcnt <= DILITHIUM_TEST_COUNT)
					{
						for (size_t i = 0; i < 5; ++i)
						{
							read = qsc_fileutils_get_line(&line, &rlen, fp);

							if (memcmp(line, CAVP_DILITHIUM_MESSAGE, strlen(CAVP_DILITHIUM_MESSAGE)) == 0)
							{
								mlen = ((size_t)read - (strlen(CAVP_DILITHIUM_MESSAGE) + 1)) / 2;
								cavp_hex_to_bin(line + strlen(CAVP_DILITHIUM_MESSAGE), msgex, mlen);
							}
							else if (memcmp(line, CAVP_DILITHIUM_PUBKEY, strlen(CAVP_DILITHIUM_PUBKEY)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_DILITHIUM_PUBKEY), pubk, QSC_DILITHIUM_PUBLICKEY_SIZE);
							}
							else if (memcmp(line, CAVP_DILITHIUM_PRIKEY, strlen(CAVP_DILITHIUM_PRIKEY)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_DILITHIUM_PRIKEY), prik, QSC_DILITHIUM_PRIVATEKEY_SIZE);
							}
							else if (memcmp(line, CAVP_DILITHIUM_CONTEXT, strlen(CAVP_DILITHIUM_CONTEXT)) == 0)
							{
								clen = ((size_t)read - (strlen(CAVP_DILITHIUM_CONTEXT) + 1)) / 2;
								cavp_hex_to_bin(line + strlen(CAVP_DILITHIUM_CONTEXT), context, clen);
							}
							else if (memcmp(line, CAVP_DILITHIUM_SIGNATURE, strlen(CAVP_DILITHIUM_SIGNATURE)) == 0)
							{
								sglen = ((size_t)read - (strlen(CAVP_DILITHIUM_SIGNATURE) + 1)) / 2;
								cavp_hex_to_bin(line + strlen(CAVP_DILITHIUM_SIGNATURE), sigex, sglen);
							}
							else
							{
								res = false;
								break;
							}
						}
						
						qsc_dilithium_sign_ex(sig, &smsglen, msgex, mlen, context, clen, prik, NULL);

						if (cavp_byte_arrays_are_equal8(sig, sigex, sglen) == false)
						{
							res = false;
							break;
						}

						if (qsc_dilithium_verify_ex(msg, &mlen, context, clen, sig, smsglen, pubk))
						{
							if (cavp_byte_arrays_are_equal8(msg, msgex, mlen) == false)
							{
								res = false;
								break;
							}
						}
						else
						{
							res = false;
							break;
						}

						smsglen = 0;
						qsc_memutils_clear(context, sizeof(context));
						qsc_memutils_clear(msg, sizeof(msg));
						qsc_memutils_clear(msgex, sizeof(msgex));
						qsc_memutils_clear(pubk, sizeof(pubk));
						qsc_memutils_clear(prik, sizeof(prik));
						qsc_memutils_clear(sig, sizeof(sig));
						qsc_memutils_clear(sigex, sizeof(sigex));
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

static bool dilithium_keygen_kat_tests()
{
	bool res;

	if (qsc_fileutils_exists(CAVP_MLDSA_KEYGEN_44_KAT) && qsc_fileutils_exists(CAVP_MLDSA_KEYGEN_65_KAT) && qsc_fileutils_exists(CAVP_MLDSA_KEYGEN_87_KAT))
	{
		res = true;

#if defined(QSC_DILITHIUM_S1P44)
		if (dilithium_keygen_kat(CAVP_MLDSA_KEYGEN_44_KAT))
		{
			cavp_print_line("Dilithium passed the MLDSA-44 parameters key generation KAT test.");
		}
		else
		{
			cavp_print_line("Dilithium failed the MLDSA-44 parameters key generation KAT test.");
			res = false;
		}
#elif defined(QSC_DILITHIUM_S3P65)
		if (dilithium_keygen_kat(CAVP_MLDSA_KEYGEN_65_KAT))
		{
			cavp_print_line("Dilithium passed the MLDSA-65 parameters key generation KAT test.");
		}
		else
		{
			cavp_print_line("Dilithium failed the MLDSA-65 parameters key generation KAT test.");
			res = false;
		}
#elif defined(QSC_DILITHIUM_S5P87)
		if (dilithium_keygen_kat(CAVP_MLDSA_KEYGEN_87_KAT))
		{
			cavp_print_line("Dilithium passed the MLDSA-87 parameters key generation KAT test.");
		}
		else
		{
			cavp_print_line("Dilithium failed the MLDSA-87 parameters key generation KAT test.");
			res = false;
		}
#else
		cavp_print_line("Dilithium the parameter set is not supported.");
#endif
	}
	else
	{
		res = false;
	}

	return res;
}

static bool dilithium_siggen_kat_tests()
{
	bool res;

#if defined(QSC_DILITHIUM_RANDOMIZED_SIGNING)
	cavp_print_line("Dilithium has randomized signing enabled, known answer tests do not support randomized signatures.");
	cavp_print_line("Disable randomized signing in the QSC library dilithium.h header to enable the known answer tests.");
	res = false;
#else
	if (qsc_fileutils_exists(CAVP_MLDSA_SIGGEN_44_KAT) && qsc_fileutils_exists(CAVP_MLDSA_SIGGEN_65_KAT) && qsc_fileutils_exists(CAVP_MLDSA_SIGGEN_87_KAT))
	{
		res = true;

#if defined(QSC_DILITHIUM_S1P44)
		if (dilithium_siggen_kat(CAVP_MLDSA_SIGGEN_44_KAT))
		{
			cavp_print_line("Dilithium passed the MLDSA-44 parameters signature generation KAT test.");
		}
		else
		{
			cavp_print_line("Dilithium failed the MLDSA-44 parameters signature generation KAT test.");
			res = false;
		}
#elif defined(QSC_DILITHIUM_S3P65)
		if (dilithium_siggen_kat(CAVP_MLDSA_SIGGEN_65_KAT))
		{
			cavp_print_line("Dilithium passed the MLDSA-65 parameters signature generation KAT test.");
		}
		else
		{
			cavp_print_line("Dilithium failed the MLDSA-65 parameters signature generation KAT test.");
			res = false;
		}
#elif defined(QSC_DILITHIUM_S5P87)
		if (dilithium_siggen_kat(CAVP_MLDSA_SIGGEN_87_KAT))
		{
			cavp_print_line("Dilithium passed the MLDSA-87 parameters signature generation KAT test.");
		}
		else
		{
			cavp_print_line("Dilithium failed the MLDSA-87 parameters signature generation KAT test.");
			res = false;
		}
#else
		cavp_print_line("Dilithium the parameter set is not supported.");
#endif
	}
	else
	{
		res = false;
	}
#endif

	return res;
}

void cavp_dilithium_run()
{
	cavp_print_line("Running the NIST ACVP ML-DSA tests, testing known answers for the Dilithium 44, 65, and 87 parameter sets.");
	cavp_print_line("Tests Dilithium key generation, signing, and signature verification using the NIST ACVP known answer tests.");
	cavp_print_line("Runs tests on the parameter set selected in qsccommon.c in the QSC library.");
	cavp_print_line("Uses the ACVP vector set from the official NIST ML-DSA vector sets.");
	cavp_print_line("Seperate vector sets test the key generation and signature functions tested against known answer sets.");
	cavp_print_line("");

	if (dilithium_keygen_kat_tests())
	{
		cavp_print_line("Success! Passed the ML-DSA ACVP key generation KAT tests.");
	}
	else
	{
		cavp_print_line("Failure! Failed the ML-DSA ACVP key generation KAT tests.");
	}

	cavp_print_line("");

	if (dilithium_siggen_kat_tests())
	{
		cavp_print_line("Success! Passed the ML-DSA ACVP signature generation KAT tests.");
	}
	else
	{
		cavp_print_line("Failure! Failed the ML-DSA ACVP signature generation KAT tests.");
	}
}

