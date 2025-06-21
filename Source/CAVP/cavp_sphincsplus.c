#include "cavp_sphincsplus.h"
#include "cavp_utils.h"
#include "arrayutils.h"
#include "fileutils.h"
#include "intutils.h"
#include "memutils.h"
#include "sphincsplus.h"

#define SPHINCSPLUS_CONTEXT_MAX 2048
#define SPHINCSPLUS_MESSAGE_MAX 8192
#define SPHINCSPLUS_TEST_KEYGEN_COUNT 100
#define SPHINCSPLUS_TEST_SIGGEN_COUNT 570

static const char* CAVP_SPHINCSPLUS_CONTEXT = "Context = ";
static const char* CAVP_SPHINCSPLUS_MESSAGE = "Message = ";
static const char* CAVP_SPHINCSPLUS_PUBKEY = "Pubkey = ";
static const char* CAVP_SPHINCSPLUS_PRIKEY = "Prikey = ";
static const char* CAVP_SPHINCSPLUS_SEED = "Seed = ";
static const char* CAVP_SPHINCSPLUS_SIGNATURE = "Signature = ";
static const char* CAVP_SPHINCSPLUS_TCID = "Tcid = ";

static bool sphincsplus_keygen_kat(const char* filepath)
{
	FILE* fp;
	char* line;
	char* sln;
	uint8_t pubk[QSC_SPHINCSPLUS_PUBLICKEY_SIZE] = { 0 };
	uint8_t pubkex[QSC_SPHINCSPLUS_PUBLICKEY_SIZE] = { 0 };
	uint8_t prik[QSC_SPHINCSPLUS_PRIVATEKEY_SIZE] = { 0 };
	uint8_t prikex[QSC_SPHINCSPLUS_PRIVATEKEY_SIZE] = { 0 };
	uint8_t seed[QSC_SPHINCSPLUS_GENERATE_SEED_SIZE] = { 0 };
	int64_t read;
	size_t rlen;
	size_t sdlen;
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
				if (memcmp(line, CAVP_SPHINCSPLUS_TCID, strlen(CAVP_SPHINCSPLUS_TCID)) == 0)
				{
					sln = line + strlen(CAVP_SPHINCSPLUS_TCID);
					tcnt = qsc_arrayutils_string_to_uint32(sln, rlen - (strlen(CAVP_SPHINCSPLUS_TCID) + 1));

					if (tcnt > 0 && tcnt <= SPHINCSPLUS_TEST_KEYGEN_COUNT)
					{
						for (size_t i = 0; i < 3; ++i)
						{
							read = qsc_fileutils_get_line(&line, &rlen, fp);

							if (memcmp(line, CAVP_SPHINCSPLUS_SEED, strlen(CAVP_SPHINCSPLUS_SEED)) == 0)
							{
								sdlen = ((size_t)read - (strlen(CAVP_SPHINCSPLUS_SEED) + 1)) / 2;
								cavp_hex_to_bin(line + strlen(CAVP_SPHINCSPLUS_SEED), seed, sdlen);
							}
							else if (memcmp(line, CAVP_SPHINCSPLUS_PUBKEY, strlen(CAVP_SPHINCSPLUS_PUBKEY)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_SPHINCSPLUS_PUBKEY), pubkex, QSC_SPHINCSPLUS_PUBLICKEY_SIZE);
							}
							else if (memcmp(line, CAVP_SPHINCSPLUS_PRIKEY, strlen(CAVP_SPHINCSPLUS_PRIKEY)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_SPHINCSPLUS_PRIKEY), prikex, QSC_SPHINCSPLUS_PRIVATEKEY_SIZE);
							}
							
							else
							{
								res = false;
								break;
							}
						}
						
						qsc_sphincsplus_generate_seeded_keypair(pubk, prik, seed);

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

static bool sphincsplus_siggen_kat(const char* filepath)
{
	FILE* fp;
	char* line;
	uint8_t context[SPHINCSPLUS_CONTEXT_MAX] = { 0 };
	uint8_t msg[SPHINCSPLUS_MESSAGE_MAX] = { 0 };
	uint8_t msgex[SPHINCSPLUS_MESSAGE_MAX] = { 0 };
	uint8_t pubk[QSC_SPHINCSPLUS_PUBLICKEY_SIZE] = { 0 };
	uint8_t prik[QSC_SPHINCSPLUS_PRIVATEKEY_SIZE] = { 0 };
	uint8_t seed[QSC_SPHINCSPLUS_SIGN_SEED_SIZE] = { 0 };
	uint8_t sig[QSC_SPHINCSPLUS_SIGNATURE_SIZE + SPHINCSPLUS_MESSAGE_MAX] = { 0 };
	uint8_t sigex[QSC_SPHINCSPLUS_SIGNATURE_SIZE + SPHINCSPLUS_MESSAGE_MAX] = { 0 };
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
				if (memcmp(line, CAVP_SPHINCSPLUS_TCID, strlen(CAVP_SPHINCSPLUS_TCID)) == 0)
				{
					sln = line + strlen(CAVP_SPHINCSPLUS_TCID);
					tcnt = qsc_arrayutils_string_to_uint32(sln, rlen - (strlen(CAVP_SPHINCSPLUS_TCID) + 1));

					if (tcnt > 0 && tcnt <= SPHINCSPLUS_TEST_SIGGEN_COUNT)
					{
						for (size_t i = 0; i < 6; ++i)
						{
							read = qsc_fileutils_get_line(&line, &rlen, fp);

							if (memcmp(line, CAVP_SPHINCSPLUS_PRIKEY, strlen(CAVP_SPHINCSPLUS_PRIKEY)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_SPHINCSPLUS_PRIKEY), prik, QSC_SPHINCSPLUS_PRIVATEKEY_SIZE);
							}
							else if (memcmp(line, CAVP_SPHINCSPLUS_PUBKEY, strlen(CAVP_SPHINCSPLUS_PUBKEY)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_SPHINCSPLUS_PUBKEY), pubk, QSC_SPHINCSPLUS_PUBLICKEY_SIZE);
							}
							else if (memcmp(line, CAVP_SPHINCSPLUS_SEED, strlen(CAVP_SPHINCSPLUS_SEED)) == 0)
							{
								cavp_hex_to_bin(line + strlen(CAVP_SPHINCSPLUS_SEED), seed, QSC_SPHINCSPLUS_SIGN_SEED_SIZE);
							}
							else if (memcmp(line, CAVP_SPHINCSPLUS_MESSAGE, strlen(CAVP_SPHINCSPLUS_MESSAGE)) == 0)
							{
								mlen = ((size_t)read - (strlen(CAVP_SPHINCSPLUS_MESSAGE) + 1)) / 2;
								cavp_hex_to_bin(line + strlen(CAVP_SPHINCSPLUS_MESSAGE), msgex, mlen);
							}
							else if (memcmp(line, CAVP_SPHINCSPLUS_CONTEXT, strlen(CAVP_SPHINCSPLUS_CONTEXT)) == 0)
							{
								clen = ((size_t)read - (strlen(CAVP_SPHINCSPLUS_CONTEXT) + 1)) / 2;
								cavp_hex_to_bin(line + strlen(CAVP_SPHINCSPLUS_CONTEXT), context, clen);
							}
							else if (memcmp(line, CAVP_SPHINCSPLUS_SIGNATURE, strlen(CAVP_SPHINCSPLUS_SIGNATURE)) == 0)
							{
								sglen = ((size_t)read - (strlen(CAVP_SPHINCSPLUS_SIGNATURE) + 1)) / 2;
								cavp_hex_to_bin(line + strlen(CAVP_SPHINCSPLUS_SIGNATURE), sigex, sglen);
							}
							else
							{
								res = false;
								break;
							}
						}
						
						qsc_sphincsplus_seeded_sign_ex(sig, &smsglen, msgex, mlen, context, clen, prik, seed);

						if (cavp_byte_arrays_are_equal8(sig, sigex, sglen) == false)
						{
							res = false;
							break;
						}

						if (qsc_sphincsplus_verify_ex(msg, &mlen, context, clen, sig, smsglen, pubk))
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

static bool sphincsplus_keygen_kat_tests()
{
	bool res;

	if (qsc_fileutils_exists(CAVP_SLHDSA_KEYGEN_SHAKE128_KAT) && qsc_fileutils_exists(CAVP_SLHDSA_KEYGEN_SHAKE192_KAT) && qsc_fileutils_exists(CAVP_SLHDSA_KEYGEN_SHAKE256_KAT))
	{
		res = true;

#if defined(QSC_SPHINCSPLUS_S1S128SHAKERS)
		if (sphincsplus_keygen_kat(CAVP_SLHDSA_KEYGEN_SHAKE128_KAT))
		{
			cavp_print_line("SPHINCS+ passed the SLH-DSA-SHAKE128 parameters key generation KAT test.");
		}
		else
		{
			cavp_print_line("SPHINCS+ failed the SLH-DSA-SHAKE128 parameters key generation KAT test.");
			res = false;
		}
#elif defined(QSC_SPHINCSPLUS_S3S192SHAKERS)
		if (sphincsplus_keygen_kat(CAVP_SLHDSA_KEYGEN_SHAKE192_KAT))
		{
			cavp_print_line("SPHINCS+ passed the SLH-DSA-SHAKE192 parameters key generation KAT test.");
		}
		else
		{
			cavp_print_line("SPHINCS+ failed the SLH-DSA-SHAKE192 parameters key generation KAT test.");
			res = false;
		}
#elif defined(QSC_SPHINCSPLUS_S5S256SHAKERS)
		if (sphincsplus_keygen_kat(CAVP_SLHDSA_KEYGEN_SHAKE256_KAT))
		{
			cavp_print_line("SPHINCS+ passed the SLH-DSA-SHAKE256 parameters key generation KAT test.");
		}
		else
		{
			cavp_print_line("SPHINCS+ failed the SLH-DSA-SHAKE256 parameters key generation KAT test.");
			res = false;
		}
#else
		cavp_print_line("SPHINCS+ the parameter set is not supported.");
#endif
	}
	else
	{
		res = false;
	}

	return res;
}

static bool sphincsplus_siggen_kat_tests()
{
	bool res;

	if (qsc_fileutils_exists(CAVP_SLHDSA_SIGGEN_SHAKE128_KAT) && qsc_fileutils_exists(CAVP_SLHDSA_SIGGEN_SHAKE192_KAT) && qsc_fileutils_exists(CAVP_SLHDSA_SIGGEN_SHAKE256_KAT))
	{
		res = true;

#if defined(QSC_SPHINCSPLUS_S1S128SHAKERS)
		if (sphincsplus_siggen_kat(CAVP_SLHDSA_SIGGEN_SHAKE128_KAT))
		{
			cavp_print_line("SPHINCS+ passed the SLH-DSA-SHAKE128 parameters signature generation KAT test.");
		}
		else
		{
			cavp_print_line("SPHINCS+ failed the SLH-DSA-SHAKE128 parameters signature generation KAT test.");
			res = false;
		}
#elif defined(QSC_SPHINCSPLUS_S3S192SHAKERS)
		if (sphincsplus_siggen_kat(CAVP_SLHDSA_SIGGEN_SHAKE192_KAT))
		{
			cavp_print_line("SPHINCS+ passed the SLH-DSA-SHAKE192 parameters signature generation KAT test.");
		}
		else
		{
			cavp_print_line("SPHINCS+ failed the SLH-DSA-SHAKE192 parameters signature generation KAT test.");
			res = false;
		}
#elif defined(QSC_SPHINCSPLUS_S5S256SHAKERS)
		if (sphincsplus_siggen_kat(CAVP_SLHDSA_SIGGEN_SHAKE256_KAT))
		{
			cavp_print_line("SPHINCS+ passed the SLH-DSA-SHAKE256 parameters signature generation KAT test.");
		}
		else
		{
			cavp_print_line("SPHINCS+ failed the SLH-DSA-SHAKE256 parameters signature generation KAT test.");
			res = false;
		}
#else
		cavp_print_line("SPHINCS+ the parameter set is not supported.");
#endif
	}
	else
	{
		res = false;
	}

	return res;
}

void cavp_sphincsplus_run()
{
	cavp_print_line("Running the NIST CAVP SLH-DSA tests, testing known answers for the SPHINCS+ SHAKE128, SHAKE192, and SHAKE256 parameter sets.");
	cavp_print_line("Tests SPHINCS+ key generation, signing, and signature verification using the NIST ACVP known answer tests.");
	cavp_print_line("Runs tests on the parameter set selected in qsccommon.c in the QSC library.");
	cavp_print_line("Uses the ACVP vector set from the official NIST SLH-DSA vector sets.");
	cavp_print_line("Seperate vector sets test the key generation and signature functions tested against known answer sets.");
	cavp_print_line("");

	if (sphincsplus_keygen_kat_tests())
	{
		cavp_print_line("Success! Passed the SLH-DSA ACVP key generation KAT tests.");
	}
	else
	{
		cavp_print_line("Failure! Failed the SLH-DSA ACVP key generation KAT tests.");
	}

	cavp_print_line("");

	if (sphincsplus_siggen_kat_tests())
	{
		cavp_print_line("Success! Passed the SLH-DSA ACVP signature generation KAT tests.");
	}
	else
	{
		cavp_print_line("Failure! Failed the SLH-DSA ACVP signature generation KAT tests.");
	}
}
