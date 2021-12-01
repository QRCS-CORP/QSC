#include "../QSC/common.h"
#include "../QSC/consoleutils.h"
#include "../QSC/cpuidex.h"
#include "../QSC/memutils.h"
#include "../QSC/selftest.h"
#include "../QSC/stringutils.h"
#if defined(QSC_DEBUG_MODE)
#	include "../QSC/acp.h"
#	include "../QSC/csp.h"
#	include "../QSC/rdp.h"
#	include "../QSC/sysutils.h"
#	include "../QSC/timerex.h"
#	include "../QSC/timestamp.h"
#endif
#include "aes_test.h"
#include "aesavs_test.h"
#include "async_test.h"
#include "benchmark.h"
#include "chacha_test.h"
#include "common.h"
#include "csx_test.h"
#include "dilithium_test.h"
#include "ecdh_test.h"
#include "ecdsa_test.h"
#include "falcon_test.h"
#include "kyber_test.h"
#include "mceliece_test.h"
#include "netutils_test.h"
#include "ntru_test.h"
#include "poly1305_test.h"
#include "rcs_test.h"
#include "secrand_test.h"
#include "sha2_test.h"
#include "sha3_test.h"
#include "sphincsplus_test.h"
#include "testutils.h"

static void print_title(void)
{
	qsctest_print_line("***************************************************");
	qsctest_print_line("* QSC: Quantum Secure Cryptographic library in C  *");
	qsctest_print_line("*                                                 *");
	qsctest_print_line("* Release:   v1.0.0.5l (A5)                       *");
	qsctest_print_line("* License:   GPLv3                                *");
	qsctest_print_line("* Date:      November 31, 2021                    *");
	qsctest_print_line("* Contact:   support@digitalfreedomdefence.com    *");
	qsctest_print_line("***************************************************");
	qsctest_print_line("");
}

#if defined(QSC_DEBUG_MODE)
static void random_sample_print()
{
	uint8_t smp[256] = { 0 };

	qsc_consoleutils_print_line("Random verification test");
	qsc_consoleutils_print_line("Printing random from installed generators..");

	qsc_consoleutils_print_line("CSP sample: ");
	qsc_csp_generate(smp, sizeof(smp));
	qsc_consoleutils_print_array(smp, sizeof(smp), 64);
	qsc_memutils_clear(smp, sizeof(smp));
	qsc_consoleutils_print_line("");

#if defined(QSC_RDRAND_COMPATIBLE)
	qsc_consoleutils_print_line("RDP sample: ");
	qsc_rdp_generate(smp, sizeof(smp));
	qsc_consoleutils_print_array(smp, sizeof(smp), 64);
	qsc_memutils_clear(smp, sizeof(smp));
	qsc_consoleutils_print_line("");
#endif

	qsc_consoleutils_print_line("ACP sample: ");
	qsc_acp_generate(smp, sizeof(smp));
	qsc_consoleutils_print_array(smp, sizeof(smp), 64);
	qsc_memutils_clear(smp, sizeof(smp));
	qsc_consoleutils_print_line("");
	qsc_consoleutils_print_line("");
}
#endif

int main(void)
{
	qsc_cpuidex_cpu_features cfeat;
	bool valid;
	bool hfeat;

#if defined(QSC_DEBUG_MODE)
	qsc_consoleutils_print_line("Loading visual pre-check...");
	qsc_consoleutils_print_line("");
	random_sample_print();
	qsc_system_values_print();
	qsc_timerex_print_values();
	qsc_timestamp_print_values();
	qsc_consoleutils_print_line("");
#endif

	valid = qsc_selftest_symmetric_run();

	if (valid == true)
	{
		print_title();

		qsctest_print_line("Passed the internal symmetric primitive self-checks.");

		hfeat = qsc_cpuidex_features_set(&cfeat);

		if (hfeat == false)
		{
			qsctest_print_line("The CPU type was not recognized on this system!");
			qsctest_print_line("Some features may be disabled.");
		}

		if (cfeat.aesni == true)
		{
			qsctest_print_line("AES-NI is available on this system.");
			qsctest_print_line("The QSC_SYSTEM_AESNI_ENABLED flag has been detected, AES-NI intrinsics are enabled.");
		}
		else
		{
			qsctest_print_line("AES-NI was not detected on this system.");
		}

		if (cfeat.avx512f == true)
		{
			qsctest_print_line("AVX-512 intrinsics functions have been detected on this system.");
		}
		else if (cfeat.avx2 == true)
		{
			qsctest_print_line("AVX2 intrinsics functions have been detected on this system.");
		}
		else if (cfeat.avx == true)
		{
			qsctest_print_line("AVX intrinsics functions have been detected on this system.");
		}
		else
		{
			qsctest_print_line("The AVX intrinsics functions have not been detected or are not enabled.");
			qsctest_print_line("For best performance, enable the maximum available AVX feature set in the project properties (AVX/AVX2/AVX512).");
		}

#if defined(QSC_IS_X86)
		qsctest_print_line("The system is running in X86 mode; for best performance, compile as X64.");
#endif

#if defined(_DEBUG)
		qsctest_print_line("The system is running in Debug mode; for best performance, compile as Release.");
#endif
#if defined(QSC_CSX_AUTHENTICATED)
		qsctest_print_line("The CSX authentication flag was detected.");
		qsctest_print_line("Remove the QSC_CSX_AUTHENTICATED definition from the preprocessor definitions in csx.h to disable CSX authentication.");
#else
		qsctest_print_line("The CSX authentication flag was not detected.");
		qsctest_print_line("Add the QSC_CSX_AUTHENTICATED definition to preprocessor flags to enable the CSX cipher authentication extension.");
#endif

#if defined(QSC_RCS_AUTHENTICATED)
		qsctest_print_line("The RCS authentication flag was detected.");
		qsctest_print_line("Remove the QSC_RCS_AUTHENTICATED definition from the preprocessor definitions in rcs.h to disable RCS authentication.");
#else
		qsctest_print_line("The RCS authentication flag was not detected.");
		qsctest_print_line("Add the QSC_RCS_AUTHENTICATED definition to preprocessor flags to enable the RCS cipher authentication extension.");
#endif

		qsctest_print_line("");
		qsctest_print_line("AVX-512 intrinsics have been fully integrated into this project.");
		qsctest_print_line("On an AVX-512 capable CPU, enable AVX-512 in the project properties for best performance.");
		qsctest_print_line("Enable the maximum available AVX feature set in the project properties (AVX/AVX2/AVX512).");
		qsctest_print_line("");
	}
	else
	{
		qsctest_print_line("Failure! Internal self-checks have errored, aborting tests!");
		valid = false;
	}

	if (valid == true)
	{
		if (qsctest_test_confirm("Press 'Y' then Enter to run Diagnostic Tests, any other key to cancel: ") == true)
		{
			qsctest_print_line("*** Test the AES cipher and modes with stress tests, and the FIPS known answer tests ***");
			qsctest_aes_run();
			qsctest_print_line("");

			qsctest_print_line("*** Test the AES cipher and modes with stress tests, and the AESAVS known answer tests ***");
			qsctest_aesavs_run();
			qsctest_print_line("");

			qsctest_print_line("*** Test the ChaCha stream cipher with stress tests, and known answer tests ***");
			qsctest_chacha_run();
			qsctest_print_line("");

			qsctest_print_line("*** Test the CSX-512 stream cipher stress tests, and known answer tests ***");
			qsctest_csx_run();
			qsctest_print_line("");

			qsctest_print_line("*** Test the RCS stream cipher with stress tests, and known answer tests ***");
			qsctest_rcs_run();
			qsctest_print_line("");

			qsctest_print_line("*** Test the Poly1305 MAC generator with known answer tests ***");
			qsctest_poly1305_run();
			qsctest_print_line("");

			qsctest_print_line("*** Test HKDF, HMAC, and SHA2 implementations using the official known answer tests ***");
			qsctest_sha2_run();
			qsctest_print_line("");

			qsctest_print_line("*** Test SHAKE, cSHAKE, KMAC, and SHA3 implementations using the official known answer tests ***");
			qsctest_sha3_run();
			qsctest_print_line("");

			qsctest_print_line("*** Test the Secure Random provider and entropy provider implementations ***");
			qsctest_secrand_run();
			qsctest_print_line("");

			qsctest_print_line("*** Test the ECDH implementation using stress, validity checks, and known answer tests ***");
			qsctest_ecdh_run();
			qsctest_print_line("");

			qsctest_print_line("*** Test the Kyber implementation using stress, validity checks, and known answer tests ***");
			qsctest_kyber_run();
			qsctest_print_line("");

			qsctest_print_line("*** Test the McEliece implementation using stress, validity checks, and known answer tests ***");
			qsctest_mceliece_run();
			qsctest_print_line("");

			qsctest_print_line("*** Test the NTRU implementation using stress, validity checks, and known answer tests ***");
			qsctest_ntru_run();
			qsctest_print_line("");

			qsctest_print_line("*** Test the Falcon implementation using stress, validity checks, and known answer tests ***");
			qsctest_falcon_run();
			qsctest_print_line("");

			qsctest_print_line("*** Test the Dilithium implementation using stress, validity checks, and known answer tests ***");
			qsctest_dilithium_run();
			qsctest_print_line("");

			qsctest_print_line("*** Test the ECDSA implementation using stress, validity checks, and known answer tests ***");
			qsctest_ecdsa_run();
			qsctest_print_line("");

			qsctest_print_line("*** Test the SPHINCS+ implementation using stress, validity checks, and known answer tests ***");
			qsctest_sphincsplus_run();
			qsctest_print_line("");
		}
		else
		{
			qsctest_print_line("");
		}

		if (qsctest_test_confirm("Press 'Y' then Enter to run Symmetric Speed Tests, any other key to cancel: ") == true)
		{
			qsctest_print_line("Testing symmetric stream ciphers..");
			qsctest_benchmark_chacha_run();
			qsctest_print_line("");
			qsctest_benchmark_csx_run();
			qsctest_print_line("");
			qsctest_benchmark_rcs_run();
			qsctest_print_line("");
			qsctest_print_line("Testing symmetric Keccak primitives..");
			qsctest_benchmark_kpa_run();
			qsctest_print_line("");
			qsctest_benchmark_kmac_run();
			qsctest_print_line("");
			qsctest_benchmark_shake_run();
			qsctest_print_line("");
		}

		qsctest_print_line("Completed! Press any key to close..");
		qsctest_get_wait();
	}
	else
	{
		qsctest_print_line("The test has been canceled. Press any key to close..");
		qsctest_get_wait();
	}

    return 0;
}
