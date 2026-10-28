/* 2025 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: This software and all accompanying materials are the exclusive 
 * property of Quantum Resistant Cryptographic Solutions Corporation (QRCS).
 * The intellectual and technical concepts contained within this implementation 
 * are proprietary to QRCS and its authorized licensors and are protected under 
 * applicable U.S. and international copyright, patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC STANDARDS:
 * - This software includes implementations of cryptographic algorithms such as 
 *   SHA3, AES, and others. These algorithms are public domain or standardized 
 *   by organizations such as NIST and are NOT the property of QRCS.
 * - However, all source code, optimizations, and implementations in this library 
 *   are original works of QRCS and are protected under this license.
 *
 * RESTRICTIONS:
 * - Redistribution, modification, or unauthorized distribution of this software, 
 *   in whole or in part, is strictly prohibited.
 * - This software is provided for non-commercial, educational, and research 
 *   purposes only. Commercial use in any form is expressly forbidden.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 * - Any use of this software implies acceptance of these restrictions.
 *
 * DISCLAIMER:
 * This software is provided "as is," without warranty of any kind, express or 
 * implied, including but not limited to warranties of merchantability or fitness 
 * for a particular purpose. QRCS disclaims all liability for any direct, indirect, 
 * incidental, or consequential damages resulting from the use or misuse of this software.
 *
 * FULL LICENSE:
 * This software is subject to the **Quantum Resistant Cryptographic Solutions 
 * Proprietary License (QRCS-PL)**. The complete license terms are included 
 * in the LICENSE.txt file distributed with this software.
 *
 * Written by: John G. Underhill
 * Contact: john.underhill@protonmail.com
 */

#include "qsccommon.h"
#include "consoleutils.h"
#if defined(QSC_HAS_CPUID)
#	include "cpuidex.h"
#endif
#include "memutils.h"
#include "selftest.h"
#include "stringutils.h"
#if defined(QSC_DEBUG_MODE)
#	include "acp.h"
#	include "csp.h"
#	include "fileutils.h"
#	include "folderutils.h"
#	include "intutils.h"
#	include "netutils.h"
#	include "rdp.h"
#	include "sysutils.h"
#	include "timerex.h"
#	include "timestamp.h"
#endif
#include "aes_test.h"
#include "aesavs_test.h"
#include "async_test.h"
#include "benchmark.h"
#include "chacha_test.h"
#include "qsctestcommon.h"
#include "csx_test.h"
#include "dilithium_test.h"
#include "ecdh_test.h"
#include "ecdsa_test.h"
#include "eddh_test.h"
#include "eddsa_test.h"
#include "encoding_test.h"
#include "encoding_reference_test.h"
#include "falcon_test.h"
#include "hqc_test.h"
#include "kyber_test.h"
#include "mceliece_test.h"
#include "netutils_test.h"
#include "poly1305_test.h"
#include "pbmac1_test.h"
#include "qmac_test.h"
#include "rcs_test.h"
#include "scb_test.h"
#include "secrand_test.h"
#include "sha2_test.h"
#include "sha3_test.h"
#include "sphincsplus_test.h"
#include "testutils.h"
#include "tls_test.h"
#include "x509_test.h"

//#define QSCTEST_PRINT_STATS

static void print_title(void)
{
    qsctest_print_line("==============================================================================================================");
    qsctest_print_line(" QRCS | QSCTest");
    qsctest_print_line(" CRYPTOGRAPHIC QUALIFICATION AND PERFORMANCE SUITE");
    qsctest_print_line("--------------------------------------------------------------------------------------------------------------");
    qsctest_print_line(" Release : v1.2.0.0c (B3)  |  License : QRCS-PL");
    qsctest_print_line(" Date    : June 11, 2026");
    qsctest_print_line(" Contact : contact@qrcscorp.ca");
    qsctest_print_line("==============================================================================================================");
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
	qsc_consoleutils_print_array(smp, sizeof(smp), 64U);
	qsc_memutils_clear(smp, sizeof(smp));
	qsc_consoleutils_print_line("");

#if defined(QSC_RDRAND_COMPATIBLE)
	qsc_consoleutils_print_line("RDP sample: ");
	qsc_rdp_generate(smp, sizeof(smp));
	qsc_consoleutils_print_array(smp, sizeof(smp), 64U);
	qsc_memutils_clear(smp, sizeof(smp));
	qsc_consoleutils_print_line("");
#endif

	qsc_consoleutils_print_line("ACP sample: ");
	qsc_acp_generate(smp, sizeof(smp));
	qsc_consoleutils_print_array(smp, sizeof(smp), 64U);
	qsc_memutils_clear(smp, sizeof(smp));
	qsc_consoleutils_print_line("");
	qsc_consoleutils_print_line("");
}
#endif

static void primitives_test(void)
{
	qsctest_aes_run();
	qsctest_chacha_run();
	qsctest_csx_run();
	qsctest_rcs_run();

	qsctest_sha3_run();
	qsctest_sha3_run();

	qsctest_poly1305_run();
	qsctest_pbmac1_run();
	qsctest_qmac_run();

	qsctest_eddh_run();
	qsctest_kyber_run();
	qsctest_mceliece_run();

	qsctest_dilithium_run();
	qsctest_eddsa_run();
	qsctest_sphincsplus_run();
	
	qsctest_secrand_run();
	qsctest_scb_run();
}

int32_t main(void)
{
#if defined(QSC_HAS_CPUID)
	qsc_cpuidex_cpu_features cfeat;
	bool hfeat;
#endif
	bool valid;
	
#if defined(QSC_DEBUG_MODE) && defined(QSCTEST_PRINT_STATS)
	qsc_consoleutils_print_line("Loading pre-check...");
	qsc_folderutils_test();
	random_sample_print();
	qsc_netutils_values_print();
	qsc_consoleutils_print_line("");
	qsc_system_values_print();
	qsc_timerex_print_values();
	qsc_timestamp_print_values();
	qsc_consoleutils_print_line("");
#endif
	
	/* if it fails here, check your AVX settings. AVX2 is enabled in project defaults.
	 * If AVX is detected, AES-NI is automatically enabled, but some older CPUs may have AVX but not AES-NI.
	 * If the test CPU does not have the AES-NI instruction set, disable AES-NI in the libraries common.h file
	 * by remming the QSC_SYSTEM_AESNI_ENABLED macro.
	 */
	print_title();
    qsctest_print_section("00.01", "LIBRARY STARTUP SELF-TESTS");
    qsctest_print_line("[INFO] FIPS and internal known-answer checks follow.");
    /* QSC library-generated results retain their original direct output. */
    valid = qsc_selftest_symmetric_run();
    qsctest_print_line("");
	
	if (valid == true)
	{
		qsctest_print_line("[PASS] Library startup integrity checks");
        qsctest_print_section("00.02", "SYSTEM CONFIGURATION");

#if defined(QSC_HAS_CPUID)
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
			qsctest_print_line("For best performance, enable AVX/ARM feature set in the project properties (ARM/AVX/AVX2/AVX512).");
		}

#	if defined(QSC_CSX_REDUCED_ROUNDS)
		qsctest_print_line("The CSX reduced rounds mode has been enabled.");
#	endif
#	if defined(QSC_RCS_REDUCED_ROUNDS)
		qsctest_print_line("The RCS reduced rounds mode has been enabled.");
#	endif
#endif

#if defined(QSC_SYSTEM_ARCH_IX86_32)
		qsctest_print_line("The system is running in X86 mode; for best performance, compile as X64.");
#endif

#if defined(_DEBUG)
		qsctest_print_line("The system is running in Debug mode; for best performance, compile as Release.");
#endif

#if defined(QSC_CSX_AUTHENTICATED)
		qsctest_print_line("The CSX authentication flag was detected.");
		qsctest_print_line("Remove the QSC_CSX_AUTHENTICATED definition from csx.h to disable CSX authentication.");
#else
		qsctest_print_line("The CSX authentication flag was not detected.");
		qsctest_print_line("Add the QSC_CSX_AUTHENTICATED definition to preprocessor flags to enable the CSX cipher authentication.");
#endif

#if defined(QSC_RCS_AUTHENTICATED)
		qsctest_print_line("The RCS authentication flag was detected.");
		qsctest_print_line("Remove the QSC_RCS_AUTHENTICATED definition from rcs.h to disable RCS authentication.");
#else
		qsctest_print_line("The RCS authentication flag was not detected.");
		qsctest_print_line("Add the QSC_RCS_AUTHENTICATED definition to preprocessor flags to enable the RCS cipher authentication.");
#endif

		qsctest_print_line("");
		qsctest_print_line("AVX-512 intrinsics have been integrated into this project.");
		qsctest_print_line("On an AVX-512 capable CPU, enable AVX-512 in the project properties for best performance.");
		qsctest_print_line("Enable the maximum available AVX feature set in the project properties (AVX/AVX2/AVX512).");
		qsctest_print_line("");
	}
	else
	{
		qsctest_print_line("[FAIL] Library startup checks; diagnostics aborted.");
		valid = false;
	}

	if (valid == true)
	{
		if (qsctest_test_confirm("Run diagnostic qualification? [Y/N]: ") == true)
		{
			qsctest_print_section("01.01", "AES CIPHER / FIPS KAT");
			qsctest_aes_run();
			qsctest_print_line("");

			qsctest_print_section("01.02", "AES CIPHER / AESAVS");
			qsctest_aesavs_run();
			qsctest_print_line("");

			qsctest_print_section("01.03", "CHACHA CIPHER QUALIFICATION");
			qsctest_chacha_run();
			qsctest_print_line("");

			qsctest_print_section("01.04", "CSX-512 CIPHER QUALIFICATION");
			qsctest_csx_run();
			qsctest_print_line("");

			qsctest_print_section("01.05", "RCS CIPHER QUALIFICATION");
			qsctest_rcs_run();
			qsctest_print_line("");

			qsctest_print_section("02.01", "SHA-2 / HMAC / HKDF");
			qsctest_sha2_run();
			qsctest_print_line("");

			qsctest_print_section("02.02", "SHA-3 / SHAKE / cSHAKE / KMAC");
			qsctest_sha3_run();
			qsctest_print_line("");
						
			qsctest_print_section("02.03", "Poly1305 MAC");
			qsctest_poly1305_run();
			qsctest_print_line("");

			qsctest_print_section("02.04", "QMAC");
			qsctest_qmac_run();
			qsctest_print_line("");

			qsctest_print_section("02.05", "RANDOM GENERATOR AND ENTROPY TESTS");
			qsctest_secrand_run();
			qsctest_print_line("");

			qsctest_print_section("02.06", "SHAKE Cost-Based KDF");
			qsctest_scb_run();
			qsctest_print_line("");
			
			qsctest_print_section("03.01", "BER, DER, HEX, and PEM encoding schemes");
			qsctest_encoding_run();
			qsctest_print_line("");

			qsctest_print_section("03.02", "ENCODING REFERENCE VECTORS");
			if (qsctest_encoding_reference_run() == false)
			{
				valid = false;
				qsctest_print_line("[FAIL] Encoding reference-vector suite");
			}
			qsctest_print_line("");

			qsctest_print_section("05.01", "X.509 CERTIFICATE QUALIFICATION");
			qsctest_x509_run();
			qsctest_print_line("");

			qsctest_print_section("06.01", "TLS 1.3 PROTOCOL QUALIFICATION");
			qsctest_tls_run();
			qsctest_print_line("");

			qsctest_print_section("04.01", "Dilithium");
			qsctest_dilithium_run();
			qsctest_print_line("");

			qsctest_print_section("04.02", "NIST ECDSA");
			qsctest_ecdsa_run();
			qsctest_print_line("");

			qsctest_print_section("04.03", "EDDSA SIGNATURE QUALIFICATION");
			qsctest_eddsa_run();
			qsctest_print_line("");

			qsctest_print_section("04.04", "Falcon");
			qsctest_falcon_run();
			qsctest_print_line("");

			qsctest_print_section("04.05", "SPHINCS+");
			qsctest_sphincsplus_run();
			qsctest_print_line("");
			
			qsctest_print_section("04.06", "EDDH KEY AGREEMENT QUALIFICATION");
			qsctest_eddh_run();
			qsctest_print_line("");

			qsctest_print_section("04.07", "HQC");
			qsctest_hqc_run();
			qsctest_print_line("");

			qsctest_print_section("04.08", "Kyber");
			qsctest_kyber_run();
			qsctest_print_line("");

#if defined(QSC_MISRA_FULL_COMPLIANCE)
			qsctest_print_line("Warning: McEliece uses large static arrays internally, increase maximum stack allocation to 10-20MB.");
#endif
			qsctest_print_section("04.09", "McEliece");
			qsctest_mceliece_run();
			qsctest_print_line("");
		}
		else
		{
			qsctest_print_line("");
		}

		if (qsctest_test_confirm("Run performance benchmarks? [Y/N]: ") == true)
		{
#if !defined(QSC_SYSTEM_AVX_INTRINSICS)
			qsctest_print_line("System intrinsics have not been enabled, timings will be significantly slower!");
			qsctest_print_line("Enable the highest supported instruction set on the library and test project AVX/AVX2/AVX-512.");
#endif
			qsctest_print_section("07.01", "SYMMETRIC CIPHER PERFORMANCE");
			qsctest_benchmark_chacha_run();
			qsctest_print_line("");
			qsctest_benchmark_csx_run();
			qsctest_print_line("");
			qsctest_benchmark_aes_run();
			qsctest_print_line("");
			qsctest_benchmark_rcs_run();
			qsctest_print_line("");
			qsctest_print_section("07.02", "MAC AND HASH PERFORMANCE");
			qsctest_benchmark_qmac_run();
			qsctest_print_line("");
			qsctest_benchmark_kmac_run();
			qsctest_print_line("");
			qsctest_benchmark_shake_run();
			qsctest_print_line("");
		}

		qsctest_print_section("99.01", "EXECUTION COMPLETE");
        qsctest_print_line("[INFO] Review reported [FAIL] results above.");
        qsctest_print_line("Press any key to close.");
		qsctest_get_wait();
	}
	else
	{
		qsctest_print_line("The test has been canceled. Press any key to close..");
		qsctest_get_wait();
	}

    return (valid == true) ? 0 : 1;
}
