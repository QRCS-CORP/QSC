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
 * Contact: contact@qrcscorp.ca
 */

#include "qsccommon.h"
#include "consoleutils.h"
#if defined(QSC_HAS_CPUID)
#	include "cpuidex.h"
#endif
#include "cavp_aes.h"
#include "cavp_dilithium.h"
#include "cavp_kyber.h"
#include "cavp_utils.h"
#include "cavp_sha2.h"
#include "cavp_sha3.h"
#include "cavp_sphincsplus.h"

static void print_title(void)
{
	cavp_print_line("***************************************************");
	cavp_print_line("* QSC: CAVP Test Project                          *");
	cavp_print_line("*                                                 *");
	cavp_print_line("* Release:   v1.0.0.0 (A1)                        *");
	cavp_print_line("* License:   QRCS-PL                              *");
	cavp_print_line("* Date:      June 20, 2025                        *");
	cavp_print_line("* Contact:   contact@qrcscorp.ca                  *");
	cavp_print_line("***************************************************");
	cavp_print_line("");
}

int main()
{
	print_title();

	#if defined(QSC_HAS_CPUID)
	qsc_cpuidex_cpu_features cfeat;
	bool hfeat;

	hfeat = qsc_cpuidex_features_set(&cfeat);

	if (hfeat == false)
	{
		cavp_print_line("The CPU type was not recognized on this system!");
		cavp_print_line("Some features may be disabled.");
	}

	if (cfeat.aesni == true)
	{
		cavp_print_line("AES-NI is available on this system.");
		cavp_print_line("The QSC_SYSTEM_AESNI_ENABLED flag has been detected, AES-NI intrinsics are enabled.");
	}
	else
	{
		cavp_print_line("AES-NI was not detected on this system.");
	}

	if (cfeat.avx512f == true)
	{
		cavp_print_line("AVX-512 intrinsics functions have been detected on this system.");
	}
	else if (cfeat.avx2 == true)
	{
		cavp_print_line("AVX2 intrinsics functions have been detected on this system.");
	}
	else if (cfeat.avx == true)
	{
		cavp_print_line("AVX intrinsics functions have been detected on this system.");
	}
	else
	{
		cavp_print_line("The AVX intrinsics functions have not been detected or are not enabled.");
		cavp_print_line("For best performance, enable the maximum available AVX feature set in the project properties (AVX/AVX2/AVX512).");
	}
#endif

#if defined(QSC_SYSTEM_ARCH_IX86_32)
	cavp_print_line("The system is running in X86 mode; for best performance, compile as X64.");
#endif

#if defined(_DEBUG)
	cavp_print_line("The system is running in Debug mode; for best performance, compile as Release.");
#endif

	/* run the AES CAVP tests */
	cavp_print_line("");
    cavp_aes_run();
	cavp_print_line("");

	/* run the SHA2 CAVP tests */
	cavp_print_line("");
	cavp_sha2_run();
	cavp_print_line("");
	
	/* run the SHA3 CAVP tests */
	cavp_print_line("");
	cavp_sha3_run();
	cavp_print_line("");
		
	/* run the Kyber ACVP tests */
	cavp_print_line("");
	cavp_kyber_run();
	cavp_print_line("");

	/* run the Dilithium ACVP tests */
	cavp_print_line("");
	cavp_dilithium_run();
	cavp_print_line("");
	
	/* run the SPHINCS+ ACVP tests */
	cavp_print_line("");
	cavp_sphincsplus_run();
	cavp_print_line("");

	cavp_print_line("Completed! Press any key to close..");
	cavp_get_wait();
}

