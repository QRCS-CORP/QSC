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

#ifndef QSCTEST_BENCHMARK_H
#define QSCTEST_BENCHMARK_H

#include "qsctestcommon.h"

/**
* \file benchmark.h
* \brief Symmetric primitives performance benchmarking.
* \details Tests hash functions, ciphers and modes for timing performance.
*
* \section symmetric_benchmark_links Reference Links
* - <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf">AES Specification NIST FIPS 197</a>
* - <a href="https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf">CBC and CTR Mode (NIST SP 800-38A)</a>
* - <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">SHA3 Implementation NIST FIPS 202</a>
*/

/**
* \brief Tests the RHX implementations performance.
* Tests the AEX; qsc_aes_mode_cbc, qsc_aes_mode_ctr, and HBA modes for performance timing.
*/
void qsctest_benchmark_aes_run(void);

/**
* \brief Tests the ChaCha implementations performance.
* Tests the ChaCha stream cipher for performance timing.
*/
void qsctest_benchmark_chacha_run(void);

/**
* \brief Tests the CSX implementations performance.
* Tests the CSX stream cipher for performance timing.
*/
void qsctest_benchmark_csx_run(void);

/**
* \brief Tests the KMAC implementations performance.
* Tests the Keccak MACs for performance timing.
*/
void qsctest_benchmark_kmac_run(void);

/**
* \brief Tests the RCS implementations performance.
* Tests the RCS authenticated stream cipher for performance timing.
*/
void qsctest_benchmark_rcs_run(void);

/**
* \brief Tests the SHAKE implementations performance.
* Tests the various SHAKE implementations for performance timing.
*/
void qsctest_benchmark_shake_run(void);

/* QMAC removed for further development */
///**
//* \brief Tests the QMAC implementations performance.
//* Tests the QMAC implementations for performance timing.
//*/
//void qsctest_benchmark_qmac_run(void);

#endif
