
/* 2024 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains
 * the property of Quantum Resistant Cryptographic Solutions Incorporated.
 * The intellectual and technical concepts contained
 * herein are proprietary to Quantum Resistant Cryptographic Solutions Incorporated
 * and its suppliers and may be covered by U.S. and Foreign Patents,
 * patents in process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from Quantum Resistant Cryptographic Solutions Incorporated.
 *
 * Written by John G. Underhill
 * Contact: develop@qrcs.ca
 */

#ifndef QSCTEST_BENCHMARK_H
#define QSCTEST_BENCHMARK_H

#include "common.h"

/**
* \file symmetric_benchmark.h
* \brief Symmetric primitives performance benchmarking \n
* Tests hash functions, ciphers and modes for timing performance.
* \author John Underhill
* \date October 12, 2020
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
* \brief Tests the KPA MAC implementations performance.
* Tests the Keccak-based Parallel Authentication MACs for performance timing.
*/
void qsctest_benchmark_kpa_run(void);

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

#endif
