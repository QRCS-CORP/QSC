/**
* \file symmetric_benchmark.h
* \brief Symmetric primitives performance benchmarking \n
* Tests hash functions, ciphers and modes for timing performance.
* \author John Underhill
* \date October 12, 2020
*/

#ifndef QSCTEST_BENCHMARK_H
#define QSCTEST_BENCHMARK_H

#include "common.h"

/**
* \brief Tests the RHX implementations performance.
* Tests the AEX; CBC, CTR, and HBA modes for performance timing.
*/
void qsctest_benchmark_aes_run(void);

/**
* \brief Tests the RHX implementations performance.
* Tests the RHX; CBC, CTR, and HBA modes for performance timing.
*/
void qsctest_benchmark_rhx_run(void);

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
