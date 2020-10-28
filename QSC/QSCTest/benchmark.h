/**
* \file symmetric_benchmark.h
* \brief <b>AES and RHX performance benchmarking</b> \n
* Tests the CBC, CTR, AND HBA modes for timimng performance.
* \author John Underhill
* \date October 12, 2020
*/

#ifndef QSCTEST_CIPHER_SPEED_H
#define QSCTEST_CIPHER_SPEED_H

#include "common.h"

/**
* \brief Tests the RHX implementations performance.
* Tests the AEX; CBC, CTR, and HBA modes for performance timing.
*/
void qsctest_aes_speed_run();

/**
* \brief Tests the RHX implementations performance.
* Tests the RHX; CBC, CTR, and HBA modes for performance timing.
*/
void qsctest_rhx_speed_run();

/**
* \brief Tests the ChaCha implementations performance.
* Tests the ChaCha stream cipher for performance timing.
*/
void qsctest_chacha_speed_run();

/**
* \brief Tests the CSX implementations performance.
* Tests the CSX stream cipher for performance timing.
*/
void qsctest_csx_speed_run();

/**
* \brief Tests the KPA MAC implementations performance.
* Tests the Keccak-based Parallel Authentication MACs for performance timing.
*/
void qsctest_kpa_speed_run();

/**
* \brief Tests the RCS implementations performance.
* Tests the RCS authenticated stream cipher for performance timing.
*/
void qsctest_rcs_speed_run();

#endif