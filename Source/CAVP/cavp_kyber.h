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

#ifndef CAVP_KYBER_H
#define CAVP_KYBER_H

/**
 * \file cavp_kyber.h
 * \brief Kyber Test Functions.
 *
 * \details
 * This file contains tests for the NIST ML-KEM key encapsulation mechanism (KEM) implementation
 * as specified in the NIST FIPS 203 specification. The test suite includes:
 *
 * - A Known Answer Test (KAT) that verifies the generated public and private keys from the NIST ACVP vector set.
 * - A Known Answer Test (KAT) that verifies the encapsulation function from the NIST ACVP vector set.
 * Tests are run against the supported parameter set selected in the qsccommon.h file of the QSC library.
 *
 * \section kyber_test_links Reference Links
 * - <a href="https://csrc.nist.gov/pubs/fips/203/final">NIST Kyber FIPS 203 Main page</a>
 * - <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf">NIST Kyber FIPS 203 Specification</a>
 * - <a href="https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-encapDecap-FIPS203">The NIST ML-KEM encasulation KAT vector set</a>
 * - <a href="https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-keyGen-FIPS203">The NIST ML-KEM key generation KAT vector set</a>
 */

static const char* CAVP_MLKEM_ENCAP_512_KAT = "KAT/MLKEM/MLKEMEncap512.rsp";
static const char* CAVP_MLKEM_ENCAP_768_KAT = "KAT/MLKEM/MLKEMEncap768.rsp";
static const char* CAVP_MLKEM_ENCAP_1024_KAT = "KAT/MLKEM/MLKEMEncap1024.rsp";
static const char* CAVP_MLKEM_KEYGEN_512_KAT = "KAT/MLKEM/MLKEMKeyGen512.rsp";
static const char* CAVP_MLKEM_KEYGEN_768_KAT = "KAT/MLKEM/MLKEMKeyGen768.rsp";
static const char* CAVP_MLKEM_KEYGEN_1024_KAT = "KAT/MLKEM/MLKEMKeyGen1024.rsp";

/**
 * \brief Runs the ML-KEM (Kyber) ACVP test suite.
 *
 * \details
 * This function sequentially executes all supported ML-KEM ACVP tests, including:
 * - Public and private key generation Known Answer Tests (KATs)
 * - Thhe encapsulation function Known Answer Tests (KATs)
 *
 * The function prints the result of each test to the console.
 */
void cavp_kyber_run(void);

#endif