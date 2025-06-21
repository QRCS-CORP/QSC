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


#ifndef CAVP_SPHINCSPLUS_H
#define CAVP_SPHINCSPLUS_H

/**
 * \file dilithium_test.h
 * \brief Dilithium Test Suite for the Digital Signature Scheme.
 *
 * \details
 * This header defines a set of tests for the ML-DSA (Dilithium) digital signature scheme implementation.
 * The test suite is designed to verify the correct operation of the ML-DSA scheme by performing the following:
 *
 * - **Known Answer Test (KAT)**:  
 *   Validates key pair generation, signing, and signature verification using expected test vectors from the
 *   NIST ACVP Dilithium FIPS 204 specification. It confirms that the generated public key, secret key, signature, and recovered
 *   message exactly match the expected values.
 *
 * The known answer test uses one of the NIST FIPS 204 ACVP test vector files, selected based on the active parameter set.
 *
 * \section dilithium_test_links Reference Links
 * - <a href="https://csrc.nist.gov/pubs/fips/204/final">NIST Dilithium FIPS 204 Main page</a>
 * - <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf">NIST Dilithium FIPS 204 Specification</a>
 * - <a href="https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/ML-DSA-keyGen-FIPS204/expectedResults.json">The ACVP key generation known answer tests</a>
 * - <a href="https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/ML-DSA-sigGen-FIPS204/expectedResults.json">The ACVP signature generation known answer tests</a>
 */

static const char* CAVP_SLHDSA_KEYGEN_SHAKE128_KAT = "KAT/SLHDSA/SLHDSASHAKE128KeyGen.rsp";
static const char* CAVP_SLHDSA_KEYGEN_SHAKE192_KAT = "KAT/SLHDSA/SLHDSASHAKE192KeyGen.rsp";
static const char* CAVP_SLHDSA_KEYGEN_SHAKE256_KAT = "KAT/SLHDSA/SLHDSASHAKE256KeyGen.rsp";
static const char* CAVP_SLHDSA_SIGGEN_SHAKE128_KAT = "KAT/SLHDSA/SLHDSASHAKE128SigGen.rsp";
static const char* CAVP_SLHDSA_SIGGEN_SHAKE192_KAT = "KAT/SLHDSA/SLHDSASHAKE192SigGen.rsp";
static const char* CAVP_SLHDSA_SIGGEN_SHAKE256_KAT = "KAT/SLHDSA/SLHDSASHAKE256SigGen.rsp";

/**
 * \brief Runs the ML-DSA (Dilithium) ACVP test suite.
 *
 * \details
 * -Tests the ACVP KAT against the key-pair generation
 * -Tests the ACVP KAT against the signature generation
 *
 * The function prints the result of each test to the console.
 */
void cavp_sphincsplus_run(void);

#endif
