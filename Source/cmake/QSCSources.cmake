#[=[
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
]=]

# Explicit source inventory from the QSC November 6 Visual Studio project.
set(QSC_ALL_SOURCES
    acp.c
    aes.c
    arrayutils.c
    asn1.c
    async.c
    chacha.c
    cjp.c
    collection.c
    consoleutils.c
    cpuidex.c
    csg.c
    csp.c
    csx.c
    dilithium.c
    dilithiumbase.c
    dilithiumbase_avx2.c
    donna128.c
    ecdh.c
    ecdhp256.c
    ecdhp384.c
    ecdhp521.c
    ecdsa.c
    ecdsap256.c
    ecdsap384.c
    ecdsap521.c
    ed25519.c
    ed448.c
    eddh.c
    eddh25519.c
    eddh448.c
    eddsa.c
    eddsa25519.c
    eddsa448.c
    encoding.c
    etr.c
    event.c
    falcon.c
    falconbase.c
    falconbase_avx2.c
    fileutils.c
    folderutils.c
    hcg.c
    hqc.c
    hqc1.c
    hqc3.c
    hqc5.c
    hqcbase.c
    hqcbase_avx2.c
    hwatecc.c
    hwncrypt.c
    hwncrypttls.c
    hwpkcs11tls.c
    hwplatform.c
    hwprovider.c
    hwpsa.c
    hwpsanative.c
    hwse050.c
    hwtpm.c
    hwtpmquote.c
    intutils.c
    ipinfo.c
    kyber.c
    kyber1024.c
    kyber1280.c
    kyber512.c
    kyber768.c
    kyberbase.c
    kyberbase_avx2.c
    list.c
    mceliece.c
    mceliece_460896.c
    mceliece_460896f.c
    mceliece_460896pc.c
    mceliece_460896pcf.c
    mceliece_6688128.c
    mceliece_6688128f.c
    mceliece_6688128pc.c
    mceliece_6688128pcf.c
    mceliece_6960119.c
    mceliece_6960119f.c
    mceliece_6960119pc.c
    mceliece_6960119pcf.c
    mceliece_8192128.c
    mceliece_8192128f.c
    mceliece_8192128pc.c
    mceliece_8192128pcf.c
    mceliecebase.c
    mceliecebase_avx2.c
    memutils.c
    mldsa44.c
    mldsa65.c
    mldsa87.c
    netutils.c
    oid.c
    p11agree.c
    p11keys.c
    p11loader.c
    p11session.c
    p11sign.c
    pbmac1.c
    poly1305.c
    qmac.c
    qsort.c
    queue.c
    rcs.c
    rdp.c
    scb.c
    secrand.c
    selftest.c
    sha2.c
    sha3.c
    slhdsa_shake128f.c
    slhdsa_shake128s.c
    slhdsa_shake192f.c
    slhdsa_shake192s.c
    slhdsa_shake256f.c
    slhdsa_shake256s.c
    socket.c
    socketbase.c
    socketclient.c
    socketserver.c
    sphincsplus.c
    sphincsplusbase.c
    sphincsplusbase_avx2.c
    stringutils.c
    sysutils.c
    threadpool.c
    timerex.c
    timestamp.c
    tlsalert.c
    tlscert.c
    tlscertx509.c
    tlsclient.c
    tlscodec.c
    tlsecdsader.c
    tlsengine.c
    tlserrors.c
    tlsextensions.c
    tlsgroups.c
    tlshandshake.c
    tlsio.c
    tlskeyschedule.c
    tlsrecord.c
    tlsserver.c
    tlssession.c
    tlssigalgs.c
    tlssignerdefault.c
    tlssocket.c
    tlstranscript.c
    transpose.c
    winutils.c
    x509aia.c
    x509cert.c
    x509certwrite.c
    x509crl.c
    x509crlwrite.c
    x509csr.c
    x509ext.c
    x509host.c
    x509key.c
    x509keywrite.c
    x509name.c
    x509ocsp.c
    x509pem.c
    x509pkcs12.c
    x509pkcs12crypto.c
    x509rev.c
    x509revext.c
    x509sig.c
    x509sigver.c
    x509spki.c
    x509store.c
    x509time.c
    x509verify.c
    x509wrap.c
    x509write.c
)
set(QSC_HARDWARE_SOURCES
    hwatecc.c
    hwncrypt.c
    hwncrypttls.c
    hwpkcs11tls.c
    hwplatform.c
    hwprovider.c
    hwpsa.c
    hwpsanative.c
    hwse050.c
    hwtpm.c
    hwtpmquote.c
    p11agree.c
    p11keys.c
    p11loader.c
    p11session.c
    p11sign.c
)
set(QSC_COMPACT_BASE_SOURCES intutils.c memutils.c)
set(QSC_CLASSICAL_SOURCES eddh25519.c ecdsap256.c)
set(QSC_PQC3_SOURCES kyber768.c mldsa65.c)
set(QSC_PQC5_SOURCES kyber1024.c mldsa87.c)

# The source inventory deliberately does not enumerate source code under the
# repository root: only the QSC library directory is scanned.
function(qsc_validate_source_inventory)
    file(GLOB _all_c RELATIVE "${QSC_LIBRARY_DIR}" "${QSC_LIBRARY_DIR}/*.c")
    foreach(_c IN LISTS _all_c)
        if(NOT _c IN_LIST QSC_ALL_SOURCES)
            message(FATAL_ERROR "Unclassified QSC library source: ${_c}")
        endif()
    endforeach()
    foreach(_c IN LISTS QSC_ALL_SOURCES)
        if(NOT EXISTS "${QSC_LIBRARY_DIR}/${_c}")
            message(FATAL_ERROR "QSC source absent: ${_c}")
        endif()
    endforeach()
    # The project manifest is an additional source of truth for file membership.
    if(EXISTS "${QSC_LIBRARY_DIR}/QSC.vcxproj")
        file(STRINGS "${QSC_LIBRARY_DIR}/QSC.vcxproj" _vs REGEX "<ClCompile Include=\"[^\"]+\.c\"[ ]*/>")
        foreach(_line IN LISTS _vs)
            string(REGEX REPLACE ".*<ClCompile Include=\"([^\"]+\.c)\"[ ]*/>.*" "\\1" _source "${_line}")
            if(NOT _source IN_LIST QSC_ALL_SOURCES)
                message(FATAL_ERROR "QSC Visual Studio source not in CMake: ${_source}")
            endif()
        endforeach()
    endif()
endfunction()

# TLS and X.509 share dispatch across many algorithms. Do not prune case labels
# without protocol-specific qualification; initial closure retains full source.
set(QSC_TLS_COMPATIBLE_SOURCES
    aes.c
    arrayutils.c
    asn1.c
    async.c
    chacha.c
    consoleutils.c
    cpuidex.c
    csp.c
    ecdhp256.c
    ecdhp384.c
    ecdhp521.c
    ecdsap256.c
    ecdsap384.c
    ecdsap521.c
    ed25519.c
    ed448.c
    eddh25519.c
    eddh448.c
    eddsa25519.c
    eddsa448.c
    encoding.c
    fileutils.c
    intutils.c
    ipinfo.c
    kyber1024.c
    kyber512.c
    kyber768.c
    memutils.c
    mldsa44.c
    mldsa65.c
    mldsa87.c
    netutils.c
    oid.c
    pbmac1.c
    poly1305.c
    sha2.c
    sha3.c
    socketbase.c
    socketclient.c
    socketserver.c
    stringutils.c
    sysutils.c
    timestamp.c
    tlsalert.c
    tlscert.c
    tlscertx509.c
    tlsclient.c
    tlscodec.c
    tlsecdsader.c
    tlsengine.c
    tlserrors.c
    tlsextensions.c
    tlsgroups.c
    tlshandshake.c
    tlsio.c
    tlskeyschedule.c
    tlsrecord.c
    tlsserver.c
    tlssession.c
    tlssigalgs.c
    tlssignerdefault.c
    tlssocket.c
    tlstranscript.c
    x509aia.c
    x509cert.c
    x509certwrite.c
    x509crl.c
    x509crlwrite.c
    x509csr.c
    x509ext.c
    x509host.c
    x509key.c
    x509keywrite.c
    x509name.c
    x509ocsp.c
    x509pem.c
    x509pkcs12.c
    x509pkcs12crypto.c
    x509rev.c
    x509revext.c
    x509sig.c
    x509sigver.c
    x509spki.c
    x509store.c
    x509time.c
    x509verify.c
    x509wrap.c
    x509write.c
)
