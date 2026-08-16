#include "tls_stage36_pq_standards_tests.h"
#include "../testutils.h"
#include "csp.h"
#include "dilithium.h"
#include "kyber.h"
#include "memutils.h"
#include "tlsgroups.h"
#include "tlssigalgs.h"
#include "tlssignerdefault.h"
#include "x509spki.h"

static bool stage36_buffer_is_zero(const uint8_t* input, size_t inlen)
{
    size_t i;
    bool res;

    res = (input != NULL);

    if (res == true)
    {
        for (i = 0U; i < inlen; ++i)
        {
            if (input[i] != 0U)
            {
                res = false;
                break;
            }
        }
    }

    return res;
}

static qsc_tls_named_group stage36_active_mlkem_group(void)
{
#if defined(QSC_KYBER_S1K2P512)
    return qsc_tls_group_mlkem512;
#elif defined(QSC_KYBER_S5K4P1024)
    return qsc_tls_group_mlkem1024;
#else
    return qsc_tls_group_mlkem768;
#endif
}

static qsc_tls_signature_scheme stage36_active_mldsa_scheme(void)
{
#if defined(QSC_DILITHIUM_S1P44)
    return qsc_tls_sig_mldsa44;
#elif defined(QSC_DILITHIUM_S5P87)
    return qsc_tls_sig_mldsa87;
#else
    return qsc_tls_sig_mldsa65;
#endif
}

static bool stage36_identifier_and_size_test(void)
{
    const qsc_tls_group_descriptor* desc;
    bool res;

    res = ((uint16_t)qsc_tls_group_mlkem512 == 0x0200U &&
        (uint16_t)qsc_tls_group_mlkem768 == 0x0201U &&
        (uint16_t)qsc_tls_group_mlkem1024 == 0x0202U &&
        (uint16_t)qsc_tls_group_x25519_mlkem768 == 0x11ECU &&
        (uint16_t)qsc_tls_group_secp256r1_mlkem768 == 0x11EBU &&
        (uint16_t)qsc_tls_group_secp384r1_mlkem1024 == 0x11EDU &&
        (uint16_t)qsc_tls_sig_mldsa44 == 0x0904U &&
        (uint16_t)qsc_tls_sig_mldsa65 == 0x0905U &&
        (uint16_t)qsc_tls_sig_mldsa87 == 0x0906U);

    if (res == true)
    {
        res = (qsc_tls_signature_scheme_signature_size(qsc_tls_sig_mldsa44) == 2420U &&
            qsc_tls_signature_scheme_signature_size(qsc_tls_sig_mldsa65) == 3309U &&
            qsc_tls_signature_scheme_signature_size(qsc_tls_sig_mldsa87) == 4627U &&
            qsc_tls_signature_scheme_public_key_size(qsc_tls_sig_mldsa44) == 1312U &&
            qsc_tls_signature_scheme_public_key_size(qsc_tls_sig_mldsa65) == 1952U &&
            qsc_tls_signature_scheme_public_key_size(qsc_tls_sig_mldsa87) == 2592U);
    }

    if (res == true)
    {
        desc = qsc_tls_groups_descriptor_get(stage36_active_mlkem_group());
        res = (desc != NULL && desc->iskem == true && desc->ishybrid == false &&
            desc->clientpublicsize == QSC_KYBER_PUBLICKEY_SIZE &&
            desc->serverpublicsize == QSC_KYBER_CIPHERTEXT_SIZE &&
            desc->sharedsecretsize == QSC_KYBER_SHAREDSECRET_SIZE);
    }

    return res;
}

static bool stage36_standalone_mlkem_roundtrip_test(void)
{
    qsc_tls_key_exchange_state state;
    uint8_t clientsecret[QSC_TLS_MAX_SHARED_SECRET_SIZE] = { 0U };
    uint8_t serverkeyshare[QSC_TLS_MAX_HYBRID_SERVER_KEYSHARE_SIZE] = { 0U };
    uint8_t serversecret[QSC_TLS_MAX_SHARED_SECRET_SIZE] = { 0U };
    size_t clientsecretlen;
    size_t serverkeysharelen;
    size_t serversecretlen;
    qsc_tls_status status;
    bool res;

    qsc_memutils_clear(&state, sizeof(state));
    clientsecretlen = 0U;
    serverkeysharelen = 0U;
    serversecretlen = 0U;
    status = qsc_tls_groups_generate_client_keypair(&state, stage36_active_mlkem_group());
    res = (status == qsc_tls_status_success && state.publicsharelen == QSC_KYBER_PUBLICKEY_SIZE);

    if (res == true)
    {
        status = qsc_tls_groups_server_respond(state.group, state.publicshare, state.publicsharelen, serverkeyshare, sizeof(serverkeyshare), &serverkeysharelen, serversecret, sizeof(serversecret), &serversecretlen);
        res = (status == qsc_tls_status_success && serverkeysharelen == QSC_KYBER_CIPHERTEXT_SIZE && serversecretlen == QSC_KYBER_SHAREDSECRET_SIZE);
    }

    if (res == true)
    {
        status = qsc_tls_groups_client_derive_shared_secret(&state, serverkeyshare, serverkeysharelen, clientsecret, sizeof(clientsecret), &clientsecretlen);
        res = (status == qsc_tls_status_success && clientsecretlen == serversecretlen && qsc_memutils_are_equal(clientsecret, serversecret, serversecretlen) == true);
    }

    qsc_tls_groups_key_exchange_state_dispose(&state);
    qsc_memutils_secure_erase(clientsecret, sizeof(clientsecret));
    qsc_memutils_secure_erase(serversecret, sizeof(serversecret));

    return res;
}

static bool stage36_standalone_mlkem_encapsulation_key_check_test(void)
{
    const qsc_tls_group_descriptor* desc;
    qsc_tls_key_exchange_state state;
    uint8_t clientshare[QSC_TLS_MAX_HYBRID_CLIENT_KEYSHARE_SIZE] = { 0U };
    uint8_t serverkeyshare[QSC_TLS_MAX_HYBRID_SERVER_KEYSHARE_SIZE];
    uint8_t sharedsecret[QSC_TLS_MAX_SHARED_SECRET_SIZE];
    size_t serverkeysharelen;
    size_t sharedsecretlen;
    qsc_tls_status status;
    bool res;

    qsc_memutils_clear(&state, sizeof(state));
    qsc_memutils_set_value(serverkeyshare, sizeof(serverkeyshare), 0xA5U);
    qsc_memutils_set_value(sharedsecret, sizeof(sharedsecret), 0x5AU);
    serverkeysharelen = 0U;
    sharedsecretlen = 0U;
    status = qsc_tls_groups_generate_client_keypair(&state, stage36_active_mlkem_group());
    res = (status == qsc_tls_status_success && state.publicsharelen >= 3U);

    if (res == true)
    {
        qsc_memutils_copy(clientshare, state.publicshare, state.publicsharelen);

        /* Encode the first 12-bit coefficient as q = 3329. FIPS 203 requires rejection when any decoded coefficient is >= q. */
        clientshare[0U] = 0x01U;
        clientshare[1U] = (uint8_t)((clientshare[1U] & 0xF0U) | 0x0DU);
        status = qsc_tls_groups_server_respond(state.group, clientshare, state.publicsharelen, serverkeyshare, sizeof(serverkeyshare), &serverkeysharelen, sharedsecret, sizeof(sharedsecret), &sharedsecretlen);
        desc = qsc_tls_groups_descriptor_get(state.group);
        res = (desc != NULL && status == qsc_tls_status_invalid_message && serverkeysharelen == 0U && sharedsecretlen == 0U &&
            stage36_buffer_is_zero(serverkeyshare, desc->serverpublicsize) == true &&
            stage36_buffer_is_zero(sharedsecret, desc->sharedsecretsize) == true);
    }

    qsc_tls_groups_key_exchange_state_dispose(&state);
    qsc_memutils_secure_erase(sharedsecret, sizeof(sharedsecret));

    return res;
}

static bool stage36_mlkem_implicit_rejection_test(void)
{
    uint8_t ciphertext[QSC_KYBER_CIPHERTEXT_SIZE] = { 0U };
    uint8_t privatekey[QSC_KYBER_PRIVATEKEY_SIZE] = { 0U };
    uint8_t publickey[QSC_KYBER_PUBLICKEY_SIZE] = { 0U };
    uint8_t rejection1[QSC_KYBER_SHAREDSECRET_SIZE] = { 0U };
    uint8_t rejection2[QSC_KYBER_SHAREDSECRET_SIZE] = { 0U };
    uint8_t sharedsecret[QSC_KYBER_SHAREDSECRET_SIZE] = { 0U };
    bool res;

    res = qsc_kyber_generate_keypair(publickey, privatekey, qsc_csp_generate);

    if (res == true)
    {
        res = qsc_kyber_encapsulate(sharedsecret, ciphertext, publickey, qsc_csp_generate);
    }

    if (res == true)
    {
        ciphertext[0U] ^= 0x01U;
        res = (qsc_kyber_decapsulate(rejection1, ciphertext, privatekey) == true &&
            qsc_kyber_decapsulate(rejection2, ciphertext, privatekey) == true &&
            qsc_memutils_are_equal(rejection1, sharedsecret, sizeof(rejection1)) == false &&
            qsc_memutils_are_equal(rejection1, rejection2, sizeof(rejection1)) == true);
    }

    qsc_memutils_secure_erase(privatekey, sizeof(privatekey));
    qsc_memutils_secure_erase(rejection1, sizeof(rejection1));
    qsc_memutils_secure_erase(rejection2, sizeof(rejection2));
    qsc_memutils_secure_erase(sharedsecret, sizeof(sharedsecret));

    return res;
}

static bool stage36_mlkem_primitive_input_check_test(void)
{
    uint8_t ciphertext[QSC_KYBER_CIPHERTEXT_SIZE] = { 0U };
    uint8_t privatekey[QSC_KYBER_PRIVATEKEY_SIZE] = { 0U };
    uint8_t publickey[QSC_KYBER_PUBLICKEY_SIZE] = { 0U };
    uint8_t sharedsecret[QSC_KYBER_SHAREDSECRET_SIZE] = { 0U };
    size_t hashoffset;
    bool res;

    res = qsc_kyber_generate_keypair(publickey, privatekey, qsc_csp_generate);

    if (res == true)
    {
        publickey[0U] = 0x01U;
        publickey[1U] = (uint8_t)((publickey[1U] & 0xF0U) | 0x0DU);
        res = (qsc_kyber_encapsulate(sharedsecret, ciphertext, publickey, qsc_csp_generate) == false && stage36_buffer_is_zero(sharedsecret, sizeof(sharedsecret)) == true);
    }

    if (res == true)
    {
        res = qsc_kyber_generate_keypair(publickey, privatekey, qsc_csp_generate);
    }

    if (res == true)
    {
        res = qsc_kyber_encapsulate(sharedsecret, ciphertext, publickey, qsc_csp_generate);
    }

    if (res == true)
    {
        hashoffset = QSC_KYBER_PRIVATEKEY_SIZE - (2U * QSC_KYBER_SHAREDSECRET_SIZE);
        privatekey[hashoffset] ^= 0x01U;
        qsc_memutils_set_value(sharedsecret, sizeof(sharedsecret), 0xA5U);
        res = (qsc_kyber_decapsulate(sharedsecret, ciphertext, privatekey) == false && stage36_buffer_is_zero(sharedsecret, sizeof(sharedsecret)) == true);
    }

    qsc_memutils_secure_erase(privatekey, sizeof(privatekey));
    qsc_memutils_secure_erase(sharedsecret, sizeof(sharedsecret));

    return res;
}

static bool stage36_mldsa_tls_empty_context_test(void)
{
    qsc_tls_signer_default_context signer;
    qsc_tls_certificate_view view;
    uint8_t message[48U] = { 0U };
    uint8_t publickey[QSC_DILITHIUM_PUBLICKEY_SIZE] = { 0U };
    uint8_t privatekey[QSC_DILITHIUM_PRIVATEKEY_SIZE] = { 0U };
    uint8_t signature[QSC_DILITHIUM_SIGNATURE_SIZE] = { 0U };
    uint8_t signedmsg[QSC_DILITHIUM_SIGNATURE_SIZE + sizeof(message)] = { 0U };
    uint8_t recovered[sizeof(message)] = { 0U };
    const uint8_t nonemptycontext[1U] = { 0x01U };
    size_t recoveredlen;
    size_t signaturelen;
    size_t i;
    qsc_tls_signature_scheme scheme;
    bool res;

    qsc_memutils_clear(&signer, sizeof(signer));
    recoveredlen = 0U;
    signaturelen = sizeof(signature);
    scheme = stage36_active_mldsa_scheme();

    for (i = 0U; i < sizeof(message); ++i)
    {
        message[i] = (uint8_t)i;
    }

    res = qsc_dilithium_generate_keypair(publickey, privatekey, qsc_csp_generate);

    if (res == true)
    {
        signer.scheme = scheme;
        signer.privatekey = privatekey;
        signer.privatekeylen = sizeof(privatekey);
        res = qsc_tls_signer_default_sign(scheme, message, sizeof(message), signature, &signaturelen, &signer);
    }

    if (res == true)
    {
        view.data = publickey;
        view.datalen = sizeof(publickey);
        res = (signaturelen == QSC_DILITHIUM_SIGNATURE_SIZE && qsc_tls_signer_default_verify(scheme, message, sizeof(message), signature, signaturelen, &view, NULL) == true);
    }

    if (res == true)
    {
        qsc_memutils_copy(signedmsg, signature, signaturelen);
        qsc_memutils_copy(signedmsg + signaturelen, message, sizeof(message));
        res = (qsc_dilithium_verify_ex(recovered, &recoveredlen, nonemptycontext, sizeof(nonemptycontext), signedmsg, signaturelen + sizeof(message), publickey) == false);
    }

    qsc_memutils_secure_erase(privatekey, sizeof(privatekey));
    qsc_memutils_secure_erase(signature, sizeof(signature));
    qsc_memutils_secure_erase(signedmsg, sizeof(signedmsg));

    return res;
}

static bool stage36_rfc9881_algorithm_identifier_test(void)
{
    const qsc_x509_pqc_parameter_set parameters[3U] = { QSC_X509_PQC_PARAMETER_SET_ML_DSA_44, QSC_X509_PQC_PARAMETER_SET_ML_DSA_65, QSC_X509_PQC_PARAMETER_SET_ML_DSA_87 };
    const qsc_oid_id oids[3U] = { QSC_OID_ID_ML_DSA_44, QSC_OID_ID_ML_DSA_65, QSC_OID_ID_ML_DSA_87 };
    qsc_x509_algorithm_identifier algorithm;
    qsc_x509_algorithm_identifier invalid;
    size_t i;
    qsc_asn1_status status;
    bool res;

    i = 0U;
    res = true;

    for (i = 0U; i < 3U && res == true; ++i)
    {
        qsc_x509_algorithm_identifier_initialize(&algorithm);
        status = qsc_x509_algorithm_identifier_initialize_mldsa(&algorithm, parameters[i]);

        res = (status == QSC_ASN1_STATUS_SUCCESS && algorithm.oid == oids[i] &&
            algorithm.parameters_present == false && algorithm.parameters_null == false && algorithm.parameters_oid == false &&
            qsc_x509_algorithm_identifier_validate(&algorithm) == QSC_ASN1_STATUS_SUCCESS);

        if (res == true)
        {
            invalid = algorithm;
            invalid.parameters_present = true;
            invalid.parameters_null = true;
            res = (qsc_x509_algorithm_identifier_validate(&invalid) == QSC_ASN1_STATUS_INVALID_ENCODING);
        }
    }

    return res;
}

bool qsctest_tls_stage36_tests(void)
{
    bool res;

    res = true;

    if (stage36_identifier_and_size_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 36 ML-KEM/ML-DSA registered identifier and size test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 36 ML-KEM/ML-DSA registered identifier and size test.");
        res = false;
    }

    if (stage36_standalone_mlkem_roundtrip_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 36 standalone ML-KEM key-agreement test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 36 standalone ML-KEM key-agreement test.");
        res = false;
    }

    if (stage36_standalone_mlkem_encapsulation_key_check_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 36 standalone ML-KEM FIPS 203 encapsulation-key check test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 36 standalone ML-KEM FIPS 203 encapsulation-key check test.");
        res = false;
    }

    if (stage36_mlkem_implicit_rejection_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 36 FIPS 203 ML-KEM implicit-rejection test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 36 FIPS 203 ML-KEM implicit-rejection test.");
        res = false;
    }

    if (stage36_mlkem_primitive_input_check_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 36 FIPS 203 ML-KEM primitive input-check test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 36 FIPS 203 ML-KEM primitive input-check test.");
        res = false;
    }

    if (stage36_mldsa_tls_empty_context_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 36 ML-DSA pure-signature empty-context test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 36 ML-DSA pure-signature empty-context test.");
        res = false;
    }

    if (stage36_rfc9881_algorithm_identifier_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 36 RFC 9881 ML-DSA AlgorithmIdentifier test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 36 RFC 9881 ML-DSA AlgorithmIdentifier test.");
        res = false;
    }

    return res;
}
