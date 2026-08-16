#include "tls_stage34_rfc10024_hybrid_tests.h"
#include "../testutils.h"
#include "csp.h"
#include "ecdhp256base.h"
#include "ecdhp384base.h"
#include "eddsa.h"
#include "memutils.h"
#include "tlscert.h"
#include "tlsclient.h"
#include "tlsgroups.h"
#include "tlssignerdefault.h"
#include "tlsserver.h"

static uint8_t stage34_server_public_key[QSC_EDDSA_PUBLICKEY_SIZE];
static uint8_t stage34_server_private_key[QSC_EDDSA_PRIVATEKEY_SIZE];
static uint8_t stage34_server_certificate[QSC_EDDSA_PUBLICKEY_SIZE];

static bool stage34_buffer_is_zero(const uint8_t* input, size_t inlen)
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

static bool stage34_run_for_supported_groups(bool (*test)(qsc_tls_named_group))
{
    const qsc_tls_named_group groups[3U] = { qsc_tls_group_x25519_mlkem768, qsc_tls_group_secp256r1_mlkem768, qsc_tls_group_secp384r1_mlkem1024 };
    size_t i;
    bool found;
    bool res;

    i = 0U;
    found = false;
    res = (test != NULL);

    for (i = 0U; i < 3U && res == true; ++i)
    {
        if (qsc_tls_groups_is_supported(groups[i]) == true)
        {
            found = true;
            res = test(groups[i]);
        }
    }

    /* RFC 10024 currently standardizes the ML-KEM-768 and ML-KEM-1024 hybrid groups above.
     * A Class 1 ML-KEM-512 build therefore has no applicable RFC 10024 hybrid group;
     * the active ML-KEM-512 primitive and pure TLS named group are covered independently. */
    if (found == false)
    {
#if defined(QSC_KYBER_S1K2P512)
        res = (test != NULL);
#else
        res = false;
#endif
    }

    return res;
}

static size_t stage34_client_kem_offset(qsc_tls_named_group group)
{
    size_t offset;

    offset = 0U;

    if (group == qsc_tls_group_secp256r1_mlkem768)
    {
        offset = 65U;
    }
    else if (group == qsc_tls_group_secp384r1_mlkem1024)
    {
        offset = 97U;
    }

    return offset;
}

static size_t stage34_client_kem_private_offset(qsc_tls_named_group group)
{
    size_t offset;

    offset = 0U;

    if (group == qsc_tls_group_secp256r1_mlkem768)
    {
        offset = QSC_ECDHP256_PRIVATEKEY_SIZE;
    }
    else if (group == qsc_tls_group_secp384r1_mlkem1024)
    {
        offset = QSC_ECDHP384_PRIVATEKEY_SIZE;
    }

    return offset;
}

static bool stage34_validate_chain(const qsc_tls_certificate_view* chain, size_t chainlength, const qsc_tls_certificate_validation_context* context, void* state)
{
    (void)context;
    (void)state;

    return (chain != NULL && chainlength == 1U && chain[0U].datalen == sizeof(stage34_server_certificate));
}

static bool stage34_verify_certificate_verify(qsc_tls_signature_scheme scheme, const uint8_t* input, size_t inputlen, const uint8_t* signature, 
    size_t signaturelen, const qsc_tls_certificate_view* signer, void* state)
{
    qsc_tls_certificate_view view;

    (void)signer;
    (void)state;
    view.data = stage34_server_public_key;
    view.datalen = sizeof(stage34_server_public_key);

    return qsc_tls_signer_default_verify(scheme, input, inputlen, signature, signaturelen, &view, NULL);
}

static bool stage34_initialize_configs(qsc_tls_named_group group, qsc_tls_client_config* clientconfig, qsc_tls_server_config* serverconfig, qsc_tls_signer_default_context* signer)
{
    static qsc_tls_cipher_suite client_suites[1U] = { qsc_tls_cipher_suite_tls_aes_128_gcm_sha256 };
    static qsc_tls_named_group client_groups[1U];
    static qsc_tls_signature_scheme client_sigs[1U] = { qsc_tls_sig_ed25519 };
    static qsc_tls_cipher_suite server_suites[1U] = { qsc_tls_cipher_suite_tls_aes_128_gcm_sha256 };
    static qsc_tls_named_group server_groups[1U];
    static qsc_tls_signature_scheme server_sigs[1U] = { qsc_tls_sig_ed25519 };
    bool res;

    res = false;

    if (clientconfig != NULL && serverconfig != NULL && signer != NULL && group != qsc_tls_group_none)
    {
        qsc_memutils_clear(clientconfig, sizeof(*clientconfig));
        qsc_memutils_clear(serverconfig, sizeof(*serverconfig));
        qsc_memutils_clear(signer, sizeof(*signer));
        client_groups[0U] = group;
        server_groups[0U] = group;
        qsc_eddsa_generate_keypair(stage34_server_public_key, stage34_server_private_key, qsc_csp_generate);
        qsc_memutils_copy(stage34_server_certificate, stage34_server_public_key, sizeof(stage34_server_certificate));

        clientconfig->ciphersuites = client_suites;
        clientconfig->ciphersuitecount = 1U;
        clientconfig->groups = client_groups;
        clientconfig->groupcount = 1U;
        clientconfig->sigschemes = client_sigs;
        clientconfig->sigschemecount = 1U;
        clientconfig->hostname = "example.com";
        clientconfig->certinterface.validatechain = stage34_validate_chain;
        clientconfig->certinterface.verifycertificateverify = stage34_verify_certificate_verify;
        clientconfig->certinterface.state = NULL;

        serverconfig->ciphersuitepreference = server_suites;
        serverconfig->ciphersuitepreferencecount = 1U;
        serverconfig->groupspreference = server_groups;
        serverconfig->groupspreferencecount = 1U;
        serverconfig->sigschemepreference = server_sigs;
        serverconfig->sigschemepreferencecount = 1U;
        serverconfig->localcert.chain[0U].data = stage34_server_certificate;
        serverconfig->localcert.chain[0U].datalen = sizeof(stage34_server_certificate);
        serverconfig->localcert.chainlength = 1U;
        serverconfig->localcert.verifyscheme = qsc_tls_sig_ed25519;
        serverconfig->localcert.configured = true;

        signer->scheme = qsc_tls_sig_ed25519;
        signer->privatekey = stage34_server_private_key;
        signer->privatekeylen = sizeof(stage34_server_private_key);
        serverconfig->localcert.signcallback = qsc_tls_signer_default_sign;
        serverconfig->localcert.signstate = signer;
        res = true;
    }

    return res;
}

static bool stage34_find_client_keyshare(uint8_t* record, size_t recordlen, uint8_t** keyshare, size_t* keysharelen)
{
    size_t bodyoff;
    size_t extoff;
    size_t extend;
    size_t off;
    uint16_t extlen;
    uint16_t exttype;
    uint16_t len;
    bool res;

    bodyoff = 0U;
    extoff = 0U;
    extend = 0U;
    off = 0U;
    extlen = 0U;
    exttype = 0U;
    len = 0U;
    res = false;

    if (keyshare != NULL)
    {
        *keyshare = NULL;
    }

    if (keysharelen != NULL)
    {
        *keysharelen = 0U;
    }

    if (record != NULL && keyshare != NULL && keysharelen != NULL && recordlen >= 5U + 4U + 35U)
    {
        bodyoff = 5U + 4U;
        off = bodyoff + 2U + 32U;

        if (off < recordlen)
        {
            len = record[off];
            off += 1U;
        }

        if (off + len <= recordlen)
        {
            off += len;
        }

        if (off + 2U <= recordlen)
        {
            len = (uint16_t)(((uint16_t)record[off] << 8U) | record[off + 1U]);
            off += 2U;
        }

        if (off + len <= recordlen)
        {
            off += len;
        }

        if (off < recordlen)
        {
            len = record[off];
            off += 1U;
        }

        if (off + len <= recordlen)
        {
            off += len;
        }

        if (off + 2U <= recordlen)
        {
            extlen = (uint16_t)(((uint16_t)record[off] << 8U) | record[off + 1U]);
            off += 2U;
            extoff = off;
            extend = extoff + extlen;
        }

        if (extend <= recordlen)
        {
            while (off + 4U <= extend && res == false)
            {
                exttype = (uint16_t)(((uint16_t)record[off] << 8U) | record[off + 1U]);
                len = (uint16_t)(((uint16_t)record[off + 2U] << 8U) | record[off + 3U]);
                off += 4U;

                if (off + len > extend)
                {
                    break;
                }

                if (exttype == (uint16_t)qsc_tls_extension_key_share && len >= 6U)
                {
                    size_t ksoff;
                    uint16_t listlen;
                    uint16_t kslen;

                    ksoff = off;
                    listlen = (uint16_t)(((uint16_t)record[ksoff] << 8U) | record[ksoff + 1U]);
                    ksoff += 2U;

                    if ((size_t)listlen + 2U == len && ksoff + 4U <= off + len)
                    {
                        ksoff += 2U;
                        kslen = (uint16_t)(((uint16_t)record[ksoff] << 8U) | record[ksoff + 1U]);
                        ksoff += 2U;

                        if (ksoff + kslen <= off + len)
                        {
                            *keyshare = record + ksoff;
                            *keysharelen = kslen;
                            res = true;
                        }
                    }
                }

                off += len;
            }
        }
    }

    return res;
}

static bool stage34_descriptor_and_roundtrip_test(qsc_tls_named_group group)
{
    qsc_tls_key_exchange_state client;
    const qsc_tls_group_descriptor* descriptor;
    uint8_t clientsecret[QSC_TLS_MAX_SHARED_SECRET_SIZE] = { 0U };
    uint8_t serverkeyshare[QSC_TLS_MAX_HYBRID_SERVER_KEYSHARE_SIZE] = { 0U };
    uint8_t serversecret[QSC_TLS_MAX_SHARED_SECRET_SIZE] = { 0U };
    size_t clientsecretwritten;
    size_t serverkeysharewritten;
    size_t serversecretwritten;
    qsc_tls_status status;
    bool res;

    qsc_memutils_clear(&client, sizeof(client));
    clientsecretwritten = 0U;
    serverkeysharewritten = 0U;
    serversecretwritten = 0U;
    descriptor = qsc_tls_groups_descriptor_get(group);
    res = (descriptor != NULL && descriptor->ishybrid == true && descriptor->iskem == true && descriptor->isclassical == true);

    if (res == true)
    {
        res = ((group != qsc_tls_group_x25519_mlkem768 || (uint16_t)group == 0x11ECU) &&
            (group != qsc_tls_group_secp256r1_mlkem768 || (uint16_t)group == 0x11EBU) &&
            (group != qsc_tls_group_secp384r1_mlkem1024 || (uint16_t)group == 0x11EDU));
    }

    if (res == true)
    {
        status = qsc_tls_groups_generate_client_keypair(&client, group);
        res = (status == qsc_tls_status_success && client.publicsharelen == descriptor->clientpublicsize);
    }

    if (res == true)
    {
        status = qsc_tls_groups_server_respond(group, client.publicshare, client.publicsharelen, serverkeyshare, sizeof(serverkeyshare),
            &serverkeysharewritten, serversecret, sizeof(serversecret), &serversecretwritten);
        res = (status == qsc_tls_status_success && serverkeysharewritten == descriptor->serverpublicsize &&
            serversecretwritten == descriptor->sharedsecretsize);
    }

    if (res == true)
    {
        status = qsc_tls_groups_client_derive_shared_secret(&client, serverkeyshare, serverkeysharewritten,
            clientsecret, sizeof(clientsecret), &clientsecretwritten);
        res = (status == qsc_tls_status_success && clientsecretwritten == serversecretwritten &&
            qsc_memutils_are_equal(clientsecret, serversecret, clientsecretwritten) == true);
    }

    qsc_tls_groups_key_exchange_state_dispose(&client);
    qsc_memutils_secure_erase(clientsecret, sizeof(clientsecret));
    qsc_memutils_secure_erase(serversecret, sizeof(serversecret));

    return res;
}

static bool stage34_encapsulation_key_check_test(qsc_tls_named_group group)
{
    qsc_tls_key_exchange_state client;
    const qsc_tls_group_descriptor* descriptor;
    uint8_t badshare[QSC_TLS_MAX_HYBRID_CLIENT_KEYSHARE_SIZE] = { 0U };
    uint8_t serverkeyshare[QSC_TLS_MAX_HYBRID_SERVER_KEYSHARE_SIZE] = { 0U };
    uint8_t sharedsecret[QSC_TLS_MAX_SHARED_SECRET_SIZE] = { 0U };
    size_t kemoffset;
    size_t serverkeysharewritten;
    size_t sharedsecretwritten;
    qsc_tls_status status;
    bool res;

    qsc_memutils_clear(&client, sizeof(client));
    descriptor = qsc_tls_groups_descriptor_get(group);
    res = (descriptor != NULL);
    serverkeysharewritten = 0U;
    sharedsecretwritten = 0U;

    if (res == true)
    {
        status = qsc_tls_groups_generate_client_keypair(&client, group);
        res = (status == qsc_tls_status_success);
    }

    if (res == true)
    {
        qsc_memutils_copy(badshare, client.publicshare, client.publicsharelen);
        kemoffset = stage34_client_kem_offset(group);
        badshare[kemoffset] = 0xFFU;
        badshare[kemoffset + 1U] = (uint8_t)((badshare[kemoffset + 1U] & 0xF0U) | 0x0FU);
        qsc_memutils_set_value(serverkeyshare, descriptor->serverpublicsize, 0xA5U);
        qsc_memutils_set_value(sharedsecret, descriptor->sharedsecretsize, 0xA5U);
        serverkeysharewritten = 17U;
        sharedsecretwritten = 19U;
        status = qsc_tls_groups_server_respond(group, badshare, client.publicsharelen, serverkeyshare, sizeof(serverkeyshare),
            &serverkeysharewritten, sharedsecret, sizeof(sharedsecret), &sharedsecretwritten);
        res = (status == qsc_tls_status_invalid_message && serverkeysharewritten == 0U && sharedsecretwritten == 0U &&
            stage34_buffer_is_zero(serverkeyshare, descriptor->serverpublicsize) == true &&
            stage34_buffer_is_zero(sharedsecret, descriptor->sharedsecretsize) == true);
    }

    qsc_tls_groups_key_exchange_state_dispose(&client);
    qsc_memutils_secure_erase(sharedsecret, sizeof(sharedsecret));

    return res;
}

static bool stage34_failure_zeroization_test(qsc_tls_named_group group)
{
    qsc_tls_key_exchange_state client;
    const qsc_tls_group_descriptor* descriptor;
    uint8_t clientsecret[QSC_TLS_MAX_SHARED_SECRET_SIZE] = { 0U };
    uint8_t serverkeyshare[QSC_TLS_MAX_HYBRID_SERVER_KEYSHARE_SIZE] = { 0U };
    uint8_t serversecret[QSC_TLS_MAX_SHARED_SECRET_SIZE] = { 0U };
    size_t clientsecretwritten;
    size_t serverkeysharewritten;
    size_t serversecretwritten;
    size_t kemoffset;
    qsc_tls_status status;
    bool res;

    qsc_memutils_clear(&client, sizeof(client));
    descriptor = qsc_tls_groups_descriptor_get(group);
    res = (descriptor != NULL);
    clientsecretwritten = 0U;
    serverkeysharewritten = 0U;
    serversecretwritten = 0U;

    if (res == true)
    {
        status = qsc_tls_groups_generate_client_keypair(&client, group);
        res = (status == qsc_tls_status_success);
    }

    if (res == true)
    {
        status = qsc_tls_groups_server_respond(group, client.publicshare, client.publicsharelen, serverkeyshare, sizeof(serverkeyshare),
            &serverkeysharewritten, serversecret, sizeof(serversecret), &serversecretwritten);

        res = (status == qsc_tls_status_success);
    }

    if (res == true)
    {
        kemoffset = stage34_client_kem_private_offset(group) + QSC_KYBER_PRIVATEKEY_SIZE - (2U * QSC_KYBER_SHAREDSECRET_SIZE);
        client.privatekey[kemoffset] ^= 0x01U;
        qsc_memutils_set_value(clientsecret, descriptor->sharedsecretsize, 0xA5U);
        clientsecretwritten = 23U;
        status = qsc_tls_groups_client_derive_shared_secret(&client, serverkeyshare, serverkeysharewritten, clientsecret, sizeof(clientsecret), &clientsecretwritten);
        
        res = (status == qsc_tls_status_authentication_failure && clientsecretwritten == 0U &&
            stage34_buffer_is_zero(clientsecret, descriptor->sharedsecretsize) == true);
    }

    if (res == true && group == qsc_tls_group_x25519_mlkem768)
    {
        uint8_t badclientshare[QSC_TLS_MAX_HYBRID_CLIENT_KEYSHARE_SIZE] = { 0U };

        qsc_memutils_copy(badclientshare, client.publicshare, client.publicsharelen);
        qsc_memutils_clear(badclientshare + QSC_KYBER_PUBLICKEY_SIZE, 32U);
        qsc_memutils_set_value(serverkeyshare, descriptor->serverpublicsize, 0xA5U);
        qsc_memutils_set_value(serversecret, descriptor->sharedsecretsize, 0xA5U);
        serverkeysharewritten = 29U;
        serversecretwritten = 31U;

        status = qsc_tls_groups_server_respond(group, badclientshare, client.publicsharelen, serverkeyshare, sizeof(serverkeyshare),
            &serverkeysharewritten, serversecret, sizeof(serversecret), &serversecretwritten);
        
        res = (status == qsc_tls_status_invalid_message && serverkeysharewritten == 0U && serversecretwritten == 0U &&
            stage34_buffer_is_zero(serverkeyshare, descriptor->serverpublicsize) == true &&
            stage34_buffer_is_zero(serversecret, descriptor->sharedsecretsize) == true);
    }

    qsc_tls_groups_key_exchange_state_dispose(&client);
    qsc_memutils_secure_erase(clientsecret, sizeof(clientsecret));
    qsc_memutils_secure_erase(serversecret, sizeof(serversecret));

    return res;
}

static bool stage34_server_alert_mapping_test(qsc_tls_named_group group)
{
    qsc_tls_signer_default_context signer = { 0 };
    qsc_tls_client_config clientconfig = { 0 };
    qsc_tls_server_config serverconfig = { 0 };
    qsc_tls_client_state* client;
    qsc_tls_server_state* server;
    uint8_t clienthello[32768U] = { 0U };
    uint8_t serverout[131072U] = { 0U };
    uint8_t* keyshare;
    size_t clienthellolen;
    size_t consumed;
    size_t kemoffset;
    size_t keysharelen;
    size_t serveroutlen;
    qsc_tls_status status;
    bool clientinitialized;
    bool res;
    bool serverinitialized;

    client = (qsc_tls_client_state*)qsc_memutils_malloc(sizeof(qsc_tls_client_state));
    server = (qsc_tls_server_state*)qsc_memutils_malloc(sizeof(qsc_tls_server_state));
    clientinitialized = false;
    keyshare = NULL;
    clienthellolen = 0U;
    consumed = 0U;
    keysharelen = 0U;
    serveroutlen = 0U;
    res = (client != NULL && server != NULL);
    serverinitialized = false;

    if (res == true)
    {
        qsc_memutils_clear(client, sizeof(qsc_tls_client_state));
        qsc_memutils_clear(server, sizeof(qsc_tls_server_state));
        res = stage34_initialize_configs(group, &clientconfig, &serverconfig, &signer);
    }

    if (res == true)
    {
        status = qsc_tls_client_initialize(client, &clientconfig);
        res = (status == qsc_tls_status_success);
        clientinitialized = res;
    }

    if (res == true)
    {
        status = qsc_tls_server_initialize(server, &serverconfig);
        res = (status == qsc_tls_status_success);
        serverinitialized = res;
    }

    if (res == true)
    {
        status = qsc_tls_client_send_hello(client, clienthello, sizeof(clienthello), &clienthellolen);
        res = (status == qsc_tls_status_success && stage34_find_client_keyshare(clienthello, clienthellolen, &keyshare, &keysharelen) == true);
    }

    if (res == true)
    {
        kemoffset = stage34_client_kem_offset(group);
        res = (kemoffset + 2U <= keysharelen);
    }

    if (res == true)
    {
        keyshare[kemoffset] = 0xFFU;
        keyshare[kemoffset + 1U] = (uint8_t)((keyshare[kemoffset + 1U] & 0xF0U) | 0x0FU);
        status = qsc_tls_server_process_record(server, clienthello, clienthellolen, &consumed, serverout, sizeof(serverout), &serveroutlen);
        res = (status == qsc_tls_status_invalid_message && server->lastalert == qsc_tls_alert_illegal_parameter && server->phase == qsc_tls_server_phase_failed && serveroutlen == 0U);
    }

    if (clientinitialized == true)
    {
        qsc_tls_client_dispose(client);
    }

    if (serverinitialized == true)
    {
        qsc_tls_server_dispose(server);
    }

    if (client != NULL)
    {
        qsc_memutils_secure_erase(client, sizeof(qsc_tls_client_state));
        qsc_memutils_alloc_free(client);
    }

    if (server != NULL)
    {
        qsc_memutils_secure_erase(server, sizeof(qsc_tls_server_state));
        qsc_memutils_alloc_free(server);
    }

    return res;
}

static bool stage34_client_alert_mapping_test(qsc_tls_named_group group)
{
    qsc_tls_signer_default_context signer = { 0 };
    qsc_tls_client_config clientconfig = { 0 };
    qsc_tls_server_config serverconfig = { 0 };
    qsc_tls_client_state* client;
    qsc_tls_server_state* server;
    uint8_t clienthello[32768U] = { 0U };
    uint8_t clientout[32768U] = { 0U };
    uint8_t serverflight[131072U] = { 0U };
    size_t clienthellolen;
    size_t clientoutlen;
    size_t consumed;
    size_t kemoffset;
    size_t serverflightlen;
    size_t serverhellolen;
    qsc_tls_status status;
    bool clientinitialized;
    bool res;
    bool serverinitialized;

    client = (qsc_tls_client_state*)qsc_memutils_malloc(sizeof(qsc_tls_client_state));
    server = (qsc_tls_server_state*)qsc_memutils_malloc(sizeof(qsc_tls_server_state));
    clienthellolen = 0U;
    clientinitialized = false;
    clientoutlen = 0U;
    consumed = 0U;
    kemoffset = 0U;
    serverflightlen = 0U;
    serverhellolen = 0U;
    res = (client != NULL && server != NULL);
    serverinitialized = false;

    if (res == true)
    {
        qsc_memutils_clear(client, sizeof(qsc_tls_client_state));
        qsc_memutils_clear(server, sizeof(qsc_tls_server_state));
        res = stage34_initialize_configs(group, &clientconfig, &serverconfig, &signer);
    }

    if (res == true)
    {
        status = qsc_tls_client_initialize(client, &clientconfig);
        res = (status == qsc_tls_status_success);
        clientinitialized = res;
    }

    if (res == true)
    {
        status = qsc_tls_server_initialize(server, &serverconfig);
        res = (status == qsc_tls_status_success);
        serverinitialized = res;
    }

    if (res == true)
    {
        status = qsc_tls_client_send_hello(client, clienthello, sizeof(clienthello), &clienthellolen);
        res = (status == qsc_tls_status_success);
    }

    if (res == true)
    {
        status = qsc_tls_server_process_record(server, clienthello, clienthellolen, &consumed, serverflight, sizeof(serverflight), &serverflightlen);
        res = (status == qsc_tls_status_success && serverflightlen >= 5U);
    }

    if (res == true)
    {
        serverhellolen = 5U + (size_t)(((uint16_t)serverflight[3U] << 8U) | serverflight[4U]);
        res = (serverhellolen <= serverflightlen);
    }

    if (res == true)
    {
        /* Corrupt the local ML-KEM decapsulation-key hash so Decaps reports an explicit input/key failure. */
        kemoffset = stage34_client_kem_private_offset(group) + QSC_KYBER_PRIVATEKEY_SIZE - (2U * QSC_KYBER_SHAREDSECRET_SIZE);
        client->keyexchange.privatekey[kemoffset] ^= 0x01U;
        consumed = 0U;
        status = qsc_tls_client_process_record(client, serverflight, serverhellolen, &consumed, clientout, sizeof(clientout), &clientoutlen);
        res = (status == qsc_tls_status_authentication_failure && client->lastalert == qsc_tls_alert_internal_error && client->phase == qsc_tls_client_phase_failed && clientoutlen == 0U);
    }

    if (clientinitialized == true)
    {
        qsc_tls_client_dispose(client);
    }

    if (serverinitialized == true)
    {
        qsc_tls_server_dispose(server);
    }

    if (client != NULL)
    {
        qsc_memutils_secure_erase(client, sizeof(qsc_tls_client_state));
        qsc_memutils_alloc_free(client);
    }

    if (server != NULL)
    {
        qsc_memutils_secure_erase(server, sizeof(qsc_tls_server_state));
        qsc_memutils_alloc_free(server);
    }

    return res;
}

bool qsctest_tls_stage34_tests(void)
{
    bool res;

    res = true;

    if (stage34_run_for_supported_groups(stage34_descriptor_and_roundtrip_test) == true)
    {
        qsctest_print_line("[PASS] TLS Stage 34 RFC 10024 hybrid group round-trip test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 34 RFC 10024 hybrid group round-trip test.");
        res = false;
    }

    if (stage34_run_for_supported_groups(stage34_encapsulation_key_check_test) == true)
    {
        qsctest_print_line("[PASS] TLS Stage 34 RFC 10024 ML-KEM encapsulation-key check test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 34 RFC 10024 ML-KEM encapsulation-key check test.");
        res = false;
    }

    if (stage34_run_for_supported_groups(stage34_failure_zeroization_test) == true)
    {
        qsctest_print_line("[PASS] TLS Stage 34 hybrid failure-path zeroization test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 34 hybrid failure-path zeroization test.");
        res = false;
    }

    if (stage34_run_for_supported_groups(stage34_server_alert_mapping_test) == true)
    {
        qsctest_print_line("[PASS] TLS Stage 34 RFC 10024 server illegal_parameter mapping test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 34 RFC 10024 server illegal_parameter mapping test.");
        res = false;
    }

    if (stage34_run_for_supported_groups(stage34_client_alert_mapping_test) == true)
    {
        qsctest_print_line("[PASS] TLS Stage 34 RFC 10024 client internal_error mapping test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 34 RFC 10024 client internal_error mapping test.");
        res = false;
    }

    return res;
}
