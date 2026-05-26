#include "tlssocket.h"
#include "memutils.h"
#include "stringutils.h"
#include "intutils.h"

static const qsc_tls_cipher_suite TLS_SOCKET_DEFAULT_SUITES[] =
{
    qsc_tls_cipher_suite_tls_aes_256_gcm_sha384,
    qsc_tls_cipher_suite_tls_chacha20_poly1305_sha256,
    qsc_tls_cipher_suite_tls_aes_128_gcm_sha256
};

static const qsc_tls_named_group TLS_SOCKET_DEFAULT_GROUPS[] =
{
    qsc_tls_group_x25519,
    qsc_tls_group_secp256r1
};

static const qsc_tls_signature_scheme TLS_SOCKET_DEFAULT_SIGSCHEMES[] =
{
    qsc_tls_sig_ecdsa_secp256r1_sha256,
    qsc_tls_sig_ecdsa_secp384r1_sha384,
    qsc_tls_sig_ed25519
};

static const qsc_tls_named_group TLS_SOCKET_MLKEM_HYBRID_GROUPS[] =
{
    qsc_tls_group_x25519_mlkem768,
    qsc_tls_group_x25519,
    qsc_tls_group_secp256r1
};

static const qsc_tls_named_group TLS_SOCKET_EXPERIMENTAL_PQC_GROUPS[] =
{
    qsc_tls_group_x25519_mlkem768,
    qsc_tls_group_secp256r1_mlkem768,
    qsc_tls_group_mlkem768,
    qsc_tls_group_x25519,
    qsc_tls_group_secp256r1
};

static const qsc_tls_signature_scheme TLS_SOCKET_EXPERIMENTAL_PQC_SIGSCHEMES[] =
{
    qsc_tls_sig_mldsa65,
    qsc_tls_sig_mldsa44,
    qsc_tls_sig_mldsa87,
    qsc_tls_sig_ecdsa_secp256r1_sha256,
    qsc_tls_sig_ecdsa_secp384r1_sha384,
    qsc_tls_sig_ed25519
};

static const uint32_t TLS_SOCKET_OPTION_INT32_MAX = 2147483647UL;

static qsc_tls_socket_status tls_socket_status_from_tls(qsc_tls_status status)
{
    qsc_tls_socket_status res;

    res = qsc_tls_socket_status_tls_handshake_failed;

    if (status == qsc_tls_status_success)
    {
        res = qsc_tls_socket_status_success;
    }
    else if (status == qsc_tls_status_invalid_input)
    {
        res = qsc_tls_socket_status_invalid_input;
    }
    else if (status == qsc_tls_status_authentication_failure)
    {
        res = qsc_tls_socket_status_certificate_verify_failed;
    }
    else if (status == qsc_tls_status_not_supported)
    {
        res = qsc_tls_socket_status_policy_rejected;
    }
    else if (status == qsc_tls_status_invalid_state)
    {
        res = qsc_tls_socket_status_not_initialized;
    }
    else if (status == qsc_tls_status_buffer_too_small || status == qsc_tls_status_invalid_length || status == qsc_tls_status_invalid_message)
    {
        res = qsc_tls_socket_status_io_failed;
    }

    return res;
}

static qsc_tls_socket_status tls_socket_status_from_x509(qsc_x509w_status status)
{
    qsc_tls_socket_status res;

    res = qsc_tls_socket_status_certificate_load_failed;

    if (status == QSC_X509W_STATUS_SUCCESS)
    {
        res = qsc_tls_socket_status_success;
    }
    else if (status == QSC_X509W_STATUS_INVALID_INPUT)
    {
        res = qsc_tls_socket_status_invalid_input;
    }
    else if (status == QSC_X509W_STATUS_KEY_MISMATCH)
    {
        res = qsc_tls_socket_status_private_key_invalid;
    }
    else if (status == QSC_X509W_STATUS_VERIFY_ERROR || status == QSC_X509W_STATUS_HOSTNAME_MISMATCH || status == QSC_X509W_STATUS_PURPOSE_REJECTED)
    {
        res = qsc_tls_socket_status_certificate_verify_failed;
    }
    else if (status == QSC_X509W_STATUS_PROFILE_ERROR || status == QSC_X509W_STATUS_UNSUPPORTED)
    {
        res = qsc_tls_socket_status_policy_rejected;
    }

    return res;
}

static qsc_x509w_status tls_socket_x509_status_from_verify(qsc_x509_verify_status status)
{
    qsc_x509w_status res;

    res = QSC_X509W_STATUS_VERIFY_ERROR;

    switch (status)
    {
        case QSC_X509_VERIFY_STATUS_SUCCESS:
        {
            res = QSC_X509W_STATUS_SUCCESS;
            break;
        }
        case QSC_X509_VERIFY_STATUS_INVALID_INPUT:
        {
            res = QSC_X509W_STATUS_INVALID_INPUT;
            break;
        }
        case QSC_X509_VERIFY_STATUS_NAME_MISMATCH:
        {
            res = QSC_X509W_STATUS_HOSTNAME_MISMATCH;
            break;
        }
        case QSC_X509_VERIFY_STATUS_PURPOSE_REJECTED:
        {
            res = QSC_X509W_STATUS_PURPOSE_REJECTED;
            break;
        }
        default:
        {
            break;
        }
    }

    return res;
}

static const qsc_tls_qsc_x509_context* tls_socket_get_x509_context(const qsc_tls_socket_connection* connection)
{
    const qsc_tls_certificate_interface* iface;
    const qsc_tls_qsc_x509_context* xctx;

    iface = NULL;
    xctx = NULL;

    if (connection != NULL)
    {
        if (connection->role == qsc_tls_role_client)
        {
            iface = &connection->engine.state.client.config.certinterface;
        }
        else
        {
            iface = &connection->engine.state.server.config.clientcertinterface;
        }

        if (iface != NULL && iface->state != NULL &&
            iface->validatechain == qsc_tls_x509_validate_chain &&
            iface->verifycertificateverify == qsc_tls_x509_verify_certificate_verify)
        {
            xctx = (const qsc_tls_qsc_x509_context*)iface->state;
        }
    }

    return xctx;
}

static void tls_socket_copy_peer_text(char* output, size_t outputlen, const char* input)
{
    if (output != NULL && outputlen != 0U)
    {
        output[0U] = '\0';

        if (input != NULL && input[0U] != '\0')
        {
            (void)qsc_stringutils_copy_string(output, outputlen, input);
        }
    }
}

static void tls_socket_update_peer_info(qsc_tls_socket_connection* connection)
{
    const qsc_tls_qsc_x509_context* xctx;
    qsc_tls_socket_peer_info* peer;
    qsc_x509_verify_status vstatus;
    qsc_x509w_status xstatus;
    qsc_tls_alert_description alert;

    if (connection != NULL)
    {
        peer = &connection->peerinfo;
        qsc_memutils_clear(peer, sizeof(*peer));
        peer->cipher_suite = qsc_tls_socket_negotiated_cipher_suite(connection);
        peer->named_group = qsc_tls_socket_negotiated_group(connection);
        peer->signature_scheme = qsc_tls_socket_negotiated_signature_scheme(connection);
        peer->result = connection->lastresult;
        peer->x509_status = connection->lastresult.x509status;
        peer->verify_status = connection->lastresult.verifystatus;

        if (connection->role == qsc_tls_role_client)
        {
            peer->authenticated = connection->engine.state.client.serverauthenticated;
            peer->psk_accepted = connection->engine.state.client.pskaccepted;
            peer->early_data_accepted = connection->engine.state.client.earlydataaccepted;
            peer->alpn_selected = connection->engine.state.client.alpnselected;

            if (connection->engine.state.client.alpnselected == true)
            {
                qsc_memutils_copy(peer->selected_alpn, connection->engine.state.client.selectedalpn, connection->engine.state.client.selectedalpnlen);
                peer->selected_alpn[connection->engine.state.client.selectedalpnlen] = '\0';
            }
        }
        else
        {
            peer->authenticated = connection->engine.state.server.clientauthenticated;
            peer->psk_accepted = connection->engine.state.server.pskaccepted;
            peer->early_data_accepted = connection->engine.state.server.earlydataaccepted;
            peer->alpn_selected = connection->engine.state.server.alpnselected;

            if (connection->engine.state.server.alpnselected == true)
            {
                qsc_memutils_copy(peer->selected_alpn, connection->engine.state.server.selectedalpn, connection->engine.state.server.selectedalpnlen);
                peer->selected_alpn[connection->engine.state.server.selectedalpnlen] = '\0';
            }
        }

        xctx = tls_socket_get_x509_context(connection);

        if (xctx != NULL)
        {
            vstatus = xctx->lastverifystatus;
            xstatus = tls_socket_x509_status_from_verify(vstatus);
            alert = xctx->lastalert;
            peer->verify_status = vstatus;
            peer->x509_status = xstatus;
            peer->chain_valid = xctx->peersummary.chainvalid;
            peer->hostname_checked = xctx->peersummary.hostnamechecked;
            peer->hostname_matched = xctx->peersummary.hostnamevalid;

            if (xctx->peersummary.populated == true)
            {
                tls_socket_copy_peer_text(peer->subject, sizeof(peer->subject), xctx->peersummary.subject);
                tls_socket_copy_peer_text(peer->issuer, sizeof(peer->issuer), xctx->peersummary.issuer);
                tls_socket_copy_peer_text(peer->common_name, sizeof(peer->common_name), xctx->peersummary.commonname);
                tls_socket_copy_peer_text(peer->dns_name, sizeof(peer->dns_name), xctx->peersummary.dnsname);
            }

            connection->lastresult.x509status = xstatus;
            connection->lastresult.verifystatus = vstatus;
            connection->lastresult.alert = alert;
            peer->result = connection->lastresult;
        }
        else
        {
            peer->chain_valid = peer->authenticated;
            peer->hostname_matched = false;
            peer->hostname_checked = false;
        }
    }
}

static void tls_socket_set_result(qsc_tls_socket_result* result, qsc_tls_socket_status status, qsc_tls_status tlsstatus, qsc_socket_exceptions socketstatus, qsc_x509w_status x509status, qsc_x509_verify_status verifystatus, qsc_tls_alert_description alert)
{
    if (result != NULL)
    {
        result->status = status;
        result->tlsstatus = tlsstatus;
        result->socketstatus = socketstatus;
        result->x509status = x509status;
        result->verifystatus = verifystatus;
        result->alert = alert;
    }
}

static void tls_socket_emit_log(qsc_tls_socket_log_callback callback, void* state, qsc_tls_socket_log_level level, qsc_tls_socket_event event, const qsc_tls_socket_result* result, const char* message)
{
    if (callback != NULL)
    {
        callback(level, event, result, message, state);
    }
}

static void tls_socket_connection_log(qsc_tls_socket_connection* connection, qsc_tls_socket_log_level level, qsc_tls_socket_event event, const char* message)
{
    if (connection != NULL)
    {
        tls_socket_emit_log(connection->logcallback, connection->logstate, level, event, &connection->lastresult, message);
    }
}

static void tls_socket_server_log(qsc_tls_socket_server* server, qsc_tls_socket_log_level level, qsc_tls_socket_event event, const qsc_tls_socket_result* result, const char* message)
{
    if (server != NULL)
    {
        tls_socket_emit_log(server->onlog, server->logstate, level, event, result, message);
    }
}

static qsc_tls_socket_status tls_socket_validate_options(const qsc_tls_socket_options* options)
{
    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (options != NULL)
    {
        if (options->connect_timeout_ms <= TLS_SOCKET_OPTION_INT32_MAX &&
            options->handshake_timeout_ms <= TLS_SOCKET_OPTION_INT32_MAX &&
            options->receive_timeout_ms <= TLS_SOCKET_OPTION_INT32_MAX &&
            options->send_timeout_ms <= TLS_SOCKET_OPTION_INT32_MAX &&
            options->idle_timeout_ms <= TLS_SOCKET_OPTION_INT32_MAX &&
            options->receive_buffer_size <= (size_t)TLS_SOCKET_OPTION_INT32_MAX &&
            options->send_buffer_size <= (size_t)TLS_SOCKET_OPTION_INT32_MAX)
        {
            status = qsc_tls_socket_status_success;
        }
    }

    return status;
}

static bool tls_socket_ticket_policy_is_valid(const qsc_tls_socket_ticket_policy* policy)
{
    bool res;

    res = false;

    if (policy != NULL)
    {
        if (policy->lifetime_seconds > 0U && policy->lifetime_seconds <= QSC_TLS_SOCKET_TICKET_LIFETIME_MAX)
        {
            if (policy->renewal_interval_seconds == 0U || policy->renewal_interval_seconds < policy->lifetime_seconds)
            {
                res = true;
            }
        }
    }

    return res;
}

static bool tls_socket_session_ticket_is_valid_internal(const qsc_tls_session_ticket* ticket)
{
    bool res;

    res = false;

    if (ticket != NULL)
    {
        if (ticket->lifetime > 0U && ticket->lifetime <= QSC_TLS_SOCKET_TICKET_LIFETIME_MAX &&
            ticket->noncelen <= QSC_TLS_TICKET_NONCE_MAX_SIZE &&
            ticket->ticketlen > 0U && ticket->ticketlen <= QSC_TLS_TICKET_MAX_SIZE &&
            ticket->resumptionsecretlen > 0U && ticket->resumptionsecretlen <= QSC_TLS_HASH_MAX_SIZE &&
            ticket->suite != qsc_tls_cipher_suite_none)
        {
            res = true;
        }
    }

    return res;
}

static qsc_tls_socket_status tls_socket_set_io_timeouts(qsc_socket* sock, uint32_t receivems, uint32_t sendms)
{
    qsc_socket_exceptions se;
    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (sock != NULL && receivems <= TLS_SOCKET_OPTION_INT32_MAX && sendms <= TLS_SOCKET_OPTION_INT32_MAX)
    {
        se = qsc_socket_set_option(sock, qsc_socket_protocol_socket, qsc_socket_option_receive_time_out, (int32_t)receivems);
        status = (se == (qsc_socket_exceptions)QSC_SOCKET_RET_SUCCESS) ? qsc_tls_socket_status_success : qsc_tls_socket_status_io_failed;

        if (status == qsc_tls_socket_status_success)
        {
            se = qsc_socket_set_option(sock, qsc_socket_protocol_socket, qsc_socket_option_send_time_out, (int32_t)sendms);
            status = (se == (qsc_socket_exceptions)QSC_SOCKET_RET_SUCCESS) ? qsc_tls_socket_status_success : qsc_tls_socket_status_io_failed;
        }
    }

    return status;
}

static qsc_tls_socket_status tls_socket_apply_options(qsc_socket* sock, qsc_socket_address_families family, const qsc_tls_socket_options* options, bool listener)
{
    qsc_socket_exceptions se;
    qsc_tls_socket_status status;

    status = tls_socket_validate_options(options);

    if (sock == NULL)
    {
        status = qsc_tls_socket_status_invalid_input;
    }

    if (status == qsc_tls_socket_status_success)
    {
        if (listener == true)
        {
            se = qsc_socket_set_option(sock, qsc_socket_protocol_socket, qsc_socket_option_reuse_address, options->reuse_address == true ? 1 : 0);

            if (se != (qsc_socket_exceptions)QSC_SOCKET_RET_SUCCESS)
            {
                status = qsc_tls_socket_status_io_failed;
            }
        }

        if (status == qsc_tls_socket_status_success)
        {
            se = qsc_socket_set_option(sock, qsc_socket_protocol_tcp, qsc_socket_option_tcp_no_delay, options->no_delay == true ? 1 : 0);

            if (se != (qsc_socket_exceptions)QSC_SOCKET_RET_SUCCESS)
            {
                status = qsc_tls_socket_status_io_failed;
            }
        }

        if (status == qsc_tls_socket_status_success)
        {
            se = qsc_socket_set_option(sock, qsc_socket_protocol_socket, qsc_socket_option_keepalive, options->keep_alive == true ? 1 : 0);

            if (se != (qsc_socket_exceptions)QSC_SOCKET_RET_SUCCESS)
            {
                status = qsc_tls_socket_status_io_failed;
            }
        }

        if (status == qsc_tls_socket_status_success && family == qsc_socket_address_family_ipv6)
        {
            se = qsc_socket_set_option(sock, qsc_socket_protocol_ipv6, qsc_socket_option_ipv6_only, options->dual_stack == true ? 0 : 1);

            if (se != (qsc_socket_exceptions)QSC_SOCKET_RET_SUCCESS)
            {
                status = qsc_tls_socket_status_io_failed;
            }
        }

        if (status == qsc_tls_socket_status_success && options->receive_buffer_size != 0U)
        {
            se = qsc_socket_set_option(sock, qsc_socket_protocol_socket, qsc_socket_option_receive_buffer_size, (int32_t)options->receive_buffer_size);

            if (se != (qsc_socket_exceptions)QSC_SOCKET_RET_SUCCESS)
            {
                status = qsc_tls_socket_status_io_failed;
            }
        }

        if (status == qsc_tls_socket_status_success && options->send_buffer_size != 0U)
        {
            se = qsc_socket_set_option(sock, qsc_socket_protocol_socket, qsc_socket_option_send_buffer_size, (int32_t)options->send_buffer_size);

            if (se != (qsc_socket_exceptions)QSC_SOCKET_RET_SUCCESS)
            {
                status = qsc_tls_socket_status_io_failed;
            }
        }

        if (status == qsc_tls_socket_status_success)
        {
            status = tls_socket_set_io_timeouts(sock, options->receive_timeout_ms, options->send_timeout_ms);
        }

        if (status == qsc_tls_socket_status_success)
        {
            se = qsc_socket_set_blocking(sock, options->blocking);

            if (se != (qsc_socket_exceptions)QSC_SOCKET_RET_SUCCESS)
            {
                status = qsc_tls_socket_status_io_failed;
            }
        }
    }

    return status;
}

static qsc_tls_socket_status tls_socket_send_all(qsc_tls_socket_connection* connection, const uint8_t* input, size_t inlen)
{
    size_t sent;
    qsc_tls_socket_status status;

    sent = 0U;
    status = qsc_tls_socket_status_invalid_input;

    if (connection != NULL && input != NULL)
    {
        status = qsc_tls_socket_status_success;

        while (sent < inlen)
        {
            size_t written;
            size_t offset;

            written = 0U;
            offset = sent;
            status = qsc_tls_socket_send(connection, input + offset, inlen - offset, &written);

            if (status != qsc_tls_socket_status_success || written == 0U)
            {
                if (status == qsc_tls_socket_status_success)
                {
                    status = qsc_tls_socket_status_io_failed;
                }

                break;
            }

            sent += written;
        }
    }

    return status;
}

static qsc_tls_socket_status tls_socket_receive_exact(qsc_tls_socket_connection* connection, uint8_t* output, size_t outlen)
{
    size_t total;
    qsc_tls_socket_status status;

    total = 0U;
    status = qsc_tls_socket_status_invalid_input;

    if (connection != NULL && output != NULL)
    {
        status = qsc_tls_socket_status_success;

        while (total < outlen)
        {
            size_t got;

            got = 0U;
            status = qsc_tls_socket_receive(connection, output + total, outlen - total, &got);

            if (status != qsc_tls_socket_status_success || got == 0U)
            {
                if (status == qsc_tls_socket_status_success)
                {
                    status = qsc_tls_socket_status_closed;
                }

                break;
            }

            total += got;
        }
    }

    return status;
}

static bool tls_socket_frame_send_input_valid(const uint8_t* input, size_t inlen)
{
    bool res;

    res = false;

    if (inlen <= QSC_TLS_SOCKET_FRAME_SIZE_MAX)
    {
        if (inlen == 0U || input != NULL)
        {
            res = true;
        }
    }

    return res;
}

static bool tls_socket_frame_receive_output_valid(const uint8_t* output, size_t outlen)
{
    bool res;

    res = false;

    if (output != NULL || outlen == 0U)
    {
        res = true;
    }

    return res;
}

static qsc_tls_socket_status tls_socket_frame_status_from_length(uint32_t framelen, size_t outlen)
{
    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_success;

    if (framelen > QSC_TLS_SOCKET_FRAME_SIZE_MAX)
    {
        status = qsc_tls_socket_status_io_failed;
    }
    else if ((size_t)framelen > outlen)
    {
        status = qsc_tls_socket_status_invalid_input;
    }

    return status;
}

static bool tls_socket_context_has_policy(const qsc_tls_socket_context* context)
{
    bool res;

    res = false;

    if (context != NULL && context->initialized == true && context->ciphersuitecount != 0U && context->groupcount != 0U && context->sigschemecount != 0U)
    {
        res = true;
    }

    return res;
}

static qsc_tls_socket_status tls_socket_configure_bridge(qsc_tls_socket_context* context)
{
    qsc_x509w_status xs;
    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (context != NULL)
    {
        xs = qsc_x509w_tls_bridge_configure(&context->bridge, &context->truststore, &context->certificateprofile);
        status = tls_socket_status_from_x509(xs);

        if (status == qsc_tls_socket_status_success)
        {
            context->hastruststore = true;
        }
    }

    return status;
}

static qsc_tls_socket_status tls_socket_build_client_config(const qsc_tls_socket_context* context, const char* hostname, const qsc_tls_session_ticket* ticket, bool enableearlydata, qsc_tls_client_config* config)
{
    const qsc_tls_certificate_interface* iface;
    const qsc_tls_session_ticket* offered;
    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;
    offered = ticket;

    if (context != NULL && config != NULL)
    {
        if (tls_socket_context_has_policy(context) == true)
        {
            qsc_memutils_clear(config, sizeof(*config));
            config->ciphersuites = context->ciphersuites;
            config->ciphersuitecount = context->ciphersuitecount;
            config->groups = context->groups;
            config->groupcount = context->groupcount;
            config->sigschemes = context->sigschemes;
            config->sigschemecount = context->sigschemecount;
            config->alpn = context->alpn;

            if (context->ticketpolicy.enabled == true)
            {
                if (offered == NULL && context->hassessionticket == true && tls_socket_session_ticket_is_valid_internal(&context->sessionticket) == true)
                {
                    offered = &context->sessionticket;
                }

                if (offered != NULL && tls_socket_session_ticket_is_valid_internal(offered) == false)
                {
                    offered = NULL;
                    enableearlydata = false;
                }

                if (context->ticketpolicy.allow_early_data == false)
                {
                    enableearlydata = false;
                }
            }
            else
            {
                offered = NULL;
                enableearlydata = false;
            }

            config->offeredticket = offered;
            config->enableearlydata = enableearlydata;
            iface = qsc_x509w_tls_bridge_get_interface(&context->bridge);

            if (iface != NULL)
            {
                config->certinterface = *iface;
                config->hostname = hostname;
                status = qsc_tls_socket_status_success;
            }
            else
            {
                status = qsc_tls_socket_status_invalid_input;
            }
        }
        else
        {
            status = qsc_tls_socket_status_not_initialized;
        }
    }

    return status;
}

static qsc_tls_socket_status tls_socket_build_server_config(const qsc_tls_socket_context* context, qsc_tls_server_config* config)
{
    const qsc_tls_certificate_interface* iface;
    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (context != NULL && config != NULL)
    {
        if (tls_socket_context_has_policy(context) == true && context->hasidentity == true)
        {
            qsc_memutils_clear(config, sizeof(*config));
            config->ciphersuitepreference = context->ciphersuites;
            config->ciphersuitepreferencecount = context->ciphersuitecount;
            config->groupspreference = context->groups;
            config->groupspreferencecount = context->groupcount;
            config->sigschemepreference = context->sigschemes;
            config->sigschemepreferencecount = context->sigschemecount;
            config->alpn = context->alpn;
            iface = qsc_x509w_tls_bridge_get_interface(&context->bridge);

            if (iface != NULL && context->localcert.chainlength != 0U && context->localcert.privatekeylen <= sizeof(config->localcert.signprivatekey))
            {
                config->clientcertinterface = *iface;
                config->requestclientauth = context->requestclientauth;
                config->requireclientauth = context->requireclientauth;
                config->clientauthcallback = context->clientauthcallback;
                config->clientauthstate = context->clientauthstate;
                config->requireclientauthorization = context->requireclientauthorization;
                config->requiresni = context->requiresni;

                if (qsc_tls_server_config_set_local_certificate(config, context->localcert.chain, context->localcert.chainlength,
                    context->localcert.verifyscheme, context->localcert.privatekeydata, context->localcert.privatekeylen) == qsc_tls_status_success)
                {
                    status = qsc_tls_socket_status_success;
                }
                else
                {
                    status = qsc_tls_socket_status_invalid_input;
                }

                for (size_t i = 0U; i < context->sniidentitycount && status == qsc_tls_socket_status_success; ++i)
                {
                    qsc_tls_server_config tcfg;

                    qsc_memutils_clear(&tcfg, sizeof(tcfg));

                    if (qsc_tls_server_config_set_local_certificate(&tcfg, context->snilocalcerts[i].chain, context->snilocalcerts[i].chainlength,
                        context->snilocalcerts[i].verifyscheme, context->snilocalcerts[i].privatekeydata, context->snilocalcerts[i].privatekeylen) != qsc_tls_status_success)
                    {
                        status = qsc_tls_socket_status_invalid_input;
                    }
                    else if (qsc_tls_server_config_add_certificate_identity(config, context->snihostnames[i], &tcfg.localcert) != qsc_tls_status_success)
                    {
                        status = qsc_tls_socket_status_invalid_input;
                    }
                }
            }
            else
            {
                status = qsc_tls_socket_status_invalid_input;
            }
        }
        else
        {
            status = qsc_tls_socket_status_not_initialized;
        }
    }

    return status;
}

static qsc_tls_socket_status tls_socket_connection_handshake(qsc_tls_socket_connection* connection)
{
    qsc_tls_status st;
    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (connection != NULL)
    {
        st = qsc_tls_io_attach(&connection->io, &connection->engine, &connection->socket);
        status = tls_socket_status_from_tls(st);

        if (status == qsc_tls_socket_status_success)
        {
            if (connection->socketoptions.handshake_timeout_ms != 0U)
            {
                status = tls_socket_set_io_timeouts(&connection->socket, connection->socketoptions.handshake_timeout_ms, connection->socketoptions.handshake_timeout_ms);
            }

            if (status == qsc_tls_socket_status_success)
            {
                tls_socket_connection_log(connection, qsc_tls_socket_log_level_info, qsc_tls_socket_event_handshake_start, "TLS handshake started");
                st = qsc_tls_io_handshake(&connection->io);
                status = tls_socket_status_from_tls(st);
                connection->handshaked = (status == qsc_tls_socket_status_success);

                if (connection->handshaked == true)
                {
                    tls_socket_connection_log(connection, qsc_tls_socket_log_level_info, qsc_tls_socket_event_handshake_complete, "TLS handshake completed");
                }
            }

            (void)tls_socket_set_io_timeouts(&connection->socket, connection->socketoptions.receive_timeout_ms, connection->socketoptions.send_timeout_ms);
        }

        tls_socket_set_result(&connection->lastresult, status, st, (qsc_socket_exceptions)QSC_SOCKET_RET_SUCCESS, QSC_X509W_STATUS_SUCCESS, QSC_X509_VERIFY_STATUS_SUCCESS, qsc_tls_alert_close_notify);
        tls_socket_update_peer_info(connection);
    }

    return status;
}

static qsc_tls_socket_status tls_socket_client_connect_common(qsc_tls_socket_connection* connection, const qsc_tls_socket_context* context, const char* hostname, 
    const char* service, const qsc_ipinfo_ipv4_address* ipv4, const qsc_ipinfo_ipv6_address* ipv6, uint16_t port, const qsc_tls_session_ticket* ticket, bool enableearlydata)
{
    qsc_tls_client_config config;
    qsc_socket_exceptions se;
    qsc_tls_status st;
    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (connection != NULL && context != NULL)
    {
        qsc_tls_socket_connection_initialize(connection);
        connection->socketoptions = context->socketoptions;
        connection->ticketpolicy = context->ticketpolicy;
        connection->logcallback = context->logcallback;
        connection->logstate = context->logstate;
        qsc_socket_client_initialize(&connection->socket);

        if (hostname != NULL && service != NULL)
        {
            se = qsc_socket_client_connect_host(&connection->socket, hostname, service);
            connection->family = qsc_socket_client_address_family(&connection->socket);
        }
        else if (ipv4 != NULL)
        {
            se = qsc_socket_client_connect_ipv4(&connection->socket, ipv4, port);
            connection->family = qsc_socket_address_family_ipv4;
        }
        else if (ipv6 != NULL)
        {
            se = qsc_socket_client_connect_ipv6(&connection->socket, ipv6, port);
            connection->family = qsc_socket_address_family_ipv6;
        }
        else
        {
            se = qsc_socket_exception_invalid_protocol;
        }

        if (se == (qsc_socket_exceptions)QSC_SOCKET_RET_SUCCESS)
        {
            connection->connected = true;
            connection->owns_socket = true;
            connection->role = qsc_tls_role_client;
            status = tls_socket_apply_options(&connection->socket, connection->family, &connection->socketoptions, false);
            tls_socket_connection_log(connection, qsc_tls_socket_log_level_info, qsc_tls_socket_event_connect, "TCP socket connected");

            if (status == qsc_tls_socket_status_success)
            {
                status = tls_socket_build_client_config(context, hostname, ticket, enableearlydata, &config);
            }

            if (status == qsc_tls_socket_status_success)
            {
                st = qsc_tls_engine_initialize_client(&connection->engine, &config);
                status = tls_socket_status_from_tls(st);

                if (status == qsc_tls_socket_status_success)
                {
                    status = tls_socket_connection_handshake(connection);
                }
                else
                {
                    tls_socket_set_result(&connection->lastresult, status, st, se, QSC_X509W_STATUS_SUCCESS, QSC_X509_VERIFY_STATUS_SUCCESS, qsc_tls_alert_internal_error);
                }
            }
        }
        else
        {
            status = qsc_tls_socket_status_socket_connect_failed;
            tls_socket_set_result(&connection->lastresult, status, qsc_tls_status_failure, se, QSC_X509W_STATUS_SUCCESS, QSC_X509_VERIFY_STATUS_SUCCESS, qsc_tls_alert_internal_error);
        }
    }

    return status;
}


static size_t tls_socket_server_active_count(qsc_tls_socket_server* server)
{
    size_t count;
    size_t i;

    count = 0U;

    if (server != NULL)
    {
        if (server->poolmutex != NULL)
        {
            qsc_async_mutex_lock(server->poolmutex);
        }

        for (i = 0U; i < server->maxclients && i < QSC_TLS_SOCKET_SERVER_CONNECTIONS_MAX; ++i)
        {
            if (server->active[i] == true)
            {
                ++count;
            }
        }

        if (server->poolmutex != NULL)
        {
            qsc_async_mutex_unlock(server->poolmutex);
        }
    }

    return count;
}


static bool tls_socket_thread_is_valid(qsc_thread thread)
{
    bool res;

#if defined(QSC_SYSTEM_OS_WINDOWS)
    res = (thread != NULL);
#else
    res = (thread != (qsc_thread)0);
#endif

    return res;
}

static void tls_socket_thread_clear(qsc_thread* thread)
{
    if (thread != NULL)
    {
#if defined(QSC_SYSTEM_OS_WINDOWS)
        *thread = NULL;
#else
        *thread = (qsc_thread)0;
#endif
    }
}

static bool tls_socket_server_acquire_slot(qsc_tls_socket_server* server, size_t* index)
{
    bool res;
    size_t i;
    size_t maxc;

    res = false;

    if (index != NULL)
    {
        *index = 0U;
    }

    if (server != NULL && index != NULL)
    {
        maxc = server->maxclients;

        if (maxc > QSC_TLS_SOCKET_SERVER_CONNECTIONS_MAX)
        {
            maxc = QSC_TLS_SOCKET_SERVER_CONNECTIONS_MAX;
        }

        if (server->poolmutex != NULL)
        {
            qsc_async_mutex_lock(server->poolmutex);
        }

        for (i = 0U; i < maxc; ++i)
        {
            if (server->active[i] == false)
            {
                if (server->started[i] == true)
                {
                    if (tls_socket_thread_is_valid(server->workerthreads[i]) == true)
                    {
                        qsc_async_thread_wait(server->workerthreads[i]);
                    }

                    tls_socket_thread_clear(&server->workerthreads[i]);
                    server->started[i] = false;
                }

                qsc_tls_socket_connection_initialize(&server->connections[i]);
                server->active[i] = true;
                server->workerstates[i].server = server;
                server->workerstates[i].index = i;
                *index = i;
                res = true;
                break;
            }
        }

        if (server->poolmutex != NULL)
        {
            qsc_async_mutex_unlock(server->poolmutex);
        }
    }

    return res;
}

static void tls_socket_server_release_slot(qsc_tls_socket_server* server, size_t index)
{
    if (server != NULL && index < QSC_TLS_SOCKET_SERVER_CONNECTIONS_MAX)
    {
        if (server->poolmutex != NULL)
        {
            qsc_async_mutex_lock(server->poolmutex);
        }

        server->active[index] = false;
        server->workerstates[index].server = NULL;
        server->workerstates[index].index = 0U;
        qsc_tls_socket_connection_dispose(&server->connections[index]);

        if (server->poolmutex != NULL)
        {
            qsc_async_mutex_unlock(server->poolmutex);
        }
    }
}

static void tls_socket_server_connection_worker(void* state)
{
    uint8_t buffer[QSC_TLS_SOCKET_SERVER_BUFFER_SIZE] = { 0U };
    qsc_tls_socket_server_worker_state* wstate;
    qsc_tls_socket_server* server;
    qsc_tls_socket_connection* connection;
    size_t msglen;
    size_t index;
    qsc_tls_socket_status status;

    wstate = (qsc_tls_socket_server_worker_state*)state;

    if (wstate != NULL && wstate->server != NULL && wstate->index < QSC_TLS_SOCKET_SERVER_CONNECTIONS_MAX)
    {
        server = wstate->server;
        index = wstate->index;
        connection = &server->connections[index];

        tls_socket_server_log(server, qsc_tls_socket_log_level_info, qsc_tls_socket_event_worker_start, &connection->lastresult, "TLS socket worker started");

        if (server->onconnect != NULL)
        {
            server->onconnect(connection, server->callbackstate);
        }

        if (connection->role == qsc_tls_role_server && connection->ticketpolicy.enabled == true && connection->ticketpolicy.auto_send_server_ticket == true)
        {
            if (qsc_tls_socket_server_send_session_ticket(connection, connection->ticketpolicy.lifetime_seconds, &connection->lastticket) == qsc_tls_socket_status_success)
            {
                connection->haslastticket = true;
            }
        }

        while (server->running == true && connection->connected == true)
        {
            msglen = 0U;
            status = qsc_tls_socket_receive(connection, buffer, sizeof(buffer), &msglen);

            if (status != qsc_tls_socket_status_success)
            {
                if (server->onerror != NULL)
                {
                    server->onerror(connection, status, server->callbackstate);
                }

                break;
            }

            if (msglen != 0U && server->onreceive != NULL)
            {
                server->onreceive(connection, buffer, msglen, server->callbackstate);
            }
        }

        if (server->ondisconnect != NULL)
        {
            server->ondisconnect(connection, server->callbackstate);
        }

        tls_socket_server_log(server, qsc_tls_socket_log_level_info, qsc_tls_socket_event_worker_stop, &connection->lastresult, "TLS socket worker stopped");
        tls_socket_server_release_slot(server, index);
    }
}

void qsc_tls_socket_result_clear(qsc_tls_socket_result* result)
{
    QSC_ASSERT(result != NULL);

    if (result != NULL)
    {
        qsc_memutils_clear(result, sizeof(*result));
        result->status = qsc_tls_socket_status_success;
        result->tlsstatus = qsc_tls_status_success;
        result->socketstatus = (qsc_socket_exceptions)QSC_SOCKET_RET_SUCCESS;
        result->x509status = QSC_X509W_STATUS_SUCCESS;
        result->verifystatus = QSC_X509_VERIFY_STATUS_SUCCESS;
        result->alert = qsc_tls_alert_close_notify;
    }
}

const char* qsc_tls_socket_status_string(qsc_tls_socket_status status)
{
    const char* res;

    switch (status)
    {
        case qsc_tls_socket_status_success:
        {
            res = "success";
            break;
        }
        case qsc_tls_socket_status_invalid_input:
        {
            res = "invalid input";
            break;
        }
        case qsc_tls_socket_status_not_initialized:
        {
            res = "not initialized";
            break;
        }
        case qsc_tls_socket_status_socket_start_failed:
        {
            res = "socket start failed";
            break;
        }
        case qsc_tls_socket_status_socket_connect_failed:
        {
            res = "socket connect failed";
            break;
        }
        case qsc_tls_socket_status_socket_bind_failed:
        {
            res = "socket bind failed";
            break;
        }
        case qsc_tls_socket_status_socket_listen_failed:
        {
            res = "socket listen failed";
            break;
        }
        case qsc_tls_socket_status_socket_accept_failed:
        {
            res = "socket accept failed";
            break;
        }
        case qsc_tls_socket_status_tls_initialize_failed:
        {
            res = "TLS initialize failed";
            break;
        }
        case qsc_tls_socket_status_tls_handshake_failed:
        {
            res = "TLS handshake failed";
            break;
        }
        case qsc_tls_socket_status_certificate_load_failed:
        {
            res = "certificate load failed";
            break;
        }
        case qsc_tls_socket_status_certificate_verify_failed:
        {
            res = "certificate verify failed";
            break;
        }
        case qsc_tls_socket_status_private_key_invalid:
        {
            res = "private key invalid";
            break;
        }
        case qsc_tls_socket_status_policy_rejected:
        {
            res = "policy rejected";
            break;
        }
        case qsc_tls_socket_status_io_failed:
        {
            res = "I/O failed";
            break;
        }
        case qsc_tls_socket_status_closed:
        {
            res = "closed";
            break;
        }
        default:
        {
            res = "internal error";
            break;
        }
    }

    return res;
}

void qsc_tls_socket_options_initialize_default(qsc_tls_socket_options* options)
{
    QSC_ASSERT(options != NULL);

    if (options != NULL)
    {
        qsc_memutils_clear(options, sizeof(*options));
        options->receive_timeout_ms = 30000U;
        options->send_timeout_ms = 30000U;
        options->handshake_timeout_ms = 30000U;
        options->reuse_address = true;
        options->no_delay = true;
        options->keep_alive = false;
        options->dual_stack = true;
        options->blocking = true;
        options->receive_buffer_size = QSC_TLS_SOCKET_SERVER_BUFFER_SIZE;
        options->send_buffer_size = QSC_TLS_SOCKET_SERVER_BUFFER_SIZE;
    }
}

void qsc_tls_socket_ticket_policy_initialize_default(qsc_tls_socket_ticket_policy* policy)
{
    QSC_ASSERT(policy != NULL);

    if (policy != NULL)
    {
        qsc_memutils_clear(policy, sizeof(*policy));
        policy->enabled = false;
        policy->allow_early_data = false;
        policy->auto_send_server_ticket = false;
        policy->lifetime_seconds = 86400U;
        policy->renewal_interval_seconds = 0U;
    }
}

void qsc_tls_socket_context_initialize(qsc_tls_socket_context* context)
{
    QSC_ASSERT(context != NULL);

    if (context != NULL)
    {
        qsc_memutils_clear(context, sizeof(*context));
        qsc_x509w_trust_store_initialize(&context->truststore);
        qsc_x509w_server_identity_initialize(&context->identity);
        qsc_x509w_tls_bridge_initialize(&context->bridge);
        qsc_x509w_tls_local_certificate_initialize(&context->localcert);

        for (size_t i = 0U; i < QSC_TLS_SOCKET_SERVER_IDENTITY_MAX; ++i)
        {
            qsc_x509w_tls_local_certificate_initialize(&context->snilocalcerts[i]);
        }

        qsc_x509w_profile_initialize(&context->certificateprofile);
        qsc_tls_socket_options_initialize_default(&context->socketoptions);
        qsc_tls_socket_ticket_policy_initialize_default(&context->ticketpolicy);
        context->initialized = true;
    }
}

void qsc_tls_socket_context_dispose(qsc_tls_socket_context* context)
{
    QSC_ASSERT(context != NULL);

    if (context != NULL)
    {
        qsc_x509w_trust_store_clear(&context->truststore);
        qsc_x509w_server_identity_clear(&context->identity);
        qsc_tls_session_ticket_dispose(&context->sessionticket);
        qsc_memutils_secure_erase(context, sizeof(*context));
    }
}

qsc_tls_socket_status qsc_tls_socket_context_set_cipher_suites(qsc_tls_socket_context* context, const qsc_tls_cipher_suite* suites, size_t suitecount)
{
    QSC_ASSERT(context != NULL);
    QSC_ASSERT(suites != NULL);

    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (context != NULL && suites != NULL && suitecount != 0U && suitecount <= QSC_TLS_SOCKET_CIPHER_SUITE_MAX)
    {
        qsc_memutils_clear(context->ciphersuites, sizeof(context->ciphersuites));
        qsc_memutils_copy(context->ciphersuites, suites, suitecount * sizeof(qsc_tls_cipher_suite));
        context->ciphersuitecount = suitecount;
        status = qsc_tls_socket_status_success;
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_context_set_named_groups(qsc_tls_socket_context* context, const qsc_tls_named_group* groups, size_t groupcount)
{
    QSC_ASSERT(context != NULL);

    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (context != NULL && groups != NULL && groupcount != 0U && groupcount <= QSC_TLS_SOCKET_GROUP_MAX)
    {
        qsc_memutils_clear(context->groups, sizeof(context->groups));
        qsc_memutils_copy(context->groups, groups, groupcount * sizeof(qsc_tls_named_group));
        context->groupcount = groupcount;
        status = qsc_tls_socket_status_success;
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_context_set_signature_schemes(qsc_tls_socket_context* context, const qsc_tls_signature_scheme* schemes, size_t sigschemecount)
{
    QSC_ASSERT(context != NULL);
    QSC_ASSERT(schemes != NULL);

    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (context != NULL && schemes != NULL && sigschemecount != 0U && sigschemecount <= QSC_TLS_SOCKET_SIGNATURE_SCHEME_MAX)
    {
        qsc_memutils_clear(context->sigschemes, sizeof(context->sigschemes));
        qsc_memutils_copy(context->sigschemes, schemes, sigschemecount * sizeof(qsc_tls_signature_scheme));
        context->sigschemecount = sigschemecount;
        status = qsc_tls_socket_status_success;
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_context_set_default_client_policy(qsc_tls_socket_context* context)
{
    QSC_ASSERT(context != NULL);

    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (context != NULL)
    {
        qsc_x509w_profile_apply_preset(&context->certificateprofile, QSC_X509W_PROFILE_PRESET_TLS_SERVER);
        status = qsc_tls_socket_context_set_cipher_suites(context, TLS_SOCKET_DEFAULT_SUITES, sizeof(TLS_SOCKET_DEFAULT_SUITES) / sizeof(TLS_SOCKET_DEFAULT_SUITES[0]));

        if (status == qsc_tls_socket_status_success)
        {
            status = qsc_tls_socket_context_set_named_groups(context, TLS_SOCKET_DEFAULT_GROUPS, sizeof(TLS_SOCKET_DEFAULT_GROUPS) / sizeof(TLS_SOCKET_DEFAULT_GROUPS[0]));
        }

        if (status == qsc_tls_socket_status_success)
        {
            status = qsc_tls_socket_context_set_signature_schemes(context, TLS_SOCKET_DEFAULT_SIGSCHEMES, sizeof(TLS_SOCKET_DEFAULT_SIGSCHEMES) / sizeof(TLS_SOCKET_DEFAULT_SIGSCHEMES[0]));
        }

        if (status == qsc_tls_socket_status_success)
        {
            status = tls_socket_configure_bridge(context);
        }
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_context_set_default_server_policy(qsc_tls_socket_context* context)
{
    QSC_ASSERT(context != NULL);

    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (context != NULL)
    {
        qsc_x509w_profile_apply_preset(&context->certificateprofile, QSC_X509W_PROFILE_PRESET_TLS_CLIENT);
        status = qsc_tls_socket_context_set_cipher_suites(context, TLS_SOCKET_DEFAULT_SUITES, sizeof(TLS_SOCKET_DEFAULT_SUITES) / sizeof(TLS_SOCKET_DEFAULT_SUITES[0]));

        if (status == qsc_tls_socket_status_success)
        {
            status = qsc_tls_socket_context_set_named_groups(context, TLS_SOCKET_DEFAULT_GROUPS, sizeof(TLS_SOCKET_DEFAULT_GROUPS) / sizeof(TLS_SOCKET_DEFAULT_GROUPS[0]));
        }

        if (status == qsc_tls_socket_status_success)
        {
            status = qsc_tls_socket_context_set_signature_schemes(context, TLS_SOCKET_DEFAULT_SIGSCHEMES, sizeof(TLS_SOCKET_DEFAULT_SIGSCHEMES) / sizeof(TLS_SOCKET_DEFAULT_SIGSCHEMES[0]));
        }

        if (status == qsc_tls_socket_status_success)
        {
            status = tls_socket_configure_bridge(context);
        }
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_context_set_mlkem_hybrid_policy(qsc_tls_socket_context* context)
{
    QSC_ASSERT(context != NULL);

    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (context != NULL)
    {
        status = qsc_tls_socket_context_set_cipher_suites(context, TLS_SOCKET_DEFAULT_SUITES, sizeof(TLS_SOCKET_DEFAULT_SUITES) / sizeof(TLS_SOCKET_DEFAULT_SUITES[0]));

        if (status == qsc_tls_socket_status_success)
        {
            status = qsc_tls_socket_context_set_named_groups(context, TLS_SOCKET_MLKEM_HYBRID_GROUPS, sizeof(TLS_SOCKET_MLKEM_HYBRID_GROUPS) / sizeof(TLS_SOCKET_MLKEM_HYBRID_GROUPS[0]));
        }

        if (status == qsc_tls_socket_status_success)
        {
            status = qsc_tls_socket_context_set_signature_schemes(context, TLS_SOCKET_DEFAULT_SIGSCHEMES, sizeof(TLS_SOCKET_DEFAULT_SIGSCHEMES) / sizeof(TLS_SOCKET_DEFAULT_SIGSCHEMES[0]));
        }

        if (status == qsc_tls_socket_status_success)
        {
            status = tls_socket_configure_bridge(context);
        }
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_context_set_experimental_pqc_policy(qsc_tls_socket_context* context)
{
    QSC_ASSERT(context != NULL);

    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (context != NULL)
    {
        status = qsc_tls_socket_context_set_cipher_suites(context, TLS_SOCKET_DEFAULT_SUITES, sizeof(TLS_SOCKET_DEFAULT_SUITES) / sizeof(TLS_SOCKET_DEFAULT_SUITES[0]));

        if (status == qsc_tls_socket_status_success)
        {
            status = qsc_tls_socket_context_set_named_groups(context, TLS_SOCKET_EXPERIMENTAL_PQC_GROUPS, sizeof(TLS_SOCKET_EXPERIMENTAL_PQC_GROUPS) / sizeof(TLS_SOCKET_EXPERIMENTAL_PQC_GROUPS[0]));
        }

        if (status == qsc_tls_socket_status_success)
        {
            status = qsc_tls_socket_context_set_signature_schemes(context, TLS_SOCKET_EXPERIMENTAL_PQC_SIGSCHEMES, sizeof(TLS_SOCKET_EXPERIMENTAL_PQC_SIGSCHEMES) / sizeof(TLS_SOCKET_EXPERIMENTAL_PQC_SIGSCHEMES[0]));
        }

        if (status == qsc_tls_socket_status_success)
        {
            status = tls_socket_configure_bridge(context);
        }
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_context_set_strict_policy(qsc_tls_socket_context* context)
{
    QSC_ASSERT(context != NULL);

    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (context != NULL)
    {
        qsc_x509w_profile_apply_preset(&context->certificateprofile, QSC_X509W_PROFILE_PRESET_STRICT_REVOCATION);
        context->allowunverified = false;
        status = tls_socket_configure_bridge(context);
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_context_set_development_policy(qsc_tls_socket_context* context)
{
    QSC_ASSERT(context != NULL);

    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (context != NULL)
    {
        qsc_x509w_profile_apply_preset(&context->certificateprofile, QSC_X509W_PROFILE_PRESET_DEVELOPMENT);
        context->allowunverified = true;
        status = tls_socket_configure_bridge(context);
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_context_load_trust_anchor_file(qsc_tls_socket_context* context, const char* path, bool selfsigned)
{
    QSC_ASSERT(context != NULL);
    QSC_ASSERT(path != NULL);

    qsc_x509w_status xs;
    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (context != NULL && path != NULL)
    {
        xs = qsc_x509w_trust_store_add_anchor_file(&context->truststore, path, selfsigned);
        status = tls_socket_status_from_x509(xs);

        if (status == qsc_tls_socket_status_success)
        {
            status = tls_socket_configure_bridge(context);
        }
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_context_load_trust_anchor_bundle_file(qsc_tls_socket_context* context, const char* path, bool selfsigned)
{
    QSC_ASSERT(context != NULL);
    QSC_ASSERT(path != NULL);

    qsc_x509w_status xs;
    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (context != NULL && path != NULL)
    {
        xs = qsc_x509w_trust_store_add_anchor_bundle_file(&context->truststore, path, selfsigned);
        status = tls_socket_status_from_x509(xs);

        if (status == qsc_tls_socket_status_success)
        {
            status = tls_socket_configure_bridge(context);
        }
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_context_load_crl_file(qsc_tls_socket_context* context, const char* path)
{
    QSC_ASSERT(context != NULL);
    QSC_ASSERT(path != NULL);

    qsc_x509w_status xs;
    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (context != NULL && path != NULL)
    {
        xs = qsc_x509w_trust_store_add_crl_file(&context->truststore, path);
        status = tls_socket_status_from_x509(xs);

        if (status == qsc_tls_socket_status_success)
        {
            status = tls_socket_configure_bridge(context);
        }
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_context_load_server_identity_files(qsc_tls_socket_context* context, const char* certificatechainpath, const char* privatekeypath, qsc_tls_signature_scheme verifyscheme)
{
    QSC_ASSERT(context != NULL);
    QSC_ASSERT(certificatechainpath != NULL);
    QSC_ASSERT(privatekeypath != NULL);

    qsc_x509w_status xs;
    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (context != NULL && certificatechainpath != NULL && privatekeypath != NULL)
    {
        xs = qsc_x509w_server_identity_load_files(&context->identity, certificatechainpath, privatekeypath);
        status = tls_socket_status_from_x509(xs);

        if (status == qsc_tls_socket_status_success)
        {
            xs = qsc_x509w_tls_local_certificate_from_identity(&context->identity, verifyscheme, &context->localcert);
            status = tls_socket_status_from_x509(xs);
        }

        if (status == qsc_tls_socket_status_success)
        {
            context->hasidentity = true;
        }
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_context_add_server_identity_files(qsc_tls_socket_context* context, const char* hostname, const char* certificatechainpath, const char* privatekeypath, qsc_tls_signature_scheme verifyscheme)
{
    QSC_ASSERT(context != NULL);
    QSC_ASSERT(hostname != NULL);
    QSC_ASSERT(certificatechainpath != NULL);
    QSC_ASSERT(privatekeypath != NULL);

    qsc_x509w_server_identity identity;
    qsc_x509w_status xs;
    qsc_tls_socket_status status;
    size_t hostlen;

    status = qsc_tls_socket_status_invalid_input;

    if (context != NULL && hostname != NULL && certificatechainpath != NULL && privatekeypath != NULL && context->sniidentitycount < QSC_TLS_SOCKET_SERVER_IDENTITY_MAX)
    {
        hostlen = 0U;

        while (hostname[hostlen] != '\0' && hostlen <= QSC_TLS_MAX_HOSTNAME_SIZE)
        {
            ++hostlen;
        }

        if (hostlen != 0U && hostlen <= QSC_TLS_MAX_HOSTNAME_SIZE)
        {
            qsc_x509w_server_identity_initialize(&identity);
            xs = qsc_x509w_server_identity_load_files(&identity, certificatechainpath, privatekeypath);
            status = tls_socket_status_from_x509(xs);

            if (status == qsc_tls_socket_status_success)
            {
                xs = qsc_x509w_tls_local_certificate_from_identity(&identity, verifyscheme, &context->snilocalcerts[context->sniidentitycount]);
                status = tls_socket_status_from_x509(xs);
            }

            if (status == qsc_tls_socket_status_success)
            {
                qsc_memutils_copy(context->snihostnames[context->sniidentitycount], hostname, hostlen);
                context->snihostnames[context->sniidentitycount][hostlen] = '\0';
                ++context->sniidentitycount;
            }

            qsc_x509w_server_identity_clear(&identity);
        }
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_context_set_sni_required(qsc_tls_socket_context* context, bool required)
{
    QSC_ASSERT(context != NULL);

    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (context != NULL)
    {
        context->requiresni = required;
        status = qsc_tls_socket_status_success;
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_context_set_client_auth(qsc_tls_socket_context* context, bool requestclientauth, bool requireclientauth)
{
    QSC_ASSERT(context != NULL);

    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (context != NULL)
    {
        context->requestclientauth = requestclientauth || requireclientauth;
        context->requireclientauth = requireclientauth;
        status = qsc_tls_socket_status_success;
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_context_set_client_authorization(qsc_tls_socket_context* context, qsc_tls_client_authorization_callback callback, void* state, bool required)
{
    QSC_ASSERT(context != NULL);

    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (context != NULL && (callback != NULL || required == false))
    {
        context->clientauthcallback = callback;
        context->clientauthstate = state;
        context->requireclientauthorization = required;
        status = qsc_tls_socket_status_success;
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_context_set_socket_options(qsc_tls_socket_context* context, const qsc_tls_socket_options* options)
{
    QSC_ASSERT(context != NULL);
    QSC_ASSERT(options != NULL);

    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (context != NULL && options != NULL)
    {
        status = tls_socket_validate_options(options);

        if (status == qsc_tls_socket_status_success)
        {
            context->socketoptions = *options;
            tls_socket_emit_log(context->logcallback, context->logstate, qsc_tls_socket_log_level_info, qsc_tls_socket_event_socket_options, NULL, "TLS socket options configured");
        }
    }

    return status;
}

static qsc_tls_socket_status tls_socket_alpn_set(qsc_tls_alpn_protocols* alpn, const char* const* protocols, size_t protocolcount, bool required)
{
    size_t i;
    size_t j;
    size_t plen;
    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (alpn != NULL && protocols != NULL && protocolcount != 0U && protocolcount <= QSC_TLS_SOCKET_ALPN_PROTOCOL_MAX)
    {
        qsc_memutils_clear(alpn, sizeof(*alpn));
        status = qsc_tls_socket_status_success;

        for (i = 0U; i < protocolcount && status == qsc_tls_socket_status_success; ++i)
        {
            if (protocols[i] != NULL)
            {
                plen = qsc_stringutils_string_size(protocols[i]);

                if (plen != 0U && plen <= QSC_TLS_SOCKET_ALPN_SIZE_MAX)
                {
                    for (j = 0U; j < i; ++j)
                    {
                        if (alpn->protocollens[j] == plen && qsc_memutils_are_equal(alpn->protocols[j], (const uint8_t*)protocols[i], plen) == true)
                        {
                            status = qsc_tls_socket_status_invalid_input;
                            break;
                        }
                    }

                    if (status == qsc_tls_socket_status_success)
                    {
                        qsc_memutils_copy(alpn->protocols[i], (const uint8_t*)protocols[i], plen);
                        alpn->protocollens[i] = plen;
                    }
                }
                else
                {
                    status = qsc_tls_socket_status_invalid_input;
                }
            }
            else
            {
                status = qsc_tls_socket_status_invalid_input;
            }
        }

        if (status == qsc_tls_socket_status_success)
        {
            alpn->protocolcount = protocolcount;
            alpn->required = required;
            alpn->configured = true;
        }
        else
        {
            qsc_memutils_clear(alpn, sizeof(*alpn));
        }
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_context_set_alpn_protocols(qsc_tls_socket_context* context, const char* const* protocols, size_t protocolcount, bool required)
{
    QSC_ASSERT(context != NULL);
    QSC_ASSERT(protocols != NULL);

    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (context != NULL && context->initialized == true)
    {
        status = tls_socket_alpn_set(&context->alpn, protocols, protocolcount, required);
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_context_clear_alpn_protocols(qsc_tls_socket_context* context)
{
    QSC_ASSERT(context != NULL);

    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (context != NULL && context->initialized == true)
    {
        qsc_memutils_clear(&context->alpn, sizeof(context->alpn));
        status = qsc_tls_socket_status_success;
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_context_set_log_callback(qsc_tls_socket_context* context, qsc_tls_socket_log_callback callback, void* state)
{
    QSC_ASSERT(context != NULL);

    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (context != NULL)
    {
        context->logcallback = callback;
        context->logstate = state;
        status = qsc_tls_socket_status_success;
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_context_set_session_ticket_policy(qsc_tls_socket_context* context, const qsc_tls_socket_ticket_policy* policy)
{
    QSC_ASSERT(context != NULL);
    QSC_ASSERT(policy != NULL);

    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (context != NULL && policy != NULL)
    {
        if (tls_socket_ticket_policy_is_valid(policy) == true)
        {
            context->ticketpolicy = *policy;

            if (context->ticketpolicy.enabled == false)
            {
                qsc_tls_socket_context_clear_session_ticket(context);
            }

            status = qsc_tls_socket_status_success;
        }
        else
        {
            status = qsc_tls_socket_status_policy_rejected;
        }
    }

    return status;
}

bool qsc_tls_socket_session_ticket_is_valid(const qsc_tls_session_ticket* ticket)
{
    QSC_ASSERT(ticket != NULL);

    return tls_socket_session_ticket_is_valid_internal(ticket);
}

qsc_tls_socket_status qsc_tls_socket_context_set_session_ticket(qsc_tls_socket_context* context, const qsc_tls_session_ticket* ticket)
{
    QSC_ASSERT(context != NULL);
    QSC_ASSERT(ticket != NULL);

    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (context != NULL && ticket != NULL)
    {
        if (context->ticketpolicy.enabled == true)
        {
            context->sessionticket = *ticket;

            if (context->sessionticket.lifetime == 0U)
            {
                context->sessionticket.lifetime = context->ticketpolicy.lifetime_seconds;
            }

            if (tls_socket_session_ticket_is_valid_internal(&context->sessionticket) == true)
            {
                context->hassessionticket = true;
                status = qsc_tls_socket_status_success;
            }
            else
            {
                qsc_tls_socket_context_clear_session_ticket(context);
                status = qsc_tls_socket_status_policy_rejected;
            }
        }
        else
        {
            qsc_tls_socket_context_clear_session_ticket(context);
            status = qsc_tls_socket_status_policy_rejected;
        }
    }

    return status;
}

void qsc_tls_socket_context_clear_session_ticket(qsc_tls_socket_context* context)
{
    QSC_ASSERT(context != NULL);

    if (context != NULL)
    {
        qsc_tls_session_ticket_dispose(&context->sessionticket);
        context->hassessionticket = false;
    }
}

void qsc_tls_socket_connection_initialize(qsc_tls_socket_connection* connection)
{
    QSC_ASSERT(connection != NULL);

    if (connection != NULL)
    {
        qsc_memutils_clear(connection, sizeof(*connection));
        qsc_tls_socket_result_clear(&connection->lastresult);
        qsc_tls_socket_options_initialize_default(&connection->socketoptions);
        qsc_tls_socket_ticket_policy_initialize_default(&connection->ticketpolicy);
        connection->role = qsc_tls_role_client;
        connection->family = qsc_socket_address_family_none;
    }
}

void qsc_tls_socket_connection_dispose(qsc_tls_socket_connection* connection)
{
    QSC_ASSERT(connection != NULL);

    if (connection != NULL)
    {
        qsc_tls_engine_dispose(&connection->engine);
        qsc_tls_session_ticket_dispose(&connection->lastticket);

        if (connection->owns_socket == true)
        {
            (void)qsc_socket_shut_down(&connection->socket, qsc_socket_shut_down_flag_both);
            (void)qsc_socket_close_socket(&connection->socket);
        }

        qsc_memutils_secure_erase(connection, sizeof(*connection));
    }
}

qsc_tls_socket_status qsc_tls_socket_client_connect_host(qsc_tls_socket_connection* connection, const qsc_tls_socket_context* context, const char* hostname, const char* service)
{
    return qsc_tls_socket_client_connect_host_ex(connection, context, hostname, service, NULL, false);
}

qsc_tls_socket_status qsc_tls_socket_client_connect_host_ex(qsc_tls_socket_connection* connection, const qsc_tls_socket_context* context, const char* hostname, const char* service, const qsc_tls_session_ticket* ticket, bool enableearlydata)
{
    return tls_socket_client_connect_common(connection, context, hostname, service, NULL, NULL, 0U, ticket, enableearlydata);
}

qsc_tls_socket_status qsc_tls_socket_client_connect_ipv4(qsc_tls_socket_connection* connection, const qsc_tls_socket_context* context, const qsc_ipinfo_ipv4_address* address, uint16_t port, const char* hostname)
{
    return tls_socket_client_connect_common(connection, context, hostname, NULL, address, NULL, port, NULL, false);
}

qsc_tls_socket_status qsc_tls_socket_client_connect_ipv6(qsc_tls_socket_connection* connection, const qsc_tls_socket_context* context, const qsc_ipinfo_ipv6_address* address, uint16_t port, const char* hostname)
{
    return tls_socket_client_connect_common(connection, context, hostname, NULL, NULL, address, port, NULL, false);
}

qsc_tls_socket_status qsc_tls_socket_send(qsc_tls_socket_connection* connection, const uint8_t* input, size_t inlen, size_t* written)
{
    QSC_ASSERT(connection != NULL);
    QSC_ASSERT(input != NULL);

    qsc_tls_status st;
    qsc_tls_socket_status status;
    size_t tmp;

    status = qsc_tls_socket_status_invalid_input;
    tmp = 0U;

    if (written != NULL)
    {
        *written = 0U;
    }

    if (connection != NULL && input != NULL && inlen != 0U)
    {
        if (connection->connected == true && connection->handshaked == true)
        {
            st = qsc_tls_io_send(&connection->io, input, inlen, &tmp);
            status = tls_socket_status_from_tls(st);

            if (written != NULL)
            {
                *written = tmp;
            }
        }
        else
        {
            st = qsc_tls_status_invalid_state;
            status = qsc_tls_socket_status_not_initialized;
        }

        tls_socket_set_result(&connection->lastresult, status, st, (qsc_socket_exceptions)QSC_SOCKET_RET_SUCCESS, QSC_X509W_STATUS_SUCCESS, QSC_X509_VERIFY_STATUS_SUCCESS, qsc_tls_alert_close_notify);
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_receive(qsc_tls_socket_connection* connection, uint8_t* output, size_t outlen, size_t* read)
{
    QSC_ASSERT(connection != NULL);
    QSC_ASSERT(output != NULL);

    qsc_tls_status st;
    qsc_tls_socket_status status;
    size_t tmp;

    status = qsc_tls_socket_status_invalid_input;
    tmp = 0U;

    if (read != NULL)
    {
        *read = 0U;
    }

    if (connection != NULL && output != NULL && outlen != 0U)
    {
        if (connection->connected == true && connection->handshaked == true)
        {
            st = qsc_tls_io_receive(&connection->io, output, outlen, &tmp);
            status = tls_socket_status_from_tls(st);

            if (read != NULL)
            {
                *read = tmp;
            }
        }
        else
        {
            st = qsc_tls_status_invalid_state;
            status = qsc_tls_socket_status_not_initialized;
        }

        tls_socket_set_result(&connection->lastresult, status, st, (qsc_socket_exceptions)QSC_SOCKET_RET_SUCCESS, QSC_X509W_STATUS_SUCCESS, QSC_X509_VERIFY_STATUS_SUCCESS, qsc_tls_alert_close_notify);
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_shutdown(qsc_tls_socket_connection* connection)
{
    QSC_ASSERT(connection != NULL);

    qsc_tls_status st;
    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (connection != NULL)
    {
        st = qsc_tls_io_shutdown(&connection->io);
        status = tls_socket_status_from_tls(st);
        (void)qsc_socket_shut_down(&connection->socket, qsc_socket_shut_down_flag_both);
        (void)qsc_socket_close_socket(&connection->socket);
        connection->connected = false;
        connection->owns_socket = false;
        tls_socket_set_result(&connection->lastresult, status, st, (qsc_socket_exceptions)QSC_SOCKET_RET_SUCCESS, QSC_X509W_STATUS_SUCCESS, QSC_X509_VERIFY_STATUS_SUCCESS, qsc_tls_alert_close_notify);
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_key_update(qsc_tls_socket_connection* connection, bool requestpeerupdate)
{
    QSC_ASSERT(connection != NULL);

    uint8_t outbuf[QSC_TLS_MAX_RECORD_SIZE] = { 0U };
    size_t written;
    size_t sent;
    qsc_tls_status st;
    qsc_tls_socket_status status;

    written = 0U;
    sent = 0U;
    status = qsc_tls_socket_status_invalid_input;

    if (connection != NULL)
    {
        st = qsc_tls_engine_request_key_update(&connection->engine, requestpeerupdate, outbuf, sizeof(outbuf), &written);
        status = tls_socket_status_from_tls(st);

        if (status == qsc_tls_socket_status_success && written > 0U)
        {
            while (sent < written)
            {
                size_t n;

                n = qsc_socket_send(&connection->socket, outbuf + sent, written - sent, qsc_socket_send_flag_none);

                if (n == 0U)
                {
                    status = qsc_tls_socket_status_io_failed;
                    st = qsc_tls_status_failure;
                    break;
                }

                sent += n;
            }
        }

        tls_socket_set_result(&connection->lastresult, status, st, (qsc_socket_exceptions)QSC_SOCKET_RET_SUCCESS, QSC_X509W_STATUS_SUCCESS, QSC_X509_VERIFY_STATUS_SUCCESS, qsc_tls_alert_close_notify);
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_server_send_session_ticket(qsc_tls_socket_connection* connection, uint32_t lifetime_seconds, qsc_tls_session_ticket* ticketout)
{
    QSC_ASSERT(connection != NULL);
    QSC_ASSERT(ticketout != NULL);

    uint8_t outbuf[QSC_TLS_MAX_RECORD_SIZE] = { 0U };
    size_t written;
    size_t sent;
    qsc_tls_status st;
    qsc_tls_socket_status status;

    written = 0U;
    sent = 0U;
    status = qsc_tls_socket_status_invalid_input;

    if (connection != NULL && ticketout != NULL)
    {
        qsc_tls_session_ticket_dispose(ticketout);

        if (connection->ticketpolicy.enabled == false || lifetime_seconds == 0U || lifetime_seconds > QSC_TLS_SOCKET_TICKET_LIFETIME_MAX)
        {
            st = qsc_tls_status_invalid_input;
            status = qsc_tls_socket_status_policy_rejected;
        }
        else
        {
            st = qsc_tls_engine_emit_session_ticket(&connection->engine, lifetime_seconds, outbuf, sizeof(outbuf), &written, ticketout);
            status = tls_socket_status_from_tls(st);
        }

        if (status == qsc_tls_socket_status_success && written > 0U)
        {
            while (sent < written)
            {
                size_t n;

                n = qsc_socket_send(&connection->socket, outbuf + sent, written - sent, qsc_socket_send_flag_none);

                if (n == 0U)
                {
                    status = qsc_tls_socket_status_io_failed;
                    st = qsc_tls_status_failure;
                    break;
                }

                sent += n;
            }
        }

        if (status == qsc_tls_socket_status_success)
        {
            connection->lastticket = *ticketout;
            connection->haslastticket = true;
        }

        tls_socket_set_result(&connection->lastresult, status, st, (qsc_socket_exceptions)QSC_SOCKET_RET_SUCCESS, QSC_X509W_STATUS_SUCCESS, QSC_X509_VERIFY_STATUS_SUCCESS, qsc_tls_alert_close_notify);
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_connection_set_socket_options(qsc_tls_socket_connection* connection, const qsc_tls_socket_options* options)
{
    QSC_ASSERT(connection != NULL);
    QSC_ASSERT(options != NULL);

    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (connection != NULL && options != NULL)
    {
        status = tls_socket_validate_options(options);

        if (status == qsc_tls_socket_status_success)
        {
            if (connection->connected == true)
            {
                status = tls_socket_apply_options(&connection->socket, connection->family, options, false);
            }

            if (status == qsc_tls_socket_status_success)
            {
                connection->socketoptions = *options;
            }
        }
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_connection_set_log_callback(qsc_tls_socket_connection* connection, qsc_tls_socket_log_callback callback, void* state)
{
    QSC_ASSERT(connection != NULL);

    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (connection != NULL)
    {
        connection->logcallback = callback;
        connection->logstate = state;
        status = qsc_tls_socket_status_success;
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_connection_cancel(qsc_tls_socket_connection* connection)
{
    QSC_ASSERT(connection != NULL);

    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (connection != NULL)
    {
        connection->cancelrequested = true;
        (void)qsc_socket_shut_down(&connection->socket, qsc_socket_shut_down_flag_both);
        status = qsc_tls_socket_status_success;
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_get_peer_info(const qsc_tls_socket_connection* connection, qsc_tls_socket_peer_info* peerinfo)
{
    QSC_ASSERT(connection != NULL);
    QSC_ASSERT(peerinfo != NULL);

    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (connection != NULL && peerinfo != NULL)
    {
        qsc_memutils_copy(peerinfo, &connection->peerinfo, sizeof(*peerinfo));
        status = qsc_tls_socket_status_success;
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_get_selected_alpn(const qsc_tls_socket_connection* connection, char* protocol, size_t protocolcap, size_t* protocollen)
{
    QSC_ASSERT(connection != NULL);
    QSC_ASSERT(protocol != NULL);
    QSC_ASSERT(protocollen != NULL);

    qsc_tls_socket_status status;
    size_t plen;

    status = qsc_tls_socket_status_invalid_input;

    if (protocollen != NULL)
    {
        *protocollen = 0U;
    }

    if (connection != NULL && protocol != NULL && protocollen != NULL && protocolcap != 0U)
    {
        if (connection->peerinfo.alpn_selected == true)
        {
            plen = qsc_stringutils_string_size(connection->peerinfo.selected_alpn);

            if (plen + 1U <= protocolcap)
            {
                qsc_memutils_copy(protocol, connection->peerinfo.selected_alpn, plen + 1U);
                *protocollen = plen;
                status = qsc_tls_socket_status_success;
            }
        }
        else
        {
            protocol[0U] = '\0';
            status = qsc_tls_socket_status_not_initialized;
        }
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_connection_get_session_ticket(const qsc_tls_socket_connection* connection, qsc_tls_session_ticket* ticketout)
{
    QSC_ASSERT(connection != NULL);
    QSC_ASSERT(ticketout != NULL);

    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (ticketout != NULL)
    {
        qsc_tls_session_ticket_dispose(ticketout);
    }

    if (connection != NULL && ticketout != NULL)
    {
        if (connection->ticketpolicy.enabled == true && connection->haslastticket == true &&
            tls_socket_session_ticket_is_valid_internal(&connection->lastticket) == true)
        {
            *ticketout = connection->lastticket;
            status = qsc_tls_socket_status_success;
        }
        else
        {
            status = qsc_tls_socket_status_not_initialized;
        }
    }

    return status;
}

void qsc_tls_socket_connection_clear_session_ticket(qsc_tls_socket_connection* connection)
{
    QSC_ASSERT(connection != NULL);

    if (connection != NULL)
    {
        qsc_tls_session_ticket_dispose(&connection->lastticket);
        connection->haslastticket = false;
    }
}

qsc_tls_socket_status qsc_tls_socket_send_frame(qsc_tls_socket_connection* connection, const uint8_t* input, size_t inlen)
{
    QSC_ASSERT(connection != NULL);
    QSC_ASSERT(input != NULL || inlen == 0U);

    uint8_t hdr[QSC_TLS_SOCKET_FRAME_HEADER_SIZE] = { 0U };
    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (connection != NULL && tls_socket_frame_send_input_valid(input, inlen) == true)
    {
        qsc_intutils_be32to8(hdr, (uint32_t)inlen);
        status = tls_socket_send_all(connection, hdr, sizeof(hdr));

        if (status == qsc_tls_socket_status_success && inlen != 0U)
        {
            status = tls_socket_send_all(connection, input, inlen);
        }

        tls_socket_connection_log(connection, status == qsc_tls_socket_status_success ? qsc_tls_socket_log_level_debug : qsc_tls_socket_log_level_error,
            qsc_tls_socket_event_frame_send, status == qsc_tls_socket_status_success ? "TLS frame sent" : "TLS frame send failed");
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_receive_frame(qsc_tls_socket_connection* connection, uint8_t* output, size_t outlen, size_t* read)
{
    QSC_ASSERT(connection != NULL);
    QSC_ASSERT(output != NULL || outlen == 0U);
    QSC_ASSERT(read != NULL);

    uint8_t hdr[QSC_TLS_SOCKET_FRAME_HEADER_SIZE] = { 0U };
    uint32_t flen;
    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (read != NULL)
    {
        *read = 0U;
    }

    if (connection != NULL && read != NULL && tls_socket_frame_receive_output_valid(output, outlen) == true)
    {
        status = tls_socket_receive_exact(connection, hdr, sizeof(hdr));

        if (status == qsc_tls_socket_status_success)
        {
            flen = qsc_intutils_be8to32(hdr);
            status = tls_socket_frame_status_from_length(flen, outlen);

            if (status == qsc_tls_socket_status_success)
            {
                if (flen == 0U)
                {
                    *read = 0U;
                }
                else
                {
                    status = tls_socket_receive_exact(connection, output, (size_t)flen);

                    if (status == qsc_tls_socket_status_success)
                    {
                        *read = (size_t)flen;
                    }
                }
            }
        }

        tls_socket_connection_log(connection, status == qsc_tls_socket_status_success ? qsc_tls_socket_log_level_debug : qsc_tls_socket_log_level_error,
            qsc_tls_socket_event_frame_receive, status == qsc_tls_socket_status_success ? "TLS frame received" : "TLS frame receive failed");
    }

    return status;
}

bool qsc_tls_socket_is_connected(const qsc_tls_socket_connection* connection)
{
    QSC_ASSERT(connection != NULL);

    bool res;

    res = false;

    if (connection != NULL)
    {
        res = connection->connected;
    }

    return res;
}

bool qsc_tls_socket_is_handshake_complete(const qsc_tls_socket_connection* connection)
{
    QSC_ASSERT(connection != NULL);

    bool res;

    res = false;

    if (connection != NULL)
    {
        res = connection->handshaked;
    }

    return res;
}

qsc_tls_cipher_suite qsc_tls_socket_negotiated_cipher_suite(const qsc_tls_socket_connection* connection)
{
    QSC_ASSERT(connection != NULL);

    qsc_tls_cipher_suite res;

    res = qsc_tls_cipher_suite_none;

    if (connection != NULL && connection->handshaked == true)
    {
        if (connection->role == qsc_tls_role_client)
        {
            res = connection->engine.state.client.negotiatedsuite;
        }
        else
        {
            res = connection->engine.state.server.negotiatedsuite;
        }
    }

    return res;
}

qsc_tls_named_group qsc_tls_socket_negotiated_group(const qsc_tls_socket_connection* connection)
{
    QSC_ASSERT(connection != NULL);

    qsc_tls_named_group res;

    res = qsc_tls_group_none;

    if (connection != NULL && connection->handshaked == true)
    {
        if (connection->role == qsc_tls_role_client)
        {
            res = connection->engine.state.client.negotiatedgroup;
        }
        else
        {
            res = connection->engine.state.server.negotiatedgroup;
        }
    }

    return res;
}

qsc_tls_signature_scheme qsc_tls_socket_negotiated_signature_scheme(const qsc_tls_socket_connection* connection)
{
    QSC_ASSERT(connection != NULL);

    qsc_tls_signature_scheme res;

    res = qsc_tls_sig_none;

    if (connection != NULL && connection->handshaked == true)
    {
        if (connection->role == qsc_tls_role_client)
        {
            res = connection->engine.state.client.negotiatedsigscheme;
        }
        else
        {
            res = connection->engine.state.server.negotiatedsigscheme;
        }
    }

    return res;
}

void qsc_tls_socket_listener_initialize(qsc_tls_socket_listener* listener)
{
    QSC_ASSERT(listener != NULL);

    if (listener != NULL)
    {
        qsc_memutils_clear(listener, sizeof(*listener));
        qsc_socket_server_initialize(&listener->socket);
        listener->family = qsc_socket_address_family_ipv4;
        listener->backlog = QSC_SOCKET_SERVER_LISTEN_BACKLOG;
        qsc_tls_socket_options_initialize_default(&listener->socketoptions);
        listener->initialized = true;
    }
}

qsc_tls_socket_status qsc_tls_socket_listener_set_options(qsc_tls_socket_listener* listener, bool reuseaddress, bool nodelay, uint32_t recvtimeoutms, uint32_t sendtimeoutms)
{
    QSC_ASSERT(listener != NULL);

    qsc_tls_socket_options options = { 0 };
    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (listener != NULL)
    {
        qsc_tls_socket_options_initialize_default(&options);
        options.reuse_address = reuseaddress;
        options.no_delay = nodelay;
        options.receive_timeout_ms = recvtimeoutms;
        options.send_timeout_ms = sendtimeoutms;

        status = qsc_tls_socket_listener_set_socket_options(listener, &options);
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_listener_set_socket_options(qsc_tls_socket_listener* listener, const qsc_tls_socket_options* options)
{
    QSC_ASSERT(listener != NULL);
    QSC_ASSERT(options != NULL);

    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (listener != NULL && options != NULL)
    {
        status = tls_socket_validate_options(options);

        if (status == qsc_tls_socket_status_success)
        {
            if (listener->listening == true)
            {
                status = tls_socket_apply_options(&listener->socket, listener->family, options, true);
            }

            if (status == qsc_tls_socket_status_success)
            {
                listener->socketoptions = *options;
            }
        }
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_listener_bind(qsc_tls_socket_listener* listener, const qsc_tls_socket_context* context, const char* address, uint16_t port, qsc_socket_address_families family)
{
    QSC_ASSERT(listener != NULL);
    QSC_ASSERT(context != NULL);
    QSC_ASSERT(address != NULL);

    qsc_socket_exceptions se;
    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (listener != NULL && context != NULL && address != NULL && port != 0U)
    {
        if (listener->initialized == false)
        {
            qsc_tls_socket_listener_initialize(listener);
        }

        listener->context = context;
        listener->socketoptions = context->socketoptions;
        listener->family = family;
        listener->port = port;
        se = qsc_socket_create(&listener->socket, family, qsc_socket_transport_stream, qsc_socket_protocol_tcp);

        if (se == (qsc_socket_exceptions)QSC_SOCKET_RET_SUCCESS)
        {
            status = tls_socket_apply_options(&listener->socket, family, &listener->socketoptions, true);

            if (status != qsc_tls_socket_status_success)
            {
                return status;
            }

            se = qsc_socket_bind(&listener->socket, address, port);

            if (se == (qsc_socket_exceptions)QSC_SOCKET_RET_SUCCESS)
            {
                se = qsc_socket_listen(&listener->socket, listener->backlog);

                if (se == (qsc_socket_exceptions)QSC_SOCKET_RET_SUCCESS)
                {
                    listener->listening = true;
                    status = qsc_tls_socket_status_success;
                }
                else
                {
                    status = qsc_tls_socket_status_socket_listen_failed;
                }
            }
            else
            {
                status = qsc_tls_socket_status_socket_bind_failed;
            }
        }
        else
        {
            status = qsc_tls_socket_status_socket_start_failed;
        }
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_listener_accept(qsc_tls_socket_listener* listener, qsc_tls_socket_connection* connection)
{
    QSC_ASSERT(listener != NULL);
    QSC_ASSERT(connection != NULL);

    qsc_tls_server_config config = { 0 };
    qsc_socket_exceptions se;
    qsc_tls_status st;
    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (listener != NULL && connection != NULL)
    {
        if (listener->listening == true && listener->context != NULL)
        {
            qsc_tls_socket_connection_initialize(connection);
            se = qsc_socket_accept(&listener->socket, &connection->socket);

            if (se == (qsc_socket_exceptions)QSC_SOCKET_RET_SUCCESS)
            {
                connection->connected = true;
                connection->owns_socket = true;
                connection->role = qsc_tls_role_server;
                connection->family = listener->family;
                connection->socketoptions = listener->socketoptions;
                connection->ticketpolicy = listener->context->ticketpolicy;
                connection->logcallback = listener->context->logcallback;
                connection->logstate = listener->context->logstate;
                status = tls_socket_apply_options(&connection->socket, connection->family, &connection->socketoptions, false);

                if (status == qsc_tls_socket_status_success)
                {
                    status = tls_socket_build_server_config(listener->context, &config);
                }

                if (status == qsc_tls_socket_status_success)
                {
                    st = qsc_tls_engine_initialize_server(&connection->engine, &config);
                    status = tls_socket_status_from_tls(st);

                    if (status == qsc_tls_socket_status_success)
                    {
                        connection->signcontext.scheme = connection->engine.state.server.config.localcert.verifyscheme;
                        connection->signcontext.privatekey = connection->engine.state.server.config.localcert.signprivatekey;
                        connection->signcontext.privatekeylen = connection->engine.state.server.config.localcert.signprivatekeylen;
                        connection->engine.state.server.config.localcert.signcallback = qsc_tls_signer_default_sign;
                        connection->engine.state.server.config.localcert.signstate = &connection->signcontext;
                        status = tls_socket_connection_handshake(connection);
                    }
                    else
                    {
                        tls_socket_set_result(&connection->lastresult, status, st, se, QSC_X509W_STATUS_SUCCESS, QSC_X509_VERIFY_STATUS_SUCCESS, qsc_tls_alert_internal_error);
                    }
                }
            }
            else
            {
                status = qsc_tls_socket_status_socket_accept_failed;
                tls_socket_set_result(&connection->lastresult, status, qsc_tls_status_failure, se, QSC_X509W_STATUS_SUCCESS, QSC_X509_VERIFY_STATUS_SUCCESS, qsc_tls_alert_internal_error);
            }
        }
        else
        {
            status = qsc_tls_socket_status_not_initialized;
        }
    }

    return status;
}

void qsc_tls_socket_listener_close(qsc_tls_socket_listener* listener)
{
    QSC_ASSERT(listener != NULL);
    
    if (listener != NULL)
    {
        (void)qsc_socket_shut_down(&listener->socket, qsc_socket_shut_down_flag_both);
        (void)qsc_socket_close_socket(&listener->socket);
        listener->listening = false;
    }
}

void qsc_tls_socket_server_initialize(qsc_tls_socket_server* server)
{
    QSC_ASSERT(server != NULL);

    if (server != NULL)
    {
        qsc_memutils_clear(server, sizeof(*server));
        qsc_tls_socket_listener_initialize(&server->listener);
        server->maxclients = QSC_TLS_SOCKET_SERVER_CONNECTIONS_MAX;
        server->poolmutex = qsc_async_mutex_create();
        server->initialized = true;
    }
}

qsc_tls_socket_status qsc_tls_socket_server_configure(qsc_tls_socket_server* server, const qsc_tls_socket_context* context, const char* address, uint16_t port, qsc_socket_address_families family)
{
    QSC_ASSERT(server != NULL);

    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (server != NULL)
    {
        if (server->initialized == false)
        {
            qsc_tls_socket_server_initialize(server);
        }

        status = qsc_tls_socket_listener_bind(&server->listener, context, address, port, family);
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_server_set_callbacks(qsc_tls_socket_server* server, qsc_tls_socket_server_connect_callback onconnect, qsc_tls_socket_server_receive_callback onreceive, qsc_tls_socket_server_disconnect_callback ondisconnect, qsc_tls_socket_server_error_callback onerror, void* state)
{
    QSC_ASSERT(server != NULL);

    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (server != NULL)
    {
        server->onconnect = onconnect;
        server->onreceive = onreceive;
        server->ondisconnect = ondisconnect;
        server->onerror = onerror;
        server->callbackstate = state;
        status = qsc_tls_socket_status_success;
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_server_set_log_callback(qsc_tls_socket_server* server, qsc_tls_socket_log_callback callback, void* state)
{
    QSC_ASSERT(server != NULL);

    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (server != NULL)
    {
        server->onlog = callback;
        server->logstate = state;
        status = qsc_tls_socket_status_success;
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_server_set_max_clients(qsc_tls_socket_server* server, size_t maxclients)
{
    QSC_ASSERT(server != NULL);

    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (server != NULL && maxclients != 0U && maxclients <= QSC_TLS_SOCKET_SERVER_CONNECTIONS_MAX)
    {
        if (tls_socket_server_active_count(server) == 0U)
        {
            server->maxclients = maxclients;
            status = qsc_tls_socket_status_success;
        }
        else
        {
            status = qsc_tls_socket_status_policy_rejected;
        }
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_server_start(qsc_tls_socket_server* server)
{
    QSC_ASSERT(server != NULL);

    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (server != NULL)
    {
        if (server->listener.listening == true)
        {
            server->running = true;
            status = qsc_tls_socket_status_success;

            while (server->running == true)
            {
                uint8_t buffer[QSC_TLS_SOCKET_SERVER_BUFFER_SIZE] = { 0U };
                qsc_tls_socket_connection connection;
                size_t msglen;

                qsc_tls_socket_connection_initialize(&connection);
                status = qsc_tls_socket_listener_accept(&server->listener, &connection);

                if (status == qsc_tls_socket_status_success)
                {
                    if (server->onconnect != NULL)
                    {
                        server->onconnect(&connection, server->callbackstate);
                    }

                    if (connection.role == qsc_tls_role_server && connection.ticketpolicy.enabled == true && connection.ticketpolicy.auto_send_server_ticket == true)
                    {
                        if (qsc_tls_socket_server_send_session_ticket(&connection, connection.ticketpolicy.lifetime_seconds, &connection.lastticket) == qsc_tls_socket_status_success)
                        {
                            connection.haslastticket = true;
                        }
                    }

                    while (server->running == true && connection.connected == true)
                    {
                        msglen = 0U;
                        status = qsc_tls_socket_receive(&connection, buffer, sizeof(buffer), &msglen);

                        if (status != qsc_tls_socket_status_success)
                        {
                            if (server->onerror != NULL)
                            {
                                server->onerror(&connection, status, server->callbackstate);
                            }

                            break;
                        }

                        if (msglen != 0U && server->onreceive != NULL)
                        {
                            server->onreceive(&connection, buffer, msglen, server->callbackstate);
                        }
                    }

                    if (server->ondisconnect != NULL)
                    {
                        server->ondisconnect(&connection, server->callbackstate);
                    }

                    qsc_tls_socket_connection_dispose(&connection);
                }
                else
                {
                    if (server->onerror != NULL)
                    {
                        server->onerror(&connection, status, server->callbackstate);
                    }

                    qsc_tls_socket_connection_dispose(&connection);
                }
            }
        }
        else
        {
            status = qsc_tls_socket_status_not_initialized;
        }
    }

    return status;
}

qsc_tls_socket_status qsc_tls_socket_server_start_concurrent(qsc_tls_socket_server* server)
{
    QSC_ASSERT(server != NULL);

    qsc_tls_socket_status status;

    status = qsc_tls_socket_status_invalid_input;

    if (server != NULL)
    {
        if (server->listener.listening == true && server->maxclients != 0U && server->maxclients <= QSC_TLS_SOCKET_SERVER_CONNECTIONS_MAX)
        {
            server->running = true;
            server->concurrent = true;
            status = qsc_tls_socket_status_success;

            while (server->running == true)
            {
                size_t index;

                if (tls_socket_server_acquire_slot(server, &index) == true)
                {
                    status = qsc_tls_socket_listener_accept(&server->listener, &server->connections[index]);

                    if (status == qsc_tls_socket_status_success)
                    {
                        server->workerstates[index].server = server;
                        server->workerstates[index].index = index;
                        server->workerthreads[index] = qsc_async_thread_create(tls_socket_server_connection_worker, &server->workerstates[index]);

                        if (tls_socket_thread_is_valid(server->workerthreads[index]) == true)
                        {
                            server->started[index] = true;
                        }
                        else
                        {
                            status = qsc_tls_socket_status_internal_error;

                            if (server->onerror != NULL)
                            {
                                server->onerror(&server->connections[index], status, server->callbackstate);
                            }

                            tls_socket_server_release_slot(server, index);
                        }
                    }
                    else
                    {
                        if (server->onerror != NULL)
                        {
                            server->onerror(&server->connections[index], status, server->callbackstate);
                        }

                        tls_socket_server_release_slot(server, index);

                        if (server->running == false)
                        {
                            break;
                        }
                    }
                }
                else
                {
                    qsc_async_thread_sleep(10U);
                }
            }
        }
        else
        {
            status = qsc_tls_socket_status_not_initialized;
        }
    }

    return status;
}

void qsc_tls_socket_server_stop(qsc_tls_socket_server* server)
{
    QSC_ASSERT(server != NULL);

    size_t i;
    size_t maxc;

    if (server != NULL)
    {
        server->running = false;
        qsc_tls_socket_listener_close(&server->listener);
        maxc = server->maxclients;

        if (maxc > QSC_TLS_SOCKET_SERVER_CONNECTIONS_MAX)
        {
            maxc = QSC_TLS_SOCKET_SERVER_CONNECTIONS_MAX;
        }

        for (i = 0U; i < maxc; ++i)
        {
            if (server->active[i] == true || server->started[i] == true)
            {
                server->connections[i].cancelrequested = true;
                (void)qsc_socket_shut_down(&server->connections[i].socket, qsc_socket_shut_down_flag_both);
                (void)qsc_socket_close_socket(&server->connections[i].socket);
            }
        }

        for (i = 0U; i < maxc; ++i)
        {
            if (server->started[i] == true)
            {
                if (tls_socket_thread_is_valid(server->workerthreads[i]) == true)
                {
                    qsc_async_thread_wait(server->workerthreads[i]);
                }

                tls_socket_thread_clear(&server->workerthreads[i]);
                server->started[i] = false;
            }
        }

        if (server->poolmutex != NULL)
        {
            qsc_async_mutex_lock(server->poolmutex);
        }

        for (i = 0U; i < maxc; ++i)
        {
            if (server->active[i] == true)
            {
                qsc_tls_socket_connection_dispose(&server->connections[i]);
                server->active[i] = false;
                server->workerstates[i].server = NULL;
                server->workerstates[i].index = 0U;
                tls_socket_thread_clear(&server->workerthreads[i]);
            }
        }

        if (server->poolmutex != NULL)
        {
            qsc_async_mutex_unlock(server->poolmutex);
        }
    }
}

void qsc_tls_socket_server_dispose(qsc_tls_socket_server* server)
{
    QSC_ASSERT(server != NULL);

    if (server != NULL)
    {
        qsc_tls_socket_server_stop(server);

        if (server->poolmutex != NULL)
        {
            (void)qsc_async_mutex_destroy(server->poolmutex);
        }

        qsc_memutils_secure_erase(server, sizeof(*server));
    }
}
