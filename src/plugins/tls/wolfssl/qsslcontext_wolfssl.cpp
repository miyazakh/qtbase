/*
 * Copyright (C) 2026 The Qt Company Ltd.
 * SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
 */

#include "qsslcontext_wolfssl_p.h"
#include "qtls_wolfssl_p.h"
#include "qtlsbackend_wolfssl_p.h"

#include <QtNetwork/private/qssldiffiehellmanparameters_p.h>
#include <QtNetwork/private/qtlsbackend_p.h>

#include <QtNetwork/qsslcertificate.h>
#include <QtNetwork/qsslcipher.h>
#include <QtNetwork/qssldiffiehellmanparameters.h>
#include <QtNetwork/qsslkey.h>

#include <QtCore/qdatetime.h>

#include <algorithm>

/* wolfssl/options.h must come first, see qtlsbackend_wolfssl.cpp. */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

QT_BEGIN_NAMESPACE

using namespace Qt::StringLiterals;

namespace QTlsPrivate {

bool tls13ExternalPskRequested()
{
    /* TLS 1.3 external PSK is not implemented yet (docs/design-io-bridge.md
     * 11.5). Once it is, this returns
     * qEnvironmentVariableIsSet("QT_USE_TLS_1_3_PSK"), the same opt-in as the
     * OpenSSL backend. */
    return false;
}

PskPolicy pskPolicy(const QSslConfiguration &configuration,
                    QSslSocket::SslMode mode)
{
    PskPolicy policy;
    if (mode == QSslSocket::SslClientMode) {
        /* wolfSSL calls a registered client PSK callback while building every
         * TLS 1.3 ClientHello, and treats a zero-length key as a PSK rather
         * than "no PSK" (docs/design-io-bridge.md 11.3). Register it only when
         * TLS 1.3 cannot be negotiated, so that
         * preSharedKeyAuthenticationRequired is not emitted for every TLS 1.3
         * connection. */
        policy.clientTls12 = configuration.protocol() == QSsl::TlsV1_2;
    } else if (mode == QSslSocket::SslServerMode) {
        /* The server callback checks the negotiated version itself and does
         * not ask the application during a TLS 1.3 handshake. */
        policy.serverTls12 = true;
    }
    policy.tls13 = tls13ExternalPskRequested();
    return policy;
}

} /* namespace QTlsPrivate */

using QTlsPrivate::TlsCryptographWolfSSL;

namespace {

TlsCryptographWolfSSL *cryptographFromSsl(WOLFSSL *ssl)
{
    /* The I/O read context is the TlsCryptographWolfSSL that owns ssl (see
     * TlsCryptographWolfSSL::initSsl()); the other callbacks reuse it. */
    return ssl ? static_cast<TlsCryptographWolfSSL *>(wolfSSL_GetIOReadCtx(ssl))
               : nullptr;
}

extern "C" {

int q_wolfssl_io_recv(WOLFSSL *, char *buf, int sz, void *ctx)
{
    auto *tls = static_cast<TlsCryptographWolfSSL *>(ctx);
    if (!tls)
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    return tls->ioRecv(buf, sz);
}

int q_wolfssl_io_send(WOLFSSL *, char *buf, int sz, void *ctx)
{
    auto *tls = static_cast<TlsCryptographWolfSSL *>(ctx);
    if (!tls)
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    return tls->ioSend(buf, sz);
}

int q_wolfssl_verify_callback(int preverify, WOLFSSL_X509_STORE_CTX *store)
{
    /* userCtx is set with wolfSSL_SetCertCbCtx() for every WOLFSSL object. */
    auto *tls = store ? static_cast<TlsCryptographWolfSSL *>(store->userCtx)
                      : nullptr;
    if (!tls) {
        qCWarning(lcTlsBackendWolfSSL,
                  "Verify callback without a TLS cryptograph");
        return preverify;
    }
    return tls->verifyCertificate(preverify, store);
}

int q_wolfssl_new_session_callback(WOLFSSL *ssl, WOLFSSL_SESSION *session)
{
    /* Returning 0 tells wolfSSL that we did not keep the reference it took
     * for us; the session is serialized (or referenced) separately. */
    if (auto *tls = cryptographFromSsl(ssl))
        return tls->handleNewSession(session);
    return 0;
}

#ifndef NO_PSK
unsigned int q_wolfssl_psk_client_callback(WOLFSSL *ssl, const char *hint,
                                           char *identity,
                                           unsigned int maxIdentityLen,
                                           unsigned char *key,
                                           unsigned int maxKeyLen)
{
    if (auto *tls = cryptographFromSsl(ssl))
        return tls->pskClientTlsCallback(hint, identity, maxIdentityLen, key,
                                         maxKeyLen);
    return 0;
}

unsigned int q_wolfssl_psk_server_callback(WOLFSSL *ssl, const char *identity,
                                           unsigned char *key,
                                           unsigned int maxKeyLen)
{
    /* wolfSSL falls back to this (TLS 1.2) callback during a TLS 1.3
     * handshake when no TLS 1.3 callback is registered
     * (docs/design-io-bridge.md 11.3, 11.4). External TLS 1.3 PSK is not
     * supported yet, so do not ask the application in that case. */
    if (wolfSSL_GetVersion(ssl) == WOLFSSL_TLSV1_3)
        return 0;
    if (auto *tls = cryptographFromSsl(ssl))
        return tls->pskServerTlsCallback(identity, key, maxKeyLen);
    return 0;
}
#endif /* !NO_PSK */

} /* extern "C" */

QByteArray cipherListFromConfiguration(const QSslConfiguration &configuration,
                                       bool withPsk)
{
    QList<QSslCipher> ciphers = configuration.ciphers();
    if (ciphers.isEmpty())
        ciphers = QTlsBackend::defaultCiphers();

    /* OpenSSL keeps its TLS 1.3 suites (set separately) when the list has
     * only TLS 1.2 suites, and the other way round. Do the same, so that a
     * list without TLS 1.3 suites does not disable TLS 1.3. */
    const auto isTls13 = [](const QSslCipher &cipher) {
        return cipher.protocol() == QSsl::TlsV1_3;
    };
    const bool hasTls13 = std::any_of(ciphers.cbegin(), ciphers.cend(),
                                      isTls13);
    const bool hasTls12 = std::any_of(ciphers.cbegin(), ciphers.cend(),
                                      [&isTls13](const QSslCipher &cipher) {
                                          return !isTls13(cipher);
                                      });
    if (!hasTls13 || !hasTls12) {
        const auto defaults = QTlsBackend::defaultCiphers();
        for (const QSslCipher &cipher : defaults) {
            if (isTls13(cipher) ? !hasTls13 : !hasTls12)
                ciphers << cipher;
        }
    }

    /* The names are wolfSSL's own suite names (see
     * QTlsBackendWolfSSL::ensureInitialized()); wolfSSL takes TLS 1.2 and
     * TLS 1.3 suites in one list. */
    QByteArray list;
    for (const QSslCipher &cipher : std::as_const(ciphers)) {
        if (cipher.isNull())
            continue;
        /* wolfSSL offers PSK suites whether or not a PSK callback is set;
         * OpenSSL does not. Leave them out when no callback is registered. */
        if (!withPsk && cipher.authenticationMethod() == "PSK"_L1)
            continue;
        if (!list.isEmpty())
            list.append(':');
        list.append(cipher.name().toLatin1());
    }
    return list;
}

} /* unnamed namespace */

QSslContext::~QSslContext()
{
    if (session)
        wolfSSL_SESSION_free(session);
    if (ctx)
        wolfSSL_CTX_free(ctx);
}

std::shared_ptr<QSslContext> QSslContext::sharedFromConfiguration(
        QSslSocket::SslMode mode, const QSslConfiguration &configuration,
        bool allowRootCertOnDemandLoading)
{
    struct AccessToPrivateCtor : QSslContext {};
    std::shared_ptr<QSslContext> sslContext
            = std::make_shared<AccessToPrivateCtor>();
    sslContext->init(mode, configuration, allowRootCertOnDemandLoading);
    return sslContext;
}

void QSslContext::setError(const QString &description)
{
    errorStr = description;
    errorCode = QSslError::UnspecifiedError;
}

void QSslContext::init(QSslSocket::SslMode mode,
                       const QSslConfiguration &configuration,
                       bool allowRootCertOnDemandLoading)
{
    sslConfiguration = configuration;
    m_mode = mode;
    errorCode = QSslError::NoError;

    const bool client = mode == QSslSocket::SslClientMode;

    /* Protocol versions. The backend offers TLS 1.2 and TLS 1.3 only. */
    WOLFSSL_METHOD *method = nullptr;
    bool needsMinimumTls12 = false;
    switch (configuration.protocol()) {
    case QSsl::TlsV1_2:
        method = client ? wolfTLSv1_2_client_method()
                        : wolfTLSv1_2_server_method();
        break;
    case QSsl::TlsV1_3:
    case QSsl::TlsV1_3OrLater:
        method = client ? wolfTLSv1_3_client_method()
                        : wolfTLSv1_3_server_method();
        break;
    case QSsl::AnyProtocol:
    case QSsl::SecureProtocols:
    case QSsl::TlsV1_2OrLater:
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
    /* wolfSSL: no TLS 1.0 or 1.1 here, so "1.0 or later" and "1.1 or
     * later" negotiate TLS 1.2 or 1.3, as OpenSSL does at its default
     * security level. */
    case QSsl::TlsV1_0OrLater:
    case QSsl::TlsV1_1OrLater:
QT_WARNING_POP
        method = client ? wolfTLS_client_method() : wolfTLS_server_method();
        needsMinimumTls12 = true;
        break;
    default:
        break;
    }

    if (!method) {
        setError(QSslSocket::tr("Error creating SSL context (%1)")
                         .arg(QSslSocket::tr("unsupported protocol")));
        return;
    }

    ctx = wolfSSL_CTX_new(method);
    if (!ctx) {
        setError(QSslSocket::tr("Error creating SSL context (%1)")
                         .arg(QTlsBackendWolfSSL::errorString(MEMORY_E)));
        return;
    }

    if (needsMinimumTls12) {
        const int ret = wolfSSL_CTX_SetMinVersion(ctx, WOLFSSL_TLSV1_2);
        if (ret != WOLFSSL_SUCCESS) {
            setError(QSslSocket::tr(
                    "Error while setting the minimal protocol version"));
            return;
        }
    }

    /* The I/O bridge (docs/design-io-bridge.md 3.1). Only the functions are
     * set here; the per-connection context is set in createSsl()'s caller,
     * since a QSslContext can be shared between sockets. */
    wolfSSL_CTX_SetIORecv(ctx, q_wolfssl_io_recv);
    wolfSSL_CTX_SetIOSend(ctx, q_wolfssl_io_send);

    /* Ciphers */
#ifndef NO_PSK
    const QTlsPrivate::PskPolicy psk
            = QTlsPrivate::pskPolicy(configuration, mode);
    const bool withPsk = psk.clientTls12 || psk.serverTls12 || psk.tls13;
#else
    const bool withPsk = false;
#endif
    const QByteArray cipherList
            = cipherListFromConfiguration(configuration, withPsk);
    if (cipherList.isEmpty()
        || wolfSSL_CTX_set_cipher_list(ctx, cipherList.constData())
                != WOLFSSL_SUCCESS) {
        setError(QSslSocket::tr("Invalid or empty cipher list (%1)")
                         .arg(QString::fromLatin1(cipherList)));
        return;
    }

    /* CA certificates for peer verification. Expired certificates are left
     * out, as in the OpenSSL backend. */
    const QDateTime now = QDateTime::currentDateTimeUtc();
    const auto caCertificates = configuration.caCertificates();
    for (const QSslCertificate &caCertificate : caCertificates) {
        if (caCertificate.expiryDate() < now)
            continue;
        const QByteArray der = caCertificate.toDer();
        const int ret = wolfSSL_CTX_load_verify_buffer(
                ctx, reinterpret_cast<const unsigned char *>(der.constData()),
                long(der.size()), WOLFSSL_FILETYPE_ASN1);
        if (ret != WOLFSSL_SUCCESS) {
            qCWarning(lcTlsBackendWolfSSL)
                    << "Failed to add a CA certificate:"
                    << QTlsBackendWolfSSL::errorString(ret);
        }
    }

    /* TLSTODO (Phase 5): load the system CA certificates
     * (wolfSSL_CTX_load_system_CA_certs()) when on-demand loading is allowed.
     */
    Q_UNUSED(allowRootCertOnDemandLoading);

    /* Local certificate and private key */
    if (!configuration.localCertificate().isNull()) {
        const QSslKey privateKey = configuration.privateKey();
        if (privateKey.isNull()) {
            setError(
                    QSslSocket::tr("Cannot provide a certificate with no key"));
            return;
        }
        if (privateKey.algorithm() == QSsl::Opaque) {
            setError(QSslSocket::tr("Error loading private key, %1")
                             .arg(QSslSocket::tr(
                                     "opaque keys are not supported")));
            return;
        }

        /* The local certificate first, then any intermediates. */
        QByteArray chainPem = configuration.localCertificate().toPem();
        const auto chain = configuration.localCertificateChain();
        for (qsizetype i = 1; i < chain.size(); ++i)
            chainPem += chain.at(i).toPem();

        int ret = wolfSSL_CTX_use_certificate_chain_buffer(
                ctx,
                reinterpret_cast<const unsigned char *>(chainPem.constData()),
                long(chainPem.size()));
        if (ret != WOLFSSL_SUCCESS) {
            setError(QSslSocket::tr("Error loading local certificate, %1")
                             .arg(QTlsBackendWolfSSL::errorString(ret)));
            return;
        }

        const QByteArray keyDer = privateKey.toDer();
        ret = wolfSSL_CTX_use_PrivateKey_buffer(
                ctx,
                reinterpret_cast<const unsigned char *>(keyDer.constData()),
                long(keyDer.size()), WOLFSSL_FILETYPE_ASN1);
        if (ret != WOLFSSL_SUCCESS) {
            setError(QSslSocket::tr("Error loading private key, %1")
                             .arg(QTlsBackendWolfSSL::errorString(ret)));
            return;
        }

        ret = wolfSSL_CTX_check_private_key(ctx);
        if (ret != WOLFSSL_SUCCESS) {
            setError(QSslSocket::tr(
                             "Private key does not certify public key, %1")
                             .arg(QTlsBackendWolfSSL::errorString(ret)));
            return;
        }
    }

    /* Peer verification. wolfSSL only verifies (and a server only requests a
     * client certificate) with WOLFSSL_VERIFY_PEER. The callback records the
     * errors and lets the handshake continue; QSslSocket's peerVerifyMode
     * decides afterwards whether they matter (docs/design-io-bridge.md 6). */
    if (configuration.peerVerifyMode() == QSslSocket::VerifyNone) {
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, nullptr);
    } else {
        int verifyMode = WOLFSSL_VERIFY_PEER;
        if (!client && configuration.missingCertificateIsFatal())
            verifyMode |= WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT;
        wolfSSL_CTX_set_verify(ctx, verifyMode, q_wolfssl_verify_callback);
    }

    if (configuration.peerVerifyDepth() != 0)
        wolfSSL_CTX_set_verify_depth(ctx, configuration.peerVerifyDepth());

    /* Session tickets and resumption */
#ifdef HAVE_SESSION_TICKET
    const bool ticketsDisabled
            = configuration.testSslOption(QSsl::SslOptionDisableSessionTickets);
    if (client) {
        if (!ticketsDisabled)
            wolfSSL_CTX_UseSessionTicket(ctx);
    } else if (ticketsDisabled) {
        wolfSSL_CTX_NoTicketTLSv12(ctx);
#ifdef WOLFSSL_TLS13
        wolfSSL_CTX_no_ticket_TLSv13(ctx);
#endif
    }
#endif /* HAVE_SESSION_TICKET */

    /* Called for every new session (TLS 1.2 at the end of the handshake,
     * TLS 1.3 for each NewSessionTicket); needs HAVE_EXT_CACHE. */
    if (client)
        wolfSSL_CTX_sess_set_new_cb(ctx, q_wolfssl_new_session_callback);

    /* A persisted session set by the application. */
    if (!configuration.sessionTicket().isEmpty())
        m_sessionASN1 = configuration.sessionTicket();

    /* Diffie-Hellman parameters (server side, TLS 1.2 DHE suites).
     * TLSTODO (Phase 3): parse and validate QSslDiffieHellmanParameters in
     * the backend (dhParametersFromDer/Pem). */
    const QSslDiffieHellmanParameters dhParameters
            = configuration.diffieHellmanParameters();
    if (!dhParameters.isValid()) {
        setError(QSslSocket::tr("Diffie-Hellman parameters are not valid"));
        return;
    }
    if (!client && !dhParameters.isEmpty()) {
        /* QSslContext is a friend of QSslDiffieHellmanParameters. */
        const QByteArray &der = dhParameters.d->derData;
        const int ret = wolfSSL_CTX_SetTmpDH_buffer(
                ctx, reinterpret_cast<const unsigned char *>(der.constData()),
                long(der.size()), WOLFSSL_FILETYPE_ASN1);
        if (ret != WOLFSSL_SUCCESS) {
            qCWarning(lcTlsBackendWolfSSL)
                    << "Failed to set the Diffie-Hellman parameters:"
                    << QTlsBackendWolfSSL::errorString(ret);
        }
    }

    /* PSK (TLS 1.2 external PSK; TLS 1.3 resumption does not use these) */
#ifndef NO_PSK
    if (psk.clientTls12)
        wolfSSL_CTX_set_psk_client_callback(ctx, q_wolfssl_psk_client_callback);
    if (psk.serverTls12) {
        wolfSSL_CTX_set_psk_server_callback(ctx, q_wolfssl_psk_server_callback);
        const QByteArray hint = configuration.preSharedKeyIdentityHint();
        if (!hint.isEmpty())
            wolfSSL_CTX_use_psk_identity_hint(ctx, hint.constData());
    }
    /* TLSTODO: register the *_tls13 callbacks when psk.tls13 is set
     * (docs/design-io-bridge.md 11.5). */
#endif /* !NO_PSK */

    /* TLSTODO (Phase 3): elliptic curves (QSslConfiguration::ellipticCurves()
     * -> wolfSSL_CTX_set_groups()). */
    if (!configuration.ellipticCurves().isEmpty()) {
        qCWarning(lcTlsBackendWolfSSL,
                  "Setting elliptic curves is not supported yet, using "
                  "wolfSSL's defaults");
    }
}

WOLFSSL *QSslContext::createSsl()
{
    if (!ctx)
        return nullptr;

    WOLFSSL *ssl = wolfSSL_new(ctx);
    if (!ssl)
        return nullptr;

    if (m_mode == QSslSocket::SslClientMode) {
        if (!session && !m_sessionASN1.isEmpty()
            && !sslConfiguration.testSslOption(
                    QSsl::SslOptionDisableSessionPersistence)) {
            const auto *data = reinterpret_cast<const unsigned char *>(
                    m_sessionASN1.constData());
            session = wolfSSL_d2i_SSL_SESSION(nullptr, &data,
                                              long(m_sessionASN1.size()));
            if (!session)
                qCWarning(lcTlsBackendWolfSSL,
                          "Could not restore the persisted TLS session");
        }

        if (session && wolfSSL_set_session(ssl, session) != WOLFSSL_SUCCESS) {
            /* An expired session or one for another protocol version; start
             * a full handshake. */
            qCDebug(lcTlsBackendWolfSSL,
                    "Could not resume the cached TLS session");
            wolfSSL_SESSION_free(session);
            session = nullptr;
        }
    }

    return ssl;
}

bool QSslContext::cacheSession(WOLFSSL *ssl)
{
    WOLFSSL_SESSION *current = wolfSSL_get1_session(ssl);
    if (!current)
        return false;
    cacheSession(current);
    wolfSSL_SESSION_free(current);
    return true;
}

void QSslContext::cacheSession(WOLFSSL_SESSION *newSession)
{
    if (!newSession || newSession == session)
        return;

    if (wolfSSL_SESSION_up_ref(newSession) != WOLFSSL_SUCCESS)
        return;
    if (session)
        wolfSSL_SESSION_free(session);
    session = newSession;

    if (sslConfiguration.testSslOption(
                QSsl::SslOptionDisableSessionPersistence)) {
        return;
    }

    const int size = wolfSSL_i2d_SSL_SESSION(session, nullptr);
    if (size <= 0) {
        qCWarning(lcTlsBackendWolfSSL,
                  "Could not store persistent version of the TLS session");
        return;
    }
    QByteArray asn1(size, Qt::Uninitialized);
    auto *data = reinterpret_cast<unsigned char *>(asn1.data());
    if (wolfSSL_i2d_SSL_SESSION(session, &data) != size) {
        qCWarning(lcTlsBackendWolfSSL,
                  "Could not store persistent version of the TLS session");
        return;
    }
    m_sessionASN1 = asn1;
    m_sessionTicketLifeTimeHint
            = int(wolfSSL_SESSION_get_ticket_lifetime_hint(session));
}

QT_END_NAMESPACE
