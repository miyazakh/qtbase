/*
 * Copyright (C) 2026 The Qt Company Ltd.
 * SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
 * Qt-Security score:critical reason:cryptography
 */

#include "qsslcontext_wolfssl_p.h"
#include "qtls_wolfssl_p.h"
#include "qtlsbackend_wolfssl_p.h"

#include <QtNetwork/private/qssldiffiehellmanparameters_p.h>
#include <QtNetwork/private/qtlsbackend_p.h>

#include <QtNetwork/qsslcertificate.h>
#include <QtNetwork/qsslcipher.h>
#include <QtNetwork/qssldiffiehellmanparameters.h>
#include <QtNetwork/qsslellipticcurve.h>
#include <QtNetwork/qsslkey.h>

#include <QtCore/qdatetime.h>

#include <algorithm>

/* wolfssl/options.h must come first, see qtlsbackend_wolfssl.cpp. */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

QT_BEGIN_NAMESPACE

using namespace Qt::StringLiterals;

namespace QTlsPrivate {

WolfSSLCallbacks::~WolfSSLCallbacks() = default;

int WolfSSLCallbacks::handleNewSession(WOLFSSL_SESSION *session)
{
    Q_UNUSED(session);
    return 0;
}

unsigned WolfSSLCallbacks::pskClientTlsCallback(const char *hint,
                                                char *identity,
                                                unsigned maxIdentityLen,
                                                unsigned char *psk,
                                                unsigned maxPskLen)
{
    Q_UNUSED(hint);
    Q_UNUSED(identity);
    Q_UNUSED(maxIdentityLen);
    Q_UNUSED(psk);
    Q_UNUSED(maxPskLen);
    return 0;
}

unsigned WolfSSLCallbacks::pskServerTlsCallback(const char *identity,
                                                unsigned char *psk,
                                                unsigned maxPskLen)
{
    Q_UNUSED(identity);
    Q_UNUSED(psk);
    Q_UNUSED(maxPskLen);
    return 0;
}

unsigned WolfSSLCallbacks::pskClientTls13Callback(const char *cipherName,
                                                  char *identity,
                                                  unsigned maxIdentityLen,
                                                  unsigned char *psk,
                                                  unsigned maxPskLen)
{
    Q_UNUSED(cipherName);
    Q_UNUSED(identity);
    Q_UNUSED(maxIdentityLen);
    Q_UNUSED(psk);
    Q_UNUSED(maxPskLen);
    return 0;
}

unsigned WolfSSLCallbacks::pskServerTls13Callback(const char *identity,
                                                  unsigned char *psk,
                                                  unsigned maxPskLen,
                                                  const char **cipherName)
{
    Q_UNUSED(identity);
    Q_UNUSED(psk);
    Q_UNUSED(maxPskLen);
    Q_UNUSED(cipherName);
    return 0;
}

bool isDtlsProtocol(QSsl::SslProtocol protocol)
{
    switch (protocol) {
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
    case QSsl::DtlsV1_0:
    case QSsl::DtlsV1_0OrLater:
QT_WARNING_POP
    case QSsl::DtlsV1_2:
    case QSsl::DtlsV1_2OrLater:
        return true;
    default:
        return false;
    }
}

bool tls13ExternalPskRequested()
{
    /* The same opt-in as the OpenSSL backend: a TLS 1.3 client asks the
     * application for an external PSK only when this is set, since it has
     * to do so before it knows whether the server wants one. */
    return qEnvironmentVariableIsSet("QT_USE_TLS_1_3_PSK");
}

PskPolicy pskPolicy(const QSslConfiguration &configuration,
                    QSslSocket::SslMode mode)
{
    const QSsl::SslProtocol protocol = configuration.protocol();
    /* DTLS is DTLS 1.2 only, which uses the TLS 1.2 callbacks. */
    const bool tls12Possible = protocol != QSsl::TlsV1_3
            && protocol != QSsl::TlsV1_3OrLater;
    const bool tls13Possible = protocol != QSsl::TlsV1_2
            && !isDtlsProtocol(protocol);

    PskPolicy policy;
    if (mode == QSslSocket::SslClientMode) {
#ifndef WOLFSSL_PSK_ONE_ID
        /* wolfSSL calls a client PSK callback while it builds every TLS 1.3
         * ClientHello. With the cipher suite callback registered, it calls
         * that one there instead (once per TLS 1.3 suite) and takes a key
         * length of 0 as "no PSK"; the TLS 1.2 callback is then only called
         * once the server has chosen a TLS 1.2 PSK suite
         * (docs/design-io-bridge.md 11.3, 11.4). */
        policy.clientTls12 = tls12Possible;
        policy.clientTls13 = tls13Possible;
#else
        /* wolfSSL: with WOLFSSL_PSK_ONE_ID the TLS 1.2 callback is called
         * for the TLS 1.3 ClientHello and cannot answer "no PSK". Register
         * it only when TLS 1.3 cannot be negotiated. */
        policy.clientTls12 = !tls13Possible;
#endif
    } else if (mode == QSslSocket::SslServerMode) {
        /* Like the OpenSSL backend, a server always answers PSK identities,
         * TLS 1.2 and TLS 1.3 alike. */
        policy.serverTls12 = tls12Possible;
        policy.serverTls13 = tls13Possible;
    }
    return policy;
}

} /* namespace QTlsPrivate */

using QTlsPrivate::WolfSSLCallbacks;

namespace {

WolfSSLCallbacks *cryptographFromSsl(WOLFSSL *ssl)
{
    /* The I/O read context is the object that owns ssl (see
     * TlsCryptographWolfSSL::initSsl() and qdtls_wolfssl.cpp); the other
     * callbacks reuse it. */
    return ssl ? static_cast<WolfSSLCallbacks *>(wolfSSL_GetIOReadCtx(ssl))
               : nullptr;
}

extern "C" {

int q_wolfssl_io_recv(WOLFSSL *, char *buf, int sz, void *ctx)
{
    auto *tls = static_cast<WolfSSLCallbacks *>(ctx);
    if (!tls)
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    return tls->ioRecv(buf, sz);
}

int q_wolfssl_io_send(WOLFSSL *, char *buf, int sz, void *ctx)
{
    auto *tls = static_cast<WolfSSLCallbacks *>(ctx);
    if (!tls)
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    return tls->ioSend(buf, sz);
}

int q_wolfssl_verify_callback(int preverify, WOLFSSL_X509_STORE_CTX *store)
{
    /* userCtx is set with wolfSSL_SetCertCbCtx() for every WOLFSSL object. */
    auto *tls = store ? static_cast<WolfSSLCallbacks *>(store->userCtx)
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
     * handshake when the TLS 1.3 callback finds no key
     * (docs/design-io-bridge.md 11.3). The application has already been
     * asked by then. */
    if (wolfSSL_GetVersion(ssl) == WOLFSSL_TLSV1_3)
        return 0;
    if (auto *tls = cryptographFromSsl(ssl))
        return tls->pskServerTlsCallback(identity, key, maxKeyLen);
    return 0;
}

#ifndef WOLFSSL_PSK_ONE_ID
unsigned int q_wolfssl_psk_client_cs_callback(WOLFSSL *ssl, const char *hint,
                                              char *identity,
                                              unsigned int maxIdentityLen,
                                              unsigned char *key,
                                              unsigned int maxKeyLen,
                                              const char *cipherName)
{
    /* TLS 1.3 has no identity hint. */
    Q_UNUSED(hint);
    if (auto *tls = cryptographFromSsl(ssl)) {
        return tls->pskClientTls13Callback(cipherName, identity,
                                           maxIdentityLen, key, maxKeyLen);
    }
    return 0;
}
#endif

unsigned int q_wolfssl_psk_server_tls13_callback(WOLFSSL *ssl,
                                                 const char *identity,
                                                 unsigned char *key,
                                                 unsigned int maxKeyLen,
                                                 const char **cipherName)
{
    if (auto *tls = cryptographFromSsl(ssl)) {
        return tls->pskServerTls13Callback(identity, key, maxKeyLen,
                                           cipherName);
    }
    return 0;
}
#endif /* !NO_PSK */

} /* extern "C" */

QByteArray cipherListFromConfiguration(const QSslConfiguration &configuration,
                                       bool withPsk, bool dtls)
{
    QList<QSslCipher> ciphers = configuration.ciphers();
    const auto isTls13 = [](const QSslCipher &cipher) {
        return cipher.protocol() == QSsl::TlsV1_3;
    };

    if (dtls) {
        /* DTLS 1.2 only: no TLS 1.3 suites. */
#if QT_CONFIG(dtls)
        if (ciphers.isEmpty())
            ciphers = QTlsBackend::defaultDtlsCiphers();
#endif
        ciphers.removeIf(isTls13);
    } else {
        if (ciphers.isEmpty())
            ciphers = QTlsBackend::defaultCiphers();

        /* OpenSSL keeps its TLS 1.3 suites (set separately) when the list
         * has only TLS 1.2 suites, and the other way round. Do the same, so
         * that a list without TLS 1.3 suites does not disable TLS 1.3. */
        const bool hasTls13 = std::any_of(ciphers.cbegin(), ciphers.cend(),
                                          isTls13);
        const bool hasTls12 = std::any_of(
                ciphers.cbegin(), ciphers.cend(),
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
#if QT_CONFIG(wolfssl_dtls)
    /* DTLS 1.2 only: no QSsl::DtlsV1_3 exists, and DTLS 1.0 is not offered,
     * so "1.0 or later" negotiates DTLS 1.2. */
    case QSsl::DtlsV1_2:
    case QSsl::DtlsV1_2OrLater:
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
    case QSsl::DtlsV1_0OrLater:
QT_WARNING_POP
        method = client ? wolfDTLSv1_2_client_method()
                        : wolfDTLSv1_2_server_method();
        break;
#endif
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
    const bool withPsk = psk.any();
#else
    const bool withPsk = false;
#endif
    const QByteArray cipherList = cipherListFromConfiguration(
            configuration, withPsk,
            QTlsPrivate::isDtlsProtocol(configuration.protocol()));
    if (cipherList.isEmpty()
        || wolfSSL_CTX_set_cipher_list(ctx, cipherList.constData())
                != WOLFSSL_SUCCESS) {
        setError(QSslSocket::tr("Invalid or empty cipher list (%1)")
                         .arg(QString::fromLatin1(cipherList)));
        return;
    }

    /* wolfSSL picks the server's preferred suite by default, as Qt does
     * unless asked otherwise. */
    if (!client
        && configuration.testSslOption(
                QSsl::SslOptionDisableServerCipherPreference)) {
        wolfSSL_CTX_UseClientSuites(ctx);
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

    /* The system CA certificates are already in the default configuration
     * (QTlsBackendWolfSSL::ensureInitialized()), so there is nothing to load
     * on demand: the backend never reports on-demand loading as supported.
     * On Windows this also means that missing roots are not fetched from
     * Windows Update during the handshake, unlike the OpenSSL backend. */
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

    /* Diffie-Hellman parameters (server side, TLS 1.2 DHE suites), validated
     * by QTlsBackendWolfSSL::dhParametersFromDer/Pem(). */
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

    /* External PSK (TLS 1.3 resumption does not use these callbacks) */
#ifndef NO_PSK
    if (psk.clientTls12)
        wolfSSL_CTX_set_psk_client_callback(ctx, q_wolfssl_psk_client_callback);
#ifndef WOLFSSL_PSK_ONE_ID
    if (psk.clientTls13) {
        wolfSSL_CTX_set_psk_client_cs_callback(
                ctx, q_wolfssl_psk_client_cs_callback);
    }
#endif
    if (psk.serverTls12) {
        wolfSSL_CTX_set_psk_server_callback(ctx, q_wolfssl_psk_server_callback);
        const QByteArray hint = configuration.preSharedKeyIdentityHint();
        if (!hint.isEmpty())
            wolfSSL_CTX_use_psk_identity_hint(ctx, hint.constData());
    }
    if (psk.serverTls13) {
        wolfSSL_CTX_set_psk_server_tls13_callback(
                ctx, q_wolfssl_psk_server_tls13_callback);
    }

    /* A TLS 1.3 external PSK is bound to a hash. As OpenSSL does for the
     * PSK callbacks of QSslSocket, use SHA-256: the first SHA-256 suite of
     * the cipher list. The server only accepts the PSK with exactly this
     * suite; the client accepts any suite with the same hash. */
    if (psk.clientTls13 || psk.serverTls13) {
        const auto names = cipherList.split(':');
        for (const QByteArray &name : names) {
            if (name.startsWith("TLS13-") && name.endsWith("-SHA256")) {
                m_tls13PskCipher = name;
                break;
            }
        }
        qCDebug(lcTlsBackendWolfSSL) << "TLS 1.3 external PSK cipher suite:"
                                     << m_tls13PskCipher;
    }
#endif /* !NO_PSK */

    /* Elliptic curves, in the order of preference given. wolfSSL takes the
     * TLS group code points, which are the QSslEllipticCurve ids of this
     * backend; this sets both supported_groups and the TLS 1.3 key shares. */
    const QList<QSslEllipticCurve> curves = configuration.ellipticCurves();
    if (!curves.isEmpty()) {
        QList<int> groups;
        for (const QSslEllipticCurve &curve : curves) {
            const int group = QTlsBackendWolfSSL::tlsGroupForCurve(curve.id);
            if (group && !groups.contains(group))
                groups << group;
        }
        if (groups.isEmpty()) {
            setError(QSslSocket::tr(
                             "Error when setting the elliptic curves (%1)")
                             .arg(QSslSocket::tr(
                                     "no curve is supported by wolfSSL")));
            return;
        }
        if (groups.size() > WOLFSSL_MAX_GROUP_COUNT) {
            setError(QSslSocket::tr(
                             "Error when setting the elliptic curves (%1)")
                             .arg(QSslSocket::tr(
                                          "wolfSSL accepts at most %1 curves")
                                          .arg(WOLFSSL_MAX_GROUP_COUNT)));
            return;
        }
        const int ret = wolfSSL_CTX_set_groups(ctx, groups.data(),
                                               int(groups.size()));
        if (ret != WOLFSSL_SUCCESS) {
            setError(QSslSocket::tr(
                             "Error when setting the elliptic curves (%1)")
                             .arg(QTlsBackendWolfSSL::errorString(ret)));
            return;
        }
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
