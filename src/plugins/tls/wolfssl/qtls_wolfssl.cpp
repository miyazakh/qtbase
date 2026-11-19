/*
 * Copyright (C) 2026 The Qt Company Ltd.
 * SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
 * Qt-Security score:critical reason:cryptography
 */

#include "qtls_wolfssl_p.h"
#include "qsslcontext_wolfssl_p.h"
#include "qtlsbackend_wolfssl_p.h"
#include "qx509_wolfssl_p.h"

#include <QtNetwork/private/qsslcertificate_p.h>
#include <QtNetwork/private/qsslsocket_p.h>

#include <QtNetwork/qhostaddress.h>
#include <QtNetwork/qsslpresharedkeyauthenticator.h>
#include <QtNetwork/qtcpsocket.h>

#include <QtCore/qscopedvaluerollback.h>
#include <QtCore/qurl.h>

#include <algorithm>
#include <cstring>

/* wolfssl/options.h must come first, see qtlsbackend_wolfssl.cpp. */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

QT_BEGIN_NAMESPACE

using namespace Qt::StringLiterals;

namespace QTlsPrivate {

namespace {

using ScopedBool = QScopedValueRollback<bool>;

/* Largest TLS record payload; wolfSSL_read() never returns more at once. */
constexpr int readChunkSize = 16384;

bool isWantReadOrWrite(int error)
{
    return error == WOLFSSL_ERROR_WANT_READ
            || error == WOLFSSL_ERROR_WANT_WRITE;
}

} /* unnamed namespace */

TlsCryptographWolfSSL::TlsCryptographWolfSSL() = default;

TlsCryptographWolfSSL::~TlsCryptographWolfSSL()
{
    /* The I/O and verify callbacks point to this object; free the WOLFSSL
     * object first (docs/design-io-bridge.md 8). */
    destroySsl();
}

void TlsCryptographWolfSSL::init(QSslSocket *qObj, QSslSocketPrivate *dObj)
{
    Q_ASSERT(qObj);
    Q_ASSERT(dObj);
    q = qObj;
    d = dObj;

    /* QSslSocket calls init() again when a socket is reused. Do not drop a
     * context set with checkSettingSslContext(): QHttpNetworkConnection sets
     * it before connecting. */
    reset();
}

void TlsCryptographWolfSSL::reset()
{
    if (ssl) {
        wolfSSL_free(ssl);
        ssl = nullptr;
    }
    handshakeState = HandshakeState::Initial;
    certificateErrors.clear();
    sslErrors.clear();
    ioClosed = false;
    pendingSocketError = false;
    pendingNewSessionTicket = false;
    tls13Psk = {};
    drainingOnDisconnect = false;
    shutdown = false;
    closeNotifyReceived = false;
    fatalErrorDetected = false;
}

void TlsCryptographWolfSSL::destroySsl()
{
    if (ssl) {
        wolfSSL_free(ssl);
        ssl = nullptr;
    }
    sslContextPointer.reset();
}

void TlsCryptographWolfSSL::checkSettingSslContext(
        std::shared_ptr<QSslContext> tlsContext)
{
    if (!sslContextPointer)
        sslContextPointer = std::move(tlsContext);
}

std::shared_ptr<QSslContext> TlsCryptographWolfSSL::sslContext() const
{
    return sslContextPointer;
}

QList<QSslError> TlsCryptographWolfSSL::tlsErrors() const
{
    return sslErrors;
}

void TlsCryptographWolfSSL::startClientEncryption()
{
    Q_ASSERT(q);
    if (q->isEncrypted())
        return;
    reset();
    if (!initSsl())
        return;
    handshakeState = HandshakeState::InProgress;
    transmit();
}

void TlsCryptographWolfSSL::startServerEncryption()
{
    Q_ASSERT(q);
    if (q->isEncrypted())
        return;
    reset();
    if (!initSsl())
        return;
    handshakeState = HandshakeState::InProgress;
    transmit();
}

bool TlsCryptographWolfSSL::initSsl()
{
    Q_ASSERT(q);
    Q_ASSERT(d);

    const auto mode = d->tlsMode();
    const auto configuration = q->sslConfiguration();

    /* If no external context was set (e.g. by QHttpNetworkConnection), create
     * a new one. */
    if (sslContextPointer && sslContextPointer->mode() != mode)
        sslContextPointer.reset();
    if (!sslContextPointer) {
        sslContextPointer = QSslContext::sharedFromConfiguration(
                mode, configuration, d->isRootsOnDemandAllowed());
    }

    if (sslContextPointer->error() != QSslError::NoError) {
        setErrorAndEmit(d, QAbstractSocket::SslInvalidUserDataError,
                        sslContextPointer->errorString());
        sslContextPointer.reset();
        return false;
    }

    ssl = sslContextPointer->createSsl();
    if (!ssl) {
        setErrorAndEmit(
                d, QAbstractSocket::SslInternalError,
                QSslSocket::tr("Error creating SSL session, %1")
                        .arg(QTlsBackendWolfSSL::errorString(MEMORY_E)));
        return false;
    }

    /* Per-connection context for the I/O bridge and the verify callback
     * (docs/design-io-bridge.md 3.1). The other callbacks find this object
     * through wolfSSL_GetIOReadCtx(). */
    WolfSSLCallbacks *callbacks = this;
    wolfSSL_SetIOReadCtx(ssl, callbacks);
    wolfSSL_SetIOWriteCtx(ssl, callbacks);
    wolfSSL_SetCertCbCtx(ssl, callbacks);

    const bool tls12Possible = configuration.protocol() != QSsl::TlsV1_3
            && configuration.protocol() != QSsl::TlsV1_3OrLater;
    if (tls12Possible) {
        /* TLS 1.2 renegotiation is refused (docs/design-io-bridge.md 4.2):
         * announce RFC 5746 support, answer a renegotiation request with a
         * no_renegotiation alert and drop the connection in transmit(). */
#ifdef HAVE_SECURE_RENEGOTIATION
        if (mode == QSslSocket::SslClientMode)
            wolfSSL_UseSecureRenegotiation(ssl);
#endif
        wolfSSL_set_options(ssl, WOLFSSL_OP_NO_RENEGOTIATION);
    }

    if (mode == QSslSocket::SslClientMode) {
        /* Server Name Indication. RFC 6066 requires the host name in ACE
         * form, without a trailing dot, and no IP addresses. */
        const auto verificationPeerName = d->verificationName();
        QString tlsHostName = verificationPeerName.isEmpty()
                ? q->peerName()
                : verificationPeerName;
        if (tlsHostName.isEmpty())
            tlsHostName = d->tlsHostName();
        QByteArray ace = QUrl::toAce(tlsHostName);
        if (!ace.isEmpty() && !QHostAddress().setAddress(tlsHostName)
            && !configuration.testSslOption(
                    QSsl::SslOptionDisableServerNameIndication)) {
            if (ace.endsWith('.'))
                ace.chop(1);
            if (wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, ace.constData(),
                               quint16(ace.size())) != WOLFSSL_SUCCESS) {
                qCWarning(lcTlsBackendWolfSSL,
                          "Could not set the Server Name Indication extension");
            }
        }
    }

#ifdef HAVE_ALPN
    /* ALPN. wolfSSL takes a comma-separated list.
     * wolfSSL: there is no ALPN select callback without OPENSSL_ALL/
     * WOLFSSL_NGINX/..., so a server passes its own list here and wolfSSL
     * picks the first of the client's protocols that is in it
     * (ALPN_find_match). If nothing matches, the handshake continues
     * without ALPN. */
    QByteArray alpnList;
    const auto protocols = configuration.allowedNextProtocols();
    for (const QByteArray &protocol : protocols) {
        if (protocol.isEmpty() || protocol.size() > 255
            || protocol.contains(',')) {
            qCWarning(lcTlsBackendWolfSSL)
                    << "ALPN protocol" << protocol << "is ignored";
            continue;
        }
        if (!alpnList.isEmpty())
            alpnList.append(',');
        alpnList.append(protocol);
    }
    if (!alpnList.isEmpty()
        && wolfSSL_UseALPN(ssl, alpnList.data(), word32(alpnList.size()),
                           WOLFSSL_ALPN_CONTINUE_ON_MISMATCH)
                != WOLFSSL_SUCCESS) {
        qCWarning(lcTlsBackendWolfSSL, "Could not set the ALPN extension");
    }
#endif /* HAVE_ALPN */

    return true;
}

bool TlsCryptographWolfSSL::readThrottled() const
{
    /* docs/design-io-bridge.md 4.1: stop pulling records from the socket
     * once the decrypted buffer is full, but never during a handshake and
     * never while draining a closed connection. */
    const qint64 max = d->maxReadBufferSize();
    if (handshakeState != HandshakeState::Done || drainingOnDisconnect
        || max <= 0) {
        return false;
    }
    /* Inside readDecrypted() the buffer already holds the space reserved for
     * the wolfSSL_read() in progress; count only what is really there. */
    const qint64 buffered = bufferedBeforeRead >= 0 ? bufferedBeforeRead
                                                    : d->tlsBuffer().size();
    return buffered >= max;
}

int TlsCryptographWolfSSL::ioRecv(char *buf, int size)
{
    /* Runs inside a wolfSSL call: no signals, no closing (design 3). */
    QTcpSocket *plainSocket = d->plainTcpSocket();
    Q_ASSERT(plainSocket);

    if (readThrottled())
        return WOLFSSL_CBIO_ERR_WANT_READ;

    const qint64 n = plainSocket->read(buf, size);
    if (n > 0)
        return int(n);
    if (n < 0 || plainSocket->state() == QAbstractSocket::UnconnectedState) {
        ioClosed = true;
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    }
    /* Never return 0: wolfSSL would keep calling us (GetInputData()). */
    return WOLFSSL_CBIO_ERR_WANT_READ;
}

int TlsCryptographWolfSSL::ioSend(const char *buf, int size)
{
    QTcpSocket *plainSocket = d->plainTcpSocket();
    Q_ASSERT(plainSocket);

    if (!plainSocket->isValid()
        || plainSocket->openMode() == QIODevice::NotOpen) {
        ioClosed = true;
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    }
    /* QTcpSocket buffers everything we give it, so there is no WANT_WRITE. */
    const qint64 n = plainSocket->write(buf, size);
    if (n < 0) {
        /* Reported by transmit() once wolfSSL has returned. */
        pendingSocketError = true;
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    return int(n);
}

int TlsCryptographWolfSSL::verifyCertificate(int preverify,
                                             WOLFSSL_X509_STORE_CTX *store)
{
    /* Runs inside wolfSSL_connect()/wolfSSL_accept(). With
     * WOLFSSL_ALWAYS_VERIFY_CB this is called for the peer's certificate
     * even when it verified, and for every certificate that failed. */
    if (preverify && store->error == 0)
        return 1;

    const CertificateError error{store->error, store->error_depth};
    const bool known = std::any_of(
            certificateErrors.cbegin(), certificateErrors.cend(),
            [&error](const CertificateError &e) {
                return e.code == error.code && e.depth == error.depth;
            });
    if (!known)
        certificateErrors.append(error);

    switch (verifyMode) {
    case VerifyMode::Collect:
        /* Qt decides after the handshake (verifyPeer()). */
        return 1;
    case VerifyMode::Interrupt:
        /* Reserved for handshakeMustInterruptOnError(), which QtNetwork only
         * supports with OpenSSL for now. */
        return 0;
    }
    Q_UNREACHABLE_RETURN(1);
}

int TlsCryptographWolfSSL::handleNewSession(WOLFSSL_SESSION *session)
{
    /* Called by wolfSSL when the client gets a new session: at the end of a
     * TLS 1.2 handshake and for every TLS 1.3 NewSessionTicket. As in the
     * OpenSSL backend, only TLS 1.3 tickets are handled here; a TLS 1.2
     * session is cached when the handshake completes (finishHandshake()). */
    if (!q || !d || !session || !ssl)
        return 0;
    if (wolfSSL_GetVersion(ssl) != WOLFSSL_TLSV1_3)
        return 0;

    const auto configuration = q->sslConfiguration();
    if (configuration.testSslOption(QSsl::SslOptionDisableSessionPersistence))
        return 0;

    if (sslContextPointer
        && !configuration.testSslOption(QSsl::SslOptionDisableSessionSharing)) {
        sslContextPointer->cacheSession(session);
        if (!sslContextPointer->sessionASN1().isEmpty()) {
            QTlsBackend::setSessionAsn1(d, sslContextPointer->sessionASN1());
            QTlsBackend::setSessionLifetimeHint(
                    d, sslContextPointer->sessionTicketLifeTimeHint());
        }
    } else {
        const int size = wolfSSL_i2d_SSL_SESSION(session, nullptr);
        if (size <= 0)
            return 0;
        QByteArray asn1(size, Qt::Uninitialized);
        auto *data = reinterpret_cast<unsigned char *>(asn1.data());
        if (wolfSSL_i2d_SSL_SESSION(session, &data) != size)
            return 0;
        QTlsBackend::setSessionAsn1(d, asn1);
        QTlsBackend::setSessionLifetimeHint(
                d, int(wolfSSL_SESSION_get_ticket_lifetime_hint(session)));
    }

    /* We are inside wolfSSL_read(): emit newSessionTicketReceived() once it
     * has returned, so that a slot can safely call write() or close(). */
    pendingNewSessionTicket = true;
    return 0;
}

unsigned TlsCryptographWolfSSL::pskClientTlsCallback(const char *hint,
                                                     char *identity,
                                                     unsigned maxIdentityLen,
                                                     unsigned char *psk,
                                                     unsigned maxPskLen)
{
    Q_ASSERT(q);

    /* Like the OpenSSL backend, the application is asked synchronously, from
     * inside the handshake. */
    QSslPreSharedKeyAuthenticator authenticator;
    const int hintLength = hint ? int(std::strlen(hint)) : 0;
    QTlsBackend::setupClientPskAuth(&authenticator, hint, hintLength,
                                    maxIdentityLen, maxPskLen);
    emit q->preSharedKeyAuthenticationRequired(&authenticator);

    /* No PSK set? Return 0 to make the handshake fail. */
    if (authenticator.preSharedKey().isEmpty())
        return 0;

    const int identityLength = qMin(authenticator.identity().size(),
                                    authenticator.maximumIdentityLength());
    std::memcpy(identity, authenticator.identity().constData(), identityLength);
    identity[identityLength] = 0;

    const int pskLength = qMin(authenticator.preSharedKey().size(),
                               authenticator.maximumPreSharedKeyLength());
    std::memcpy(psk, authenticator.preSharedKey().constData(), pskLength);
    return pskLength;
}

unsigned TlsCryptographWolfSSL::pskServerTlsCallback(const char *identity,
                                                     unsigned char *psk,
                                                     unsigned maxPskLen)
{
    Q_ASSERT(q);

    QSslPreSharedKeyAuthenticator authenticator;
    QTlsBackend::setupServerPskAuth(
            &authenticator, identity,
            q->sslConfiguration().preSharedKeyIdentityHint(), maxPskLen);
    emit q->preSharedKeyAuthenticationRequired(&authenticator);

    if (authenticator.preSharedKey().isEmpty())
        return 0;

    const int pskLength = qMin(authenticator.preSharedKey().size(),
                               authenticator.maximumPreSharedKeyLength());
    std::memcpy(psk, authenticator.preSharedKey().constData(), pskLength);
    return pskLength;
}

unsigned TlsCryptographWolfSSL::pskClientTls13Callback(const char *cipherName,
                                                       char *identity,
                                                       unsigned maxIdentityLen,
                                                       unsigned char *psk,
                                                       unsigned maxPskLen)
{
    Q_ASSERT(q);

    /* Called while the TLS 1.3 ClientHello is built, once for each TLS 1.3
     * suite, and again when the binder is computed. Returning 0 offers no
     * PSK for that suite; the handshake goes on with certificates. Without
     * the opt-in the application is not asked, as in the OpenSSL backend. */
    if (!tls13ExternalPskRequested() || !sslContextPointer || !cipherName)
        return 0;
    const char *pskCipher = sslContextPointer->tls13PskCipher();
    if (!pskCipher || std::strcmp(cipherName, pskCipher) != 0)
        return 0;

    if (!tls13Psk.asked) {
        tls13Psk.asked = true;
        QSslPreSharedKeyAuthenticator authenticator;
        QTlsBackend::setupClientPskAuth(&authenticator, nullptr, 0,
                                        maxIdentityLen, maxPskLen);
        emit q->preSharedKeyAuthenticationRequired(&authenticator);
        if (!authenticator.preSharedKey().isEmpty()) {
            tls13Psk.identity = authenticator.identity().left(
                    authenticator.maximumIdentityLength());
            tls13Psk.key = authenticator.preSharedKey().left(
                    authenticator.maximumPreSharedKeyLength());
        }
    }

    /* No PSK set? Return 0: the server authenticates with a certificate. */
    if (tls13Psk.key.isEmpty())
        return 0;

    std::memcpy(identity, tls13Psk.identity.constData(),
                tls13Psk.identity.size());
    identity[tls13Psk.identity.size()] = 0;
    std::memcpy(psk, tls13Psk.key.constData(), tls13Psk.key.size());
    return unsigned(tls13Psk.key.size());
}

unsigned TlsCryptographWolfSSL::pskServerTls13Callback(const char *identity,
                                                       unsigned char *psk,
                                                       unsigned maxPskLen,
                                                       const char **cipherName)
{
    Q_ASSERT(q);

    /* Called for each identity the client offers, once for each suite the
     * two sides share. Ask the application once per identity. */
    const char *pskCipher
            = sslContextPointer ? sslContextPointer->tls13PskCipher() : nullptr;
    if (!pskCipher || !identity)
        return 0;

    const QByteArray offered(identity);
    if (!tls13Psk.asked || tls13Psk.identity != offered) {
        tls13Psk.asked = true;
        tls13Psk.identity = offered;
        tls13Psk.key.clear();
        QSslPreSharedKeyAuthenticator authenticator;
        QTlsBackend::setupServerPskAuth(
                &authenticator, identity,
                q->sslConfiguration().preSharedKeyIdentityHint(), maxPskLen);
        emit q->preSharedKeyAuthenticationRequired(&authenticator);
        tls13Psk.key = authenticator.preSharedKey().left(
                authenticator.maximumPreSharedKeyLength());
    }

    if (tls13Psk.key.isEmpty())
        return 0;

    *cipherName = pskCipher;
    std::memcpy(psk, tls13Psk.key.constData(), tls13Psk.key.size());
    return unsigned(tls13Psk.key.size());
}

void TlsCryptographWolfSSL::transmit()
{
    Q_ASSERT(q);
    Q_ASSERT(d);

    if (inSetAndEmitError || fatalErrorDetected)
        return;
    if (!ssl)
        return;

    /* Paused on sslErrors(): wait for QSslSocket::resume() / ignoreSslErrors().
     */
    if (handshakeState == HandshakeState::Verifying)
        return;

    bool progressed;
    do {
        progressed = false;

        if (handshakeState == HandshakeState::InProgress
            || handshakeState == HandshakeState::Renegotiating) {
            if (d->isPaused())
                return;
            if (!doHandshake())
                return; /* waiting for data, paused, or failed */
            progressed = true;
        }

        if (!ssl || handshakeState != HandshakeState::Done)
            return;

        if (!d->tlsWriteBuffer().isEmpty() && !writeEncrypted())
            return;

        if (!ssl)
            return;

        bool gotData = false;
        if (!readDecrypted(&gotData))
            return;
        progressed = progressed || gotData;
    } while (progressed && ssl && handshakeState == HandshakeState::Done);
}

bool TlsCryptographWolfSSL::doHandshake()
{
    QTcpSocket *plainSocket = d->plainTcpSocket();
    const bool client = d->tlsMode() == QSslSocket::SslClientMode;

    const int result = client ? wolfSSL_connect(ssl) : wolfSSL_accept(ssl);

    /* A slot connected to preSharedKeyAuthenticationRequired() may have
     * aborted the connection. */
    if (!ssl || q->state() != QAbstractSocket::ConnectedState)
        return false;

    if (result != WOLFSSL_SUCCESS) {
        const int error = wolfSSL_get_error(ssl, result);
        if (isWantReadOrWrite(error))
            return false; /* the handshake is not complete yet */

        if (pendingSocketError) {
            const ScopedBool bg(inSetAndEmitError, true);
            fatalErrorDetected = true;
            setErrorAndEmit(d, plainSocket->error(),
                            plainSocket->errorString());
            return false;
        }
        if (ioClosed) {
            /* The TCP connection went away without a TLS alert. QSslSocket
             * reports that from the plain socket (RemoteHostClosedError). */
            return false;
        }

        fatalErrorDetected = true;
        {
            const ScopedBool bg(inSetAndEmitError, true);
            setErrorAndEmit(
                    d, QAbstractSocket::SslHandshakeFailedError,
                    QSslSocket::tr("Error during SSL handshake: %1")
                            .arg(QTlsBackendWolfSSL::errorString(error)));
        }
        /* wolfSSL has queued a fatal alert in the plain socket; try to get it
         * out before dropping the connection, as the OpenSSL backend does. */
        plainSocket->flush();
        q->abort();
        return false;
    }

    return verifyPeer();
}

void TlsCryptographWolfSSL::storePeerCertificates()
{
    /* Needs SESSION_CERTS (--enable-sessioncerts). For both clients and
     * servers the chain starts with the peer's own certificate. */
    QList<QSslCertificate> chain;
    if (WOLFSSL_X509_CHAIN *peerChain = wolfSSL_get_peer_chain(ssl)) {
        const int count = wolfSSL_get_chain_count(peerChain);
        chain.reserve(count);
        for (int i = 0; i < count; ++i) {
            const unsigned char *der = wolfSSL_get_chain_cert(peerChain, i);
            const int length = wolfSSL_get_chain_length(peerChain, i);
            if (!der || length <= 0)
                continue;
            QSslCertificate certificate(
                    QByteArray(reinterpret_cast<const char *>(der), length),
                    QSsl::Der);
            if (!certificate.isNull())
                chain.append(certificate);
        }
    }

    QTlsBackend::storePeerCertificate(d, chain.value(0));
    QTlsBackend::storePeerCertificateChain(d, chain);
}

bool TlsCryptographWolfSSL::verifyPeer()
{
    /* The handshake has completed; judge the peer now (docs/design-io-bridge.md
     * 6). Structured like the OpenSSL backend's startHandshake() after
     * SSL_connect() succeeded. */
    handshakeState = HandshakeState::Verifying;

    const auto mode = d->tlsMode();
    storePeerCertificates();

    const auto configuration = q->sslConfiguration();
    const auto peerCertificateChain = configuration.peerCertificateChain();
    const QSslCertificate peerCertificate = configuration.peerCertificate();

    QList<QSslError> errors;
    const auto addError = [this, &errors](const QSslError &error) {
        errors << error;
        emit q->peerVerifyError(error);
        return q->state() == QAbstractSocket::ConnectedState;
    };

    /* Errors collected by the verify callback during the handshake. */
    QList<QSslError> chainErrors;
    for (const CertificateError &error : std::as_const(certificateErrors)) {
        const QSslCertificate cert = peerCertificateChain.value(error.depth);
        const QSslError sslError(
                X509CertificateWolfSSL::sslErrorFromWolfSSL(
                        error.code, error.depth, peerCertificateChain),
                cert);
        if (!chainErrors.contains(sslError))
            chainErrors << sslError;
    }
    X509CertificateWolfSSL::addValidityErrors(&chainErrors);
    for (const QSslError &error : std::as_const(chainErrors)) {
        if (!addError(error))
            return false;
    }

    /* Check the whole chain for blacklisting (including the root). */
    for (const QSslCertificate &cert : peerCertificateChain) {
        if (QSslCertificatePrivate::isBlacklisted(cert)
            && !addError(QSslError(QSslError::CertificateBlacklisted, cert))) {
            return false;
        }
    }

    const bool doVerifyPeer
            = configuration.peerVerifyMode() == QSslSocket::VerifyPeer
            || (configuration.peerVerifyMode() == QSslSocket::AutoVerifyPeer
                && mode == QSslSocket::SslClientMode);

    if (!peerCertificate.isNull()) {
        /* Only a client checks the host name. */
        if (mode == QSslSocket::SslClientMode) {
            const auto verificationPeerName = d->verificationName();
            const QString peerName = verificationPeerName.isEmpty()
                    ? q->peerName()
                    : verificationPeerName;
            if (!isMatchingHostname(peerCertificate, peerName)
                && !addError(QSslError(QSslError::HostNameMismatch,
                                       peerCertificate))) {
                return false;
            }
        }
    } else if (doVerifyPeer) {
        /* A PSK handshake or a resumed session can complete without a
         * certificate; report it if the socket expected one. */
        if (!wolfSSL_session_reused(ssl)
            && !addError(QSslError(QSslError::NoPeerCertificate))) {
            return false;
        }
    }

    if (!errors.isEmpty()) {
        sslErrors = errors;
        if (!checkSslErrors())
            return false;
        /* A slot connected to sslErrors() may have closed the socket. */
        if (q->state() != QAbstractSocket::ConnectedState)
            return false;
    } else {
        sslErrors.clear();
    }

    continueHandshake();
    return ssl && handshakeState == HandshakeState::Done;
}

bool TlsCryptographWolfSSL::checkSslErrors()
{
    /* Same as the OpenSSL and Schannel backends. */
    if (sslErrors.isEmpty())
        return true;

    emit q->sslErrors(sslErrors);

    const auto configuration = q->sslConfiguration();
    const bool doVerifyPeer
            = configuration.peerVerifyMode() == QSslSocket::VerifyPeer
            || (configuration.peerVerifyMode() == QSslSocket::AutoVerifyPeer
                && d->tlsMode() == QSslSocket::SslClientMode);
    const bool doEmitSslError = !d->verifyErrorsHaveBeenIgnored();
    if (doVerifyPeer && doEmitSslError) {
        if (q->pauseMode() & QAbstractSocket::PauseOnSslErrors) {
            QSslSocketPrivate::pauseSocketNotifiers(q);
            d->setPaused(true);
        } else {
            fatalErrorDetected = true;
            setErrorAndEmit(d, QAbstractSocket::SslHandshakeFailedError,
                            sslErrors.constFirst().errorString());
            /* We verify after wolfSSL completed the handshake, so our last
             * flight (with Finished) is still unsent in the plain socket.
             * Drop it: the peer must not see a completed handshake. The
             * OpenSSL backend never moves it out of its write BIO. */
            d->plainTcpSocket()->abort();
        }
        return false;
    }
    return true;
}

void TlsCryptographWolfSSL::continueHandshake()
{
    /* Called by verifyPeer() and by QSslSocket when the application resumes
     * a socket paused on sslErrors() (after ignoring them). */
    Q_ASSERT(q);
    Q_ASSERT(d);

    if (!ssl)
        return;

    switch (handshakeState) {
    case HandshakeState::Initial:
        return;
    case HandshakeState::InProgress:
    case HandshakeState::Renegotiating:
        transmit();
        return;
    case HandshakeState::Verifying:
        finishHandshake();
        return;
    case HandshakeState::Done:
        return;
    }
}

void TlsCryptographWolfSSL::finishHandshake()
{
    auto *plainSocket = d->plainTcpSocket();
    Q_ASSERT(plainSocket);

    /* If we have a max read buffer size, reset the plain socket's to match. */
    if (const auto maxSize = d->maxReadBufferSize())
        plainSocket->setReadBufferSize(maxSize);

    if (wolfSSL_session_reused(ssl))
        QTlsBackend::setPeerSessionShared(d, true);

    const auto configuration = q->sslConfiguration();
    const auto mode = d->tlsMode();

    /* Cache this session in the QSslContext for resumption. For TLS 1.3 the
     * usable session arrives later, with the NewSessionTicket
     * (handleNewSession()). */
    if (mode == QSslSocket::SslClientMode && sslContextPointer
        && !configuration.testSslOption(QSsl::SslOptionDisableSessionSharing)) {
        if (sslContextPointer->cacheSession(ssl)
            && !configuration.testSslOption(
                    QSsl::SslOptionDisableSessionPersistence)) {
            if (!sslContextPointer->sessionASN1().isEmpty())
                QTlsBackend::setSessionAsn1(d,
                                            sslContextPointer->sessionASN1());
            QTlsBackend::setSessionLifetimeHint(
                    d, sslContextPointer->sessionTicketLifeTimeHint());
        }
    }

#ifdef HAVE_ALPN
    if (!configuration.allowedNextProtocols().isEmpty()) {
        char *protocol = nullptr;
        word16 protocolSize = 0;
        if (wolfSSL_ALPN_GetProtocol(ssl, &protocol, &protocolSize)
                    == WOLFSSL_SUCCESS
            && protocol && protocolSize) {
            QTlsBackend::setAlpnStatus(
                    d, QSslConfiguration::NextProtocolNegotiationNegotiated);
            QTlsBackend::setNegotiatedProtocol(
                    d, QByteArray(protocol, protocolSize));
        } else {
            /* wolfSSL does not tell a server whether the client sent no ALPN
             * extension or no protocol matched; both end up here. */
            QTlsBackend::setAlpnStatus(
                    d, QSslConfiguration::NextProtocolNegotiationNone);
            QTlsBackend::setNegotiatedProtocol(d, {});
        }
    }
#endif /* HAVE_ALPN */

    handshakeState = HandshakeState::Done;
    d->setEncrypted(true);
    emit q->encrypted();
    if (d->isAutoStartingHandshake() && d->isPendingClose()) {
        d->setPendingClose(false);
        q->disconnectFromHost();
    }
}

bool TlsCryptographWolfSSL::writeEncrypted()
{
    auto &writeBuffer = d->tlsWriteBuffer();
    qint64 totalBytesWritten = 0;
    int nextDataBlockSize;
    while ((nextDataBlockSize = writeBuffer.nextDataBlockSize()) > 0) {
        const int written = wolfSSL_write(ssl, writeBuffer.readPointer(),
                                          nextDataBlockSize);
        if (written <= 0) {
            const int error = wolfSSL_get_error(ssl, written);
            if (isWantReadOrWrite(error)) {
                /* WANT_READ: e.g. waiting for the peer during a TLS 1.3 key
                 * update; the read below picks it up. */
                break;
            }
            handleWolfSSLError(error, QAbstractSocket::SslInternalError,
                               QSslSocket::tr("Unable to write data: %1"));
            return false;
        }
        writeBuffer.free(written);
        totalBytesWritten += written;
    }

    if (checkRefusedRenegotiation())
        return false;

    if (totalBytesWritten > 0) {
        /* Don't emit bytesWritten() recursively. */
        bool &emittedBytesWritten = d->tlsEmittedBytesWritten();
        if (!emittedBytesWritten) {
            emittedBytesWritten = true;
            emit q->bytesWritten(totalBytesWritten);
            emittedBytesWritten = false;
        }
        emit q->channelBytesWritten(0, totalBytesWritten);
    }
    return ssl != nullptr;
}

bool TlsCryptographWolfSSL::readDecrypted(bool *gotData)
{
    /* Read until wolfSSL wants more data: records already pulled into
     * wolfSSL's input buffer are not visible through wolfSSL_pending(), so
     * stopping early could stall the socket (docs/design-io-bridge.md 4). */
    if (closeNotifyReceived)
        return false; /* reported once already */

    auto &buffer = d->tlsBuffer();
    while (ssl) {
        if (q->readChannelCount() == 0) {
            /* The read buffer is deallocated, don't try resize or write to it.
             */
            break;
        }

        bufferedBeforeRead = buffer.size();
        const int readBytes = wolfSSL_read(ssl, buffer.reserve(readChunkSize),
                                           readChunkSize);
        bufferedBeforeRead = -1;
        if (readBytes > 0) {
            buffer.chop(readChunkSize - readBytes);
            *gotData = true;
            if (bool *readyReadEmittedPointer = d->readyReadPointer())
                *readyReadEmittedPointer = true;
            emit q->readyRead();
            emit q->channelReadyRead(0);
            if (pendingNewSessionTicket && ssl) {
                pendingNewSessionTicket = false;
                emit q->newSessionTicketReceived();
            }
            continue;
        }
        buffer.chop(readChunkSize);

        const int error = wolfSSL_get_error(ssl, readBytes);

        if (pendingNewSessionTicket) {
            pendingNewSessionTicket = false;
            emit q->newSessionTicketReceived();
            if (!ssl)
                return false;
        }

        if (isWantReadOrWrite(error))
            break;

        if (error == WOLFSSL_ERROR_ZERO_RETURN) {
            /* The peer sent close_notify; do not send ours. */
            shutdown = true;
            closeNotifyReceived = true;
            const ScopedBool bg(inSetAndEmitError, true);
            setErrorAndEmit(
                    d, QAbstractSocket::RemoteHostClosedError,
                    QSslSocket::tr("The TLS/SSL connection has been closed"));
            return false;
        }

        if (ioClosed && !pendingSocketError) {
            /* The TCP connection closed without close_notify. QSslSocket
             * reports it from the plain socket, as with the OpenSSL backend. */
            shutdown = true;
            return false;
        }

        handleWolfSSLError(error, QAbstractSocket::SslInternalError,
                           QSslSocket::tr("Error while reading: %1"));
        return false;
    }

    return !checkRefusedRenegotiation() && ssl;
}

void TlsCryptographWolfSSL::handleWolfSSLError(
        int error, QAbstractSocket::SocketError socketError,
        const QString &context)
{
    /* An error after the handshake: the connection cannot be used any more. */
    fatalErrorDetected = true;
    const ScopedBool bg(inSetAndEmitError, true);
    if (pendingSocketError) {
        auto *plainSocket = d->plainTcpSocket();
        setErrorAndEmit(d, plainSocket->error(), plainSocket->errorString());
        return;
    }
    setErrorAndEmit(d, socketError,
                    context.arg(QTlsBackendWolfSSL::errorString(error)));
}

bool TlsCryptographWolfSSL::checkRefusedRenegotiation()
{
    /* docs/design-io-bridge.md 4.2: wolfSSL answers a renegotiation request
     * with a warning no_renegotiation alert and carries on; we drop the
     * connection instead. */
    if (!ssl)
        return false;
    WOLFSSL_ALERT_HISTORY history = {};
    if (wolfSSL_get_alert_history(ssl, &history) != WOLFSSL_SUCCESS
        || history.last_tx.code != no_renegotiation) {
        return false;
    }

    fatalErrorDetected = true;
    shutdown = true;
    {
        const ScopedBool bg(inSetAndEmitError, true);
        setErrorAndEmit(
                d, QAbstractSocket::SslHandshakeFailedError,
                QSslSocket::tr("The peer requested a TLS renegotiation, "
                               "which is not supported"));
    }
    d->plainTcpSocket()->flush();
    q->abort();
    return true;
}

bool TlsCryptographWolfSSL::hasUndecryptedData() const
{
    /* Counts only decrypted bytes wolfSSL holds; see readDecrypted() for
     * why records still in its input buffer do not matter. */
    return ssl && wolfSSL_pending(ssl) > 0;
}

void TlsCryptographWolfSSL::disconnectFromHost()
{
    Q_ASSERT(d);
    auto *plainSocket = d->plainTcpSocket();
    Q_ASSERT(plainSocket);

    if (ssl && !shutdown && !fatalErrorDetected
        && handshakeState == HandshakeState::Done
        && plainSocket->state() != QAbstractSocket::UnconnectedState) {
        shutdown = true;
        /* Sends close_notify through ioSend(); like the other backends we do
         * not wait for the peer's close_notify. */
        wolfSSL_shutdown(ssl);
    }
    plainSocket->disconnectFromHost();
}

void TlsCryptographWolfSSL::disconnected()
{
    Q_ASSERT(d);
    auto *plainSocket = d->plainTcpSocket();
    Q_ASSERT(plainSocket);

    shutdown = true;
    if (ssl && (plainSocket->bytesAvailable() > 0 || hasUndecryptedData())) {
        /* Read as much as possible, this is likely our last chance. The
         * readBufferSize limit does not apply (design 4.1). */
        const ScopedBool draining(drainingOnDisconnect, true);
        const qint64 tmpReadBufferMaxSize = d->maxReadBufferSize();
        d->setMaxReadBufferSize(0);
        transmit();
        d->setMaxReadBufferSize(tmpReadBufferMaxSize);
        /* Keep the WOLFSSL object until the socket is reused or destroyed. */
    } else {
        destroySsl();
    }
    d->setEncrypted(false);
}

QSslCipher TlsCryptographWolfSSL::sessionCipher() const
{
    if (!ssl || handshakeState != HandshakeState::Done)
        return {};
    const char *name = wolfSSL_get_cipher_name(ssl);
    if (!name)
        return {};
    return QTlsBackendWolfSSL::ciphersuiteFromName(QLatin1StringView(name));
}

QSsl::SslProtocol TlsCryptographWolfSSL::sessionProtocol() const
{
    if (!ssl)
        return QSsl::UnknownProtocol;

    switch (wolfSSL_GetVersion(ssl)) {
    case WOLFSSL_TLSV1_2:
        return QSsl::TlsV1_2;
    case WOLFSSL_TLSV1_3:
        return QSsl::TlsV1_3;
    default:
        return QSsl::UnknownProtocol;
    }
}

} /* namespace QTlsPrivate */

QT_END_NAMESPACE
