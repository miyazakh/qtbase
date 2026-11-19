/*
 * Copyright (C) 2026 The Qt Company Ltd.
 * SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
 * Qt-Security score:critical reason:cryptography
 */

#include "qdtls_wolfssl_p.h"
#include "qtlsbackend_wolfssl_p.h"
#include "qx509_wolfssl_p.h"

#include <QtNetwork/private/qsslcertificate_p.h>

#include <QtNetwork/qudpsocket.h>

#include <QtCore/qdebug.h>

#include <algorithm>
#include <cstring>

/* wolfssl/options.h must come first, see qtlsbackend_wolfssl.cpp. */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/random.h>

QT_BEGIN_NAMESPACE

using namespace Qt::StringLiterals;

namespace {

/* As in the OpenSSL backend: without an MTU hint and without a path MTU
 * from a connected socket, the handshake is fragmented for 576 bytes. */
constexpr quint16 defaultMtu = 576;

/* The largest DTLS record (2^14 bytes of plaintext). Once the handshake is
 * done the MTU is raised to this: QDtls documents that the hint only
 * affects the handshake, and an application datagram must fit into one
 * UDP datagram, which is the application's business. wolfSSL would
 * otherwise refuse to send, and to receive, records larger than the MTU. */
constexpr quint16 maxRecordMtu = 16384;

/* The default cookie secret: one random value per process, so that a
 * QDtlsClientVerifier and a server-side QDtls agree without the
 * application having to set GeneratorParameters (as in the OpenSSL
 * backend). */
QByteArray fallbackSecret()
{
    static const QByteArray secret = [] {
        QByteArray key(32, Qt::Uninitialized);
        WC_RNG rng;
        if (wc_InitRng(&rng) != 0)
            return QByteArray();
        const int ret = wc_RNG_GenerateBlock(
                &rng, reinterpret_cast<byte *>(key.data()),
                word32(key.size()));
        wc_FreeRng(&rng);
        return ret == 0 ? key : QByteArray();
    }();
    return secret;
}

/* The peer's address and port as bytes. wolfSSL does not interpret them
 * (our I/O callbacks do the addressing), but uses them in the DTLS 1.2
 * cookie, so the cookie is bound to the peer as in the OpenSSL backend. */
QByteArray peerBytes(const QHostAddress &address, quint16 port)
{
    QByteArray data;
    data.append(reinterpret_cast<const char *>(&port), sizeof port);
    if (address.protocol() == QAbstractSocket::IPv6Protocol) {
        const Q_IPV6ADDR ipv6 = address.toIPv6Address();
        data.append(reinterpret_cast<const char *>(&ipv6), sizeof ipv6);
    } else {
        const quint32 ipv4 = address.toIPv4Address();
        data.append(reinterpret_cast<const char *>(&ipv4), sizeof ipv4);
    }
    return data;
}

bool isWantReadOrWrite(int error)
{
    return error == WOLFSSL_ERROR_WANT_READ
            || error == WOLFSSL_ERROR_WANT_WRITE;
}

extern "C" int q_wolfssl_dtls_hello_verified(WOLFSSL *, void *ctx)
{
    /* The cookie is good: that is all QDtlsClientVerifier wants to know.
     * Stop before the rest of the ClientHello is processed (cipher suites
     * and so on, for which the verifier has no certificate). */
    *static_cast<bool *>(ctx) = true;
    return -1;
}

QString msgFunctionFailed(const char *function)
{
    /*: %1: Some function */
    return QDtls::tr("%1 failed").arg(QLatin1StringView(function));
}

} /* unnamed namespace */

namespace dtlswolfssl {

DtlsState::~DtlsState()
{
    /* The callbacks point to this object: free the WOLFSSL first. */
    reset();
}

bool DtlsState::init(QDtlsBasePrivate *dtlsBase, QUdpSocket *socket,
                     const QHostAddress &remote, quint16 port,
                     const QByteArray &receivedMessage)
{
    Q_ASSERT(dtlsBase);
    Q_ASSERT(socket);

    udpSocket = socket;
    if (!ssl && !initTls(dtlsBase))
        return false;

    dgram = receivedMessage;
    if (remote != remoteAddress || port != remotePort)
        setPeer(remote, port);
    return true;
}

void DtlsState::setPeer(const QHostAddress &remote, quint16 port)
{
    remoteAddress = remote;
    remotePort = port;
    QByteArray peer = peerBytes(remote, port);
    if (wolfSSL_dtls_set_peer(ssl, peer.data(), unsigned(peer.size()))
        != WOLFSSL_SUCCESS) {
        qCWarning(lcTlsBackendWolfSSL, "Could not set the DTLS peer");
    }
}

void DtlsState::resetConnection()
{
    if (ssl) {
        wolfSSL_free(ssl);
        ssl = nullptr;
    }
    dgram.clear();
    remoteAddress.clear();
    remotePort = 0;
    certificateErrors.clear();
    mtu = 0;
    writeSuppressed = false;
    writeFailed = false;
}

void DtlsState::reset()
{
    resetConnection();
    tlsContext.reset();
}

bool DtlsState::initTls(QDtlsBasePrivate *dtlsBase)
{
    if (dtlsBase->mode == QSslSocket::UnencryptedMode) {
        dtlsBase->setDtlsError(QDtlsError::TlsInitializationError,
                               QDtls::tr("Invalid SslMode, SslServerMode or "
                                         "SslClientMode expected"));
        return false;
    }

    const QSslConfiguration &configuration = dtlsBase->dtlsConfiguration;
    if (!QDtlsBasePrivate::isDtlsProtocol(configuration.protocol())) {
        dtlsBase->setDtlsError(QDtlsError::TlsInitializationError,
                               QDtls::tr("Invalid protocol version, DTLS "
                                         "protocol expected"));
        return false;
    }

    if (!tlsContext) {
        /* The CA certificates are in the configuration already; wolfSSL
         * never loads roots on demand. */
        auto context = QSslContext::sharedFromConfiguration(
                dtlsBase->mode, configuration, false);
        if (context->error() != QSslError::NoError) {
            dtlsBase->setDtlsError(QDtlsError::TlsInitializationError,
                                   context->errorString());
            return false;
        }
        tlsContext = std::move(context);
    }

    ssl = tlsContext->createSsl();
    if (!ssl) {
        dtlsBase->setDtlsError(QDtlsError::TlsInitializationError,
                               msgFunctionFailed("wolfSSL_new"));
        return false;
    }

    WolfSSLCallbacks *callbacks = this;
    wolfSSL_SetIOReadCtx(ssl, callbacks);
    wolfSSL_SetIOWriteCtx(ssl, callbacks);
    wolfSSL_SetCertCbCtx(ssl, callbacks);

    /* Required: without it wolfSSL takes WANT_READ from the receive
     * callback as an expired retransmission timer. */
    wolfSSL_dtls_set_using_nonblock(ssl, 1);

    /* No renegotiation, as for TLS (and as OpenSSL's QDtls never asks
     * for one). */
    wolfSSL_set_options(ssl, WOLFSSL_OP_NO_RENEGOTIATION);

    if (dtlsBase->mode == QSslSocket::SslServerMode) {
        if (cookieVerifier || configuration.dtlsCookieVerificationEnabled()) {
            /* wolfSSL: the DTLS 1.2 cookie is HMAC-SHA256 over the peer and
             * parts of the ClientHello, keyed with this secret. The hash
             * cannot be chosen, so GeneratorParameters::hash is kept but
             * not used. The cookie is only checked by the server that made
             * it, so this does not matter to the client. */
            const QByteArray &secret = dtlsBase->secret;
            if (secret.isEmpty()
                || wolfSSL_DTLS_SetCookieSecret(
                           ssl,
                           reinterpret_cast<const byte *>(secret.constData()),
                           word32(secret.size()))
                        != 0) {
                dtlsBase->setDtlsError(
                        QDtlsError::TlsInitializationError,
                        msgFunctionFailed("wolfSSL_DTLS_SetCookieSecret"));
                resetConnection();
                return false;
            }
        } else {
            wolfSSL_disable_cookie(ssl);
        }
    }

    setLinkMtu(dtlsBase, false);
    return true;
}

void DtlsState::setLinkMtu(QDtlsBasePrivate *dtlsBase, bool handshakeDone)
{
    Q_ASSERT(ssl);

    int linkMtu = maxRecordMtu;
    if (!handshakeDone) {
        linkMtu = dtlsBase->mtuHint;
        if (!linkMtu && udpSocket
            && udpSocket->state() == QAbstractSocket::ConnectedState) {
            /* A connected socket may know the path MTU (IP_MTU). */
            const QVariant value = udpSocket->socketOption(
                    QAbstractSocket::PathMtuSocketOption);
            bool ok = false;
            if (value.isValid())
                linkMtu = value.toInt(&ok);
            if (!ok)
                linkMtu = 0;
        }
        if (linkMtu <= 0)
            linkMtu = defaultMtu;
        linkMtu = qMin(linkMtu, int(maxRecordMtu));
    }
    setMtu(linkMtu);
}

void DtlsState::setMtu(int newMtu)
{
    Q_ASSERT(ssl);
    if (wolfSSL_dtls_set_mtu(ssl, word16(newMtu)) == WOLFSSL_SUCCESS) {
        mtu = newMtu;
    } else {
        qCWarning(lcTlsBackendWolfSSL)
                << "Could not set the DTLS MTU to" << newMtu;
    }
}

int DtlsState::ioRecv(char *buf, int size)
{
    /* Runs inside a wolfSSL call: no signals. One datagram, in one piece,
     * or nothing. */
    if (dgram.isEmpty())
        return WOLFSSL_CBIO_ERR_WANT_READ;

    if (dgram.size() > size) {
        /* wolfSSL's receive buffer is the MTU plus a margin. Cutting the
         * datagram would only produce a broken record: drop it, as if it
         * had been lost. */
        qCDebug(lcTlsBackendWolfSSL) << "Dropped a datagram of" << dgram.size()
                                     << "bytes, larger than" << size;
        dgram.clear();
        return WOLFSSL_CBIO_ERR_WANT_READ;
    }

    const int n = int(dgram.size());
    std::memcpy(buf, dgram.constData(), size_t(n));
    dgram.clear();
    return n;
}

int DtlsState::ioSend(const char *buf, int size)
{
    if (writeSuppressed)
        return size;

    Q_ASSERT(udpSocket);
    const QByteArray datagram = QByteArray::fromRawData(buf, size);
    qint64 written = -1;
    if (udpSocket->state() == QAbstractSocket::ConnectedState)
        written = udpSocket->write(datagram);
    else
        written = udpSocket->writeDatagram(datagram, remoteAddress, remotePort);

    if (written < 0) {
        /* UDP: treat the datagram as lost, so that wolfSSL's state stays
         * consistent (a handshake flight is retransmitted later). The
         * caller reports the socket error once wolfSSL has returned. */
        writeFailed = true;
    }
    return size;
}

int DtlsState::verifyCertificate(int preverify, WOLFSSL_X509_STORE_CTX *store)
{
    /* Collect the errors and let the handshake continue; QDtls decides
     * after the handshake, like the OpenSSL backend. */
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
    return 1;
}

unsigned DtlsState::pskClientTlsCallback(const char *hint, char *identity,
                                         unsigned maxIdentityLen,
                                         unsigned char *psk,
                                         unsigned maxPskLen)
{
    if (!dtlsPrivate)
        return 0;
    return dtlsPrivate->pskClientCallback(hint, identity, maxIdentityLen, psk,
                                          maxPskLen);
}

unsigned DtlsState::pskServerTlsCallback(const char *identity,
                                         unsigned char *psk,
                                         unsigned maxPskLen)
{
    if (!dtlsPrivate)
        return 0;
    return dtlsPrivate->pskServerCallback(identity, psk, maxPskLen);
}

} /* namespace dtlswolfssl */

QDtlsClientVerifierWolfSSL::QDtlsClientVerifierWolfSSL()
    : QDtlsBasePrivate(QSslSocket::SslServerMode, fallbackSecret())
{
    dtls.cookieVerifier = true;
}

void QDtlsClientVerifierWolfSSL::setConfiguration(
        const QSslConfiguration &configuration)
{
    QDtlsBasePrivate::setConfiguration(configuration);
    dtls.reset();
}

bool QDtlsClientVerifierWolfSSL::verifyClient(QUdpSocket *socket,
                                              const QByteArray &dgram,
                                              const QHostAddress &address,
                                              quint16 port)
{
    Q_ASSERT(socket);
    Q_ASSERT(dgram.size());
    Q_ASSERT(!address.isNull());
    Q_ASSERT(port);

    clearDtlsError();
    verifiedClientHello.clear();

    /* The check is stateless: a new WOLFSSL object for every datagram, on
     * the same context. A HelloVerifyRequest goes out through ioSend(). */
    dtls.resetConnection();
    if (!dtls.init(this, socket, address, port, dgram))
        return false;
    /* The secret may have changed since the last call. */
    if (secret.isEmpty()
        || wolfSSL_DTLS_SetCookieSecret(
                   dtls.ssl,
                   reinterpret_cast<const byte *>(secret.constData()),
                   word32(secret.size()))
                != 0) {
        setDtlsError(QDtlsError::TlsInitializationError,
                     msgFunctionFailed("wolfSSL_DTLS_SetCookieSecret"));
        dtls.resetConnection();
        return false;
    }

    /* Like DTLSv1_listen() in the OpenSSL backend, only the cookie is
     * checked: without one, or with a wrong one, wolfSSL answers with a
     * HelloVerifyRequest; with a good one it calls us back, and we stop. */
    bool verified = false;
    wolfDTLS_SetChGoodCb(dtls.ssl, q_wolfssl_dtls_hello_verified, &verified);
    wolfSSL_accept(dtls.ssl);
    dtls.resetConnection();

    if (verified) {
        verifiedClientHello = dgram;
        return true;
    }
    /* Not verified yet, or not a ClientHello at all. It's UDP: ignore the
     * datagram without an error, as the OpenSSL backend does. */
    return false;
}

QByteArray QDtlsClientVerifierWolfSSL::verifiedHello() const
{
    return verifiedClientHello;
}

void QDtlsPrivateWolfSSL::TimeoutHandler::start(int timeoutMs)
{
    stop();
    timerId = startTimer(timeoutMs > 0 ? timeoutMs : 1000, Qt::PreciseTimer);
}

void QDtlsPrivateWolfSSL::TimeoutHandler::stop()
{
    if (timerId != -1) {
        killTimer(timerId);
        timerId = -1;
    }
}

void QDtlsPrivateWolfSSL::TimeoutHandler::timerEvent(QTimerEvent *event)
{
    Q_UNUSED(event);
    Q_ASSERT(timerId != -1);

    killTimer(timerId);
    timerId = -1;

    Q_ASSERT(dtlsConnection);
    dtlsConnection->reportTimeout();
}

QDtlsPrivateWolfSSL::QDtlsPrivateWolfSSL(QDtls *qObject,
                                         QSslSocket::SslMode side)
    : QDtlsBasePrivate(side, fallbackSecret()), q(qObject)
{
    Q_ASSERT(qObject);
    dtls.dtlsPrivate = this;
}

QDtlsPrivateWolfSSL::~QDtlsPrivateWolfSSL() = default;

QSslSocket::SslMode QDtlsPrivateWolfSSL::cryptographMode() const
{
    return mode;
}

void QDtlsPrivateWolfSSL::setPeer(const QHostAddress &addr, quint16 port,
                                  const QString &name)
{
    remoteAddress = addr;
    remotePort = port;
    peerVfyName = name;
}

QHostAddress QDtlsPrivateWolfSSL::peerAddress() const
{
    return remoteAddress;
}

quint16 QDtlsPrivateWolfSSL::peerPort() const
{
    return remotePort;
}

void QDtlsPrivateWolfSSL::setPeerVerificationName(const QString &name)
{
    peerVfyName = name;
}

QString QDtlsPrivateWolfSSL::peerVerificationName() const
{
    return peerVfyName;
}

void QDtlsPrivateWolfSSL::setDtlsMtuHint(quint16 mtu)
{
    mtuHint = mtu;
}

quint16 QDtlsPrivateWolfSSL::dtlsMtuHint() const
{
    return mtuHint;
}

QDtls::HandshakeState QDtlsPrivateWolfSSL::state() const
{
    return handshakeState;
}

bool QDtlsPrivateWolfSSL::isConnectionEncrypted() const
{
    return connectionEncrypted;
}

bool QDtlsPrivateWolfSSL::startHandshake(QUdpSocket *socket,
                                         const QByteArray &dgram)
{
    Q_ASSERT(socket);
    Q_ASSERT(handshakeState == QDtls::HandshakeNotStarted);

    clearDtlsError();
    connectionEncrypted = false;

    if (!dtls.init(this, socket, remoteAddress, remotePort, dgram))
        return false;

    if (mode == QSslSocket::SslServerMode
        && dtlsConfiguration.dtlsCookieVerificationEnabled()) {
        /* QDtlsClientVerifier has checked this ClientHello; check it again
         * here, without sending anything: sending a HelloVerifyRequest is
         * the verifier's job. On success wolfSSL has taken the ClientHello
         * and wolfSSL_accept() goes on from there. */
        dtls.writeSuppressed = true;
        const int ret = wolfDTLS_accept_stateless(dtls.ssl);
        dtls.writeSuppressed = false;
        if (ret != WOLFSSL_SUCCESS) {
            setDtlsError(QDtlsError::TlsFatalError,
                         QDtls::tr("Cannot start the handshake, verified "
                                   "client hello expected"));
            dtls.reset();
            return false;
        }
        /* The ClientHello must not be read a second time. */
        dtls.dgram.clear();
    }

    handshakeState = QDtls::HandshakeInProgress;
    dtls.certificateErrors.clear();
    tlsErrors.clear();

    return doHandshakeStep();
}

bool QDtlsPrivateWolfSSL::continueHandshake(QUdpSocket *socket,
                                            const QByteArray &dgram)
{
    Q_ASSERT(socket);
    Q_ASSERT(handshakeState == QDtls::HandshakeInProgress);

    clearDtlsError();

    if (timeoutHandler)
        timeoutHandler->stop();

    if (!dtls.init(this, socket, remoteAddress, remotePort, dgram))
        return false;

    return doHandshakeStep();
}

bool QDtlsPrivateWolfSSL::doHandshakeStep()
{
    Q_ASSERT(dtls.ssl);

    /* Never refuse the peer's datagram for being larger than our MTU guess
     * (wolfSSL's receive buffer follows the MTU): the path evidently
     * carries it. */
    if (dtls.dgram.size() > dtls.mtu)
        dtls.setMtu(int(qMin(dtls.dgram.size(), qsizetype(maxRecordMtu))));

    dtls.writeFailed = false;
    const int result = mode == QSslSocket::SslServerMode
            ? wolfSSL_accept(dtls.ssl)
            : wolfSSL_connect(dtls.ssl);

    if (result != WOLFSSL_SUCCESS) {
        const int error = wolfSSL_get_error(dtls.ssl, result);
        if (isWantReadOrWrite(error)) {
            /* The handshake is not complete yet. A datagram the socket
             * refused counts as lost: the timer retransmits it. */
            startTimeout();
            return true;
        }

        storePeerCertificates();
        setDtlsError(QDtlsError::TlsFatalError,
                     QDtls::tr("Error during SSL handshake: %1")
                             .arg(QTlsBackendWolfSSL::errorString(error)));
        dtls.reset();
        handshakeState = QDtls::HandshakeNotStarted;
        return false;
    }

    if (timeoutHandler)
        timeoutHandler->stop();

    storePeerCertificates();
    fetchNegotiatedParameters();
    dtls.setLinkMtu(this, true);

    const bool doVerifyPeer
            = dtlsConfiguration.peerVerifyMode() == QSslSocket::VerifyPeer
            || (dtlsConfiguration.peerVerifyMode()
                        == QSslSocket::AutoVerifyPeer
                && mode == QSslSocket::SslClientMode);

    if (!doVerifyPeer || verifyPeer() || tlsErrorsWereIgnored()) {
        connectionEncrypted = true;
        handshakeState = QDtls::HandshakeComplete;
        return true;
    }

    /* As with OpenSSL, our Finished has been sent already: the peer may
     * consider the handshake done. abortHandshake() sends close_notify. */
    setDtlsError(QDtlsError::PeerVerificationError,
                 QDtls::tr("Peer verification failed"));
    handshakeState = QDtls::PeerVerificationFailed;
    return false;
}

void QDtlsPrivateWolfSSL::startTimeout()
{
    if (!timeoutHandler) {
        timeoutHandler = std::make_unique<TimeoutHandler>();
        timeoutHandler->dtlsConnection = this;
    }
    /* wolfSSL's current retransmission timeout, in seconds. */
    timeoutHandler->start(wolfSSL_dtls_get_current_timeout(dtls.ssl) * 1000);
}

bool QDtlsPrivateWolfSSL::handleTimeout(QUdpSocket *socket)
{
    Q_ASSERT(socket);
    Q_ASSERT(dtls.ssl);

    clearDtlsError();
    dtls.udpSocket = socket;

    /* Retransmits the last flight and doubles the timeout. It fails once
     * the timeout would exceed wolfSSL's maximum (64 seconds). */
    if (wolfSSL_dtls_got_timeout(dtls.ssl) != WOLFSSL_SUCCESS) {
        const int error = wolfSSL_get_error(dtls.ssl, WOLFSSL_FATAL_ERROR);
        setDtlsError(QDtlsError::TlsFatalError,
                     QDtls::tr("Error during SSL handshake: %1")
                             .arg(QTlsBackendWolfSSL::errorString(error)));
        return false;
    }

    startTimeout();
    return true;
}

bool QDtlsPrivateWolfSSL::resumeHandshake(QUdpSocket *socket)
{
    Q_UNUSED(socket);
    Q_ASSERT(socket);
    Q_ASSERT(handshakeState == QDtls::PeerVerificationFailed);

    clearDtlsError();

    if (tlsErrorsWereIgnored()) {
        handshakeState = QDtls::HandshakeComplete;
        connectionEncrypted = true;
        tlsErrors.clear();
        tlsErrorsToIgnore.clear();
        return true;
    }

    return false;
}

void QDtlsPrivateWolfSSL::abortHandshake(QUdpSocket *socket)
{
    Q_ASSERT(socket);
    Q_ASSERT(handshakeState == QDtls::PeerVerificationFailed
             || handshakeState == QDtls::HandshakeInProgress);

    clearDtlsError();

    if (handshakeState == QDtls::PeerVerificationFailed) {
        /* The handshake did complete: tell the peer we are leaving. */
        connectionEncrypted = true;
        sendShutdownAlert(socket);
    } else {
        resetDtls();
    }
}

void QDtlsPrivateWolfSSL::sendShutdownAlert(QUdpSocket *socket)
{
    Q_ASSERT(socket);

    clearDtlsError();

    if (connectionEncrypted && !connectionWasShutdown && dtls.ssl) {
        dtls.udpSocket = socket;
        wolfSSL_shutdown(dtls.ssl);
    }

    resetDtls();
}

QList<QSslError> QDtlsPrivateWolfSSL::peerVerificationErrors() const
{
    return tlsErrors;
}

void QDtlsPrivateWolfSSL::ignoreVerificationErrors(
        const QList<QSslError> &errorsToIgnore)
{
    tlsErrorsToIgnore = errorsToIgnore;
}

QSslCipher QDtlsPrivateWolfSSL::dtlsSessionCipher() const
{
    return sessionCipher;
}

QSsl::SslProtocol QDtlsPrivateWolfSSL::dtlsSessionProtocol() const
{
    return sessionProtocol;
}

qint64 QDtlsPrivateWolfSSL::writeDatagramEncrypted(QUdpSocket *socket,
                                                   const QByteArray &dgram)
{
    Q_ASSERT(socket);
    Q_ASSERT(dtls.ssl);
    Q_ASSERT(connectionEncrypted);

    clearDtlsError();

    dtls.udpSocket = socket;
    dtls.writeFailed = false;
    const int written = wolfSSL_write(dtls.ssl, dgram.constData(),
                                      int(dgram.size()));
    if (dtls.writeFailed) {
        setDtlsError(QDtlsError::UnderlyingSocketError,
                     socket->errorString());
        return -1;
    }
    if (written > 0)
        return written;

    const int error = wolfSSL_get_error(dtls.ssl, written);
    switch (error) {
    case WOLFSSL_ERROR_WANT_READ:
    case WOLFSSL_ERROR_WANT_WRITE:
        /* No error: the application may try again. */
        break;
    case WOLFSSL_ERROR_ZERO_RETURN:
        connectionWasShutdown = true;
        setDtlsError(QDtlsError::TlsFatalError,
                     QDtls::tr("The DTLS connection has been closed"));
        handshakeState = QDtls::HandshakeNotStarted;
        dtls.reset();
        break;
    default:
        /* For example DTLS_SIZE_ERROR, a datagram larger than a record.
         * The connection is still usable, as with OpenSSL. */
        setDtlsError(QDtlsError::TlsFatalError,
                     QDtls::tr("Error while writing: %1")
                             .arg(QTlsBackendWolfSSL::errorString(error)));
        break;
    }
    return -1;
}

QByteArray QDtlsPrivateWolfSSL::decryptDatagram(QUdpSocket *socket,
                                                const QByteArray &tlsdgram)
{
    Q_ASSERT(socket);
    Q_ASSERT(tlsdgram.size());
    Q_ASSERT(dtls.ssl);
    Q_ASSERT(connectionEncrypted);

    dtls.dgram = tlsdgram;
    dtls.udpSocket = socket;

    clearDtlsError();

    /* A record never decrypts to more than it is long. */
    QByteArray dgram(tlsdgram.size(), Qt::Uninitialized);
    const int read = wolfSSL_read(dtls.ssl, dgram.data(), int(dgram.size()));
    if (read > 0) {
        dgram.resize(read);
        return dgram;
    }
    dgram.clear();

    const int error = wolfSSL_get_error(dtls.ssl, read);
    switch (error) {
    case WOLFSSL_ERROR_WANT_READ:
    case WOLFSSL_ERROR_WANT_WRITE:
        /* A handshake retransmission, a record wolfSSL dropped (DTLS
         * ignores bad records) or one without application data. */
        return dgram;
    case WOLFSSL_ERROR_ZERO_RETURN:
        connectionWasShutdown = true;
        setDtlsError(QDtlsError::RemoteClosedConnectionError,
                     QDtls::tr("The DTLS connection has been shutdown"));
        dtls.reset();
        connectionEncrypted = false;
        handshakeState = QDtls::HandshakeNotStarted;
        return dgram;
    default:
        setDtlsError(QDtlsError::TlsNonFatalError,
                     QDtls::tr("Error while reading: %1")
                             .arg(QTlsBackendWolfSSL::errorString(error)));
        return dgram;
    }
}

unsigned QDtlsPrivateWolfSSL::pskClientCallback(const char *hint,
                                                char *identity,
                                                unsigned maxIdentityLen,
                                                unsigned char *psk,
                                                unsigned maxPskLen)
{
    {
        QSslPreSharedKeyAuthenticator authenticator;
        if (hint) {
            identityHint.clear();
            identityHint.append(hint);
        }
        QTlsBackend::setupClientPskAuth(
                &authenticator, hint ? identityHint.constData() : nullptr,
                hint ? int(std::strlen(hint)) : 0, maxIdentityLen, maxPskLen);
        pskAuthenticator.swap(authenticator);
    }

    /* Asked synchronously, from inside the handshake, as with OpenSSL. */
    emit q->pskRequired(&pskAuthenticator);

    /* No PSK set? Return 0 to make the handshake fail. */
    if (pskAuthenticator.preSharedKey().isEmpty())
        return 0;

    const int identityLength
            = qMin(pskAuthenticator.identity().size(),
                   pskAuthenticator.maximumIdentityLength());
    std::memcpy(identity, pskAuthenticator.identity().constData(),
                identityLength);
    identity[identityLength] = 0;

    const int pskLength
            = qMin(pskAuthenticator.preSharedKey().size(),
                   pskAuthenticator.maximumPreSharedKeyLength());
    std::memcpy(psk, pskAuthenticator.preSharedKey().constData(), pskLength);
    return unsigned(pskLength);
}

unsigned QDtlsPrivateWolfSSL::pskServerCallback(const char *identity,
                                                unsigned char *psk,
                                                unsigned maxPskLen)
{
    {
        QSslPreSharedKeyAuthenticator authenticator;
        QTlsBackend::setupServerPskAuth(
                &authenticator, identity,
                dtlsConfiguration.preSharedKeyIdentityHint(), maxPskLen);
        pskAuthenticator.swap(authenticator);
    }

    emit q->pskRequired(&pskAuthenticator);

    if (pskAuthenticator.preSharedKey().isEmpty())
        return 0;

    const int pskLength
            = qMin(pskAuthenticator.preSharedKey().size(),
                   pskAuthenticator.maximumPreSharedKeyLength());
    std::memcpy(psk, pskAuthenticator.preSharedKey().constData(), pskLength);
    return unsigned(pskLength);
}

bool QDtlsPrivateWolfSSL::verifyPeer()
{
    using QTlsPrivate::X509CertificateWolfSSL;

    QList<QSslError> errors;

    const auto peerCertificateChain = dtlsConfiguration.peerCertificateChain();

    /* Errors collected by the verify callback during the handshake. */
    QList<QSslError> chainErrors;
    for (const auto &error : std::as_const(dtls.certificateErrors)) {
        const QSslError sslError(
                X509CertificateWolfSSL::sslErrorFromWolfSSL(
                        error.code, error.depth, peerCertificateChain),
                peerCertificateChain.value(error.depth));
        if (!chainErrors.contains(sslError))
            chainErrors << sslError;
    }
    X509CertificateWolfSSL::addValidityErrors(&chainErrors);

    /* Check the whole chain for blacklisting (including the root). */
    for (const QSslCertificate &cert : peerCertificateChain) {
        if (QSslCertificatePrivate::isBlacklisted(cert))
            errors << QSslError(QSslError::CertificateBlacklisted, cert);
    }

    const QSslCertificate peerCertificate = dtlsConfiguration.peerCertificate();
    if (peerCertificate.isNull()) {
        errors << QSslError(QSslError::NoPeerCertificate);
    } else if (mode == QSslSocket::SslClientMode) {
        /* As in the OpenSSL backend: the verification name, or the name the
         * socket was connected with. */
        QString name = peerVfyName;
        if (name.isEmpty()) {
            Q_ASSERT(dtls.udpSocket);
            name = dtls.udpSocket->peerName();
        }
        if (!QTlsPrivate::TlsCryptograph::isMatchingHostname(peerCertificate,
                                                             name)) {
            errors << QSslError(QSslError::HostNameMismatch, peerCertificate);
        }
    }

    errors << chainErrors;
    tlsErrors = errors;
    return tlsErrors.isEmpty();
}

void QDtlsPrivateWolfSSL::storePeerCertificates()
{
    if (!dtls.ssl)
        return;

    /* Needs SESSION_CERTS. The chain starts with the peer's certificate,
     * for clients and servers alike. */
    QList<QSslCertificate> chain;
    if (WOLFSSL_X509_CHAIN *peerChain = wolfSSL_get_peer_chain(dtls.ssl)) {
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

    QTlsBackend::storePeerCertificate(dtlsConfiguration, chain.value(0));
    QTlsBackend::storePeerCertificateChain(dtlsConfiguration, chain);
}

bool QDtlsPrivateWolfSSL::tlsErrorsWereIgnored() const
{
    /* All errors must be in the list given to ignoreVerificationErrors(). */
    for (const QSslError &error : tlsErrors) {
        if (!tlsErrorsToIgnore.contains(error))
            return false;
    }

    return !tlsErrorsToIgnore.empty();
}

void QDtlsPrivateWolfSSL::fetchNegotiatedParameters()
{
    Q_ASSERT(dtls.ssl);

    const char *name = wolfSSL_get_cipher_name(dtls.ssl);
    sessionCipher = name ? QTlsBackendWolfSSL::ciphersuiteFromName(
                                   QLatin1StringView(name))
                         : QSslCipher();

    switch (wolfSSL_GetVersion(dtls.ssl)) {
    case WOLFSSL_DTLSV1_2:
        sessionProtocol = QSsl::DtlsV1_2;
        break;
    default:
        qCWarning(lcTlsBackendWolfSSL, "Unknown DTLS protocol version");
        sessionProtocol = QSsl::UnknownProtocol;
        break;
    }
}

void QDtlsPrivateWolfSSL::reportTimeout()
{
    emit q->handshakeTimeout();
}

void QDtlsPrivateWolfSSL::resetDtls()
{
    if (timeoutHandler)
        timeoutHandler->stop();
    dtls.reset();
    connectionEncrypted = false;
    tlsErrors.clear();
    tlsErrorsToIgnore.clear();
    QTlsBackend::clearPeerCertificates(dtlsConfiguration);
    connectionWasShutdown = false;
    handshakeState = QDtls::HandshakeNotStarted;
    sessionCipher = {};
    sessionProtocol = QSsl::UnknownProtocol;
}

QT_END_NAMESPACE
