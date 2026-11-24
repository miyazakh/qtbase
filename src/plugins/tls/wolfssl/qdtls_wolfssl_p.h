/*
 * Copyright (C) 2026 The Qt Company Ltd.
 * SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
 */

#ifndef QDTLS_WOLFSSL_P_H
#define QDTLS_WOLFSSL_P_H

/*
 *  W A R N I N G
 *  -------------
 *
 * This file is not part of the Qt API.  It exists purely as an
 * implementation detail.  This header file may change from version to
 * version without notice, or even be removed.
 *
 * We mean it.
 */

#include <QtNetwork/private/qtnetworkglobal_p.h>

QT_REQUIRE_CONFIG(wolfssl_dtls);

#include "qsslcontext_wolfssl_p.h"
#include "../shared/qdtls_base_p.h"

#include <QtNetwork/private/qtlsbackend_p.h>

#include <QtNetwork/qhostaddress.h>
#include <QtNetwork/qsslpresharedkeyauthenticator.h>

#include <QtCore/qbitarray.h>
#include <QtCore/qbytearray.h>
#include <QtCore/qlist.h>
#include <QtCore/qobject.h>

#include <memory>

QT_BEGIN_NAMESPACE

class QDtlsPrivateWolfSSL;
class QUdpSocket;

namespace dtlswolfssl {

/* wolfSSL ignores a fragmented DTLS 1.2 ClientHello: a server that has
 * not verified the client yet keeps no state for it. OpenSSL clients that
 * cannot query the path MTU (on macOS, for example) fragment theirs for a
 * 256-byte link, though, as do clients with a small MTU hint. The
 * assembler collects the fragments of one ClientHello at a time and gives
 * the whole message to wolfSSL as one record. */
class ClientHelloAssembler
{
public:
    enum Result {
        NotFragmented, /* not a ClientHello fragment: use the datagram */
        Incomplete,    /* fragment stored, more to come */
        Complete       /* *hello is the reassembled datagram */
    };

    Result add(const QByteArray &dgram, const QHostAddress &address,
               quint16 port, QByteArray *hello);
    void clear();

private:
    QHostAddress peerAddress;
    quint16 peerPort = 0;
    quint16 messageSeq = 0;
    QByteArray recordHeader;
    QByteArray body;
    QBitArray received;
    qsizetype missing = 0;
};

/* One WOLFSSL object and the datagram I/O bridge around it, shared by
 * QDtls and QDtlsClientVerifier (like DtlsState in the OpenSSL backend).
 *
 * wolfSSL reads the datagram being processed (the one given to
 * doHandshake() or decryptDatagram()) through ioRecv(), in one piece, and
 * every ioSend() is one datagram written to the QUdpSocket. */
class DtlsState final : public QTlsPrivate::WolfSSLCallbacks
{
public:
    DtlsState() = default;
    ~DtlsState() override;
    Q_DISABLE_COPY_MOVE(DtlsState)

    bool init(QDtlsBasePrivate *dtlsBase, QUdpSocket *socket,
              const QHostAddress &remote, quint16 port,
              const QByteArray &receivedMessage);
    /* Frees the WOLFSSL object, keeps the context. */
    void resetConnection();
    /* Frees both. */
    void reset();

    int ioRecv(char *buf, int size) override;
    int ioSend(const char *buf, int size) override;
    int verifyCertificate(int preverify,
                          WOLFSSL_X509_STORE_CTX *store) override;
    unsigned pskClientTlsCallback(const char *hint, char *identity,
                                  unsigned maxIdentityLen, unsigned char *psk,
                                  unsigned maxPskLen) override;
    unsigned pskServerTlsCallback(const char *identity, unsigned char *psk,
                                  unsigned maxPskLen) override;

    /* Path MTU for the handshake, or the largest record afterwards. */
    void setLinkMtu(QDtlsBasePrivate *dtlsBase, bool handshakeDone);
    void setMtu(int newMtu);

    struct CertificateError
    {
        int code = 0;
        int depth = 0;
    };

    std::shared_ptr<QSslContext> tlsContext;
    WOLFSSL *ssl = nullptr;

    QByteArray dgram;
    QUdpSocket *udpSocket = nullptr;
    QHostAddress remoteAddress;
    quint16 remotePort = 0;

    QList<CertificateError> certificateErrors;
    int mtu = 0;

    /* Set while the server checks a ClientHello with a cookie that
     * QDtlsClientVerifier has already verified: nothing is sent then. */
    bool writeSuppressed = false;
    /* Set by ioSend() when the socket refused a datagram. */
    bool writeFailed = false;
    /* QDtlsClientVerifier: always check cookies. */
    bool cookieVerifier = false;

    QDtlsPrivateWolfSSL *dtlsPrivate = nullptr;

private:
    bool initTls(QDtlsBasePrivate *dtlsBase);
    void setPeer(const QHostAddress &remote, quint16 port);
};

} /* namespace dtlswolfssl */

/* The trick with the 'right' ancestor overriding some shared virtual
 * functions is intentional, as in the OpenSSL backend. */
QT_WARNING_PUSH
QT_WARNING_DISABLE_MSVC(4250)

class QDtlsClientVerifierWolfSSL : public QTlsPrivate::DtlsCookieVerifier,
                                   public QDtlsBasePrivate
{
public:
    QDtlsClientVerifierWolfSSL();

    void setConfiguration(const QSslConfiguration &configuration) override;

    bool verifyClient(QUdpSocket *socket, const QByteArray &dgram,
                      const QHostAddress &address, quint16 port) override;
    QByteArray verifiedHello() const override;

private:
    dtlswolfssl::DtlsState dtls;
    dtlswolfssl::ClientHelloAssembler helloAssembler;
    QByteArray verifiedClientHello;
};

class QDtlsPrivateWolfSSL : public QTlsPrivate::DtlsCryptograph,
                            public QDtlsBasePrivate
{
public:
    QDtlsPrivateWolfSSL(QDtls *qObject, QSslSocket::SslMode mode);
    ~QDtlsPrivateWolfSSL() override;

private:
    QSslSocket::SslMode cryptographMode() const override;
    void setPeer(const QHostAddress &addr, quint16 port,
                 const QString &name) override;
    QHostAddress peerAddress() const override;
    quint16 peerPort() const override;
    void setPeerVerificationName(const QString &name) override;
    QString peerVerificationName() const override;

    void setDtlsMtuHint(quint16 mtu) override;
    quint16 dtlsMtuHint() const override;

    QDtls::HandshakeState state() const override;
    bool isConnectionEncrypted() const override;

    bool startHandshake(QUdpSocket *socket,
                        const QByteArray &datagram) override;
    bool continueHandshake(QUdpSocket *socket,
                           const QByteArray &datagram) override;
    bool resumeHandshake(QUdpSocket *socket) override;
    void abortHandshake(QUdpSocket *socket) override;
    bool handleTimeout(QUdpSocket *socket) override;
    void sendShutdownAlert(QUdpSocket *socket) override;

    QList<QSslError> peerVerificationErrors() const override;
    void ignoreVerificationErrors(
            const QList<QSslError> &errorsToIgnore) override;

    QSslCipher dtlsSessionCipher() const override;
    QSsl::SslProtocol dtlsSessionProtocol() const override;

    qint64 writeDatagramEncrypted(QUdpSocket *socket,
                                  const QByteArray &datagram) override;
    QByteArray decryptDatagram(QUdpSocket *socket,
                               const QByteArray &tlsdgram) override;

public:
    /* Called from DtlsState's PSK callbacks. */
    unsigned pskClientCallback(const char *hint, char *identity,
                               unsigned maxIdentityLen, unsigned char *psk,
                               unsigned maxPskLen);
    unsigned pskServerCallback(const char *identity, unsigned char *psk,
                               unsigned maxPskLen);

private:
    bool doHandshakeStep();
    bool verifyPeer();
    void storePeerCertificates();
    bool tlsErrorsWereIgnored() const;
    void fetchNegotiatedParameters();
    void reportTimeout();
    void startTimeout();
    void resetDtls();

    dtlswolfssl::DtlsState dtls;
    /* Server: a fragmented ClientHello (see ClientHelloAssembler). */
    dtlswolfssl::ClientHelloAssembler helloAssembler;

    /* QUdpSocket is non-blocking and wolfSSL does not know when a
     * retransmission is due; the timer tells the application
     * (handshakeTimeout()), which then calls handleTimeout(). The delay is
     * wolfSSL's own (1 second, doubled by every retransmission). */
    struct TimeoutHandler : QObject
    {
        void start(int timeoutMs);
        void stop();
        void timerEvent(QTimerEvent *event) override;

        int timerId = -1;
        QDtlsPrivateWolfSSL *dtlsConnection = nullptr;
    };

    QDtls *q = nullptr;
    QDtls::HandshakeState handshakeState = QDtls::HandshakeNotStarted;

    QList<QSslError> tlsErrors;
    QList<QSslError> tlsErrorsToIgnore;
    bool connectionEncrypted = false;
    /* Created lazily, in case QDtls is moved to another thread. */
    std::unique_ptr<TimeoutHandler> timeoutHandler;
    bool connectionWasShutdown = false;
    QSslPreSharedKeyAuthenticator pskAuthenticator;
    QByteArray identityHint;
};

QT_WARNING_POP

QT_END_NAMESPACE

#endif /* QDTLS_WOLFSSL_P_H */
