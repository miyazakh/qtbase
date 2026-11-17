/*
 * Copyright (C) 2026 The Qt Company Ltd.
 * SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
 * Qt-Security score:significant reason:default
 */

#ifndef QTLS_WOLFSSL_P_H
#define QTLS_WOLFSSL_P_H

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

#include <QtNetwork/private/qsslsocket_p.h>
#include <QtNetwork/private/qtlsbackend_p.h>

#include <QtNetwork/qsslerror.h>

#include <QtCore/qbytearray.h>
#include <QtCore/qlist.h>

#include <memory>

struct WOLFSSL;
struct WOLFSSL_SESSION;
struct WOLFSSL_X509_STORE_CTX;

QT_BEGIN_NAMESPACE

class QSslContext;

namespace QTlsPrivate {

/* TLS over TCP on top of wolfSSL's native API.
 *
 * wolfSSL reads and writes TLS records through the I/O callbacks (ioRecv(),
 * ioSend()), which talk to the plain QTcpSocket directly, like the Schannel
 * backend does (docs/design-io-bridge.md, chapters 2 and 3). The callbacks
 * never emit signals or close the socket: they only record what happened,
 * and transmit() reports it once the wolfSSL call has returned. */
class TlsCryptographWolfSSL final : public TlsCryptograph
{
    Q_DISABLE_COPY_MOVE(TlsCryptographWolfSSL)
public:
    TlsCryptographWolfSSL();
    ~TlsCryptographWolfSSL() override;

    void init(QSslSocket *qObj, QSslSocketPrivate *dObj) override;
    void checkSettingSslContext(
            std::shared_ptr<QSslContext> tlsContext) override;
    std::shared_ptr<QSslContext> sslContext() const override;

    QList<QSslError> tlsErrors() const override;

    void startClientEncryption() override;
    void startServerEncryption() override;
    void continueHandshake() override;
    void disconnectFromHost() override;
    void disconnected() override;
    QSslCipher sessionCipher() const override;
    QSsl::SslProtocol sessionProtocol() const override;

    void transmit() override;
    bool hasUndecryptedData() const override;

    /* Called from the wolfSSL callbacks (see qtls_wolfssl.cpp). */
    int ioRecv(char *buf, int size);
    int ioSend(const char *buf, int size);
    int verifyCertificate(int preverify, WOLFSSL_X509_STORE_CTX *store);
    int handleNewSession(WOLFSSL_SESSION *session);
    unsigned pskClientTlsCallback(const char *hint, char *identity,
                                  unsigned maxIdentityLen, unsigned char *psk,
                                  unsigned maxPskLen);
    unsigned pskServerTlsCallback(const char *identity, unsigned char *psk,
                                  unsigned maxPskLen);

private:
    /* The state is not derived from isEncrypted() alone, so that TLS 1.2
     * renegotiation can be added later (docs/design-io-bridge.md 4, 4.2). */
    enum class HandshakeState {
        Initial, /* no WOLFSSL object yet */
        InProgress, /* wolfSSL_connect()/wolfSSL_accept() not finished */
        Verifying, /* handshake done, waiting for the application (paused on
                      sslErrors) */
        Done, /* encrypted */
        Renegotiating, /* reserved: TLS 1.2 renegotiation is refused for now */
    };

    /* How the verify callback treats certificate errors
     * (docs/design-io-bridge.md 6). Only Collect is used: Qt's
     * handshakeMustInterruptOnError() is OpenSSL-only in QtNetwork. */
    enum class VerifyMode {
        Collect, /* record the error, let the handshake continue */
        Interrupt, /* reserved: stop the handshake at the first error */
    };

    struct CertificateError
    {
        int code = 0;
        int depth = 0;
    };

    bool initSsl();
    void destroySsl();
    void reset();

    bool doHandshake();
    bool verifyPeer();
    bool checkSslErrors();
    void storePeerCertificates();
    void finishHandshake();

    bool writeEncrypted();
    bool readDecrypted(bool *gotData);
    bool checkRefusedRenegotiation();
    void handleWolfSSLError(int error, QAbstractSocket::SocketError socketError,
                            const QString &context);

    bool readThrottled() const;

    QSslSocket *q = nullptr;
    QSslSocketPrivate *d = nullptr;

    std::shared_ptr<QSslContext> sslContextPointer;
    WOLFSSL *ssl = nullptr;

    HandshakeState handshakeState = HandshakeState::Initial;
    VerifyMode verifyMode = VerifyMode::Collect;

    QList<CertificateError> certificateErrors;
    QList<QSslError> sslErrors;

    /* Set by the I/O callbacks, examined by transmit(). */
    bool ioClosed = false;
    bool pendingSocketError = false;

    bool pendingNewSessionTicket = false;
    /* Size of the decrypted-data buffer while wolfSSL_read() runs, see
     * readThrottled(). */
    qint64 bufferedBeforeRead = -1;

    bool inSetAndEmitError = false;
    bool drainingOnDisconnect = false;
    bool shutdown = false;
    bool closeNotifyReceived = false;
    bool fatalErrorDetected = false;
};

} /* namespace QTlsPrivate */

QT_END_NAMESPACE

#endif /* QTLS_WOLFSSL_P_H */
