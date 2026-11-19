/*
 * Copyright (C) 2026 The Qt Company Ltd.
 * SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
 */

#ifndef QSSLCONTEXT_WOLFSSL_P_H
#define QSSLCONTEXT_WOLFSSL_P_H

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

#include <QtNetwork/qsslconfiguration.h>
#include <QtNetwork/qsslerror.h>
#include <QtNetwork/qsslsocket.h>

#include <QtCore/qbytearray.h>
#include <QtCore/qstring.h>

#include <memory>

/* Forward declarations, so that this header does not pull in wolfSSL
 * (wolfssl/options.h must be the first wolfSSL header in every TU). */
struct WOLFSSL_CTX;
struct WOLFSSL;
struct WOLFSSL_SESSION;
struct WOLFSSL_X509_STORE_CTX;

QT_BEGIN_NAMESPACE

namespace QTlsPrivate {

/* The object that owns a WOLFSSL and answers the callbacks registered on
 * the shared WOLFSSL_CTX: a TLS socket (TlsCryptographWolfSSL) or a DTLS
 * connection (qdtls_wolfssl.cpp). It is set as the I/O read and write
 * context and as the certificate callback context of each WOLFSSL; always
 * pass a WolfSSLCallbacks pointer there, never a pointer to the derived
 * class. */
class WolfSSLCallbacks
{
public:
    virtual ~WolfSSLCallbacks();

    virtual int ioRecv(char *buf, int size) = 0;
    virtual int ioSend(const char *buf, int size) = 0;
    virtual int verifyCertificate(int preverify,
                                  WOLFSSL_X509_STORE_CTX *store) = 0;

    virtual int handleNewSession(WOLFSSL_SESSION *session);
    virtual unsigned pskClientTlsCallback(const char *hint, char *identity,
                                          unsigned maxIdentityLen,
                                          unsigned char *psk,
                                          unsigned maxPskLen);
    virtual unsigned pskServerTlsCallback(const char *identity,
                                          unsigned char *psk,
                                          unsigned maxPskLen);
    virtual unsigned pskClientTls13Callback(const char *cipherName,
                                            char *identity,
                                            unsigned maxIdentityLen,
                                            unsigned char *psk,
                                            unsigned maxPskLen);
    virtual unsigned pskServerTls13Callback(const char *identity,
                                            unsigned char *psk,
                                            unsigned maxPskLen,
                                            const char **cipherName);
};

/* QSsl::DtlsV1_0 ... DtlsV1_2OrLater */
bool isDtlsProtocol(QSsl::SslProtocol protocol);

/* Which PSK callbacks are registered. Decided in one place (pskPolicy()) and
 * used both when the WOLFSSL_CTX is created and when a WOLFSSL object is set
 * up. See docs/design-io-bridge.md, chapter 11. */
struct PskPolicy
{
    bool clientTls12 = false; /* wolfSSL_CTX_set_psk_client_callback */
    bool clientTls13 = false; /* wolfSSL_CTX_set_psk_client_cs_callback */
    bool serverTls12 = false; /* wolfSSL_CTX_set_psk_server_callback */
    bool serverTls13 = false; /* wolfSSL_CTX_set_psk_server_tls13_callback */

    bool any() const
    {
        return clientTls12 || clientTls13 || serverTls12 || serverTls13;
    }
};

PskPolicy pskPolicy(const QSslConfiguration &configuration,
                    QSslSocket::SslMode mode);
bool tls13ExternalPskRequested();

} /* namespace QTlsPrivate */

/* The definition of QSslContext is backend-specific (see
 * TlsCryptograph::checkSettingSslContext()). This one wraps a WOLFSSL_CTX
 * built from a QSslConfiguration and caches the last session for
 * resumption, like the OpenSSL backend's QSslContext. */
class QSslContext
{
public:
    Q_DISABLE_COPY_MOVE(QSslContext)

    ~QSslContext();

    static std::shared_ptr<QSslContext> sharedFromConfiguration(
            QSslSocket::SslMode mode, const QSslConfiguration &configuration,
            bool allowRootCertOnDemandLoading);

    QSslError::SslError error() const { return errorCode; }
    QString errorString() const { return errorStr; }

    /* The caller owns the returned object (wolfSSL_free()). */
    WOLFSSL *createSsl();

    /* Called when a handshake completes (or a new session ticket arrives):
     * keeps a reference to the session for resumption and, unless session
     * persistence is disabled, its serialized form. */
    bool cacheSession(WOLFSSL *ssl);
    void cacheSession(WOLFSSL_SESSION *session);

    QByteArray sessionASN1() const { return m_sessionASN1; }
    void setSessionASN1(const QByteArray &sessionASN1)
    {
        m_sessionASN1 = sessionASN1;
    }
    int sessionTicketLifeTimeHint() const
    {
        return m_sessionTicketLifeTimeHint;
    }

    QSslSocket::SslMode mode() const { return m_mode; }

    /* The TLS 1.3 suite an external PSK is bound to, or nullptr if the
     * cipher list has none that fits (see init()). */
    const char *tls13PskCipher() const
    {
        return m_tls13PskCipher.isEmpty() ? nullptr
                                          : m_tls13PskCipher.constData();
    }

private:
    QSslContext() = default;

    void init(QSslSocket::SslMode mode, const QSslConfiguration &configuration,
              bool allowRootCertOnDemandLoading);
    void setError(const QString &description);

    WOLFSSL_CTX *ctx = nullptr;
    WOLFSSL_SESSION *session = nullptr;
    QByteArray m_sessionASN1;
    QByteArray m_tls13PskCipher;
    int m_sessionTicketLifeTimeHint = -1;
    QSslError::SslError errorCode = QSslError::NoError;
    QString errorStr;
    QSslConfiguration sslConfiguration;
    QSslSocket::SslMode m_mode = QSslSocket::UnencryptedMode;
};

QT_END_NAMESPACE

#endif /* QSSLCONTEXT_WOLFSSL_P_H */
