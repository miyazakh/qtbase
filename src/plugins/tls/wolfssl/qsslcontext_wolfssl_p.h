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

QT_BEGIN_NAMESPACE

namespace QTlsPrivate {

/* Which PSK callbacks are registered. Decided in one place (pskPolicy()) and
 * used both when the WOLFSSL_CTX is created and when a WOLFSSL object is set
 * up. See docs/design-io-bridge.md, chapter 11. */
struct PskPolicy
{
    bool clientTls12 = false; /* client: wolfSSL_CTX_set_psk_client_callback */
    bool serverTls12 = false; /* server: wolfSSL_CTX_set_psk_server_callback */
    bool tls13 = false; /* *_tls13 callbacks (external TLS 1.3 PSK, not yet) */
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

private:
    QSslContext() = default;

    void init(QSslSocket::SslMode mode, const QSslConfiguration &configuration,
              bool allowRootCertOnDemandLoading);
    void setError(const QString &description);

    WOLFSSL_CTX *ctx = nullptr;
    WOLFSSL_SESSION *session = nullptr;
    QByteArray m_sessionASN1;
    int m_sessionTicketLifeTimeHint = -1;
    QSslError::SslError errorCode = QSslError::NoError;
    QString errorStr;
    QSslConfiguration sslConfiguration;
    QSslSocket::SslMode m_mode = QSslSocket::UnencryptedMode;
};

QT_END_NAMESPACE

#endif /* QSSLCONTEXT_WOLFSSL_P_H */
