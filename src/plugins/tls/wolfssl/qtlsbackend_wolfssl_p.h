/*
 * Copyright (C) 2026 The Qt Company Ltd.
 * SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
 * Qt-Security score:significant reason:default
 */

#ifndef QTLSBACKEND_WOLFSSL_P_H
#define QTLSBACKEND_WOLFSSL_P_H

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

#include <QtNetwork/private/qtlsbackend_p.h>

#include <QtNetwork/qsslcipher.h>

#include <QtCore/qglobal.h>
#include <QtCore/qloggingcategory.h>
#include <QtCore/qstring.h>

QT_BEGIN_NAMESPACE

class QTlsBackendWolfSSL final : public QTlsBackend
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID QTlsBackend_iid)
    Q_INTERFACES(QTlsBackend)

public:
    QTlsBackendWolfSSL();
    ~QTlsBackendWolfSSL() override;

    /* Human-readable text for a wolfSSL or wolfCrypt error code. */
    static QString errorString(int errorCode);
    /* A QSslCipher for one of wolfSSL's own suite names, such as
     * "ECDHE-RSA-AES128-GCM-SHA256" or "TLS13-AES128-GCM-SHA256". */
    static QSslCipher ciphersuiteFromName(QLatin1StringView name);
    /* The TLS supported group (IANA "TLS Supported Groups" registry) for a
     * QSslEllipticCurve id, or 0. The ids are those code points. */
    static int tlsGroupForCurve(int curveId);

private:
    bool isValid() const override;
    long tlsLibraryVersionNumber() const override;
    QString tlsLibraryVersionString() const override;
    long tlsLibraryBuildVersionNumber() const override;
    QString tlsLibraryBuildVersionString() const override;
    void ensureInitialized() const override;
    QList<QSslCertificate> systemCaCertificates() const override;

    QString backendName() const override;
    QList<QSsl::SslProtocol> supportedProtocols() const override;
    QList<QSsl::SupportedFeature> supportedFeatures() const override;
    QList<QSsl::ImplementedClass> implementedClasses() const override;

    QTlsPrivate::TlsKey *createKey() const override;
    QTlsPrivate::X509Certificate *createCertificate() const override;
    QTlsPrivate::TlsCryptograph *createTlsCryptograph() const override;
#if QT_CONFIG(wolfssl_dtls)
    QTlsPrivate::DtlsCryptograph *createDtlsCryptograph(
            QDtls *q, int mode) const override;
    QTlsPrivate::DtlsCookieVerifier *createDtlsCookieVerifier() const override;
#endif
    QTlsPrivate::X509ChainVerifyPtr X509Verifier() const override;
    QTlsPrivate::X509PemReaderPtr X509PemReader() const override;
    QTlsPrivate::X509DerReaderPtr X509DerReader() const override;
    QTlsPrivate::X509Pkcs12ReaderPtr X509Pkcs12Reader() const override;

    QList<int> ellipticCurvesIds() const override;
    int curveIdFromShortName(const QString &name) const override;
    int curveIdFromLongName(const QString &name) const override;
    QString shortNameForId(int cid) const override;
    QString longNameForId(int cid) const override;
    bool isTlsNamedCurve(int cid) const override;

    int dhParametersFromDer(const QByteArray &derData,
                            QByteArray *data) const override;
    int dhParametersFromPem(const QByteArray &pemData,
                            QByteArray *data) const override;

    bool m_libraryInitialized = false;
};

Q_DECLARE_LOGGING_CATEGORY(lcTlsBackendWolfSSL)

QT_END_NAMESPACE

#endif /* QTLSBACKEND_WOLFSSL_P_H */
