/*
 * Copyright (C) 2026 The Qt Company Ltd.
 * SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
 */

#ifndef QX509_WOLFSSL_P_H
#define QX509_WOLFSSL_P_H

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

#include "../shared/qx509_generic_p.h"

#include <QtNetwork/qsslcertificate.h>
#include <QtNetwork/qsslerror.h>

#include <QtCore/qbytearray.h>
#include <QtCore/qlist.h>
#include <QtCore/qstring.h>

QT_BEGIN_NAMESPACE

class QIODevice;
class QSslKey;

namespace QTlsPrivate {

/* Certificates are parsed by Qt's generic ASN.1 code. wolfSSL provides chain
 * verification (QSslCertificate::verify()) and PKCS#12 import. */
class X509CertificateWolfSSL final : public X509CertificateGeneric
{
public:
    TlsKey *publicKey() const override;

    static QList<QSslError> verify(const QList<QSslCertificate> &chain,
                                   const QString &hostName);
    static QList<QSslError> verify(const QList<QSslCertificate> &caCertificates,
                                   const QList<QSslCertificate> &chain,
                                   const QString &hostName);

    static bool importPkcs12(QIODevice *device, QSslKey *key,
                             QSslCertificate *cert,
                             QList<QSslCertificate> *caCertificates,
                             const QByteArray &passPhrase);

    /* Translates an error wolfSSL reports for the certificate at 'depth' of
     * 'chain' (0 is the end-entity certificate). */
    static QSslError::SslError sslErrorFromWolfSSL(
            int code, int depth, const QList<QSslCertificate> &chain);
    /* wolfSSL reports one error per certificate and prefers other errors to
     * an invalid validity period. Adds the missing CertificateExpired and
     * CertificateNotYetValid errors for the certificates in 'errors'. */
    static void addValidityErrors(QList<QSslError> *errors);
};

} /* namespace QTlsPrivate */

QT_END_NAMESPACE

#endif /* QX509_WOLFSSL_P_H */
