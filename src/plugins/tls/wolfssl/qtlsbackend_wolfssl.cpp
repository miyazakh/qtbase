/*
 * Copyright (C) 2026 The Qt Company Ltd.
 * SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
 */

#include "qtlsbackend_wolfssl_p.h"

#include "../shared/qx509_generic_p.h"

#include <QtNetwork/qssl.h>

#include <QtCore/qlist.h>
#include <QtCore/qstring.h>

/* wolfssl/options.h must be included before any other wolfSSL header, so that
 * the library and the plugin agree on the configuration (struct layouts depend
 * on it). Only the native API is used; never include the wolfssl/openssl
 * headers. */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/version.h>

QT_BEGIN_NAMESPACE

using namespace Qt::StringLiterals;

Q_LOGGING_CATEGORY(lcTlsBackendWolfSSL, "qt.tlsbackend.wolfssl");

QTlsBackendWolfSSL::QTlsBackendWolfSSL()
{
    /* wolfSSL_Init() is reference counted and balanced by wolfSSL_Cleanup()
     * in the destructor, so other users of wolfSSL in the same process are
     * not affected. */
    m_libraryInitialized = wolfSSL_Init() == WOLFSSL_SUCCESS;
    if (!m_libraryInitialized)
        qCWarning(lcTlsBackendWolfSSL,
                  "Failed to initialize the wolfSSL library");
}

QTlsBackendWolfSSL::~QTlsBackendWolfSSL()
{
    if (m_libraryInitialized)
        wolfSSL_Cleanup();
}

bool QTlsBackendWolfSSL::isValid() const
{
    return m_libraryInitialized;
}

long QTlsBackendWolfSSL::tlsLibraryVersionNumber() const
{
    return long(wolfSSL_lib_version_hex());
}

QString QTlsBackendWolfSSL::tlsLibraryVersionString() const
{
    return "wolfSSL "_L1 + QLatin1StringView(wolfSSL_lib_version());
}

long QTlsBackendWolfSSL::tlsLibraryBuildVersionNumber() const
{
    return LIBWOLFSSL_VERSION_HEX;
}

QString QTlsBackendWolfSSL::tlsLibraryBuildVersionString() const
{
    return "wolfSSL "_L1 + QLatin1StringView(LIBWOLFSSL_VERSION_STRING);
}

QString QTlsBackendWolfSSL::backendName() const
{
    return u"wolfssl"_s;
}

QList<QSsl::SslProtocol> QTlsBackendWolfSSL::supportedProtocols() const
{
    /* TLS 1.2 and TLS 1.3 only; the configure test rejects wolfSSL builds
     * without either of them. DTLS is not provided by this backend. */
    return {
        QSsl::AnyProtocol,
        QSsl::SecureProtocols,
        QSsl::TlsV1_2,
        QSsl::TlsV1_2OrLater,
        QSsl::TlsV1_3,
        QSsl::TlsV1_3OrLater,
    };
}

QList<QSsl::SupportedFeature> QTlsBackendWolfSSL::supportedFeatures() const
{
    /* TLSTODO: report ALPN, PSK and session tickets once the TLS socket
     * implementation (TlsCryptographWolfSSL) is in place. */
    return {};
}

QList<QSsl::ImplementedClass> QTlsBackendWolfSSL::implementedClasses() const
{
    /* TLSTODO: add Socket, Key, DiffieHellman and EllipticCurve as they are
     * implemented. */
    return { QSsl::ImplementedClass::Certificate };
}

QTlsPrivate::X509Certificate *QTlsBackendWolfSSL::createCertificate() const
{
    return new QTlsPrivate::X509CertificateGeneric;
}

QTlsPrivate::X509PemReaderPtr QTlsBackendWolfSSL::X509PemReader() const
{
    return QTlsPrivate::X509CertificateGeneric::certificatesFromPem;
}

QTlsPrivate::X509DerReaderPtr QTlsBackendWolfSSL::X509DerReader() const
{
    return QTlsPrivate::X509CertificateGeneric::certificatesFromDer;
}

QT_END_NAMESPACE

#include "moc_qtlsbackend_wolfssl_p.cpp"
