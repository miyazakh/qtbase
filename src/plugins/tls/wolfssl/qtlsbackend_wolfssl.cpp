/*
 * Copyright (C) 2026 The Qt Company Ltd.
 * SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
 * Qt-Security score:significant reason:default
 */

#include "qtlsbackend_wolfssl_p.h"
#include "qtls_wolfssl_p.h"
#include "qtlskey_wolfssl_p.h"

#include "../shared/qx509_generic_p.h"

#include <QtNetwork/qssl.h>

#include <QtCore/qlist.h>
#include <QtCore/qmutex.h>
#include <QtCore/qscopeguard.h>
#include <QtCore/qstring.h>

#include <algorithm>

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
     * without either of them. DTLS is not provided by this backend.
     * TlsV1_0OrLater and TlsV1_1OrLater negotiate TLS 1.2 or later. */
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
    return {
        QSsl::AnyProtocol,
        QSsl::SecureProtocols,
        QSsl::TlsV1_0OrLater,
        QSsl::TlsV1_1OrLater,
        QSsl::TlsV1_2,
        QSsl::TlsV1_2OrLater,
        QSsl::TlsV1_3,
        QSsl::TlsV1_3OrLater,
    };
QT_WARNING_POP
}

QList<QSsl::SupportedFeature> QTlsBackendWolfSSL::supportedFeatures() const
{
    QList<QSsl::SupportedFeature> features;
#ifdef HAVE_ALPN
    features << QSsl::SupportedFeature::ClientSideAlpn;
    /* wolfSSL: no ALPN select callback without OPENSSL_ALL; a server picks the
     * first of the client's protocols that is in its own list. */
    features << QSsl::SupportedFeature::ServerSideAlpn;
#endif
#ifndef NO_PSK
    features << QSsl::SupportedFeature::Psk;
#endif
#if defined(HAVE_SESSION_TICKET) && defined(HAVE_EXT_CACHE)
    features << QSsl::SupportedFeature::SessionTicket;
#endif
    /* Not supported: CertificateVerification (Phase 3), OCSP (out of scope),
     * Alerts, and interrupting the handshake on verification errors (QtNetwork
     * only supports the latter with OpenSSL). */
    return features;
}

QList<QSsl::ImplementedClass> QTlsBackendWolfSSL::implementedClasses() const
{
    /* TLSTODO (Phase 3): DiffieHellman and EllipticCurve. */
    return {
        QSsl::ImplementedClass::Key,
        QSsl::ImplementedClass::Certificate,
        QSsl::ImplementedClass::Socket,
    };
}

void QTlsBackendWolfSSL::ensureInitialized() const
{
    /* Same pattern as the OpenSSL backend: setDefaultSupportedCiphers() can
     * call back into ensureInitialized() on the same thread, hence the
     * recursive mutex and the "started" flag. */
    Q_CONSTINIT static bool initializationStarted = false;
    Q_CONSTINIT static QAtomicInt initialized = Q_BASIC_ATOMIC_INITIALIZER(0);
    Q_CONSTINIT static QRecursiveMutex initMutex;

    if (initialized.loadAcquire() || !m_libraryInitialized)
        return;

    const QMutexLocker locker(&initMutex);
    if (initializationStarted || initialized.loadAcquire())
        return;
    initializationStarted = true;
    auto guard = qScopeGuard([] { initialized.storeRelease(1); });

    /* The suites compiled into wolfSSL, in its order of preference. */
    QByteArray names(8192, Qt::Uninitialized);
    if (wolfSSL_get_ciphers(names.data(), int(names.size()))
        != WOLFSSL_SUCCESS) {
        qCWarning(lcTlsBackendWolfSSL,
                  "Could not get the list of cipher suites");
        return;
    }
    names.truncate(qstrnlen(names.constData(), names.size()));

    QList<QSslCipher> ciphers;
    QList<QSslCipher> defaultCiphers;
    for (const auto name : QLatin1StringView(names).tokenize(u':')) {
        const QSslCipher cipher = ciphersuiteFromName(name);
        if (cipher.isNull())
            continue;
        ciphers << cipher;
        /* Keep pre-RFC 7905 ChaCha20 suites and NULL ciphers out of the
         * defaults; they are still available on request. */
        if (!name.endsWith("-OLD"_L1) && !name.contains("NULL"_L1))
            defaultCiphers << cipher;
    }

    /* wolfSSL_get_ciphers() lists the suites in the order they are compiled
     * in, not by preference, and a cipher list given to wolfSSL is used in
     * the order given. Put the strongest first: TLS 1.3, then forward-secret
     * AEAD suites, then CBC suites, PSK-only suites last. */
    const auto rank = [](const QSslCipher &cipher) {
        const QString name = cipher.name();
        if (cipher.protocol() == QSsl::TlsV1_3)
            return 0;
        const bool aead = name.contains("-GCM-"_L1)
                || name.contains("CHACHA20"_L1) || name.contains("-CCM"_L1);
        const bool ecdhe = cipher.keyExchangeMethod() == "ECDH"_L1;
        const bool dhe = cipher.keyExchangeMethod() == "DH"_L1;
        const bool sha1 = name.endsWith("-SHA"_L1);
        if (cipher.authenticationMethod() == "PSK"_L1)
            return 6;
        if (aead)
            return ecdhe ? 1 : (dhe ? 2 : 5);
        if (!sha1)
            return ecdhe ? 3 : 4;
        return 5;
    };
    const auto byRank = [&rank](const QSslCipher &lhs, const QSslCipher &rhs) {
        return rank(lhs) < rank(rhs);
    };
    std::stable_sort(ciphers.begin(), ciphers.end(), byRank);
    std::stable_sort(defaultCiphers.begin(), defaultCiphers.end(), byRank);

    setDefaultSupportedCiphers(ciphers);
    setDefaultCiphers(defaultCiphers);

    /* TLSTODO (Phase 3): elliptic curves (resetDefaultEllipticCurves()).
     * TLSTODO (Phase 5): system CA certificates. */
}

QString QTlsBackendWolfSSL::errorString(int errorCode)
{
    char buffer[WOLFSSL_MAX_ERROR_SZ] = {};
    /* wolfSSL's error codes are negative; the function takes them as
     * unsigned long and converts them back. */
    wolfSSL_ERR_error_string_n(static_cast<unsigned long>(errorCode), buffer,
                               sizeof buffer);
    return QString::fromLatin1(buffer) + " ("_L1 + QString::number(errorCode)
            + u')';
}

QSslCipher QTlsBackendWolfSSL::ciphersuiteFromName(QLatin1StringView name)
{
    /* wolfSSL names: "TLS13-<ENC>-<HASH>" for TLS 1.3, and
     * "[<KX>-][<AU>-]<ENC>[-<MODE>]-<HASH>" for TLS 1.2, with an optional
     * "-OLD" suffix for draft ChaCha20 suites. */
    if (name.isEmpty())
        return {};

    QList<QLatin1StringView> parts;
    for (const auto part : name.tokenize(u'-'))
        parts << part;

    const bool tls13 = parts.first() == "TLS13"_L1;
    qsizetype index = 0;
    QString keyExchange;
    QString authentication;

    if (tls13) {
        /* As reported by OpenSSL: TLS 1.3 suites do not determine these. */
        keyExchange = u"any"_s;
        authentication = u"any"_s;
        index = 1;
    } else {
        const auto token = [&parts](qsizetype i) {
            return i < parts.size() ? parts.at(i) : QLatin1StringView();
        };
        if (token(0) == "ECDHE"_L1 || token(0) == "ECDH"_L1) {
            keyExchange = u"ECDH"_s;
            index = 1;
        } else if (token(0) == "DHE"_L1 || token(0) == "DH"_L1) {
            keyExchange = u"DH"_s;
            index = 1;
        }

        if (token(index) == "RSA"_L1 || token(index) == "ECDSA"_L1) {
            authentication = token(index).toString();
            ++index;
        } else if (token(index) == "PSK"_L1) {
            authentication = u"PSK"_s;
            if (keyExchange.isEmpty())
                keyExchange = u"PSK"_s;
            ++index;
        }

        if (keyExchange.isEmpty())
            keyExchange = u"RSA"_s;
        if (authentication.isEmpty())
            authentication = u"RSA"_s;
    }

    /* The bulk cipher and its key size. */
    const QLatin1StringView encryption
            = index < parts.size() ? parts.at(index) : QLatin1StringView();
    const QLatin1StringView mode = index + 1 < parts.size()
            ? parts.at(index + 1)
            : QLatin1StringView();
    QString method;
    int bits = 0;
    if (encryption.startsWith("AES"_L1)) {
        bits = encryption.sliced(3).toString().toInt();
        if (mode == "GCM"_L1)
            method = u"AESGCM"_s;
        else if (mode == "CCM"_L1 || mode == "CCM8"_L1)
            method = u"AESCCM"_s;
        else
            method = u"AES"_s;
    } else if (encryption == "CHACHA20"_L1) {
        bits = 256;
        method = u"CHACHA20/POLY1305"_s;
    } else if (encryption.startsWith("CAMELLIA"_L1)) {
        bits = encryption.sliced(8).toString().toInt();
        method = u"Camellia"_s;
    } else if (encryption.startsWith("ARIA"_L1)) {
        bits = encryption.sliced(4).toString().toInt();
        method = u"ARIA"_s;
    } else if (encryption == "NULL"_L1) {
        method = u"None"_s;
    } else {
        method = encryption.toString();
    }
    if (bits)
        method += u'(' + QString::number(bits) + u')';

    return QTlsBackend::createCiphersuite(name.toString(), keyExchange, method,
                                          authentication, bits,
                                          tls13 ? QSsl::TlsV1_3 : QSsl::TlsV1_2,
                                          tls13 ? u"TLSv1.3"_s : u"TLSv1.2"_s);
}

QTlsPrivate::TlsKey *QTlsBackendWolfSSL::createKey() const
{
    return new QTlsPrivate::TlsKeyWolfSSL;
}

QTlsPrivate::TlsCryptograph *QTlsBackendWolfSSL::createTlsCryptograph() const
{
    return new QTlsPrivate::TlsCryptographWolfSSL;
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
