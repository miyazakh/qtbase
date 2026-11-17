/*
 * Copyright (C) 2026 The Qt Company Ltd.
 * SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
 * Qt-Security score:significant reason:default
 */

#include "qtlsbackend_wolfssl_p.h"
#include "qtls_wolfssl_p.h"
#include "qtlskey_wolfssl_p.h"
#include "qx509_wolfssl_p.h"

#include <QtNetwork/qssl.h>
#include <QtNetwork/qssldiffiehellmanparameters.h>

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
#include <wolfssl/wolfcrypt/dh.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

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
    features << QSsl::SupportedFeature::CertificateVerification;
    /* Not supported: OCSP (out of scope), Alerts, and interrupting the
     * handshake on verification errors (QtNetwork only supports the latter
     * with OpenSSL). */
    return features;
}

QList<QSsl::ImplementedClass> QTlsBackendWolfSSL::implementedClasses() const
{
    return {
        QSsl::ImplementedClass::Key,
        QSsl::ImplementedClass::Certificate,
        QSsl::ImplementedClass::Socket,
        QSsl::ImplementedClass::DiffieHellman,
        QSsl::ImplementedClass::EllipticCurve,
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

    resetDefaultEllipticCurves();
    /* TLSTODO (Phase 5): system CA certificates. */
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
    return new QTlsPrivate::X509CertificateWolfSSL;
}

QTlsPrivate::X509ChainVerifyPtr QTlsBackendWolfSSL::X509Verifier() const
{
    return QTlsPrivate::X509CertificateWolfSSL::verify;
}

QTlsPrivate::X509PemReaderPtr QTlsBackendWolfSSL::X509PemReader() const
{
    return QTlsPrivate::X509CertificateGeneric::certificatesFromPem;
}

QTlsPrivate::X509DerReaderPtr QTlsBackendWolfSSL::X509DerReader() const
{
    return QTlsPrivate::X509CertificateGeneric::certificatesFromDer;
}

QTlsPrivate::X509Pkcs12ReaderPtr QTlsBackendWolfSSL::X509Pkcs12Reader() const
{
    return QTlsPrivate::X509CertificateWolfSSL::importPkcs12;
}

namespace {

/* Elliptic curves. QSslEllipticCurve ids are opaque; this backend uses the
 * code points of the IANA "TLS Supported Groups" registry, which wolfSSL
 * takes directly (wolfSSL_CTX_set_groups()), and lists only curves that have
 * one. Names are the OpenSSL short names Qt applications already use, plus
 * the NIST names as aliases. */
struct CurveInfo
{
    int group;
    int eccCurveId; /* wolfCrypt's ecc_curve_id; -1 for X25519/X448 */
    const char *name;
    const char *nistName;
};

constexpr CurveInfo curveTable[] = {
        /* RFC 4492 / RFC 8422 */
        {WOLFSSL_ECC_SECP160K1, ECC_SECP160K1, "secp160k1", nullptr},
        {WOLFSSL_ECC_SECP160R1, ECC_SECP160R1, "secp160r1", nullptr},
        {WOLFSSL_ECC_SECP160R2, ECC_SECP160R2, "secp160r2", nullptr},
        {WOLFSSL_ECC_SECP192K1, ECC_SECP192K1, "secp192k1", nullptr},
        {WOLFSSL_ECC_SECP192R1, ECC_SECP192R1, "prime192v1", "P-192"},
        {WOLFSSL_ECC_SECP224K1, ECC_SECP224K1, "secp224k1", nullptr},
        {WOLFSSL_ECC_SECP224R1, ECC_SECP224R1, "secp224r1", "P-224"},
        {WOLFSSL_ECC_SECP256K1, ECC_SECP256K1, "secp256k1", nullptr},
        {WOLFSSL_ECC_SECP256R1, ECC_SECP256R1, "prime256v1", "P-256"},
        {WOLFSSL_ECC_SECP384R1, ECC_SECP384R1, "secp384r1", "P-384"},
        {WOLFSSL_ECC_SECP521R1, ECC_SECP521R1, "secp521r1", "P-521"},
        /* RFC 7027 */
        {WOLFSSL_ECC_BRAINPOOLP256R1, ECC_BRAINPOOLP256R1, "brainpoolP256r1",
         nullptr},
        {WOLFSSL_ECC_BRAINPOOLP384R1, ECC_BRAINPOOLP384R1, "brainpoolP384r1",
         nullptr},
        {WOLFSSL_ECC_BRAINPOOLP512R1, ECC_BRAINPOOLP512R1, "brainpoolP512r1",
         nullptr},
        /* RFC 7748 / RFC 8422 */
        {WOLFSSL_ECC_X25519, -1, "X25519", nullptr},
        {WOLFSSL_ECC_X448, -1, "X448", nullptr},
};

bool isCompiledIn(const CurveInfo &curve)
{
#ifdef HAVE_ECC
    if (curve.eccCurveId >= 0)
        return wc_ecc_get_curve_idx(curve.eccCurveId) >= 0;
#endif
#ifdef HAVE_CURVE25519
    if (curve.group == WOLFSSL_ECC_X25519)
        return true;
#endif
#ifdef HAVE_CURVE448
    if (curve.group == WOLFSSL_ECC_X448)
        return true;
#endif
    return false;
}

const CurveInfo *findCurve(int group)
{
    for (const CurveInfo &curve : curveTable) {
        if (curve.group == group)
            return isCompiledIn(curve) ? &curve : nullptr;
    }
    return nullptr;
}

const CurveInfo *findCurve(const QString &name)
{
    if (name.isEmpty())
        return nullptr;
    for (const CurveInfo &curve : curveTable) {
        if (name == QLatin1StringView(curve.name)
            || (curve.nistName && name == QLatin1StringView(curve.nistName))) {
            return isCompiledIn(curve) ? &curve : nullptr;
        }
    }
    return nullptr;
}

} /* unnamed namespace */

int QTlsBackendWolfSSL::tlsGroupForCurve(int curveId)
{
    return findCurve(curveId) ? curveId : 0;
}

QList<int> QTlsBackendWolfSSL::ellipticCurvesIds() const
{
    QList<int> ids;
    for (const CurveInfo &curve : curveTable) {
        if (isCompiledIn(curve))
            ids << curve.group;
    }
    return ids;
}

int QTlsBackendWolfSSL::curveIdFromShortName(const QString &name) const
{
    const CurveInfo *curve = findCurve(name);
    return curve ? curve->group : 0;
}

int QTlsBackendWolfSSL::curveIdFromLongName(const QString &name) const
{
    /* As with OpenSSL, long and short names are the same for these curves. */
    return curveIdFromShortName(name);
}

QString QTlsBackendWolfSSL::shortNameForId(int id) const
{
    const CurveInfo *curve = findCurve(id);
    return curve ? QString::fromLatin1(curve->name) : QString();
}

QString QTlsBackendWolfSSL::longNameForId(int id) const
{
    return shortNameForId(id);
}

bool QTlsBackendWolfSSL::isTlsNamedCurve(int id) const
{
    /* Only curves with a TLS code point are listed. */
    return findCurve(id) != nullptr;
}

namespace {

/* Remainder of the big-endian unsigned integer 'number' divided by 'divisor'.
 */
unsigned remainder(QByteArrayView number, unsigned divisor)
{
    unsigned result = 0;
    for (const char byte : number)
        result = (result * 256 + static_cast<unsigned char>(byte)) % divisor;
    return result;
}

QByteArrayView withoutLeadingZeros(QByteArrayView number)
{
    while (!number.isEmpty() && number.front() == '\0')
        number = number.sliced(1);
    return number;
}

int numberOfBits(QByteArrayView number)
{
    number = withoutLeadingZeros(number);
    if (number.isEmpty())
        return 0;
    int bits = int(number.size() - 1) * 8;
    for (unsigned top = static_cast<unsigned char>(number.front()); top;
         top >>= 1)
        ++bits;
    return bits;
}

#ifndef NO_DH
bool isPrime(QByteArrayView number, QByteArrayView generator)
{
    /* wolfCrypt's untrusted-parameter check is a Miller-Rabin test of the
     * modulus with random bases (RFC 7919 groups are recognised directly). */
    DhKey key;
    if (wc_InitDhKey(&key) != 0)
        return false;
    const int result = wc_DhSetCheckKey(
            &key, reinterpret_cast<const byte *>(number.data()),
            word32(number.size()),
            reinterpret_cast<const byte *>(generator.data()),
            word32(generator.size()), nullptr, 0, 0, nullptr);
    wc_FreeDhKey(&key);
    return result == 0;
}
#endif /* !NO_DH */

} /* unnamed namespace */

int QTlsBackendWolfSSL::dhParametersFromDer(const QByteArray &der,
                                            QByteArray *data) const
{
    /* The same checks as the OpenSSL backend's (DH_check()): p must be a safe
     * prime of at least 1024 bits and g a suitable generator. */
    using DHParams = QSslDiffieHellmanParameters;
    Q_ASSERT(data);

    if (der.isEmpty())
        return DHParams::InvalidInputDataError;

#ifndef NO_DH
    /* Large enough for 16384-bit parameters. */
    QByteArray p(2048 + 1, Qt::Uninitialized);
    QByteArray g(2048 + 1, Qt::Uninitialized);
    auto pSize = word32(p.size());
    auto gSize = word32(g.size());
    if (wc_DhParamsLoad(reinterpret_cast<const byte *>(der.constData()),
                        word32(der.size()), reinterpret_cast<byte *>(p.data()),
                        &pSize, reinterpret_cast<byte *>(g.data()), &gSize)
        != 0) {
        return DHParams::InvalidInputDataError;
    }
    const QByteArrayView prime
            = withoutLeadingZeros(QByteArrayView(p).first(pSize));
    const QByteArrayView generator
            = withoutLeadingZeros(QByteArrayView(g).first(gSize));

    if (numberOfBits(prime) < 1024 || !(prime.back() & 1))
        return DHParams::UnsafeParametersError;

    /* g > 1, and shorter than p (so that g < p - 1) */
    if (numberOfBits(generator) < 2
        || numberOfBits(generator) >= numberOfBits(prime)) {
        return DHParams::UnsafeParametersError;
    }

    /* As in the OpenSSL backend, accept the IETF groups (p mod 24 == 23)
     * as well as OpenSSL's own (p mod 24 == 11) for g == 2. */
    if (numberOfBits(generator) <= 8) {
        const unsigned g = static_cast<unsigned char>(generator.back());
        if (g == 2) {
            const unsigned residue = remainder(prime, 24);
            if (residue != 11 && residue != 23)
                return DHParams::UnsafeParametersError;
        } else if (g == 5) {
            const unsigned residue = remainder(prime, 10);
            if (residue != 3 && residue != 7)
                return DHParams::UnsafeParametersError;
        }
    }

    /* p and q = (p - 1) / 2 must both be prime. p is odd, so q is p shifted
     * right by one bit. */
    QByteArray q(prime.size(), Qt::Uninitialized);
    unsigned carry = 0;
    for (qsizetype i = 0; i < prime.size(); ++i) {
        const unsigned byte = static_cast<unsigned char>(prime.at(i));
        q[i] = char((byte >> 1) | (carry << 7));
        carry = byte & 1;
    }
    if (!isPrime(prime, generator)
        || !isPrime(withoutLeadingZeros(q), QByteArrayView("\x02", 1))) {
        return DHParams::UnsafeParametersError;
    }

    *data = der;
    return DHParams::NoError;
#else
    Q_UNUSED(data);
    qCWarning(lcTlsBackendWolfSSL,
              "Diffie-Hellman parameters are not supported: "
              "wolfSSL was built without DH");
    return DHParams::InvalidInputDataError;
#endif /* !NO_DH */
}

int QTlsBackendWolfSSL::dhParametersFromPem(const QByteArray &pem,
                                            QByteArray *data) const
{
    using DHParams = QSslDiffieHellmanParameters;
    Q_ASSERT(data);

    static constexpr QByteArrayView begin("-----BEGIN DH PARAMETERS-----");
    static constexpr QByteArrayView end("-----END DH PARAMETERS-----");
    const qsizetype beginIndex = pem.indexOf(begin);
    if (beginIndex == -1)
        return DHParams::InvalidInputDataError;
    const qsizetype bodyIndex = beginIndex + begin.size();
    const qsizetype endIndex = pem.indexOf(end, bodyIndex);
    if (endIndex == -1)
        return DHParams::InvalidInputDataError;

    QByteArray body = pem.mid(bodyIndex, endIndex - bodyIndex);
    body.removeIf([](char c) {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n';
    });
    const auto decoded = QByteArray::fromBase64Encoding(
            body, QByteArray::AbortOnBase64DecodingErrors);
    if (!decoded)
        return DHParams::InvalidInputDataError;
    return dhParametersFromDer(*decoded, data);
}

QT_END_NAMESPACE

#include "moc_qtlsbackend_wolfssl_p.cpp"
