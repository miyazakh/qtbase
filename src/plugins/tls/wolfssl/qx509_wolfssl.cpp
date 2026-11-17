/*
 * Copyright (C) 2026 The Qt Company Ltd.
 * SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
 * Qt-Security score:critical reason:cryptography
 */

#include "qx509_wolfssl_p.h"
#include "qtlsbackend_wolfssl_p.h"
#include "qtlskey_wolfssl_p.h"

#include "../shared/qasn1element_p.h"

#include <QtNetwork/private/qsslcertificate_p.h>
#include <QtNetwork/private/qtlsbackend_p.h>

#include <QtNetwork/qsslcertificateextension.h>
#include <QtNetwork/qsslconfiguration.h>
#include <QtNetwork/qsslkey.h>

#include <QtCore/qdatetime.h>
#include <QtCore/qiodevice.h>
#include <QtCore/qscopeguard.h>
#include <QtCore/qvariant.h>

#include <memory>

/* wolfssl/options.h must come first, see qtlsbackend_wolfssl.cpp. */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/pkcs12.h>
#include <wolfssl/wolfcrypt/types.h>

QT_BEGIN_NAMESPACE

using namespace Qt::StringLiterals;

namespace QTlsPrivate {

namespace {

const unsigned char *bytes(const QByteArray &array)
{
    return reinterpret_cast<const unsigned char *>(array.constData());
}

struct CertManagerDeleter
{
    void operator()(WOLFSSL_CERT_MANAGER *cm) const
    {
        wolfSSL_CertManagerFree(cm);
    }
};
using CertManagerPtr
        = std::unique_ptr<WOLFSSL_CERT_MANAGER, CertManagerDeleter>;

bool isCaCertificate(const QSslCertificate &cert)
{
    /* basicConstraints, as parsed by X509CertificateGeneric. */
    const auto extensions = cert.extensions();
    for (const QSslCertificateExtension &extension : extensions) {
        if (extension.oid() == "2.5.29.19"_L1)
            return extension.value().toMap().value("ca"_L1).toBool();
    }
    return false;
}

} /* unnamed namespace */

TlsKey *X509CertificateWolfSSL::publicKey() const
{
    /* As in the Schannel backend. */
    auto key = std::make_unique<TlsKeyWolfSSL>(QSsl::PublicKey);
    if (publicKeyAlgorithm != QSsl::Opaque)
        key->decodeDer(QSsl::PublicKey, publicKeyAlgorithm, publicKeyDerData,
                       {}, false);
    return key.release();
}

QSslError::SslError X509CertificateWolfSSL::sslErrorFromWolfSSL(
        int code, int depth, const QList<QSslCertificate> &chain)
{
    /* wolfSSL's own error codes (OPENSSL_COMPATIBLE_DEFAULTS is not used),
     * as they come from certificate parsing and the verify callback. */
    switch (code) {
    case ASN_NO_SIGNER_E: {
        const QSslCertificate cert = chain.value(depth);
        if (!cert.isNull() && cert.isSelfSigned())
            return depth == 0 ? QSslError::SelfSignedCertificate
                              : QSslError::SelfSignedCertificateInChain;
        if (!chain.isEmpty() && chain.constLast().isSelfSigned())
            return QSslError::SelfSignedCertificateInChain;
        return QSslError::UnableToGetLocalIssuerCertificate;
    }
    case ASN_SELF_SIGNED_E:
        return depth == 0 ? QSslError::SelfSignedCertificate
                          : QSslError::SelfSignedCertificateInChain;
    case ASN_AFTER_DATE_E:
        return QSslError::CertificateExpired;
    case ASN_BEFORE_DATE_E:
        return QSslError::CertificateNotYetValid;
    case ASN_SIG_CONFIRM_E:
        return QSslError::CertificateSignatureFailed;
    case ASN_SIG_OID_E:
    case ASN_SIG_HASH_E:
    case ASN_SIG_KEY_E:
        return QSslError::UnableToDecryptCertificateSignature;
    case NOT_CA_ERROR:
        return QSslError::InvalidCaCertificate;
    case ASN_PATHLEN_SIZE_E:
    case ASN_PATHLEN_INV_E:
        return QSslError::PathLengthExceeded;
    case KEYUSE_SIGNATURE_E:
    case KEYUSE_ENCIPHER_E:
    case EXTKEYUSE_AUTH_E:
    case KEYUSAGE_E:
    case EXTKEYUSAGE_E:
        /* KEYUSAGE_E also covers keyCertSign without cA, which wolfSSL
         * rejects as RFC 5280 requires. */
        return QSslError::InvalidPurpose;
    case CRL_CERT_REVOKED:
        return QSslError::CertificateRevoked;
    case RSA_KEY_SIZE_E:
    case ECC_KEY_SIZE_E:
        /* The issuer's key is below the configured minimum size. */
        return QSslError::CertificateRejected;
    default:
        qCDebug(lcTlsBackendWolfSSL)
                << "Certificate verification error at depth" << depth << ':'
                << QTlsBackendWolfSSL::errorString(code);
        return QSslError::UnspecifiedError;
    }
}

void X509CertificateWolfSSL::addValidityErrors(QList<QSslError> *errors)
{
    /* Only certificates that already have an error: for the others wolfSSL
     * has checked the dates itself, and a certificate it did not use (such
     * as an expired cross-signed root sent by a server) must not fail. */
    QList<QSslCertificate> checked;
    const QDateTime now = QDateTime::currentDateTimeUtc();
    const QList<QSslError> existing = *errors;
    for (const QSslError &error : existing) {
        const QSslCertificate cert = error.certificate();
        if (cert.isNull() || checked.contains(cert))
            continue;
        checked << cert;
        QSslError dateError;
        if (cert.effectiveDate().isValid() && cert.effectiveDate() > now)
            dateError = QSslError(QSslError::CertificateNotYetValid, cert);
        else if (cert.expiryDate().isValid() && cert.expiryDate() < now)
            dateError = QSslError(QSslError::CertificateExpired, cert);
        if (dateError.error() != QSslError::NoError
            && !errors->contains(dateError)) {
            errors->append(dateError);
        }
    }
}

QList<QSslError> X509CertificateWolfSSL::verify(
        const QList<QSslCertificate> &chain, const QString &hostName)
{
    /* TLSTODO (Phase 5): add the system CA certificates, as the OpenSSL
     * backend does when they are loaded on demand. */
    return verify(QSslConfiguration::defaultConfiguration().caCertificates(),
                  chain, hostName);
}

QList<QSslError> X509CertificateWolfSSL::verify(
        const QList<QSslCertificate> &caCertificates,
        const QList<QSslCertificate> &chain, const QString &hostName)
{
    if (chain.isEmpty())
        return {QSslError(QSslError::UnspecifiedError)};

    const CertManagerPtr cm(wolfSSL_CertManagerNew());
    if (!cm) {
        qCWarning(lcTlsBackendWolfSSL,
                  "Unable to create a certificate manager");
        return {QSslError(QSslError::UnspecifiedError)};
    }

    /* As in the OpenSSL backend, expired CA certificates are left out so that
     * they cannot shadow a valid one with the same name. */
    const QDateTime now = QDateTime::currentDateTimeUtc();
    for (const QSslCertificate &caCertificate : caCertificates) {
        if (caCertificate.expiryDate() < now)
            continue;
        const QByteArray der = caCertificate.toDer();
        wolfSSL_CertManagerLoadCABuffer(cm.get(), bytes(der), long(der.size()),
                                        WOLFSSL_FILETYPE_ASN1);
    }

    QList<QSslError> errors;

    /* wolfSSL's certificate manager verifies one certificate at a time
     * against the CAs it holds. Walk the chain from the top, as wolfSSL does
     * with a peer's chain during a handshake: verify a certificate, then add
     * it as a chain CA (which wolfSSL refuses for certificates that are not
     * CAs) so that the next one down can be verified against it. */
    bool issuerMissing = false;
    for (qsizetype depth = chain.size() - 1; depth >= 0; --depth) {
        const QSslCertificate &cert = chain.at(depth);
        const QByteArray der = cert.toDer();
        if (der.isEmpty()) {
            errors << QSslError(QSslError::UnspecifiedError, cert);
            issuerMissing = true;
            continue;
        }

        const int verified = wolfSSL_CertManagerVerifyBuffer(
                cm.get(), bytes(der), long(der.size()), WOLFSSL_FILETYPE_ASN1);
        /* A missing issuer below an unusable one is a consequence of the
         * error already reported for that one. */
        if (verified != WOLFSSL_SUCCESS
            && !(issuerMissing && verified == ASN_NO_SIGNER_E)) {
            errors << QSslError(
                    sslErrorFromWolfSSL(verified, int(depth), chain), cert);
        }

        if (depth == 0)
            break;

        /* wolfSSL refuses chain CAs without basicConstraints cA, but it may
         * fail on another check first (such as keyCertSign without cA), so
         * look at the extension here. */
        if (!isCaCertificate(cert)) {
            errors << QSslError(QSslError::InvalidCaCertificate, cert);
            issuerMissing = true;
            continue;
        }
        const int loaded = wolfSSL_CertManagerLoadCABufferType(
                cm.get(), bytes(der), long(der.size()), WOLFSSL_FILETYPE_ASN1,
                0, WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY, WOLFSSL_CHAIN_CA);
        issuerMissing = loaded != WOLFSSL_SUCCESS;
    }

    addValidityErrors(&errors);

    /* As in the OpenSSL backend, these come first. */
    QList<QSslError> result;
    if (chain.constFirst().isBlacklisted())
        result << QSslError(QSslError::CertificateBlacklisted,
                            chain.constFirst());
    if (!hostName.isEmpty()
        && !TlsCryptograph::isMatchingHostname(chain.constFirst(), hostName)) {
        result << QSslError(QSslError::HostNameMismatch, chain.constFirst());
    }
    return result + errors;
}

bool X509CertificateWolfSSL::importPkcs12(
        QIODevice *device, QSslKey *key, QSslCertificate *cert,
        QList<QSslCertificate> *caCertificates, const QByteArray &passPhrase)
{
    /* These are required */
    Q_ASSERT(device);
    Q_ASSERT(key);
    Q_ASSERT(cert);

#ifdef HAVE_PKCS12
    const QByteArray pkcs12Data = device->readAll();
    if (pkcs12Data.isEmpty())
        return false;

    WC_PKCS12 *pkcs12 = wc_PKCS12_new();
    if (!pkcs12)
        return false;
    const auto pkcs12Guard = qScopeGuard([pkcs12] { wc_PKCS12_free(pkcs12); });

    int result = wc_d2i_PKCS12(bytes(pkcs12Data), word32(pkcs12Data.size()),
                               pkcs12);
    if (result != 0) {
        qCWarning(lcTlsBackendWolfSSL, "Unable to read PKCS#12 structure: %ls",
                  qUtf16Printable(QTlsBackendWolfSSL::errorString(result)));
        return false;
    }

    byte *keyDer = nullptr;
    word32 keyDerSize = 0;
    byte *certDer = nullptr;
    word32 certDerSize = 0;
    WC_DerCertList *caList = nullptr;
    /* Keep the PKCS#8 header: it names the key algorithm. */
    result = wc_PKCS12_parse_ex(pkcs12, passPhrase.constData(), &keyDer,
                                &keyDerSize, &certDer, &certDerSize, &caList,
                                1);
    const auto parsedGuard = qScopeGuard([&] {
        if (keyDer) {
            wc_ForceZero(keyDer, keyDerSize);
            XFREE(keyDer, nullptr, DYNAMIC_TYPE_PUBLIC_KEY);
        }
        XFREE(certDer, nullptr, DYNAMIC_TYPE_PKCS);
        wc_FreeCertList(caList, nullptr);
    });
    if (result != 0) {
        qCWarning(lcTlsBackendWolfSSL, "Unable to parse PKCS#12 structure: %ls",
                  qUtf16Printable(QTlsBackendWolfSSL::errorString(result)));
        return false;
    }
    if (!keyDer || !keyDerSize) {
        qCWarning(lcTlsBackendWolfSSL,
                  "No private key in the PKCS#12 structure");
        return false;
    }
    if (!certDer || !certDerSize) {
        qCWarning(lcTlsBackendWolfSSL,
                  "No certificate in the PKCS#12 structure");
        return false;
    }

    /* PrivateKeyInfo ::= SEQUENCE { version, AlgorithmIdentifier, OCTET STRING
     * } */
    QByteArray pkcs8(reinterpret_cast<const char *>(keyDer),
                     qsizetype(keyDerSize));
    const auto wipe = qScopeGuard(
            [&pkcs8] { wc_ForceZero(pkcs8.data(), size_t(pkcs8.size())); });
    QAsn1Element element;
    QList<QAsn1Element> items;
    if (element.read(pkcs8) && element.type() == QAsn1Element::SequenceType)
        items = element.toList();
    QList<QAsn1Element> algorithmItems;
    if (items.size() >= 3 && items.at(1).type() == QAsn1Element::SequenceType)
        algorithmItems = items.at(1).toList();
    if (algorithmItems.isEmpty()
        || items.at(2).type() != QAsn1Element::OctetStringType) {
        qCWarning(lcTlsBackendWolfSSL, "Unable to convert private key");
        return false;
    }

    QSslKey privateKey;
    const QByteArray algorithm = algorithmItems.constFirst().toObjectId();
    if (algorithm == RSA_ENCRYPTION_OID) {
        /* An RSAPrivateKey, as the OpenSSL backend returns it. */
        privateKey = QSslKey(items.at(2).value(), QSsl::Rsa, QSsl::Der,
                             QSsl::PrivateKey);
    } else if (algorithm == EC_ENCRYPTION_OID) {
        privateKey = QSslKey(pkcs8, QSsl::Ec, QSsl::Der, QSsl::PrivateKey);
    } else if (algorithm == DSA_ENCRYPTION_OID) {
        privateKey = QSslKey(pkcs8, QSsl::Dsa, QSsl::Der, QSsl::PrivateKey);
    } else if (algorithm == DH_ENCRYPTION_OID) {
        privateKey = QSslKey(pkcs8, QSsl::Dh, QSsl::Der, QSsl::PrivateKey);
    }
    if (privateKey.isNull()) {
        qCWarning(lcTlsBackendWolfSSL, "Unable to convert private key");
        return false;
    }

    const QSslCertificate certificate(
            QByteArray(reinterpret_cast<const char *>(certDer),
                       qsizetype(certDerSize)),
            QSsl::Der);
    if (certificate.isNull()) {
        qCWarning(lcTlsBackendWolfSSL,
                  "Unable to read the certificate in the PKCS#12 structure");
        return false;
    }

    QList<QSslCertificate> cas;
    for (const WC_DerCertList *entry = caList; entry; entry = entry->next) {
        const QSslCertificate ca(
                QByteArray(reinterpret_cast<const char *>(entry->buffer),
                           qsizetype(entry->bufferSz)),
                QSsl::Der);
        if (!ca.isNull())
            cas << ca;
    }

    *key = privateKey;
    *cert = certificate;
    if (caCertificates)
        *caCertificates = cas;
    return true;
#else
    Q_UNUSED(caCertificates);
    Q_UNUSED(passPhrase);
    qCWarning(lcTlsBackendWolfSSL, "wolfSSL was built without PKCS#12 support");
    return false;
#endif /* HAVE_PKCS12 */
}

} /* namespace QTlsPrivate */

QT_END_NAMESPACE
