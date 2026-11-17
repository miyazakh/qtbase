/*
 * Copyright (C) 2026 The Qt Company Ltd.
 * SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
 */

#include "qtlskey_wolfssl_p.h"
#include "qtlsbackend_wolfssl_p.h"

#include <QtCore/qscopeguard.h>

/* wolfssl/options.h must come first, see qtlsbackend_wolfssl.cpp. */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/des3.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/rc2.h>
#include <wolfssl/wolfcrypt/types.h>

QT_BEGIN_NAMESPACE

namespace QTlsPrivate {

namespace {

const byte *bytes(const QByteArray &array)
{
    return reinterpret_cast<const byte *>(array.constData());
}

int blockSize(Cipher cipher)
{
    switch (cipher) {
    case Cipher::DesCbc:
    case Cipher::DesEde3Cbc:
    case Cipher::Rc2Cbc:
        return 8;
    case Cipher::Aes128Cbc:
    case Cipher::Aes192Cbc:
    case Cipher::Aes256Cbc:
        return 16;
    }
    Q_UNREACHABLE_RETURN(16);
}

int keySize(Cipher cipher)
{
    switch (cipher) {
    case Cipher::DesCbc:
        return 8;
    case Cipher::DesEde3Cbc:
        return 24;
    case Cipher::Rc2Cbc:
        return 0; /* variable */
    case Cipher::Aes128Cbc:
        return 16;
    case Cipher::Aes192Cbc:
        return 24;
    case Cipher::Aes256Cbc:
        return 32;
    }
    Q_UNREACHABLE_RETURN(0);
}

/* Runs the block cipher in CBC mode over 'in' (a multiple of the block
 * size) and writes the result to 'out', which has the same size. */
bool cbc(Cipher cipher, const QByteArray &key, const QByteArray &iv,
         bool encrypt, const QByteArray &in, QByteArray *out)
{
    const auto size = word32(in.size());
    auto *output = reinterpret_cast<byte *>(out->data());
    int result = NOT_COMPILED_IN;

    switch (cipher) {
    case Cipher::DesCbc:
#ifndef NO_DES3
    {
        Des des;
        result = wc_Des_SetKey(&des, bytes(key), bytes(iv),
                               encrypt ? DES_ENCRYPTION : DES_DECRYPTION);
        if (result == 0) {
            result = encrypt ? wc_Des_CbcEncrypt(&des, output, bytes(in), size)
                             : wc_Des_CbcDecrypt(&des, output, bytes(in), size);
        }
        wc_ForceZero(&des, sizeof des);
    }
#endif
        break;
    case Cipher::DesEde3Cbc:
#ifndef NO_DES3
    {
        Des3 des3;
        result = wc_Des3Init(&des3, nullptr, INVALID_DEVID);
        if (result != 0)
            break;
        result = wc_Des3_SetKey(&des3, bytes(key), bytes(iv),
                                encrypt ? DES_ENCRYPTION : DES_DECRYPTION);
        if (result == 0) {
            result = encrypt
                    ? wc_Des3_CbcEncrypt(&des3, output, bytes(in), size)
                    : wc_Des3_CbcDecrypt(&des3, output, bytes(in), size);
        }
        wc_Des3Free(&des3);
    }
#endif
        break;
    case Cipher::Rc2Cbc:
#ifdef WC_RC2
    {
        /* As with OpenSSL's EVP_CTRL_SET_RC2_KEY_BITS: the effective key
         * length is the length of the key. */
        Rc2 rc2;
        result = wc_Rc2SetKey(&rc2, bytes(key), word32(key.size()), bytes(iv),
                              word32(key.size() * 8));
        if (result == 0) {
            result = encrypt ? wc_Rc2CbcEncrypt(&rc2, output, bytes(in), size)
                             : wc_Rc2CbcDecrypt(&rc2, output, bytes(in), size);
        }
        wc_Rc2Free(&rc2);
    }
#endif
        break;
    case Cipher::Aes128Cbc:
    case Cipher::Aes192Cbc:
    case Cipher::Aes256Cbc:
#if !defined(NO_AES) && defined(HAVE_AES_CBC)
    {
        Aes aes;
        result = wc_AesInit(&aes, nullptr, INVALID_DEVID);
        if (result != 0)
            break;
#ifdef HAVE_AES_DECRYPT
        const int direction = encrypt ? AES_ENCRYPTION : AES_DECRYPTION;
#else
        if (!encrypt) {
            wc_AesFree(&aes);
            result = NOT_COMPILED_IN;
            break;
        }
        const int direction = AES_ENCRYPTION;
#endif
        result = wc_AesSetKey(&aes, bytes(key), word32(key.size()), bytes(iv),
                              direction);
        if (result == 0) {
#ifdef HAVE_AES_DECRYPT
            result = encrypt ? wc_AesCbcEncrypt(&aes, output, bytes(in), size)
                             : wc_AesCbcDecrypt(&aes, output, bytes(in), size);
#else
            result = wc_AesCbcEncrypt(&aes, output, bytes(in), size);
#endif
        }
        wc_AesFree(&aes);
    }
#endif
        break;
    }

    if (result == NOT_COMPILED_IN) {
        qCWarning(lcTlsBackendWolfSSL,
                  "This cipher for encrypted keys is not compiled into "
                  "wolfCrypt");
    } else if (result != 0) {
        qCWarning(lcTlsBackendWolfSSL, "%s failed: %ls",
                  encrypt ? "Encryption" : "Decryption",
                  qUtf16Printable(QTlsBackendWolfSSL::errorString(result)));
    }
    return result == 0;
}

/* Same contract as the other backends: CBC with PKCS#7 padding, which
 * encrypt() adds and decrypt() removes. An empty result means failure. */
QByteArray doCrypt(Cipher cipher, const QByteArray &data, const QByteArray &key,
                   const QByteArray &iv, bool encrypt)
{
    const int block = blockSize(cipher);
    const int expectedKeySize = keySize(cipher);
    if (iv.size() != block || key.isEmpty()
        || (expectedKeySize && key.size() != expectedKeySize)) {
        return {};
    }

    QByteArray input = data;
    if (encrypt) {
        const int padding = block - int(data.size() % block);
        input.append(padding, char(padding));
    } else if (data.isEmpty() || data.size() % block) {
        return {};
    }

    QByteArray output(input.size(), Qt::Uninitialized);
    const bool ok = cbc(cipher, key, iv, encrypt, input, &output);
    /* The plain text may be a private key. */
    const auto wipe = qScopeGuard([&] {
        wc_ForceZero(encrypt ? input.data() : output.data(),
                  word32(encrypt ? input.size() : output.size()));
    });
    if (!ok)
        return {};
    if (encrypt)
        return output;

    const int padding = static_cast<unsigned char>(output.back());
    if (padding < 1 || padding > block)
        return {};
    for (qsizetype i = output.size() - padding; i < output.size(); ++i) {
        if (static_cast<unsigned char>(output.at(i)) != padding)
            return {};
    }
    return output.first(output.size() - padding);
}

} /* unnamed namespace */

void TlsKeyWolfSSL::decodeDer(KeyType type, KeyAlgorithm algorithm,
                              const QByteArray &der,
                              const QByteArray &passPhrase, bool deepClear)
{
#if !defined(NO_PWDBASED) && defined(HAVE_PKCS8)
    /* isEncryptedPkcs8() is TlsKeyBase's. */
    if (type == QSsl::PrivateKey && isEncryptedPkcs8(der)) {
        /* wc_DecryptPKCS8Key() decrypts in place and returns the length of
         * the PrivateKeyInfo. */
        QByteArray decrypted = der;
        const auto wipe = qScopeGuard([&decrypted] {
            wc_ForceZero(decrypted.data(), size_t(decrypted.size()));
        });
        const int length = wc_DecryptPKCS8Key(
                reinterpret_cast<byte *>(decrypted.data()),
                word32(decrypted.size()), passPhrase.constData(),
                int(passPhrase.size()));
        if (length > 0) {
            TlsKeyGeneric::decodeDer(type, algorithm, decrypted.first(length),
                                     {}, deepClear);
            return;
        }
        /* Wrong pass phrase or a scheme wolfCrypt does not know; let the
         * generic code try. */
    }
#endif
    TlsKeyGeneric::decodeDer(type, algorithm, der, passPhrase, deepClear);
}

QByteArray TlsKeyWolfSSL::decrypt(Cipher cipher, const QByteArray &data,
                                  const QByteArray &key,
                                  const QByteArray &iv) const
{
    return doCrypt(cipher, data, key, iv, false);
}

QByteArray TlsKeyWolfSSL::encrypt(Cipher cipher, const QByteArray &data,
                                  const QByteArray &key,
                                  const QByteArray &iv) const
{
    return doCrypt(cipher, data, key, iv, true);
}

} /* namespace QTlsPrivate */

QT_END_NAMESPACE
