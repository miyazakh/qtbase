/*
 * Copyright (C) 2026 The Qt Company Ltd.
 * SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
 */

#include "qtlskey_wolfssl_p.h"
#include "qtlsbackend_wolfssl_p.h"

QT_BEGIN_NAMESPACE

namespace QTlsPrivate {

/* TLSTODO (Phase 3): implement AES-CBC (and DES-EDE3-CBC where wolfCrypt
 * provides it) with wolfCrypt, so that encrypted private keys can be read
 * and written. Until then only unencrypted keys work. */

QByteArray TlsKeyWolfSSL::decrypt(Cipher cipher, const QByteArray &data,
                                  const QByteArray &key,
                                  const QByteArray &iv) const
{
    Q_UNUSED(cipher);
    Q_UNUSED(data);
    Q_UNUSED(key);
    Q_UNUSED(iv);
    qCWarning(lcTlsBackendWolfSSL,
              "Encrypted private keys are not supported yet");
    return {};
}

QByteArray TlsKeyWolfSSL::encrypt(Cipher cipher, const QByteArray &data,
                                  const QByteArray &key,
                                  const QByteArray &iv) const
{
    Q_UNUSED(cipher);
    Q_UNUSED(data);
    Q_UNUSED(key);
    Q_UNUSED(iv);
    qCWarning(lcTlsBackendWolfSSL,
              "Encrypted private keys are not supported yet");
    return {};
}

} /* namespace QTlsPrivate */

QT_END_NAMESPACE
