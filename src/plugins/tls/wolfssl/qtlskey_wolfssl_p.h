/*
 * Copyright (C) 2026 The Qt Company Ltd.
 * SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
 * Qt-Security score:significant reason:default
 */

#ifndef QTLSKEY_WOLFSSL_P_H
#define QTLSKEY_WOLFSSL_P_H

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

#include "../shared/qtlskey_generic_p.h"

#include <QtCore/qbytearray.h>

QT_BEGIN_NAMESPACE

namespace QTlsPrivate {

/* Keys are parsed by Qt's generic ASN.1 code; the backend only supplies the
 * symmetric ciphers used for encrypted PEM/PKCS#8 keys. */
class TlsKeyWolfSSL final : public TlsKeyGeneric
{
public:
    using TlsKeyGeneric::TlsKeyGeneric;

    QByteArray decrypt(Cipher cipher, const QByteArray &data,
                       const QByteArray &key,
                       const QByteArray &iv) const override;
    QByteArray encrypt(Cipher cipher, const QByteArray &data,
                       const QByteArray &key,
                       const QByteArray &iv) const override;
};

} /* namespace QTlsPrivate */

QT_END_NAMESPACE

#endif /* QTLSKEY_WOLFSSL_P_H */
