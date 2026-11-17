# Copyright (C) 2026 The Qt Company Ltd.
# SPDX-License-Identifier: BSD-3-Clause

qt_internal_add_plugin(QTlsBackendWolfSSLPlugin
    OUTPUT_NAME qwolfsslbackend
    CLASS_NAME QTlsBackendWolfSSL
    PLUGIN_TYPE tls
    SOURCES
        ../shared/qtlskey_base_p.h
        ../shared/qtlskey_base.cpp
        ../shared/qtlskey_generic_p.h
        ../shared/qtlskey_generic.cpp
        ../shared/qx509_base_p.h
        ../shared/qx509_base.cpp
        ../shared/qx509_generic_p.h
        ../shared/qx509_generic.cpp
        ../shared/qasn1element_p.h
        ../shared/qasn1element.cpp
        qsslcontext_wolfssl.cpp qsslcontext_wolfssl_p.h
        qtls_wolfssl.cpp qtls_wolfssl_p.h
        qtlsbackend_wolfssl.cpp qtlsbackend_wolfssl_p.h
        qtlskey_wolfssl.cpp qtlskey_wolfssl_p.h
        qx509_wolfssl.cpp qx509_wolfssl_p.h
    LIBRARIES
        Qt::NetworkPrivate
        WrapWolfSSL::WrapWolfSSL
    DEFINES
        QT_NO_CAST_FROM_ASCII
)

qt_internal_extend_target(QTlsBackendWolfSSLPlugin CONDITION APPLE
    SOURCES
        ../shared/qsslsocket_mac_shared.cpp
    LIBRARIES
        ${FWCoreFoundation}
        ${FWSecurity}
)

qt_internal_extend_target(QTlsBackendWolfSSLPlugin CONDITION WIN32
    SOURCES
        ../shared/qwincrypt_p.h
    LIBRARIES
        crypt32
)
