# Copyright (C) 2026 The Qt Company Ltd.
# SPDX-License-Identifier: BSD-3-Clause

qt_internal_add_plugin(QTlsBackendWolfSSLPlugin
    OUTPUT_NAME qwolfsslbackend
    CLASS_NAME QTlsBackendWolfSSL
    PLUGIN_TYPE tls
    SOURCES
        ../shared/qx509_base_p.h
        ../shared/qx509_base.cpp
        ../shared/qx509_generic_p.h
        ../shared/qx509_generic.cpp
        ../shared/qasn1element_p.h
        ../shared/qasn1element.cpp
        qtlsbackend_wolfssl.cpp qtlsbackend_wolfssl_p.h
    LIBRARIES
        Qt::NetworkPrivate
        WrapWolfSSL::WrapWolfSSL
    DEFINES
        QT_NO_CAST_FROM_ASCII
)
