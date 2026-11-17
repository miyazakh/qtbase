# Copyright (C) 2026 The Qt Company Ltd.
# SPDX-License-Identifier: BSD-3-Clause

#.rst:
# FindWrapWolfSSL
# ---------------
#
# Try to locate the wolfSSL library.
#
# wolfSSL installs a CMake package (wolfssl::wolfssl) both from its own CMake
# build and, since 5.x, from its autotools build. Fall back to pkg-config for
# installations that only ship wolfssl.pc.
#
# If found, this will define the following variables:
#
# ``WrapWolfSSL_FOUND``
#     True if the wolfSSL library is available
# ``WrapWolfSSL_VERSION``
#     The wolfSSL version, if known
#
# and the following imported target:
#
# ``WrapWolfSSL::WrapWolfSSL``
#     The wolfSSL library

# We can't create the same interface imported target multiple times, CMake
# will complain if we do that. This can happen if the find_package call is
# done in multiple different subdirectories.
if(TARGET WrapWolfSSL::WrapWolfSSL)
    set(WrapWolfSSL_FOUND ON)
    return()
endif()

set(WrapWolfSSL_FOUND OFF)

find_package(wolfssl CONFIG QUIET)

include(FindPackageHandleStandardArgs)

if(TARGET wolfssl::wolfssl)
    set(WrapWolfSSL_VERSION "${wolfssl_VERSION}")
    find_package_handle_standard_args(WrapWolfSSL
                                      REQUIRED_VARS wolfssl_DIR
                                      VERSION_VAR WrapWolfSSL_VERSION)
    if(WrapWolfSSL_FOUND)
        add_library(WrapWolfSSL::WrapWolfSSL INTERFACE IMPORTED)
        target_link_libraries(WrapWolfSSL::WrapWolfSSL
            INTERFACE wolfssl::wolfssl)
    endif()
else()
    get_cmake_property(__packages_not_found PACKAGES_NOT_FOUND)
    if(__packages_not_found)
        list(REMOVE_ITEM __packages_not_found wolfssl)
        set_property(GLOBAL PROPERTY
            PACKAGES_NOT_FOUND "${__packages_not_found}")
    endif()
    unset(__packages_not_found)

    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(PC_WOLFSSL QUIET IMPORTED_TARGET "wolfssl")
    endif()

    if(TARGET PkgConfig::PC_WOLFSSL)
        set(WrapWolfSSL_VERSION "${PC_WOLFSSL_VERSION}")
        find_package_handle_standard_args(WrapWolfSSL
                                          REQUIRED_VARS PC_WOLFSSL_LIBRARIES
                                          VERSION_VAR WrapWolfSSL_VERSION)
        if(WrapWolfSSL_FOUND)
            add_library(WrapWolfSSL::WrapWolfSSL INTERFACE IMPORTED)
            target_link_libraries(WrapWolfSSL::WrapWolfSSL
                INTERFACE PkgConfig::PC_WOLFSSL)
        endif()
    else()
        find_package_handle_standard_args(WrapWolfSSL
                                          REQUIRED_VARS PC_WOLFSSL_LIBRARIES)
    endif()
endif()

include(FeatureSummary)
set_package_properties(WrapWolfSSL PROPERTIES
    URL "https://www.wolfssl.com"
    DESCRIPTION "wolfSSL embedded TLS library")
