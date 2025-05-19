#
# Copyright (C) 2024-2025 Javier Blanco-Romero @fj-blanco (UC3M, QURSA project)
#

AC_INIT([qkd-plugins-strongswan], [1.0.0])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

# Add archiver support for libtool libraries
AM_PROG_AR

# Programs
AC_PROG_CC
AC_PROG_INSTALL
LT_INIT([disable-static])

# Get strongSwan headers location
AC_ARG_WITH([strongswan-headers],
    [AS_HELP_STRING([--with-strongswan-headers=DIR], [path to strongSwan headers])],
    [strongswan_headers="$withval"],
    [strongswan_headers="/usr/include/strongswan"])
AC_SUBST([strongswan_headers])

# Check for necessary strongSwan headers
AC_CHECK_FILE([$strongswan_headers/library.h],
    [],
    [AC_MSG_ERROR([strongSwan headers not found at $strongswan_headers. Please install strongSwan development headers or specify the correct path with --with-strongswan-headers.])])

# Set plugin installation directory
AC_ARG_WITH([plugin-dir],
    [AS_HELP_STRING([--with-plugin-dir=DIR], [where to install the plugins])],
    [plugindir="$withval"],
    [plugindir="/usr/lib/ipsec/plugins"])
AC_SUBST([plugindir])

# Enable/disable plugins
AC_ARG_ENABLE([qkd],
    [AS_HELP_STRING([--enable-qkd], [enable QKD plugin [default=yes]])],
    [enable_qkd=$enableval],
    [enable_qkd=yes])
AM_CONDITIONAL([ENABLE_QKD], [test "x$enable_qkd" = "xyes"])

AC_ARG_ENABLE([qkd-kem],
    [AS_HELP_STRING([--enable-qkd-kem], [enable QKD-KEM plugin [default=yes]])],
    [enable_qkd_kem=$enableval],
    [enable_qkd_kem=yes])
AM_CONDITIONAL([ENABLE_QKD_KEM], [test "x$enable_qkd_kem" = "xyes"])

# Check for OpenSSL - required by qkd-kem
PKG_CHECK_MODULES([openssl], [openssl >= 1.1.0],
    [
        AC_SUBST(OPENSSL_CFLAGS, $openssl_CFLAGS)
        AC_SUBST(OPENSSL_LIBS, $openssl_LIBS)
        openssl=true
    ],
    [
        # Try manual detection if pkg-config fails
        AC_CHECK_LIB([crypto], [EVP_CIPHER_CTX_new],
            [
                AC_SUBST(OPENSSL_LIBS, "-lcrypto")
                openssl=true
            ],
            [
                if test "x$enable_qkd_kem" = "xyes"; then
                    AC_MSG_ERROR([OpenSSL library not found, required for QKD-KEM plugin])
                else
                    AC_MSG_WARN([OpenSSL library not found, QKD-KEM plugin will not work if enabled])
                fi
            ]
        )
        AC_CHECK_HEADER([openssl/evp.h],
            [],
            [
                if test "x$enable_qkd_kem" = "xyes"; then
                    AC_MSG_ERROR([OpenSSL headers not found, required for QKD-KEM plugin])
                else
                    AC_MSG_WARN([OpenSSL headers not found, QKD-KEM plugin will not work if enabled])
                fi
            ]
        )
    ]
)

# QKD ETSI API configuration
AC_ARG_WITH([qkd-etsi-api],
    [AS_HELP_STRING([--with-qkd-etsi-api=DIR], [path to QKD ETSI API])],
    [qkd_etsi_api="$withval"],
    [qkd_etsi_api="/usr/local"])
AC_SUBST([qkd_etsi_api])

# Check for ETSI API version
AC_ARG_WITH([etsi-api-version],
    [AS_HELP_STRING([--with-etsi-api-version=004|014], [ETSI API version to use [default=014]])],
    [etsi_api_version="$withval"],
    [etsi_api_version="014"])

# Add appropriate defines based on ETSI API version
if test "x$etsi_api_version" = "x004"; then
    AC_DEFINE([ETSI_004_API], [1], [Using ETSI 004 API])
else
    AC_DEFINE([ETSI_014_API], [1], [Using ETSI 014 API])
fi

AM_CONDITIONAL([ETSI_004_API], [test "x$etsi_api_version" = "x004"])

# Set QKD ETSI API flags
QKD_ETSI_API_CFLAGS="-I${qkd_etsi_api}/include -I${qkd_etsi_api}/include/qkd-etsi-api-c-wrapper"
QKD_ETSI_API_LIBS="-L${qkd_etsi_api}/lib -lqkd-etsi-api-c-wrapper"
AC_SUBST([QKD_ETSI_API_CFLAGS])
AC_SUBST([QKD_ETSI_API_LIBS])

# Check for QKD ETSI API
AC_MSG_CHECKING([for QKD ETSI API])
saved_CFLAGS=$CFLAGS
saved_LIBS=$LIBS
CFLAGS="$CFLAGS $QKD_ETSI_API_CFLAGS"
LIBS="$LIBS $QKD_ETSI_API_LIBS"
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM(
        [[#include <qkd-etsi-api-c-wrapper/QKD_ETSI_API_C_Wrapper.h>]],
        [[void *api = NULL; QKD_open(&api);]])],
    [AC_MSG_RESULT([yes])
     AC_DEFINE([HAVE_QKD_ETSI_API], [1], [Define if QKD ETSI API is available])],
    [AC_MSG_RESULT([no])
     if test "x$enable_qkd" = "xyes"; then
         AC_MSG_WARN([QKD ETSI API not found. QKD plugin may not work correctly.])
     fi]
)
CFLAGS=$saved_CFLAGS
LIBS=$saved_LIBS

# QKD-KEM Provider configuration
AC_ARG_WITH([qkd-kem-provider],
    [AS_HELP_STRING([--with-qkd-kem-provider=DIR], [path to QKD-KEM Provider])],
    [qkd_kem_provider="$withval"],
    [qkd_kem_provider="/usr/local/lib/ossl-modules"])
AC_SUBST([qkd_kem_provider])

# Set QKD-KEM Provider flags
QKD_KEM_PROVIDER_CFLAGS="-I${qkd_kem_provider}/include"
QKD_KEM_PROVIDER_LIBS="${qkd_kem_provider}/qkdkemprovider.so"
AC_SUBST([QKD_KEM_PROVIDER_CFLAGS])
AC_SUBST([QKD_KEM_PROVIDER_LIBS])

# Check for QKD-KEM Provider
AC_MSG_CHECKING([for QKD-KEM Provider])
saved_CFLAGS=$CFLAGS
saved_LIBS=$LIBS
CFLAGS="$CFLAGS $QKD_KEM_PROVIDER_CFLAGS"
LIBS="$LIBS $QKD_KEM_PROVIDER_LIBS"
AC_LINK_IFELSE(
    [AC_LANG_PROGRAM(
        [[#include <qkd-kem-provider/QKD_KEM_Provider.h>]],
        [[void *provider = NULL; QKD_KEM_open(&provider);]])],
    [AC_MSG_RESULT([yes])
     AC_DEFINE([HAVE_QKD_KEM_PROVIDER], [1], [Define if QKD-KEM Provider is available])],
    [AC_MSG_RESULT([no])
     if test "x$enable_qkd_kem" = "xyes"; then
         AC_MSG_WARN([QKD-KEM Provider not found. QKD-KEM plugin may not work correctly.])
     fi]
)
CFLAGS=$saved_CFLAGS
LIBS=$saved_LIBS

# Define directories to process
AC_CONFIG_FILES([
    Makefile
    src/Makefile
    src/qkd/Makefile
    src/qkd-kem/Makefile
])

AC_OUTPUT

# Display configuration
echo
echo "strongSwan QKD plugins configuration:"
echo "------------------------------------"
echo "strongSwan headers:    ${strongswan_headers}"
echo "Plugin directory:      ${plugindir}"
if test "x$enable_qkd" = "xyes"; then
    echo "QKD plugin:            enabled"
    echo "QKD ETSI API path:     ${qkd_etsi_api}"
    echo "ETSI API version:      ${etsi_api_version}"
else
    echo "QKD plugin:            disabled"
fi
if test "x$enable_qkd_kem" = "xyes"; then
    echo "QKD-KEM plugin:        enabled"
    echo "QKD-KEM Provider path: ${qkd_kem_provider}"
else
    echo "QKD-KEM plugin:        disabled"
fi