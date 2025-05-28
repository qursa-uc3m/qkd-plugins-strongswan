AM_CPPFLAGS = \
    -I$(strongswan_headers) \
    -include /usr/lib/ipsec/include/config.h \
    $(OPENSSL_CFLAGS) \
    $(QKD_ETSI_API_CFLAGS) \
    $(QKD_KEM_PROVIDER_CFLAGS)

# Define whether the QKD connection is server or client initiated
if QKD_SERVER_INITIATED
AM_CPPFLAGS += -DQKD_SERVER_INITIATED=1
else
AM_CPPFLAGS += -DQKD_CLIENT_INITIATED=1
endif

AM_CFLAGS = \
    -Wall -Wno-format -Wno-format-security -Wno-pointer-sign -Wno-missing-field-initializers

# Build the plugin
plugin_LTLIBRARIES = libstrongswan-qkd-kem.la

libstrongswan_qkd_kem_la_SOURCES = \
    qkd_kem.h qkd_kem.c \
    qkd_kem_plugin.h qkd_kem_plugin.c

libstrongswan_qkd_kem_la_LDFLAGS = -module -avoid-version
libstrongswan_qkd_kem_la_LIBADD = \
    $(QKD_ETSI_API_LIBS) \
    $(QKD_KEM_PROVIDER_LIBS) \
    $(OPENSSL_LIBS)