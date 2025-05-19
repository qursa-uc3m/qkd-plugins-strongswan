AM_CPPFLAGS = \
	-I$(strongswan_headers) \
	-include /usr/lib/ipsec/include/config.h \
	$(QKD_ETSI_API_CFLAGS)

# Define which ETSI API version to use based on configure.ac settings
if ETSI_004_API
AM_CPPFLAGS += -DETSI_004_API=1
else
AM_CPPFLAGS += -DETSI_014_API=1
endif

AM_CFLAGS = \
	-Wall -Wno-format -Wno-format-security -Wno-pointer-sign -Wno-missing-field-initializers

noinst_LTLIBRARIES = libqkd-etsi-adapter.la

libqkd_etsi_adapter_la_SOURCES = \
	qkd_etsi_adapter.h qkd_etsi_adapter.c \
	qkd_kex.h qkd_kex.c

libqkd_etsi_adapter_la_LIBADD = $(QKD_ETSI_API_LIBS) -luuid

# Build the plugin
plugin_LTLIBRARIES = libstrongswan-qkd.la

libstrongswan_qkd_la_SOURCES = \
	qkd_plugin.h qkd_plugin.c

libstrongswan_qkd_la_LDFLAGS = -module -avoid-version
libstrongswan_qkd_la_LIBADD = libqkd-etsi-adapter.la