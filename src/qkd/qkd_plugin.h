/*
 * Copyright (C) 2024 Javier Blanco-Romero @fj-blanco (UC3M, QURSA project)
 */

/**
 * @defgroup qkd_p qkd
 * @ingroup plugins
 *
 * @defgroup qkd_plugin qkd_plugin
 * @{ @ingroup qkd_p
 */

#ifndef QKD_PLUGIN_H_
#define QKD_PLUGIN_H_

#include <plugins/plugin.h>

enum qkd_key_exchange_method_t {
    KE_QKD = 65516,
};

typedef struct qkd_plugin_t qkd_plugin_t;

struct qkd_plugin_t {
    plugin_t plugin;
};

#endif /** QKD_PLUGIN_H_ @}*/