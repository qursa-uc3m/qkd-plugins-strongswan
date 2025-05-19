/*
 * Copyright (C) 2024 Javier Blanco-Romero @fj-blanco (UC3M, QURSA project)
 */

/*
 * qkd_kem_plugin.h
 */

/**
 * @defgroup qkd_kem_p qkd_kem
 * @ingroup plugins
 *
 * @defgroup qkd_kem_plugin qkd_kem_plugin
 * @{ @ingroup qkd_kem_p
 */

#ifndef QKD_KEM_PLUGIN_H_
#define QKD_KEM_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct qkd_kem_plugin_t qkd_kem_plugin_t;

struct qkd_kem_plugin_t {
    plugin_t plugin;
};

#endif /** QKD_KEM_PLUGIN_H_ @}*/