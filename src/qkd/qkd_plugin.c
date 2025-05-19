/*
 * Copyright (C) 2024 Javier Blanco-Romero @fj-blanco (UC3M, QURSA project)
 */

/*
 * qkd_plugin.c
 */

#include "qkd_plugin.h"
#include "qkd_kex.h"

#include <crypto/proposal/proposal_keywords.h>
#include <library.h>

typedef struct private_qkd_plugin_t private_qkd_plugin_t;

struct private_qkd_plugin_t {
    qkd_plugin_t public;
};

static void register_algorithm_names(void) {
    proposal_keywords_t *proposal = lib->proposal;

    /* Register QKD key exchange method */
    proposal->register_token(proposal, "qkd", KEY_EXCHANGE_METHOD, KE_QKD, 0);

    DBG1(DBG_LIB, "QKD_plugin: registered QKD algorithm names");
}

METHOD(plugin_t, get_name, char *, private_qkd_plugin_t *this) { return "qkd"; }

METHOD(plugin_t, get_features, int, private_qkd_plugin_t *this,
       plugin_feature_t *features[]) {
    static plugin_feature_t f[] = {
        /* QKD-based key exchange method */
        PLUGIN_REGISTER(KE, qkd_kex_create),
        PLUGIN_PROVIDE(KE, KE_QKD),
    };

    *features = f;
    DBG1(DBG_LIB, "QKD_plugin: QKD plugin providing %d features", countof(f));
    return countof(f);
}

METHOD(plugin_t, destroy, void, private_qkd_plugin_t *this) {
    DBG2(DBG_LIB, "QKD_plugin: destroying QKD plugin");
    free(this);
}

plugin_t *qkd_plugin_create(void) {
    private_qkd_plugin_t *this;

    DBG1(DBG_LIB, "QKD_plugin: plugin_create called");

    INIT(this,
         .public = {
             .plugin =
                 {
                     .get_name = _get_name,
                     .get_features = _get_features,
                     .destroy = _destroy,
                 },
         }, );

    if (!this) {
        DBG1(DBG_LIB, "QKD_plugin: INIT failed");
        return NULL;
    }

    register_algorithm_names();

    DBG1(DBG_LIB, "QKD_plugin: plugin initialized successfully");
    return &this->public.plugin;
}