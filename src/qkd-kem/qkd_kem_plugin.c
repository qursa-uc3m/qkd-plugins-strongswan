/*
 * Copyright (C) 2024 Javier Blanco-Romero @fj-blanco (UC3M, QURSA project)
 */

/*
 * qkd_kem_plugin.c
 */

#include "qkd_kem_plugin.h"
#include "qkd_kem.h"

#include <crypto/proposal/proposal_keywords.h>
#include <library.h>

typedef struct private_qkd_kem_plugin_t private_qkd_kem_plugin_t;

struct private_qkd_kem_plugin_t {
    qkd_kem_plugin_t public;
};

static void register_algorithm_names(void) {
    proposal_keywords_t *proposal = lib->proposal;

    /* Register QKD-KEM key exchange methods */
    proposal->register_token(proposal, "qkd_frodoa1", KEY_EXCHANGE_METHOD,
                             KE_QKD_FRODO_AES_L1, 0);
    proposal->register_token(proposal, "qkd_frodos1", KEY_EXCHANGE_METHOD,
                             KE_QKD_FRODO_SHAKE_L1, 0);
    proposal->register_token(proposal, "qkd_frodoa3", KEY_EXCHANGE_METHOD,
                             KE_QKD_FRODO_AES_L3, 0);
    proposal->register_token(proposal, "qkd_frodos3", KEY_EXCHANGE_METHOD,
                             KE_QKD_FRODO_SHAKE_L3, 0);
    proposal->register_token(proposal, "qkd_frodoa5", KEY_EXCHANGE_METHOD,
                             KE_QKD_FRODO_AES_L5, 0);
    proposal->register_token(proposal, "qkd_frodos5", KEY_EXCHANGE_METHOD,
                             KE_QKD_FRODO_SHAKE_L5, 0);
    proposal->register_token(proposal, "qkd_kyber1", KEY_EXCHANGE_METHOD,
                             KE_QKD_KYBER_L1, 0);
    proposal->register_token(proposal, "qkd_kyber3", KEY_EXCHANGE_METHOD,
                             KE_QKD_KYBER_L3, 0);
    proposal->register_token(proposal, "qkd_kyber5", KEY_EXCHANGE_METHOD,
                             KE_QKD_KYBER_L5, 0);
    proposal->register_token(proposal, "qkd_mlkem1", KEY_EXCHANGE_METHOD,
                             KE_QKD_MLKEM_L1, 0);
    proposal->register_token(proposal, "qkd_mlkem3", KEY_EXCHANGE_METHOD,
                             KE_QKD_MLKEM_L3, 0);
    proposal->register_token(proposal, "qkd_mlkem5", KEY_EXCHANGE_METHOD,
                             KE_QKD_MLKEM_L5, 0);
    proposal->register_token(proposal, "qkd_bike1", KEY_EXCHANGE_METHOD,
                             KE_QKD_BIKE_L1, 0);
    proposal->register_token(proposal, "qkd_bike3", KEY_EXCHANGE_METHOD,
                             KE_QKD_BIKE_L3, 0);
    proposal->register_token(proposal, "qkd_bike5", KEY_EXCHANGE_METHOD,
                             KE_QKD_BIKE_L5, 0);
    proposal->register_token(proposal, "qkd_hqc1", KEY_EXCHANGE_METHOD,
                             KE_QKD_HQC_L1, 0);
    proposal->register_token(proposal, "qkd_hqc3", KEY_EXCHANGE_METHOD,
                             KE_QKD_HQC_L3, 0);
    proposal->register_token(proposal, "qkd_hqc5", KEY_EXCHANGE_METHOD,
                             KE_QKD_HQC_L5, 0);

    DBG1(DBG_LIB, "QKD_KEM_plugin: registered QKD-KEM algorithm names");
}

METHOD(plugin_t, get_name, char *, private_qkd_kem_plugin_t *this) {
    return "qkd-kem";
}

METHOD(plugin_t, get_features, int, private_qkd_kem_plugin_t *this,
       plugin_feature_t *features[]) {
    static plugin_feature_t f[] = {
        /* QKD-KEM key exchange methods */
        PLUGIN_REGISTER(KE, qkd_kem_create),
        PLUGIN_PROVIDE(KE, KE_QKD_FRODO_AES_L1),
        PLUGIN_PROVIDE(KE, KE_QKD_FRODO_SHAKE_L1),
        PLUGIN_PROVIDE(KE, KE_QKD_FRODO_AES_L3),
        PLUGIN_PROVIDE(KE, KE_QKD_FRODO_SHAKE_L3),
        PLUGIN_PROVIDE(KE, KE_QKD_FRODO_AES_L5),
        PLUGIN_PROVIDE(KE, KE_QKD_FRODO_SHAKE_L5),
        PLUGIN_PROVIDE(KE, KE_QKD_KYBER_L1),
        PLUGIN_PROVIDE(KE, KE_QKD_KYBER_L3),
        PLUGIN_PROVIDE(KE, KE_QKD_KYBER_L5),
        PLUGIN_PROVIDE(KE, KE_QKD_MLKEM_L1),
        PLUGIN_PROVIDE(KE, KE_QKD_MLKEM_L3),
        PLUGIN_PROVIDE(KE, KE_QKD_MLKEM_L5),
        PLUGIN_PROVIDE(KE, KE_QKD_BIKE_L1),
        PLUGIN_PROVIDE(KE, KE_QKD_BIKE_L3),
        PLUGIN_PROVIDE(KE, KE_QKD_BIKE_L5),
        PLUGIN_PROVIDE(KE, KE_QKD_HQC_L1),
        PLUGIN_PROVIDE(KE, KE_QKD_HQC_L3),
        PLUGIN_PROVIDE(KE, KE_QKD_HQC_L5),
    };

    *features = f;
    DBG1(DBG_LIB, "QKD_KEM_plugin: QKD-KEM plugin providing %d features",
         countof(f));
    return countof(f);
}

METHOD(plugin_t, destroy, void, private_qkd_kem_plugin_t *this) {
    DBG2(DBG_LIB, "QKD_KEM_plugin: destroying QKD-KEM plugin");
    free(this);
}

plugin_t *qkd_kem_plugin_create(void) {
    private_qkd_kem_plugin_t *this;

    DBG1(DBG_LIB, "QKD_KEM_plugin: plugin_create called");

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
        DBG1(DBG_LIB, "QKD_KEM_plugin: INIT failed");
        return NULL;
    }

    /* Register algorithm names dynamically */
    register_algorithm_names();

    DBG1(DBG_LIB, "QKD_KEM_plugin: plugin initialized successfully");
    return &this->public.plugin;
}