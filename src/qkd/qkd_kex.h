/*
 * Copyright (C) 2024 Javier Blanco-Romero @fj-blanco (UC3M, QURSA project)
 */

/*
 * qkd_kex.h
 */
#ifndef QKD_KEX_H_
#define QKD_KEX_H_

#include "qkd_plugin.h"
#include <crypto/key_exchange.h>

typedef struct qkd_kex_t qkd_kex_t;

#ifndef KE_QKD
#define KE_QKD 65535
#endif

struct qkd_kex_t {
    key_exchange_t ke;
    chunk_t shared_secret;
};

qkd_kex_t *qkd_kex_create(key_exchange_method_t method);

#endif /** QKD_KEX_H_ */