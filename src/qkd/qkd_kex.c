/*
 * Copyright (C) 2024-2025 Javier Blanco-Romero @fj-blanco (UC3M, QURSA project)
 */

/*
 * qkd_kex.c - Implements QKD-based key exchange using ETSI API
 */

#include "qkd_kex.h"
#include "qkd_etsi_adapter.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <utils/debug.h>

typedef struct private_qkd_kex_t private_qkd_kex_t;

struct private_qkd_kex_t {
    qkd_kex_t public;
    key_exchange_method_t method;
    qkd_handle_t handle;
    struct timeval create_time;
};

#define QKD_TIMING_LOG "/tmp/plugin_timing.csv"

static void log_time(private_qkd_kex_t *this) {
    struct timeval destroy_time;
    FILE *fp;

    gettimeofday(&destroy_time, NULL);

    fp = fopen(QKD_TIMING_LOG, "a");
    if (fp == NULL) {
        DBG1(DBG_LIB, "QKD_plugin: Could not open timing log file: %s",
             QKD_TIMING_LOG);
        return;
    }

    fprintf(fp, "%d,%ld,%ld,%ld,%ld\n", this->method,
            (long)this->create_time.tv_sec, (long)this->create_time.tv_usec,
            (long)destroy_time.tv_sec, (long)destroy_time.tv_usec);

    fclose(fp);

    DBG1(DBG_LIB, "QKD_plugin: Logged timing event for method %d",
         this->method);
}

METHOD(key_exchange_t, get_public_key, bool, private_qkd_kex_t *this,
       chunk_t *value) {
    DBG1(DBG_LIB, "QKD_plugin: get_public_key()");
    if (!this || !value) {
        return FALSE;
    }

    // If key_id is NULL, this is Alice generating the initial key_id
    if (qkd_is_key_id_null(this->handle)) {
        DBG1(DBG_LIB, "QKD_plugin: Alice generating key ID");
        chunk_t key_id;
        if (!qkd_get_key_id(this->handle, &key_id)) {
            DBG1(DBG_LIB, "QKD_plugin: failed to get key ID");
            return FALSE;
        }
        *value = chunk_clone(key_id);
        chunk_clear(&key_id);
        return TRUE;
    } else {
        // This is Bob, send empty response
        DBG1(DBG_LIB, "QKD_plugin: Bob sending empty response");
        *value = chunk_empty;
        return TRUE;
    }

    return FALSE; /* Should never reach here */
}

METHOD(key_exchange_t, set_public_key, bool, private_qkd_kex_t *this,
       chunk_t value) {
    DBG1(DBG_LIB, "QKD_plugin: set_public_key()");
    if (!this) {
        return FALSE;
    }

    // Bob receives key_id from Alice
    if (qkd_is_key_id_null(this->handle)) {
        DBG1(DBG_LIB, "QKD_plugin: Bob receiving key ID");
        if (value.len != QKD_KEY_ID_SIZE) {
            DBG1(DBG_LIB, "QKD_plugin: invalid key ID received");
            return FALSE;
        }

        if (!qkd_set_key_id(this->handle, value)) {
            DBG1(DBG_LIB, "QKD_plugin: failed to store key ID");
            return FALSE;
        }

        if (!qkd_get_key(this->handle)) {
            DBG1(DBG_LIB, "QKD_plugin: failed to fetch key using key ID");
            return FALSE;
        }

        DBG1(DBG_LIB,
             "QKD_plugin: Bob successfully fetched key using Alice's key ID");
        return TRUE;
    } else {
        // Alice receives empty response from Bob
        DBG1(DBG_LIB, "QKD_plugin: Alice receiving empty response");
        return TRUE;
    }

    return FALSE; /* Should never reach here */
}

METHOD(key_exchange_t, get_shared_secret, bool, private_qkd_kex_t *this,
       chunk_t *secret) {
    DBG1(DBG_LIB, "QKD_plugin: get_shared_secret()");

    if (!this || !this->handle || !secret) {
        DBG1(DBG_LIB, "QKD_plugin: invalid parameters for get_shared_secret");
        return FALSE;
    }

    if (!qkd_get_shared_secret(this->handle, secret)) {
        DBG1(DBG_LIB, "QKD_plugin: failed to get shared secret");
        return FALSE;
    }

    chunk_clear(&this->public.shared_secret);
    this->public.shared_secret = chunk_clone(*secret);

    DBG1(DBG_LIB, "QKD_plugin: successfully returned shared secret");

    return TRUE;
}

METHOD(key_exchange_t, destroy, void, private_qkd_kex_t *this) {
    DBG1(DBG_LIB, "QKD_plugin: destroy()");
    if (this) {
        chunk_clear(&this->public.shared_secret);
        if (this->handle) {
            qkd_close(this->handle);
        }
        free(this);
    }
    log_time(this);
}

METHOD(key_exchange_t, get_method, key_exchange_method_t,
       private_qkd_kex_t *this) {
    DBG1(DBG_LIB, "QKD_plugin: get_method()");
    return this->method;
}

qkd_kex_t *qkd_kex_create(key_exchange_method_t method) {
    private_qkd_kex_t *this;

    DBG1(DBG_LIB, "QKD_plugin: qkd_kex_create called with method %d", method);

    if (method != KE_QKD) {
        DBG1(DBG_LIB, "QKD_plugin: unsupported key exchange method");
        return NULL;
    }

    INIT(this,
         .public =
             {
                 .ke =
                     {
                         .get_shared_secret = _get_shared_secret,
                         .get_method = _get_method,
                         .destroy = _destroy,
                         .get_public_key = _get_public_key,
                         .set_public_key = _set_public_key,
                         .set_seed = (void *)return_false,
                     },
                 .shared_secret = chunk_empty,
             },
         .method = method, .handle = NULL);

    gettimeofday(&this->create_time, NULL);

    if (!qkd_open(&this->handle)) {
        free(this);
        return NULL;
    }

    DBG1(DBG_LIB, "QKD_plugin: key exchange object created");
    return &this->public;
}
