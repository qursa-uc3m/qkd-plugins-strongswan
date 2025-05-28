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

#ifdef QKD_CLIENT_INITIATED
    // Client-initiated logic: IKE initiator (Alice) generates key_id
    if (qkd_is_key_id_null(this->handle)) {
        DBG1(DBG_LIB, "QKD_plugin: IKE initiator generating key ID");
        chunk_t key_id;
        if (!qkd_get_key_id(this->handle, &key_id)) {
            DBG1(DBG_LIB, "QKD_plugin: failed to get key ID");
            return FALSE;
        }
        *value = chunk_clone(key_id);
        chunk_clear(&key_id);
        return TRUE;
    } else {
        DBG1(DBG_LIB, "QKD_plugin: IKE responder sending empty response");
        *value = chunk_empty;
        return TRUE;
    }

#elif defined(QKD_SERVER_INITIATED)
    // Server-initiated logic
    if (qkd_is_key_id_null(this->handle)) {
        // No key_id yet - send empty
        DBG1(DBG_LIB, "QKD_plugin: Sending empty (server-initiated mode)");
        *value = chunk_empty;
        return TRUE;
    } else {
        // We have a key_id in handle - send it (Bob's role)
        DBG1(DBG_LIB, "QKD_plugin: IKE responder sending generated key ID "
                      "(server-initiated mode)");

        chunk_t stored_key_id;
        if (!qkd_get_stored_key_id(this->handle, &stored_key_id)) {
            DBG1(DBG_LIB, "QKD_plugin: failed to get stored key ID");
            return FALSE;
        }
        *value = chunk_clone(stored_key_id);
        chunk_clear(&stored_key_id);
        return TRUE;
    }
#endif
}

METHOD(key_exchange_t, set_public_key, bool, private_qkd_kex_t *this,
       chunk_t value) {
    DBG1(DBG_LIB, "QKD_plugin: set_public_key()");
    if (!this) {
        return FALSE;
    }

#ifdef QKD_CLIENT_INITIATED
    // Client-initiated: IKE responder (Bob) receives key_id from IKE initiator
    // (Alice)
    if (qkd_is_key_id_null(this->handle)) {
        DBG1(DBG_LIB, "QKD_plugin: IKE responder receiving key ID");
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

        DBG1(DBG_LIB, "QKD_plugin: IKE responder successfully fetched key "
                      "using initiator's key ID");
        return TRUE;
    } else {
        // IKE initiator receives empty response from responder
        DBG1(DBG_LIB, "QKD_plugin: IKE initiator receiving empty response");
        return TRUE;
    }

#elif defined(QKD_SERVER_INITIATED)
    // Server-initiated: Use received value to determine role
    if (value.len == 0) {
        // Received empty chunk - we're the IKE responder (Bob), generate key_id
        DBG1(DBG_LIB, "QKD_plugin: IKE responder receiving empty request - "
                      "generating key ID");

        // Generate key_id and store it in handle
        chunk_t key_id;
        if (!qkd_get_key_id(this->handle, &key_id)) {
            DBG1(DBG_LIB, "QKD_plugin: failed to generate key ID");
            return FALSE;
        }
        chunk_clear(&key_id); // key_id is now stored in handle->key_id
        return TRUE;

    } else if (value.len == QKD_KEY_ID_SIZE) {
        // Received a key_id - we're the IKE initiator (Alice)
        DBG1(DBG_LIB,
             "QKD_plugin: IKE initiator receiving key ID from responder");

        if (!qkd_set_key_id(this->handle, value)) {
            DBG1(DBG_LIB, "QKD_plugin: failed to store key ID");
            return FALSE;
        }

        if (!qkd_get_key(this->handle)) {
            DBG1(DBG_LIB, "QKD_plugin: failed to fetch key using key ID");
            return FALSE;
        }

        DBG1(DBG_LIB, "QKD_plugin: IKE initiator successfully fetched key "
                      "using responder's key ID");
        return TRUE;
    } else {
        DBG1(DBG_LIB, "QKD_plugin: invalid key ID size received: %zu",
             value.len);
        return FALSE;
    }
#endif
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
