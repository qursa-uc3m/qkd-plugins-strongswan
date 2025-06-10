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
#include <unistd.h>
#include <utils/debug.h>

typedef struct private_qkd_kex_t private_qkd_kex_t;

struct private_qkd_kex_t {
    qkd_kex_t public;
    key_exchange_method_t method;
    qkd_handle_t handle;
    struct timeval create_time;
    bool key_retrieved;
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

// Helper to determine if we're in ETSI 004 mode
static bool is_etsi_004_mode(void) {
    const char *api_version = getenv("ETSI_API_VERSION");
    return (api_version && strcmp(api_version, "004") == 0);
}

METHOD(key_exchange_t, get_public_key, bool, private_qkd_kex_t *this,
       chunk_t *value) {
    DBG1(DBG_LIB, "QKD_plugin: get_public_key()");
    if (!this || !value) {
        return FALSE;
    }

#ifdef ETSI_004_API
    // ETSI 004: Initiator calls get_public_key first and generates key_id
    if (qkd_is_key_id_null(this->handle)) {
        DBG1(DBG_LIB, "QKD_plugin: ETSI 004 - generating key ID (initiator)");
        chunk_t key_id;
        if (!qkd_get_key_id(this->handle, &key_id)) {
            DBG1(DBG_LIB, "QKD_plugin: failed to generate key ID");
            return FALSE;
        }
        *value = chunk_clone(key_id);
        chunk_clear(&key_id);
        return TRUE;
    } else {
        DBG1(DBG_LIB, "QKD_plugin: ETSI 004 - returning stored key ID");
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

#ifdef ETSI_004_API
    // ETSI 004:
    if (qkd_is_key_id_null(this->handle)) {
        // We don't have a key_id yet, so we're the responder
        // Receive initiator's key_id and use it
        DBG1(DBG_LIB, "QKD_plugin: ETSI 004 - responder receiving key ID");
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

        this->key_retrieved = true;
        DBG1(DBG_LIB,
             "QKD_plugin: ETSI 004 - responder successfully fetched key "
             "using initiator's key ID");
        return TRUE;
    } else {
        // We already have a key_id, so we're the initiator
        // Receive responder's key_id but use our own for key retrieval
        DBG1(DBG_LIB,
             "QKD_plugin: ETSI 004 - initiator receiving responder key ID");

        // For ETSI 004, initiator needs to retrieve key using own key_id
        if (!this->key_retrieved) {
            if (!qkd_get_key(this->handle)) {
                DBG1(DBG_LIB,
                     "QKD_plugin: failed to fetch key using stored key ID");
                return FALSE;
            }
            this->key_retrieved = true;
            DBG1(DBG_LIB,
                 "QKD_plugin: ETSI 004 - initiator successfully fetched key");
        }
        return TRUE;
    }
#endif

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

    // For ETSI 004, ensure we've retrieved our key first
    if (is_etsi_004_mode() && !this->key_retrieved) {
        DBG1(DBG_LIB,
             "QKD_plugin: ETSI 004 - retrieving key before sharing secret");
        if (!qkd_get_key(this->handle)) {
            DBG1(DBG_LIB, "QKD_plugin: ETSI 004 - failed to retrieve key");
            return FALSE;
        }
        this->key_retrieved = true;
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
        log_time(this);
        free(this);
    }
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
         .method = method, .handle = NULL, .key_retrieved = false);

    gettimeofday(&this->create_time, NULL);

    if (!qkd_open(&this->handle)) {
        free(this);
        return NULL;
    }

    if (is_etsi_004_mode()) {
        DBG1(DBG_LIB,
             "QKD_plugin: key exchange object created (ETSI 004 mode)");
    } else {
        DBG1(DBG_LIB,
             "QKD_plugin: key exchange object created (ETSI 014 mode)");
    }

    return &this->public;
}