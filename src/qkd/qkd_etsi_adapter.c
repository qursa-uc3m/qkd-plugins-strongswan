/*
 * Copyright (C) 2024-2025 Javier Blanco-Romero @fj-blanco (UC3M, QURSA project)
 * Copyright (C) 2024-2025 Pedro Otero-García @pedrotega (UVigo, QURSA project)
 */

/*
 * qkd_etsi_adapter.c - Adapter implementation between StrongSwan and external
 * QKD ETSI API
 */
#include "qkd_etsi_adapter.h"
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <utils/chunk.h>
#include <utils/debug.h>
#include <uuid/uuid.h>

#include <qkd-etsi-api-c-wrapper/qkd_etsi_api.h>
#ifdef ETSI_004_API
#include <qkd-etsi-api-c-wrapper/etsi004/api.h>
#elif defined(ETSI_014_API)
#include <qkd-etsi-api-c-wrapper/etsi014/api.h>
#endif

struct qkd_handle_t {
    bool is_open;
    chunk_t key;
    chunk_t key_id;

#ifdef ETSI_014_API
    char *master_kme;
    char *slave_kme;
    char *master_sae;
    char *slave_sae;
#endif
#ifdef ETSI_004_API
    bool is_connected;
    struct qkd_qos_s qos;
    char *source_uri;
    char *dest_uri;
#endif
};

#define ENV_QKD_BACKEND "QKD_BACKEND"
#define ENV_QKD_SOURCE_URI "QKD_SOURCE_URI"
#define ENV_QKD_DEST_URI "QKD_DEST_URI"

#ifdef ETSI_014_API
#define ENV_MASTER_KME "QKD_MASTER_KME_HOSTNAME"
#define ENV_SLAVE_KME "QKD_SLAVE_KME_HOSTNAME"
#define ENV_MASTER_SAE "QKD_MASTER_SAE"
#define ENV_SLAVE_SAE "QKD_SLAVE_SAE"
#endif

void qkd_print_key_id(const char *prefix, chunk_t key_id) {
    char hex[256] = "";
    chunk_to_hex(key_id, hex, FALSE);
    DBG1(DBG_LIB, "QKD_plugin: %s key ID: %s", prefix, hex);
}

void qkd_print_key(const char *prefix, chunk_t key) {
    char hex[2048] = "";
    chunk_to_hex(key, hex, FALSE);
    DBG1(DBG_LIB, "QKD_plugin: %s key: %s", prefix, hex);
}

#ifdef ETSI_014_API
static int encode_UUID(const char *uuid_str, unsigned char bin[16]) {
    if (uuid_parse(uuid_str, bin) == -1)
        return -1;
    return 0;
}

static void decode_UUID(const unsigned char bin[16], char uuid_str[37]) {
    uuid_unparse(bin, uuid_str);
}

static unsigned char *base64_decode(const char *in, size_t *outlen) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new_mem_buf((void *)in, -1);
    if (!bmem) {
        BIO_free_all(b64);
        return NULL;
    }
    bmem = BIO_push(b64, bmem);
    BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);

    size_t inlen = strlen(in);
    unsigned char *out = malloc(inlen);
    *outlen = BIO_read(bmem, out, inlen);
    BIO_free_all(bmem);

    if (*outlen <= 0) {
        free(out);
        return NULL;
    }
    return out;
}
#endif /* ETSI_014_API */

bool qkd_open(qkd_handle_t *handle) {
    DBG1(DBG_LIB, "QKD_plugin: qkd_open called");

    if (!handle) {
        DBG1(DBG_LIB, "QKD_plugin: invalid handle pointer");
        return FALSE;
    }

    *handle = calloc(1, sizeof(struct qkd_handle_t));
    if (!*handle) {
        DBG1(DBG_LIB, "QKD_plugin: memory allocation failed for handle");
        return FALSE;
    }

    (*handle)->is_open = TRUE;
    (*handle)->key = chunk_empty;
    (*handle)->key_id = chunk_empty;
#ifdef ETSI_004_API
    (*handle)->is_connected = FALSE;
#endif

    const char *qkd_backend = getenv(ENV_QKD_BACKEND);
    const char *backend_name = qkd_backend ? qkd_backend : "simulated";

#ifdef ETSI_014_API
    // ETSI 014 requires KME and SAE configuration
    const char *master_kme = getenv(ENV_MASTER_KME);
    const char *slave_kme = getenv(ENV_SLAVE_KME);
    const char *master_sae = getenv(ENV_MASTER_SAE);
    const char *slave_sae = getenv(ENV_SLAVE_SAE);

    if (!master_kme || !slave_kme || !master_sae || !slave_sae) {
        DBG1(DBG_LIB,
             "QKD_plugin: missing required ETSI 014 environment variables");
        DBG1(DBG_LIB, "  Required: QKD_MASTER_KME_HOSTNAME, "
                      "QKD_SLAVE_KME_HOSTNAME, QKD_MASTER_SAE, QKD_SLAVE_SAE");
        free(*handle);
        *handle = NULL;
        return FALSE;
    }

    (*handle)->master_kme = strdup(master_kme);
    (*handle)->slave_kme = strdup(slave_kme);
    (*handle)->master_sae = strdup(master_sae);
    (*handle)->slave_sae = strdup(slave_sae);

    DBG1(DBG_LIB, "QKD_plugin: ETSI 014 configuration:");
    DBG1(DBG_LIB, "  Backend: %s", backend_name);
    DBG1(DBG_LIB, "  Master KME: %s", (*handle)->master_kme);
    DBG1(DBG_LIB, "  Slave KME: %s", (*handle)->slave_kme);
    DBG1(DBG_LIB, "  Master SAE: %s", (*handle)->master_sae);
    DBG1(DBG_LIB, "  Slave SAE: %s", (*handle)->slave_sae);

#elif defined(ETSI_004_API)
    // ETSI 004 requires URI configuration
    const char *source_uri = getenv(ENV_QKD_SOURCE_URI);
    const char *dest_uri = getenv(ENV_QKD_DEST_URI);

    if (!source_uri || !dest_uri) {
        DBG1(DBG_LIB,
             "QKD_plugin: missing required ETSI 004 URI environment variables");
        DBG1(DBG_LIB, "  Required: QKD_SOURCE_URI, QKD_DEST_URI");
        free(*handle);
        *handle = NULL;
        return FALSE;
    }

    (*handle)->source_uri = strdup(source_uri);
    (*handle)->dest_uri = strdup(dest_uri);

    DBG1(DBG_LIB, "QKD_plugin: ETSI 004 configuration:");
    DBG1(DBG_LIB, "  Backend: %s", backend_name);
    DBG1(DBG_LIB, "  Source URI: %s", (*handle)->source_uri);
    DBG1(DBG_LIB, "  Destination URI: %s", (*handle)->dest_uri);

    // Configure QoS parameters
    const char *key_chunk_size_env = getenv("QKD_KEY_CHUNK_SIZE");
    const char *timeout_env = getenv("QKD_TIMEOUT");
    const char *max_bps_env = getenv("QKD_MAX_BPS");
    const char *min_bps_env = getenv("QKD_MIN_BPS");

    (*handle)->qos.Key_chunk_size =
        key_chunk_size_env ? atoi(key_chunk_size_env) : QKD_KEY_SIZE;
    (*handle)->qos.Timeout = timeout_env ? atoi(timeout_env) : 60000;
    (*handle)->qos.Priority = 0;
    (*handle)->qos.Max_bps = max_bps_env ? atoi(max_bps_env) : 40000;
    (*handle)->qos.Min_bps = min_bps_env ? atoi(min_bps_env) : 5000;
    (*handle)->qos.Jitter = 10;
    (*handle)->qos.TTL = 3600;
    strcpy((*handle)->qos.Metadata_mimetype, "application/json");

    DBG1(DBG_LIB, "QKD_plugin: QoS configuration:");
    DBG1(DBG_LIB, "  Key chunk size: %u", (*handle)->qos.Key_chunk_size);
    DBG1(DBG_LIB, "  Timeout: %u ms", (*handle)->qos.Timeout);
    DBG1(DBG_LIB, "  Max BPS: %u", (*handle)->qos.Max_bps);
    DBG1(DBG_LIB, "  Min BPS: %u", (*handle)->qos.Min_bps);
#endif

    return TRUE;
}

bool qkd_close(qkd_handle_t handle) {
    DBG1(DBG_LIB, "QKD_plugin: qkd_close called");

    if (!handle) {
        DBG1(DBG_LIB, "QKD_plugin: invalid handle in close");
        return FALSE;
    }

#ifdef ETSI_004_API
    if (handle->is_connected) {
        uint32_t status;
        uint32_t result = CLOSE(handle->key_id.ptr, &status);

        if (result == 0 && (status == QKD_STATUS_SUCCESS ||
                            status == QKD_STATUS_PEER_NOT_CONNECTED)) {
            handle->is_connected = FALSE;
            DBG1(DBG_LIB,
                 "QKD_plugin: ETSI 004 connection closed successfully");
        } else {
            DBG1(DBG_LIB,
                 "QKD_plugin: Failed to close ETSI 004 connection, result=%u, "
                 "status=%u",
                 result, status);
        }
    }
    free(handle->source_uri);
    free(handle->dest_uri);
#endif

    chunk_clear(&handle->key);
    chunk_clear(&handle->key_id);

#ifdef ETSI_014_API
    free(handle->master_kme);
    free(handle->slave_kme);
    free(handle->master_sae);
    free(handle->slave_sae);
#endif

    handle->is_open = FALSE;
    free(handle);

    DBG1(DBG_LIB, "QKD_plugin: connection resources released successfully");
    return TRUE;
}

bool qkd_is_key_id_null(qkd_handle_t handle) {
    if (!handle) {
        return TRUE;
    }
    return handle->key_id.ptr == NULL;
}

bool qkd_get_stored_key_id(qkd_handle_t handle, chunk_t *key_id) {
    if (!handle || !handle->is_open || !key_id) {
        DBG1(DBG_LIB, "QKD_plugin: Invalid parameters in get_stored_key_id");
        return FALSE;
    }

    if (handle->key_id.len == 0 || handle->key_id.ptr == NULL) {
        DBG1(DBG_LIB, "QKD_plugin: No key ID stored in handle");
        return FALSE;
    }

    *key_id = chunk_clone(handle->key_id);
    return TRUE;
}

bool qkd_set_key_id(qkd_handle_t handle, chunk_t key_id) {
    DBG1(DBG_LIB, "QKD_plugin: qkd_set_key_id() called (Bob/responder)");

    if (!handle || !handle->is_open || key_id.len != QKD_KEY_ID_SIZE) {
        DBG1(DBG_LIB, "QKD_plugin: Invalid parameters in set_key_id");
        return FALSE;
    }

    qkd_print_key_id("Received", key_id);

    chunk_clear(&handle->key_id);
    handle->key_id = chunk_clone(key_id);

#ifdef ETSI_004_API
    /* For ETSI 004, Bob would initiate connection here using the key ID */
    if (!handle->is_connected) {
        uint32_t status;

        unsigned char key_stream_id[QKD_KEY_ID_SIZE];
        memcpy(key_stream_id, handle->key_id.ptr, QKD_KEY_ID_SIZE);

        /* Call OPEN_CONNECT to establish connection with received key ID */
        uint32_t result = OPEN_CONNECT(handle->source_uri, handle->dest_uri,
                                       &handle->qos, key_stream_id, &status);

        if (result != 0 || (status != QKD_STATUS_SUCCESS &&
                            status != QKD_STATUS_PEER_NOT_CONNECTED &&
                            status != QKD_STATUS_QOS_NOT_MET)) {
            DBG1(DBG_LIB,
                 "QKD_plugin: Failed to establish ETSI 004 connection as "
                 "responder, result=%u, status=%u",
                 result, status);
            return FALSE;
        }

        handle->is_connected = TRUE;
        DBG1(DBG_LIB,
             "QKD_plugin: ETSI 004 connection established as responder");

        if (status == QKD_STATUS_QOS_NOT_MET) {
            DBG1(DBG_LIB, "QKD_plugin: Connection established with adjusted "
                          "QoS parameters");
        }
    }
#endif

    DBG1(DBG_LIB, "QKD_plugin: Bob received and stored key ID successfully");
    return TRUE;
}

bool qkd_get_key_id(qkd_handle_t handle, chunk_t *key_id) {
    DBG1(DBG_LIB, "QKD_plugin: qkd_get_key_id() called (Alice/initiator)");

    if (!handle || !handle->is_open || !key_id) {
        DBG1(DBG_LIB, "QKD_plugin: Invalid parameters in get_key_id");
        return FALSE;
    }

#ifdef ETSI_004_API
    /* ETSI 004 implementation for initiator (Alice) */
    uint32_t status;

    /* If not connected, establish connection first */
    if (!handle->is_connected) {
        unsigned char key_stream_id[QKD_KEY_ID_SIZE] = {0};

        uint32_t result = OPEN_CONNECT(handle->source_uri, handle->dest_uri,
                                       &handle->qos, key_stream_id, &status);

        if (result != 0 || (status != QKD_STATUS_SUCCESS &&
                            status != QKD_STATUS_PEER_NOT_CONNECTED &&
                            status != QKD_STATUS_QOS_NOT_MET)) {
            DBG1(DBG_LIB,
                 "QKD_plugin: Failed to establish ETSI 004 connection, "
                 "result=%u, status=%u",
                 result, status);
            return FALSE;
        }

        handle->is_connected = TRUE;

        chunk_clear(&handle->key_id);
        handle->key_id = chunk_alloc(QKD_KEY_ID_SIZE);
        memcpy(handle->key_id.ptr, key_stream_id, QKD_KEY_ID_SIZE);

        *key_id = chunk_clone(handle->key_id);

        qkd_print_key_id("Generated (ETSI 004)", handle->key_id);

        if (status == QKD_STATUS_QOS_NOT_MET) {
            DBG1(DBG_LIB, "QKD_plugin: Connection established with adjusted "
                          "QoS parameters");
        }

        return TRUE;
    } else {
        /* Already connected, just return the stored key ID */
        *key_id = chunk_clone(handle->key_id);
        qkd_print_key_id("Existing (ETSI 004)", handle->key_id);
        return TRUE;
    }

#elif defined(ETSI_014_API)
    qkd_key_request_t request;
    qkd_key_container_t container;

    memset(&request, 0, sizeof(request));
    memset(&container, 0, sizeof(container));

    request.number = 1;
    request.size = QKD_KEY_SIZE;

    uint32_t status =
        GET_KEY(handle->master_kme, handle->slave_sae, &request, &container);

    if (status != QKD_STATUS_OK) {
        DBG1(DBG_LIB,
             "QKD_plugin: Failed to obtain key from QKD system, status: %u",
             status);
        return FALSE;
    }

    DBG1(DBG_LIB, "QKD_plugin: Successfully obtained key from QKD system");

    if (container.key_count <= 0 || !container.keys) {
        DBG1(DBG_LIB, "QKD_plugin: No keys returned");
        return FALSE;
    }

    qkd_key_t *first_key = &container.keys[0];

    if (!first_key->key_ID) {
        DBG1(DBG_LIB, "QKD_plugin: No key ID in the returned key");
        return FALSE;
    }

    unsigned char *key_id_data = malloc(QKD_KEY_ID_SIZE);
    if (!key_id_data) {
        return FALSE;
    }

    if (encode_UUID(first_key->key_ID, key_id_data) != 0) {
        DBG1(DBG_LIB, "QKD_plugin: Failed to encode UUID");
        free(key_id_data);
        return FALSE;
    }

    size_t outlen = 0;
    unsigned char *decoded_key = base64_decode(first_key->key, &outlen);
    if (!decoded_key) {
        DBG1(DBG_LIB, "QKD_plugin: Base64 decode failed");
        free(key_id_data);
        return FALSE;
    }

    chunk_clear(&handle->key_id);
    chunk_clear(&handle->key);

    handle->key_id = chunk_create(key_id_data, QKD_KEY_ID_SIZE);
    handle->key = chunk_create(decoded_key, outlen);

    qkd_print_key_id("Generated", handle->key_id);

    *key_id = chunk_clone(handle->key_id);

    return TRUE;
#else
    DBG1(DBG_LIB, "QKD_plugin: No QKD API implementation available");
    return FALSE;
#endif
}

bool qkd_get_key(qkd_handle_t handle) {
    DBG1(DBG_LIB, "QKD_plugin: qkd_get_key called");

    if (!handle || !handle->is_open) {
        DBG1(DBG_LIB, "QKD_plugin: invalid parameters in get_key");
        return FALSE;
    }

    if (handle->key_id.len == 0 || handle->key_id.ptr == NULL) {
        DBG1(DBG_LIB, "QKD_plugin: no key ID set for key retrieval");
        return FALSE;
    }

    qkd_print_key_id("Using", handle->key_id);

#ifdef ETSI_004_API
    if (!handle->is_connected) {
        DBG1(DBG_LIB, "QKD_plugin: ETSI 004 connection not established");
        return FALSE;
    }

    uint32_t status;
    uint32_t index = 0;
    unsigned char key_buffer[QKD_KEY_SIZE];

    unsigned char metadata_buffer[QKD_METADATA_MAX_SIZE];
    struct qkd_metadata_s metadata;
    metadata.Metadata_size = QKD_METADATA_MAX_SIZE;
    metadata.Metadata_buffer = metadata_buffer;

    uint32_t result =
        GET_KEY(handle->key_id.ptr, &index, key_buffer, &metadata, &status);

    if (result != 0 || (status != QKD_STATUS_SUCCESS &&
                        status != QKD_STATUS_PEER_NOT_CONNECTED)) {
        DBG1(DBG_LIB,
             "QKD_plugin: Failed to get key from ETSI 004 API, result=%u, "
             "status=%u",
             result, status);
        return FALSE;
    }

    chunk_clear(&handle->key);
    handle->key = chunk_alloc(QKD_KEY_SIZE);
    memcpy(handle->key.ptr, key_buffer, QKD_KEY_SIZE);

    qkd_print_key("Retrieved (ETSI 004)", handle->key);
    return TRUE;

#elif defined(ETSI_014_API)
    qkd_key_ids_t key_ids;
    qkd_key_container_t container;

    memset(&key_ids, 0, sizeof(key_ids));
    memset(&container, 0, sizeof(container));

    key_ids.key_ID_count = 1;
    key_ids.key_IDs = malloc(sizeof(qkd_key_id_t));
    if (!key_ids.key_IDs) {
        return FALSE;
    }

    char uuid_str[37]; // 36 chars + null terminator
    decode_UUID(handle->key_id.ptr, uuid_str);

    DBG1(DBG_LIB, "QKD_plugin: Converted key ID for API: %s", uuid_str);

    key_ids.key_IDs[0].key_ID = strdup(uuid_str);
    if (!key_ids.key_IDs[0].key_ID) {
        free(key_ids.key_IDs);
        return FALSE;
    }

    uint32_t status = GET_KEY_WITH_IDS(handle->slave_kme, handle->master_sae,
                                       &key_ids, &container);

    free(key_ids.key_IDs[0].key_ID);
    free(key_ids.key_IDs);

    if (status != QKD_STATUS_OK) {
        DBG1(DBG_LIB,
             "QKD_plugin: Failed to retrieve key with ID from QKD system, "
             "status: %u",
             status);
        return FALSE;
    }

    DBG1(DBG_LIB, "QKD_plugin: Successfully retrieved key from QKD system");

    if (container.key_count <= 0 || !container.keys) {
        DBG1(DBG_LIB, "QKD_plugin: No keys returned");
        return FALSE;
    }

    qkd_key_t *first_key = &container.keys[0];

    size_t outlen = 0;
    unsigned char *decoded_key = base64_decode(first_key->key, &outlen);
    if (!decoded_key) {
        DBG1(DBG_LIB, "QKD_plugin: Base64 decode failed");
        return FALSE;
    }

    if (outlen != QKD_KEY_SIZE) {
        DBG1(DBG_LIB, "QKD_plugin: Unexpected key size from QKD system: %zu",
             outlen);
    }

    chunk_clear(&handle->key);
    handle->key = chunk_create(decoded_key, outlen);

    qkd_print_key("Retrieved", handle->key);

    return TRUE;
#else
    DBG1(DBG_LIB, "QKD_plugin: No QKD API implementation available");
    return FALSE;
#endif
}

bool qkd_get_shared_secret(qkd_handle_t handle, chunk_t *key) {
    if (!handle || !handle->is_open || !key) {
        DBG1(DBG_LIB, "QKD_plugin: invalid parameters in get_shared_secret");
        return FALSE;
    }

    if (!handle->key.ptr || handle->key.len == 0) {
        DBG1(DBG_LIB, "QKD_plugin: no key available in handle");
        return FALSE;
    }

    *key = chunk_clone(handle->key);
    DBG1(DBG_LIB, "QKD_plugin: retrieved key of length %d from handle",
         handle->key.len);
    return TRUE;
}