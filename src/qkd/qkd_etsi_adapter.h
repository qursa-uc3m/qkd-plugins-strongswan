/*
 * Copyright (C) 2024-2025 Javier Blanco-Romero @fj-blanco (UC3M, QURSA project)
 * Copyright (C) 2024-2025 Pedro Otero-García @pedrotega (UVigo, QURSA project)
 */

/*
 * qkd_etsi_adapter.h - Adapter between StrongSwan plugin and external QKD ETSI
 * API
 */

#ifndef QKD_ETSI_ADAPTER_H_
#define QKD_ETSI_ADAPTER_H_

#include <library.h>

/**
 * Key and Key ID sizes
 */
#define QKD_KEY_SIZE 32
#define QKD_KEY_ID_SIZE 16

/**
 * Metadata structure for ETSI 004 API
 * Required for QoS settings and GET_KEY operation
 */
#ifdef ETSI_004_API
typedef struct {
    uint32_t key_size; /* Size of the key in bytes */
    uint32_t timeout;  /* Timeout in milliseconds */
    uint32_t priority; /* Priority level (0 = normal) */
    void *reserved;    /* Reserved for future use */
} qkd_qos_t;

typedef struct {
    uint32_t auth_level; /* Authentication level */
    uint32_t conf_level; /* Confidentiality level */
    uint32_t integrity;  /* Integrity level */
    void *reserved;      /* Reserved for future use */
} qkd_metadata_t;
#endif

/**
 * Forward declaration of handle struct
 */
typedef struct qkd_handle_t *qkd_handle_t;

/**
 * Open a QKD connection and initialize the handle
 *
 * @param handle      pointer to store the created handle
 * @return            TRUE if successful, FALSE otherwise
 */
bool qkd_open(qkd_handle_t *handle);

/**
 * Close a QKD connection and free resources
 *
 * @param handle      QKD handle to close
 * @return            TRUE if successful, FALSE otherwise
 */
bool qkd_close(qkd_handle_t handle);

/**
 * Get a key ID (Alice's side)
 * This generates a new key ID and retrieves the corresponding key
 *
 * @param handle      QKD handle
 * @param key_id      pointer to store the generated key ID
 * @return            TRUE if successful, FALSE otherwise
 */
bool qkd_get_key_id(qkd_handle_t handle, chunk_t *key_id);

/**
 * Set a key ID (Bob's side)
 * This stores the key ID received from Alice
 *
 * @param handle      QKD handle
 * @param key_id      key ID received from Alice
 * @return            TRUE if successful, FALSE otherwise
 */
bool qkd_set_key_id(qkd_handle_t handle, chunk_t key_id);

/**
 * Get the QKD key associated with the current key ID
 *
 * @param handle      QKD handle
 * @return            TRUE if successful, FALSE otherwise
 */
bool qkd_get_key(qkd_handle_t handle);

/**
 * Check if key ID is NULL
 *
 * @param handle      QKD handle
 * @return            TRUE if key ID is NULL, FALSE otherwise
 */
bool qkd_is_key_id_null(qkd_handle_t handle);

/**
 * Get the stored key ID from the handle without generating a new one
 * Used in server-initiated mode to retrieve a previously generated key ID
 *
 * @param handle      QKD handle containing the stored key ID
 * @param key_id      pointer to store the retrieved key ID (caller must free)
 * @return            TRUE if successful and key ID exists, FALSE otherwise
 */
bool qkd_get_stored_key_id(qkd_handle_t handle, chunk_t *key_id);

/**
 * Get the shared secret key from the handle
 *
 * @param handle        QKD handle
 * @param key           Where to store the key (will be allocated)
 * @return              TRUE if successful, FALSE otherwise
 */
bool qkd_get_shared_secret(qkd_handle_t handle, chunk_t *key);

#ifdef ETSI_004_API
/**
 * Helper function to establish ETSI 004 connection
 * Internal function used by get_key_id and set_key_id
 *
 * @param handle        QKD handle
 * @param is_initiator  TRUE if this is the initiator (Alice)
 * @param key_id        Key ID to use (NULL for initiator to generate new one)
 * @return              TRUE if successful, FALSE otherwise
 */
bool qkd_establish_connection(qkd_handle_t handle, bool is_initiator,
                              unsigned char *key_id);
#endif

#endif /* QKD_ETSI_ADAPTER_H_ */