/*
 * Copyright (C) 2024 Javier Blanco-Romero @fj-blanco (UC3M, QURSA project)
 */

/*
 * qkd_kem.c
 */

#include "qkd_kem.h"
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <utils/debug.h>

typedef struct private_qkd_kem_t private_qkd_kem_t;

struct private_qkd_kem_t {
    qkd_kem_t public;
    key_exchange_method_t method;
    OSSL_LIB_CTX *libctx;
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *key;
    unsigned char *ciphertext;
    size_t ciphertext_len;
    unsigned char *shared_secret;
    size_t shared_secret_len;
    struct timeval create_time;
};

#define QKD_TIMING_LOG "/tmp/plugin_timing.csv"

static void log_time(private_qkd_kem_t *this) {
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

static const char *get_kem_name(key_exchange_method_t method) {
    DBG1(DBG_LIB, "QKD-KEM plugin: get_kem_name called with method %d", method);
    uint32_t method_number = (uint32_t)method;
    switch (method_number) {
    case KE_QKD_FRODO_AES_L1:
        return "qkd_frodo640aes";
    case KE_QKD_FRODO_SHAKE_L1:
        return "qkd_frodo640shake";
    case KE_QKD_FRODO_AES_L3:
        return "qkd_frodo976aes";
    case KE_QKD_FRODO_SHAKE_L3:
        return "qkd_frodo976shake";
    case KE_QKD_FRODO_AES_L5:
        return "qkd_frodo1344aes";
    case KE_QKD_FRODO_SHAKE_L5:
        return "qkd_frodo1344shake";
    case KE_QKD_KYBER_L1:
        return "qkd_kyber512";
    case KE_QKD_KYBER_L3:
        return "qkd_kyber768";
    case KE_QKD_KYBER_L5:
        return "qkd_kyber1024";
    case KE_QKD_MLKEM_L1:
        return "qkd_mlkem512";
    case KE_QKD_MLKEM_L3:
        return "qkd_mlkem768";
    case KE_QKD_MLKEM_L5:
        return "qkd_mlkem1024";
    case KE_QKD_BIKE_L1:
        return "qkd_bikel1";
    case KE_QKD_BIKE_L3:
        return "qkd_bikel3";
    case KE_QKD_BIKE_L5:
        return "qkd_bikel5";
    case KE_QKD_HQC_L1:
        return "qkd_hqc128";
    case KE_QKD_HQC_L3:
        return "qkd_hqc192";
    case KE_QKD_HQC_L5:
        return "qkd_hqc256";
    default:
        return NULL;
    }
}

static bool load_provider_to_context(OSSL_LIB_CTX *libctx,
                                     const char *modulename) {
    char *config_file, *modules_dir;

    DBG1(DBG_LIB, "QKD-KEM plugin: loading provider '%s'", modulename);

    config_file = getenv("OPENSSL_CONF");
    modules_dir = getenv("OPENSSL_MODULES");
    DBG1(DBG_LIB, "QKD-KEM: OPENSSL_CONF=%s",
         config_file ? config_file : "not set");
    DBG1(DBG_LIB, "QKD-KEM: OPENSSL_MODULES=%s",
         modules_dir ? modules_dir : "not set");

    if (!libctx) {
        DBG1(DBG_LIB, "QKD-KEM: OpenSSL library context is NULL");
        return false;
    }

    if (!OSSL_PROVIDER_load(libctx, modulename)) {
        DBG1(DBG_LIB, "QKD-KEM: failed to load provider '%s'", modulename);
        return false;
    }

    if (!OSSL_PROVIDER_available(libctx, modulename)) {
        DBG1(DBG_LIB, "QKD-KEM: provider '%s' is not available after loading",
             modulename);
        return false;
    }

    return true;
}

static bool encaps_shared_secret(private_qkd_kem_t *this, chunk_t value) {
    unsigned long err;
    char err_buf[256];

#ifdef QKD_CLIENT_INITIATED
    DBG1(DBG_LIB,
         "QKD-KEM plugin: Bob performing encapsulation (client-initiated)");
    DBG1(DBG_LIB, "QKD-KEM plugin: Provider will handle QKD key generation "
                  "during encapsulation");
#elif defined(QKD_SERVER_INITIATED)
    DBG1(DBG_LIB,
         "QKD-KEM plugin: Alice performing encapsulation (server-initiated)");
    DBG1(DBG_LIB, "QKD-KEM plugin: Provider will handle QKD key generation "
                  "during encapsulation");
#endif

    DBG1(DBG_LIB,
         "QKD-KEM plugin: Bob received public key from Alice, size: %zu bytes",
         value.len);

    const char *kem_name = get_kem_name(this->method);
    EVP_PKEY *alice_key = NULL;

    if (!this->ctx) {
        this->ctx = EVP_PKEY_CTX_new_from_name(this->libctx, kem_name, NULL);
        if (!this->ctx) {
            err = ERR_get_error();
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            DBG1(DBG_LIB, "QKD-KEM plugin: Failed to create context: %s",
                 err_buf);
            return FALSE;
        }
    }

    if (EVP_PKEY_fromdata_init(this->ctx) <= 0) {
        err = ERR_get_error();
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        DBG1(DBG_LIB, "QKD-KEM plugin: Failed to initialize fromdata: %s",
             err_buf);
        return FALSE;
    }

    OSSL_PARAM import_params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, value.ptr,
                                          value.len),
        OSSL_PARAM_END};

    if (EVP_PKEY_fromdata(this->ctx, &alice_key, EVP_PKEY_PUBLIC_KEY,
                          import_params) <= 0) {
        err = ERR_get_error();
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        DBG1(DBG_LIB, "QKD-KEM plugin: Failed to import Alice's public key: %s",
             err_buf);
        return FALSE;
    }

    EVP_PKEY_CTX_free(this->ctx);
    this->ctx = EVP_PKEY_CTX_new(alice_key, NULL);

    if (!this->ctx) {
        err = ERR_get_error();
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        DBG1(DBG_LIB,
             "QKD-KEM plugin: Failed to create encapsulation context: %s",
             err_buf);
        EVP_PKEY_free(alice_key);
        return FALSE;
    }

    if (EVP_PKEY_encapsulate_init(this->ctx, NULL) <= 0) {
        err = ERR_get_error();
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        DBG1(DBG_LIB, "QKD-KEM plugin: Encapsulate init failed: %s", err_buf);
        EVP_PKEY_free(alice_key);
        return FALSE;
    }

    if (EVP_PKEY_encapsulate(this->ctx, NULL, &this->ciphertext_len, NULL,
                             &this->shared_secret_len) <= 0) {
        err = ERR_get_error();
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        DBG1(DBG_LIB, "QKD-KEM plugin: Failed to get buffer sizes: %s",
             err_buf);
        EVP_PKEY_free(alice_key);
        return FALSE;
    }

    if (this->ciphertext) {
        OPENSSL_free(this->ciphertext);
        this->ciphertext = NULL;
    }

    if (this->shared_secret) {
        OPENSSL_secure_clear_free(this->shared_secret, this->shared_secret_len);
        this->shared_secret = NULL;
    }

    this->ciphertext = OPENSSL_malloc(this->ciphertext_len);
    this->shared_secret = OPENSSL_secure_malloc(this->shared_secret_len);

    if (!this->ciphertext || !this->shared_secret) {
        if (this->ciphertext) {
            OPENSSL_free(this->ciphertext);
            this->ciphertext = NULL;
        }
        if (this->shared_secret) {
            OPENSSL_secure_clear_free(this->shared_secret,
                                      this->shared_secret_len);
            this->shared_secret = NULL;
        }
        DBG1(DBG_LIB, "QKD-KEM plugin: Failed to allocate buffers");
        EVP_PKEY_free(alice_key);
        return FALSE;
    }

    if (EVP_PKEY_encapsulate(this->ctx, this->ciphertext, &this->ciphertext_len,
                             this->shared_secret,
                             &this->shared_secret_len) <= 0) {
        err = ERR_get_error();
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        DBG1(DBG_LIB, "QKD-KEM plugin: Encapsulation failed: %s", err_buf);
        EVP_PKEY_free(alice_key);
        return FALSE;
    }

    EVP_PKEY_free(alice_key);

    DBG1(DBG_LIB, "QKD-KEM plugin: Encapsulation successful");
    DBG1(DBG_LIB,
         "QKD-KEM plugin: Encapsulation succeeded - ciphertext_len: %zu, "
         "shared_secret_len: %zu",
         this->ciphertext_len, this->shared_secret_len);
    return TRUE;
}

static bool set_ciphertext(private_qkd_kem_t *this, chunk_t value) {
    unsigned long err;
    char err_buf[256];

#ifdef QKD_CLIENT_INITIATED
    DBG1(DBG_LIB,
         "QKD-KEM plugin: Alice performing decapsulation (client-initiated)");
    DBG1(DBG_LIB, "QKD-KEM plugin: Provider will handle QKD key retrieval "
                  "during decapsulation");
#elif defined(QKD_SERVER_INITIATED)
    DBG1(DBG_LIB,
         "QKD-KEM plugin: Bob performing decapsulation (server-initiated)");
    DBG1(DBG_LIB, "QKD-KEM plugin: Provider will handle QKD key retrieval "
                  "during decapsulation");
#endif

    if (this->ciphertext_len == 0) {
        this->ciphertext_len = value.len;
        DBG1(DBG_LIB,
             "QKD-KEM plugin: Setting expected ciphertext size to %zu bytes",
             this->ciphertext_len);
    }

    if (value.len != this->ciphertext_len) {
        DBG1(DBG_LIB,
             "QKD-KEM plugin: wrong ciphertext size of %zu bytes, %zu bytes "
             "expected",
             value.len, this->ciphertext_len);
        return FALSE;
    }

    if (this->ctx) {
        EVP_PKEY_CTX_free(this->ctx);
    }

    this->ctx = EVP_PKEY_CTX_new_from_pkey(this->libctx, this->key, NULL);
    if (!this->ctx) {
        err = ERR_get_error();
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        DBG1(DBG_LIB, "QKD-KEM plugin: Failed to create context from key: %s",
             err_buf);
        return FALSE;
    }

    if (!EVP_PKEY_decapsulate_init(this->ctx, NULL)) {
        err = ERR_get_error();
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        DBG1(DBG_LIB, "QKD-KEM plugin: Decapsulate init failed: %s", err_buf);
        return FALSE;
    }

    if (!EVP_PKEY_decapsulate(this->ctx, NULL, &this->shared_secret_len,
                              value.ptr, value.len)) {
        err = ERR_get_error();
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        DBG1(DBG_LIB,
             "QKD-KEM plugin: Failed to determine shared secret length: %s",
             err_buf);
        return FALSE;
    }

    DBG1(DBG_LIB, "QKD-KEM plugin: Determined shared secret length: %zu bytes",
         this->shared_secret_len);

    if (this->shared_secret) {
        OPENSSL_secure_clear_free(this->shared_secret, this->shared_secret_len);
        this->shared_secret = NULL;
    }

    this->shared_secret = OPENSSL_secure_malloc(this->shared_secret_len);
    if (!this->shared_secret) {
        DBG1(DBG_LIB, "QKD-KEM plugin: Failed to allocate secure memory for "
                      "shared secret");
        return FALSE;
    }

    if (!EVP_PKEY_decapsulate(this->ctx, this->shared_secret,
                              &this->shared_secret_len, value.ptr, value.len)) {
        err = ERR_get_error();
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        DBG1(DBG_LIB, "QKD-KEM plugin: Decapsulation failed: %s", err_buf);

        OPENSSL_secure_clear_free(this->shared_secret, this->shared_secret_len);
        this->shared_secret = NULL;
        return FALSE;
    }

    DBG1(DBG_LIB,
         "QKD-KEM plugin: Decapsulation successful - shared_secret_len: %zu",
         this->shared_secret_len);
    return TRUE;
}

METHOD(key_exchange_t, get_public_key, bool, private_qkd_kem_t *this,
       chunk_t *value) {
    unsigned char *pubkey = NULL;
    size_t pubkey_len;

    DBG1(DBG_LIB, "QKD-KEM plugin: get_public_key()");
    if (!this || !value) {
        DBG1(DBG_LIB, "QKD-KEM plugin: Invalid parameters in get_public_key");
        return FALSE;
    }

#ifdef QKD_CLIENT_INITIATED
    // Client-initiated logic: Alice sends PQ public key first, Bob responds
    // with ciphertext
    if (this->ciphertext) {
        /* Bob - responder sends ciphertext back to Alice */
        DBG1(DBG_LIB, "QKD-KEM plugin: IKE responder sending ciphertext "
                      "(client-initiated)");
        *value =
            chunk_clone(chunk_create(this->ciphertext, this->ciphertext_len));
        return TRUE;
    }

    /* Alice - initiator generates PQ keypair and sends public key */
    if (!this->key) {
        DBG1(DBG_LIB, "QKD-KEM plugin: IKE initiator generating PQ keypair "
                      "(client-initiated)");
        EVP_PKEY_CTX *gen_ctx = EVP_PKEY_CTX_new_from_name(
            this->libctx, get_kem_name(this->method), NULL);
        if (!gen_ctx || !EVP_PKEY_keygen_init(gen_ctx) ||
            !EVP_PKEY_generate(gen_ctx, &this->key)) {
            EVP_PKEY_CTX_free(gen_ctx);
            return FALSE;
        }
        EVP_PKEY_CTX_free(gen_ctx);
    }

#elif defined(QKD_SERVER_INITIATED)
    // Server-initiated logic: Bob sends PQ public key first, Alice responds
    // with ciphertext
    if (this->ciphertext) {
        /* Alice - initiator sends ciphertext back to Bob */
        DBG1(DBG_LIB, "QKD-KEM plugin: IKE initiator sending ciphertext "
                      "(server-initiated)");
        *value =
            chunk_clone(chunk_create(this->ciphertext, this->ciphertext_len));
        return TRUE;
    }

    /* Bob - responder generates PQ keypair and sends public key */
    if (!this->key) {
        DBG1(DBG_LIB, "QKD-KEM plugin: IKE responder generating PQ keypair "
                      "(server-initiated)");

        const char *kem_name = get_kem_name(this->method);
        if (!kem_name) {
            DBG1(DBG_LIB, "QKD-KEM plugin: Invalid KEM method");
            return FALSE;
        }

        EVP_PKEY_CTX *gen_ctx =
            EVP_PKEY_CTX_new_from_name(this->libctx, kem_name, NULL);
        if (!gen_ctx) {
            DBG1(DBG_LIB,
                 "QKD-KEM plugin: Failed to create key generation context for "
                 "%s",
                 kem_name);
            return FALSE;
        }

        if (!EVP_PKEY_keygen_init(gen_ctx)) {
            DBG1(DBG_LIB,
                 "QKD-KEM plugin: Failed to initialize key generation");
            EVP_PKEY_CTX_free(gen_ctx);
            return FALSE;
        }

        if (!EVP_PKEY_generate(gen_ctx, &this->key)) {
            DBG1(DBG_LIB, "QKD-KEM plugin: Failed to generate keypair");
            EVP_PKEY_CTX_free(gen_ctx);
            return FALSE;
        }

        EVP_PKEY_CTX_free(gen_ctx);
        DBG1(DBG_LIB, "QKD-KEM plugin: Successfully generated PQ keypair");
    }
#else
#error "Must define either QKD_CLIENT_INITIATED or QKD_SERVER_INITIATED"
#endif

    // Common code for extracting and sending public key
    // Add null check before calling EVP_PKEY_get_raw_public_key
    if (!this->key) {
        DBG1(DBG_LIB,
             "QKD-KEM plugin: No key available for public key extraction");
        return FALSE;
    }

    if (!EVP_PKEY_get_raw_public_key(this->key, NULL, &pubkey_len)) {
        DBG1(DBG_LIB, "QKD-KEM plugin: Failed to get public key length");
        return FALSE;
    }

    DBG1(DBG_LIB, "QKD-KEM plugin: Public key length: %zu bytes", pubkey_len);

    pubkey = OPENSSL_malloc(pubkey_len);
    if (!pubkey) {
        DBG1(DBG_LIB,
             "QKD-KEM plugin: Failed to allocate memory for public key");
        return FALSE;
    }

    if (!EVP_PKEY_get_raw_public_key(this->key, pubkey, &pubkey_len)) {
        DBG1(DBG_LIB, "QKD-KEM plugin: Failed to extract public key");
        OPENSSL_free(pubkey);
        return FALSE;
    }

    *value = chunk_clone(chunk_create(pubkey, pubkey_len));
    OPENSSL_free(pubkey);

    DBG1(DBG_LIB, "QKD-KEM plugin: Public key sent successfully (%zu bytes)",
         pubkey_len);
    return TRUE;
}

METHOD(key_exchange_t, set_public_key, bool, private_qkd_kem_t *this,
       chunk_t value) {

    DBG1(DBG_LIB, "QKD-KEM plugin: set_public_key() (size: %zu bytes)",
         value.len);
    if (!this) {
        return FALSE;
    }

#ifdef QKD_CLIENT_INITIATED
    // Client-initiated: Alice sends PQ public key -> Bob encapsulates -> Alice
    // decapsulates
    if (this->key) {
        /* Alice's case (initiator) - receives ciphertext from Bob */
        DBG1(DBG_LIB, "QKD-KEM plugin: IKE initiator performing decapsulation "
                      "(client-initiated)");
        return set_ciphertext(this, value);
    }

    /* Bob's case (responder) - receives Alice's PQ public key, performs
     * encapsulation */
    DBG1(DBG_LIB, "QKD-KEM plugin: IKE responder performing encapsulation "
                  "(client-initiated)");
    return encaps_shared_secret(this, value);

#elif defined(QKD_SERVER_INITIATED)
    // Server-initiated: Bob sends PQ public key -> Alice encapsulates -> Bob
    // decapsulates
    if (this->key) {
        /* Bob's case (responder) - receives ciphertext from Alice */
        DBG1(DBG_LIB, "QKD-KEM plugin: IKE responder performing decapsulation "
                      "(server-initiated)");
        return set_ciphertext(this, value);
    }

    /* Alice's case (initiator) - receives Bob's PQ public key, performs
     * encapsulation */
    DBG1(DBG_LIB, "QKD-KEM plugin: IKE initiator performing encapsulation "
                  "(server-initiated)");
    return encaps_shared_secret(this, value);

#else
    // Add fallback for when compilation flags are missing
    DBG1(DBG_LIB, "QKD-KEM plugin: ERROR - No QKD initiation mode defined!");
    DBG1(DBG_LIB, "QKD-KEM plugin: Must compile with -DQKD_CLIENT_INITIATED or "
                  "-DQKD_SERVER_INITIATED");
    return FALSE;
#endif
}

METHOD(key_exchange_t, get_shared_secret, bool, private_qkd_kem_t *this,
       chunk_t *secret) {
    DBG1(DBG_LIB, "QKD-KEM plugin: retrieving shared secret");
    *secret =
        chunk_clone(chunk_create(this->shared_secret, this->shared_secret_len));
    return TRUE;
}

METHOD(key_exchange_t, get_method, key_exchange_method_t,
       private_qkd_kem_t *this) {
    DBG1(DBG_LIB, "QKD-KEM plugin: get_method()");
    return this->method;
}

METHOD(key_exchange_t, destroy, void, private_qkd_kem_t *this) {
    DBG1(DBG_LIB, "QKD-KEM plugin: destroy()");

    log_time(this);

    if (!this) {
        return;
    }

    if (this->shared_secret) {
        OPENSSL_secure_clear_free(this->shared_secret, this->shared_secret_len);
        this->shared_secret = NULL;
    }

    if (this->ciphertext) {
        OPENSSL_free(this->ciphertext);
        this->ciphertext = NULL;
    }

    if (this->key) {
        EVP_PKEY_free(this->key);
        this->key = NULL;
    }

    if (this->ctx) {
        EVP_PKEY_CTX_free(this->ctx);
        this->ctx = NULL;
    }

    if (this->libctx) {
        OSSL_LIB_CTX_free(this->libctx);
        this->libctx = NULL;
    }

    free(this);
}

qkd_kem_t *qkd_kem_create(key_exchange_method_t method) {
    DBG1(DBG_LIB, "QKD-KEM plugin: qkd_kem_create called with method %d",
         method);
    private_qkd_kem_t *this;
    const char *kem_name = get_kem_name(method);

    if (!kem_name) {
        DBG1(DBG_LIB, "QKD-KEM plugin: unsupported key exchange method %d",
             method);
        return NULL;
    }

    DBG1(DBG_LIB, "QKD-KEM plugin: kem_name = %s", kem_name);

    INIT(this,
         .public =
             {
                 .ke =
                     {
                         .get_method = _get_method,
                         .get_public_key = _get_public_key,
                         .set_public_key = _set_public_key,
                         .get_shared_secret = _get_shared_secret,
                         .destroy = _destroy,
                     },
             },
         .method = method,
         .libctx = OSSL_LIB_CTX_new(), // FIX: Create libctx BEFORE using it
         .ctx = NULL, .key = NULL, .ciphertext = NULL, .ciphertext_len = 0,
         .shared_secret = NULL, .shared_secret_len = 0);

    // Check if libctx creation succeeded
    if (!this->libctx) {
        DBG1(DBG_LIB,
             "QKD-KEM plugin: Failed to create OpenSSL library context");
        free(this);
        return NULL;
    }

    DBG1(DBG_LIB, "QKD-KEM plugin: before loading qkd_kem_provider");
    if (!load_provider_to_context(this->libctx, "qkdkemprovider")) {
        DBG1(DBG_LIB, "QKD-KEM plugin: Failed to load QKD-KEM provider");
        destroy(this);
        return NULL;
    }

    DBG1(DBG_LIB, "QKD-KEM plugin: after loading qkd_kem_provider");

    this->ctx = EVP_PKEY_CTX_new_from_name(this->libctx, kem_name, NULL);
    if (!this->ctx) {
        DBG1(DBG_LIB, "QKD-KEM plugin: Failed to create EVP_PKEY_CTX");
        destroy(this);
        return NULL;
    }

    gettimeofday(&this->create_time, NULL);

    DBG1(DBG_LIB, "QKD-KEM plugin: Key exchange object created successfully");
    return &this->public;
}