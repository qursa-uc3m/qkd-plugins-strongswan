/*
 * Copyright (C) 2024 Javier Blanco-Romero @fj-blanco (UC3M, QURSA project)
 */

/*
 * qkd_kem.h
 */
#ifndef QKD_KEX_H_
#define QKD_KEX_H_

typedef struct qkd_kem_t qkd_kem_t;

#include <crypto/key_exchange.h>

#ifndef KE_QKD_FRODO_AES_L1
#define KE_QKD_FRODO_AES_L1 65534
#endif

#ifndef KE_QKD_FRODO_SHAKE_L1
#define KE_QKD_FRODO_SHAKE_L1 65533
#endif

#ifndef KE_QKD_FRODO_AES_L3
#define KE_QKD_FRODO_AES_L3 65532
#endif

#ifndef KE_QKD_FRODO_SHAKE_L3
#define KE_QKD_FRODO_SHAKE_L3 65531
#endif

#ifndef KE_QKD_FRODO_AES_L5
#define KE_QKD_FRODO_AES_L5 65530
#endif

#ifndef KE_QKD_FRODO_SHAKE_L5
#define KE_QKD_FRODO_SHAKE_L5 65529
#endif

#ifndef KE_QKD_KYBER_L1
#define KE_QKD_KYBER_L1 65528
#endif

#ifndef KE_QKD_KYBER_L3
#define KE_QKD_KYBER_L3 65527
#endif

#ifndef KE_QKD_KYBER_L5
#define KE_QKD_KYBER_L5 65526
#endif

#ifndef KE_QKD_MLKEM_L1
#define KE_QKD_MLKEM_L1 65525
#endif

#ifndef KE_QKD_MLKEM_L3
#define KE_QKD_MLKEM_L3 65524
#endif

#ifndef KE_QKD_MLKEM_L5
#define KE_QKD_MLKEM_L5 65523
#endif

#ifndef KE_QKD_BIKE_L1
#define KE_QKD_BIKE_L1 65522
#endif

#ifndef KE_QKD_BIKE_L3
#define KE_QKD_BIKE_L3 65521
#endif

#ifndef KE_QKD_BIKE_L5
#define KE_QKD_BIKE_L5 65520
#endif

#ifndef KE_QKD_HQC_L1
#define KE_QKD_HQC_L1 65519
#endif

#ifndef KE_QKD_HQC_L3
#define KE_QKD_HQC_L3 65518
#endif

#ifndef KE_QKD_HQC_L5
#define KE_QKD_HQC_L5 65517
#endif

struct qkd_kem_t {
    key_exchange_t ke;
};

qkd_kem_t *qkd_kem_create(key_exchange_method_t method);

#endif /** QKD_KEX_H_ @}*/