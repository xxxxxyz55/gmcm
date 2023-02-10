#ifndef _GMCM_ALG_API_H_
#define _GMCM_ALG_API_H_


#include "gmcmSdf.h"

#ifndef EXPORT_FUNC
#define EXPORT_FUNC
#endif

EXPORT_FUNC void openssl_err_stack();

EXPORT_FUNC int alg_random(unsigned int length, unsigned char * buf);

EXPORT_FUNC int alg_sm2_gen_pri(unsigned char *pri);
EXPORT_FUNC int alg_sm2_pri_gen_pub(unsigned char *pri, unsigned char *pub_x, unsigned char *pub_y);
EXPORT_FUNC int alg_sm2_gen_key_pair(ECCrefPublicKey *pPub, ECCrefPrivateKey *pPri);

EXPORT_FUNC int alg_sm2_pub_encrypt(ECCrefPublicKey *pPub, unsigned char *data, unsigned int dataLen, ECCCipher *cipher);
EXPORT_FUNC int alg_sm2_pri_decrypt(ECCrefPrivateKey *pPri, ECCCipher *cipher, unsigned char *data, unsigned int *dataLen);
EXPORT_FUNC int alg_sm2_sign(ECCrefPrivateKey *pPri, unsigned char *data, unsigned int dataLen, ECCSignature *sign);
EXPORT_FUNC int alg_sm2_verify(ECCrefPublicKey *pPub, unsigned char *data, unsigned int dataLen, ECCSignature *sign);

#define MAX_DATA_LEN   8192
EXPORT_FUNC int alg_sm4_encrypt(unsigned char *key, unsigned int algid, unsigned int pad,
                                unsigned char *in, unsigned int inLen,
                                unsigned char *iv, unsigned int ivLen,
                                unsigned char *out, unsigned int *outLen);
EXPORT_FUNC int alg_sm4_decrypt(unsigned char *key, unsigned int algid, unsigned int pad,
                                unsigned char *in, unsigned int inLen,
                                unsigned char *iv, unsigned int ivLen,
                                unsigned char *out, unsigned int *outLen);

EXPORT_FUNC int alg_sm3_init(unsigned char *pSm3Ctx, unsigned int *ctxLen, unsigned char *pubX, unsigned char *pubY, unsigned char *id, unsigned int idLen);
EXPORT_FUNC void alg_sm3_update(unsigned char *pSm3Ctx, unsigned char *data, unsigned int dataLen);
EXPORT_FUNC void alg_sm3_final(unsigned char *pSm3Ctx, unsigned char *hash);

#endif