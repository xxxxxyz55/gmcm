#include "gmcmalgConf.h"
#include "../include/algApi.h"
#include "../include/softSdfApi.h"
#include "utilFunc.h"
#include "openssl/rand.h"
#include "openssl/ec.h"
#include "openssl/obj_mac.h"
#include <string.h>
#include "openssl/sms4.h"
#include "openssl/sm3.h"
#include "openssl/sm2.h"
#include "openssl/err.h"
#include "openssl/pem.h"

void openssl_err_stack()
{
    int ret = ERR_get_error();
    while (ret)
    {
        printf("%d\n", ret);
        printf("ERR FUN :%s\n", ERR_func_error_string(ret));
        printf("ERR reason :%s\n", ERR_reason_error_string(ret));
        ret = ERR_get_error();
    }
    return;
}

int alg_random(unsigned int length, unsigned char *buf)
{
    if (RAND_bytes(buf, length) <= 0)
    {
        return -1;
    }
    return 0;
}

int alg_str_to_int(const char *alg)
{
    int len = strlen(alg);

    //alg len
#define STR_ALG_TO_INT(dst, num)                            \
    if (len == (sizeof(dst) - 1) && !memcmp(alg, dst, len)) \
    {                                                       \
        return num;                                         \
    }

    STR_ALG_TO_INT("SM2", SGD_SM2)
    STR_ALG_TO_INT("sm2", SGD_SM2)
    STR_ALG_TO_INT("RSA", SGD_RSA)
    STR_ALG_TO_INT("rsa", SGD_RSA)
    
    //cert usage
    STR_ALG_TO_INT("CA", USAGE_CA)
    STR_ALG_TO_INT("SIGN", USAGE_SIGN)
    STR_ALG_TO_INT("ENC", USAGE_ENC)
    STR_ALG_TO_INT("TLS", USAGE_TLS)
    STR_ALG_TO_INT("WEB", USAGE_WEB)
    STR_ALG_TO_INT("TSA", USAGE_TSA)
    STR_ALG_TO_INT("IPSEC", USAGE_IPSEC)
    STR_ALG_TO_INT("EMAIL", USAGE_EMAIL)
    STR_ALG_TO_INT("CARD", USAGE_CARD)

    return 0;
}

static char *str_del_lf(char * str)
{
    char *pDst = str;
    char *pSrc = str;
    for (; *pSrc != '\0';)
    {
        if(*pSrc != '\n')
        {
            *pDst = *pSrc;
            ++pDst;
            ++pSrc;
        }
        else
        {
            pSrc++;
        }
    }
    *pDst = '\0';
    return str;
}

char *alg_pem_get_base64(char *alg)
{
    char *p = strstr(alg, "-----BEGIN");
    if (p != NULL)
    {
        char *head = strstr(p, "\n");
        if (head != NULL)
        {
            head++;
            char *end = strstr(head, "-----END");
            if (end != NULL)
            {
                *(end - 1) = '\0';
                return str_del_lf(head);
            }
        }
    }

    return NULL;
}

int alg_sm2_gen_pri(unsigned char * pri)
{
    int iRet = alg_random(32, pri);
    if (iRet)
    {
        return iRet;
    }
    else
    {
        for (size_t i = 0; i < 8; i++)
        {
            if (*(unsigned int *)(pri + (i * 4)))
            {
                return 0;
            }
        }
    }
    return alg_sm2_gen_pri(pri);
}

int alg_sm2_pri_gen_pub(unsigned char * pri, unsigned char * pub_x, unsigned char * pub_y)
{
    BIGNUM *bn_pri = BN_bin2bn(pri, 32, NULL);
    int ret = 0;

    BN_CTX *bn_ctx = BN_CTX_new();
    const EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);
    EC_POINT *point = EC_POINT_new(group);
    BIGNUM *x;
    BIGNUM *y;

    BN_CTX_start(bn_ctx);
    x = BN_CTX_get(bn_ctx);
    y = BN_CTX_get(bn_ctx);
    if (x == NULL || y == NULL)
    {
        ret = -1;
    }
    else
    {
        if(!EC_POINT_mul(group, point, bn_pri, NULL, NULL, bn_ctx))
        {
            ret = -1;
        }
        else
        {
            if (!EC_POINT_get_affine_coordinates_GFp(group, point, x, y, bn_ctx))
            {
                ret = -1;
            }

            if (!ret)
            {
                BN_bn2bin(x, pub_x + 32 - BN_num_bytes(x));
                BN_bn2bin(y, pub_y + 32 - BN_num_bytes(y));
            }
        }
    }

    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    EC_GROUP_free((EC_GROUP *)group);
    EC_POINT_free(point);
    BN_free(bn_pri);
    return ret;
}

int alg_sm2_gen_key_pair(ECCrefPublicKey *pPub, ECCrefPrivateKey *pPri)
{
    pPri->bits = SM2_BITS;
    pPub->bits = SM2_BITS;
    if (alg_sm2_gen_pri(pPri->K + 32) || alg_sm2_pri_gen_pub(pPri->K + 32, pPub->x + 32, pPub->y + 32))
    {
        return -1;
    }
    else
    {
        return 0;
    }
}

static void rsa_to_bin(RSA *rsa, RSArefPublicKey *pPub, RSArefPrivateKey *pPri)
{
    if (pPub)
    {
        const BIGNUM *n, *e, *d;
        RSA_get0_key(rsa, &n, &e, &d);
        pPub->bits = BN_num_bits(n);
        BN_bn2bin(n, pPub->m + sizeof(pPub->m) - BN_num_bytes(n));
        BN_bn2bin(e, pPub->e + sizeof(pPub->e) - BN_num_bytes(e));
    }

    if (pPri)
    {
        const BIGNUM *n, *e, *d, *p, *q, *dp, *dq, *coef;
        RSA_get0_key(rsa, &n, &e, &d);
        RSA_get0_factors(rsa, &p, &q);
        RSA_get0_crt_params(rsa, &dp, &dq, &coef);

        pPri->bits = BN_num_bits(n);
        BN_bn2bin(n, pPri->m + sizeof(pPri->m) - BN_num_bytes(n));
        BN_bn2bin(e, pPri->e + sizeof(pPri->e) - BN_num_bytes(e));
        BN_bn2bin(d, pPri->d + sizeof(pPri->d) - BN_num_bytes(d));
        BN_bn2bin(p, pPri->prime[0] + sizeof(pPri->prime[0]) - BN_num_bytes(p));
        BN_bn2bin(q, pPri->prime[1] + sizeof(pPri->prime[1]) - BN_num_bytes(q));
        BN_bn2bin(dp, pPri->pexp[0] + sizeof(pPri->pexp[0]) - BN_num_bytes(dp));
        BN_bn2bin(dq, pPri->pexp[1] + sizeof(pPri->pexp[1]) - BN_num_bytes(dq));
        BN_bn2bin(coef, pPri->coef + sizeof(pPri->coef) - BN_num_bytes(coef));
    }
}

int alg_rsa_gen_key_pair(int bits, unsigned long e, RSArefPublicKey *pPub, RSArefPrivateKey *pPri)
{
    if(bits > RSAref_MAX_BITS)
    {
        ALG_LOG_ERROR("support max bits %d", RSAref_MAX_BITS);
        return -1;
    }

    RSA *rsa = RSA_new();
    BIGNUM *bE = BN_new();
    int iRet = 0;
    if(rsa == NULL || bE == NULL)
    {
        RSA_free(rsa);
        BN_free(bE);
        return -1;
    }

    BN_set_word(bE, e);
    if (RSA_generate_key_ex(rsa, bits, bE, NULL) <= 0)
    {
        iRet = -1;
        ALG_LOG_ERROR("generate rsa fail.");
    }
    else
    {
        rsa_to_bin(rsa, pPub, pPri);
    }

    RSA_free(rsa);
    BN_free(bE);
    return iRet;
}

void alg_padding_pkcs7(unsigned int block,
                      unsigned char *in, unsigned int inLen,
                      unsigned char *out, unsigned int *outLen)
{
    unsigned int padLen = block - (inLen % block);
    *outLen = inLen + padLen;

    memcpy(out, in, inLen);
    for (size_t i = inLen; i < *outLen; i++)
    {
        out[i] = padLen;
    }
}

void alg_delpadding_pkcs7(unsigned int block,
                         unsigned char *in, unsigned int inLen,
                         unsigned char *out, unsigned int *outLen)
{
    unsigned int padLen = in[inLen - 1];
    if (padLen > block)
    {
        padLen = 0;
    }

    memcpy(out, in, inLen - padLen);
    *outLen = inLen - padLen;
}

void sm4_ecb_encrypt(unsigned char *key, unsigned int enc,
                     unsigned char *in, unsigned int inLen,
                     unsigned char *out, unsigned int *outLen)
{
    sms4_key_t sm4Key;
    if(enc)
    {
        sms4_set_encrypt_key(&sm4Key, key);

        for (unsigned int i = 0; i < inLen; i += 16)
        {
            sms4_encrypt(in + i, out + i, &sm4Key);
        }
    }
    else
    {
        sms4_set_decrypt_key(&sm4Key, key);
        for (unsigned int i = 0; i < inLen; i += 16)
        {
            sms4_encrypt(in + i, out + i, &sm4Key);
        }
    }
    *outLen = inLen;
}

void sm4_cbc_encrypt(unsigned char *key, unsigned int enc,
                     unsigned char *in, unsigned int inLen,
                     unsigned char *iv, unsigned int ivLen,
                     unsigned char *out, unsigned int *outLen)
{
    sms4_key_t sm4Key;
    if(enc)
    {
        sms4_set_encrypt_key(&sm4Key, key);
    }
    else
    {
        sms4_set_decrypt_key(&sm4Key, key);
    }
    sms4_cbc_encrypt(in, out, inLen, &sm4Key, iv, enc);
}

void sm4_cfb_encrypt(unsigned char *key, unsigned int enc,
                     unsigned char *in, unsigned int inLen,
                     unsigned char *iv, unsigned int ivLen,
                     unsigned char *out, unsigned int *outLen)
{
    sms4_key_t sm4Key;
    int num = 0;
    if(enc)
    {
        sms4_set_encrypt_key(&sm4Key, key);
    }
    else
    {
        sms4_set_decrypt_key(&sm4Key, key);
    }

    sms4_cfb128_encrypt(in, out, inLen, &sm4Key, iv, &num, enc);
    *outLen = inLen;
}

void sm4_ofb_encrypt(unsigned char *key, unsigned int enc,
                     unsigned char *in, unsigned int inLen,
                     unsigned char *iv, unsigned int ivLen,
                     unsigned char *out, unsigned int *outLen)
{
    sms4_key_t sm4Key;
    int num = 0;
    if(enc)
    {
        sms4_set_encrypt_key(&sm4Key, key);
    }
    else
    {
        sms4_set_decrypt_key(&sm4Key, key);
    }

    sms4_ofb128_encrypt(in, out, inLen, &sm4Key, iv, &num);
    *outLen = inLen;
}

int alg_sm4_encrypt(unsigned char *key, unsigned int algid, unsigned int pad,
                    unsigned char *in, unsigned int inLen,
                    unsigned char *iv, unsigned int ivLen,
                    unsigned char *out, unsigned int *outLen)
{
    if (inLen > MAX_DATA_LEN)
    {
        return -1;
    }

    unsigned char * pdata = in;
    unsigned int  dataLen = inLen;
    unsigned char padBuf[MAX_DATA_LEN + 16];
    unsigned int padLen;

    if (pad)
    {
        alg_padding_pkcs7(16, in, inLen, padBuf, &padLen);
        pdata = padBuf;
        dataLen = padLen;
    }

    switch (algid)
    {
    case SGD_SM4_ECB:
        sm4_ecb_encrypt(key, 1, pdata, dataLen, out, outLen);
        break;
    case SGD_SM4_CBC:
        sm4_cbc_encrypt(key, 1, pdata, dataLen, iv, ivLen, out, outLen);
        break;
    case SGD_SM4_CFB:
        sm4_cfb_encrypt(key, 1, pdata, dataLen, iv, ivLen, out, outLen);
        break;
    case SGD_SM4_OFB:
        sm4_ofb_encrypt(key, 1, pdata, dataLen, iv, ivLen, out, outLen);
        break;
    
    default:
        return -1;
    }

    return 0;
}

int alg_sm4_decrypt(unsigned char *key, unsigned int algid, unsigned int pad,
                    unsigned char *in, unsigned int inLen,
                    unsigned char *iv, unsigned int ivLen,
                    unsigned char *out, unsigned int *outLen)
{
    if (inLen > MAX_DATA_LEN + 16 || inLen % 16 != 0)
    {
        return -1;
    }

    unsigned char * pDec = out;
    unsigned int decLen;
    unsigned char decBuf[MAX_DATA_LEN + 16];
    if(pad)
    {
        pDec = decBuf;
    }

    switch (algid)
    {
    case SGD_SM4_ECB:
        sm4_ecb_encrypt(key, 0, in, inLen, pDec, &decLen);
        break;
    case SGD_SM4_CBC:
    case SGD_SM4_MAC:
        sm4_cbc_encrypt(key, 0, in, inLen, iv, ivLen, pDec, &decLen);
        break;
    case SGD_SM4_CFB:
        sm4_cfb_encrypt(key, 0, in, inLen, iv, ivLen, pDec, &decLen);
        break;
    case SGD_SM4_OFB:
        sm4_ofb_encrypt(key, 0, in, inLen, iv, ivLen, pDec, &decLen);
        break;

    default:
        return -1;
    }

    if (pad)
    {
        alg_delpadding_pkcs7(16, pDec, decLen, out, outLen);
    }
    else
    {
        *outLen = decLen;
    }

    return 0;
}

void alg_sm3_get_z(unsigned char *pubX, unsigned char *pubY, unsigned char *id, unsigned int idLen, unsigned char * z)
{
    sm3_ctx_t ctx;
	uint8_t zin[18 + 32 * 6] = {
		0x00, 0x80,
		0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
		0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFC,
		0x28,0xE9,0xFA,0x9E,0x9D,0x9F,0x5E,0x34,0x4D,0x5A,0x9E,0x4B,0xCF,0x65,0x09,0xA7,
		0xF3,0x97,0x89,0xF5,0x15,0xAB,0x8F,0x92,0xDD,0xBC,0xBD,0x41,0x4D,0x94,0x0E,0x93,
        0x32,0xC4,0xAE,0x2C,0x1F,0x19,0x81,0x19,0x5F,0x99,0x04,0x46,0x6A,0x39,0xC9,0x94,
		0x8F,0xE3,0x0B,0xBF,0xF2,0x66,0x0B,0xE1,0x71,0x5A,0x45,0x89,0x33,0x4C,0x74,0xC7,
		0xBC,0x37,0x36,0xA2,0xF4,0xF6,0x77,0x9C,0x59,0xBD,0xCE,0xE3,0x6B,0x69,0x21,0x53,
		0xD0,0xA9,0x87,0x7C,0xC6,0x2A,0x47,0x40,0x02,0xDF,0x32,0xE5,0x21,0x39,0xF0,0xA0,
	};

    memcpy(&zin[18 + 32 * 4], pubX, 32);
    memcpy(&zin[18 + 32 * 5], pubY, 32);

    sm3_init(&ctx);
    uint8_t idbits[2];
    idbits[0] = (uint8_t)(idLen >> 5);
    idbits[1] = (uint8_t)(idLen << 3);

    sm3_update(&ctx, idbits, 2);
    sm3_update(&ctx, (uint8_t *)id, idLen);
    sm3_update(&ctx, zin + 18, 32 * 6);
    sm3_final(&ctx, z);
}

int alg_sm3_init(unsigned char *psm3Ctx, unsigned int *ctxLen, unsigned char *pubX, unsigned char *pubY, unsigned char *id, unsigned int idLen)
{
    if (*ctxLen < sizeof(sm3_ctx_t))
    {
        return -1;
    }

    sm3_ctx_t ctx;
    sm3_init(&ctx);
    if (idLen && pubX && pubY)
    {
        unsigned char z[32];
        alg_sm3_get_z(pubX, pubY, id, idLen, z);
        sm3_update(&ctx, z, 32);
    }

    memcpy(psm3Ctx, &ctx, sizeof(sm3_ctx_t));
    *ctxLen = sizeof(sm3_ctx_t);
    return 0;
}

void alg_sm3_update(unsigned char *pSm3Ctx, unsigned char *data, unsigned int dataLen)
{
    sm3_update((sm3_ctx_t *)pSm3Ctx, data, dataLen);
}

void alg_sm3_final(unsigned char *pSm3Ctx, unsigned char *hash)
{
    sm3_final((sm3_ctx_t *)pSm3Ctx, hash);
}

EC_KEY * alg_sm2_sdf_key_to_eckey(ECCrefPublicKey *pPub, ECCrefPrivateKey *pPri)
{
    unsigned char pubx[32] = {0};
    unsigned char puby[32] = {0};
    unsigned char *pPubx = NULL;
    unsigned char *pPuby = NULL;

    if(pPub == NULL)
    {
        alg_sm2_pri_gen_pub(pPri->K + 32, pubx, puby);
        pPubx = pubx;
        pPuby = puby;
    }
    else
    {
        pPubx = pPub->x + 32;
        pPuby = pPub->y + 32;
    }

    BIGNUM *bn_x = NULL, *bn_y = NULL;
    EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_sm2p256v1);
    EC_POINT *pub_key = EC_POINT_new(EC_KEY_get0_group(eckey));
    int ret = 0;

    if (pub_key == NULL)
    {
        ret = -1;
    }
    else
    {
        bn_x = BN_bin2bn(pPubx, 32, NULL);
        bn_y = BN_bin2bn(pPuby, 32, NULL);

        if (!(EC_POINT_set_affine_coordinates_GFp(EC_KEY_get0_group(eckey), pub_key, bn_x, bn_y, NULL)))
        {
            ret = -1;
        }
        else
        {

            EC_KEY_set_public_key(eckey, pub_key);
            // PEM_write_EC_PUBKEY(stdout, eckey);
            if (pPri)
            {
                BIGNUM *bn_k = BN_bin2bn(pPri->K + 32, 32, NULL);
                if (!EC_KEY_set_private_key(eckey, bn_k))
                {
                    ret = -1;
                }
                // PEM_write_ECPrivateKey(stdout, eckey, NULL, NULL, 0, NULL, NULL);
            }
        }
        BN_free(bn_x);
        BN_free(bn_y);
    }

    EC_POINT_free(pub_key);
    if (ret)
    {
        EC_KEY_free(eckey);
        eckey = NULL;
    }

    return eckey;
}

#ifndef _SM2_LCL_
//copy from sm2_lcl.h
struct SM2CiphertextValue_st
{
    BIGNUM *xCoordinate;
    BIGNUM *yCoordinate;
    ASN1_OCTET_STRING *hash;
    ASN1_OCTET_STRING *ciphertext;
};


struct ECDSA_SIG_st {
    BIGNUM *r;
    BIGNUM *s;
};
#endif

void alg_sm2_SM2CiphertextValue_to_ECCCIPHER(SM2CiphertextValue *sm2Enc, ECCCipher *cipher)
{
    BN_bn2bin(sm2Enc->xCoordinate, cipher->x + 64 - BN_num_bytes(sm2Enc->xCoordinate));
    BN_bn2bin(sm2Enc->yCoordinate, cipher->y + 64 - BN_num_bytes(sm2Enc->yCoordinate));
    memcpy(cipher->M, sm2Enc->hash->data, sm2Enc->hash->length);
    cipher->L = sm2Enc->ciphertext->length;
    memcpy(cipher->C, sm2Enc->ciphertext->data, sm2Enc->ciphertext->length);
}

void alg_sm2_ECCCIPHER_to_SM2CiphertextValue(ECCCipher *cipher, SM2CiphertextValue *sm2Enc)
{
    ASN1_OCTET_STRING_set(sm2Enc->ciphertext, cipher->C, cipher->L);
    BN_bin2bn(cipher->x + 32, 32, sm2Enc->xCoordinate);
    BN_bin2bn(cipher->y + 32, 32, sm2Enc->yCoordinate);
    ASN1_OCTET_STRING_set(sm2Enc->hash, cipher->M, 32);
}

int alg_sm2_pub_encrypt(ECCrefPublicKey *pPub, unsigned char *data, unsigned int dataLen, ECCCipher *cipher)
{
    EC_KEY *eckey = alg_sm2_sdf_key_to_eckey(pPub, NULL);
    int ret =0;

    if(eckey == NULL)
    {
        ALG_LOG_ERROR("sm2 pub err.");
        ret = -1;
    }
    else
    {

        SM2CiphertextValue *sm2Enc = SM2_do_encrypt(EVP_sm3(), data, dataLen, eckey);
        if (sm2Enc == NULL)
        {
            ALG_LOG_ERROR("sm2 encrypt err.");
            openssl_err_stack();
            ret = -1;
        }
        else
        {
            alg_sm2_SM2CiphertextValue_to_ECCCIPHER(sm2Enc, cipher);
            SM2CiphertextValue_free(sm2Enc);
        }
        
        EC_KEY_free(eckey);
    }
    return ret;
}

int alg_sm2_pri_decrypt(ECCrefPrivateKey *pPri, ECCCipher *cipher, unsigned char *data, unsigned int *dataLen)
{
    int ret = 0;
    EC_KEY * eckey = alg_sm2_sdf_key_to_eckey(NULL, pPri);
    if (eckey == NULL)
    {
        ALG_LOG_ERROR("sm2 pub err.");
        ret = -1;
    }
    else
    {
        SM2CiphertextValue *sm2Enc = SM2CiphertextValue_new();
        if(sm2Enc == NULL)
        {
            ret = -1;
        }
        else
        {
            alg_sm2_ECCCIPHER_to_SM2CiphertextValue(cipher, sm2Enc);
            size_t outLen = 0;
            if (!SM2_do_decrypt(EVP_sm3(), sm2Enc, data, &outLen, eckey))
            {
                ret = -1;
            }
            else
            {
                *dataLen = outLen;
            }
            SM2CiphertextValue_free(sm2Enc);
        }
        EC_KEY_free(eckey);
    }
    return ret;
}

int alg_sm2_sign(ECCrefPrivateKey *pPri, unsigned char * data, unsigned int dataLen, ECCSignature *sign)
{
    int ret = 0;
    EC_KEY *eckey = alg_sm2_sdf_key_to_eckey(NULL, pPri);
    if (eckey == NULL)
    {
        ALG_LOG_ERROR("sm2 pri err.");
        ret = -1;
    }
    else
    {
        ECDSA_SIG *sig = SM2_do_sign(data, dataLen, eckey);
        if (sig == NULL)
        {
            ALG_LOG_ERROR("sm2 sign err.");
            ret = -1;
        }
        else
        {
            BN_bn2bin(sig->r, sign->r + 64 - BN_num_bytes(sig->r));
            BN_bn2bin(sig->s, sign->s + 64 - BN_num_bytes(sig->s));
            ECDSA_SIG_free(sig);
        }
        EC_KEY_free(eckey);
    }
    return ret;
}

int alg_sm2_verify(ECCrefPublicKey *pPub, unsigned char *data, unsigned int dataLen, ECCSignature *sign)

{
    int ret = 0;
    EC_KEY *eckey = alg_sm2_sdf_key_to_eckey(pPub, NULL);
    if (eckey == NULL)
    {
        ALG_LOG_ERROR("sm2 pub err.");
        ret = -1;
    }
    else
    {
        ECDSA_SIG *sig = ECDSA_SIG_new();
        if(sig == NULL)
        {
            ret = -1;
        }
        else
        {
            sig->r = BN_bin2bn(sign->r + 32, 32, NULL);
            sig->s = BN_bin2bn(sign->s + 32, 32, NULL);

            if (!SM2_do_verify(data, dataLen, sig, eckey))
            {
                ret = -1;
            }
            else
            {
                
            }
            ECDSA_SIG_free(sig);
        }
        EC_KEY_free(eckey);
    }

    return ret;
    
}

int alg_sm2_import(char *sPem, ECCrefPublicKey *pPub, ECCrefPrivateKey *pPri)
{
    void * pKey = NULL;

    if (alg_pem_import_key(sPem, &pKey))
    {
        ALG_LOG_ERROR("import key fail.");
        return GMCM_FAIL;
    }

    int iRet = GMCM_OK;
    EC_KEY *pEckey = EVP_PKEY_get0_EC_KEY((EVP_PKEY *)pKey);
    if(pEckey == NULL)
    {
        iRet = GMCM_FAIL;
    }
    else
    {
        if(pPub)
        {
            BIGNUM *x = BN_new();
            BIGNUM *y = BN_new();
            const EC_POINT *pPoint = EC_KEY_get0_public_key(pEckey);
            if (EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(pEckey),
                                                    pPoint, x, y, NULL) <= 0)
            {
                iRet = GMCM_FAIL;
            }
            else
            {
                pPub->bits = SM2_BITS;
                BN_bn2bin(x, pPub->x + sizeof(pPub->x) - BN_num_bytes(x));
                BN_bn2bin(y, pPub->y + sizeof(pPub->y) - BN_num_bytes(x));
            }
            BN_free(x);
            BN_free(y);
        }

        if(pPri)
        {
            const BIGNUM *k = EC_KEY_get0_private_key(pEckey);
            pPri->bits = SM2_BITS;
            BN_bn2bin(k, pPri->K + sizeof(pPri->K) - BN_num_bytes(k));
        }
    }

    alg_free_key(&pKey);
    return iRet;
}

int alg_rsa_import(char *sPem, RSArefPublicKey *pPub, RSArefPrivateKey *pPri)
{
    void * pKey = NULL;

    if (alg_pem_import_key(sPem, &pKey))
    {
        ALG_LOG_ERROR("import key fail.");
        return GMCM_FAIL;
    }

    int iRet = GMCM_OK;
    RSA *rsa = EVP_PKEY_get0_RSA((EVP_PKEY *)pKey);
    if(rsa == NULL)
    {
        iRet = GMCM_FAIL;
    }
    else
    {
        rsa_to_bin(rsa, pPub, pPri);
    }

    alg_free_key(&pKey);
    return iRet;
}