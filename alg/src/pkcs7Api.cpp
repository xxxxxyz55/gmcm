#include "algApi.h"
#include "openssl/x509.h"
#include "openssl/evp.h"
/*
const void *alg2evp(unsigned int alg)
{
    EVP_CIPHER *p = NULL;
    switch (alg_id)
    {
    case SGD_SM4_ECB:
    case SGD_SM4:
        return EVP_sms4_ecb();
    case SGD_SM4_CBC:
        return EVP_sms4_cbc();
    case SGD_SM4_CFB:
        return EVP_sms4_cfb();
    case SGD_SM4_OFB:
        return EVP_sms4_ofb();
    case SGD_SM4_MAC:
        break;
    case SGD_DES_ECB:
        return EVP_des_ecb();
    case SGD_DES_CBC:
        return EVP_des_cbc();
    case SGD_DES_CFB:
        return EVP_des_cfb();
    case SGD_DES_OFB:
        return EVP_des_ofb();
    case SGD_DES_CTR:
    case SGD_DES_MAC:
        break;

    case SGD_2DES_ECB:
        return EVP_des_ede_ecb();
    case SGD_2DES_CBC:
        return EVP_des_ede_cbc();
    case SGD_2DES_CFB:
        return EVP_des_ede_cfb();
    case SGD_2DES_OFB:
        return EVP_des_ede_ofb();
    case SGD_2DES_CTR:
    case SGD_2DES_MAC:
        break;

    case SGD_3DES_ECB:
        return EVP_des_ede3_ecb();
    case SGD_3DES_CBC:
        return EVP_des_ede3_cbc();
    case SGD_3DES_CFB:
        return EVP_des_ede3_cfb();
    case SGD_3DES_OFB:
        return EVP_des_ede3_ofb();
    case SGD_3DES_CTR:
    case SGD_3DES_MAC:
        break;

    case SGD_AES_ECB:
        return EVP_aes_128_ecb();
    case SGD_AES_CBC:
        return EVP_aes_128_cbc();
    case SGD_AES_CFB:
        return EVP_aes_128_cfb();
    case SGD_AES_OFB:
        return EVP_aes_128_ofb();
    case SGD_AES_CTR:
        return EVP_aes_128_ctr();
    case SGD_AES_MAC:
        break;

    case SGD_AES192_ECB:
        return EVP_aes_192_ecb();
    case SGD_AES192_CBC:
        return EVP_aes_192_cbc();
    case SGD_AES192_CFB:
        return EVP_aes_192_cfb();
    case SGD_AES192_OFB:
        return EVP_aes_192_ofb();
    case SGD_AES192_CTR:
        return EVP_aes_192_ctr();
    case SGD_AES192_MAC:
        break;

    case SGD_AES256_ECB:
        return EVP_aes_256_ecb();
    case SGD_AES256_CBC:
        return EVP_aes_256_cbc();
    case SGD_AES256_CFB:
        return EVP_aes_256_cfb();
    case SGD_AES256_OFB:
        return EVP_aes_256_ofb();
    case SGD_AES256_CTR:
        return EVP_aes_256_ctr();
    case SGD_AES256_MAC:
        break;
        //hash
    case SGD_SM3:
        return EVP_sm3();
    case SGD_SHA1:
        return EVP_sha1();
    case SGD_SHA224:
        return EVP_sha224();
    case SGD_SHA256:
        return EVP_sha256();
    case SGD_SHA512:
        return EVP_sha512();
    case SGD_SHA384:
        return EVP_sha384();
    case SGD_MD4:
        return EVP_md4();
    case SGD_MD5:
        return EVP_md5();

    case SGD_SM1_ECB:
        p = EVP_CIPHER_meth_new(NID_sm1_ecb, 16, 16);
        return p;
    case SGD_SM1_CBC:
        p = EVP_CIPHER_meth_new(NID_sm1_cbc, 16, 16);
        p->iv_len = 16;
        return p;
    case SGD_SM1_OFB:
        p = EVP_CIPHER_meth_new(NID_sm1_ofb128, 16, 16);
        p->iv_len = 16;
        return p;
    case SGD_SM1_CFB:
        p = EVP_CIPHER_meth_new(NID_sm1_cfb128, 16, 16);
        p->iv_len = 16;
        return p;

    default:
        break;
    }

    return NULL;
}

int alg_pkcs7_signdata(pkcs7_meth *pMeth, char *b64P7, char *b64Data,
                       void *key, void *cert, unsigned int alg)
{
    int ret = 0;
    PKCS7 * p7 = NULL;
    const EVP_MD *md = (EVP_MD *)id2evp_cipher(hash_alg_id);
    unsigned char sign[TOPCSP_LEN_8192] = {0};
    int sign_len = 0;
    unsigned char p7_der[MAX_CERT_LEN] = {0};
    unsigned char * p = p7_der;
    int len = 0;
    X509_ALGOR *x509_alg = NULL;
    PKCS7_SIGNER_INFO *info = NULL;

    p7 = PKCS7_new();
    if(p7 == NULL)
    {
        ret = CSP_ERR_OPENSSL_NEW;
        goto err;
    }
    //设置类型和版本
    ret = csp_pkcs7_set_type(p7, EVP_PKEY_id((EVP_PKEY *)pkey) == EVP_PKEY_EC ? NID_SS_sm2_signData : NID_pkcs7_signed);
    if (ret)
    {
        ret =  CSP_ERR_P7_TYPE;
        goto err;
    }

    //算法
    x509_alg =  X509_ALGOR_new();
    X509_ALGOR_set_md(x509_alg, md);
    sk_X509_ALGOR_push(p7->d.sign->md_algs, x509_alg);

    //原文
    if (!PKCS7_content_new(p7, EVP_PKEY_id((EVP_PKEY *)pkey) == EVP_PKEY_EC ? NID_SS_sm2_data : NID_pkcs7_data))
    {
        ret = CSP_ERR_OPENSSL_NEW;
        goto err;
    }

    if(not_detached)
    {
        ASN1_OCTET_STRING_set(p7->d.sign->contents->d.data, data, data_len);
    }

    //签名证书
    if(p7->d.sign->cert == NULL)
    {
        p7->d.sign->cert = sk_X509_new(NULL);
    }

    X509_up_ref((X509 *)x509);
    if(!sk_X509_push(p7->d.sign->cert, (X509 *)x509))
    {
        X509_free((X509 *)x509);
    }

    //crl
    //无

    //签名值
    {
        //版本 issuer and serial
        info = PKCS7_SIGNER_INFO_new();
        if (!PKCS7_SIGNER_INFO_set(info, (X509 *)x509, (EVP_PKEY *)pkey, md))
        {
            ret = CSP_ERR_PKCS7_SIGN;
            goto err;
        }

        if (info->digest_enc_alg->algorithm)
        {
                ASN1_OBJECT_free(info->digest_enc_alg->algorithm);
        }

        if (EVP_PKEY_id((EVP_PKEY *)pkey) == EVP_PKEY_EC)
        {
            info->digest_enc_alg->algorithm = OBJ_nid2obj(NID_sm2sign);
        }
        else
        {
            info->digest_enc_alg->algorithm = OBJ_nid2obj(NID_rsaEncryption);
        }

        if (sign_with_hash == NULL || EVP_PKEY_id((EVP_PKEY *)pkey) != EVP_PKEY_EC || hash_alg_id != SGD_SM3)
        {
            ret = def_sign_with_hash(data, data_len, hash_alg_id, pkey, sign, &sign_len);
        }
        else
        {
            ret = sign_with_hash(data, data_len, hash_alg_id, pkey, sign, &sign_len);
        }

        if (ret)
        {
            goto err;
        }
        //签名
        ASN1_OCTET_STRING_set(info->enc_digest, sign, sign_len);

        //该域可选
        // info->auth_attr

        sk_PKCS7_SIGNER_INFO_push(p7->d.sign->signer_info, info);
    }

    len = i2d_PKCS7(p7, &p);
    if(len <= 0)
    {
        ret = CSP_ERR_PEM_RW;
    }

    *b64_p7_len = der_to_base64(p7_der, b64_p7, len);
    if(*b64_p7_len <= 0)
    {
        ret = CSP_ERR_DECODE;
    }

err:
    if(p7) PKCS7_free(p7);
    return ret;
}
int alg_pkcs7_verify_signdata(pkcs7_meth *pMeth, char *p7)
{
    return 0;
}

int alg_pkcs7_signdata_detached(pkcs7_meth *pMeth, char *b64P7, char *b64Data,
                                void *key, void *cert, unsigned int alg)
{
    return 0;
}
int alg_pkcs7_verify_signdata_detached(pkcs7_meth *pMeth, char *p7, char *b64Data)
{
    return 0;
}

int alg_pkcs7_enveloped(pkcs7_meth *pMeth, char *p7, char *b64Data,
                        void *cert, unsigned int alg)
{
    return 0;
}
int alg_pkcs7_unpack_enveloped(pkcs7_meth *pMeth, char *p7, char *b64Data,
                               void *key)
{
    return 0;
}

int alg_pkcs7_sign_envloped(pkcs7_meth *pMeth, char *p7, char *b64Data,
                            void *signCert, void *signKey, void *encCert,
                            unsigned int alg)
{
    return 0;
}

int alg_pkcs7_unpack_sign_envloped(pkcs7_meth *pMeth, char *p7, char *b64Data,
                                   void *encKey, unsigned int alg)
{
    return 0;
}

int alg_pkcs7_encrypt(pkcs7_meth *pMeth, char *p7, char *b64Data, char *b64Cipher, void *cert)
{
    return 0;
}
int alg_pkcs7_unpack_encrypt(pkcs7_meth *pMeth, char *p7, char *b64Data, char *b64Cipher, void *key)
{
    return 0;
}
*/