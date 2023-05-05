#include "gmcmalgConf.h"
#include "../include/algApi.h"
#include <string.h>
#include "openssl/x509.h"
#include "openssl/bio.h"
#include "openssl/pem.h"
#include "openssl/conf.h"
#include "openssl/err.h"
#include "openssl/x509v3.h"
#include "openssl/evp.h"
#include "openssl/bn.h"
#include "utilFunc.h"
using namespace std;

#define OPENSSL_ERR                                                             \
    do                                                                          \
    {                                                                           \
        int err;                                                                \
        while ((err = ERR_get_error()))                                         \
        {                                                                       \
            printf("err [%d] line [%d] func [%s]\n", err, __LINE__, __func__); \
            printf("func   [%s]\n", ERR_func_error_string(err));                  \
            printf("reason [%s]\n", ERR_reason_error_string(err));                \
        }                                                                       \
    } while (0);

int alg_pem_import_cert(const char *b64Cert, void **pCert)
{
    int iRet = GMCM_OK;

    if (strstr(b64Cert, "-----BEGIN ") == NULL)
    {
        unsigned int b64Len = strlen(b64Cert);
        unsigned char *derCert = new unsigned char[b64Len];
        const unsigned char *pDer = derCert;

        unsigned int derLen = base64::base64Decode(b64Cert, b64Len, derCert);
        if (derLen == 0)
        {
            ALG_LOG_ERROR("base64 data decode fail.");
            iRet = GMCM_FAIL;
        }
        else
        {
            *pCert = (void *)d2i_X509(NULL, &pDer, derLen);
            if (*pCert == NULL)
            {
                ALG_LOG_ERROR("d2i cert fail.");
                iRet = GMCM_FAIL;
            }
        }
        delete derCert;
    }
    else
    {
        BIO *bp = BIO_new(BIO_s_mem());
        if (BIO_write(bp, b64Cert, strlen(b64Cert)) <= 0)
        {
            iRet = GMCM_FAIL;
        }
        else
        {
            *pCert = PEM_read_bio_X509(bp, NULL, NULL, NULL);
            if (*pCert == NULL)
            {
                OPENSSL_ERR
                ALG_LOG_ERROR("pem read cert fail.");
                iRet = GMCM_FAIL;
            }
        }
        BIO_free(bp);
    }

    return iRet;
}

void alg_free_cert(void ** pCert)
{
    if (pCert && *(X509 **)pCert)
    {
        // PEM_write_X509(stdout, (X509 *)*pCert);
        X509_free(*(X509 **)pCert);
        *pCert = NULL;
    }
}

int alg_pem_import_key(const char *b64Key, void **pKey)
{
    int iRet = GMCM_OK;

    if (strstr(b64Key, "-----BEGIN ") == NULL)
    {
        unsigned int b64Len = strlen(b64Key);
        unsigned char *derKey = new unsigned char[b64Len];
        const unsigned char *pDer = derKey;

        unsigned int derLen = base64::base64Decode(b64Key, b64Len, derKey);
        if (derLen == 0)
        {
            ALG_LOG_DEBUG("key [%s]", b64Key);
            ALG_LOG_ERROR("base64 data decode fail.");
            iRet = GMCM_FAIL;
        }
        else
        {
            *pKey = (void *)d2i_PrivateKey(EVP_PKEY_EC, NULL, &pDer, derLen);
            if (*pKey == NULL)
            {
                pDer = derKey;
                *pKey = (void *)d2i_PrivateKey(EVP_PKEY_RSA2, NULL, &pDer, derLen);
                if (*pKey == NULL)
                {
                    ALG_LOG_ERROR("d2i pkey fail.");
                    iRet = GMCM_FAIL;
                }
            }
        }
        delete derKey;
    }
    else
    {
        BIO *bp = BIO_new(BIO_s_mem());
        if (BIO_write(bp, b64Key, strlen(b64Key)) <= 0)
        {
            ALG_LOG_ERROR("bio write fail.");
            iRet = GMCM_FAIL;
        }
        else
        {
            *pKey = PEM_read_bio_PrivateKey(bp, NULL, NULL, NULL);
            if (*pKey == NULL)
            {
                ALG_LOG_ERROR("pem read prikey fail.");
                iRet = GMCM_FAIL;
            }
        }
        BIO_free(bp);
    }

    return iRet;
}


void alg_free_key(void **pKey)
{
    if (pKey && *pKey)
    {
        // PEM_write_PrivateKey(stdout, (EVP_PKEY *)*pKey, NULL, NULL, 0, NULL, 0);
        EVP_PKEY_free((EVP_PKEY *)*pKey);
        *pKey = NULL;
    }
}

static int alg_pkey_new_from_sm2(ECCrefPublicKey *pPub, ECCrefPrivateKey *pPri, EVP_PKEY **pKey)
{
    if (pPub == NULL && pPri == NULL)
    {
        ALG_LOG_ERROR("param null.");
        return GMCM_FAIL;
    }

    EVP_PKEY * evpKey = EVP_PKEY_new();
    EC_KEY *pEckey = EC_KEY_new_by_curve_name(NID_sm2p256v1);
    if(evpKey == NULL || pEckey == NULL)
    {
        EVP_PKEY_free(evpKey);
        EC_KEY_free(pEckey);
        return GMCM_FAIL;
    }

    if (pPub != NULL)
    {
        BIGNUM *x = BN_bin2bn(pPub->x + 32, 32, NULL);
        BIGNUM *y = BN_bin2bn(pPub->y + 32, 32, NULL);
        if (EC_KEY_set_public_key_affine_coordinates(pEckey, x, y) <= 0)
        {
            OPENSSL_ERR
        }
        BN_free(x);
        BN_free(y);
    }

    if (pPri != NULL)
    {
        BIGNUM *k = BN_bin2bn(pPri->K + 32, 32, NULL);
        EC_KEY_set_private_key(pEckey, k);
        BN_free(k);
    }

    EVP_PKEY_set1_EC_KEY(evpKey, pEckey);
    EC_KEY_free(pEckey);
    *pKey = evpKey;
    return GMCM_OK;
}

static int alg_pkey_new_from_rsa(RSArefPublicKey *pPub, RSArefPrivateKey *pPri, EVP_PKEY **pKey)
{
    if(pPub == NULL && pPri == NULL)
    {
        ALG_LOG_ERROR("param null.");
        return GMCM_FAIL;
    }

    EVP_PKEY * evpKey = EVP_PKEY_new();
    RSA *rsa = RSA_new();
    if (evpKey == NULL || rsa == NULL)
    {
        EVP_PKEY_free(evpKey);
        RSA_free(rsa);
    }

    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    BIGNUM *d = NULL;

    if(pPri != NULL)
    {
        n = BN_bin2bn(pPri->m, sizeof(pPri->m), NULL);
        e = BN_bin2bn(pPri->e, sizeof(pPri->e), NULL);
        d = BN_bin2bn(pPri->d, sizeof(pPri->d), NULL);
        BIGNUM *p, *q, *dp, *dq, *coef;
        p = BN_bin2bn(pPri->prime[0], sizeof(pPri->prime[0]), NULL);
        q = BN_bin2bn(pPri->prime[1], sizeof(pPri->prime[1]), NULL);
        dp = BN_bin2bn(pPri->pexp[0], sizeof(pPri->pexp[0]), NULL);
        dq = BN_bin2bn(pPri->pexp[1], sizeof(pPri->pexp[1]), NULL);
        coef = BN_bin2bn(pPri->coef, sizeof(pPri->coef), NULL);
        RSA_set0_factors(rsa, p, q);
        RSA_set0_crt_params(rsa, dp, dq, coef);
    }
    else
    {
        n = BN_bin2bn(pPub->m, sizeof(pPub->m), NULL);
        e = BN_bin2bn(pPub->e, sizeof(pPub->e), NULL);
    }

    RSA_set0_key(rsa, n, e, d);
    EVP_PKEY_set1_RSA(evpKey, rsa);
    RSA_free(rsa);
    *pKey =  evpKey;
    return 0;
}

static CONF * load_conf(const char * sConf)
{
    BIO *bConf = BIO_new(BIO_s_mem());
    CONF *pConf = NCONF_new(NULL);
    if (bConf == NULL || pConf == NULL)
    {
        BIO_free(bConf);
        NCONF_free(pConf);
        return NULL;
    }

    int32_t iRet = GMCM_OK;
    if(BIO_write(bConf, sConf, strlen(sConf)) <= 0)
    {
        ALG_LOG_ERROR("read conf fail.");
        iRet = GMCM_FAIL;
    }
    else
    {
        long iLine = -1;
        if(NCONF_load_bio(pConf, bConf, &iLine) <= 0)
        {
            ALG_LOG_ERROR("load conf fail.");
            iRet = GMCM_FAIL;
        }
    }

    if (iRet)
    {
        NCONF_free(pConf);
        pConf = NULL;
    }

    BIO_free(bConf);
    return pConf;
}

static X509_NAME *parse_name(const char *cp, long chtype, int canmulti)
{
    int nextismulti = 0;
    char *work;
    X509_NAME *n;

    if (*cp++ != '/')
        return NULL;

    n = X509_NAME_new();
    if (n == NULL)
        return NULL;
    work = OPENSSL_strdup(cp);
    if (work == NULL)
        goto err;

    while (*cp) {
        char *bp = work;
        char *typestr = bp;
        unsigned char *valstr;
        int nid;
        int ismulti = nextismulti;
        nextismulti = 0;

        /* Collect the type */
        while (*cp && *cp != '=')
            *bp++ = *cp++;
        if (*cp == '\0')
        {
            ALG_LOG_DEBUG("Hit end of string before finding the equals.");
            goto err;
        }
        *bp++ = '\0';
        ++cp;

        /* Collect the value. */
        valstr = (unsigned char *)bp;
        for (; *cp && *cp != '/'; *bp++ = *cp++)
        {
            if (canmulti && *cp == '+')
            {
                nextismulti = 1;
                break;
            }
            if (*cp == '\\' && *++cp == '\0')
            {
                ALG_LOG_DEBUG("escape character at end of string.");
                goto err;
            }
        }
        *bp++ = '\0';

        /* If not at EOS (must be + or /), move forward. */
        if (*cp)
            ++cp;

        /* Parse */
        nid = OBJ_txt2nid(typestr);
        if (nid == NID_undef)
        {
            ALG_LOG_DEBUG("Skipping unknown attribute %s.", typestr);
            continue;
        }
        if (!X509_NAME_add_entry_by_NID(n, nid, chtype,
                                        valstr, strlen((char *)valstr),
                                        -1, ismulti ? -1 : 0))
            goto err;
    }

    OPENSSL_free(work);
    return n;

 err:
    X509_NAME_free(n);
    OPENSSL_free(work);
    return NULL;
}

static X509_REQ *alg_make_req(EVP_PKEY *pKey, char *subj)
{
    X509_REQ *pReq = X509_REQ_new();
    if (pReq == NULL)
    {
        return NULL;
    }

    unsigned long chtype = MBSTRING_ASC;
    int multirdn = 0;

    X509_NAME *n;
    if ((n = parse_name(subj, chtype, multirdn)) == NULL)
    {
        ALG_LOG_ERROR("subject parse fail[%s].", subj);
        goto err;
    }

    if (!X509_REQ_set_subject_name(pReq, n))
    {
        X509_NAME_free(n);
        ALG_LOG_ERROR("set subj name fail.");
        goto err;
    }
    X509_NAME_free(n);

    if (!X509_REQ_set_pubkey(pReq, pKey))
    {
        ALG_LOG_ERROR("set pub key fail.");
        goto err;
    }

    return pReq;
err:
    X509_REQ_free(pReq);
    return NULL;
}

int alg_csr_gen_sm2(ECCrefPublicKey *pPub, ECCrefPrivateKey *pPri, char *subj, char *b64Csr)
{
    EVP_PKEY *pKey = NULL;
    int32_t iRet = 0;
    iRet = alg_pkey_new_from_sm2(pPub, pPri, &pKey);
    if (iRet)
    {
        ALG_LOG_ERROR("load sm2 key fail.");
        return iRet;
    }

    X509_REQ *pReq = alg_make_req(pKey, subj);
    if (pReq == NULL)
    {
        OPENSSL_ERR
        ALG_LOG_ERROR("make req fail.");
        iRet = GMCM_FAIL;
    }
    else
    {
        if (X509_REQ_sign(pReq, pKey, EVP_sm3()) <= 0)
        {
            ALG_LOG_ERROR("req sign fail.");
            iRet = GMCM_FAIL;
        }
        else
        {
            BIO *bReq = BIO_new(BIO_s_mem());
            if (PEM_write_bio_X509_REQ(bReq, pReq) <= 0)
            {
                ALG_LOG_ERROR("pem write req fail.");
                iRet = GMCM_FAIL;
            }
            else
            {
                if (BIO_read(bReq, b64Csr, MAX_DATA_LEN) <= 0)
                {
                    ALG_LOG_ERROR("bio read fail.");
                    iRet = GMCM_FAIL;
                }
            }
            BIO_free(bReq);
        }
    }

    EVP_PKEY_free(pKey);
    return iRet;
}

int alg_csr_gen_rsa(RSArefPublicKey *pPub, RSArefPrivateKey *pPri, char *subj, char *b64Csr)
{
    EVP_PKEY *pKey = NULL;
    int32_t iRet = 0;
    iRet = alg_pkey_new_from_rsa(pPub, pPri, &pKey);
    if (iRet)
    {
        ALG_LOG_ERROR("load rsa key fail.");
        return iRet;
    }

    X509_REQ *pReq = alg_make_req(pKey, subj);
    if (pReq == NULL)
    {
        ALG_LOG_ERROR("make req fail.");
        iRet = GMCM_FAIL;
    }
    else
    {
        if (X509_REQ_sign(pReq, pKey, EVP_sha256()) <= 0)
        {
            ALG_LOG_ERROR("req sign fail.");
            iRet = GMCM_FAIL;
        }
        else
        {
            BIO *bReq = BIO_new(BIO_s_mem());
            if (PEM_write_bio_X509_REQ(bReq, pReq) <= 0)
            {
                ALG_LOG_ERROR("pem write req fail.");
                iRet = GMCM_FAIL;
            }
            else
            {
                if (BIO_read(bReq, b64Csr, MAX_DATA_LEN) <= 0)
                {
                    ALG_LOG_ERROR("bio read fail.");
                    iRet = GMCM_FAIL;
                }
            }
            BIO_free(bReq);
        }
    }

    EVP_PKEY_free(pKey);
    return iRet;
}

static int alg_csr_import(char *b64Csr, X509_REQ **pReq)
{
    int iRet = GMCM_OK;

    if (strstr(b64Csr, "-----BEGIN ") == NULL)
    {
        unsigned int b64Len = strlen(b64Csr);
        unsigned char *derKey = new unsigned char[b64Len];
        const unsigned char *pDer = derKey;

        unsigned int derLen = base64::base64Decode(b64Csr, b64Len, derKey);
        if (derLen == 0)
        {
            ALG_LOG_ERROR("base64 data decode fail.");
            iRet = GMCM_FAIL;
        }
        else
        {
            *pReq = d2i_X509_REQ(NULL, &pDer, derLen);
            if (*pReq == NULL)
            {
                ALG_LOG_ERROR("d2i x509 req fail.");
                iRet = GMCM_FAIL;
            }
        }
        delete derKey;
    }
    else
    {
        BIO *bp = BIO_new(BIO_s_mem());
        if (BIO_write(bp, b64Csr, strlen(b64Csr)) <= 0)
        {
            ALG_LOG_ERROR("bio write fail.");
            iRet = GMCM_FAIL;
        }
        else
        {
            *pReq = PEM_read_bio_X509_REQ(bp, NULL, NULL, NULL);
            if (*pReq == NULL)
            {
                ALG_LOG_ERROR("pem read x509 req fail.");
                iRet = GMCM_FAIL;
            }
        }
        BIO_free(bp);
    }

    return iRet;
}

static int x509_name_format(X509_NAME *pName, char *sName)
{
    BIO *bName = BIO_new(BIO_s_mem());
    if (bName == NULL)
    {
        return GMCM_FAIL;
    }

    X509_NAME_print_ex(bName, pName, 0, XN_FLAG_RFC2253);
    BIO_read(bName, sName, MAX_DATA_LEN);
    BIO_free(bName);
    return GMCM_OK;
}

int cert_set_usage_ext(X509 *x509, X509 *pCa, cert_usage usage)
{
    char sConf[MAX_DATA_LEN];
    char subj[MAX_DATA_LEN];
    char site[1024];
    char *pSite = site;

    switch (usage)
    {
    case USAGE_CA:
        snprintf(sConf, sizeof(sConf), "%s%s", CNF_CA_REQ, CNF_POLSECT);
        break;
    case USAGE_SIGN:
    case USAGE_ENC:
        snprintf(sConf, sizeof(sConf), "%s%s", CNF_SIGN_ENC_REQ, CNF_POLSECT);
        break;
    case USAGE_WEB:
        snprintf(sConf, sizeof(sConf), "%s%s", CNF_WEB_REQ, CNF_POLSECT);
        break;
    case USAGE_TLS:
        x509_name_format(X509_get_subject_name(x509), subj);
        for (char *p = strstr(subj, "CN=") + 3; p != NULL && *p != '\0' && *p != '/'; p++)
        {
            *pSite = *p;
            pSite++;
        }
        *pSite = '\0';
        snprintf(sConf, sizeof(sConf), "%ssubjectAltName = DNS:%s\n%s", CNF_TLS_REQ, site, CNF_POLSECT);
        break;
    case USAGE_TLS_ENC:
        x509_name_format(X509_get_subject_name(x509), subj);
        for (char *p = strstr(subj, "CN=") + 3; p != NULL && *p != '\0' && *p != '/'; p++)
        {
            *pSite = *p;
            pSite++;
        }
        *pSite = '\0';
        snprintf(sConf, sizeof(sConf), "%ssubjectAltName = DNS:%s\n%s", CNF_TLS_ENC_REQ, site, CNF_POLSECT);
        break;
    case USAGE_TSA:
        snprintf(sConf, sizeof(sConf), "%s%s", CNF_TSA_REQ, CNF_POLSECT);
        break;
    case USAGE_IPSEC:
        snprintf(sConf, sizeof(sConf), "%s%s", CNF_IPSEC_REQ, CNF_POLSECT);
        break;
    case USAGE_EMAIL:
        snprintf(sConf, sizeof(sConf), "%s%s", CNF_EMAIL_REQ, CNF_POLSECT);
        break;
    case USAGE_CARD:
        snprintf(sConf, sizeof(sConf), "%s%s", CNF_CARD_REQ, CNF_POLSECT);
        break;

    default:
        break;
    }

    CONF *pConf = load_conf(sConf);
    if(pConf == NULL)
    {
        ALG_LOG_DEBUG("load conf fail.");
        return GMCM_FAIL;
    }
    OPENSSL_ERR
    X509V3_CTX ctx;
    X509_set_version(x509, 2);
    if(pCa == NULL)
    {
        X509V3_set_ctx(&ctx, x509, x509, NULL, NULL, 0);
    }
    else
    {
        X509V3_set_ctx(&ctx, pCa, x509, NULL, NULL, 0);
    }
    X509V3_set_nconf(&ctx, pConf);
    X509V3_EXT_add_nconf(pConf, &ctx, "v3_req", x509);
    OPENSSL_ERR

    return GMCM_OK;
}

static X509 *alg_csr_sign_cert(X509_REQ *pReq, X509 *pCa, EVP_PKEY *pKey,
                               unsigned int days, unsigned char *serial, unsigned int serLen,
                               cert_usage usage, const EVP_MD *md)
{
    int iRet = GMCM_OK;
    X509 *x509 = X509_new();
    BIGNUM *bSno = NULL;
    if (serial == NULL)
    {
        unsigned char md[32];
        unsigned int mdLen = 0;
        if (X509_REQ_digest(pReq, EVP_sha1(), md, &mdLen) > 0) //序列号为请求sha1
        {
            bSno = BN_bin2bn(md, mdLen, NULL);
        }
    }
    else
    {
        bSno = BN_bin2bn(serial, serLen, NULL);
    }

    if (bSno == NULL)
    {
        ALG_LOG_ERROR("set serial fail.");
        iRet = GMCM_FAIL;
    }
    else
    {
        ASN1_INTEGER *pSno = BN_to_ASN1_INTEGER(bSno, NULL);
        BN_free(bSno);

        if (!X509_set_serialNumber(x509, pSno) ||
            !X509_set_issuer_name(x509, pCa ? X509_get_subject_name((X509 *)pCa) : X509_REQ_get_subject_name(pReq)) ||
            !X509_set_subject_name(x509, X509_REQ_get_subject_name(pReq)) ||
            !X509_gmtime_adj(X509_getm_notBefore(x509), 0) ||           //开始时间为now
            !X509_time_adj_ex(X509_getm_notAfter(x509), days, 0, NULL)) //结束时间按有效期
        {
            int err = ERR_get_error();
            ALG_LOG_DEBUG("cert set param fail[%s][%s].", ERR_func_error_string(err), ERR_reason_error_string(err));
            iRet = GMCM_FAIL;
        }
        ASN1_INTEGER_free(pSno);

        if (!iRet)
        {
            iRet = cert_set_usage_ext(x509, pCa, usage);
            if (iRet)
            {
                ALG_LOG_ERROR("set usage and ext fail.");
            }
        }

        if (!iRet)
        {
            if (pCa != NULL)
            {
                if(X509_check_private_key((X509 *)pCa, pKey) <= 0)
                {
                    ALG_LOG_ERROR("ca and pkey do not match.");
                    iRet = GMCM_FAIL;
                }
            }
            else
            {
                //自签名
            }

            X509_set_pubkey(x509, X509_REQ_get0_pubkey(pReq));

            if(!iRet)
            {
                if (!X509_sign(x509, pKey, md))
                {
                    ALG_LOG_ERROR("cert sign fail.");
                    iRet = GMCM_FAIL;
                }
                else
                {
                    return x509;
                }
            }
        }
    }

    return NULL;
}

int alg_x509_export(X509 * x509 , char * sCert)
{
    BIO *bp = BIO_new(BIO_s_mem());
    int iRet = GMCM_OK;
    if(PEM_write_bio_X509(bp, x509) <= 0)
    {
        ALG_LOG_ERROR("pem write cert fail.");
        iRet = GMCM_FAIL;
    }
    else
    {
        if(BIO_read(bp, sCert, MAX_DATA_LEN) <= 0)
        {
            ALG_LOG_ERROR("bio read cert fail.");
            iRet = GMCM_FAIL;
        }
    }

    return iRet;
}

int alg_csr_sign_cert_sm2(char *b64Csr, void *pCa, ECCrefPublicKey *pPub, ECCrefPrivateKey *pPri,
                          unsigned int days, cert_usage usage, unsigned char *serial,
                          unsigned int serLen, char *sCert)
{
    X509_REQ * pReq = NULL;
    int iRet;
    iRet = alg_csr_import(b64Csr, &pReq);
    if(iRet)
    {
        ALG_LOG_ERROR("read b64csr fail.");
        return iRet;
    }

    EVP_PKEY *pKey = NULL;
    iRet = alg_pkey_new_from_sm2(pPub, pPri, &pKey);
    if (iRet)
    {
        ALG_LOG_ERROR("load sm2 key fail.");
        X509_REQ_free(pReq);
        return iRet;
    }

    if(X509_REQ_verify(pReq, X509_REQ_get0_pubkey(pReq)) <= 0)
    {
        ALG_LOG_ERROR("verify req sign fail.");
        iRet = GMCM_FAIL;
    }
    else
    {
        X509 *x509 = alg_csr_sign_cert(pReq, (X509 *)pCa, pKey, days, serial, serLen, usage, EVP_sm3());
        iRet = alg_x509_export(x509, sCert);
        X509_free(x509);
    }

    X509_REQ_free(pReq);
    EVP_PKEY_free(pKey);
    OPENSSL_ERR
    return iRet;
}

int alg_csr_sign_cert_rsa(char *b64Csr, void *pCa, RSArefPublicKey *pPub, RSArefPrivateKey *pPri,
                          unsigned int days, cert_usage usage, unsigned char *serial,
                          unsigned int serLen, char *sCert)
{
    X509_REQ * pReq = NULL;
    int iRet;
    iRet = alg_csr_import(b64Csr, &pReq);
    if(iRet)
    {
        ALG_LOG_ERROR("read b64csr fail.");
        return iRet;
    }

    EVP_PKEY *pKey = NULL;
    iRet = alg_pkey_new_from_rsa(pPub, pPri, &pKey);
    if (iRet)
    {
        ALG_LOG_ERROR("load rsa key fail.");
        X509_REQ_free(pReq);
        return iRet;
    }

    if(X509_REQ_verify(pReq, X509_REQ_get0_pubkey(pReq)) <= 0)
    {
        ALG_LOG_ERROR("verify req sign fail.");
        iRet = GMCM_FAIL;
    }
    else
    {
        X509 *x509 = alg_csr_sign_cert(pReq, (X509 *)pCa, pKey, days, serial, serLen, usage, EVP_sha256());
        iRet = alg_x509_export(x509, sCert);
        X509_free(x509);
    }

    X509_REQ_free(pReq);
    EVP_PKEY_free(pKey);

    return iRet;
}

int alg_sm2_export(ECCrefPublicKey *pPub, ECCrefPrivateKey *pPri, char *sPem)
{
    EVP_PKEY *pKey = NULL;
    int iRet = alg_pkey_new_from_sm2(pPub, pPri, &pKey);
    if(iRet)
    {
        ALG_LOG_ERROR("load sm2 key fail.");
    }
    else
    {
        BIO *bp = BIO_new(BIO_s_mem());
        if(PEM_write_bio_ECPrivateKey(bp, EVP_PKEY_get0_EC_KEY(pKey), NULL, NULL, 0, NULL, NULL) <= 0)
        {
            ALG_LOG_ERROR("pem write ec key fail.");
            OPENSSL_ERR
            iRet = GMCM_FAIL;
        }
        else
        {
            if(BIO_read(bp, sPem, MAX_DATA_LEN) <= 0)
            {
                ALG_LOG_ERROR("bio read pem key fail.");
                iRet = GMCM_FAIL;
            }
            BIO_free(bp);
        }

        EVP_PKEY_free((EVP_PKEY *)pKey);
    }

    return iRet;
}

int alg_rsa_export( RSArefPrivateKey *pPri, char *sPem)
{
    EVP_PKEY *pKey = NULL;
    int iRet = alg_pkey_new_from_rsa(NULL, pPri, &pKey);
    if(iRet)
    {
        ALG_LOG_ERROR("load sm2 key fail.");
    }
    else
    {
        BIO *bp = BIO_new(BIO_s_mem());
        if (PEM_write_bio_RSAPrivateKey(bp, EVP_PKEY_get0_RSA(pKey), NULL, NULL, 0, NULL, NULL) <= 0)
        {
            ALG_LOG_ERROR("pem write rsa key fail.");
            iRet = GMCM_FAIL;
        }
        else
        {
            if (BIO_read(bp, sPem, MAX_DATA_LEN) <= 0)
            {
                ALG_LOG_ERROR("bio read pem key fail.");
                iRet = GMCM_FAIL;
            }
            BIO_free(bp);
        }

        EVP_PKEY_free((EVP_PKEY *)pKey);
    }

    return iRet;
}

