#include "gmcmalgConf.h"
#include "algApi.h"
#include "utilFunc.h"
#include "openssl/ssl.h"
#include <sys/types.h>
#include <dirent.h>

void *alg_tls_ctx_init(int isClient,
                       const char *signCert, const char *signKey,
                       const char *encCert, const char *encKey)
{
    if(signCert == NULL || signKey == NULL)
    {
        return NULL;
    }
    SSL_CTX * ctx = NULL;
    EVP_PKEY *pSignKey = NULL;
    const SSL_METHOD * method = NULL;
    int ret;
    ret = alg_pem_import_key(signKey, (void **)&pSignKey);
    if(ret)
    {
        ALG_LOG_ERROR("import key fail [%s].", signKey);
        openssl_err_stack();
        return NULL;
    }

    if (EVP_PKEY_id(pSignKey) == EVP_PKEY_EC)
    {
        if (isClient)
        {
            method = GMTLS_server_method();
        }
        else
        {
            method = GMTLS_client_method();
        }
    }
    else
    {
        if (isClient)
        {
            method = TLS_server_method();
        }
        else
        {
            method = TLS_client_method();
        }
    }

    ctx = SSL_CTX_new(method);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_clear_options(ctx, SSL_OP_LEGACY_SERVER_CONNECT);
    SSL_CTX_clear_options(ctx, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
    SSL_CTX_set_session_id_context(ctx, (const unsigned char *)ctx, sizeof(ctx));

    X509 *pSignCert = NULL;
    X509 *pEncCert = NULL;
    EVP_PKEY *pEncKey = NULL;
    if (
        alg_pem_import_cert(signCert, (void **)&pSignCert) ||
        !SSL_CTX_use_certificate(ctx, pSignCert) ||
        !SSL_CTX_use_PrivateKey(ctx, pSignKey))
    {
        ALG_LOG_ERROR("import sign key or cert fail.");
        ret = GMCM_FAIL;
    }
    else
    {
        if (pEncCert && pEncKey)
        {
            if (alg_pem_import_cert(encCert, (void **)&pEncCert) ||
                alg_pem_import_key(encKey, (void **)pEncKey) ||
                !SSL_CTX_use_certificate(ctx, pEncCert) ||
                !SSL_CTX_use_PrivateKey(ctx, pEncKey))
            {
                ret = GMCM_FAIL;
                ALG_LOG_ERROR("import enc key or cert fail.");
            }
        }
    }

    alg_free_cert((void **)&pSignCert);
    alg_free_cert((void **)&pEncCert);
    alg_free_key((void **)&pEncKey);
    alg_free_key((void **)&pSignKey);

    if (ret)
    {
        SSL_CTX_free(ctx);
        ctx = NULL;
    }
    return ctx;
}

int alg_tls_ctx_add_ca(void *ctx, char *caPem)
{
    void * pCa;
    if (alg_pem_import_cert(caPem, &pCa))
    {
        return GMCM_FAIL;
    }

    X509_STORE *store = SSL_CTX_get_cert_store((SSL_CTX *)ctx);
    if (!X509_STORE_add_cert(store, (X509 *)pCa))
    {
        ALG_LOG_ERROR("x509 store add cert fail.");
        alg_free_cert(&pCa);
        return GMCM_FAIL;
    }
    return GMCM_OK;
}

int alg_tls_ctx_add_ca_dir(void *ctx, const char *dir)
{
    if(ctx == NULL)
    {
        return GMCM_FAIL;
    }
    struct  dirent **entList = NULL;
    size_t fileNum = scandir(dir, &entList, NULL, alphasort);
    char path[512];
    for (size_t i = 0; i < fileNum; i++)
    {
        if (entList[i] == NULL)
        {
            continue;
        }
        else if (entList[i]->d_type & DT_REG)
        {
            snprintf(path, sizeof(path), "%s/%s", dir, entList[i]->d_name);
            FILE *fp = fopen(path, "r");
            if (fp == NULL)
            {
                continue;
            }
            else
            {
                X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
                if (cert)
                {
                    if(!X509_STORE_add_cert(SSL_CTX_get_cert_store((SSL_CTX *)ctx), cert))
                    {
                        ALG_LOG_ERROR("store add cert fail.");
                        alg_free_cert((void **)&cert);
                    }
                    else
                    {
                        ALG_LOG_DEBUG("ssl add ca cert %s .", path);
                    }
                }
                fclose(fp);
            }
        }
    }

    return GMCM_OK;
}

void alg_tls_free(void **ctx)
{
    if (ctx && *ctx)
    {
        SSL_CTX_free((SSL_CTX *)*ctx);
        *ctx = NULL;
    }
}