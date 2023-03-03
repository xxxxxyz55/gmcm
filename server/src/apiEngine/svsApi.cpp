#include "svsApi.h"
#include "../package/packageDefine.h"
#include "../application/application.h"
#include "../tool/gmcmLog.h"
#include "../gmcmErr.h"
#include "algApi.h"

vector<pair<string, svsApiFuncPtr>> gSvsAPiFuncs = {
    {"help", helpPage},
    {"GenerateRandom", SvsGenerateRandom},
    {"GenKey", SvsGenKey},
    {"GenCsr", SvsGenCsr},
    {"SignCert", SvsSignCert},
};

svsApiEngine::svsApiEngine() : apiEngine<svsApiFuncPtr>(gSvsAPiFuncs)
{
}

svsApiEngine::~svsApiEngine()
{
}

unsigned int helpPage(TC_HttpRequest *request, TC_HttpResponse *response)
{
    jsonResp jResp;
    jResp.addRespField("随机数", "http://host:port/GenerateRandom");
    jResp.addRespField("生成SM2密钥", "http://host:port/GenerateRandom");
    response->setResponse(200, "OK", jResp.toResponseStr());
    return GMCM_OK;
}

// curl 10.28.16.83:8806/GenerateRandom -d "{\"length\":32}"
unsigned int SvsGenerateRandom(TC_HttpRequest *request, TC_HttpResponse *response)
{
    reqGenerateRandom req;
    jsonResp jResp;

    int iRet;
    iRet = req.pointToPuffer(request->getContent().data());
    if(iRet)
    {
        return iRet;
    }

    sdfMeth *pMeth = applicationList::getSdfMeth(APP_SVS_DEF);
    unsigned char randBuf[8192];
    iRet = pMeth->GenerateRandom(req.length.num(), randBuf);
    if (iRet)
    {
        return iRet;
    }

    jResp.addbase64Str("random", randBuf, req.length.num());
    response->setResponse(200, "OK", jResp.toResponseStr());

    return GMCM_OK;
}

unsigned int SvsGenKey(TC_HttpRequest *request, TC_HttpResponse *response)
{
    jsonResp jResp;
    reqSvsGenKey req;
    int iRet;

    iRet = req.pointToPuffer(request->getContent().data());
    if (iRet)
    {
        return iRet;
    }

    char pem[MAX_DATA_LEN];
    int algid = alg_str_to_int(req.type.str());
    if(algid == SGD_SM2)
    {
        ECCrefPublicKey pub;
        ECCrefPrivateKey pri;
        iRet = alg_sm2_gen_key_pair(&pub, &pri);
        if (iRet)
        {
            return GMCM_ERR_GEN_KEY;
        }

        iRet = alg_sm2_export(&pub, &pri, pem);
        if (iRet)
        {
            return GMCM_ERR_EXPORT_PEM;
        }
    }
    else if (algid == SGD_RSA)
    {
        if (req.bits.ptr() == NULL || req.bits.num() == 0)
        {
            return GMCM_ERR_PARAM_NULL;
        }

        RSArefPublicKey pub;
        RSArefPrivateKey pri;
        iRet = alg_rsa_gen_key_pair(65537, req.bits.num(), &pub, &pri);
        if (iRet)
        {
            return GMCM_ERR_GEN_KEY;
        }

        iRet = alg_rsa_export(&pri, pem);
        if (iRet)
        {
            return GMCM_ERR_EXPORT_PEM;
        }
    }
    else
    {
        return GMCM_ERR_ALGID;
    }
    
    jResp.addRespField("prikey", alg_pem_get_base64(pem));
    response->setResponse(200, "OK", jResp.toResponseStr());

    return GMCM_OK;
}

unsigned int SvsGenCsr(TC_HttpRequest *request, TC_HttpResponse *response)
{
    jsonResp jResp;
    reqSvsGenCsr req;
    int iRet;

    iRet = req.pointToPuffer(request->getContent().data());
    if (iRet)
    {
        return iRet;
    }

    ECCrefPublicKey sm2Pub;
    ECCrefPrivateKey sm2Pri;
    RSArefPublicKey rsaPub;
    RSArefPrivateKey rsaPri;
    char csr[MAX_DATA_LEN];

    if (!(iRet = alg_sm2_import(req.prikey.str(), &sm2Pub, &sm2Pri)))
    {
        iRet = alg_csr_gen_sm2(&sm2Pub, &sm2Pri, req.subj.str(), csr);
    }
    else if (!(iRet == alg_rsa_import(req.prikey.str(), &rsaPub, &rsaPri)))
    {
        iRet = alg_csr_gen_rsa(&rsaPub, &rsaPri, req.subj.str(), csr);
    }
    else
    {
        return GMCM_ERR_KEY;
    }

    if(iRet)
    {
        return GMCM_ERR_GEN_CSR;
    }

    jResp.addRespField("csr", alg_pem_get_base64(csr));
    response->setResponse(200, "OK", jResp.toResponseStr());

    return GMCM_OK;
}

unsigned int SvsSignCert(TC_HttpRequest *request, TC_HttpResponse *response)
{
    jsonResp jResp;
    reqSvsSignCert req;
    int iRet;

    iRet = req.pointToPuffer(request->getContent().data());
    if (iRet)
    {
        return iRet;
    }

    char cert[MAX_DATA_LEN];
    ECCrefPublicKey sm2Pub;
    ECCrefPrivateKey sm2Pri;
    RSArefPublicKey rsaPub;
    RSArefPrivateKey rsaPri;
    void *pCa = NULL;
    if (req.caCert.ptr())
    {
        iRet = alg_pem_import_cert(req.caCert.str(), &pCa);
        if (iRet)
        {
            return GMCM_ERR_CERT;
        }
    }

    cert_usage usage = (cert_usage)alg_str_to_int(req.usage.str());
    if(usage == 0)
    {
        return GMCM_ERR_CERT_USAGE;
    }

    if (!(iRet = alg_sm2_import(req.caKey.str(), &sm2Pub, &sm2Pri)))
    {
        iRet = alg_csr_sign_cert_sm2(req.csr.str(), pCa, &sm2Pub, &sm2Pri, 365, usage, NULL, 0, cert);
    }
    else if (!(iRet == alg_rsa_import(req.caKey.str(), &rsaPub, &rsaPri)))
    {
        iRet = alg_csr_sign_cert_rsa(req.csr.str(), pCa, &rsaPub, &rsaPri, 365, usage, NULL, 0, cert);
    }
    else
    {
        return GMCM_ERR_KEY;
    }
    
    if(iRet)
    {
        return GMCM_ERR_SIGN_CERT;
    }

    jResp.addRespField("cert", alg_pem_get_base64(cert));
    response->setResponse(200, "OK", jResp.toResponseStr());

    return GMCM_OK;
}