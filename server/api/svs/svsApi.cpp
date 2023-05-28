#include "svsApi.h"
#include "algApi.h"
#include "svsRequest.h"
#include "../../application/application.h"
#include "../../tool/gmcmLog.h"


void svsSendErr(int32_t err, TC_HttpResponse *response)
{
    jsonPkt resp;
    resp.addRespField("errno", err);
    resp.addRespField("reason", errGetReason(err));
    response->setResponse(200, "OK", resp.toJsonStr());
}

void SvsDealError(TC_HttpRequest *request, TC_HttpResponse *response)
{
    svsSendErr(GMCM_ERR_CMD_UNDEFINE, response);
}

int32_t help(reqNULL *pReq, jsonPkt *pResp)
{
    pResp->addRespField("随机数", "http://host:port/GenerateRandom");
    pResp->addRespField("生成SM2密钥", "http://host:port/GenerateRandom");
    return GMCM_OK;
}

// curl 10.28.16.83:8806/GenerateRandom -d "{\"length\":32}"
int32_t GenerateRandom(reqGenerateRandom *pReq, jsonPkt *pResp)
{
    sdfMeth *pMeth = applicationList::getSdfMeth(APP_SVS_DEF);
    unsigned char randBuf[8192];
    int32_t iRet = pMeth->GenerateRandom(pReq->length->num(), randBuf);
    if (iRet)
    {
        return iRet;
    }

    pResp->addbase64Str("random", randBuf, pReq->length->num());
    return iRet;
}

void SvsGenKey(TC_HttpRequest *request, TC_HttpResponse *response)
{
    jsonPkt jResp;
    reqSvsGenKey req;
    int iRet;

    iRet = req.setString(request->getContent().data());
    if (iRet)
    {
        return svsSendErr(iRet, response);
    }

    char pem[MAX_DATA_LEN];
    int algid = alg_str_to_int(req.type->str());
    if(algid == SGD_SM2)
    {
        ECCrefPublicKey pub;
        ECCrefPrivateKey pri;
        iRet = alg_sm2_gen_key_pair(&pub, &pri);
        if (iRet)
        {
            return svsSendErr(GMCM_ERR_GEN_KEY, response);
        }

        iRet = alg_sm2_export(&pub, &pri, pem);
        if (iRet)
        {
            return svsSendErr(GMCM_ERR_EXPORT_PEM, response);
        }
    }
    else if (algid == SGD_RSA)
    {
        if (req.bits->ptr() == false || req.bits->num() == 0)
        {
            return svsSendErr(GMCM_ERR_PARAM_NULL, response);
        }

        RSArefPublicKey pub;
        RSArefPrivateKey pri;
        iRet = alg_rsa_gen_key_pair(65537, req.bits->num(), &pub, &pri);
        if (iRet)
        {
            return svsSendErr(GMCM_ERR_GEN_KEY, response);
        }

        iRet = alg_rsa_export(&pri, pem);
        if (iRet)
        {
            return svsSendErr(GMCM_ERR_EXPORT_PEM, response);
        }
    }
    else
    {
        return svsSendErr(GMCM_ERR_ALGID, response);
    }

    jResp.addRespField("prikey", alg_pem_get_base64(pem));
    response->setResponse(200, "OK", jResp.toJsonStr());
}

void SvsGenCsr(TC_HttpRequest *request, TC_HttpResponse *response)
{
    jsonPkt jResp;
    reqSvsGenCsr req;
    int iRet;

    iRet = req.setString(request->getContent().data());
    if (iRet)
    {
        return svsSendErr(GMCM_ERR_ALGID, response);
    }

    ECCrefPublicKey sm2Pub;
    ECCrefPrivateKey sm2Pri;
    RSArefPublicKey rsaPub;
    RSArefPrivateKey rsaPri;
    char csr[MAX_DATA_LEN];

    if (!(iRet = alg_sm2_import((char *)req.prikey->str(), &sm2Pub, &sm2Pri)))
    {
        iRet = alg_csr_gen_sm2(&sm2Pub, &sm2Pri, (char *)req.subj->str(), csr);
    }
    else if (!(iRet == alg_rsa_import((char *)req.prikey->str(), &rsaPub, &rsaPri)))
    {
        iRet = alg_csr_gen_rsa(&rsaPub, &rsaPri, (char *)req.subj->str(), csr);
    }
    else
    {
        return svsSendErr(GMCM_ERR_KEY, response);
    }

    if(iRet)
    {
        return svsSendErr(GMCM_ERR_GEN_CSR, response);
    }

    jResp.addRespField("csr", alg_pem_get_base64(csr));
    response->setResponse(200, "OK", jResp.toJsonStr());
}

void SvsSignCert(TC_HttpRequest *request, TC_HttpResponse *response)
{
    jsonPkt jResp;
    reqSvsSignCert req;
    int iRet;

    iRet = req.setString(request->getContent().data());
    if (iRet)
    {
        return svsSendErr(iRet, response);
    }

    char cert[MAX_DATA_LEN];
    ECCrefPublicKey sm2Pub;
    ECCrefPrivateKey sm2Pri;
    RSArefPublicKey rsaPub;
    RSArefPrivateKey rsaPri;
    void *pCa = NULL;
    if (req.caCert->str())
    {
        iRet = alg_pem_import_cert(req.caCert->str(), &pCa);
        if (iRet)
        {
            return svsSendErr(GMCM_ERR_CERT, response);
        }
    }

    cert_usage usage = (cert_usage)alg_str_to_int(req.usage->str());
    if(usage == 0)
    {
        return svsSendErr(GMCM_ERR_CERT_USAGE, response);
    }

    if (!(iRet = alg_sm2_import((char *)req.caKey->str(), &sm2Pub, &sm2Pri)))
    {
        iRet = alg_csr_sign_cert_sm2((char *)req.csr->str(), pCa, &sm2Pub, &sm2Pri, 365, usage, NULL, 0, cert);
    }
    else if (!(iRet == alg_rsa_import((char *)req.caKey->str(), &rsaPub, &rsaPri)))
    {
        iRet = alg_csr_sign_cert_rsa((char *)req.csr->str(), pCa, &rsaPub, &rsaPri, 365, usage, NULL, 0, cert);
    }
    else
    {
        return svsSendErr(GMCM_ERR_KEY, response);
    }
    
    if(iRet)
    {
        return svsSendErr(GMCM_ERR_SIGN_CERT, response);
    }

    jResp.addRespField("cert", alg_pem_get_base64(cert));
    response->setResponse(200, "OK", jResp.toJsonStr());
}

DECLARE_SVS_API(help, reqNULL, jsonPkt)
DECLARE_SVS_API(GenerateRandom, reqGenerateRandom, jsonPkt)

vector<pair<string, svsApiFuncPtr>> getSvsApis()
{
    vector<pair<string, svsApiFuncPtr>> vtApis;

    vtApis.push_back(pair<string, svsApiFuncPtr>("/help", SVS_API_NAME(help)));
    vtApis.push_back(pair<string, svsApiFuncPtr>("/GenerateRandom", SVS_API_NAME(GenerateRandom)));
    vtApis.push_back(pair<string, svsApiFuncPtr>("/GenKey", SvsGenKey));
    vtApis.push_back(pair<string, svsApiFuncPtr>("/GenCsr", SvsGenCsr));
    vtApis.push_back(pair<string, svsApiFuncPtr>("/SignCert", SvsSignCert));
    return vtApis;
}