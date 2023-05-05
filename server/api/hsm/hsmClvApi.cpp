#include "hsmClvPkt.h"
#include "../../application/application.h"
#include "../../tool/gmcmLog.h"
#include "hsmApi.h"

static uint8_t ext_ok[4] = {0x01, 0x00, 0x00, 0x00};

int32_t send_err(int32_t ret, std::function<int32_t(void *, uint16_t)> writCb)
{
    static uint8_t ext[4] = {0x00, 0x00, 0x00, 0x00};
    respError resp;
    resp.err.ref(&ret);
    return resp.send(ext, writCb);
}

#define HSM_CLV_API(name, reqType, respType, process)                                                                 \
    unsigned int name(unsigned char *reqStr, unsigned int reqStrLen, std::function<int32_t(void *, uint16_t)> writCb) \
    {                                                                                                                 \
        reqType req;                                                                                                \
        respType resp;                                                                                              \
        unsigned int ret = 0;                                                                                         \
        ret = req.mapping(reqStr, reqStrLen);                                                                         \
        if (ret)                                                                                                      \
        {                                                                                                             \
            return send_err(ret, writCb);                                                                             \
        }                                                                                                             \
                                                                                                                      \
        ret = process(&req, &resp);                                                                                   \
        if (ret)                                                                                                      \
        {                                                                                                             \
            return send_err(ret, writCb);                                                                                               \
        }                                                                                                             \
                                                                                                                      \
        return resp.send(ext_ok, writCb);                                                                             \
    }

unsigned int randBytesProc(reqRandom *req, respRandom *resp)
{
    sdfMeth *pMeth = applicationList::getSdfMeth(APP_HSM_DEF);
    uint32_t ret = pMeth->GenerateRandom(req->length.val(), resp->rand.alloc(req->length.val()));
    return ret;
}

HSM_CLV_API(randBytes, reqRandom, respRandom, randBytesProc)

unsigned int genEccKeyPairProc(reqGenEccPair *req, respGenEccPair *resp)
{
    sdfMeth *pMeth = applicationList::getSdfMeth(APP_HSM_DEF);
    return pMeth->GenerateKeyPair_ECC(resp->pub.alloc(), resp->pri.alloc());
}

HSM_CLV_API(genEccKeyPair, reqGenEccPair, respGenEccPair, genEccKeyPairProc)

unsigned int importKeyProc(reqImportKey *req, respImportKey *resp)
{
    sdfMeth *pMeth = applicationList::getSdfMeth(APP_HSM_DEF);
    unsigned short len = 0;
    uint32_t ret = pMeth->ImportKey(req->uikey.ptr(), req->uikey.len(), resp->hd.alloc(16), &len);
    if(ret)
    {
        return ret;
    }

    resp->hd.setLen(len);
    return 0;
}

HSM_CLV_API(importKey, reqImportKey, respImportKey, importKeyProc)

unsigned int destroyKeyProc(reqDestroyKey *req, respDestroyKey *resp)
{
    sdfMeth *pMeth = applicationList::getSdfMeth(APP_HSM_DEF);
    return pMeth->DestroyKey(req->hd.ptr(), req->hd.len());
}

HSM_CLV_API(destroyKey, reqDestroyKey, respDestroyKey, destroyKeyProc)

unsigned int encryptProc(reqEncrypt *req, respEncrypt *resp)
{
    sdfMeth *pMeth = applicationList::getSdfMeth(APP_HSM_DEF);
    unsigned short outLen = 0;
    int ret = pMeth->encrypt(req->hd.ptr(), req->hd.len(),
                             req->algid.val(), req->iv.ptr(),
                             req->data.ptr(), req->data.len(),
                             resp->encData.alloc(req->data.len() + 32), &outLen);
    if (ret)
    {
        gmcmLog::LogError() << "encrypt fail " << to_string(ret) << ".\n";
        return ret;
    }
    resp->iv.ref(req->iv.ptr(), req->iv.len());
    resp->encData.setLen(outLen);
    return 0;
}

HSM_CLV_API(encrypt, reqEncrypt, respEncrypt, encryptProc)

unsigned int decryptProc(reqDecrypt *req, respDecrypt *resp)
{
    sdfMeth *pMeth = applicationList::getSdfMeth(APP_HSM_DEF);
    unsigned short outLen = 0;
    int ret = pMeth->decrypt(req->hd.ptr(), req->hd.len(),
                             req->algid.val(), req->iv.ptr(),
                             req->encData.ptr(), req->encData.len(),
                             resp->decData.alloc(req->encData.len()), &outLen);
    if (ret)
    {
        gmcmLog::LogError() << "decrypt fail " << to_string(ret) << ".\n";
        return ret;
    }
    resp->iv.ref(req->iv.ptr(), req->iv.len());
    resp->decData.setLen(outLen);
    return 0;
}

HSM_CLV_API(decrypt, reqDecrypt, respDecrypt, decryptProc)

std::vector<std::pair<std::string, hsmApiClvFuncPtr>> getHsmClvApis()
{
    vector<pair<string, hsmApiClvFuncPtr>> vtApis;
    vtApis.push_back(pair<string, hsmApiClvFuncPtr>("0002", randBytes));
    vtApis.push_back(pair<string, hsmApiClvFuncPtr>("0007", genEccKeyPair));
    vtApis.push_back(pair<string, hsmApiClvFuncPtr>("0017", importKey));
    vtApis.push_back(pair<string, hsmApiClvFuncPtr>("0018", destroyKey));
    vtApis.push_back(pair<string, hsmApiClvFuncPtr>("0027", encrypt));
    vtApis.push_back(pair<string, hsmApiClvFuncPtr>("0028", decrypt));
    return vtApis;
}