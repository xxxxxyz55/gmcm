#include "hsmApi.h"
#include "../package/packageDefine.h"
#include "../application/application.h"
#include "../tool/gmcmLog.h"

vector<pair<string, hsmApiFuncPtr>> gHsmAPiFuncs = {
    {"0002", randBytes},
    {"0007", genEccKeyPair},
    {"0017", importKey},
    {"0018", destroyKey},
    {"0027", encrypt},
    {"0028", decrypt},
};

hsmApiEngine::hsmApiEngine() : apiEngine<hsmApiFuncPtr>(gHsmAPiFuncs)
{
}

hsmApiEngine::~hsmApiEngine()
{
}

unsigned int randBytes(unsigned char *reqStr, unsigned int reqStrLen, pstBuffer *respBase)
{
    unsigned int ret = 0;
    reqRandBytes reqPkg;
    respRandBytes respPkg;
    
    ret = reqPkg.pointToBuffer(reqStr, reqStrLen);
    if (ret)
    {
        return ret;
    }
    respPkg.pointToBase(respBase);

    sdfMeth *pMeth = applicationList::getSdfMeth(APP_HSM_DEF);

    ret = pMeth->GenerateRandom(reqPkg.length.uIntVal(), (unsigned char *)respPkg.random.pValue);
    if(ret)
    {
        printf("rand byte fail = %d\n", ret);
        return ret;
    }

    respPkg.random.setLength(reqPkg.length.uIntVal());

    return ret;
}

unsigned int genEccKeyPair(unsigned char *reqStr, unsigned int reqStrLen, pstBuffer *respBase)
{
    unsigned int ret = 0;
    reqGenEccKeyPair reqPkg;
    respGenEccKeyPair respPkg;
    
    ret = reqPkg.pointToBuffer(reqStr, reqStrLen);
    if (ret)
    {
        return ret;
    }
    respPkg.pointToBase(respBase);

    sdfMeth *pMeth = applicationList::getSdfMeth(APP_HSM_DEF);
    memset(respPkg.pub.stPtr<ECCrefPublicKey>(), 0x00, sizeof(ECCrefPublicKey));
    memset(respPkg.pri.stPtr<ECCrefPrivateKey>(), 0x00, sizeof(ECCrefPrivateKey));
    ret = pMeth->GenerateKeyPair_ECC(respPkg.pub.stPtr<ECCrefPublicKey>(), respPkg.pri.stPtr<ECCrefPrivateKey>());
    if(ret)
    {
        return ret;
    }

    respPkg.pub.setLength(sizeof(ECCrefPublicKey));
    respPkg.pri.setLength(sizeof(ECCrefPrivateKey));
    return ret;
}

unsigned int importKey(unsigned char *reqStr, unsigned int reqStrLen, pstBuffer *respBase)
{
    unsigned int ret = 0;
    reqImportKey reqPkg;
    respImportKey respPkg;
    
    ret = reqPkg.pointToBuffer(reqStr, reqStrLen);
    if (ret)
    {
        return ret;
    }
    respPkg.pointToBase(respBase);

    sdfMeth *pMeth = applicationList::getSdfMeth(APP_HSM_DEF);

    ret = pMeth->ImportKey(reqPkg.uikey.uStrVal(), reqPkg.uikey.length(),
                           respPkg.handle.uStrVal(), respPkg.handle.pLen);
    if (ret)
    {
        return ret;
    }
    
    return ret;
}

unsigned int destroyKey(unsigned char *reqStr, unsigned int reqStrLen, pstBuffer *respBase)
{
    unsigned int ret = 0;
    reqDestroyKey reqPkg;
    respDestroyKey respPkg;
    
    ret = reqPkg.pointToBuffer(reqStr, reqStrLen);
    if (ret)
    {
        return ret;
    }
    respPkg.pointToBase(respBase);

    sdfMeth *pMeth = applicationList::getSdfMeth(APP_HSM_DEF);

    ret = pMeth->DestroyKey(reqPkg.handle.uStrVal(), reqPkg.handle.length());
    if (ret)
    {
        return ret;
    }

    return ret;
}

unsigned int encrypt(unsigned char *reqStr, unsigned int reqStrLen, pstBuffer *respBase)
{
    unsigned int ret = 0;
    reqEncrypt reqPkg;
    respEncrypt respPkg;

    ret = reqPkg.pointToBuffer(reqStr, reqStrLen);
    if (ret)
    {
        return ret;
    }
    respPkg.pointToBase(respBase);

    sdfMeth *pMeth = applicationList::getSdfMeth(APP_HSM_DEF);

    ret = pMeth->encrypt(reqPkg.handle.uStrVal(), reqPkg.handle.length(),
                         reqPkg.algid.uIntVal(), reqPkg.iv.uStrVal(),
                         reqPkg.data.uStrVal(), reqPkg.data.length(),
                         respPkg.encData.uStrVal(), respPkg.encData.pLen);
    if (ret)
    {
        return ret;
    }
    else
    {
        respPkg.iv = reqPkg.iv;
    }

    return ret;
}

unsigned int decrypt(unsigned char *reqStr, unsigned int reqStrLen, pstBuffer *respBase)
{
    unsigned int ret = 0;
    reqDecrypt reqPkg;
    respDecrypt respPkg;
    
    ret = reqPkg.pointToBuffer(reqStr, reqStrLen);
    if (ret)
    {
        return ret;
    }
    respPkg.pointToBase(respBase);

    sdfMeth *pMeth = applicationList::getSdfMeth(APP_HSM_DEF);

    ret = pMeth->decrypt(reqPkg.handle.uStrVal(), reqPkg.handle.length(),
                         reqPkg.algid.uIntVal(), reqPkg.iv.uStrVal(),
                         reqPkg.encData.uStrVal(), reqPkg.encData.length(),
                         respPkg.decData.uStrVal(), respPkg.decData.pLen);
    if (ret)
    {
        gmcmLog::LogError() << "decrypt fail. " << ret << endl;
    }
    else
    {
        respPkg.iv = reqPkg.iv;
    }

    return ret;
}