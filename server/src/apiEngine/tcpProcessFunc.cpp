#include "tcpProcessFunc.h"
#include "../server.h"
#include "packgeDefine.h"
#include "utilFunc.h"

tcpApiEngine *tcpApiEngine::gmcmApiFuncs = NULL;

static tcpDealFunc tcpAipFuncs[]{
    {"0002", randBytes},
    {"0007", genEccKeyPair},
    {"0017", importKey},
    {"0018", destroyKey},
    {"0027", encrypt},
    {"0028", decrypt},
};

map<string, tcpDealFunc> *tcpApiEngine::getMap()
{
    if (gmcmApiFuncs == NULL)
    {
        gmcmLog::LogInfo() << "tcp api engine init" << endl;
        gmcmApiFuncs = new tcpApiEngine();
        gmcmApiFuncs->apiMap.clear();
        for (size_t i = 0; i < (sizeof(tcpAipFuncs) / sizeof(tcpDealFunc)); i++)
        {
            gmcmApiFuncs->apiMap.insert(pair<string, tcpDealFunc>(tcpAipFuncs[i].cmd, tcpAipFuncs[i]));
        }
    }
    return &gmcmApiFuncs->apiMap;
}

unsigned int randBytes(unsigned char *reqStr, unsigned int reqStrLen, protoBase *respBase)
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

    sdfMeth *pMeth = gmcmServer::getSdfMeth();

    ret = pMeth->GenerateRandom(*reqPkg.length, respPkg.random);
    if(ret)
    {
        printf("rand byte fail = %d\n", ret);
        return ret;
    }

    *respPkg.randomPlen = *reqPkg.length;

    return ret;
}

unsigned int genEccKeyPair(unsigned char *reqStr, unsigned int reqStrLen, protoBase *respBase)
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

    sdfMeth *pMeth = gmcmServer::getSdfMeth();

    ret = pMeth->GenerateKeyPair_ECC(respPkg.pub, respPkg.pri);
    if(ret)
    {
        return ret;
    }

    *respPkg.pubPlen = sizeof(ECCrefPublicKey);
    *respPkg.priPlen = sizeof(ECCrefPrivateKey);

    return ret;
}

unsigned int importKey(unsigned char *reqStr, unsigned int reqStrLen, protoBase *respBase)
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

    sdfMeth *pMeth = gmcmServer::getSdfMeth();

    ret = pMeth->ImportKey(reqPkg.uikey, *reqPkg.uikeyPlen, respPkg.handle, respPkg.handlePlen);
    if (ret)
    {
        return ret;
    }
    
    return ret;
}

unsigned int destroyKey(unsigned char *reqStr, unsigned int reqStrLen, protoBase *respBase)
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

    sdfMeth *pMeth = gmcmServer::getSdfMeth();

    ret = pMeth->DestroyKey(reqPkg.handle, *reqPkg.handlePlen);
    if (ret)
    {
        return ret;
    }

    return ret;
}
/*
5A
0400
5C
00000000
0400
21040000
1000C09FF9B1B67F000000000000000000002400F50AB393C6F2DA710D135CFC1A8FE11EFA10D2CE75C5950B7726C7D48867C2B1BF41D1F7
*/
unsigned int encrypt(unsigned char *reqStr, unsigned int reqStrLen, protoBase *respBase)
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

    sdfMeth *pMeth = gmcmServer::getSdfMeth();

    ret = pMeth->encrypt(reqPkg.handle, *reqPkg.handlePlen,
                         *reqPkg.algid, reqPkg.iv, reqPkg.data, *reqPkg.dataPlen,
                         respPkg.encData, respPkg.encDataPlen);
    if (ret)
    {
        return ret;
    }
    else
    {
        memcpy(respPkg.iv, reqPkg.iv, *reqPkg.ivPlen);
        *respPkg.ivPlen = *reqPkg.ivPlen;
    }

    return ret;
}

unsigned int decrypt(unsigned char *reqStr, unsigned int reqStrLen, protoBase *respBase)
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
    reqPkg.print();

    sdfMeth *pMeth = gmcmServer::getSdfMeth();

    ret = pMeth->decrypt(reqPkg.handle, *reqPkg.handlePlen,
                         *reqPkg.algid, reqPkg.iv, reqPkg.encData, *reqPkg.encDataPlen,
                         respPkg.decData, respPkg.decDataPlen);
    if (ret)
    {
        return ret;
    }
    else
    {
        memcpy(respPkg.iv, reqPkg.iv, *reqPkg.ivPlen);
        *respPkg.ivPlen = *reqPkg.ivPlen;
    }

    respPkg.print();
    return ret;
}