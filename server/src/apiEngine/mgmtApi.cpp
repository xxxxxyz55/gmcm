#include "mgmtApi.h"
#include "../package/packageDefine.h"
#include "../application/application.h"
#include "../tool/gmcmLog.h"

vector<pair<string, mgmtApiFuncPtr>> gMgmtAPiFuncs = {
    {"help", mgmtHelpPage},
};

mgmtApiEngine::mgmtApiEngine() : apiEngine<mgmtApiFuncPtr>(gMgmtAPiFuncs)
{
}

mgmtApiEngine::~mgmtApiEngine()
{
}

unsigned int mgmtHelpPage(TC_HttpRequest *request, TC_HttpResponse *response)
{
    jsonResp jResp;
    jResp.addRespField("random", "http://host:port/GenerateRandom");
    response->setResponse(200, "OK", jResp.toResponseStr());
    return GMCM_OK;
}

// curl 10.28.16.83:8806/GenerateRandom -d "{\"length\":32}"
/*
unsigned int mgmtGenerateRandom(TC_HttpRequest *request, TC_HttpResponse *response)
{
    reqGenerateRandom req;
    jsonResp jResp;

    cJSON * jReq = NULL;
    int iRet;
    iRet = req.pointToPuffer(request->getContent().data(), &jReq);
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
*/