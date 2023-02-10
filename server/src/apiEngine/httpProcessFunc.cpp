#include "httpProcessFunc.h"
#include "../server.h"
#include "util/tc_base64.h"
#include "../package/jsonResp.h"
#include "../gmcmLog.h"

using namespace std;
using namespace tars;

httpApiEngine *httpApiEngine::gmcmApiFuncs = NULL;

static httpDealFunc httpAipFuncs[]{
    {"help", helpPage},
    {"GenerateRandom", httpGenerateRandom},
};

map<string, httpDealFunc> *httpApiEngine::getMap()
{
    if (gmcmApiFuncs == NULL)
    {
        gmcmLog::LogInfo() << "http api engine init" << endl;
        gmcmApiFuncs = new httpApiEngine();
        gmcmApiFuncs->apiMap.clear();
        for (size_t i = 0; i < (sizeof(httpAipFuncs) / sizeof(httpDealFunc)); i++)
        {
            printf("action [%s] [%p]\n", httpAipFuncs[i].action, &httpAipFuncs[i]);
            gmcmApiFuncs->apiMap.insert(pair<string, httpDealFunc>(httpAipFuncs[i].action, httpAipFuncs[i]));
        }
    }
    return &gmcmApiFuncs->apiMap;
}

unsigned int helpPage(TC_HttpRequest *request, TC_HttpResponse *response)
{
    jsonResp jResp;
    jResp.addRespField("random", "http://host:port/GenerateRandom");
    response->setResponse(200, "OK", jResp.toResponseStr());
    return 0;
}

unsigned int httpGenerateRandom(TC_HttpRequest *request, TC_HttpResponse *response)
{
    reqGenerateRandom req;
    cJSON *jReq = cJSON_Parse(request->getContent().data());
    unsigned int iRet = req.parseParams(jReq);
    if(iRet)
    {
        return iRet;
    }

    return GMCM_OK;
}