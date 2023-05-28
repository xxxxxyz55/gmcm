#include "mgmtApi.h"
#include "util/tc_http.h"
#include "mgmtPkt.h"

using namespace tars;

void mgmtHelpPage(TC_HttpRequest *request, TC_HttpResponse *response)
{
    jsonPkt jResp;
    jResp.addRespField("random", "http://host:port/GenerateRandom");
    response->setResponse(200, "OK", jResp.toJsonStr());
}

vector<pair<string, mgmtApiFuncPtr>>  getMgmtApis()
{
    vector<pair<string, mgmtApiFuncPtr>> vtApi;
    vtApi.push_back(pair<string, mgmtApiFuncPtr>("help", mgmtHelpPage));
    return vtApi;
}