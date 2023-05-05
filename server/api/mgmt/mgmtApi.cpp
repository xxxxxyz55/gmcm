#include "mgmtApi.h"
#include "util/tc_http.h"
#include "pjst.h"

using namespace tars;
using namespace pjst;

unsigned int mgmtHelpPage(TC_HttpRequest *request, TC_HttpResponse *response)
{
    jsonResp jResp;
    jResp.addRespField("random", "http://host:port/GenerateRandom");
    response->setResponse(200, "OK", jResp.toResponseStr());
    return GMCM_OK;
}

vector<pair<string, mgmtApiFuncPtr>>  getMgmtApis()
{
    vector<pair<string, mgmtApiFuncPtr>> vtApi;
    vtApi.push_back(pair<string, mgmtApiFuncPtr>("help", mgmtHelpPage));
    return vtApi;
}