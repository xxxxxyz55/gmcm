#ifndef _GMCM_HTTP_PROCESS_FUNC_H_
#define _GMCM_HTTP_PROCESS_FUNC_H_

#include <iostream>
#include <map>
#include <string>
#include "util/tc_http.h"
#include "../package/httpParams.h"

typedef unsigned int (*httpApiFunc)(TC_HttpRequest *request, TC_HttpResponse *response);

typedef struct httpDealFunc_st
{
    char action[ACTION_MAX];
    httpApiFunc func;
} httpDealFunc;

class httpApiEngine
{
private:
    httpApiEngine(/* args */){};
    map<string, httpDealFunc> apiMap;
    static httpApiEngine *gmcmApiFuncs;

public:
    static map<string, httpDealFunc> *getMap();
    ~httpApiEngine()
    {
        apiMap.clear();
    };
};

#define ADD_HTTP_API_FUNC(name) unsigned int name(TC_HttpRequest *request, TC_HttpResponse *response);

ADD_HTTP_API_FUNC(helpPage)

HTTP_PARAM(reqGenerateRandom, "随机数")
HTTP_PARAM_ADD(length, "length", 1, NULL)
HTTP_PARAM_END(reqGenerateRandom)
ADD_HTTP_API_FUNC(httpGenerateRandom)

#endif