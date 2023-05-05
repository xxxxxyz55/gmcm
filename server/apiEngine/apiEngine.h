#ifndef _GMCM_API_ENGINE_H_
#define _GMCM_API_ENGINE_H_

#include <map>
#include <string>
#include <functional>
#include <vector>
#include "../tool/gmcmLog.h"
#include "util/tc_http.h"
#include "pst.h"

template <typename T>
class apiEngine
{
private:
    map<std::string, T> apiMap;

public:
    apiEngine()
    {
        apiMap.clear();
    }

    bool loadApi(std::pair<std::string, T> api)
    {
        return apiMap.insert(api).second;
    }

    void loadApis(std::vector<std::pair<std::string, T>> vtApi)
    {
        for (size_t i = 0; i < vtApi.size(); i++)
        {
            if (loadApi(vtApi[i]))
            {
                gmcmLog::LogDebug() << "load API : " << vtApi[i].first << endl;
            }
            else
            {
                gmcmLog::LogError() << "load API fail : " << vtApi[i].first << endl;
            }
        }
    }

    // handle
    T getApiFunc(string action)
    {
        try
        {
            return apiMap.at(action);
        }
        catch (const std::exception &e)
        {
            return NULL;
        }
    }

    ~apiEngine()
    {
        apiMap.clear();
    }
};


typedef unsigned int (*hsmApiClvFuncPtr)(unsigned char *req, unsigned int reqLen, std::function<int32_t(void *, uint16_t)> writeCb);
class hsmApiClvEngine : public apiEngine<hsmApiClvFuncPtr>
{
public:
    hsmApiClvEngine();
    ~hsmApiClvEngine();
};


typedef unsigned int (*mgmtApiFuncPtr)(tars::TC_HttpRequest *request, tars::TC_HttpResponse *response);
class mgmtApiEngine : public apiEngine<mgmtApiFuncPtr>
{
public:
    mgmtApiEngine();
    ~mgmtApiEngine();
};

typedef unsigned int (*svsApiFuncPtr)(tars::TC_HttpRequest *request, tars::TC_HttpResponse *response);
class svsApiEngine : public apiEngine<svsApiFuncPtr>
{
public:
    svsApiEngine();
    ~svsApiEngine();
};

#endif