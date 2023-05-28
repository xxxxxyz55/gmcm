#ifndef _GMCM_API_ENGINE_H_
#define _GMCM_API_ENGINE_H_

#include <map>
#include <string>
#include <functional>
#include <vector>
#include "../tool/gmcmLog.h"
#include "util/tc_http.h"

template <typename T>
class apiEngine
{
private:
    map<std::string, T> _apiMap;
    T _defCb = NULL;

public:
    apiEngine()
    {
    }

    ~apiEngine()
    {
        _apiMap.clear();
    }

    // handle
    T getApiFunc(string action)
    {
        try
        {
            return _apiMap.at(action);
        }
        catch (const std::exception &e)
        {
            return _defCb;
        }
    }

protected:
    bool loadApi(std::pair<std::string, T> api)
    {
        return _apiMap.insert(api).second;
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

    void setDefcb(T cb)
    {
        _defCb = cb;
    }

};

typedef string (*hsmApiFuncPtr)(unsigned char *req, unsigned int reqLen);
class hsmApiEngine : public apiEngine<hsmApiFuncPtr>
{
public:
    hsmApiEngine();
    ~hsmApiEngine();
};

typedef void (*mgmtApiFuncPtr)(tars::TC_HttpRequest *request, tars::TC_HttpResponse *response);
class mgmtApiEngine : public apiEngine<mgmtApiFuncPtr>
{
public:
    mgmtApiEngine();
    ~mgmtApiEngine();
};

typedef void (*svsApiFuncPtr)(tars::TC_HttpRequest *request, tars::TC_HttpResponse *response);
class svsApiEngine : public apiEngine<svsApiFuncPtr>
{
public:
    svsApiEngine();
    ~svsApiEngine();
};

#endif