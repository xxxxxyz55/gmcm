#ifndef _GMCM_API_ENGINE_H_
#define _GMCM_API_ENGINE_H_

#include <map>
#include <string>
#include <functional>
#include <vector>
#include "../tool/gmcmLog.h"

using namespace std;

template <typename T>
class apiEngine
{
private:
    map<string, T> apiMap;

public:
    apiEngine(vector<pair<string, T>> vec)
    {
        apiMap.clear();
        for (size_t i = 0; i < vec.size(); i++)
        {
            apiMap.insert(vec[i]);
            gmcmLog::LogDebug() << "insert API : " << vec[i].first << endl;
        }
    }

    //handle
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


#endif