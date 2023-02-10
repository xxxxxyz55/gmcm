#ifndef _CM_JSON_RESP_H_
#define _CM_JSON_RESP_H_
#include "../gmcmErr.h"
#include "string.h"
#include "cJSON.h"

using namespace std;
using namespace tars;

class jsonResp
{
    public:
    jsonResp()
    {
        pResponse = cJSON_CreateObject();
    }
    
    ~jsonResp()
    {
        cJSON_Delete(pResponse);
    }

    cJSON *addRespField(const char *key, int8_t *val)
    {
        return cJSON_AddStringToObject(pResponse, key, (char *)val);
    }
    cJSON *addRespField(const char *key, const char *val)
    {
        return cJSON_AddStringToObject(pResponse, key, val);
    }

    cJSON *addRespField(const char *key, uint64_t val)
    {
        char sVal[32] = {0};
        snprintf(sVal, sizeof(sVal), "%ld", val);
        return cJSON_AddStringToObject(pResponse, key, sVal);
    }

    cJSON *addRespField(const char *key, double num)
    {
        return cJSON_AddNumberToObject(pResponse, key, num);
    }
    cJSON *addRespField(const char *key, int32_t num)
    {
        return cJSON_AddNumberToObject(pResponse, key, (double)num);
    }

    char * toResponseStr()
    {
        return cJSON_Print(pResponse);
    }

private:
    cJSON *pResponse;
};




#endif