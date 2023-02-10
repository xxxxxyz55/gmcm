#ifndef _CM_HTTP_PARAMS_H_
#define _CM_HTTP_PARAMS_H_
#include "../gmcmErr.h"
#include "string.h"
#include "cJSON.h"
using namespace tars;

typedef unsigned int (*httpCheckParamCallBack)(char * param);

#define FIELD_NAME_MAX 32
#define HTTP_PARAM_MAX 16
#define ACTION_MAX 32

#define HTTP_PARAM(name, desc) \
    class name                 \
    {                          \
    public:                    \
        name(){};              \
        ~name(){};

#define HTTP_PARAM_ADD(field, name, required, checkParam) \
    char field##Required = required;                      \
    char *field;                                          \
    static constexpr const char *field##Name = "&" name;  \
    const char *pFieldName = field##Name;                 \
    httpCheckParamCallBack field##Check = checkParam;

typedef struct paramBase_st
{
    char required;
    char *pParamVal;
    char *paramName;
    httpCheckParamCallBack pCheck;
} paramBase;

typedef struct paramBasePointer_st
{
    paramBase param[HTTP_PARAM_MAX];
} paramBasePointer;

#define HTTP_GET_FIELD_NUM(name)                        \
    unsigned int getFieldNum()                          \
    {                                                   \
        return (sizeof(name) - 12) / sizeof(paramBase); \
    }

#define HTTP_GET_FIELD(name)                              \
    paramBase *getField(unsigned int index)               \
    {                                                     \
        return &((paramBasePointer *)this)->param[index]; \
    }

inline void cnvertChar(char *src, unsigned int srcLen, char oldChar, char newChar)
{
    for (size_t i = 0; i < srcLen; i++)
    {
        if (src[i] == oldChar)
        {
            src[i] = newChar;
        }
    }
}

#define HTTP_PARAM_PARSE(name)                                       \
    unsigned int parseParams(cJSON *jReq)                            \
    {                                                                \
        paramBase *pParam = NULL;                                    \
        for (size_t i = 0; i < getFieldNum(); i++)                   \
        {                                                            \
            pParam = getField(i);                                    \
            pParam->pParamVal = getJsonVal(jReq, pParam->paramName); \
            if (pParam->pParamVal == NULL && pParam->required)       \
            {                                                        \
                return GMCM_ERR_REQUIRED_PARAM;                      \
            }                                                        \
            this->code = pParam->pCheck(pParam->pParamVal);          \
            if (this->code)                                          \
            {                                                        \
                this->pErrParam = pParam->paramName;                 \
                return this->code;                                   \
            }                                                        \
        }                                                            \
        return GMCM_OK;                                              \
    }

#define HTTP_CJSON_GET(name)                          \
    char *getJsonVal(cJSON *pJSReq, const char *pKey) \
    {                                                 \
        cJSON *pVal = NULL;                           \
        pVal = cJSON_GetObjectItem(pJSReq, pKey);     \
        if (pVal == NULL)                             \
        {                                             \
            return NULL;                              \
        }                                             \
        else                                          \
        {                                             \
            return pVal->valuestring;                 \
        }                                             \
    }

#define HTTP_PARAM_FUNCS(name) \
    HTTP_PARAM_PARSE(name)     \
    HTTP_GET_FIELD_NUM(name)   \
    HTTP_GET_FIELD(name)       \
    HTTP_CJSON_GET(name)

#define HTTP_PARAM_END(name) \
    HTTP_PARAM_FUNCS(name)   \
    unsigned int code = 0;   \
    char *pErrParam = NULL;  \
    }                        \
    ;

inline unsigned int getAtcion(char *req, char action[ACTION_MAX], char **pValStart)
{
    if (memcmp(req, "?Action=", 8))
    {
        return GMCM_FAIL;
    }
    char *pReq = req + 8;
    size_t i;
    for (i = 0; i < ACTION_MAX - 1; i++)
    {
        if (pReq[i] == '&' || pReq[i] == '\0')
        {
            break;
        }
        action[i] = pReq[i];
    }
    action[i] = '\0';
    *pValStart = pReq + i;
    return GMCM_OK;
}

#endif