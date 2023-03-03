#ifndef _PROTO_JSON_STRUCT_H_
#define _PROTO_JSON_STRUCT_H_

#include <stdio.h>
#include "cJSON.h"
#include <string.h>
#include <stdint.h>
#include "utilFunc.h"

namespace pjst
{

#define PJST_MAX_FIELD_NUM 16
#define PJST_MAX_FIELD_LEN 8192

enum pjstFiledType
{
    PJST_STRING = 1,
    PJST_NUM,
    PJST_BASE64,
};

typedef int (*pjst_check_param_callback)(void *param, pjstFiledType type);

class pjstFieldPtr
{
    cJSON *val;
    pjst_check_param_callback pCheck;
    const char *name;
    unsigned char type;
    char required;
    friend class pjstFieldPtrsFunc;

public:
    pjstFieldPtr(const char *name, pjstFiledType type, char isRequired, pjst_check_param_callback checkCb)
    {
        this->name = name;
        this->type = type;
        this->required = isRequired;
        this->pCheck = checkCb;
    }
    pjstFieldPtr(){};

    cJSON *ptr()
    {
        return this->val;
    }

    double num()
    {
        return this->val->valuedouble;
    }

    char *str()
    {
        return this->val->valuestring;
    }
};

class pjstFieldPtrsData
{
private:
    const char *errField;
    cJSON *_jReq;
    unsigned int fieldNum = 0;
    pjstFieldPtr fields[PJST_MAX_FIELD_NUM];
    friend class pjstFieldPtrsFunc;
};

class pjstFieldPtrsFunc
{

private:

    pjstFieldPtr *getField(unsigned int index)
    {
        return &((pjstFieldPtrsData *)this)->fields[index];
    }

public:
    unsigned int getFieldNum()
    {
        return ((pjstFieldPtrsData *)this)->fieldNum;
    }

    void setErrField(const char *name)
    {
        ((pjstFieldPtrsData *)this)->errField = name;
    }

    int pointToPuffer(const char *reqStr)
    {
        setErrField(NULL);
        cJSON *jReq = cJSON_Parse(reqStr);
        if(jReq == NULL)
        {
            setErrField("invalid json format.");
            return 41;
        }

        for (size_t i = 0; i < getFieldNum(); i++)
        {
            pjstFieldPtr *pField = getField(i);
            pField->val = cJSON_GetObjectItem(jReq, pField->name);
            if (pField->val == NULL && pField->required)
            {
                setErrField(pField->name);
                cJSON_Delete(jReq);
                printf("get json value fail, key [%s]\n", pField->name);
                return 4;
            }
            else
            {
                int iRet = 0;
                if (pField->type == PJST_STRING)
                {
                    if (pField->pCheck)
                    {
                        iRet = pField->pCheck((void *)pField->val->valuestring, PJST_STRING);
                    }
                }
                else if (pField->type == PJST_NUM)
                {
                    if (pField->pCheck)
                    {
                        iRet = pField->pCheck((void *)&pField->val->valuedouble, PJST_NUM);
                    }
                }
                else
                {
                    setErrField("json format is'nt support.");
                    cJSON_Delete(jReq);
                    return 42;
                }
                if(iRet)
                {
                    return iRet;
                }
            }
        }
        ((pjstFieldPtrsData *)this)->_jReq = jReq;
        return 0;
    }

    void print()
    {
        printf("========================\n");
         for (size_t i = 0; i < getFieldNum(); i++)
        {
            pjstFieldPtr *pField = getField(i);
            printf("key     [%s]\n", pField->name);
            printf("type    [%d]\n", pField->type);
            printf("val     [%s][%lf]\n", pField->val->valuestring, pField->val->valuedouble);
        }
        printf("========================\n");
    }
};

#define PJST_FIELD_BEGIN(name, desc)      \
    class name : public pjstFieldPtrsFunc \
    {                                     \
    public:                               \
        const char *errField;             \
        cJSON *_jReq = NULL;              \
        unsigned int fieldNum = (sizeof(name) - 24) / sizeof(pjstFieldPtr);

#define PJST_FIELD_ADD(name, type, isRequired, checkCb) \
    pjstFieldPtr name{#name, type, isRequired, checkCb};

#define PJST_FIELD_END(name)     \
public:                          \
    ~name()                      \
    {                            \
        if (_jReq)               \
        {                        \
            cJSON_Delete(_jReq); \
        }                        \
    }                            \
                                 \
private:                         \
    }                            \
    ;

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

    cJSON * addbase64Str(const char *key, unsigned char * str, unsigned int len)
    {
        char *b64Buf = new char[((len / 3) + 1) * 4];
        base64::base64Encode(str, len, b64Buf);
        cJSON *pObj = cJSON_AddStringToObject(pResponse, key, b64Buf);
        delete b64Buf;
        return pObj;
    }

    char *toResponseStr()
    {
        return cJSON_Print(pResponse);
    }

private:
    cJSON *pResponse;
};

} // namespace pjst

#endif