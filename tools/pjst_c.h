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

    string toResponseStr()
    {
        char * pJson = cJSON_Print(pResponse);
        string str(pJson);
        free(pJson);
        return str;
    }

private:
    cJSON *pResponse;
};

class pjstFieldPtr
{
    void *val;
    pjst_check_param_callback pCheck;
    const char *name;
    unsigned char type;
    char required;
    char isReq;
    friend class pjstFieldPtrsFunc;

public:
    pjstFieldPtr(const char *name, pjstFiledType type, char isRequired, pjst_check_param_callback checkCb, char isReq)
    {
        this->name = name;
        this->type = type;
        this->required = isRequired;
        this->pCheck = checkCb;
        this->isReq = isReq;
    }

    pjstFieldPtr(const char *name, unsigned int size, pjstFiledType type, char isReq)
    {
        this->name = name;
        this->type = type;
        this->isReq = isReq;
        if (type == PJST_NUM)
        {
            this->val = new double;
        }
        else
        {
            this->val = new char[size];
        }
    }
    pjstFieldPtr(){};

    ~pjstFieldPtr()
    {
        if (isReq == 0)
        {
            if (type == PJST_NUM)
            {
                delete (double *)val;
            }
            else
            {
                delete (char *)val;
            }
        }
    }

    cJSON *ptr()
    {
        if (!isReq)
        {
            return NULL;
        }
        return (cJSON *)this->val;
    }

    double num()
    {
        if (isReq)
        {
            return ((cJSON *)this->val)->valuedouble;
        }
        else
        {
            return *(double *)this->val;
        }
    }

    double *pNum()
    {
        if (isReq)
        {
            return &((cJSON *)this->val)->valuedouble;
        }
        else
        {
            return (double *)this->val;
        }
    }

    bool setNUM(double num)
    {
        if(isReq)
        {
            return false;
        }
        else
        {
            *(double *)this->val = num;
            return true;
        }
    }

    char *str()
    {
        if(isReq)
        {
            return ((cJSON *)this->val)->valuestring;
        }
        else
        {
            return (char *)this->val;
        }
    }

    bool setStr(const char *str)
    {
        if(isReq)
        {
            return false;
        }
        else
        {
            strcpy((char *)this->val, str);
            return true;
        }
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
                    printf("name [%s] val[%s] addr [%p]\n", pField->name, pField->str(), pField->ptr());
                    if (pField->pCheck)
                    {
                        iRet = pField->pCheck((void *)pField->str(), PJST_STRING);
                    }
                }
                else if (pField->type == PJST_NUM)
                {
                    printf("name [%s] val[%lf] addr [%p]\n", pField->name, pField->num(), pField->ptr());
                    if (pField->pCheck)
                    {
                        iRet = pField->pCheck((void *)pField->pNum(), PJST_NUM);
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

    string toJsonStr()
    {
        jsonResp resp;
        for (size_t i = 0; i < getFieldNum(); i++)
        {
            pjstFieldPtr *pField = getField(i);
            if(pField->type == PJST_STRING)
            {
                resp.addRespField(pField->name, pField->str());
            }
            else if (pField->type == PJST_NUM)
            {
                resp.addRespField(pField->name, pField->num());
            }
            else
            {
                resp.addRespField(pField->name, pField->str());
            }
        }

        return resp.toResponseStr();
    }

    void print()
    {
        printf("========================\n");
         for (size_t i = 0; i < getFieldNum(); i++)
        {
            pjstFieldPtr *pField = getField(i);
            printf("key     [%s]\n", pField->name);
            printf("type    [%d]\n", pField->type);
            if (pField->type == PJST_NUM)
            {
                printf("val     [%lf]\n", pField->num());
            }
            else
            {
                printf("val     [%s]\n", pField->str());
            }
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

#define PJST_FIELD_ADD_REQ(name, type, isRequired, checkCb) \
    pjstFieldPtr name{#name, type, isRequired, checkCb, 1};

#define PJST_FIELD_ADD_RESP(name, size, type) \
    pjstFieldPtr name{#name, size, type, 0};

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


} // namespace pjst

#endif