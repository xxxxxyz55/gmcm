#ifndef _PROTO_JSON_STRUCT_H_
#define _PROTO_JSON_STRUCT_H_

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "utilFunc.h"
#include "util/tc_json.h"
#include <string>

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

typedef int (*pjst_check_param_callback)(void *param, uint32_t type);

class jsonResp
{
public:
    jsonResp()
    {
        pResponse = new tars::JsonValueObj();
    }

    tars::JsonValueObjPtr getResp()
    {
        return pResponse;
    }

    void addRespField(const char *key, const char *val)
    {
        pResponse->value[key] = new tars::JsonValueString(val);
    }

    void addRespField(const char *key, double num)
    {
        pResponse->value[key] = new tars::JsonValueNum(num);
    }

    void addRespField(const char *key, int64_t num)
    {
        pResponse->value[key] = new tars::JsonValueNum(num);
    }

    void addbase64Str(const char *key, unsigned char *str, unsigned int len)
    {
        char *b64Buf = new char[((len / 3) + 1) * 4];
        base64::base64Encode(str, len, b64Buf);
        pResponse->value[key] = new tars::JsonValueString(b64Buf);
        delete[] b64Buf;
    }
    void addJson(const char *key, jsonResp &obj)
    {
        pResponse->value[key] = obj.getResp();
    }

    string toResponseStr()
    {
        return tars::TC_Json::writeValue(pResponse);
    }
    void print() {}
    string toJsonStr() { return toResponseStr(); }
private:
    tars::JsonValueObjPtr pResponse;
};


class pjstFieldPtr
{
    union {
        tars::JsonValue *jVal;
        void *pVal;
    };

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
            this->pVal = new double;
        }
        else
        {
            this->pVal = new char[size];
        }
    }
    pjstFieldPtr(){};

    ~pjstFieldPtr()
    {
        if(type == PJST_NUM)
        {
            delete (double *)this->pVal;
        }
        else
        {
            delete[] (char *)this->pVal;
        }
        
    }

    tars::JsonValue *ptr()
    {
        if (!isReq)
        {
            return NULL;
        }
        return this->jVal;
    }

    double num()
    {
        if (isReq)
        {
            // return JsonValueNumPtr::dynamicCast(this->jVal)->value;
            return ((tars::JsonValueNum *)this->jVal)->value;
        }
        else
        {
            return *(double *)this->pVal;
        }
    }

    double *pNum()
    {
        if (isReq)
        {
            // return &JsonValueNumPtr::dynamicCast(this->jVal)->value;
            return &((tars::JsonValueNum *)this->jVal)->value;
        }
        else
        {
            return (double *)this->pVal;
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
            *(double *)this->pVal = num;
            return true;
        }
    }

    /*const */
    char *str()
    {
        if(isReq)
        {
            return (char *)((tars::JsonValueString *)this->jVal)->value.c_str();
            // return (char *)JsonValueStringPtr::dynamicCast(this->jVal)->value.c_str();
        }
        else
        {
            return (char *)this->pVal;
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
            strcpy((char *)this->pVal, str);
            return true;
        }
    }
};

class pjstFieldPtrsData
{
private:
    const char *errField;
    tars::JsonValueObjPtr _jReq;
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
        tars::JsonValueObjPtr jReq;
        try
        {
            jReq = tars::JsonValueObjPtr::dynamicCast(tars::TC_Json::getValue(reqStr));
        }
        catch(const std::exception& e)
        {
            setErrField("invalid json format.");
            return 41;
        }
        
        for (size_t i = 0; i < getFieldNum(); i++)
        {
            pjstFieldPtr *pField = getField(i);
            try
            {
                printf("name %s field num %d\n", pField->name, getFieldNum());
                pField->jVal = jReq->get(pField->name).get();
                printf("get ok\n");
            }
            catch(const std::exception& e)
            {
                if(pField->required)
                {
                    setErrField(pField->name);
                    printf("get json value fail, key [%s]\n", pField->name);
                    return 4;
                }
            }

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
                return 42;
            }
            if (iRet)
            {
                return iRet;
            }
        }
        /*内存泄漏？*/
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
        tars::JsonValueObjPtr _jReq;      \
        unsigned int fieldNum = (sizeof(name) - 24) / sizeof(pjst::pjstFieldPtr);

#define PJST_FIELD_ADD_REQ(name, type, isRequired, checkCb) \
    pjst::pjstFieldPtr name{#name, type, isRequired, checkCb, 1};

#define PJST_FIELD_ADD_RESP(name, size, type) \
    pjst::pjstFieldPtr name{#name, size, type, 0};

#define PJST_FIELD_END(name)     \
public:                          \
    ~name()                      \
    {                            \
    }                            \
                                 \
private:                         \
    }                            \
    ;


} // namespace pjst

#endif