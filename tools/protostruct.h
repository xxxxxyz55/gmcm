
#ifndef _CM_PROTOSTRUCT_H_
#define _CM_PROTOSTRUCT_H_
#include <iostream>
#include "./utilFunc.h"

#define BASE_CMD 20

#define PROTOTST_MAX_FIELD  16
#define PROTOTST_MAX_LEN  1024*32
#define PKG_LENGTH_TYPE unsigned short

typedef unsigned int (*writeCallBack)(unsigned char *buf, unsigned int length);
typedef unsigned int (*checkParamCallBack)(unsigned char * param, PKG_LENGTH_TYPE len);

class protoBase
{
private:
public:
    unsigned int fieldNum;
    PKG_LENGTH_TYPE length[PROTOTST_MAX_FIELD];
    unsigned char *pVal[PROTOTST_MAX_FIELD];
    checkParamCallBack pCheck[PROTOTST_MAX_FIELD];

    protoBase(/* args */)
    {
        for (size_t i = 0; i < PROTOTST_MAX_FIELD; i++)
        {
            pVal[i] = (unsigned char *)calloc(1, 8192);
        }
    }

    ~protoBase()
    {
        for (size_t i = 0; i < PROTOTST_MAX_FIELD; i++)
        {
            if (pVal[i] != NULL)
            {
                free(pVal[i]);
            }
        }
    }
    void print()
    {
        for(size_t i = 0 ; i < fieldNum; i ++)
        {
            utilTool::printHex(pVal[i], length[i]);
        }
        printf("\n");
    }
};

//处理请求 返回相应格式
typedef unsigned int (*processFuncCallback)(unsigned char *req, unsigned int reqLen, protoBase *resp);

typedef struct protoStField_st
{
    PKG_LENGTH_TYPE * pLength;
    void *pValue;
    checkParamCallBack pCheck;
} protoStField;

typedef struct protoStPointer_st
{
    protoStField pField[PROTOTST_MAX_FIELD];
} protoStPointer;

#define PROTOST_FUNC_GET_FIELD_NUM(name)                                                        \
    unsigned int getFieldNum()                                                                  \
    {                                                                                           \
        return sizeof(name) / sizeof(NULL) / 3;                                                 \
    }

#define PROTOST_FUNC_GET_FIELD(name)                                             \
    void *getField(unsigned int fieldIndex)                                      \
    {                                                                            \
        if (fieldIndex > PROTOTST_MAX_FIELD || fieldIndex > this->getFieldNum()) \
        {                                                                        \
            return NULL;                                                         \
        }                                                                        \
        return ((protoStPointer *)this)->pField[fieldIndex].pValue;             \
    }

#define PROTOST_FUNC_GET_FIELD_LENGTH(name)                                      \
    PKG_LENGTH_TYPE *getFieldLen(unsigned int fieldIndex)                           \
    {                                                                            \
        if (fieldIndex > PROTOTST_MAX_FIELD || fieldIndex > this->getFieldNum()) \
        {                                                                        \
            return NULL;                                                         \
        }                                                                        \
        return ((protoStPointer *)this)->pField[fieldIndex].pLength;            \
    }

#define PROTOST_FUNC_GET_CHECK_FUNC(name)                                        \
    checkParamCallBack getCheckFunc(unsigned int fieldIndex)                     \
    {                                                                            \
        if (fieldIndex > PROTOTST_MAX_FIELD || fieldIndex > this->getFieldNum()) \
        {                                                                        \
            return NULL;                                                         \
        }                                                                        \
        return ((protoStPointer *)this)->pField[fieldIndex].pCheck;              \
    }

#define PROTOST_FUNC_SET_FIELD(name)                                                    \
    unsigned int setField(unsigned int fieldIndex, void *val, PKG_LENGTH_TYPE *pLength) \
    {                                                                                   \
        if (fieldIndex >= PROTOTST_MAX_FIELD)                                           \
        {                                                                               \
            return 1;                                                                   \
        }                                                                               \
                                                                                        \
        ((protoStPointer *)this)->pField[fieldIndex].pValue = val;                      \
        if (pLength != NULL)                                                            \
        {                                                                               \
            ((protoStPointer *)this)->pField[fieldIndex].pLength = pLength;             \
        }                                                                               \
        return 0;                                                                       \
    }

#define PROTOST_FUNC_POINT_TO_BASE(name)                        \
    unsigned int pointToBase(protoBase *base)                   \
    {                                                           \
        if (base == NULL)                                       \
        {                                                       \
            return 1;                                           \
        }                                                       \
                                                                \
        for (size_t i = 0; i < this->getFieldNum(); i++)        \
        {                                                       \
            this->setField(i, base->pVal[i], &base->length[i]); \
        }                                                       \
        base->fieldNum = this->getFieldNum();                   \
        return 0;                                               \
    }

#define PROTOST_FUNC_POINT_TO_BUFFER(name)                                                                      \
    unsigned int pointToBuffer(unsigned char *buffer, unsigned int length)                                      \
    {                                                                                                           \
        if (buffer == NULL)                                                                                     \
        {                                                                                                       \
            return 1;                                                                                           \
        }                                                                                                       \
        unsigned int offset = 0;                                                                                \
        checkParamCallBack pCheckParam = NULL;                                                                  \
                                                                                                                \
        for (size_t i = 0; i < this->getFieldNum(); i++)                                                        \
        {                                                                                                       \
            this->setField(i, buffer + offset + sizeof(PKG_LENGTH_TYPE), (PKG_LENGTH_TYPE *)(buffer + offset)); \
            pCheckParam = this->getCheckFunc(i);                                                                \
            if (pCheckParam)                                                                                    \
            {                                                                                                   \
                unsigned int iRet = pCheckParam((unsigned char *)this->getField(i), *this->getFieldLen(i));     \
                if (iRet)                                                                                       \
                {                                                                                               \
                    return iRet;                                                                                \
                }                                                                                               \
            }                                                                                                   \
            offset += sizeof(PKG_LENGTH_TYPE) + *this->getFieldLen(i);                                          \
        }                                                                                                       \
        return 0;                                                                                               \
    }

#define PROTOST_FUNC_PRINT(name)                                                           \
    void print()                                                                           \
    {                                                                                      \
        for (size_t i = 0; i < this->getFieldNum(); i++)                                   \
        {                                                                                  \
            utilTool::printHex((unsigned char *)this->getField(i), *this->getFieldLen(i)); \
        }                                                                                  \
        printf("\n");                                                                      \
    }

#define PROTOST_BEGIN(name, decs) \
    class name                    \
    {                             \
    public:                       \
        name(){};                 \
        ~name(){};

#define PROTOST_FIELD_ADD(field, type, checkParam) \
    PKG_LENGTH_TYPE *field##Plen;                  \
    type *field;                                   \
    checkParamCallBack field##Check = checkParam;

#define PROTOST_END(name)               \
    PROTOST_FUNC_GET_FIELD_NUM(name)    \
    PROTOST_FUNC_GET_FIELD(name)        \
    PROTOST_FUNC_SET_FIELD(name)        \
    PROTOST_FUNC_GET_CHECK_FUNC(name)   \
    PROTOST_FUNC_POINT_TO_BUFFER(name)  \
    PROTOST_FUNC_POINT_TO_BASE(name)    \
    PROTOST_FUNC_GET_FIELD_LENGTH(naem) \
    PROTOST_FUNC_PRINT(name)            \
    }                                   \
    ;

#define BASE_SET_VAL(field, val, len) \
    memcpy(field, &val, len);         \
    *field##Plen = len;

#define BASE_SET_STR(field, val, len) \
    memcpy(field, val, len);          \
    *field##Plen = len;

PROTOST_BEGIN(respErr, "错误返回包")
PROTOST_FIELD_ADD(iRet, unsigned int, NULL)
PROTOST_END(respErr)

#endif