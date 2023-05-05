#ifndef _PROTO_STRUCT_H_
#define _PROTO_STRUCT_H_

#include "./utilFunc.h"
#include <string.h>
/*
结构体和字符串转换
1.减少拷贝
2.打包解包复用
3.分读写操作，
读操作时，输入结构体ptr，完整字符串，
使ptr类中各个自动指针指向该缓冲区，使结构体中指针指向对于的地址
写操作时，输如缓存区类，写操作函数(如send)
自动发送所有字段数据
*/

/*
LV 格式 结构体中每个字段 2字节长度 + n字节数据
len     xxxx         2byte
data    len byte     len
len     xxxx         2byte
data    len byte     len
len     xxxx         2byte
data    len byte     len
.....
*/
//

namespace pst
{

#define PST_MAX_FIELD_NUM 16
#define PST_MAX_FIELD_LEN 8192
#define PST_PKG_LEN_TYPE unsigned short
typedef int (*pst_write_callback)(unsigned char *buf, unsigned int length);
typedef int (*pst_check_param_callback)(unsigned char *param, PST_PKG_LEN_TYPE len);

class pstField
{
public:
    PST_PKG_LEN_TYPE length;
    unsigned char value[PST_MAX_FIELD_LEN];
    pst_check_param_callback pCheck;
    unsigned char type;
};

class pstBuffer
{
public:
    pstField *field;
    unsigned int fieldNum;

    pstBuffer()
    {
        field = new pstField[PST_MAX_FIELD_NUM];
    }
    ~pstBuffer()
    {
        delete[] field;
    }
    void print()
    {
        for (size_t i = 0; i < fieldNum; i++)
        {
            utilTool::printHex(field->value, field->length);
        }
    }
};

enum pstFiledType
{
    PST_U_STRING = 1,
    PST_U_INT = 2,
    PST_U_SHORT,
    PST_ST,
    PST_BASE64,
};

class pstFieldPtr
{
public:
    PST_PKG_LEN_TYPE *pLen;
    void *pValue;
private:
    pst_check_param_callback pCheck;
    unsigned char type;
    const char *name;
    friend class pstFieldPtrsFunc;

public:
    pstFieldPtr(){};
    pstFieldPtr(const char *sName, pstFiledType cType, pst_check_param_callback check)
    {
        pCheck = check;
        type = cType;
        name = sName;
    }

    unsigned char *uStrVal()
    {
        return (unsigned char *)pValue;
    }

    unsigned int uIntVal()
    {
        return *(unsigned int *)pValue;
    }

    PST_PKG_LEN_TYPE length()
    {
        return *pLen;
    }

    template<typename T>
    T * stPtr()
    {
        return (T *)this->pValue;
    }

    void setVal(unsigned int val)
    {
        *(unsigned int *)pValue = val;
        *pLen = sizeof(unsigned int);
    }

    void setVal(unsigned char *val, unsigned int valLen)
    {
        memcpy(pValue, val, valLen);
        *pLen = valLen;
    }

    void setVal(unsigned char *val, unsigned short valLen)
    {
        memcpy(pValue, val, valLen);
        *pLen = valLen;
    }

    void setLength(PST_PKG_LEN_TYPE len)
    {
        *pLen = len;
    }

    void operator=(pstFieldPtr ptr)
    {
        setVal(ptr.uStrVal(), ptr.length());
    }
};

class pstFieldPtrsData
{
private:
    const char *errField;
    unsigned int fieldNum = 0;
    pstFieldPtr fields[PST_MAX_FIELD_NUM];
    friend class pstFieldPtrsFunc;
};

class pstFieldPtrsFunc
{
private:
    pstFieldPtr *getField(unsigned int index)
    {
        return &((pstFieldPtrsData *)this)->fields[index];
    }

    PST_PKG_LEN_TYPE getFieldLen(unsigned int index)
    {
        return *((pstFieldPtrsData *)this)->fields[index].pLen;
    }

    PST_PKG_LEN_TYPE getFieldType(unsigned int index)
    {
        return ((pstFieldPtrsData *)this)->fields[index].type;
    }

    pst_check_param_callback getCheckFunc(unsigned int index)
    {
        return ((pstFieldPtrsData *)this)->fields[index].pCheck;
    }

    const char *getFieldName(unsigned int index)
    {
        return ((pstFieldPtrsData *)this)->fields[index].name;
    }

    void setField(unsigned int index, void *val, PST_PKG_LEN_TYPE *pLength)
    {
        ((pstFieldPtrsData *)this)->fields[index].pValue = val;
        ((pstFieldPtrsData *)this)->fields[index].pLen = pLength;
    }

    unsigned int getFieldNum()
    {
        return ((pstFieldPtrsData *)this)->fieldNum;
    }

    void setErrField(const char *name)
    {
        ((pstFieldPtrsData *)this)->errField = name;
    }

public:
    unsigned int pointToBase(pstBuffer *base)
    {
        if (base == NULL)
        {
            return -1;
        }

        base->fieldNum = this->getFieldNum();
        for (size_t i = 0; i < base->fieldNum; i++)
        {
            this->setField(i, base->field[i].value, &base->field[i].length);
        }
        return 0;
    }

    const char *getErrField()
    {
        return ((pstFieldPtrsData *)this)->errField;
    }

    int pointToBuffer(unsigned char *buffer, unsigned int length)
    {
        if (buffer == NULL)
        {
            return -1;
        }
        unsigned int offset = 0;
        pst_check_param_callback pCheckParam = NULL;
        setErrField(NULL);
        
        for (size_t i = 0; i < this->getFieldNum(); i++)
        {
            this->setField(i, buffer + offset + sizeof(PST_PKG_LEN_TYPE), (PST_PKG_LEN_TYPE *)(buffer + offset));
            pCheckParam = this->getCheckFunc(i);
            if (pCheckParam)
            {
                int iRet = pCheckParam((unsigned char *)this->getField(i), this->getFieldLen(i));
                if (iRet)
                {
                    this->setErrField(getFieldName(i));
                    return iRet;
                }
            }
            offset += sizeof(PST_PKG_LEN_TYPE) + this->getFieldLen(i);
        }
        return 0;
    }

    void print()
    {
        for (size_t i = 0; i < this->getFieldNum(); i++)
        {
            printf("=======================\n");
            printf("name   [%s]\n", this->getFieldName(i));
            printf("length [%d]\n", this->getFieldLen(i));
            printf("type   [%d]\n", this->getFieldType(i));
            utilTool::printHex(this->getField(i)->uStrVal(), this->getFieldLen(i));
            printf("=======================\n");
        }
    }

};

class pstPtrs : public pstFieldPtrsData, public pstFieldPtrsFunc
{
};

#define PST_FIELD_BEGIN(name, decs)           \
    class name : public pst::pstFieldPtrsFunc \
    {                                         \
    public:                                   \
        const char *errField = NULL;          \
        unsigned int fieldNum = (sizeof(name) - 16) / sizeof(pst::pstFieldPtr);

#define PST_FIELD_ADD(field, type, checkCb) \
    pst::pstFieldPtr field{#field, type, checkCb};

#define PST_FIELD_END(name) \
    }                       \
    ;

inline int write_pst_base(pstBuffer *base, pst_write_callback pWriteFunc)
{
    int ret;
    for (size_t i = 0; i < base->fieldNum; i++)
    {
        ret = pWriteFunc((unsigned char *)&base->field[i].length, sizeof(PST_PKG_LEN_TYPE));
        if (ret)
        {
            return ret;
        }

        ret = pWriteFunc(base->field[i].value, base->field[i].length);
        if (ret)
        {
            return ret;
        }
    }
    return 0;
}

} // namespace pst
#endif