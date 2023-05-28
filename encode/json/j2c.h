#ifndef _GMCM_JSON_TO_CLASS_H_
#define _GMCM_JSON_TO_CLASS_H_
#include <string>
#include <stdint.h>
#include <string.h>
#include <sstream>
#include <iostream>
#include "yyjson.h"
#include <vector>
#include <memory>
#include "utilFunc.h"

#define JSON_ERR_ENCODE            1 //编码错误
#define JSON_ERR_REQUIRED_PARAM    2 //缺少必须参数
#define JSON_ERR_FIELD_TYPE        3 //类型错误

//json 序列化成类 附带参数检查
//类转json字符串

#define V_JSON_STR      YYJSON_TYPE_STR
#define V_JSON_NUM      YYJSON_TYPE_NUM
#define V_JSON_OBJ      YYJSON_TYPE_OBJ
#define V_JSON_ARRAY    YYJSON_TYPE_ARR
#define V_JSON_BOOL     YYJSON_TYPE_BOOL
#define V_JSON_NULL     YYJSON_TYPE_NULL

// 参数检查回调
typedef int32_t (*jCheckVoid)(const void *val);
typedef int32_t (*jCheckStr)(const char *val);
typedef int32_t (*jCheckNum)(const double *val);
typedef int32_t (*jCheckBool)(const bool *val);

typedef struct yyjson_mut_st
{
    yyjson_mut_val *pKey;
    yyjson_mut_val *pVal;
} yyjson_mut;

class jHeader
{
private:
    const char *_key;
    bool _isRequired;
    const void *_val;
    friend class jObject;
    friend class jArray;

public:
    yyjson_doc *_jVal;
    jHeader(const char *key, bool isRequired) : _key(key),
                                                _isRequired(isRequired),
                                                _val(NULL),
                                                _jVal(NULL)
    {
    }
    virtual ~jHeader()
    {
        if (_jVal)
        {
            yyjson_doc_free(_jVal);
        }
    }

    virtual int32_t getType() { return V_JSON_NULL; }
    const char *getKey() { return _key; }

protected:
    /// @brief src void  to T
    /// @tparam T
    /// @return
    template <typename T>
    const T *getVal() { return (const T*)_val; }
    template <typename T>
    const T *setVal(const T *val)
    {
        _val = (const void *)val;
        return getVal<T>();
    }

    virtual void toString(size_t tabNum, std::ostringstream &jStream) {}
    virtual int32_t parseValue(yyjson_val *val) { return 0; }
    bool isRequired() { return _isRequired; }
};

class jString : public jHeader
{
private:
    jCheckStr _check;
    bool _allocFlag;

public:
    jString(const char *key, bool isRequired, jCheckStr check) : jHeader(key, isRequired), _check(check), _allocFlag(false)
    {
    }

    ~jString()
    {
        if (_allocFlag)
        {
            delete[] str();
        }
    }

    int32_t getType() { return V_JSON_STR; }
    const char *str() { return getVal<char>(); }

protected:
    void toString(size_t tabNum, std::ostringstream &jStream)
    {
        for (size_t i = 0; i < tabNum; i++)
        {
            jStream << "    ";
        }
        if (getKey())
        {
            jStream << "\"" << getKey() << "\":";
        }
        jStream << "\"" << str() << "\"";
    }

    int32_t parseValue(yyjson_val *pVal)
    {
        if (!yyjson_is_str(pVal))
        {
            return JSON_ERR_FIELD_TYPE;
        }

        // this->ref(yyjson_get_str(pVal));
        this->ref(pVal->uni.str);
        if (_check)
        {
            return _check(str());
        }
        return 0;
    }

public:
    //仅指向地址，生命周期依赖指向缓冲区
    const char *ref(const char *val)
    {
        return setVal<char>(val);
    }

    //申请空间 拷贝内容
    const char *dup(const char *val)
    {
        if(_allocFlag)
        {
            delete[] getVal<char>();
            _allocFlag = false;
        }
        size_t len = strlen(val);
        char *buf = new char[len];
        memcpy(buf, val, len);
        _allocFlag = true;
        return ref(buf);
    }
};

class jDouble : public jHeader
{
private:
    jCheckNum _check;
    bool _allocFlag;
public:

    jDouble(const char *key, bool isRequired, jCheckNum check) : jHeader(key, isRequired), _check(check), _allocFlag(false)
    {
    }
    ~jDouble()
    {
        if (_allocFlag)
        {
            delete ptr();
        }
    }

    int32_t getType() { return V_JSON_NUM; }
    const double *ptr() { return getVal<double>(); }
    double getNumVal() { return *getVal<double>(); }
    int32_t num() { return (int32_t)*getVal<double>(); }

protected:
    void toString(size_t tabNum, std::ostringstream &jStream)
    {
        for (size_t i = 0; i < tabNum; i++)
        {
            jStream << "    ";
        }
        if (getKey())
        {
            jStream << "\"" << getKey() << "\": ";
        }
        jStream << *ptr();
    }

    int32_t parseValue(yyjson_val *pVal)
    {
        // if (!yyjson_is_real(pVal) && !yyjson_is_num(pVal))
        yyjson_type type = unsafe_yyjson_get_type(pVal);
        if (type != YYJSON_TYPE_NUM)
        {
            return JSON_ERR_FIELD_TYPE;
        }

        yyjson_type subType = unsafe_yyjson_get_subtype(pVal);
        if (subType == YYJSON_SUBTYPE_SINT)
        {
            this->dup(pVal->uni.i64);
        }
        else if(subType == YYJSON_SUBTYPE_UINT)
        {
            this->dup(pVal->uni.u64);
        }
        else if (subType == YYJSON_SUBTYPE_REAL)
        {
            this->ref(&pVal->uni.f64);
        }
        else
        {
            return JSON_ERR_FIELD_TYPE;
        }

        if(_check)
        {
            return _check(ptr());
        }
        return 0;
    }

public:
    //仅指向地址，生命周期依赖指向缓冲区
    const double *ref(const double *val)
    {
        return setVal<double>(val);
    }

    //申请空间 拷贝内容
    double dup(double val)
    {
        if (_allocFlag)
        {
            delete ptr();
            _allocFlag = false;
        }

        double *buf = new double();
        *buf = val;
        _allocFlag = true;
        return *ref(buf);
    }
};

class jBool : public jHeader
{
private:
    jCheckBool _check;
    bool _allocFlag;

public:
    jBool(const char *key, bool isRequired, jCheckBool check) : jHeader(key, isRequired), _check(check), _allocFlag(false)
    {
    }
    ~jBool()
    {
        if(_allocFlag)
        {
            delete ptr();
        }
    }

    int32_t getType() { return V_JSON_BOOL; }
    const bool *ptr() { return getVal<bool>(); }
    bool val() { return *ptr(); }

protected:
    void toString(size_t tabNum, std::ostringstream &jStream)
    {
        for (size_t i = 0; i < tabNum; i++)
        {
            jStream << "    ";
        }

        if (getKey())
        {
            jStream << "\"" << getKey() << "\": ";
        }
        jStream << (*ptr() ? "true" : "false");
    }

    int32_t parseValue(yyjson_val *pVal)
    {
        if (!yyjson_is_bool(pVal))
        {
            return JSON_ERR_FIELD_TYPE;
        }

        // this->dup(yyjson_get_bool(pVal));
        this->dup(unsafe_yyjson_get_bool(pVal));
        if (_check)
        {
            return _check(ptr());
        }
        return 0;
    }

public:
    //仅指向地址，生命周期依赖指向缓冲区
    const bool *ref(const bool *val)
    {
        return setVal<bool>(val);
    }

    //申请空间 拷贝内容
    bool dup(bool val)
    {
        if (_allocFlag)
        {
            delete ptr();
            _allocFlag = false;
        }

        bool *buf = new bool;
        *buf = val;
        _allocFlag = true;
        return ref(buf);
    }
};

class jArray : public jHeader
{
private:
    jCheckVoid _check;
    bool _allocFlag;
    void deletVal()
    {
        if (_allocFlag)
        {
            auto pvt = getArrayPtr();
            for (size_t i = 0; i < pvt->size(); i++)
            {
                delete pvt->at(i);
            }
            delete pvt;
            _allocFlag = false;
        }
    }

public:
    jArray(const char *key, bool isRequired, jCheckVoid check) : jHeader(key, isRequired), _check(check), _allocFlag(false)
    {
    }

    ~jArray()
    {
        deletVal();
    }

    int32_t getType() { return V_JSON_ARRAY; }
    const std::vector<jHeader *> *getArrayPtr() { return getVal<std::vector<jHeader *>>(); }

protected:
    void toString(size_t tabNum, std::ostringstream &jStream)
    {
        for (size_t i = 0; i < tabNum; i++)
        {
            jStream << "    ";
        }

        jStream << "\"" << getKey() << "\": "
                << "[";
        for (size_t i = 0; i < getArrayPtr()->size(); i++)
        {
            if(i != 0)
            {
                jStream << ", ";
            }
            getArrayPtr()->at(i)->toString(0, jStream);
        }
        jStream << "]";
    }

    int32_t parseValue(yyjson_val *pVal)
    {
        if (!yyjson_is_arr(pVal))
        {
            return JSON_ERR_FIELD_TYPE;
        }

        deletVal();

        auto vtArr = new std::vector<jHeader *>;
        size_t arrSize = unsafe_yyjson_get_len(pVal);
        if (!arrSize)
        {
        }
        else
        {
            for (size_t i = 0; i < arrSize; i++)
            {
                yyjson_val *pElent = yyjson_arr_get(pVal, i);
                switch (yyjson_get_type(pElent))
                {
                case V_JSON_BOOL:
                {
                    vtArr->push_back(new jBool(NULL, NULL, NULL));
                }
                break;
                case V_JSON_STR:
                {
                    vtArr->push_back(new jString(NULL, NULL, NULL));
                }
                break;
                case V_JSON_NUM:
                {
                    vtArr->push_back(new jDouble(NULL, NULL, NULL));
                }
                break;

                default:
                    std::cout << "json type " << yyjson_get_type(pElent) << std::endl;
                    goto _err;
                }
                if (vtArr->at(i)->parseValue(pElent))
                {
                    goto _err;
                }
            }
        }

        if (_check)
        {
            return _check(getArrayPtr());
        }

        _allocFlag = true;
        setVal<std::vector<jHeader *>>(vtArr);
        return 0;

    _err:
        for (size_t i = 0; i < vtArr->size(); i++)
        {
            delete vtArr->at(i);
        }
        delete vtArr;
        return JSON_ERR_FIELD_TYPE;
    }

public:
    const std::vector<jString *> *getStrArray()
    {
        auto pArr = getArrayPtr();
        if (pArr->size() && pArr->at(0)->getType() != V_JSON_STR)
        {
            return NULL;
        }
        return (const std::vector<jString *> *)pArr;
    }

    const std::vector<jBool *> *getBoolArray()
    {
        auto pArr = getArrayPtr();
        if (pArr->size() && pArr->at(0)->getType() != V_JSON_BOOL)
        {
            return NULL;
        }
        return (const std::vector<jBool *> *)pArr;
    }

    const std::vector<jDouble *> *getNumArray()
    {
        auto pArr = getArrayPtr();
        if (pArr->size() && pArr->at(0)->getType() != V_JSON_NUM)
        {
            return NULL;
        }
        return (const std::vector<jDouble *> *)pArr;
    }

    //仅指向地址，生命周期依赖指向缓冲区
    const std::vector<jHeader *> *ref(std::vector<jHeader *> *val)
    {
        return setVal<std::vector<jHeader *>>(val);
    }

    //申请空间 拷贝内容
    const std::vector<jHeader *> *dup(std::vector<const char *> &vtVal)
    {
        deletVal();
        auto aVal = new std::vector<jHeader *>;
        for (size_t i = 0; i < vtVal.size(); i++)
        {
            auto ptr = new jString(NULL, NULL, NULL);
            ptr->dup(vtVal[i]);
            aVal->push_back(ptr);
        }

        _allocFlag = true;
        return ref(aVal);
    }

    const std::vector<jHeader *> *ref(std::vector<const char *> &vtVal)
    {
        deletVal();
        auto aVal = new std::vector<jHeader *>;
        for (size_t i = 0; i < vtVal.size(); i++)
        {
            auto ptr = new jString(NULL, NULL, NULL);
            ptr->ref(vtVal[i]);
            aVal->push_back(ptr);
        }

        _allocFlag = true;
        return ref(aVal);
    }

    const std::vector<jHeader *> *dup(std::vector<double> &vtVal)
    {
        deletVal();

        auto aVal = new std::vector<jHeader *>;
        for (size_t i = 0; i < vtVal.size(); i++)
        {
            auto ptr = new jDouble(NULL, NULL, NULL);
            ptr->dup(vtVal[i]);
            aVal->push_back(ptr);
        }
        _allocFlag = true;

        return ref(aVal);
    }

    const std::vector<jHeader *> *ref(std::vector<double *> &vtVal)
    {
        deletVal();

        auto aVal = new std::vector<jHeader *>;
        for (size_t i = 0; i < vtVal.size(); i++)
        {
            auto ptr = new jDouble(NULL, NULL, NULL);
            ptr->ref(vtVal[i]);
            aVal->push_back(ptr);
        }

        _allocFlag = true;
        return ref(aVal);
    }
};

#define JSON_FIELD(name, type, isRequired, checkCb) \
    type *name = new type{#name, isRequired, checkCb};

#define JSON_STR_EX(name, isRequired, checkCb) \
    jString* name = new jString{#name, isRequired, checkCb}; //

#define JSON_NUM_EX(name, isRequired, checkCb) \
    jDouble* name = new jDouble{#name, isRequired, checkCb}; //

#define JSON_BOOL_EX(name) \
    jBool* name = new jBool{#name, isRequired, checkCb}; //

#define JSON_STR(name) \
    jString* name = new jString{#name, NULL, NULL}; //

#define JSON_NUM(name) \
    jDouble* name = new jDouble{#name, NULL, NULL}; //

#define JSON_BOOL(name) \
    jBool* name = new jBool{#name, NULL, NULL}; //

#define JSON_ARRAY(name) \
    jArray* name = new jArray{#name, NULL, NULL}; //

#define JSON_OBJ(type, name) \
    type *name = new type{#name, true, NULL}; //

class jObject : public jHeader
{
private:
    jCheckVoid _check;
    bool _allocFlag;
public:
    jObject(const char *key, bool isRequired) : jHeader(key, isRequired) {}
    jObject() : jHeader(NULL, NULL) {}

    std::string getString()
    {
        std::ostringstream jStream;
        toString(0, jStream);
        return jStream.str();
    }

    int32_t getType() { return V_JSON_OBJ; }

    int32_t parseValue(yyjson_val *pVal)
    {
        size_t subNum = getSubNum();
        auto pSub = getJHeader();
        int32_t iRet = 0;
        for (size_t i = 0; i < subNum; i++)
        {
            auto pObj = yyjson_obj_get(pVal, pSub[i]->getKey());
            if (pObj == NULL)
            {
                if (pSub[i]->isRequired())
                {
                    return JSON_ERR_REQUIRED_PARAM;
                }
                else
                {
                    continue;
                }
            }

            iRet = pSub[i]->parseValue(pObj);
            if (iRet)
            {
                return iRet;
            }
        }
        return iRet;
    }

    int32_t setString(const char *jStr)
    {
        if (_jVal)
        {
            yyjson_doc_free(_jVal);
        }

        _jVal = yyjson_read(jStr, strlen(jStr), 0);
        if (_jVal == NULL)
        {
            return JSON_ERR_ENCODE;
        }

        return parseValue(_jVal->root);
    }

protected:
    size_t getSubNum() { return (size() - sizeof(jString)) / sizeof(jHeader *); }
    jHeader **getJHeader() { return (jHeader **)((char *)this + sizeof(jString)); }

private:
    virtual size_t size() { return sizeof(jObject); }

    void toString(size_t tabNum, std::ostringstream &jStream)
    {
        if (getKey())
        {
            for (size_t i = 0; i < tabNum; i++)
            {
                jStream << "    ";
            }
            jStream << "\"" << getKey() << "\" :{\n";
        }
        else
        {
            jStream << "{\n";
        }
        tabNum++;
        size_t subNum = getSubNum();
        auto pSub = getJHeader();
        for (size_t i = 0; i < subNum; i++)
        {
            if (pSub[i]->getType() == V_JSON_OBJ || pSub[i]->getVal<void>())
            {
                if (i != 0 && (pSub[i - 1]->getType() == V_JSON_OBJ || pSub[i - 1]->getVal<void>()))
                {
                    jStream << ",\n";
                }
                pSub[i]->toString(tabNum, jStream);
            }
        }

        enterWithTab(--tabNum, jStream);
        jStream << "}";
    }

    void enterWithTab(size_t tabNum, std::ostringstream &sStream)
    {
        sStream << "\n";
        for (size_t i = 0; i < tabNum; i++)
        {
            sStream << "    ";
        }
    }
};

// using jObject::jObject;//报错
#define JSON_SEQ_REF(type)                                                                     \
    class type : public jObject                                                                \
    {                                                                                          \
    private:                                                                                   \
        size_t size()                                                                          \
        {                                                                                      \
            return sizeof(type);                                                               \
        }                                                                                      \
                                                                                               \
    public:                                                                                    \
        type(const char *key, bool isRequired, jCheckVoid check) : jObject(key, isRequired){}; \
        type() : jObject(NULL, false){};

#define JSON_SEQ_END_REF(type)              \
    ~type()                                 \
    {                                       \
        size_t subNum = getSubNum();        \
        auto pSub = getJHeader();           \
        for (size_t i = 0; i < subNum; i++) \
        {                                   \
            delete pSub[i];                 \
        }                                   \
    }                                       \
    }                                       \
    ;


class jsonPkt
{
private:
    yyjson_mut_val *_root;
    yyjson_mut_doc * _doc;
    bool _rootFlag;

public:
    jsonPkt(jsonPkt *root, const char *key)
    {
        _rootFlag = false;
        _root = yyjson_mut_obj(root->_doc);
        yyjson_mut_set_obj(_root);
        _doc = root->_doc;
        yyjson_mut_val *_key = yyjson_mut_strcpy(root->_doc, key);
        yyjson_mut_obj_add(root->_root, _key, _root);
    }

    jsonPkt()
    {
        _root = new yyjson_mut_val();
        yyjson_mut_set_obj(_root);
        _doc = yyjson_mut_doc_new(NULL);
        _rootFlag = true;
    }

    ~jsonPkt()
    {
        if (_rootFlag)
        {
            delete _root;
            yyjson_mut_doc_free(_doc);
        }
    }


    std::shared_ptr<jsonPkt> createSub(const char *key)
    {
        std::shared_ptr<jsonPkt> sub = make_shared<jsonPkt>(this, key);
        return sub;
    }

    void print() {}
    std::string toJsonStr()
    {
        char *pJson = yyjson_mut_val_write(_root, 0, NULL);
        if (pJson == NULL)
        {
            return string("");
        }

        std::string str(pJson);
        free(pJson);
        return str;
    }

    bool addRespField(const char *key, int8_t *val)
    {
        yyjson_mut_val *_key = yyjson_mut_strcpy(_doc, key);
        yyjson_mut_val *_val = yyjson_mut_strcpy(_doc, (char *)val);
        if(_key == NULL || _val == NULL)
        {
            return false;
        }
        return yyjson_mut_obj_add(_root, _key, _val);
    }

    bool addbase64Str(const char *key, unsigned char *str, unsigned int len)
    {
        char *b64Buf = new char[((len / 3) + 1) * 4];
        base64::base64Encode(str, len, b64Buf);
        bool ret = addRespField(key, b64Buf);
        delete b64Buf;
        return ret;
    }

    bool addRespField(const char *key, const char *val)
    {
        yyjson_mut_val *_key = yyjson_mut_strcpy(_doc, key);
        yyjson_mut_val *_val = yyjson_mut_strcpy(_doc, val);
        if(_key == NULL || _val == NULL)
        {
            return false;
        }
        return yyjson_mut_obj_add(_root, _key, _val);
    }

    bool addRespField(const char *key, string &val)
    {
        yyjson_mut_val *_key = yyjson_mut_strcpy(_doc, key);
        yyjson_mut_val *_val = yyjson_mut_strcpy(_doc, val.c_str());
        if(_key == NULL || _val == NULL)
        {
            return false;
        }
        return yyjson_mut_obj_add(_root, _key, _val);
    }

    bool addRespField(const char *key, uint64_t val)
    {
        yyjson_mut_val *_key = yyjson_mut_strcpy(_doc, key);
        yyjson_mut_val *_val = yyjson_mut_uint(_doc, val);
        if(_key == NULL || _val == NULL)
        {
            return false;
        }
        return yyjson_mut_obj_add(_root, _key, _val);
    }

    bool addRespField(const char *key, double val)
    {
        yyjson_mut_val *_key = yyjson_mut_strcpy(_doc, key);
        yyjson_mut_val *_val = yyjson_mut_real(_doc, val);
        if(_key == NULL || _val == NULL)
        {
            return false;
        }
        return yyjson_mut_obj_add(_root, _key, _val);
    }

    bool addRespField(const char *key, int32_t val)
    {
        yyjson_mut_val *pkey = yyjson_mut_strcpy(_doc, key);
        yyjson_mut_val *pval = yyjson_mut_int(_doc, val);
        if(pkey == NULL || pval == NULL)
        {
            return false;
        }
        return yyjson_mut_obj_add(_root, pkey, pval);
    }

    bool addRespField(const char *key, bool val)
    {
        yyjson_mut_val *pkey = yyjson_mut_strcpy(_doc, key);
        yyjson_mut_val *pval = yyjson_mut_bool(_doc, val);
        if(pkey == NULL || pval == NULL)
        {
            return false;
        }
        return yyjson_mut_obj_add(_root, pkey, pval);
    }

    bool addRespField(const char *key, vector<const char *> strArray)
    {
        yyjson_mut_val *_key = yyjson_mut_strcpy(_doc, key);
        yyjson_mut_val *arr = yyjson_mut_arr(_doc);
        if(_key == NULL || arr == NULL)
        {
            return false;
        }
        for (size_t i = 0; i < strArray.size(); i++)
        {
            yyjson_mut_arr_add_strcpy(_doc, arr, strArray[i]);
        }
        return yyjson_mut_obj_add(_root, _key, arr);
    }

    bool addRespField(const char *key, vector<int> strArray)
    {
        yyjson_mut_val *_key = yyjson_mut_strcpy(_doc, key);
        yyjson_mut_val *arr = yyjson_mut_arr(_doc);
        if(_key == NULL || arr == NULL)
        {
            return false;
        }
        for (size_t i = 0; i < strArray.size(); i++)
        {
            yyjson_mut_arr_add_int(_doc, arr, strArray[i]);
        }
        return yyjson_mut_obj_add(_root, _key, arr);
    }
};

JSON_SEQ_REF(jNullPkt);
JSON_SEQ_END_REF(jNullPkt);

template <typename T, typename V>
class jCtx
{
private:
    T _in;
    V _out;

public:
    int32_t covert(const char *sIn, char *sOut, int32_t (*cb)(T *jIn, V *jOut))
    {
        int32_t ret = _in.setString(sIn);
        if (ret)
        {
            return ret;
        }

        ret = cb(&_in, &_out);
        if (ret)
        {
            return ret;
        }
        strcpy(sOut, _out.getString().c_str());
        return 0;
    }
};

#define STR_TO_CLASS_CB(inType, outType, sub)      \
    int32_t j2c_##sub(const char *sIn, char *sOut) \
    {                                              \
        jCtx<inType, outType> tCtx;                \
        return tCtx.covert(sIn, sOut, sub);        \
    }

#endif