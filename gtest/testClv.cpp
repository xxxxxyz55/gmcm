#include <iostream>
#include "gtest.h"
#include "clv/clv_static.h"
#include <string.h>
#include "utilFunc.h"
#include <unordered_map>

using namespace std;

void test_clv_send();
void test_clv_mapping();
// SPEED 4947916  Tps
// SPEED 3623 Mbps
void test_clv_speed();
// SPEED 21221843  Tps
// SPEED 14895 Mbps
void test_memcpy();
void test_this();
void test_convert();
// SPEED 1355918  Tps
// SPEED 951 Mbps
void test_jstruct_speed();
void test_mpklv();
void test_global_var();

int main(int argc, char const *argv[])
{
    Gtest test;
    test.pushTest(test_clv_send, "test clv send");
    test.pushTest(test_clv_mapping, "test clv mapping");
    test.pushTest(test_clv_speed, "test clv speed");
    test.pushTest(test_jstruct_speed, "test jStruct speed");
    test.pushTest(test_memcpy, "test memcpy");
    test.pushTest(test_this, "test this");
    test.pushTest(test_convert, "test convert");
    test.pushTest(test_mpklv, "test mpklv");
    test.pushTest(test_global_var, "test global var");
    return 0;
}

typedef struct sm4key_st
{
    int id;
    uint8_t key[16];
}SM4_KEY;

CLV_SEQ_REF(tKey)
CLV_INT(bits, NULL)
CLV_USTR(x, NULL)
CLV_USTR(y, NULL)
CLV_SEQ_END_REF(tKey)

CLV_SEQ_REF(reqKey)
CLV_INT(alg, NULL)
CLV_OBJ(tKey, key)
CLV_ST(SM4_KEY, sm4, NULL)
CLV_SEQ_END_REF(reqKey)

typedef struct TKEY_st
{
    uint32_t  bits;
    uint8_t x[32];
    uint8_t y[32];
}TKEY;

typedef struct REQKEY_St
{
    int32_t alg;
    TKEY key;
    SM4_KEY sm4;
}REQKEY;



uint8_t gBuf[8192];
uint16_t gLen;

void test_clv_send()
{
    reqKey req;
    SM4_KEY sm4 = {777, {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}};
    *req.alg.alloc() = 0x123;
    *req.key.bits.alloc() = 0x256;
    memcpy(req.key.x.alloc(32), "12345678", 8);
    memcpy(req.key.y.alloc(32), "87654321", 8);
    req.sm4.ref(&sm4);
    memset(gBuf, 0, gLen);
    gLen = 0;
    int cmd = 0x789;
    string str = req.tostring((uint8_t *)&cmd);
    memcpy(gBuf, str.c_str(), str.length());
    gLen = str.length();
    utilTool::printHex(gBuf, gLen, "send");
}

void test_clv_mapping()
{
    reqKey req;
    int32_t ret = req.mapping(gBuf, gLen, true);
    if (ret)
    {
        printf("mapping fail ret = %d\n", ret);
    }
    else
    {
        printf("alg %p\n", req.alg.ptr());
        printf("alg %d\n", req.alg.val());
        printf("bit %d\n", req.key.bits.val());
        utilTool::printHex(req.key.x.ptr(), req.key.x.len(), "x");
        utilTool::printHex(req.key.y.ptr(), req.key.y.len(), "x");
        utilTool::printHex((uint8_t *)req.sm4.ptr(), req.sm4.len(), "sm4");
        string str = req.tostring(req.clvPktGetExt(gBuf));
        memcpy(gBuf, str.c_str(), str.length());
        gLen = str.length();
    }
}

uint8_t tBuf[16][256];
uint16_t tLen[16];

class clv_run : public GtestLoop
{
public:
    int run(size_t id)
    {
        reqKey req;
        int ret = req.mapping(gBuf, gLen, true);
        if (ret)
        {
            printf("mappin ret = %d\n", ret);
            return -1;
        }
        int ext = 0x9999;
        tLen[id] = 0;
        string str = req.tostring((uint8_t *)&ext);
        memcpy(tBuf[id], str.c_str(), str.length());
        tLen[id] = str.length();

        return 0;
    }
};

void test_clv_speed()
{
    test_clv_send();
    clv_run clv;
    clv.setThreadNum(6);
    clv.setDataLength(96);
    clv.loopFor(5);
}

class clv_copy : public GtestLoop
{
public:
    int run(size_t id)
    {
        REQKEY key;
        char *buf = new char[256];
        memcpy(buf, &key, sizeof(REQKEY));
        memcpy(&key, buf, sizeof(REQKEY));
        delete buf;
        return 0;
    }
};

void test_memcpy()
{
    clv_copy test;
    test.setThreadNum(6);
    test.setDataLength(sizeof(REQKEY));
    test.loopFor(5);
}

void test_this()
{
    class thisBase{
        virtual size_t size() = 0;
    };

    class thisS : public thisBase
    {
        int num;

    public:
        size_t size() { return sizeof(thisS); }
        class thisT : public thisBase
        {
            int num;

        public:
            size_t size() { return sizeof(thisT); }
            void printThis()
            {
                printf("thisT %p %p\n", this, (char *)this + size());
            }
        };
        thisT obj;
        int num1;
        void printThis()
        {
            printf("thisT %p %p\n", this, (char *)this + size());
        }
    };

    thisS s;
    s.printThis();
    s.obj.printThis();
}



template <typename T>
class cv_crtp
{

public:
    void static_print()
    {
        static_cast<T *>(this)->print();
    }
};

class crtp_bool : public cv_crtp<crtp_bool>
{
public:
    void print()
    {
        printf("cv bool\n");
    }
};

class cv_str : public cv_crtp<cv_str>
{
public:
    void print()
    {
        printf("cv str\n");
    }
};

class cv_base : public cv_crtp<cv_base>
{
public:
    void print()
    {
        printf("cv base\n");
    }
};

void test_convert()
{
    cv_base *p = NULL;
    p = (cv_base *)new cv_str;
    p->print();
    delete p;
}

#include "../encode/json/j2c.h"

JSON_SEQ_REF(jtKey);
JSON_FIELD(bits, jDouble, 1, NULL);
JSON_FIELD(x, jString, 1, NULL);
JSON_FIELD(y, jString, 1, NULL);
JSON_SEQ_END_REF(jtKey);

JSON_SEQ_REF(jSm4);
JSON_FIELD(id, jDouble, 1, NULL);
JSON_FIELD(key, jString, 1, NULL);
JSON_SEQ_END_REF(jSm4);

JSON_SEQ_REF(jReqKey);
JSON_FIELD(alg, jDouble, 1, NULL);
JSON_FIELD(key, jtKey, 1, NULL);
JSON_FIELD(sm4, jSm4, 1, NULL);
JSON_SEQ_END_REF(jReqKey);

const char *jreqkey = "{"
                      "\"alg\":401,"
                      "\"key\":{"
                      "    \"bits\":401,"
                      "    \"x\":\"12345678123456781234567812345678\","
                      "    \"y\":\"12345678123456781234567812345678\""
                      "    },"
                      "\"sm4\":{"
                      "    \"id\":123,"
                      "    \"key\":\"1234567812345678\""
                      "    }"
                      "}";

class jstructSp : public GtestLoop
{
private:
    int run(size_t id)
    {
        jReqKey req;
        int ret = req.setString(jreqkey);
        if (ret)
        {
            printf("set string ret = %d\n", ret);
            return -1;
        }
        else
        {
            string json = req.getString();
            // cout << json << endl;
            return 0;
        }
    }

public:
};


void test_jstruct_speed()
{
    jstructSp clv;
    clv.setThreadNum(6);
    clv.setDataLength(sizeof(REQKEY));
    clv.loopFor(5);
}
class BLV
{
private:
    void *_data;
    uint16_t _len;
    bool _alloc;

public:
    uint16_t length()
    {
        return _len;
    }

    void *data()
    {
        return _data;
    }

    template <typename T>
    T *data()
    {
        return (T *)_data;
    }

    BLV(int32_t val)
    {
        printf("blv constructor int32_t \n");
        _len = sizeof(int32_t);
        _data = new char[_len];
        _alloc = true;
        *(int32_t *)_data = val;
    }

    BLV(int32_t *val)
    {
        printf("blv constructor int32_t *\n");
        _len = sizeof(int32_t);
        _data = val;
        _alloc = false;
    }

    template <typename T>
    BLV(T &val, uint16_t size = sizeof(T))
    {
        printf("blv constructor template\n");
        _len = size;
        _data = &val;
        _alloc = false;
    }

    ~BLV()
    {
        printf("blv destructor\n");
        if (_alloc)
        {
            delete[] (char *)_data;
        }
    }
};

void test_mpklv()
{
    unordered_map<string, BLV> req;
    {
        SM4_KEY sm4 = {777, {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}};
        TKEY key = {0x256, "12345689", "87654321"};
        int alg = 0x123;
        req.insert(make_pair("alg", &alg));
        req.insert(make_pair("key", BLV(key)));
        req.insert(make_pair("sm4", BLV(sm4)));
    }

    for (auto iter = req.begin(); iter != req.end(); iter++)
    {
        utilTool::printHex(iter->second.data<uint8_t>(), iter->second.length(), iter->first.c_str());
    }

    // req.at("sm4").data<SM4_KEY>()->id;
}

#include "verifyVar.h"

int32_t check_alg(int32_t *alg)
{
    utilTool::printHex((uint8_t *)alg, 4, "alg");
    return 0;
}

int32_t check_key(TKEY *key)
{
    utilTool::printHex((uint8_t *)key, sizeof(TKEY), "check key type 0");
    return 0;
}

int32_t check_key_1(TKEY *key)
{
    utilTool::printHex((uint8_t *)key, sizeof(TKEY), "check key type 1");
    return 0;
}

int32_t check_sm4(SM4_KEY *sm4)
{
    utilTool::printHex((uint8_t *)sm4, sizeof(TKEY), "sm4");
    return 0;
}

int32_t check_datalen(uint32_t len)
{
    cout << "check data len.\n";
    return 0;
}

int32_t check_index(uint32_t len)
{
    cout << "check index.\n";
    return 0;
}

void test_global_var()
{
    REQKEY req = {
        0x123,
        {
            0x456,
            {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38},
            {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38},
        },
        {
            777,
            {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
        },
    };

    VerifyVar::verify(&req);
    class TKEY1
    {
    public:
        TKEY index;
    };

    TKEY key;
    TKEY1 key1;
    VerifyVar::verify(&key);
    VerifyVar::RegisterVar<TKEY>({{offsetof(REQKEY, key), check_key}});
    VerifyVar::RegisterVar<TKEY1>({{offsetof(REQKEY, key), check_key_1}});
    VerifyVar::verify(&key);
    VerifyVar::verify(&key1);

    uint32_t dataLen;
    uint32_t index;
    class VERIFY_DATALEN
    {
    };

    class VERIFY_INDEX
    {
    };
    VerifyVar::RegisterVar<VERIFY_DATALEN>({{0, check_datalen}});
    VerifyVar::RegisterVar<VERIFY_INDEX>({{0, check_index}});

    VerifyVar::verify((VERIFY_DATALEN *)&dataLen);
    VerifyVar::verify((VERIFY_INDEX *)&index);
}