#include <iostream>
#include "gtest.h"
#include "clv/clv_static.h"
#include <string.h>
#include "utilFunc.h"

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
    test.run();
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

int32_t write_gbuf(void *buf, size_t len)
{
    // utilTool::printHex((uint8_t *)buf, len, "data");

    memcpy(gBuf + gLen, buf, len);
    gLen += len;
    return 0;
}

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
    int ret = req.send((uint8_t *)&cmd, write_gbuf);
    if (ret)
    {
        printf("send fail ret = %d\n", ret);
    }
    else
    {
        utilTool::printHex(gBuf, gLen, "send");
    }
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
        ret = req.send(req.clvPktGetExt(gBuf), write_gbuf);
        if(ret)
        {
            printf("send ret = %d\n", ret);
        }
    }
    
}

uint8_t tBuf[16][256];
uint16_t tLen[16];

int32_t writeBuf(void *buf, size_t len, void *pid)
{
    size_t id = *(size_t *)pid;
    memcpy(tBuf[id] + tLen[id], buf, len);
    tLen[id] += len;
    return 0;
}

class clv_run : public Gtest::GtestLoop
{
public:
    void run(size_t id)
    {
        reqKey req;
        int ret = req.mapping(gBuf, gLen, true);
        if (ret)
        {
            printf("mappin ret = %d\n", ret);
        }
        int ext = 0x9999;
        tLen[id] = 0;
        ret = req.send_ex((uint8_t *)&ext, writeBuf, &id);
        if (ret)
        {
            printf("send ret = %d\n", ret);
        }
    }
};

void test_clv_speed()
{
    test_clv_send();
    clv_run clv;
    clv.setThreadNum(6);
    clv.setDataLength(96);
    Gtest::gtestLoopInMs(5000, &clv);
}

class clv_copy : public Gtest::GtestLoop
{
public:
    void run(size_t id)
    {
        REQKEY key;
        char *buf = new char[256];
        memcpy(buf, &key, sizeof(REQKEY));
        memcpy(&key, buf, sizeof(REQKEY));
        delete buf;
    }
};

void test_memcpy()
{
    clv_copy test;
    test.setThreadNum(6);
    test.setDataLength(sizeof(REQKEY));
    Gtest::gtestLoopInMs(5000, &test);
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

#include "../encode/json/json2class.h"

JSON_SEQ_ref(jtKey);
JSON_FIELD(bits, jDouble, 1, NULL);
JSON_FIELD(x, jString, 1, NULL);
JSON_FIELD(y, jString, 1, NULL);
JSON_SEQ_END_ref(jtKey);

JSON_SEQ_ref(jSm4);
JSON_FIELD(id, jDouble, 1, NULL);
JSON_FIELD(key, jString, 1, NULL);
JSON_SEQ_END_ref(jSm4);

JSON_SEQ_ref(jReqKey);
JSON_FIELD(alg, jDouble, 1, NULL);
JSON_FIELD(key, jtKey, 1, NULL);
JSON_FIELD(sm4, jSm4, 1, NULL);
JSON_SEQ_END_ref(jReqKey);

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

class jstructSp : public Gtest::GtestLoop
{
private:
    void run(size_t id)
    {
        jReqKey req;
        int ret = req.setString(jreqkey);
        if (ret)
        {
            printf("set string ret = %d\n", ret);
        }
        else
        {
            string json = req.getString();
            // cout << json << endl;
        }
    }

public:
};


void test_jstruct_speed()
{
    jstructSp clv;
    clv.setThreadNum(6);
    clv.setDataLength(sizeof(REQKEY));
    Gtest::gtestLoopInMs(5000, &clv);
}