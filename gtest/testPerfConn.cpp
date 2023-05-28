#include "redis/hiredis.h"
#include "gtest.h"
#include "utilFunc.h"
#include <string.h>

using namespace std;

void test_redis_conn();
void test_json_proto();
void test_size_class();
void test_size_of();
void test_virtual1();
void test_jstruct_speed();
void test_return_str();

int main(int argc, char const *argv[])
{
    Gtest tests;

    tests.pushTest(test_redis_conn, "test redis conn");
    tests.pushTest(test_json_proto, "test json proto");
    tests.pushTest(test_size_class, "test size class");
    tests.pushTest(test_size_of, "test size of");
    tests.pushTest(test_virtual1, "test vir 2");
    tests.pushTest(test_jstruct_speed, "test json speed");
    tests.pushTest(test_return_str, "test return str");

    return 0;
}

class TestRedisConn : public GtestLoop
{
    int run(size_t id)
    {
        redisContext *pContext = NULL;
        timeval tv;
        tv.tv_usec = 0;
        tv.tv_sec = 1;
        pContext = redisConnectWithTimeout("127.0.0.1", 6379, tv);
        if (pContext == NULL)
        {
            cout << "redis conn fail." << endl;
            return -1;
        }
        else
        {
            redisFree(pContext);
            return 0;
        }
    }
};

void test_redis_conn()
{
    int tm = 3;
    TestRedisConn test;
    test.loopFor(tm);
}


// #include "jstruct.h"
#include "json/j2c.h"

// {
//     "key0" : {
//         "key1" : "val1",
//         "key2" : 2
//     },
//     "key1" : {
//         "key1" : "val1",
//         "key2" : 2
//     },
//     "key3" : "var3"
// }

int32_t check_num(const double *val)
{
    if (*val > 32)
    {
        return 1;
    }
    return 0;
}

int32_t check_str(const char *val)
{
    if (strlen(val) == 0)
    {
        return 2;
    }
    return 0;
}

JSON_SEQ_REF(CA_CRT);
JSON_FIELD(caNum, jDouble, 1, NULL) // check_num)
JSON_FIELD(ca1, jString, 1, NULL)   // check_str)
JSON_FIELD(ca2, jString, 1, NULL)   // check_str)
JSON_FIELD(ca3, jString, 1, NULL)   // check_str)
JSON_SEQ_END_REF(CA_CRT);

JSON_SEQ_REF(SSL_CONF);
JSON_FIELD(verify, jBool, 1, NULL)
JSON_FIELD(listNum, jArray, 1, NULL)
JSON_FIELD(listStr, jArray, 1, NULL)
JSON_FIELD(CAs, CA_CRT, 1, NULL)
JSON_FIELD(sign, jString, 1, NULL)
JSON_FIELD(enc, jString, 1, NULL)
JSON_SEQ_END_REF(SSL_CONF);

const char *jSsl = "{"
                   "\"verify\":true,"
                   "\"listNum\":[1,2,3],"
                   "\"listStr\":[\"ab\",\"cd\",\"ef\"],"
                   "\"CAs\" :{"
                   "    \"caNum\": 31,"
                   "    \"ca1\": \"trustCa1\","
                   "    \"ca2\": \"trustCa2\","
                   "    \"ca3\": \"trustCa3\""
                   "    },"
                   "\"sign\": \"signCer\","
                   "\"enc\": \"encCer\""
                   "}";
#define ASSERT(oper)                                           \
    if (!oper)                                                 \
    {                                                          \
        printf("operation fail. %d %s\n", __LINE__, __func__); \
    }

int32_t ssl_conf(SSL_CONF *in, jNullPkt *out)
{
    printf("verify %d\n", in->verify->val());
    auto pNum = in->listNum->getNumArray();
    for (size_t i = 0; i < pNum->size(); i++)
    {
        printf("list num %ld %ld [%lf]\n", pNum->size(), i, pNum->at(i)->getNumVal());
    }

    auto pStr = in->listStr->getStrArray();
    for (size_t i = 0; i < pStr->size(); i++)
    {
        printf("list str %ld [%s]\n", i, pStr->at(i)->str());
    }

    printf("ca num %lf\n", in->CAs->caNum->getNumVal());
    printf("ca1 %s\n", in->CAs->ca1->str());
    printf("ca2 %s\n", in->CAs->ca2->str());
    printf("ca3 %s\n", in->CAs->ca3->str());
    printf("sign %s\n", in->sign->str());
    printf("enc %s\n", in->enc->str());

    return 0;
}

STR_TO_CLASS_CB(SSL_CONF, jNullPkt, ssl_conf);

void test_json_proto()
{
    cout << "======test parse====\n";
    SSL_CONF jreq;
    cout << jreq.getString();
    int32_t iRet = jreq.setString(jSsl);
    if(iRet)
    {
        printf("set str iret = %d\n", iRet);
    }
    cout << jreq.getString();
    cout << "======test moditify====\n";
    jreq.enc->str();
    jreq.enc->ref("test");
    jreq.verify->val();
    jreq.verify->dup(false);
    jreq.CAs->caNum->ptr();
    jreq.CAs->caNum->dup(1);
    jreq.listNum->getNumArray()->at(0)->dup(4);
    jreq.listStr->getStrArray()->at(0)->ref("xy");

    cout << jreq.getString();

    cout << "======test jsonPkt====\n";
    jsonPkt pkt;
    ASSERT(pkt.addRespField("verify", true))
    ASSERT(pkt.addRespField("listNum", vector<int>{1, 2, 3}))
    ASSERT(pkt.addRespField("listStr", vector<const char *>{"ab", "cd", "ef"}))
    auto sub = pkt.createSub("CAs");
    ASSERT(sub->addRespField("caNum", 33))
    ASSERT(sub->addRespField("ca1", "trustCa1"))
    ASSERT(sub->addRespField("ca2", "trustCa2"))
    ASSERT(sub->addRespField("ca3", "trustCa3"))
    ASSERT(pkt.addRespField("sign","signCer"))
    ASSERT(pkt.addRespField("enc","encCer"))
    cout << "add field end\n";
    cout << pkt.toJsonStr() << endl;

    cout << "======test func====\n";
    char out[1024];
    int32_t ret = j2c_ssl_conf(jSsl, out);
    if (ret)
    {
        printf("j2c ssl conf ret = %d\n", ret);
    }
    else
    {
        printf("out [%s].\n", out);
    }
}

void test_size_class()
{
    class father
    {
    public:
        char str1[32];
        virtual int size() { return sizeof(father); }
        void printSize()
        {
            printf("size %d %d\n", size(), __LINE__);
        }
    };

    class son : public father
    {
    public:
        char str2[32];
        int size() { return sizeof(son); }
    };

    son obj;
    printf("son size = %d\n", obj.size());
    printf("father size = %d\n", obj.father::size());
    printf("sizeof son %ld father %ld\n", sizeof(son), sizeof(father));
    obj.printSize();
    obj.father::printSize();
}

void test_size_of()
{
    const char *str[] = {"123", "456", "7890"};
    const char * p = NULL;
    vector<const char * > vt;

    for (size_t i = 0; i < sizeof(str) / sizeof(const char *); i++)
    {
        p = str[i];
        vt.push_back(p);
    }
    p = NULL;
    for (size_t i = 0; i < vt.size(); i++)
    {
        cout << vt[i] << endl;
    }

    cout << sizeof(str) << "\n";
}

void test_virtual()
{
    class virMeth
    {
    public:
        virtual void print(){};
        virtual ~virMeth(){};
    };

    class methStr:public virMeth
    {
        const char *str = "123";

    public:
        void print() { cout << str << endl; }
        void set(char *val) { str = val; }
    };

    class methNum:public virMeth
    {
        int *num = new int(456);

    public:
        void print() { cout << *num << endl; }
        void set(int *val) { num = val; }
        ~methNum()
        {
            // delete num;
        }
    };

    class virBase
    {

    public:
        virMeth *_meth;
        virBase(virMeth *meth) : _meth(meth) {}
        virtual ~virBase() { delete _meth; }
    };
    virBase obj1(new methNum);
    obj1._meth->print();
    virBase obj2(new methStr);
}

void test_virtual1()
{
    class vir1
    {
    public:
        virtual void print() { printf("vir1\n"); }
        virtual ~vir1() {}
    };
    class vir2 : public vir1
    {
    public:
        void print() { printf("vir2\n"); }
        ~vir2() {}
    };

    vector<vir1*> vt;
    vt.push_back(new vir2());
    vt[0]->print();

    vir1 *p = new vir2();
    p->print();
    delete p;
}
#include "json/yyjson.h"

class testjson : public GtestLoop
{
public:
    int  run(size_t id)
    {
        //410k
        SSL_CONF jReq;
        if(jReq.setString(jSsl))
        {
            printf("parse json fail.\n");
            return -1;
        }
        string str = jReq.getString();

        //tc_json
        //240k
        // JsonValueObjPtr pJson = JsonValueObjPtr::dynamicCast(TC_Json::getValue(jSsl));
        // string jsonStr = TC_Json::writeValue(pJson);

        //cjson
        // SPEED 72066  Tps
        // cJSON *pJson = cJSON_Parse(jSsl);
        // char *pStr = cJSON_Print(pJson);
        // cJSON_free(pJson);
        // free(pStr);

        // yyjson
        // SPEED 1495588  Tps
        // yyjson_doc *pDoc = yyjson_read(jSsl, strlen(jSsl), 0);
        // char *p = yyjson_write(pDoc, 0, NULL);
        // yyjson_doc_free(pDoc);
        // free(p);

        // jsonPkt
        // jsonPkt pkt;
        // ASSERT(pkt.addRespField("verify", true))
        // ASSERT(pkt.addRespField("listNum", vector<int>{1, 2, 3}))
        // ASSERT(pkt.addRespField("listStr", vector<const char *>{"ab", "cd", "ef"}))
        // auto sub = pkt.createSub("CAs");
        // ASSERT(sub->addRespField("caNum", 33))
        // ASSERT(sub->addRespField("ca1", "trustCa1"))
        // ASSERT(sub->addRespField("ca2", "trustCa2"))
        // ASSERT(sub->addRespField("ca3", "trustCa3"))
        // ASSERT(pkt.addRespField("sign", "signCer"))
        // ASSERT(pkt.addRespField("enc", "encCer"))
        // pkt.toJsonStr();

        return 0;
    }
};

void test_jstruct_speed()
{
    int tm = 5;
    testjson test;
    test.setThreadNum(6);
    test.setDataLength(sizeof(jSsl));
    test.loopFor(tm);
}

class tString
{
public:
    string _str;
    tString(const char *str) : _str(str)
    {
        cout << "constructor tString\n";
    }

    ~tString()
    {
        cout << "destructor tString\n";
    }
    const char *cStr()
    {
        return _str.c_str();
    }
    void print()
    {
        cout << _str << endl;
    }
};

tString alg_str()
{
    tString str("sm4");
    return str;
}

void test_return_str()
{
    printf("1 [%s]\n", alg_str().cStr());
    const char *p = alg_str().cStr(); //错误用法
    printf("2 [%s]\n", p);
    tString str = alg_str();
    printf("3 [%s]\n", str.cStr());
    printf("4 [%s]\n", str.cStr());
}