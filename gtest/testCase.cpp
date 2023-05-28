#include "gtest.h"
#include <string.h>
#include "utilFunc.h"
#include <typeinfo>
#include <unordered_map>
#include "util/tc_clientsocket.h"
using namespace tars;

void test_snprintf();
void test_array_memset();
void test_strategy();
void test_map();
void test_map_key();
void test_epoll_client();
void test_malloc();

int main(int argc, char const *argv[])
{
    Gtest ts;
    ts.pushTest(test_snprintf, "test snprintf");
    ts.pushTest(test_array_memset, "test memset array");
    ts.pushTest(test_strategy, "test strategy");
    ts.pushTest(test_map, "test map");
    ts.pushTest(test_map_key, "test map key");
    ts.pushTest(test_epoll_client, "test epoll client");
    ts.pushTest(test_malloc, "test malloc");
    return 0;
}

void test_snprintf()
{
    typedef struct sp_buf_st
    {
        char data[8];
        char ext[8];
    } sp_buf;

    sp_buf tBuf;

    int len = snprintf(tBuf.data, sizeof(tBuf.data), "123456789");
    printf("len [%d] strlen [%ld] buf [%s]\n", len, strlen(tBuf.data), tBuf.data);
    printf("ext strlen [%ld] buf [%s]\n", strlen(tBuf.ext), tBuf.ext);
    utilTool::printHex((unsigned char *)tBuf.data, 8, "data");
    tBuf = {};
    utilTool::printHex((unsigned char *)tBuf.data, 8, "data");
    printf("len [%d] strlen [%ld] buf [%s]\n", len, strlen(tBuf.data), tBuf.data);
    printf("ext strlen [%ld] buf [%s]\n", strlen(tBuf.ext), tBuf.ext);
}

void test_array_memset()
{
    char str[8] = {0};
    // str[0] = 0;
    utilTool::printHex((unsigned char *)str, 8, "str");
    snprintf(str, sizeof(str), "1234");
    utilTool::printHex((unsigned char *)str, 8, "str");
}

#include <iostream>
#include <memory>
using namespace std;

class AutoData
{
protected:
    char *_ptr;
    bool _alloc;
    void freePtr()
    {
        if (_alloc)
        {
            cout << "delete []" << endl;
            delete[] _ptr;
            _alloc = false;
        }
    }

public:
    AutoData() : _ptr(NULL), _alloc(false) {}
    ~AutoData()
    {
        freePtr();
    }
};

template <typename T>
class AutoPtr : public AutoData
{
public:
    T *ref(T *element)
    {
        freePtr();
        _ptr = (char *)element;
        return (T *)_ptr;
    }

    T *dup(const T *element, size_t size = sizeof(T))
    {
        freePtr();
        _ptr = new char[size];
        _alloc = true;
        memcpy(_ptr, element, size);
        return (T *)_ptr;
    }

    T *ptr()
    {
        return (T *)_ptr;
    }
};

void test_strategy()
{
}

void test_vistor()
{
}

void test_adpter()
{
    class dataBase
    {
    private:
        void *_data;

    public:
    };

    class methBase
    {
    private:
    public:
    };

}


class testMap:public GtestLoop
{
private:
    // key 4  run test map.
    // SPEED 29184833  Tps
    // unordered_map<const char *, char *> _mp;

    // key 4  run test map.
    // SPEED 29357898  Tps
    map<const char *, char *> _mp;
    char * _pkey = NULL;

public:
    testMap()
    {
        for (size_t i = 0; i < 1000; i++)
        {
            char *key = new char[8];
            _mp.insert(make_pair(key, key));
        }
        _pkey = new char[8];
        _mp.insert(make_pair(_pkey, _pkey));
    }

    ~testMap()
    {
        for (auto iter = _mp.begin(); iter != _mp.end(); iter++)
        {
            delete[] iter->first;
        }
    }

    int run(size_t id)
    {
        _mp.at(_pkey);
        return 0;
    }
};

void test_map()
{
    testMap test;
    int tm = 5;
    test.setThreadNum(6);
    test.loopFor(tm);
}


void test_map_key()
{
    map<char *, bool> mp;

    char buf1[4] = "123";
    char *buf2 = (char *)"123";
    bool val;

    mp.insert(make_pair(buf1, true));
    try
    {
        val = false;
        val = mp.at(buf2);
    }
    catch(const std::exception& e)
    {
        printf("get key fail\n");
    }
    if(val)
    {
        printf("get key success\n");
    }

    string str1 = "123";
    string str2(buf1);

    map<string, bool> mpstr;
    mpstr.insert(make_pair(str1, true));
    try
    {
        val = mpstr.at(str2);
        val = mpstr.at("123");
    }
    catch(const std::exception& e)
    {
        printf("get key fail\n");
    }
    if (val)
    {
        printf("get key success\n");
    }
}


class epollClient:public GtestLoop
{
private:
#define CLIENT_NUM 12
    TC_TCPClient client[CLIENT_NUM];
    char buf[1024];

public:
    epollClient()
    {
        memset(buf, 31, sizeof(buf));
    }

    int init(size_t id)
    {
        client[id].init("127.0.0.1", 9900, 5000);
        int iRet;
        if( (iRet = client[id].checkSocket()))
        {
            printf("connect fail. %d\n", iRet);
            return 1;
        }
        return 0;
    }
    #define PKG_SIZE 256

    int run(size_t id)
    {
        // int iRet;
        // for (int sendLen = 1024; sendLen > 0; sendLen -= 128)
        // {
        //     if ((iRet =  client[id].send(buf, 128)))
        //     {
        //         printf("send fail %d.\n", iRet);
        //         return -1;
        //     }
        // }

        if (client[id].send(buf, PKG_SIZE))
        {
            printf("send fail.\n");
            return -1;
        }

        if (client[id].recvLength(buf, PKG_SIZE))
        {
            printf("recv fail.\n");
            return -1;
        }
        return 0;
    }
};

void test_epoll_client()
{
    TC_Common::ignorePipe();
    epollClient client;
    client.setDataLength(PKG_SIZE);
    client.setThreadNum(CLIENT_NUM);
    client.loopFor(10);
}

class alloc_buf : public GtestLoop
{
    int run(size_t i)
    {
        void *p = malloc(8192);
        free(p);
        return 0;
    }
};

void test_malloc()
{
    alloc_buf test;
    test.setThreadNum(6);
    test.loopFor();
}