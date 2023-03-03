#ifndef _GMCM_UIKEY_H_
#define _GMCM_UIKEY_H_

#include "utilFunc.h"
#include "concurrentqueue.h"
#include <mutex>
#include "gmcmalgConf.h"
#include <atomic>
#include "eventWait.h"

using namespace std;
using namespace moodycamel;

#define MAX_UIKEY_NUM 1024*16

typedef struct uiKey_st
{
    unsigned char key[32];
    unsigned int index;
    unsigned int length;
    atomic<time_t> updateTime;
} uikey;

class EXPORT_FUNC uiKeyArray
{
private:
    uikey * keyArrayUsing[MAX_UIKEY_NUM];
    rwlock _lock;

    ConcurrentQueue<uikey*> keyQueueIdle;

    std::thread *ukeyTimeoutThread = NULL;
    eventWait ukeyTimeouThreadExit;
    int deal_with_uikey_timeout_route(int uikey_timeout);
    void exit_ukey_timeout_thread();

public:

    //0 为关闭
    //超时时间 单位 ms
    uiKeyArray(int uikey_timeout = 0);
    int import_key(unsigned char *key, unsigned int length, void **handle);
    int getKey(void *handle, unsigned char *key, unsigned int *length);
    int delKey(void *handle);
    ~uiKeyArray();
};


#endif