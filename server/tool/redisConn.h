#ifndef _REDIS_CONN_H_
#define _REDIS_CONN_H_

// #include "concurrentqueue.h"
#include "redis/hiredis.h"
#include "util/tc_cas_queue.h"

using namespace std;
// using namespace moodycamel;
using namespace tars;

class redisConn
{
private:
    /* data */
    // ConcurrentQueue<redisContext *> connQueue;
    TC_CasQueue<redisContext *> connQueue;
    redisConn(/* args */){};
    redisContext * newConn();
    redisContext * getConn();
    void realseConn(redisContext *conn);
    redisReply *execCmd(redisContext *c, int argc, const char **argv, const size_t *argvlen);

public:
    static redisConn * pRedisConnPool;
    static redisConn *getRedisConnPool();//init

    //base
    static int setData(const char *key, unsigned char *data, unsigned int dataLen, unsigned int expireTime = 0);
    static int getData(const char *key, unsigned char *data, unsigned int &dataLen);
    static int delData(const char *key);

    //hash
    static int hashSetData(const char *hashName, const char *key, unsigned char *data, unsigned int dataLen);
    static int hashGetData(const char *hashName, const char *key, unsigned char *data, unsigned int &dataLen);
    static int hashDelData(const char *hashName, const char *key);
    static int hashKeys(const char *hashName, vector<string> *keys);
    static int hashGetAll(const char *hashName, vector<string> *keys, vector<string> *vals);
};


#endif