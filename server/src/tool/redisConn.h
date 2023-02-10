#ifndef _REDIS_CONN_H_
#define _REDIS_CONN_H_

#include "concurrentqueue.h"
#include "redis/hiredis.h"

using namespace std;
using namespace moodycamel;

class redisConn
{
private:
    /* data */
    ConcurrentQueue<redisContext *> connQueue;
    redisConn(/* args */){};
    redisContext * newConn();
    redisContext * getConn();
    void realseConn(redisContext *conn);
    redisReply *execCmd(redisContext *c, int argc, const char **argv, const size_t *argvlen);

public:
    static redisConn * pRedisConnPool;
    static redisConn *getRedisConnPool();

    static int setData(char *key, unsigned char *data, unsigned int dataLen);
    static int getData(char *key, unsigned char *data, unsigned int &dataLen);
    static int delData(char *key);
    ~redisConn(){};
};


#endif