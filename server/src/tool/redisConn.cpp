#include "redisConn.h"
#include "../gmcmErr.h"
#include "../gmcmLog.h"

redisConn *redisConn::pRedisConnPool = NULL;

redisConn *redisConn::getRedisConnPool()
{
    if (pRedisConnPool == NULL)
    {
        pRedisConnPool = new redisConn();
        redisContext *conn = pRedisConnPool->newConn();
        if(conn == NULL)
        {
            return NULL;
        }
        else
        {
            if (pRedisConnPool->connQueue.enqueue(conn) == false)
            {
                redisFree(conn);
                gmcmLog::LogError() << "redis conn pool enqueue fail." << endl;
                return NULL;
            }
        }
    }

    return pRedisConnPool;
}

redisContext *redisConn::newConn()
{
    redisContext *pContext = NULL;
    timeval tv;
    tv.tv_usec = 0;
    tv.tv_sec = 1;
    pContext = redisConnectWithTimeout("127.0.0.1", 6379, tv);
    if (pContext == NULL)
    {
        gmcmLog::LogError() << "redis connect fail." << endl;
        return NULL;
    }
    else if (pContext->err)
    {
        gmcmLog::LogError() << "redis connect fail [" << pContext->err << "] [" << pContext->errstr << "]" << endl;
        redisFree(pContext);
        return NULL;
    }

    return pContext;
}

redisContext *redisConn::getConn()
{
    redisContext *pConn = NULL;
    if (pRedisConnPool->connQueue.try_dequeue(pConn) == false)
    {
        pConn = pRedisConnPool->newConn();
    }
    return pConn;
}

void redisConn::realseConn(redisContext *conn)
{
    if(this->connQueue.enqueue(conn) == false)
    {
        redisFree(conn);
        gmcmLog::LogError() << "redis conn pool enqueu conn fail." << endl;
    }
}

redisReply *redisConn::execCmd(redisContext *pConn, int argc, const char **argv, const size_t *argvlen)
{
    redisReply *reply = (redisReply *)redisCommandArgv(pConn, argc, argv, argvlen);
    if (reply == NULL)
    {
        if (pConn->err == 1 || pConn->err == 3)
        {
            if (redisReconnect(pConn) != REDIS_OK) //释放 重新连接
            {
                gmcmLog::LogError() << "redis reconnect fail." << endl;
            }
            else
            {
                reply = (redisReply *)redisCommandArgv(pConn, argc, argv, argvlen);
            }
        }
        else
        {
            gmcmLog::LogError() << "redis exec cmd fail." << endl;
        }
    }
    else
    {
    }
    return reply;
}

int redisConn::setData(char *key, unsigned char *data, unsigned int dataLen)
{
    redisContext *pConn = pRedisConnPool->getConn();
    if(pConn == NULL)
    {
        return GMCM_FAIL;
    }

    const char *sArgv[3];
    size_t iArgvLen[3];
    int iRet = 0;
    static char sSet[] = "SET";
    sArgv[0] = sSet;
    iArgvLen[0] = 3;
    sArgv[1] = key;
    iArgvLen[1] = strlen(key);
    sArgv[2] = (char *)data;
    iArgvLen[2] = dataLen;
    redisReply *reply = pRedisConnPool->execCmd(pConn, 3, sArgv, iArgvLen);
    if (reply == NULL)
    {
        iRet = GMCM_ERR_REDIS_EXEC;
        gmcmLog::LogError() << "redis set fail, key = " << key << endl;
    }
    else
    {
        freeReplyObject(reply);
    }

    pRedisConnPool->realseConn(pConn);
    return iRet;
}


int redisConn::getData(char *key, unsigned char *data, unsigned int &dataLen)
{
    int32_t iRet = 0;
    redisContext *pConn = pRedisConnPool->getConn();
    if (pConn == NULL)
    {
        return GMCM_FAIL;
    }
    const char *sArgv[2];
    size_t iArgvLen[2];
    sArgv[0] = "GET";
    iArgvLen[0] = 3;
    sArgv[1] = key;
    iArgvLen[1] = strlen(key);

    redisReply *reply = pRedisConnPool->execCmd(pConn, 2, sArgv, iArgvLen);
    if (reply == NULL)
    {
        gmcmLog::LogError() << "redis get fail, key = " << key << endl;
        iRet = GMCM_ERR_REDIS_EXEC;
    }
    else if(reply->len == 0)
    {
        iRet = GMCM_ERR_REDIS_EXEC;
        gmcmLog::LogError() << "redis get fail, key = " << key << endl;
        freeReplyObject(reply);
    }
    else
    {
        if (reply->len > dataLen)
        {
            iRet = GMCM_BUF_TOO_SMALL;
        }
        else
        {
            dataLen = reply->len;
            memcpy(data, reply->str, reply->len);
        }
    }

    pRedisConnPool->realseConn(pConn);
    return iRet;
}

int redisConn::delData(char *key)
{
    redisContext *pConn = pRedisConnPool->getConn();
    int32_t iRet = GMCM_OK;
    if (pConn == NULL)
    {
        return GMCM_FAIL;
    }
    else
    {
        const char *sArgv[2];
        size_t iArgvLen[2];

        sArgv[0] = "DEL";
        iArgvLen[0] = 3;
        sArgv[1] = key;
        iArgvLen[1] = strlen(key);

        redisReply *reply = pRedisConnPool->execCmd(pConn, 2, sArgv, iArgvLen);
        if (reply == NULL)
        {
            gmcmLog::LogError() << "redis get cmd fail, key=" << key << endl;
            iRet = GMCM_ERR_REDIS_EXEC;
        }
        else
        {
            freeReplyObject(reply);
        }

        pRedisConnPool->realseConn(pConn);
        return iRet;
    }
}