#ifndef _GMCM_UTIL_FUNC_H_
#define _GMCM_UTIL_FUNC_H_
#include "pthread.h"
#include <iostream>
#include <string>

using namespace std;

#ifndef _GLIBCXX_HAS_GTHREADS
#define _GLIBCXX_HAS_GTHREADS
#endif

#ifndef GMCM_OK
#define GMCM_OK 0
#define GMCM_FAIL 1
#endif

class rwlock
{
private:
    /* data */
    pthread_rwlock_t rwMapLock;

public:
    rwlock(/* args */)
    {
        pthread_rwlock_init(&this->rwMapLock, NULL);
    }

    ~rwlock()
    {
        pthread_rwlock_destroy(&this->rwMapLock);
    }

    int init()
    {
        if (pthread_rwlock_init(&this->rwMapLock, NULL))
        {
            return GMCM_FAIL;
        }
        else
        {
            return GMCM_OK;
        }
    }

    int rlock()
    {
        if (pthread_rwlock_rdlock(&this->rwMapLock))
        {
            return GMCM_FAIL;
        }
        else
        {
            return GMCM_OK;
        }
    }
    int wlock()
    {
        if (pthread_rwlock_wrlock(&this->rwMapLock))
        {
            return GMCM_FAIL;
        }
        else
        {
            return GMCM_OK;
        }
    }
    int unlock()
    {
        if (pthread_rwlock_unlock(&this->rwMapLock))
        {
            return GMCM_FAIL;
        }
        else
        {
            return GMCM_OK;
        }
    }
};

class utilTool
{
private:
    /* data */

public:
    static void Msleep(unsigned int ms)
    {
        struct timeval Time;
        Time.tv_sec = ms / 1000;
        Time.tv_usec = ms % 1000 * 1000;
        select(0, NULL, NULL, NULL, &Time);
    }

    static int std_get_int(const char *tag)
    {
        printf("%s", tag);
        fflush(stdout);
        int val;
        cin >> val;
        return val;
    }

    static string std_get_string(const char *tag)
    {
        printf("%s", tag);
        fflush(stdout);
        string buf;
        cin >> buf;
        return buf;
        
    }

    static void printHex(unsigned char *data, unsigned int dataLen, const char *tag = NULL)
    {
        if(tag)
        {
            printf("%s:\n", tag);
        }

        if (data && dataLen)
        {
            for (size_t i = 0; i < dataLen; i++)
            {
                printf("%02X", data[i]);
            }
        }
        printf("\n");
    }

    utilTool(/* args */){};
    ~utilTool(){};
};


#endif