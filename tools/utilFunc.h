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

    static int stdGetInt(const char *tag)
    {
        printf("%s", tag);
        fflush(stdout);
        int val;
        cin >> val;
        return val;
    }

    static string stdGetString(const char *tag)
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

    static void printHex(string data, const char *tag = NULL)
    {
        if(tag)
        {
            printf("%s:\n", tag);
        }

        for (size_t i = 0; i < data.length(); i++)
        {
            printf("%02X", data[i]);
        }
        printf("\n");
    }

    utilTool(/* args */){};
    ~utilTool(){};
};

class base64
{
private:
#define BASE64_PAD '='
#define BASE64DE_FIRST '+'
#define BASE64DE_LAST 'z'


public:
    static unsigned int base64Encode(const unsigned char *in, unsigned int inlen, char *out)
    {
        int s;
        unsigned int i;
        unsigned int j;
        unsigned char c;
        unsigned char l;
        /* BASE 64 encode table */
        static const char base64en[] = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
        'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
        'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
        'w', 'x', 'y', 'z', '0', '1', '2', '3',
        '4', '5', '6', '7', '8', '9', '+', '/',
        };

        s = 0;
        l = 0;
        for (i = j = 0; i < inlen; i++)
        {
            c = in[i];

            switch (s)
            {
            case 0:
                s = 1;
                out[j++] = base64en[(c >> 2) & 0x3F];
                break;
            case 1:
                s = 2;
                out[j++] = base64en[((l & 0x3) << 4) | ((c >> 4) & 0xF)];
                break;
            case 2:
                s = 0;
                out[j++] = base64en[((l & 0xF) << 2) | ((c >> 6) & 0x3)];
                out[j++] = base64en[c & 0x3F];
                break;
            }
            l = c;
        }

        switch (s)
        {
        case 1:
            out[j++] = base64en[(l & 0x3) << 4];
            out[j++] = BASE64_PAD;
            out[j++] = BASE64_PAD;
            break;
        case 2:
            out[j++] = base64en[(l & 0xF) << 2];
            out[j++] = BASE64_PAD;
            break;
        }

        out[j] = 0;

        return j;
    }

    static unsigned int base64Decode(const char *in, unsigned int inlen, unsigned char *out)
    {
        unsigned int i;
        unsigned int j;
        unsigned char c;
        /* ASCII order for BASE 64 decode, 255 in unused character */
        static const unsigned char base64de[] = {
            /* nul, soh, stx, etx, eot, enq, ack, bel, */
               255, 255, 255, 255, 255, 255, 255, 255,

            /*  bs,  ht,  nl,  vt,  np,  cr,  so,  si, */
               255, 255, 255, 255, 255, 255, 255, 255,

            /* dle, dc1, dc2, dc3, dc4, nak, syn, etb, */
               255, 255, 255, 255, 255, 255, 255, 255,

            /* can,  em, sub, esc,  fs,  gs,  rs,  us, */
               255, 255, 255, 255, 255, 255, 255, 255,

            /*  sp, '!', '"', '#', '$', '%', '&', ''', */
               255, 255, 255, 255, 255, 255, 255, 255,

            /* '(', ')', '*', '+', ',', '-', '.', '/', */
               255, 255, 255,  62, 255, 255, 255,  63,

            /* '0', '1', '2', '3', '4', '5', '6', '7', */
                52,  53,  54,  55,  56,  57,  58,  59,

            /* '8', '9', ':', ';', '<', '=', '>', '?', */
                60,  61, 255, 255, 255, 255, 255, 255,

            /* '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', */
               255,   0,   1,  2,   3,   4,   5,    6,

            /* 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', */
                 7,   8,   9,  10,  11,  12,  13,  14,

            /* 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', */
                15,  16,  17,  18,  19,  20,  21,  22,

            /* 'X', 'Y', 'Z', '[', '\', ']', '^', '_', */
                23,  24,  25, 255, 255, 255, 255, 255,

            /* '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', */
               255,  26,  27,  28,  29,  30,  31,  32,

            /* 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', */
                33,  34,  35,  36,  37,  38,  39,  40,

            /* 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', */
                41,  42,  43,  44,  45,  46,  47,  48,

            /* 'x', 'y', 'z', '{', '|', '}', '~', del, */
                49,  50,  51, 255, 255, 255, 255, 255
        };

        if (inlen & 0x3)
        {
            return 0;
        }

        for (i = j = 0; i < inlen; i++)
        {
            if (in[i] == BASE64_PAD)
            {
                break;
            }
            if (in[i] < BASE64DE_FIRST || in[i] > BASE64DE_LAST)
            {
                return 0;
            }

            c = base64de[(unsigned char)in[i]];
            if (c == 255)
            {
                return 0;
            }

            switch (i & 0x3)
            {
            case 0:
                out[j] = (c << 2) & 0xFF;
                break;
            case 1:
                out[j++] |= (c >> 4) & 0x3;
                out[j] = (c & 0xF) << 4;
                break;
            case 2:
                out[j++] |= (c >> 2) & 0xF;
                out[j] = (c & 0x3) << 6;
                break;
            case 3:
                out[j++] |= c;
                break;
            }
        }

        return j;
    }
};


#endif