#ifndef _GMCM_KEY_MGMT_H_
#define _GMCM_KEY_MGMT_H_

#include "softSdfApi.h"
#include <string>

using namespace std;

//类型直接用键 区分 redis保存
#define SDF_MAX_KEY_NUM 1024

typedef struct asymKey_st
{
    unsigned int index;
    unsigned int type;
    char tag[128];
    ECCrefPublicKey pub;
    ECCrefPrivateKey pri;
    unsigned int pwdLen;
    char pwd[32];
}asymKey;

typedef struct symKey_st
{
    unsigned int index;
    unsigned int alg;
    char tag[128];
    unsigned int keyLen;
    unsigned char keyVal[32];
} symKey;

class keyOper
{
private:
    /* data */
public:
    int get(string key, unsigned char *data, unsigned int length);
    int del(string key);
    bool checkIndex(unsigned int index) { return index < SDF_MAX_KEY_NUM; }

    virtual int get(unsigned int index, unsigned char *data, unsigned int length) = 0;
    virtual int del(unsigned int index) = 0;
    virtual int gen(unsigned int index, unsigned int algid) = 0;
};

class asymKeyMgmt : public keyOper
{
private:

public:
    // virtual int get(unsigned int index, unsigned char *data, unsigned int length) = 0;
    // virtual int del(unsigned int index) = 0;
    // int gen(unsigned int index, unsigned int algid);

    int getAsymKey(unsigned int index, asymKey *key);
    int getPubkey(unsigned int index, ECCrefPublicKey *pubkey);
    int getPrikey(unsigned int index, ECCrefPrivateKey *prikey);
};

class signKeyMgmt : public asymKeyMgmt
{
private:

public:
    int get(unsigned int index, unsigned char *data, unsigned int length);
    int del(unsigned int index);
    int gen(unsigned int index, unsigned int algid);
    bool isExist(unsigned int index);
};

class encKeyMgmt : public asymKeyMgmt
{
private:
    /* data */
public:
    int get(unsigned int index, unsigned char *data, unsigned int length);
    int del(unsigned int index);
    int gen(unsigned int index, unsigned int algid);
    bool isExist(unsigned  int index);
};

class symKeyMgmt : public keyOper
{
private:

public:
    int get(unsigned int index, unsigned char *data, unsigned int length);
    int del(unsigned int index);
    int gen(unsigned int index, unsigned int algid);
    int getSymKey(unsigned int index, symKey *key);
    int getKeyVal(unsigned int index, unsigned char *key, unsigned int *length, unsigned int *algid);
    bool isExist(unsigned int index);
};

class keyMgmt : public signKeyMgmt, public encKeyMgmt, public symKeyMgmt
{

};

key_mgmt_meth *getKeyMgmtMeth();

#endif