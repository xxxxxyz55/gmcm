#ifndef _GMCM_KEY_MGMT_H_
#define _GMCM_KEY_MGMT_H_

#include <string>
#include "../tool/redisConn.h"
#include "softSdfApi.h"
#include "../algProvider/algProvider.h"

using namespace std;

#define SDF_MAX_KEY_NUM 1024

typedef struct eccKeyPair_st
{
    ECCrefPublicKey pub;
    ECCrefPrivateKey pri;
} eccKeyPair;

typedef struct rsaKeyPair_st
{
    RSArefPrivateKey pri;
} rsaKeyPair;


typedef struct asymKeyParam_st
{
    unsigned int index;
    unsigned int algId;
    char name[128];
    char tag[128];
    unsigned int pwdLen;
    char pwd[32];
}asymKeyParam;

typedef struct asymKey_st
{
    unsigned int savaSize;
    asymKeyParam param;
    union {
        eccKeyPair ecc;
        rsaKeyPair rsa;
    } val;
} asymKey;

typedef struct symKeyParam_st
{
    unsigned int index;
    unsigned int alg;
    char tag[128];
} symKeyParam;

typedef struct symKeyVal_st
{
    unsigned int ivLen;
    unsigned int iv[32];
    unsigned int keyLen;
    unsigned char key[32];
} symKeyVal;

typedef struct symKey_st
{
    unsigned int savaSize;
    symKeyParam param;
    union {
        symKeyVal sym;
    } val;
} symKey;

class keyMgmtRelyOn
{
public:
    sdfMeth *algMeth; //算法接口
    char name[128];//所属应用
    keyMgmtRelyOn(){};
    keyMgmtRelyOn(sdfMeth *meth, const char *appName)
    {
        algMeth = meth;
        snprintf(name, sizeof(name), "%s", appName);
    }
};

//asymKey
class asymKeyMgmt : virtual public keyMgmtRelyOn
{
private:

public:
    // int saveAsymKey(asymKey*key);
    int getAsymKey(unsigned int index, unsigned int algid, asymKey *key);
};

class signKeyMgmt : virtual public asymKeyMgmt
{
private:

public:
    int getEccSignPubKey(unsigned int index, ECCrefPublicKey *pub);
    int getEccSignPriKey(unsigned int index, ECCrefPrivateKey *pri);
    int getRsaSignPubKey(unsigned int index, RSArefPublicKey *pub);
    int getRsaSignPriKey(unsigned int index, RSArefPrivateKey *pri);
};

class encKeyMgmt : virtual public asymKeyMgmt
{
private:
    /* data */
public:
    int getEccEncPubKey(unsigned int index, ECCrefPublicKey *pub);
    int getEccEncPriKey(unsigned int index, ECCrefPrivateKey *pri);
    int getRsaEncPubKey(unsigned int index, RSArefPublicKey *pub);
    int getRsaEncPriKey(unsigned int index, RSArefPrivateKey *pri);
};

class symKeyMgmt : keyMgmtRelyOn
{
private:

public:
    int saveSymKey(symKey *key);
    int getSymKey(unsigned int index, unsigned int algid, symKey *key);
    int getKek(unsigned int index, unsigned char *key, unsigned int *keyLen, unsigned int *keyalg);
};

class keyMgmt : public signKeyMgmt, public encKeyMgmt, public symKeyMgmt
{

public:
    key_mgmt_meth _keyMgmtMeth;
    keyMgmt(sdfMeth *meth, const char *appName) : keyMgmtRelyOn(meth, appName)
    {
    }
};

key_mgmt_meth *getKeyMgmtMeth(keyMgmt *mgmt);


#endif