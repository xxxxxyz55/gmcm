#include "keyMgmt.h"
#include <iostream>
#include "../tool/redisConn.h"
#include <stdio.h>
#include "../gmcmErr.h"
#include <string.h>
#include "../server.h"

key_mgmt_meth *getKeyMgmtMeth(keyMgmt *mgmt)
{
    mgmt->_keyMgmtMeth.get_sign_pubKey_ecc = std::bind(&signKeyMgmt::getEccSignPubKey, mgmt, std::placeholders::_1, std::placeholders::_2);
    mgmt->_keyMgmtMeth.get_sign_priKey_ecc = std::bind(&signKeyMgmt::getEccSignPriKey, mgmt, std::placeholders::_1, std::placeholders::_2);
    mgmt->_keyMgmtMeth.get_enc_pubKey_ecc = std::bind(&encKeyMgmt::getEccEncPubKey, mgmt, std::placeholders::_1, std::placeholders::_2);
    mgmt->_keyMgmtMeth.get_enc_priKey_ecc = std::bind(&encKeyMgmt::getEccEncPriKey, mgmt, std::placeholders::_1, std::placeholders::_2);
    mgmt->_keyMgmtMeth.get_kek = std::bind(&symKeyMgmt::getKek, mgmt, std::placeholders::_1, std::placeholders::_2,
                                           std::placeholders::_3, std::placeholders::_4);
    return &mgmt->_keyMgmtMeth;
}

int asymKeyMgmt::getAsymKey(unsigned int index, unsigned int algid, asymKey *key)
{
    char redisKey[32];
    snprintf(redisKey, sizeof(redisKey), "USING_ASYM_%d", index);
    unsigned int keyLen = sizeof(asymKey);
    int ret = redisConn::hashGetData(name, redisKey, (unsigned char *)key, keyLen);
    if(ret)
    {

    }
    else
    {
        if (algid && algid != key->param.algId)
        {
            ret = GMCM_ERR_KEY_TYPE;
        }
    }

    return ret;
}

int symKeyMgmt::getSymKey(unsigned int index, unsigned int algid, symKey *key)
{
    char redisKey[32];
    snprintf(redisKey, sizeof(redisKey), "USING_SYM_%d", index);
    unsigned int keyLen = sizeof(symKey);
    int ret = redisConn::hashGetData(name, redisKey, (unsigned char *)key, keyLen);
    if(ret)
    {

    }
    else
    {
        if (algid && algid != key->param.alg)
        {
            ret = GMCM_ERR_KEY_TYPE;
        }
    }

    return ret;
}

int symKeyMgmt::getKek(unsigned int index, unsigned char *key, unsigned int *keyLen, unsigned int *keyalg)
{
    symKey keyBuf;
    int ret = getSymKey(index, 0, &keyBuf);
    if(ret)
    {

    }
    else
    {
        memcpy(key, keyBuf.val.sym.key, keyBuf.val.sym.keyLen);
        *keyLen = keyBuf.val.sym.keyLen;
        *keyalg = keyBuf.param.alg;
    }
    return ret;
}

int signKeyMgmt::getEccSignPubKey(unsigned int index, ECCrefPublicKey *pub)
{
    asymKey keyBuf;
    int ret = getAsymKey(index, SGD_SM2_SIGN, &keyBuf);
    if (ret)
    {
    }
    else
    {
        memcpy(pub, &keyBuf.val.ecc.pub, sizeof(ECCrefPublicKey));
    }

    return ret;
}

int signKeyMgmt::getEccSignPriKey(unsigned int index, ECCrefPrivateKey *pri)
{
    asymKey keyBuf;
    int ret = getAsymKey(index, SGD_SM2_SIGN, &keyBuf);
    if (ret)
    {
    }
    else
    {
        memcpy(pri, &keyBuf.val.ecc.pri, sizeof(ECCrefPrivateKey));
    }

    return ret;
}

int signKeyMgmt::getRsaSignPubKey(unsigned int index, RSArefPublicKey *pub)
{
    asymKey keyBuf;
    int ret = getAsymKey(index, SGD_RSA_SIGN, &keyBuf);
    if (ret)
    {
    }
    else
    {
        memcpy(pub, &keyBuf.val.ecc.pub, sizeof(RSArefPublicKey));
    }

    return ret;
}

int signKeyMgmt::getRsaSignPriKey(unsigned int index, RSArefPrivateKey *pri)
{
    asymKey keyBuf;
    int ret = getAsymKey(index, SGD_RSA_SIGN, &keyBuf);
    if (ret)
    {
    }
    else
    {
        memcpy(pri, &keyBuf.val.ecc.pri, sizeof(RSArefPrivateKey));
    }

    return ret;
}

int encKeyMgmt::getEccEncPubKey(unsigned int index, ECCrefPublicKey *pub)
{
    asymKey keyBuf;
    int ret = getAsymKey(index, SGD_SM2_ENC, &keyBuf);
    if (ret)
    {
    }
    else
    {
        memcpy(pub, &keyBuf.val.ecc.pub, sizeof(ECCrefPublicKey));
    }

    return ret;
}
int encKeyMgmt::getEccEncPriKey(unsigned int index, ECCrefPrivateKey *pri)
{
    asymKey keyBuf;
    int ret = getAsymKey(index, SGD_SM2_ENC, &keyBuf);
    if (ret)
    {
    }
    else
    {
        memcpy(pri, &keyBuf.val.ecc.pri, sizeof(ECCrefPrivateKey));
    }

    return ret;
}
int encKeyMgmt::getRsaEncPubKey(unsigned int index, RSArefPublicKey *pub)
{
    asymKey keyBuf;
    int ret = getAsymKey(index, SGD_RSA_ENC, &keyBuf);
    if (ret)
    {
    }
    else
    {
        memcpy(pub, &keyBuf.val.ecc.pub, sizeof(RSArefPublicKey));
    }

    return ret;
}
int encKeyMgmt::getRsaEncPriKey(unsigned int index, RSArefPrivateKey *pri)
{
    asymKey keyBuf;
    int ret = getAsymKey(index, SGD_RSA_ENC, &keyBuf);
    if (ret)
    {
    }
    else
    {
        memcpy(pri, &keyBuf.val.ecc.pri, sizeof(RSArefPrivateKey));
    }

    return ret;
}