#include "keyMgmt.h"
#include <iostream>
#include "../tool/redisConn.h"
#include <stdio.h>
#include "../gmcmErr.h"
#include <string.h>
#include "../server.h"

int keyOper::get(string key, unsigned char *data, unsigned int length)
{
    unsigned int len = length;
    return redisConn::getData((char *)key.c_str(), data, len);
}

int signKeyMgmt::get(unsigned int index, unsigned char *data, unsigned int length)
{
    if(keyOper::checkIndex(index))
    {
        return GMCM_ERR_KEK_INDEX;
    }

    string key = "sm2SignKey_" + index;
    return keyOper::get(key, data, length);
}

int encKeyMgmt::get(unsigned int index, unsigned char *data, unsigned int length)
{
    if (keyOper::checkIndex(index))
    {
        return GMCM_ERR_KEK_INDEX;
    }

    string key = "sm2EncKey_" + index;
    return keyOper::get(key, data, length);
}

int asymKeyMgmt::getAsymKey(unsigned int index, asymKey *key)
{
    return get(index, (unsigned char *)key, sizeof(asymKey));
}

int asymKeyMgmt::getPubkey(unsigned int index, ECCrefPublicKey *pubkey)
{
    asymKey key;
    int ret = get(index, (unsigned char *)&key, sizeof(asymKey));
    if (ret)
    {
    }
    else
    {
        memcpy(pubkey, &key.pub, sizeof(ECCrefPublicKey));
    }
    return ret;
}

int asymKeyMgmt::getPrikey(unsigned int index, ECCrefPrivateKey *prikey)
{
    asymKey key;
    int ret = get(index, (unsigned char *)&key, sizeof(asymKey));
    if (ret)
    {
    }
    else
    {
        memcpy(prikey, &key.pri, sizeof(ECCrefPublicKey));
    }
    return ret;
}

bool signKeyMgmt::isExist(unsigned int index)
{
    asymKey key;
    return !get(index, (unsigned char *)&key, sizeof(key));
}

int signKeyMgmt::gen(unsigned int index, unsigned int algid)
{
    if (isExist(index))
    {
        return GMCM_ERR_KEY_EXIST;
    }

    sdfMeth *pMeth = gmcmServer::getSdfMeth();
    asymKey key = {0};
    int iRet = 0;

    iRet = pMeth->GenerateKeyPair_ECC(&key.pub, &key.pri);
    if (iRet)
    {
        return iRet;
    }

    key.index = 1;
    key.type = 1;
    string skey = "sm2SignKey_" + index;
    iRet = redisConn::setData((char *)skey.c_str(), (unsigned char *)&key, sizeof(asymKey));
    return iRet;
}

bool encKeyMgmt::isExist(unsigned int index)
{
    asymKey key;
    return !get(index, (unsigned char *)&key, sizeof(key));
}

int encKeyMgmt::gen(unsigned int index, unsigned int algid)
{
    if (isExist(index))
    {
        return GMCM_ERR_KEY_EXIST;
    }

    sdfMeth *pMeth = gmcmServer::getSdfMeth();
    asymKey key = {0};
    int iRet = 0;

    iRet = pMeth->GenerateKeyPair_ECC(&key.pub, &key.pri);
    if (iRet)
    {
        return iRet;
    }

    key.index = 1;
    key.type = 2;
    string skey = "sm2EncKey_" + index;
    iRet = redisConn::setData((char *)skey.c_str(), (unsigned char *)&key, sizeof(asymKey));
    return iRet;
}

int signKeyMgmt::del(unsigned int index)
{
    string key = "sm2SignKey_" + index;
    return redisConn::delData((char *)key.c_str());
}

int encKeyMgmt::del(unsigned int index)
{
    string key = "sm2EncKey_" + index;
    return redisConn::delData((char *)key.c_str());
}

int symKeyMgmt::get(unsigned int index, unsigned char *data, unsigned int length)
{
    if (keyOper::checkIndex(index))
    {
        return GMCM_ERR_KEK_INDEX;
    }

    string key = "symKey_" + index;
    return keyOper::get(key, data, length);
}

int symKeyMgmt::del(unsigned int index)
{
    string key = "symKey_" + index;
    return redisConn::delData((char *)key.c_str());
}

bool symKeyMgmt::isExist(unsigned int index)
{
    symKey key;
    return !get(index, (unsigned char *)&key, sizeof(key));
}

int symKeyMgmt::gen(unsigned int index, unsigned int algid)
{
    if (!(algid & SGD_SM4))
    {
        return GMCM_ERR_ALGID;
    }

    if (isExist(index))
    {
        return GMCM_ERR_KEY_EXIST;
    }

    sdfMeth *pMeth = gmcmServer::getSdfMeth();
    symKey key = {0};
    int iRet = 0;

    iRet = pMeth->GenerateRandom(16, key.keyVal);
    if (iRet)
    {
        return iRet;
    }
    key.keyLen = 16;
    key.alg = algid;
    key.index = 1;

    string skey = "sm2EncKey_" + index;
    iRet = redisConn::setData((char *)skey.c_str(), (unsigned char *)&key, sizeof(asymKey));
    return iRet;
}

int symKeyMgmt::getSymKey(unsigned int index, symKey *key)
{
    return get(index, (unsigned char *)key, sizeof(symKey));
}

int symKeyMgmt::getKeyVal(unsigned int index, unsigned char *key, unsigned int *length, unsigned int *algid)
{
    symKey tkey;
    int ret = getSymKey(index, &tkey);
    if(ret)
    {
    }
    else
    {
        memcpy(key, tkey.keyVal, tkey.keyLen);
        *length = tkey.keyLen;
        *algid = tkey.alg;
    }
    return ret;
}

static keyMgmt keyMethAlgFunc;

int get_sign_pubKey_ecc(unsigned int uiKeyIndex, ECCrefPublicKey *pucPublicKey)
{
    return keyMethAlgFunc.signKeyMgmt::getPubkey(uiKeyIndex, pucPublicKey);
}

int get_sign_priKey_ecc(unsigned int uiKeyIndex, ECCrefPrivateKey *pucPrivateKey)
{
    return keyMethAlgFunc.signKeyMgmt::getPrikey(uiKeyIndex, pucPrivateKey);
}

int get_enc_pubKey_ecc(unsigned int uiKeyIndex, ECCrefPublicKey *pucPublicKey)
{
    return keyMethAlgFunc.encKeyMgmt::getPubkey(uiKeyIndex, pucPublicKey);
}

int get_enc_priKey_ecc(unsigned int uiKeyIndex, ECCrefPrivateKey *pucPrivateKey)
{
    return keyMethAlgFunc.encKeyMgmt::getPrikey(uiKeyIndex, pucPrivateKey);
}

int get_kek(unsigned int uiKeyIndex, unsigned char *key, unsigned int *keyLen, unsigned int *keyalg)
{
    return keyMethAlgFunc.symKeyMgmt::getKeyVal(uiKeyIndex, key, keyLen, keyalg);
}

key_mgmt_meth *getKeyMgmtMeth()
{
    static key_mgmt_meth tMeth = {0};
    if (tMeth.get_sign_pubKey_ecc == NULL)
    {
        tMeth.get_sign_pubKey_ecc = get_sign_pubKey_ecc;
        tMeth.get_sign_priKey_ecc = get_sign_priKey_ecc;
        tMeth.get_enc_pubKey_ecc = get_enc_pubKey_ecc;
        tMeth.get_enc_priKey_ecc = get_enc_priKey_ecc;
        tMeth.get_kek = get_kek;
    }
    return &tMeth;
}