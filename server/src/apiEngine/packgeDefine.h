#ifndef _GMCM_PACKAGE_DEFINE_H_
#define _GMCM_PACKAGE_DEFINE_H_

#include "protostruct.h"

PROTOST_BEGIN(reqRandBytes, "获取随机数")
PROTOST_FIELD_ADD(length, unsigned int, NULL)
PROTOST_END(reqRandBytes)

PROTOST_BEGIN(respRandBytes, "获取随机数")
PROTOST_FIELD_ADD(random, unsigned char, NULL)
PROTOST_END(respRandBytes)

PROTOST_BEGIN(reqGenEccKeyPair, "生成密钥对")
PROTOST_FIELD_ADD(algid, unsigned int, NULL)
PROTOST_FIELD_ADD(bits, unsigned int, NULL)
PROTOST_END(reqGenEccKeyPair)

PROTOST_BEGIN(respGenEccKeyPair, "生成密钥对")
PROTOST_FIELD_ADD(pub, ECCrefPublicKey, NULL)
PROTOST_FIELD_ADD(pri, ECCrefPrivateKey, NULL)
PROTOST_END(respGenEccKeyPair)

PROTOST_BEGIN(reqImportKey, "")
PROTOST_FIELD_ADD(uikey, unsigned char, NULL)
PROTOST_END(reqImportKey)

PROTOST_BEGIN(respImportKey, "")
PROTOST_FIELD_ADD(handle, unsigned char, NULL)
PROTOST_END(respImportKey)

PROTOST_BEGIN(reqDestroyKey, "")
PROTOST_FIELD_ADD(handle, unsigned char, NULL)
PROTOST_END(reqDestroyKey)

PROTOST_BEGIN(respDestroyKey, "")
PROTOST_END(respDestroyKey)

PROTOST_BEGIN(reqEncrypt, "")
PROTOST_FIELD_ADD(handle, unsigned char, NULL)
PROTOST_FIELD_ADD(algid, unsigned int, NULL)
PROTOST_FIELD_ADD(iv, unsigned char, NULL)
PROTOST_FIELD_ADD(data, unsigned char, NULL)
PROTOST_END(reqEncrypt)

PROTOST_BEGIN(respEncrypt, "")
PROTOST_FIELD_ADD(iv, unsigned char, NULL)
PROTOST_FIELD_ADD(encData, unsigned char, NULL)
PROTOST_END(respEncrypt)

PROTOST_BEGIN(reqDecrypt, "")
PROTOST_FIELD_ADD(handle, unsigned char, NULL)
PROTOST_FIELD_ADD(algid, unsigned int, NULL)
PROTOST_FIELD_ADD(iv, unsigned char, NULL)
PROTOST_FIELD_ADD(encData, unsigned char, NULL)
PROTOST_END(reqDecrypt)

PROTOST_BEGIN(respDecrypt, "")
PROTOST_FIELD_ADD(iv, unsigned char, NULL)
PROTOST_FIELD_ADD(decData, unsigned char, NULL)
PROTOST_END(respDecrypt)

#endif