#ifndef _PACKAGE_DEFINE_H_
#define _PACKAGE_DEFINE_H_

#include "pst.h"
using namespace pst;

PST_FIELD_BEGIN(reqRandBytes, "获取随机数")
PST_FIELD_ADD(length, PST_U_INT, NULL)
PST_FIELD_END(reqRandBytes)

PST_FIELD_BEGIN(respRandBytes, "获取随机数")
PST_FIELD_ADD(random, PST_U_STRING, NULL)
PST_FIELD_END(respRandBytes)

PST_FIELD_BEGIN(reqGenEccKeyPair, "生成密钥对")
PST_FIELD_ADD(algid, PST_U_INT, NULL)
PST_FIELD_ADD(bits, PST_U_INT, NULL)
PST_FIELD_END(reqGenEccKeyPair)

PST_FIELD_BEGIN(respGenEccKeyPair, "生成密钥对")
PST_FIELD_ADD(pub, PST_U_STRING, NULL)
PST_FIELD_ADD(pri, PST_U_STRING, NULL)
PST_FIELD_END(respGenEccKeyPair)

PST_FIELD_BEGIN(reqImportKey, "")
PST_FIELD_ADD(uikey, PST_U_INT, NULL)
PST_FIELD_END(reqImportKey)

PST_FIELD_BEGIN(respImportKey, "")
PST_FIELD_ADD(handle, PST_U_INT, NULL)
PST_FIELD_END(respImportKey)

PST_FIELD_BEGIN(reqDestroyKey, "")
PST_FIELD_ADD(handle, PST_U_STRING, NULL)
PST_FIELD_END(reqDestroyKey)

PST_FIELD_BEGIN(respDestroyKey, "")
PST_FIELD_END(respDestroyKey)

PST_FIELD_BEGIN(reqEncrypt, "")
PST_FIELD_ADD(handle, PST_U_STRING, NULL)
PST_FIELD_ADD(algid, PST_U_INT, NULL)
PST_FIELD_ADD(iv, PST_U_STRING, NULL)
PST_FIELD_ADD(data, PST_U_STRING, NULL)
PST_FIELD_END(reqEncrypt)

PST_FIELD_BEGIN(respEncrypt, "")
PST_FIELD_ADD(iv, PST_U_STRING, NULL)
PST_FIELD_ADD(encData, PST_U_STRING, NULL)
PST_FIELD_END(respEncrypt)

PST_FIELD_BEGIN(reqDecrypt, "")
PST_FIELD_ADD(handle, PST_U_STRING, NULL)
PST_FIELD_ADD(algid, PST_U_INT, NULL)
PST_FIELD_ADD(iv, PST_U_STRING, NULL)
PST_FIELD_ADD(encData, PST_U_STRING, NULL)
PST_FIELD_END(reqDecrypt)

PST_FIELD_BEGIN(respDecrypt, "")
PST_FIELD_ADD(iv, PST_U_STRING, NULL)
PST_FIELD_ADD(decData, PST_U_STRING, NULL)
PST_FIELD_END(respDecrypt)


#endif