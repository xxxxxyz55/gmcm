#ifndef _GMCM_HSM_PKT_H_
#define _GMCM_HSM_PKT_H_
#include "../../../encode/clv/clv_static.h"
#include "../../alg/include/gmcmSdf.h"

CLV_SEQ_REF(respError)
CLV_INT(err, NULL)
CLV_SEQ_END_REF(respError)

CLV_SEQ_REF(reqRandom)
CLV_INT(length, NULL)
CLV_SEQ_END_REF(reqRandom)

CLV_SEQ_REF(respRandom)
CLV_USTR(rand, NULL)
CLV_SEQ_END_REF(respRandom)

CLV_SEQ_REF(reqGenEccPair)
CLV_INT(algid, NULL)
CLV_INT(bits, NULL)
CLV_SEQ_END_REF(reqGenEccPair)

CLV_SEQ_REF(respGenEccPair)
CLV_ST(ECCrefPublicKey, pub, NULL)
CLV_ST(ECCrefPrivateKey, pri, NULL)
CLV_SEQ_END_REF(respGenEccPair)

CLV_SEQ_REF(reqImportKey)
CLV_USTR(uikey, NULL)
CLV_SEQ_END_REF(reqImportKey)

CLV_SEQ_REF(respImportKey)
CLV_USTR(hd, NULL)
CLV_SEQ_END_REF(respImportKey)

CLV_SEQ_REF(reqDestroyKey)
CLV_USTR(hd, NULL)
CLV_SEQ_END_REF(reqDestroyKey)

CLV_SEQ_REF(respDestroyKey)
CLV_SEQ_END_REF(respDestroyKey)

CLV_SEQ_REF(reqEncrypt)
CLV_USTR(hd, NULL)
CLV_INT(algid, NULL)
CLV_USTR(iv, NULL)
CLV_USTR(data, NULL)
CLV_SEQ_END_REF(reqEncrypt)

CLV_SEQ_REF(respEncrypt)
CLV_USTR(iv, NULL)
CLV_USTR(encData, NULL)
CLV_SEQ_END_REF(respEncrypt)

CLV_SEQ_REF(reqDecrypt)
CLV_USTR(hd, NULL)
CLV_INT(algid, NULL)
CLV_USTR(iv, NULL)
CLV_USTR(encData, NULL)
CLV_SEQ_END_REF(reqDecrypt)

CLV_SEQ_REF(respDecrypt)
CLV_USTR(iv, NULL)
CLV_USTR(decData, NULL)
CLV_SEQ_END_REF(respDecrypt)



#endif