#ifndef _GMCM_HSM_API_H_
#define _GMCM_HSM_API_H_

#include "apiEngine.h"
#include "pst.h"

using namespace pst;
using namespace std;

typedef unsigned int (*hsmApiFuncPtr)(unsigned char *req, unsigned int reqLen, pstBuffer *resp);
class hsmApiEngine : public apiEngine<hsmApiFuncPtr>
{
public:
    hsmApiEngine();
    ~hsmApiEngine();
};

#define ADD_API_FUNC(func) unsigned int func(unsigned char *reqStr, unsigned int reqStrLen, pstBuffer *respBase);

ADD_API_FUNC(randBytes)
ADD_API_FUNC(genEccKeyPair)
ADD_API_FUNC(importKey)
ADD_API_FUNC(destroyKey)
ADD_API_FUNC(encrypt)
ADD_API_FUNC(decrypt)
#endif