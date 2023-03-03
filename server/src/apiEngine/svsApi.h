#ifndef _GMCM_SVS_API_H_
#define _GMCM_SVS_API_H_

#include "apiEngine.h"
#include "util/tc_http.h"
#include "pjst.h"

using namespace pjst;
using namespace std;
using namespace tars;

typedef unsigned int (*svsApiFuncPtr)(TC_HttpRequest *request, TC_HttpResponse *response);
class svsApiEngine : public apiEngine<svsApiFuncPtr>
{
public:
    svsApiEngine();
    ~svsApiEngine();
};

#define ADD_HTTP_API_FUNC(name) unsigned int name(TC_HttpRequest *request, TC_HttpResponse *response);

ADD_HTTP_API_FUNC(helpPage)

PJST_FIELD_BEGIN(reqGenerateRandom, "")
PJST_FIELD_ADD(length, PJST_NUM, 1, NULL)
PJST_FIELD_END(reqGenerateRandom)
ADD_HTTP_API_FUNC(SvsGenerateRandom)

PJST_FIELD_BEGIN(reqSvsGenKey, "")
PJST_FIELD_ADD(type, PJST_STRING, 1, NULL)
PJST_FIELD_ADD(bits, PJST_NUM, 0, NULL)
PJST_FIELD_END(reqSvsGenKey)
ADD_HTTP_API_FUNC(SvsGenKey)

PJST_FIELD_BEGIN(reqSvsGenCsr, "")
PJST_FIELD_ADD(prikey, PJST_STRING, 1, NULL)
PJST_FIELD_ADD(subj, PJST_STRING, 1, NULL)
PJST_FIELD_END(reqSvsGenCsr)
ADD_HTTP_API_FUNC(SvsGenCsr)

PJST_FIELD_BEGIN(reqSvsSignCert, "")
PJST_FIELD_ADD(csr, PJST_STRING, 1, NULL)
PJST_FIELD_ADD(caCert, PJST_STRING, 0, NULL)
PJST_FIELD_ADD(caKey, PJST_STRING, 1, NULL)
PJST_FIELD_ADD(usage, PJST_STRING, 1, NULL)
PJST_FIELD_END(reqSvsSignCert)
ADD_HTTP_API_FUNC(SvsSignCert)
#endif