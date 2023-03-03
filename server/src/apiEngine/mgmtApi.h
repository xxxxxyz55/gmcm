#ifndef _GMCM_MGMT_API_H_
#define _GMCM_MGMT_API_H_

#include "apiEngine.h"
#include "util/tc_http.h"
#include "pjst.h"

using namespace pjst;
using namespace std;
using namespace tars;

typedef unsigned int (*mgmtApiFuncPtr)(TC_HttpRequest *request, TC_HttpResponse *response);
class mgmtApiEngine : public apiEngine<mgmtApiFuncPtr>
{
public:
    mgmtApiEngine();
    ~mgmtApiEngine();
};

#define ADD_HTTP_API_FUNC(name) unsigned int name(TC_HttpRequest *request, TC_HttpResponse *response);

ADD_HTTP_API_FUNC(mgmtHelpPage)
/*
PJST_FIELD_BEGIN(reqGenerateRandom, "随机数")
PJST_FIELD_ADD(length, PJST_NUM, 1, NULL)
PJST_FIELD_END(reqGenerateRandom)
ADD_HTTP_API_FUNC(mgmtGenerateRandom)
*/

#endif