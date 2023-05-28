#ifndef _GMCM_SVS_API_H_
#define _GMCM_SVS_API_H_

#include "../../apiEngine/apiEngine.h"

std::vector<std::pair<std::string, svsApiFuncPtr>> getSvsApis();
void svsSendErr(int32_t err, TC_HttpResponse *response);
void SvsDealError(TC_HttpRequest *request, TC_HttpResponse *response);

#endif