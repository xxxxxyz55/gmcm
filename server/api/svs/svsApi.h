#ifndef _GMCM_SVS_API_H_
#define _GMCM_SVS_API_H_

#include "../../apiEngine/apiEngine.h"

std::vector<std::pair<std::string, svsApiFuncPtr>> getSvsApis();

#endif