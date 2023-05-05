#ifndef _GMCM_MGMT_API_H_
#define _GMCM_MGMT_API_H_

#include "../../apiEngine/apiEngine.h"

std::vector<std::pair<std::string, mgmtApiFuncPtr>>  getMgmtApis();

#endif