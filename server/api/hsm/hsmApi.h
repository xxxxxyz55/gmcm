#ifndef _GMCM_HSM_API_H_
#define _GMCM_HSM_API_H_

#include "../../apiEngine/apiEngine.h"

std::vector<std::pair<std::string, hsmApiFuncPtr>> getHsmClvApis();
std::string hsmDealError(unsigned char *reqStr, unsigned int reqStrLen);

#endif