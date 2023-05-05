#ifndef _GMCM_HSM_API_H_
#define _GMCM_HSM_API_H_

#include "../../apiEngine/apiEngine.h"

std::vector<std::pair<std::string, hsmApiClvFuncPtr>> getHsmClvApis();
int32_t send_err(int32_t ret, std::function<int32_t(void *, uint16_t)> writCb);

#endif