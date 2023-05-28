#include "apiEngine.h"
#include "../api/hsm/hsmApi.h"
#include "../api/mgmt/mgmtApi.h"
#include "../api/svs/svsApi.h"

hsmApiEngine::hsmApiEngine()
{
    setDefcb(hsmDealError);
    loadApis(getHsmClvApis());
}

hsmApiEngine::~hsmApiEngine()
{

}

mgmtApiEngine::mgmtApiEngine() 
{
    setDefcb(SvsDealError);
    loadApis(getMgmtApis());
}

mgmtApiEngine::~mgmtApiEngine()
{
}

svsApiEngine::svsApiEngine()
{
    setDefcb(SvsDealError);
    loadApis(getSvsApis());
}

svsApiEngine::~svsApiEngine()
{
}
