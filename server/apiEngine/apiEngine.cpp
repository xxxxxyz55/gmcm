#include "apiEngine.h"
#include "../api/hsm/hsmApi.h"
#include "../api/mgmt/mgmtApi.h"
#include "../api/svs/svsApi.h"

hsmApiClvEngine::hsmApiClvEngine()
{
    loadApis(getHsmClvApis());
}

hsmApiClvEngine::~hsmApiClvEngine()
{

}

mgmtApiEngine::mgmtApiEngine() 
{
    loadApis(getMgmtApis());
}

mgmtApiEngine::~mgmtApiEngine()
{
}

svsApiEngine::svsApiEngine()
{
    loadApis(getSvsApis());
}

svsApiEngine::~svsApiEngine()
{
}
