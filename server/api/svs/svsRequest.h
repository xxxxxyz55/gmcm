#ifndef _SVS_REQUEST_H_
#define _SVS_REQUEST_H_

#include "svsPkt.h"
#include "../../gmcmErr.h"
#include "svsApi.h"

template <typename T, typename V>
class svsReq
{
private:
    /* data */
    T req;
    V resp;

public:
    void handle(TC_HttpRequest *request, TC_HttpResponse *response, int32_t (*proc)(T *pReq, V *pResp))
    {
        int32_t iRet;
        if (request->getMethod() == "POST")
        {
            iRet = req.setString(request->getContent().data());
        }
        else if (request->getMethod() == "GET")
        {
            iRet = GMCM_ERR_METHOD;
        }
        else
        {
            iRet = GMCM_ERR_METHOD;
        }

        if(iRet)
        {
            return svsSendErr(iRet, response);
        }

        iRet = proc(&req, &resp);
        if(iRet)
        {
            return svsSendErr(iRet, response);
        }
        else
        {
            response->setResponse(200, "OK", resp.toJsonStr());
        }
    }
};

#define SVS_API_NAME(x) x##Func
#define DECLARE_SVS_API(proc, reqType, respType)                                  \
    void SVS_API_NAME(proc)(TC_HttpRequest * request, TC_HttpResponse * response) \
    {                                                                             \
        svsReq<reqType, respType> ctx;                                            \
        ctx.handle(request, response, proc);                                      \
    }

#endif