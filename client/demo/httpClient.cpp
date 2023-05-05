#include "util/tc_http.h"
#include "utilFunc.h"
#include "../../server//serverConf.h"
#include "openssl/err.h"

using namespace tars;
using namespace std;

void openssl_err_stack()
{
#if TARS_SSL
    int ret = ERR_get_error();
    while (ret)
    {
        printf("%d\n", ret);
        printf("ERR FUN :%s\n", ERR_func_error_string(ret));
        printf("ERR reason :%s\n", ERR_reason_error_string(ret));
        ret = ERR_get_error();
    }
#endif
    return;
}

void testHelpPage()
{
    TC_HttpRequest stHttpReq;
    stHttpReq.setCacheControl("no-cache");
    stHttpReq.setGetRequest("https://10.28.16.83:8806/help", true);
    TC_HttpResponse stHttpRsp;
    cout << stHttpReq.getURL().getType() << endl;
    int ret;
#if TARS_SSL
    if (GMCM_CERT_TYPE == 1)
    {
        // ret = stHttpReq.doRequest(stHttpRsp, 3000, TC_OpenSSL::newCtx("", GMCM_SIGN_CERT, GMCM_SIGN_KEY, GMCM_ENC_CERT, GMCM_ENC_KEY, false, false, ""));
        ret = stHttpReq.doRequest(stHttpRsp, 3000, TC_OpenSSL::newCtx("", "", "", "", "", false, false, ""));
    }
    else
    {
        ret = stHttpReq.doRequest(stHttpRsp, 3000, TC_OpenSSL::newCtx("", GMCM_SIGN_CERT, GMCM_SIGN_KEY, "", "", true, false, ""));
    }
#else
    ret = stHttpReq.doRequest(stHttpRsp, 3000);
#endif

    if(ret)
    {
        openssl_err_stack();
        cout << "do request fail " << ret << endl;
    }
    else
    {
        cout << stHttpRsp.getContent() << endl;
    }
}


int main(int argc, char const *argv[])
{
    int choose = utilTool::stdGetInt(
        "0 exit\n"
        "1 helppage\n");

    switch (choose)
    {
    case 1:
        testHelpPage();
        break;
    
    default:
        break;
    }
    return 0;
}
