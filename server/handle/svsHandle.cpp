#include <sys/prctl.h>
#include "../gmcmErr.h"
#include "../tool/gmcmLog.h"
#include "svsHandle.h"
#include "../apiEngine/apiEngine.h"
#include "algApi.h" 
#include "pjst.h"
using namespace tars;

void gmcmSvsHandle::initialize()
{
    int bindCpu = this->getHandleIndex() % sysconf(_SC_NPROCESSORS_CONF);
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(bindCpu, &cpuset);
    prctl(PR_SET_NAME, "gmcmHttpBusi");
    int rc = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    if (rc != 0)
    {
        gmcmLog::LogError() << "thread " << this->getHandleIndex() << " bind cpu fail." << endl;
    }
}

void gmcmSvsHandle::handle(const shared_ptr<TC_EpollServer::RecvContext> &data)
{
    try
    {
        TC_HttpRequest request;
        TC_HttpResponse response;
        int ret = 0;
        request.decode(data->buffer().data(), data->buffer().size());
        string cmd = request.getRequest().data() + 1;
        // gmcmLog::LogDebug() << cmd << endl;
        // gmcmLog::LogDebug() << request.getContent() << endl;
        svsApiFuncPtr funcPtr = globalClass<svsApiEngine>::getGlobalClass()->getApiFunc(cmd);

        if (funcPtr == NULL)
        {
            ret = GMCM_ERR_CMD_UNDEFINE;
        }
        else
        {
            ret = funcPtr(&request, &response);
        }

        if (ret)
        {
            const char *errReason = errGetReason(ret);
            pjst::jsonResp resp;
            resp.addRespField("errno", int64_t(ret));
            resp.addRespField("reason", errReason);
            response.setResponse(200, "OK", resp.toResponseStr());
        }
        

        string buffer = response.encode();
        shared_ptr<TC_EpollServer::SendContext> send = data->createSendContext();
        send->buffer()->setBuffer(buffer.c_str(), buffer.size());
        gmcmLog::LogDebug() << buffer << endl;

        sendResponse(send);
    }
    catch (exception &ex)
    {
        close(data);
    }
}
void gmcmSvsHandle::handleClose(const shared_ptr<TC_EpollServer::RecvContext> &data)
{
    gmcmLog::LogDebug() << "svs TaskHandle::handleClose : " << data->ip() << " : " << data->port() << " close type " << data->closeType() << endl;
    openssl_err_stack();
}