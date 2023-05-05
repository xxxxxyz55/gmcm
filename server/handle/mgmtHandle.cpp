#include <sys/prctl.h>
#include "../gmcmErr.h"
#include "../tool/gmcmLog.h"
#include "../apiEngine/apiEngine.h"
#include "mgmtHandle.h"
#include "util/tc_http.h"

using namespace tars;

void mgmtHandle::initialize()
{
    int bindCpu = this->getHandleIndex() % sysconf(_SC_NPROCESSORS_CONF);
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(bindCpu, &cpuset);
    prctl(PR_SET_NAME, "gmcmMgmt");
    int rc = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    if (rc != 0)
    {
        gmcmLog::LogError() << "thread " << this->getHandleIndex() << " bind cpu fail." << endl;
    }

}

void mgmtHandle::handle(const shared_ptr<TC_EpollServer::RecvContext> &data)
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
        mgmtApiFuncPtr funcPtr = globalClass<mgmtApiEngine>::getGlobalClass()->getApiFunc(cmd);

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
            string err = errGetReason(ret);
            response.setResponse(200, "OK", "\"Response\": {\"err\":\"" + err + "\"}");
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
void mgmtHandle::handleClose(const shared_ptr<TC_EpollServer::RecvContext> &data)
{
    gmcmLog::LogDebug() << "TaskHandle::handleClose : " << data->ip() << " : " << data->port() << " close type " << data->closeType() << endl;
}