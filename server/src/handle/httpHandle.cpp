#include <sys/prctl.h>
#include "../gmcmErr.h"
#include "../gmcmLog.h"
#include "httpHandle.h"
#include "util/tc_http.h"

using namespace tars;

void gmcmHttpHandle::initialize()
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

void gmcmHttpHandle::handle(const shared_ptr<TC_EpollServer::RecvContext> &data)
{
    try
    {

        TC_HttpRequest request;
        TC_HttpResponse response;
        int ret = 0;
        request.decode(data->buffer().data(), data->buffer().size());
        gmcmLog::LogDebug() << data << endl;
        httpDealFunc *pFunc = NULL;
        try
        {
            string cmd = request.getRequest().data() + 1;
            pFunc = &httpApiEngine::getMap()->at(cmd);
        }
        catch (const std::exception &e)
        {
            std::cerr << e.what() << '\n';
            ret = GMCM_ERR_CMD_UNDEFINE;
        }

        if (ret || pFunc == NULL || pFunc->func == NULL)
        {
            ret = GMCM_ERR_CMD_UNDEFINE;
        }
        else
        {
            ret = pFunc->func(&request, &response);
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
void gmcmHttpHandle::handleClose(const shared_ptr<TC_EpollServer::RecvContext> &data)
{
    printf("TaskHandle::handleClose : %s : %d close type %d\n", data->ip().c_str(), data->port(), data->closeType());
}