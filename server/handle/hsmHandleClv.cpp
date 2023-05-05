#include <sys/prctl.h>
#include "../gmcmErr.h"
#include "../tool/gmcmLog.h"
#include "hsmHandleClv.h"
#include "../apiEngine/apiEngine.h"
#include "../api/hsm/hsmApi.h"

void gmcmHsmClvHandle::initialize()
{
    int bindCpu = this->getHandleIndex() % sysconf(_SC_NPROCESSORS_CONF);
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(bindCpu, &cpuset);
    prctl(PR_SET_NAME, "gmcmTcpBusi");
    int rc = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    if (rc != 0)
    {
        gmcmLog::LogError() << "thread " << this->getHandleIndex() << " bind cpu fail." << endl;
    }
    writCb = std::bind(&gmcmHsmClvHandle::send_callback, this, std::placeholders::_1, std::placeholders::_2);
}

void gmcmHsmClvHandle::handle(const shared_ptr<TC_EpollServer::RecvContext> &data)
{
    try
    {
        pSendCtx = data->createSendContext();
        char cmd[5];
        memcpy(cmd, clv_obj::clvPktGetExt((uint8_t *)data->buffer().data()), EXT_LEN);
        cmd[4] = '\0';

        hsmApiClvFuncPtr funcPtr = globalClass<hsmApiClvEngine>::getGlobalClass()->getApiFunc(cmd);
        if (funcPtr == NULL)
        {
            send_err(GMCM_ERR_CMD_UNDEFINE, writCb);
        }
        else
        {
            // utilTool::printHex((uint8_t *)data->buffer().data(), data->buffer().size(), "req");
            funcPtr((uint8_t *)data->buffer().data(), data->buffer().size(), writCb);
        }
    }
    catch (exception &ex)
    {
        gmcmLog::LogError() << "TaskHandle::handle ex: " << ex.what() << endl;
        close(data);
    }
}

void gmcmHsmClvHandle::handleClose(const shared_ptr<TC_EpollServer::RecvContext> &data)
{
    gmcmLog::LogDebug() << "TaskHandle::handleClose : " << data->ip() << " : " << data->port() << " close type " << data->closeType() << endl;
}

#define MAX_PACKAGE_LEN     65537

TC_NetWorkBuffer::PACKET_TYPE parseGmcmClv(TC_NetWorkBuffer &in, vector<char> &out)
{
    try
    {
        if (in.empty())
        {
            return TC_NetWorkBuffer::PACKET_LESS;
        }

        // utilTool::printHex((uint8_t *)in.getBuffer()->buffer(), in.getBuffer()->length(), "get pkg");

        int32_t ret = clv_obj::isCompleteClvPkt((uint8_t *)in.getBuffer()->buffer(), in.getBuffer()->length());
        if(!ret)
        {
        }
        else if(ret == CLV_ERR_PKT_ERR)
        {
            return TC_NetWorkBuffer::PACKET_ERR;
        }
        else
        {
            return TC_NetWorkBuffer::PACKET_LESS;
        }

        out = in.getBuffers(); 
        // utilTool::printHex((uint8_t *)in.getBuffer()->buffer(), in.getBuffer()->length(), "get full pkg");
        in.clearBuffers();
        return TC_NetWorkBuffer::PACKET_FULL;
    }
    catch (exception &ex)
    {
        printf("packet err exception.");
        return TC_NetWorkBuffer::PACKET_ERR;
    }

    return TC_NetWorkBuffer::PACKET_LESS; //表示收到的包不完全
}