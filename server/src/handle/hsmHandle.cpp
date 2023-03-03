#include <sys/prctl.h>
#include "../gmcmErr.h"
#include "../tool/gmcmLog.h"
#include "hsmHandle.h"
#include "../apiEngine/hsmApi.h"

void gmcmHsmHandle::initialize()
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

    setSendFunc(std::bind(&gmcmHsmHandle::send_callback, this, std::placeholders::_1, std::placeholders::_2));
}

void gmcmHsmHandle::handle(const shared_ptr<TC_EpollServer::RecvContext> &data)
{
    try
    {
        int iRet = 0;
        pSendCtx = data->createSendContext();
        iRet = this->tcpSeverPkt::unpack((unsigned char *)data->buffer().data(), data->buffer().size());
        if (iRet)
        {
            iRet = GMCM_ERR_PACKAGE;
        }
        else
        {
            hsmApiFuncPtr funcPtr = globalClass<hsmApiEngine>::getGlobalClass()->getApiFunc(getCmd());
            if (funcPtr == NULL)
            {
                iRet = GMCM_ERR_CMD_UNDEFINE;
            }
            else
            {
                iRet = funcPtr(tcpSeverPkt::getReq(), tcpSeverPkt::getReqLen(), tcpSeverPkt::getResp());
            }
        }

        if(iRet)
        {
            cout << "cmd [" << getCmd() << "]." << endl;
            utilTool::printHex(tcpSeverPkt::getReq(), tcpSeverPkt::getReqLen(), "req");
        }
        this->tcpSeverPkt::respErrPkt(iRet);
        this->tcpSeverPkt::sendResp();
    }
    catch (exception &ex)
    {
        gmcmLog::LogError() << "TaskHandle::handle ex: " << ex.what() << endl;
        close(data);
    }
}

void gmcmHsmHandle::handleClose(const shared_ptr<TC_EpollServer::RecvContext> &data)
{
    gmcmLog::LogDebug() << "TaskHandle::handleClose : " << data->ip() << " : " << data->port() << " close type " << data->closeType() << endl;
}

#define MAX_PACKAGE_LEN     65537

TC_NetWorkBuffer::PACKET_TYPE parseGmcmTcp(TC_NetWorkBuffer &in, vector<char> &out)
{
    try
    {
        if (in.empty())
        {
            return TC_NetWorkBuffer::PACKET_LESS;
        }

        if (in.getBuffer()->length() < 10)
        {
            return TC_NetWorkBuffer::PACKET_LESS;
        }

        unsigned char *p = (unsigned char *)in.getBuffer()->buffer();
        if (*(unsigned int *)p != 0xFFFFFFFF)
        {
            printf("packet err header.");
            return TC_NetWorkBuffer::PACKET_ERR;
        }
        // utilTool::printHex(p, in.getBufferLength(), "req");

        unsigned short needLen = *(unsigned short *)(p + 8);
        if (needLen > MAX_PACKAGE_LEN)
        {
            printf("packet err total len.");
            return TC_NetWorkBuffer::PACKET_ERR;
        }

        if (in.getBufferLength() < 14)
        {
            return TC_NetWorkBuffer::PACKET_LESS;
        }

        if (needLen > in.getBufferLength() - 14)
        {
            return TC_NetWorkBuffer::PACKET_LESS;
        }
        else if (needLen < in.getBufferLength() - 14)
        {
            printf("packet err recv len.");
            return TC_NetWorkBuffer::PACKET_ERR;
        }

        out = in.getBuffers();
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