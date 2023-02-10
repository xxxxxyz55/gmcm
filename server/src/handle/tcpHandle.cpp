#include "../apiEngine/tcpProcessFunc.h"
#include <sys/prctl.h>
#include "../gmcmErr.h"
#include "../gmcmLog.h"
#include "tcpHandle.h"

void gmcmTcpHandle::initialize()
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

    setSendFunc(std::bind(&gmcmTcpHandle::send_callback, this, std::placeholders::_1, std::placeholders::_2));
}
void gmcmTcpHandle::handle(const shared_ptr<TC_EpollServer::RecvContext> &data)
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
            iRet = processTcpTask(tcpSeverPkt::getReq(), tcpSeverPkt::getReqLen(), tcpSeverPkt::getResp());
        }
        this->tcpSeverPkt::respErrPkt(iRet);
        // pSendCtx->buffer()->replaceBufferEx(NULL, 0, true);
        this->tcpSeverPkt::sendResp();
        // pSendCtx->buffer()->replaceBufferEx(NULL, 0, false);
    }
    catch (exception &ex)
    {
        gmcmLog::LogError() << "TaskHandle::handle ex: " << ex.what() << endl;
        close(data);
    }
}

unsigned int gmcmTcpHandle::processTcpTask(unsigned char *req, unsigned int reqLen, protoBase *resp)
{
    tcpDealFunc *pFunc = NULL;
    try
    {
        // printf("cmd = %s\n", cmd);
        pFunc = &tcpApiEngine::getMap()->at(getCmd());
        // printf("pFunc = %p\n", pFunc);
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        return GMCM_ERR_CMD_UNDEFINE;
    }
    
    if (pFunc == NULL || pFunc->func == NULL)
    {
        return GMCM_ERR_CMD_UNDEFINE;
    }
    else
    {
        return pFunc->func(req, reqLen, resp);
    }
}

void gmcmTcpHandle::handleClose(const shared_ptr<TC_EpollServer::RecvContext> &data)
{
    printf("TaskHandle::handleClose : %s : %d close type %d\n", data->ip().c_str(), data->port(), data->closeType());
}

#define MAX_PACKAGE_LEN     65537

TC_NetWorkBuffer::PACKET_TYPE parseGmcmTcp(TC_NetWorkBuffer &in, vector<char> &out)
{
    //FFFFFFFF + 2 len + len data + FFFFFFFF
    try
    {
        if (in.empty())
        {
            return TC_NetWorkBuffer::PACKET_LESS;
        }

        if (in.getBuffer()->length() <= 6)
        {
            return TC_NetWorkBuffer::PACKET_LESS;
        }
        /*
        FFFFFFFF
        0A00
        30303031
        0400
        60000000
        FFFFFFFF
        */

        unsigned char *p = (unsigned char *)in.getBuffer()->buffer();
        if (*(unsigned int *)p != 0xFFFFFFFF)
        {
            return TC_NetWorkBuffer::PACKET_ERR;
        }

        unsigned short needLen = *(unsigned short *)(p + 4);
        if (needLen > MAX_PACKAGE_LEN)
        {
            return TC_NetWorkBuffer::PACKET_ERR;
        }

        if (needLen > in.getBufferLength() - 10)
        {
            return TC_NetWorkBuffer::PACKET_LESS;
        }
        else if (needLen < in.getBufferLength() - 10)
        {
            return TC_NetWorkBuffer::PACKET_ERR;
        }

        out = in.getBuffers();
        in.clearBuffers();
        return TC_NetWorkBuffer::PACKET_FULL;
    }
    catch (exception &ex)
    {
        return TC_NetWorkBuffer::PACKET_ERR;
    }

    return TC_NetWorkBuffer::PACKET_LESS; //表示收到的包不完全
}