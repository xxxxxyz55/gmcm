#include "../gmcmErr.h"
#include "../tool/gmcmLog.h"
#include "hsmHandle.h"
#include "../apiEngine/apiEngine.h"

void gmcmHsmHandle::initialize()
{
}

void gmcmHsmHandle::handle(const shared_ptr<TC_EpollServer::RecvContext> &data)
{
    try
    {
        char cmd[5];
        memcpy(cmd, clv_obj::clvPktGetExt((uint8_t *)data->buffer().data()), EXT_LEN);
        cmd[4] = '\0';

        hsmApiFuncPtr funcPtr = globalClass<hsmApiEngine>::getGlobalClass()->getApiFunc(cmd);
        string respStr = funcPtr((uint8_t *)data->buffer().data(), data->buffer().size());

        auto sendCtx = data->createSendContext();
        if(sendCtx->buffer()->readIdx())
        {
            sendCtx->buffer()->setBuffer(respStr);
            sendResponse(sendCtx);
        }
        else
        {
            const char *pBuffer = sendCtx->buffer()->buffer(); // readidx = 0
            size_t cap = sendCtx->buffer()->capacity();
            sendCtx->buffer()->replaceBufferEx(respStr.data(), respStr.length(), false);
            sendResponse(sendCtx);
            sendCtx->buffer()->replaceBufferEx(pBuffer, cap, false);
            sendCtx->buffer()->clear();
        }

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

TC_NetWorkBuffer::PACKET_TYPE parseGmcmClv(TC_NetWorkBuffer &in, vector<char> &out)
{
    try
    {
        if (in.empty())
        {
            return TC_NetWorkBuffer::PACKET_LESS;
        }

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
        in.clearBuffers();
        return TC_NetWorkBuffer::PACKET_FULL;
    }
    catch (exception &ex)
    {
        return TC_NetWorkBuffer::PACKET_ERR;
    }

    return TC_NetWorkBuffer::PACKET_LESS; //表示收到的包不完全
}