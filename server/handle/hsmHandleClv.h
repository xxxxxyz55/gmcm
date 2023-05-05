#ifndef _TCP_HANDLE_CLV_H_
#define _TCP_HANDLE_CLV_H_

#include "util/tc_epoll_server.h"
#include "../../encode/clv/clv_static.h"

using namespace  std;
using namespace tars;

class gmcmHsmClvHandle: public TC_EpollServer::Handle
{
private:
    /* data */
    std::function<int32_t(void *, uint16_t)> writCb = NULL;

    shared_ptr<TC_EpollServer::SendContext> pSendCtx = NULL;
    int send_callback(void *data, uint16_t dataLen)
    {
        // pSendCtx->buffer()->replaceBufferEx((char *)data, dataLen, false);
        pSendCtx->buffer()->setBuffer((char *)data, dataLen);
        sendResponse(pSendCtx);
        return 0;
    }

public:
    void initialize();
    void handle(const shared_ptr<TC_EpollServer::RecvContext> &data);
    void handleClose(const shared_ptr<TC_EpollServer::RecvContext> &data);

    gmcmHsmClvHandle(/* args */) {}
    ~gmcmHsmClvHandle() {}
};

TC_NetWorkBuffer::PACKET_TYPE parseGmcmClv(TC_NetWorkBuffer &in, vector<char> &out);

#endif