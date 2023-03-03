#ifndef _TCP_HANDLE_H_
#define _TCP_HANDLE_H_

#include "util/tc_epoll_server.h"
#include "tcpPkt.h"

using namespace  std;
using namespace tars;

class gmcmHsmHandle: public TC_EpollServer::Handle , public tcpSeverPkt
{
private:
    /* data */
    shared_ptr<TC_EpollServer::SendContext> pSendCtx = NULL;
    int send_callback(unsigned char *data, unsigned int dataLen)
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

    gmcmHsmHandle(/* args */) {}
    ~gmcmHsmHandle() {}
};

TC_NetWorkBuffer::PACKET_TYPE parseGmcmTcp(TC_NetWorkBuffer &in, vector<char> &out);

#endif