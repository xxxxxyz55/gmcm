#ifndef _TCP_HANDLE_H_
#define _TCP_HANDLE_H_

#include "util/tc_epoll_server.h"
#include "../package/tcpPkt.h"

using namespace  std;
using namespace tars;

class gmcmTcpHandle: public TC_EpollServer::Handle , public tcpSeverPkt
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

    unsigned int processTcpTask(unsigned char *req, unsigned int reqLen, protoBase *resp);

public:
    void initialize();
    void handle(const shared_ptr<TC_EpollServer::RecvContext> &data);
    void handleClose(const shared_ptr<TC_EpollServer::RecvContext> &data);

    gmcmTcpHandle(/* args */) {}
    ~gmcmTcpHandle() {}
};

TC_NetWorkBuffer::PACKET_TYPE parseGmcmTcp(TC_NetWorkBuffer &in, vector<char> &out);

#endif