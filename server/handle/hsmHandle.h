#ifndef _TCP_HANDLE_CLV_H_
#define _TCP_HANDLE_CLV_H_

#include "util/tc_epoll_server.h"
#include "../../encode/clv/clv_static.h"

using namespace  std;
using namespace tars;

class gmcmHsmHandle: public TC_EpollServer::Handle
{
public:
    void initialize();
    void handle(const shared_ptr<TC_EpollServer::RecvContext> &data);
    void handleClose(const shared_ptr<TC_EpollServer::RecvContext> &data);

    gmcmHsmHandle(/* args */) {}
    ~gmcmHsmHandle() {}
};

TC_NetWorkBuffer::PACKET_TYPE parseGmcmClv(TC_NetWorkBuffer &in, vector<char> &out);

#endif