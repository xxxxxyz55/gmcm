#ifndef _HTTP_HANDLE_H_
#define _HTTP_HANDLE_H_

#include "util/tc_epoll_server.h"

class gmcmSvsHandle:public TC_EpollServer::Handle
{
private:
    /* data */
public:
    void initialize();
    void handle(const shared_ptr<TC_EpollServer::RecvContext> &data);
    void handleClose(const shared_ptr<TC_EpollServer::RecvContext> &data);
    gmcmSvsHandle(/* args */){};
    ~gmcmSvsHandle(){};
};

#endif