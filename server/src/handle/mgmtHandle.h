#ifndef _MGMT_HANDLE_H_
#define _MGMT_HANDLE_H_

#include "util/tc_epoll_server.h"
#include "../apiEngine/mgmtApi.h"

class mgmtHandle:public TC_EpollServer::Handle
{
private:
    /* data */
public:
    void initialize();
    void handle(const shared_ptr<TC_EpollServer::RecvContext> &data);
    void handleClose(const shared_ptr<TC_EpollServer::RecvContext> &data);
    mgmtHandle(/* args */){};
    ~mgmtHandle(){};
};

#endif