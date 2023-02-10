
#ifndef _CM_SERVER_H_
#define _CM_SERVER_H_

#include "util/tc_epoll_server.h"
#include "gmcmLog.h"
#include "algProvider/algProvider.h"

using namespace  std;
using namespace tars;


class gmcmServer : public TC_EpollServer
{
private:
    gmcmLog _logger;
    dso _sdkLib;
    sdfMeth _sdfMeth;
    static gmcmServer *_Server;
    gmcmServer(/* args */);

    int bindTcp(const char *port, const char *serviceName);
    int bindHttp(const char *port, const char *serviceName);

public:
    template <typename T>
    int addService(const char *host, const char *serviceName, const TC_NetWorkBuffer::protocol_functor &pf);

    void dealSignal(std::function<void()> porcessExit = exit);

    static void exit();
    static gmcmServer *getGlobleServer();
    static sdfMeth *getSdfMeth();

    ~gmcmServer() {}
};

#endif