
#ifndef _CM_SERVER_H_
#define _CM_SERVER_H_

#include "util/tc_epoll_server.h"
#include "tool/gmcmLog.h"
#include "algProvider/algProvider.h"

using namespace  std;
using namespace tars;


class gmcmServer : public TC_EpollServer
{
private:
    static gmcmServer *_gmcmServer;
#if TARS_SSL
    SSL_CTX *_tlsCtx = NULL;
    void loadTls();
    void checkCertFile();
#endif
    gmcmServer(/* args */){};
    int init();

    int bindTcp(const char *port, const char *serviceName);
    int bindHttp(const char *port, const char *serviceName);
    void serverExit();
    void dealSignal(std::function<void()>);
    template <typename T>
    int addService(const char *host, const char *serviceName, const TC_NetWorkBuffer::protocol_functor &pf);

public:

    static int startGmcmServer();

    ~gmcmServer();
};

#endif