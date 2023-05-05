
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
#if TARS_SSL
    shared_ptr<TC_OpenSSL::CTX> _tlsCtx = NULL;
    void loadTls();
    void checkCertFile();
#endif
    int init();

    void serverExit();
    void dealSignal(std::function<void()>);
    template <typename T>
    int addService(const char *host, const char *serviceName, const TC_NetWorkBuffer::protocol_functor &pf);

public:


    gmcmServer(/* args */);
    ~gmcmServer();
};

#endif