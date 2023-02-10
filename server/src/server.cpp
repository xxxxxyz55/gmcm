#include <iostream>
#include "server.h"
#include "signal.h"
#include "handle/tcpHandle.h"
#include "handle/httpHandle.h"
#include "utilFunc.h"
#include "apiEngine/httpProcessFunc.h"
#include "apiEngine/tcpProcessFunc.h"
#include "tool/redisConn.h"
#include "keyMgmt/keyMgmt.h"
#include "softSdfApi.h"
#include "serverConf.h"

using namespace std;

gmcmServer *gmcmServer::_Server = NULL;

gmcmServer *gmcmServer::getGlobleServer()
{
    if (_Server)
    {
        return _Server;
    }
    else
    {
        _Server = new gmcmServer();
        return _Server;
    }
}

sdfMeth *gmcmServer::getSdfMeth()
{
    return &getGlobleServer()->_sdfMeth;
}

void gmcmServer::exit()
{
    if (_Server)
    {
        _Server->terminate();
    }
}

template <typename T>
int gmcmServer::addService(const char *host, const char *serviceName, const TC_NetWorkBuffer::protocol_functor &pf)
{
    int cpuNum = sysconf(_SC_NPROCESSORS_CONF);
    TC_EpollServer::BindAdapterPtr adapter = this->createBindAdapter<T>(serviceName, host, cpuNum);
    adapter->setMaxConns(1024);         //设置最大连接数
    adapter->setProtocol(pf);           //设置判断收到完整包
    adapter->enableQueueMode();
    adapter->setQueueCapacity(100000);
    bind(adapter);
    return 0;
}

gmcmServer::gmcmServer()
{
    addService<gmcmTcpHandle>(SERVICE_SDK_API, "gmcm_tcp_server", parseGmcmTcp);
    addService<gmcmHttpHandle>(SERVICE_HTTP_API, "gmcm_http_server", TC_NetWorkBuffer::parseHttp);

    if (!httpApiEngine::getMap() ||
        !tcpApiEngine::getMap() ||
        !redisConn::getRedisConnPool())
    {
        gmcmLog::LogError() << "module init fail." << endl;
        throw "module init fail.";
    }

    setOpenCoroutine(TC_EpollServer::SERVER_OPEN_COROUTINE::NET_THREAD_MERGE_HANDLES_THREAD);
    int ret = 0;
    if ((ret = _sdkLib.load_so_lib(SDF_API_LIB)))
    {
        gmcmLog::LogError() << "load lib fail." << endl;
        throw "load lib fail.";
    }

    _sdfMeth.set_dso(&_sdkLib);

    if (_sdfMeth.load_all_sdf_func() ||
        SDF_SetMgmtMeth(getKeyMgmtMeth(), NULL))
    {
        gmcmLog::LogError() << "load func fail." << endl;
        throw "load func fail.";
    }
    _sdfMeth.OpenDevice();

}

void gmcmServer::dealSignal(std::function<void()> porcessExit)
{
    TC_Port::registerCtrlC(porcessExit);
    TC_Port::registerTerm(porcessExit);
    TC_Port::registerSig(SIGSEGV, porcessExit);
    signal(SIGPIPE, SIG_IGN);
}



