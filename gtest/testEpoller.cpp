#include "util/tc_epoll_server.h"
#include "pthread.h"
#include <unistd.h>
using namespace tars;

#define PKG_SIZE 256

class epollHandle : public TC_EpollServer::Handle
{
private:
    /* data */
public:
    void initialize()
    {
        cpu_set_t mask;
        CPU_ZERO(&mask);
        uint32_t cpu_num = sysconf(_SC_NPROCESSORS_CONF);
        CPU_SET(this->getHandleIndex() % cpu_num, &mask);
        pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &mask);
    }
    void handle(const shared_ptr<TC_EpollServer::RecvContext> &data)
    {
        auto sendCtx = data->createSendContext();
        sendCtx->buffer()->setBuffer(data->buffer().data(), data->buffer().size());
        sendResponse(sendCtx);
    }
    void handleClose(const shared_ptr<TC_EpollServer::RecvContext> &data)
    {
    }
};
TC_NetWorkBuffer::PACKET_TYPE parsepkt(TC_NetWorkBuffer &in, vector<char> &out)
{
    if (in.getBuffer()->length() < PKG_SIZE)
    {
        return TC_NetWorkBuffer::PACKET_LESS;
    }
    else if(in.getBuffer()->length() < PKG_SIZE)
    {
        return TC_NetWorkBuffer::PACKET_ERR;
    }

    out = in.getBuffers();
    in.clearBuffers();
    return TC_NetWorkBuffer::PACKET_FULL;
}

void onAccept(TC_EpollServer::Connection *conn)
{
    printf(" %s connect.\n", conn->getIp().c_str());
}


int main(int argc, char const *argv[])
{
    TC_EpollServer server;
    TC_Common::ignorePipe();
    server.setOpenCoroutine(TC_EpollServer::SERVER_OPEN_COROUTINE::NET_THREAD_MERGE_HANDLES_THREAD);
    string name = "testEpoll";
    string host = "tcp -h 0.0.0.0 -p 9900 -t 0";
    TC_EpollServer::BindAdapterPtr adapter = server.createBindAdapter<epollHandle>(name, host, 12);
    server.setEmptyConnTimeout(0);
    adapter->setMaxConns(1024);         //设置最大连接数
    adapter->setProtocol(parsepkt);           //设置判断收到完整包
    adapter->enableQueueMode();
    adapter->setQueueCapacity(100000);
    server.setOnAccept(onAccept);
    server.bind(adapter);
    server.waitForShutdown();
    return 0;
}

