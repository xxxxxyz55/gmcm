#include "../tool/gmcmLog.h"
#include "svsHandle.h"
#include "../apiEngine/apiEngine.h"

void gmcmSvsHandle::initialize()
{
}

void gmcmSvsHandle::handle(const shared_ptr<TC_EpollServer::RecvContext> &data)
{
    try
    {
        TC_HttpRequest request;
        TC_HttpResponse response;
        request.decode(data->buffer().data(), data->buffer().size());
        string cmd = request.getRequestUrl().data();
        gmcmLog::LogDebug() << cmd << endl;
        gmcmLog::LogDebug() << request.getContent() << endl;

        svsApiFuncPtr funcPtr = globalClass<svsApiEngine>::getGlobalClass()->getApiFunc(cmd);
        funcPtr(&request, &response);

        string buffer = response.encode();
        shared_ptr<TC_EpollServer::SendContext> send = data->createSendContext();
        send->buffer()->setBuffer(buffer.c_str(), buffer.size());
        gmcmLog::LogDebug() << buffer << endl;

        sendResponse(send);
    }
    catch (exception &ex)
    {
        close(data);
    }
}
void gmcmSvsHandle::handleClose(const shared_ptr<TC_EpollServer::RecvContext> &data)
{
    gmcmLog::LogDebug() << "svs TaskHandle::handleClose : " << data->ip() << " : " << data->port() << " close type " << data->closeType() << endl;
}