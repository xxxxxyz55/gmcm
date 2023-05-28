#include "../tool/gmcmLog.h"
#include "mgmtHandle.h"
#include "../apiEngine/apiEngine.h"

void mgmtHandle::initialize()
{
}

void mgmtHandle::handle(const shared_ptr<TC_EpollServer::RecvContext> &data)
{
    try
    {
        TC_HttpRequest request;
        TC_HttpResponse response;
        request.decode(data->buffer().data(), data->buffer().size());
        string cmd = request.getRequest().data() + 1;
        // gmcmLog::LogDebug() << cmd << endl;
        // gmcmLog::LogDebug() << request.getContent() << endl;
        mgmtApiFuncPtr funcPtr = globalClass<mgmtApiEngine>::getGlobalClass()->getApiFunc(cmd);
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
void mgmtHandle::handleClose(const shared_ptr<TC_EpollServer::RecvContext> &data)
{
    gmcmLog::LogDebug() << "TaskHandle::handleClose : " << data->ip() << " : " << data->port() << " close type " << data->closeType() << endl;
}