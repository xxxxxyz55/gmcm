#include "server.h"

int main(int argc, char const *argv[])
{
    try
    {
        gmcmServer::getGlobleServer()->dealSignal();
        gmcmServer::getGlobleServer()->waitForShutdown();
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }

    return 0;
}