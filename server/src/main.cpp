#include "server.h"

int main(int argc, char const *argv[])
{
    try
    {
        return gmcmServer::startGmcmServer();
    }
    catch (const char *&e)
    {
        std::cerr << e << '\n';
    }

    return 0;
}