#ifndef _GMCM_SDK_CLV_H_
#define _GMCM_SDK_CLV_H_
#include <iostream>

#include "util/tc_clientsocket.h"
#include "../include/gmcmSdkApi.h"
#include "../../encode/clv/clv_static.h"

using namespace std;
using namespace tars;

class gmcmSdkDev
{
private:
    /* data */
public:
    string serverIp;
    unsigned short serverPort;
    gmcmSdkDev(const char *ip = "127.0.0.1", unsigned short port = 8805)
    {
        serverIp = ip;
        serverPort = port;
    }

};

class gmcmSdkSession : public TC_TCPClient
{
public:
    int32_t sendCb(void * data, uint16_t len);
    int32_t recvClv();

    unsigned char respStr[65537];
    unsigned int respStrLen;
};

#endif