#ifndef _GMCM_SDK_H_
#define _GMCM_SDK_H_
#include <iostream>

#include "util/tc_clientsocket.h"
#include "tcpPkt.h"
#include "../include/gmcmSdkApi.h"

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
    int send_cb(unsigned char *data , unsigned int dataLen)
    {
        int ret =  this->send((const char *)data, dataLen);
        if(ret < 0)
        {
            SDK_LOG_ERROR("send data fail");
        }
        return ret;
    }

    int recv_cb(unsigned char * buf, unsigned int length)
    {
        int ret = this->recvLength((char *)buf, length);
        if(ret < 0)
        {
            SDK_LOG_ERROR("recv data fail");
        }
        return ret;
    }

    tcpClientPkt pkt;
};

#endif