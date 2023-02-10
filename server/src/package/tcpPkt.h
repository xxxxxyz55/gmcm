#ifndef _GMCM_TCP_PKT_H_
#define _GMCM_TCP_PKT_H_

#define CMD_LEN 4
#include "protostruct.h"
#include <string.h>
#include "utilFunc.h"

using namespace std;

typedef int (*FUNC_PTR_SEND)(unsigned char *, unsigned int);
using FUNC_PTR_SEND_CB = std::function<int(unsigned char *, unsigned int)>;
typedef int (*FUNC_PTR_RECV)(unsigned char *, unsigned int);
using FUNC_PTR_RECV_CB = std::function<int(unsigned char *, unsigned int)>;

class tcpSeverPkt
{
private:
    unsigned char *req; 
    unsigned int reqLen;
    char cmd[CMD_LEN + 1];//指令
    protoBase baseBuf;//响应缓存区
    FUNC_PTR_SEND_CB _send;

public:
    int unpack(unsigned char *pReq, unsigned int uReqLen)
    {
        if (uReqLen < 14)
        {
            return -1;
        }

        memcpy(cmd, pReq + 6, 4);
        req = pReq;
        reqLen = uReqLen;
        // utilTool::printHex(pReq, uReqLen, "请求");
        return 0;
    }

    void respErrPkt(unsigned int errNo)
    {
        if(errNo)
        {
            respErr resp;
            resp.pointToBase(&baseBuf);
            memcpy(resp.iRet, &errNo, sizeof(unsigned int));
            *resp.iRetPlen = sizeof(unsigned int);
            memset(this->cmd, 0xff, 4);
        }
    }

    void setSendFunc(FUNC_PTR_SEND_CB pSendCb) { _send = pSendCb; }

    int sendResp()
    {
        static unsigned int head = 0xffffffff;
        PKG_LENGTH_TYPE totalLen = 4;
        int iRet = 0;

        for (size_t i = 0; i < baseBuf.fieldNum; i++)
        {
            totalLen = totalLen + sizeof(PKG_LENGTH_TYPE) + baseBuf.length[i];
        }

        iRet = this->_send((unsigned char *)&head, sizeof(unsigned int));
        if (iRet)
        {
            return iRet;
        }

        iRet = this->_send((unsigned char *)&totalLen, sizeof(PKG_LENGTH_TYPE));
        if (iRet)
        {
            return iRet;
        }

        iRet = this->_send((unsigned char *)cmd, CMD_LEN);
        if (iRet)
        {
            return iRet;
        }

        for (size_t i = 0; i < baseBuf.fieldNum; i++)
        {
            iRet = this->_send((unsigned char *)&baseBuf.length[i], sizeof(PKG_LENGTH_TYPE));
            if (iRet)
            {
                return iRet;
            }

            iRet = this->_send((unsigned char *)baseBuf.pVal[i], baseBuf.length[i]);
            if (iRet)
            {
                return iRet;
            }
        }

        iRet = this->_send((unsigned char *)&head, sizeof(unsigned int));
        if (iRet)
        {
            return iRet;
        }

        return 0;
    }

    unsigned char *getReq() { return req + 10; }
    unsigned int getReqLen() { return reqLen - 14; }
    protoBase *getResp() { return &baseBuf; }
    char *getCmd() { return cmd; }
};

class tcpClientPkt
{
private:
    unsigned char respStr[PROTOTST_MAX_LEN];
    unsigned int respStrLen;
    protoBase reqBase;  //请求缓存区
    protoBase respBase; //响应缓存区
    char cmd[CMD_LEN + 1];
    int iRet;
    FUNC_PTR_SEND_CB _send;
    FUNC_PTR_RECV_CB _recv;

public:
    tcpClientPkt(){};
    ~tcpClientPkt(){};
    void setSendFunc(FUNC_PTR_SEND_CB pSendCb) { _send = pSendCb; }
    void setRecvFunc(FUNC_PTR_RECV_CB pRecvCb) { _recv = pRecvCb; }
    protoBase *getReqBase() { return &reqBase; }
    unsigned char *getRespStr() { return respStr + 10; }
    unsigned int getRespStrLen() { return respStrLen - 14; }
    int getError() { return iRet; }

    void setCmd(const char *sCmd)
    {
        memcpy(this->cmd, sCmd, 4);
    }

    int sendReq()
    {
        static unsigned int head = 0xffffffff;
        int ret;
        /*
        FFFFFFFF
        0A00
        30303031
        0400
        60000000
        FFFFFFFF
        */
        PKG_LENGTH_TYPE totalLen = 4;
        for (size_t i = 0; i < reqBase.fieldNum; i++)
        {
            totalLen += sizeof(PKG_LENGTH_TYPE) + reqBase.length[i];
        }

        ret = this->_send((unsigned char *)&head, sizeof(head));
        if (ret)
        {
            return ret;
        }

        ret = this->_send((unsigned char *)&totalLen, sizeof(totalLen));
        if (ret)
        {
            return ret;
        }

        ret = this->_send((unsigned char *)this->cmd, 4);
        if (ret)
        {
            return ret;
        }

        for (size_t i = 0; i < reqBase.fieldNum; i++)
        {
            ret = this->_send((unsigned char *)&reqBase.length[i], sizeof(PKG_LENGTH_TYPE));
            if (ret)
            {
                return ret;
            }

            ret = this->_send(reqBase.pVal[i], reqBase.length[i]);
            if (ret)
            {
                return ret;
            }
        }

        ret = this->_send((unsigned char *)&head, sizeof(head));
        if (ret)
        {
            return ret;
        }

        return 0;
    }

    int recvResp()
    {
        /*
        FFFFFFFF
        0A00
        00000000
        0400
        20010000
        FFFFFFFF
        */
        int ret = 0;

        ret = this->_recv(this->respStr, 10);
        if (ret < 0)
        {
            return ret;
        }
        else
        {
            this->respStrLen = 10;
        }
    
        if (memcmp(this->cmd, this->respStr + 6, CMD_LEN))
        {
            if (*(int *)(this->respStr + 6) == -1)
            {
                ret = this->_recv(this->respStr + 10, 10);
                if (ret < 0)
                {
                }
                else
                {
                    this->respStrLen += 10;
                    memcpy(&this->iRet, this->respStr + 12, 4);
                }
                /*
                FFFFFFFF
                0C00
                FFFFFFFF
                0400
                02000000
                FFFFFFFF
                */
                // utilTool::printHex(this->respStr, this->respStrLen, "错误响应");
            }
            return -1;
        }
        else
        {
            this->iRet = 0;
        }

        unsigned short dataLen = *(unsigned short *)(this->respStr + 4);
        if (dataLen > sizeof(this->respStr))
        {
            /*
            FFFFFFFF
            2800
            30303031
            */
            // utilTool::printHex(this->respStr, this->respStrLen, "响应");
            return -1;
        }

        ret = this->_recv(this->respStr + 10, dataLen);
        if(ret < 0)
        {
            return ret;
        }
        this->respStrLen = dataLen + 8;
        // utilTool::printHex(respStr, respStrLen, "响应");
        return 0;
    }
};

#endif