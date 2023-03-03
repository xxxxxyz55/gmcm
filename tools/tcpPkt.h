#ifndef _GMCM_TCP_PKT_H_
#define _GMCM_TCP_PKT_H_

#define CMD_LEN 4
#include <string.h>
#include "pst.h"

using namespace std;
using namespace pst;


PST_FIELD_BEGIN(respErr, "")
PST_FIELD_ADD(iRet, PST_U_INT, NULL)
PST_FIELD_END(respErr)

/*
tcp 自定义协议
[request]
head    FFFFFFFF    4byte
cmd     "0001"      4byte
len     xxxx        2byte
pstdata bytes       len
tail    FFFFFFFF    4byte

[response]
head    FFFFFFFF    4byte
err     00000001    4byte
len     xxxx        2byte
pstdata bytes       len
tail    FFFFFFFF    4byte
*/


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
    pstBuffer baseBuf;
    FUNC_PTR_SEND_CB _send;

public:
    int unpack(unsigned char *pReq, unsigned int uReqLen)
    {
        if (uReqLen < 14)
        {
            return -1;
        }

        memcpy(cmd, pReq + 4, 4);
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
            resp.iRet.setVal(errNo);
            memset(this->cmd, 0xff, 4);
        }
    }

    void setSendFunc(FUNC_PTR_SEND_CB pSendCb) { _send = pSendCb; }

    int sendResp()
    {
        static unsigned int head = 0xffffffff;
        PST_PKG_LEN_TYPE totalLen = 0;
        int iRet = 0;

        for (size_t i = 0; i < baseBuf.fieldNum; i++)
        {
            totalLen = totalLen + sizeof(PST_PKG_LEN_TYPE) + baseBuf.field[i].length;
        }

        iRet = this->_send((unsigned char *)&head, sizeof(unsigned int));
        if (iRet)
        {
            return iRet;
        }

        iRet = this->_send((unsigned char *)cmd, CMD_LEN);
        if (iRet)
        {
            return iRet;
        }

        iRet = this->_send((unsigned char *)&totalLen, sizeof(PST_PKG_LEN_TYPE));
        if (iRet)
        {
            return iRet;
        }


        for (size_t i = 0; i < baseBuf.fieldNum; i++)
        {
            iRet = this->_send((unsigned char *)&baseBuf.field[i].length, sizeof(PST_PKG_LEN_TYPE));
            if (iRet)
            {
                return iRet;
            }

            iRet = this->_send((unsigned char *)baseBuf.field[i].value, baseBuf.field[i].length);
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
    pstBuffer *getResp() { return &baseBuf; }
    char *getCmd() { return cmd; }
};

class tcpClientPkt
{
private:
    unsigned char respStr[65537];
    unsigned int respStrLen;
    pstBuffer reqBase;
    pstBuffer respBase;
    char cmd[CMD_LEN + 1];
    int iRet;
    FUNC_PTR_SEND_CB _send;
    FUNC_PTR_RECV_CB _recv;

public:
    tcpClientPkt(){};
    ~tcpClientPkt(){};
    void setSendFunc(FUNC_PTR_SEND_CB pSendCb) { _send = pSendCb; }
    void setRecvFunc(FUNC_PTR_RECV_CB pRecvCb) { _recv = pRecvCb; }
    pstBuffer *getReqBase() { return &reqBase; }
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

        PST_PKG_LEN_TYPE totalLen = 0;
        for (size_t i = 0; i < reqBase.fieldNum; i++)
        {
            totalLen += sizeof(PST_PKG_LEN_TYPE) + reqBase.field[i].length;
        }

        ret = this->_send((unsigned char *)&head, sizeof(head));
        if (ret)
        {
            return ret;
        }

        ret = this->_send((unsigned char *)this->cmd, 4);
        if (ret)
        {
            return ret;
        }

        ret = this->_send((unsigned char *)&totalLen, sizeof(totalLen));
        if (ret)
        {
            return ret;
        }


        for (size_t i = 0; i < reqBase.fieldNum; i++)
        {
            ret = this->_send((unsigned char *)&reqBase.field[i].length, sizeof(PST_PKG_LEN_TYPE));
            if (ret)
            {
                return ret;
            }

            ret = this->_send(reqBase.field[i].value, reqBase.field[i].length);
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
    
        if (memcmp(this->cmd, this->respStr + 4, CMD_LEN))
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
            }
            return -1;
        }
        else
        {
            this->iRet = 0;
        }

        unsigned short dataLen = *(unsigned short *)(this->respStr + 8);
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

        ret = this->_recv(this->respStr + 10, dataLen + 4);
        if(ret < 0)
        {
            return ret;
        }
        this->respStrLen = dataLen + 14;
        // utilTool::printHex(respStr, respStrLen, "响应");
        return 0;
    }
};

#endif