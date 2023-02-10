
#include "protostruct.h"
#include <iostream>
#include "openssl/sgd.h"
#include <string.h>

using namespace std;

unsigned int checkKekIndex(unsigned char *param, unsigned int len)
{
    if (len != sizeof(unsigned int) || *((unsigned int *)param) > 8192)
    {
        return GMCM_ERR_KEK_INDEX;
    }
    else
    {
        printf("check index pass\n");
        return 0;
    }
}

unsigned int checkSymAlgId(unsigned char *param, unsigned int len)
{
    if (len != sizeof(unsigned int) || *((unsigned int *)param) != SGD_SM4)
    {
        printf("check algid fail\n");
        return GMCM_ERR_ALGID;
    }
    else
    {
        printf("check algid pass\n");
        return 0;
    }
}

unsigned int checkIv(unsigned char *param, unsigned int len)
{
    if (len != 16)
    {
        return GMCM_ERR_ALGID;
    }
    else
    {
        return 0;
    }
}

PROTOST_BEGIN(reqKekEncrypt, "test")
PROTOST_FIELD_ADD(index, unsigned int, checkKekIndex)
PROTOST_FIELD_ADD(algid, unsigned int, checkSymAlgId)
PROTOST_FIELD_ADD(iv, unsigned char, checkIv)
PROTOST_FIELD_ADD(dataLen, unsigned char, NULL)
PROTOST_FIELD_ADD(data, unsigned char, NULL)
PROTOST_END(reqKekEncrypt)

PROTOST_BEGIN(respKekEncrypt, "test")
PROTOST_FIELD_ADD(iv, unsigned char, NULL)
PROTOST_FIELD_ADD(dataLen, unsigned char, NULL)
PROTOST_FIELD_ADD(data, unsigned char, NULL)
PROTOST_END(respKekEncrypt)


unsigned char gSocketBuf[8192] = {0};
unsigned char glen = 0;

unsigned int writeToBuf(unsigned char *buf, unsigned int length)
{
    memcpy(gSocketBuf + glen, buf, length);
    glen += length;
    return 0;
}

void PrintHexbuff(const char *name, void *pBuff, int nLen)
{
    unsigned char *pData = (unsigned char *)pBuff;

    int nCount = 0;
    int i = 0;
    if (name)
    {
        printf("%s:\n", name);
    }

    for (i = 0; i < nLen; i++)
    {
        nCount++;
        printf("%02X", *pData++);

        if (nCount % 32 == 0)
        {
            nCount = 0;
        }
    }

    printf("\n");
}

int main(int argc, char const *argv[])
{

    protoBase clientBase;
    reqKekEncrypt clientReq; 
    respKekEncrypt clientResp;

    protoBase serverBase; //缓冲区 线程唯一
    reqKekEncrypt serverReq;
    respKekEncrypt serverResp;

    //客户端写入数据
    clientReq.pointToBase(&clientBase);
    unsigned int index = 1234;
    unsigned int algid = SGD_SM4;
    unsigned char iv[16];
    memset(iv, 0x31, sizeof(iv));
    unsigned int dataLen = 16;
    unsigned char data[8192];
    memset(data, 0x11, dataLen);

    BASE_SET_VAL(clientReq.index, index, sizeof(unsigned int));
    BASE_SET_VAL(clientReq.algid, algid, sizeof(unsigned int));
    BASE_SET_VAL(clientReq.iv, iv, sizeof(iv));
    BASE_SET_VAL(clientReq.dataLen, dataLen, sizeof(unsigned int));
    BASE_SET_VAL(clientReq.data, data, dataLen);

    //客户端发送
    protoStructWrite(&clientBase, writeToBuf);

    //服务端接收
    serverReq.pointToBuffer(gSocketBuf, glen);

    printf("server req index = %d\n", *serverReq.index);
    printf("server algid = %d\n", *serverReq.algid);
    PrintHexbuff("server reqiv", serverReq.iv, *serverReq.ivPlen);
    PrintHexbuff("server req data", serverReq.data, *serverReq.dataLen);

    //服务端写入数据
    unsigned int respDataLen = *serverReq.dataLen;
    serverResp.pointToBase(&serverBase);
    BASE_SET_VAL(serverResp.iv, "1122334455667788", 16);
    BASE_SET_VAL(serverResp.dataLen, respDataLen, sizeof(unsigned int));
    BASE_SET_VAL(serverResp.data, "1122112211221122", 16);

    // 服务端发送
    glen = 0;
    protoStructWrite(&serverBase, writeToBuf);

    // 客户端接收
    clientResp.pointToBuffer(gSocketBuf, glen);
    PrintHexbuff("client resp iv", clientResp.iv, *clientResp.ivPlen);
    PrintHexbuff("client resp data", clientResp.data, *clientResp.dataLen);
    return 0;
}
