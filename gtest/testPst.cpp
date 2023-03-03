#include <iostream>
#include "pst.h"

using namespace std;
using namespace pst;

int checkLen(unsigned char *buf, PST_PKG_LEN_TYPE len)
{
    if (*(unsigned int *)buf > 32)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

PST_FIELD_BEGIN(reqPst, "testPst")
PST_FIELD_ADD(len, PST_U_INT, checkLen)
PST_FIELD_ADD(data, PST_U_STRING, NULL)
PST_FIELD_ADD(key, PST_U_STRING, NULL)
PST_FIELD_END(reqPst)

PST_FIELD_BEGIN(respPst, "testPst")
PST_FIELD_ADD(len, PST_U_INT, NULL)
PST_FIELD_ADD(data, PST_U_STRING, NULL)
PST_FIELD_END(respPst)


unsigned char gSockBuf[65537];
unsigned int gSockBufLen;

int write_buf(unsigned char *data, unsigned int len)
{
    memcpy(gSockBuf + gSockBufLen, data, len);
    gSockBufLen += len;
    return 0;
}

int client_write()
{
    pstBuffer reqBase;
    reqPst reqPtr;
    int ret;
    gSockBufLen = 0;
    unsigned char data[32] = {0};
    memset(data, 0x01, 32);
    unsigned char key[16];
    memset(key, 0x11, 16);
    ret = reqPtr.pointToBase(&reqBase);
    if(ret)
    {
        printf("point to base fail.\n");
    }

    reqPtr.len.setVal(32);
    reqPtr.data.setVal(data, (unsigned int)32);
    reqPtr.key.setVal(key, (unsigned int)16);

    reqPtr.print();

    write_pst_base(&reqBase, write_buf);
    printf("client write ok\n");
    return 0;
}

int client_read()
{
    unsigned char buf[8192];
    unsigned int len;

    memcpy(buf, gSockBuf, gSockBufLen);
    len = gSockBufLen;

    respPst respPtr;
    respPtr.pointToBuffer(buf, len);

    respPtr.print();
    printf("client read ok\n");
    return 0;
}

int server_read(unsigned char *buf, unsigned int *len)
{
    memcpy(buf, gSockBuf, gSockBufLen);
    *len = gSockBufLen;

    printf("server read ok\n");
    return 0;
}


int server_write()
{
    pstBuffer respBase;

    reqPst reqPtr;
    respPst respPtr;
    unsigned char data[64] = {0};
    memset(data, 0x02, 64);

    gSockBufLen = 0;

    respPtr.pointToBase(&respBase);

    respPtr.len.setVal(64);
    respPtr.data.setVal(data, (unsigned int)64);

    write_pst_base(&respBase, write_buf);
    printf("server write ok\n");
    return 0;
}

int server_deal()
{
    unsigned char req[8192];
    unsigned int reqLen;
    reqPst reqPtr;
    int ret;
    
    server_read(req, &reqLen);
    
    ret = reqPtr.pointToBuffer(req,reqLen);
    if(ret)
    {
        printf("point to buffer fail.\n");
    }
    else
    {
        reqPtr.print();
    }
    
    server_write();
    return 0;
}


int main(int argc, char const *argv[])
{
    client_write();
    server_deal();
    client_read();

    
    return 0;
}